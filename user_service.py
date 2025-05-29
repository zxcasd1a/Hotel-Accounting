from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func 
import uuid
from typing import List, Optional, Set

import models
import schemas
from hashing import Hash
from database import SessionLocal 
# Removed: from role_service import RoleService - avoid circular dependency if RoleService also imports UserService
# Instead, RoleService instance can be passed if needed, or role operations handled by RoleService directly.

class UserService:
    def create_user(self, db: Session, user_create: schemas.UserCreate, tenant_id: uuid.UUID) -> models.User:
        tenant = db.query(models.Tenant).filter(models.Tenant.TenantID == tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant with ID {tenant_id} not found.")

        hashed_password = Hash.hash_password(user_create.password)
        
        db_user = models.User(
            TenantID=tenant_id,
            Email=user_create.email,
            PasswordHash=hashed_password,
            FirstName=user_create.firstName,
            LastName=user_create.lastName,
            IsActive=True
        )
        try:
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            self.get_or_create_2fa_record(db, db_user.UserID) # Ensure 2FA record exists
            db.commit() 
            db.refresh(db_user)
            return db_user
        except IntegrityError as e:
            db.rollback()
            if "uq_users_tenant_email" in str(e.orig).lower():
                 raise ValueError(f"User with email '{user_create.email}' already exists in this tenant.")
            raise ValueError(f"Could not create user due to an integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred: {str(e)}")

    def get_user_by_id(self, db: Session, user_id: uuid.UUID, include_roles_permissions: bool = False) -> Optional[models.User]:
        query = db.query(models.User)
        if include_roles_permissions:
            query = query.options(
                joinedload(models.User.roles).joinedload(models.Role.permissions)
            )
        return query.filter(models.User.UserID == user_id).first()

    def get_user_by_email_and_tenant_id(self, db: Session, email: str, tenant_id: uuid.UUID, include_roles_permissions: bool = False) -> Optional[models.User]:
        query = db.query(models.User)
        if include_roles_permissions:
            query = query.options(
                joinedload(models.User.roles).joinedload(models.Role.permissions)
            )
        return query.filter(
            models.User.Email == email,
            models.User.TenantID == tenant_id
        ).first()
        
    def list_users_by_tenant(self, db: Session, tenant_id: uuid.UUID, skip: int = 0, limit: int = 100) -> List[models.User]:
        tenant = db.query(models.Tenant).filter(models.Tenant.TenantID == tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant with ID {tenant_id} not found.")
        return db.query(models.User).filter(models.User.TenantID == tenant_id).offset(skip).limit(limit).all()

    def count_users_by_tenant(self, db: Session, tenant_id: uuid.UUID) -> int:
        tenant = db.query(models.Tenant).filter(models.Tenant.TenantID == tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant with ID {tenant_id} not found.")
        return db.query(models.User).filter(models.User.TenantID == tenant_id).count()

    def update_user(self, db: Session, user_id: uuid.UUID, user_update: schemas.UserUpdate) -> Optional[models.User]:
        db_user = self.get_user_by_id(db, user_id)
        if not db_user:
            return None

        update_data = user_update.model_dump(exclude_unset=True)

        for key, value in update_data.items():
            if key == "email": setattr(db_user, "Email", value)
            elif key == "firstName": setattr(db_user, "FirstName", value)
            elif key == "lastName": setattr(db_user, "LastName", value)
            # Check instance type for admin-specific updates
            elif key == "isActive" and isinstance(user_update, schemas.UserAdminUpdate):
                 setattr(db_user, "IsActive", value)
            elif key == "isActive" and not isinstance(user_update, schemas.UserAdminUpdate):
                # Non-admins cannot change IsActive through the generic UserUpdate schema
                # This logic might be better placed in the API layer based on who the caller is.
                # For service layer, it assumes the schema passed is appropriate for the action.
                pass 

        try:
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            return db_user
        except IntegrityError as e:
            db.rollback()
            if "uq_users_tenant_email" in str(e.orig).lower():
                raise ValueError(f"User email update failed: email '{update_data.get('email')}' already exists in this tenant.")
            raise ValueError(f"Could not update user. Integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred during user update: {str(e)}")

    def update_user_last_login(self, db: Session, user_id: uuid.UUID) -> Optional[models.User]:
        db_user = self.get_user_by_id(db, user_id)
        if db_user:
            db_user.LastLoginAt = func.now()
            try:
                db.commit()
                db.refresh(db_user)
                return db_user
            except Exception as e:
                db.rollback()
                print(f"Error updating last login for user {user_id}: {str(e)}")
                return None
        return None

    def verify_user_password(self, db: Session, user_id: uuid.UUID, password_to_check: str) -> bool:
        db_user = self.get_user_by_id(db, user_id)
        if not db_user:
            return False
        return Hash.verify_password(password_to_check, db_user.PasswordHash)

    def update_user_password(self, db: Session, user_id: uuid.UUID, new_password: str) -> bool:
        db_user = self.get_user_by_id(db, user_id)
        if not db_user:
            return False
        
        db_user.PasswordHash = Hash.hash_password(new_password)
        try:
            db.add(db_user)
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            print(f"Error updating password for user {user_id}: {str(e)}")
            return False

    # --- 2FA Related Methods ---
    def get_2fa_record(self, db: Session, user_id: uuid.UUID) -> Optional[models.TwoFactorAuth]:
        return db.query(models.TwoFactorAuth).filter(models.TwoFactorAuth.UserID == user_id).first()

    def get_or_create_2fa_record(self, db: Session, user_id: uuid.UUID) -> models.TwoFactorAuth:
        record = self.get_2fa_record(db, user_id)
        if not record:
            record = models.TwoFactorAuth(UserID=user_id, IsEnabled=False)
            db.add(record)
        return record

    def is_user_2fa_enabled(self, db: Session, user_id: uuid.UUID) -> bool:
        user = self.get_user_by_id(db, user_id) 
        if not user: return False
        if user.two_factor_auth:
            return user.two_factor_auth.IsEnabled
        two_fa_record = self.get_2fa_record(db, user_id) # Fallback, should not be needed
        return two_fa_record.IsEnabled if two_fa_record else False

    # --- RBAC Related Methods ---
    def assign_role_to_user(self, db: Session, user_id: uuid.UUID, role_id: uuid.UUID) -> models.User:
        """Assigns a role to a user."""
        user = self.get_user_by_id(db, user_id, include_roles_permissions=True)
        if not user:
            raise ValueError("User not found.")
        
        # RoleService should be used to fetch the role to ensure it exists and is valid for the user's tenant
        # For now, direct query:
        role = db.query(models.Role).filter(models.Role.RoleID == role_id).first()
        if not role:
            raise ValueError("Role not found.")

        # Check if role is appropriate for user's tenant (system role or same tenant)
        if not role.IsSystemRole and role.TenantID != user.TenantID:
            raise ValueError(f"Role '{role.RoleName}' does not belong to tenant '{user.TenantID}' and is not a system role.")

        if role in user.roles:
            # raise ValueError("Role already assigned to this user.")
            return user # Idempotent: already assigned

        user.roles.append(role)
        try:
            db.commit()
            db.refresh(user)
            return user
        except Exception as e:
            db.rollback()
            raise ValueError(f"Error assigning role to user: {str(e)}")

    def remove_role_from_user(self, db: Session, user_id: uuid.UUID, role_id: uuid.UUID) -> models.User:
        """Removes a role from a user."""
        user = self.get_user_by_id(db, user_id, include_roles_permissions=True)
        if not user:
            raise ValueError("User not found.")
        
        role = db.query(models.Role).filter(models.Role.RoleID == role_id).first()
        if not role:
            raise ValueError("Role not found.") # Or consider it success if role doesn't exist

        if role not in user.roles:
            # raise ValueError("Role not assigned to this user.")
            return user # Idempotent: role was not assigned

        user.roles.remove(role)
        try:
            db.commit()
            db.refresh(user)
            return user
        except Exception as e:
            db.rollback()
            raise ValueError(f"Error removing role from user: {str(e)}")

    def get_user_roles(self, db: Session, user_id: uuid.UUID) -> List[models.Role]:
        """Retrieves all roles assigned to a specific user."""
        user = self.get_user_by_id(db, user_id, include_roles_permissions=True)
        if not user:
            raise ValueError("User not found.")
        return user.roles

    def get_user_effective_permissions(self, db: Session, user_id: uuid.UUID) -> Set[str]:
        """
        Retrieves all unique permission names assigned to a user through their roles.
        """
        user = self.get_user_by_id(db, user_id, include_roles_permissions=True)
        if not user:
            # Or raise an error, or return empty set if user not found is not an error condition for this call
            return set() 
        
        effective_permissions: Set[str] = set()
        for role in user.roles:
            # Ensure role.permissions is loaded. `include_roles_permissions=True` in get_user_by_id should handle this.
            # If not, a separate query or explicit loading for role.permissions might be needed here.
            for permission in role.permissions:
                effective_permissions.add(permission.PermissionName)
        return effective_permissions


if __name__ == '__main__':
    from tenant_service import TenantService
    from role_service import RoleService
    from permission_service import PermissionService
    # from database import create_database_tables
    # create_database_tables()

    db = SessionLocal()
    user_service = UserService()
    tenant_service = TenantService()
    permission_service = PermissionService()
    role_service = RoleService(permission_service) # RoleService needs PermissionService

    try:
        # Setup: Tenant, User, Role, Permission
        test_tenant = tenant_service.create_tenant(db, schemas.TenantCreate(name="RBAC Tenant"))
        print(f"Created Tenant: {test_tenant.Name}")

        test_user = user_service.create_user(db, schemas.UserCreate(email="rbac_user@example.com", password="password"), test_tenant.TenantID)
        print(f"Created User: {test_user.Email}")
        
        perm_read = permission_service.create_permission(db, schemas.PermissionCreate(permissionName="document:read", description="Read documents"))
        perm_write = permission_service.create_permission(db, schemas.PermissionCreate(permissionName="document:write", description="Write documents"))
        print(f"Created Permissions: {perm_read.PermissionName}, {perm_write.PermissionName}")

        role_viewer = role_service.create_role(db, schemas.RoleCreate(roleName="DocumentViewer"), tenant_id=test_tenant.TenantID)
        role_editor = role_service.create_role(db, schemas.RoleCreate(roleName="DocumentEditor"), tenant_id=test_tenant.TenantID)
        print(f"Created Roles: {role_viewer.RoleName}, {role_editor.RoleName}")

        role_service.assign_permission_to_role(db, role_viewer.RoleID, perm_read.PermissionID)
        role_service.assign_permission_to_role(db, role_editor.RoleID, perm_read.PermissionID)
        role_service.assign_permission_to_role(db, role_editor.RoleID, perm_write.PermissionID)
        print("Assigned permissions to roles.")

        # Test assign role to user
        user_service.assign_role_to_user(db, test_user.UserID, role_viewer.RoleID)
        print(f"Assigned role '{role_viewer.RoleName}' to user '{test_user.Email}'")

        # Test get user roles
        user_roles = user_service.get_user_roles(db, test_user.UserID)
        print(f"Roles for '{test_user.Email}': {[r.RoleName for r in user_roles]}")
        assert role_viewer.RoleName in [r.RoleName for r in user_roles]

        # Test get effective permissions
        effective_perms = user_service.get_user_effective_permissions(db, test_user.UserID)
        print(f"Effective permissions for '{test_user.Email}': {effective_perms}")
        assert "document:read" in effective_perms
        assert "document:write" not in effective_perms

        # Assign another role
        user_service.assign_role_to_user(db, test_user.UserID, role_editor.RoleID)
        print(f"Assigned role '{role_editor.RoleName}' to user '{test_user.Email}'")
        effective_perms_updated = user_service.get_user_effective_permissions(db, test_user.UserID)
        print(f"Updated effective permissions: {effective_perms_updated}")
        assert "document:read" in effective_perms_updated
        assert "document:write" in effective_perms_updated
        
        # Test remove role from user
        user_service.remove_role_from_user(db, test_user.UserID, role_viewer.RoleID)
        print(f"Removed role '{role_viewer.RoleName}' from user '{test_user.Email}'")
        effective_perms_after_remove = user_service.get_user_effective_permissions(db, test_user.UserID)
        print(f"Effective permissions after removing viewer role: {effective_perms_after_remove}")
        assert "document:read" in effective_perms_after_remove # Still has it via Editor
        assert "document:write" in effective_perms_after_remove


    except ValueError as ve:
        print(f"Service Error: {ve}")
    except IntegrityError as ie:
        print(f"Integrity Error: {ie}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        db.close()
