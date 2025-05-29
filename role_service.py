from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
import uuid
from typing import List, Optional

import models
import schemas
from permission_service import PermissionService # To fetch permissions

class RoleService:
    def __init__(self, permission_service: PermissionService):
        self.permission_service = permission_service

    def create_role(self, db: Session, role_create: schemas.RoleCreate, tenant_id: Optional[uuid.UUID] = None) -> models.Role:
        """
        Creates a new role. If tenant_id is None, it's a system role.
        Args:
            db: SQLAlchemy database session.
            role_create: Pydantic schema with role creation data.
            tenant_id: Optional UUID of the tenant for tenant-specific roles.
        Returns:
            The created Role SQLAlchemy model instance.
        Raises:
            ValueError: If role name already exists for the tenant/system or other integrity issues.
        """
        
        is_system_role_flag = True if tenant_id is None else role_create.isSystemRole # If tenant_id is provided, isSystemRole from schema matters
        if tenant_id is None: # Explicitly a system role
            is_system_role_flag = True
        else: # Tenant-specific role
            is_system_role_flag = False 
            # Ensure tenant exists
            tenant = db.query(models.Tenant).filter(models.Tenant.TenantID == tenant_id).first()
            if not tenant:
                raise ValueError(f"Tenant with ID {tenant_id} not found. Cannot create role for this tenant.")

        # Check for existing role name
        existing_role = self.get_role_by_name(db, role_create.roleName, tenant_id)
        if existing_role:
            scope = "system" if tenant_id is None else f"tenant {tenant_id}"
            raise ValueError(f"Role with name '{role_create.roleName}' already exists in {scope}.")

        db_role = models.Role(
            RoleName=role_create.roleName,
            Description=role_create.description,
            TenantID=tenant_id,
            IsSystemRole=is_system_role_flag
        )
        try:
            db.add(db_role)
            db.commit()
            db.refresh(db_role)
            return db_role
        except IntegrityError as e: # Should be caught by pre-check, but as a safeguard
            db.rollback()
            raise ValueError(f"Could not create role due to an integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred: {str(e)}")

    def get_role_by_id(self, db: Session, role_id: uuid.UUID) -> Optional[models.Role]:
        """Retrieves a role by its ID, including its permissions."""
        return db.query(models.Role).options(joinedload(models.Role.permissions)).filter(models.Role.RoleID == role_id).first()

    def get_role_by_name(self, db: Session, role_name: str, tenant_id: Optional[uuid.UUID] = None) -> Optional[models.Role]:
        """Retrieves a role by its name and tenant_id (if provided)."""
        query = db.query(models.Role).filter(models.Role.RoleName == role_name)
        if tenant_id:
            query = query.filter(models.Role.TenantID == tenant_id)
        else:
            query = query.filter(models.Role.TenantID.is_(None)) # System role
        return query.first()

    def list_roles(self, db: Session, tenant_id: Optional[uuid.UUID] = None, skip: int = 0, limit: int = 100, include_system_roles: bool = False) -> List[models.Role]:
        """
        Lists roles. Can filter by tenant_id or list system roles.
        Args:
            db: SQLAlchemy database session.
            tenant_id: Optional tenant ID to filter roles for a specific tenant.
            skip: Pagination skip.
            limit: Pagination limit.
            include_system_roles: If True and tenant_id is specified, also includes system roles.
                                 If tenant_id is None, only system roles are listed by default unless this flag alters it (not typical).
                                 Usually, one would list system roles OR tenant roles.
                                 Let's simplify: if tenant_id is None, list system roles.
                                 If tenant_id is provided, list roles for that tenant.
                                 A separate call or parameter can be used to combine if needed.
        Returns:
            A list of Role model instances.
        """
        query = db.query(models.Role).options(joinedload(models.Role.permissions))
        if tenant_id:
            if include_system_roles: # List both tenant-specific and system roles
                 query = query.filter( (models.Role.TenantID == tenant_id) | (models.Role.IsSystemRole == True) )
            else: # List only tenant-specific roles
                query = query.filter(models.Role.TenantID == tenant_id, models.Role.IsSystemRole == False)
        else: # List only system roles
            query = query.filter(models.Role.TenantID.is_(None), models.Role.IsSystemRole == True)
            
        return query.order_by(models.Role.RoleName).offset(skip).limit(limit).all()

    def count_roles(self, db: Session, tenant_id: Optional[uuid.UUID] = None, include_system_roles: bool = False) -> int:
        """Counts roles based on the same filtering logic as list_roles."""
        query = db.query(models.Role)
        if tenant_id:
            if include_system_roles:
                 query = query.filter( (models.Role.TenantID == tenant_id) | (models.Role.IsSystemRole == True) )
            else:
                query = query.filter(models.Role.TenantID == tenant_id, models.Role.IsSystemRole == False)
        else:
            query = query.filter(models.Role.TenantID.is_(None), models.Role.IsSystemRole == True)
        return query.count()


    def update_role(self, db: Session, role_id: uuid.UUID, role_update: schemas.RoleUpdate) -> Optional[models.Role]:
        """Updates a role's details (name, description)."""
        db_role = self.get_role_by_id(db, role_id)
        if not db_role:
            return None

        update_data = role_update.model_dump(exclude_unset=True)
        
        if "roleName" in update_data and update_data["roleName"] != db_role.RoleName:
            # Check if new name conflicts
            existing_role_with_new_name = self.get_role_by_name(db, update_data["roleName"], db_role.TenantID)
            if existing_role_with_new_name and existing_role_with_new_name.RoleID != role_id:
                scope = "system" if db_role.TenantID is None else f"tenant {db_role.TenantID}"
                raise ValueError(f"Role with name '{update_data['roleName']}' already exists in {scope}.")
            db_role.RoleName = update_data["roleName"]

        if "description" in update_data:
            db_role.Description = update_data["description"]
        
        try:
            db.add(db_role)
            db.commit()
            db.refresh(db_role)
            return db_role
        except IntegrityError as e: # Should be caught by pre-check
            db.rollback()
            raise ValueError(f"Could not update role due to an integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred while updating role: {str(e)}")

    def delete_role(self, db: Session, role_id: uuid.UUID) -> bool:
        """
        Deletes a role.
        Raises ValueError if role is assigned to users or is a non-empty system role with permissions (policy dependent).
        """
        db_role = self.get_role_by_id(db, role_id)
        if not db_role:
            return False

        if db_role.users_assigned: # Check users_assigned relationship
            raise ValueError(f"Role '{db_role.RoleName}' cannot be deleted as it is currently assigned to one or more users.")
        
        # Optionally, for system roles, prevent deletion if it has permissions and is part of core system setup
        # if db_role.IsSystemRole and db_role.permissions:
        #     raise ValueError(f"System role '{db_role.RoleName}' with permissions cannot be deleted through this service.")

        try:
            # Permissions will be disassociated due to cascade on RolePermissions table (if FK constraint is set to cascade)
            # or handled by SQLAlchemy's relationship cascade if configured.
            # Here, we are directly deleting the role. Many-to-many entries in RolePermissions will be deleted by DB cascade.
            db.delete(db_role)
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred while deleting role: {str(e)}")


    def assign_permission_to_role(self, db: Session, role_id: uuid.UUID, permission_id: uuid.UUID) -> models.Role:
        """Assigns a permission to a role."""
        db_role = self.get_role_by_id(db, role_id)
        if not db_role:
            raise ValueError("Role not found.")
        
        db_permission = self.permission_service.get_permission_by_id(db, permission_id)
        if not db_permission:
            raise ValueError("Permission not found.")

        if db_permission in db_role.permissions:
            # Consider this not an error, or raise a specific "already assigned" error
            # For idempotency, just return the role.
            return db_role 
            # raise ValueError("Permission already assigned to this role.")

        db_role.permissions.append(db_permission)
        try:
            db.commit()
            db.refresh(db_role)
            return db_role
        except Exception as e:
            db.rollback()
            raise ValueError(f"Error assigning permission to role: {str(e)}")

    def remove_permission_from_role(self, db: Session, role_id: uuid.UUID, permission_id: uuid.UUID) -> models.Role:
        """Removes a permission from a role."""
        db_role = self.get_role_by_id(db, role_id)
        if not db_role:
            raise ValueError("Role not found.")
        
        db_permission = self.permission_service.get_permission_by_id(db, permission_id)
        if not db_permission:
            raise ValueError("Permission not found.")

        if db_permission not in db_role.permissions:
            # raise ValueError("Permission not assigned to this role.")
            # For idempotency, just return the role.
            return db_role

        db_role.permissions.remove(db_permission)
        try:
            db.commit()
            db.refresh(db_role)
            return db_role
        except Exception as e:
            db.rollback()
            raise ValueError(f"Error removing permission from role: {str(e)}")

    def get_permissions_for_role(self, db: Session, role_id: uuid.UUID) -> List[models.Permission]:
        """Retrieves all permissions assigned to a specific role."""
        db_role = self.get_role_by_id(db, role_id) # This already loads permissions due to joinedload
        if not db_role:
            raise ValueError("Role not found.")
        return db_role.permissions


if __name__ == "__main__":
    from database import SessionLocal, create_database_tables
    from tenant_service import TenantService # For creating a tenant for testing
    # create_database_tables()

    db = SessionLocal()
    permission_service = PermissionService() # Needed by RoleService
    role_service = RoleService(permission_service)
    tenant_service = TenantService() # For test setup

    try:
        # 1. Ensure some permissions exist
        perm_names = ["document:read", "document:write", "user:manage"]
        created_perms = {}
        for name in perm_names:
            perm = permission_service.get_permission_by_name(db, name)
            if not perm:
                try:
                    perm = permission_service.create_permission(db, schemas.PermissionCreate(permissionName=name, description=f"Allows {name}"))
                    print(f"Created permission: {perm.PermissionName}")
                except ValueError as e: # Already exists from other run
                    perm = permission_service.get_permission_by_name(db, name)
            if perm:
                 created_perms[name] = perm


        # 2. Create a system role
        sys_role_name = "SystemAuditor"
        sys_role = role_service.get_role_by_name(db, sys_role_name)
        if not sys_role:
            try:
                sys_role = role_service.create_role(db, schemas.RoleCreate(roleName=sys_role_name, description="System Auditor Role"))
                print(f"Created system role: {sys_role.RoleName}")
            except ValueError as e:
                 sys_role = role_service.get_role_by_name(db, sys_role_name)


        # 3. Assign permissions to system role
        if sys_role and created_perms.get("document:read"):
            try:
                role_service.assign_permission_to_role(db, sys_role.RoleID, created_perms["document:read"].PermissionID)
                print(f"Assigned 'document:read' to '{sys_role.RoleName}'")
            except ValueError as e:
                print(e) # Might be already assigned

        # 4. Create a tenant
        test_tenant_name = "RoleServiceTestTenant"
        tenant = db.query(models.Tenant).filter(models.Tenant.Name == test_tenant_name).first()
        if not tenant:
            tenant = tenant_service.create_tenant(db, schemas.TenantCreate(name=test_tenant_name))
            print(f"Created tenant: {tenant.Name}")
        
        # 5. Create a tenant-specific role
        tenant_role_name = "TenantEditor"
        tenant_role = role_service.get_role_by_name(db, tenant_role_name, tenant.TenantID)
        if not tenant_role:
            try:
                tenant_role = role_service.create_role(db, schemas.RoleCreate(roleName=tenant_role_name, description="Tenant Document Editor"), tenant_id=tenant.TenantID)
                print(f"Created tenant role: {tenant_role.RoleName} for Tenant {tenant.TenantID}")
            except ValueError as e:
                 tenant_role = role_service.get_role_by_name(db, tenant_role_name, tenant.TenantID)


        # 6. Assign permissions to tenant role
        if tenant_role and created_perms.get("document:write"):
            try:
                role_service.assign_permission_to_role(db, tenant_role.RoleID, created_perms["document:write"].PermissionID)
                print(f"Assigned 'document:write' to '{tenant_role.RoleName}'")
            except ValueError as e:
                print(e)


        # 7. List roles
        print("\nSystem roles:")
        system_roles = role_service.list_roles(db, include_system_roles=False) # tenant_id=None by default lists system roles
        for r in system_roles:
            print(f" - {r.RoleName} (System: {r.IsSystemRole}), Permissions: {[p.PermissionName for p in r.permissions]}")

        print(f"\nRoles for tenant '{tenant.Name}':")
        tenant_specific_roles = role_service.list_roles(db, tenant_id=tenant.TenantID)
        for r in tenant_specific_roles:
            print(f" - {r.RoleName} (System: {r.IsSystemRole}), Permissions: {[p.PermissionName for p in r.permissions]}")
        
        print(f"\nRoles for tenant '{tenant.Name}' (including system roles):")
        tenant_and_system_roles = role_service.list_roles(db, tenant_id=tenant.TenantID, include_system_roles=True)
        for r in tenant_and_system_roles:
            print(f" - {r.RoleName} (System: {r.IsSystemRole}), Permissions: {[p.PermissionName for p in r.permissions]}")


        # 8. Get permissions for a role
        if tenant_role:
            print(f"\nPermissions for role '{tenant_role.RoleName}':")
            perms = role_service.get_permissions_for_role(db, tenant_role.RoleID)
            for p in perms:
                print(f"  - {p.PermissionName}")

    except ValueError as e:
        print(f"Service Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        db.close()
