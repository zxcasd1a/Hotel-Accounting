from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import uuid
from typing import List, Optional

import models
import schemas

class PermissionService:
    def create_permission(self, db: Session, permission_create: schemas.PermissionCreate) -> models.Permission:
        """
        Creates a new permission.
        Args:
            db: SQLAlchemy database session.
            permission_create: Pydantic schema with permission creation data.
        Returns:
            The created Permission SQLAlchemy model instance.
        Raises:
            ValueError: If permission name already exists or other integrity issues.
        """
        db_permission = models.Permission(
            PermissionName=permission_create.permissionName,
            Description=permission_create.description
        )
        try:
            db.add(db_permission)
            db.commit()
            db.refresh(db_permission)
            return db_permission
        except IntegrityError as e:
            db.rollback()
            if "uq_permissions_permissionname" in str(e.orig).lower() or "unique constraint" in str(e.orig).lower(): # Check specific constraint
                raise ValueError(f"Permission with name '{permission_create.permissionName}' already exists.")
            raise ValueError(f"Could not create permission due to an integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred: {str(e)}")

    def get_permission_by_id(self, db: Session, permission_id: uuid.UUID) -> Optional[models.Permission]:
        """
        Retrieves a permission by its ID.
        Args:
            db: SQLAlchemy database session.
            permission_id: The UUID of the permission.
        Returns:
            The Permission model instance if found, else None.
        """
        return db.query(models.Permission).filter(models.Permission.PermissionID == permission_id).first()

    def get_permission_by_name(self, db: Session, permission_name: str) -> Optional[models.Permission]:
        """
        Retrieves a permission by its unique name.
        Args:
            db: SQLAlchemy database session.
            permission_name: The name of the permission.
        Returns:
            The Permission model instance if found, else None.
        """
        return db.query(models.Permission).filter(models.Permission.PermissionName == permission_name).first()

    def list_permissions(self, db: Session, skip: int = 0, limit: int = 100) -> List[models.Permission]:
        """
        Lists all permissions with pagination.
        Args:
            db: SQLAlchemy database session.
            skip: Number of records to skip.
            limit: Maximum number of records to return.
        Returns:
            A list of Permission model instances.
        """
        return db.query(models.Permission).order_by(models.Permission.PermissionName).offset(skip).limit(limit).all()
    
    def count_permissions(self, db: Session) -> int:
        """Counts all permissions."""
        return db.query(models.Permission).count()

    def update_permission(self, db: Session, permission_id: uuid.UUID, permission_update: schemas.PermissionUpdate) -> Optional[models.Permission]:
        """
        Updates a permission's details (e.g., description). Name is usually not updatable due to its use as an identifier.
        Args:
            db: SQLAlchemy database session.
            permission_id: The UUID of the permission to update.
            permission_update: Pydantic schema with update data.
        Returns:
            The updated Permission model instance or None if not found.
        Raises:
            ValueError for integrity errors (though less likely for description-only updates).
        """
        db_permission = self.get_permission_by_id(db, permission_id)
        if not db_permission:
            return None

        update_data = permission_update.model_dump(exclude_unset=True)
        
        # Only description is typically updatable for a permission.
        # PermissionName should be immutable as it's used in code.
        if "description" in update_data:
            db_permission.Description = update_data["description"]
        
        try:
            db.add(db_permission)
            db.commit()
            db.refresh(db_permission)
            return db_permission
        except Exception as e: # More generic error as IntegrityError is less likely here
            db.rollback()
            raise ValueError(f"An unexpected error occurred while updating permission: {str(e)}")


    def delete_permission(self, db: Session, permission_id: uuid.UUID) -> bool:
        """
        Deletes a permission. Caution: This is a sensitive operation.
        Permissions are often static. Deleting one might break application logic
        if it's hardcoded in permission checks. Also, check if it's assigned to roles.
        Args:
            db: SQLAlchemy database session.
            permission_id: The UUID of the permission to delete.
        Returns:
            True if deleted, False if not found.
        Raises:
            ValueError if permission is still assigned to roles.
        """
        db_permission = db.query(models.Permission).filter(models.Permission.PermissionID == permission_id).first()
        if not db_permission:
            return False

        # Check if the permission is assigned to any roles
        if db_permission.roles_having_this_permission: # Accesses the relationship
            raise ValueError(f"Permission '{db_permission.PermissionName}' cannot be deleted as it is currently assigned to one or more roles.")

        try:
            db.delete(db_permission)
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            # More specific error handling might be needed if there are DB-level constraints
            raise ValueError(f"An unexpected error occurred while deleting permission: {str(e)}")


if __name__ == "__main__":
    from database import SessionLocal, create_database_tables
    # create_database_tables() # Run if you need to create tables from models

    db = SessionLocal()
    permission_service = PermissionService()

    try:
        # Create permissions
        perm1_data = schemas.PermissionCreate(permissionName="user:create", description="Allows creating new users.")
        perm2_data = schemas.PermissionCreate(permissionName="user:read_all", description="Allows reading all user data.")
        perm_models = []
        for p_data in [perm1_data, perm2_data]:
            try:
                perm = permission_service.create_permission(db, p_data)
                print(f"Created permission: {perm.PermissionName}")
                perm_models.append(perm)
            except ValueError as e:
                print(e) # Might exist from previous run
                existing_perm = permission_service.get_permission_by_name(db, p_data.permissionName)
                if existing_perm:
                    perm_models.append(existing_perm)


        # List permissions
        print("\nListing permissions:")
        permissions = permission_service.list_permissions(db, limit=10)
        for p in permissions:
            print(f" - {p.PermissionName} (ID: {p.PermissionID}), Desc: {p.Description}")
        
        # Get a permission by name
        if perm_models:
            p_name_to_get = perm_models[0].PermissionName
            fetched_perm = permission_service.get_permission_by_name(db, p_name_to_get)
            if fetched_perm:
                print(f"\nFetched permission by name '{p_name_to_get}': {fetched_perm.Description}")

            # Update a permission
            perm_to_update_id = fetched_perm.PermissionID
            update_data = schemas.PermissionUpdate(description="Allows creating brand new platform users.")
            updated_perm = permission_service.update_permission(db, perm_to_update_id, update_data)
            if updated_perm:
                print(f"Updated permission '{updated_perm.PermissionName}' new description: {updated_perm.Description}")
        
        # Example of trying to delete a permission (assuming it's not in use)
        # For a real test, you'd need to ensure it's not assigned to any roles.
        # perm_to_delete_name = "test:delete_me"
        # try:
        #     del_perm = permission_service.create_permission(db, schemas.PermissionCreate(permissionName=perm_to_delete_name, description="To be deleted"))
        #     print(f"Created temp permission for deletion test: {del_perm.PermissionName}")
        #     permission_service.delete_permission(db, del_perm.PermissionID)
        #     print(f"Successfully deleted permission '{perm_to_delete_name}'")
        # except ValueError as e:
        #     print(f"Error in delete test: {e}")


    except ValueError as e:
        print(f"Service Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        db.close()
