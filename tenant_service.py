from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import uuid
from typing import List, Optional

import models
import schemas
from database import SessionLocal # For type hinting, actual session passed as arg

class TenantService:
    def create_tenant(self, db: Session, tenant_create: schemas.TenantCreate) -> models.Tenant:
        """
        Creates a new tenant.
        Args:
            db: SQLAlchemy database session.
            tenant_create: Pydantic schema with tenant creation data.
        Returns:
            The created Tenant SQLAlchemy model instance.
        Raises:
            ValueError: If tenant name already exists or other integrity issues.
        """
        db_tenant = models.Tenant(
            Name=tenant_create.name,
            Status=tenant_create.status if tenant_create.status else "Active"
        )
        try:
            db.add(db_tenant)
            db.commit()
            db.refresh(db_tenant)
            return db_tenant
        except IntegrityError as e:
            db.rollback()
            # Could be more specific about constraint violation if Tenant.Name is unique
            raise ValueError(f"Could not create tenant. Integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred: {str(e)}")


    def get_tenant_by_id(self, db: Session, tenant_id: uuid.UUID) -> Optional[models.Tenant]:
        """
        Retrieves a tenant by its ID.
        Args:
            db: SQLAlchemy database session.
            tenant_id: The UUID of the tenant to retrieve.
        Returns:
            The Tenant SQLAlchemy model instance if found, otherwise None.
        """
        return db.query(models.Tenant).filter(models.Tenant.TenantID == tenant_id).first()

    def list_tenants(self, db: Session, skip: int = 0, limit: int = 100) -> List[models.Tenant]:
        """
        Lists all tenants with pagination.
        Args:
            db: SQLAlchemy database session.
            skip: Number of records to skip (for pagination).
            limit: Maximum number of records to return (for pagination).
        Returns:
            A list of Tenant SQLAlchemy model instances.
        """
        return db.query(models.Tenant).offset(skip).limit(limit).all()
    
    def count_tenants(self, db: Session) -> int:
        """
        Counts all tenants.
        Args:
            db: SQLAlchemy database session.
        Returns:
            The total number of tenants.
        """
        return db.query(models.Tenant).count()

    def update_tenant(self, db: Session, tenant_id: uuid.UUID, tenant_update: schemas.TenantUpdate) -> Optional[models.Tenant]:
        """
        Updates an existing tenant's details.
        Args:
            db: SQLAlchemy database session.
            tenant_id: The UUID of the tenant to update.
            tenant_update: Pydantic schema with tenant update data.
        Returns:
            The updated Tenant SQLAlchemy model instance if found and updated, otherwise None.
        Raises:
            ValueError: If trying to update with data that violates integrity (e.g. duplicate name if unique).
        """
        db_tenant = self.get_tenant_by_id(db, tenant_id)
        if not db_tenant:
            return None

        update_data = tenant_update.model_dump(exclude_unset=True) # Pydantic V2
        # Pydantic V1: tenant_update.dict(exclude_unset=True)
        
        for key, value in update_data.items():
            # Need to map from schema field (e.g., "name") to model attribute (e.g., "Name")
            # if they are different. Given our schemas.py and models.py, direct mapping for 'name' and 'status'
            # will require matching case or using the model's actual attribute names.
            # Our Pydantic schemas use camelCase (name, status)
            # Our SQLAlchemy models use PascalCase (Name, Status)
            # So, we need to be careful here.
            if key == "name": # schema field name
                setattr(db_tenant, "Name", value) # model attribute name
            elif key == "status":
                setattr(db_tenant, "Status", value)
            # Add more fields if necessary, ensuring correct attribute mapping

        try:
            db.add(db_tenant) # Add to session, it's already there but this marks it as dirty
            db.commit()
            db.refresh(db_tenant)
            return db_tenant
        except IntegrityError as e:
            db.rollback()
            raise ValueError(f"Could not update tenant. Integrity error: {e.orig}")
        except Exception as e:
            db.rollback()
            raise ValueError(f"An unexpected error occurred during update: {str(e)}")

# Example usage (for testing purposes, not part of the final service structure for API)
if __name__ == "__main__":
    # This is illustrative. In a real app, get_db would be used by FastAPI dependency injection.
    
    # Create tables if they don't exist (for local testing)
    # Ensure you have a running PostgreSQL instance and correct DATABASE_URL
    # from database import create_database_tables
    # create_database_tables() # Uncomment if you need to create tables from models.py

    db_session = SessionLocal()
    tenant_service = TenantService()

    # Create a tenant
    try:
        new_tenant_data = schemas.TenantCreate(name="Test Tenant Inc.", status="Active")
        created_tenant = tenant_service.create_tenant(db_session, new_tenant_data)
        if created_tenant:
            print(f"Created Tenant: ID={created_tenant.TenantID}, Name={created_tenant.Name}")
            
            # Get the created tenant
            fetched_tenant = tenant_service.get_tenant_by_id(db_session, created_tenant.TenantID)
            if fetched_tenant:
                print(f"Fetched Tenant: {fetched_tenant.Name}")

            # Update the tenant
            updated_tenant_data = schemas.TenantUpdate(name="Test Tenant Corp.", status="Suspended")
            updated_tenant = tenant_service.update_tenant(db_session, created_tenant.TenantID, updated_tenant_data)
            if updated_tenant:
                print(f"Updated Tenant: Name={updated_tenant.Name}, Status={updated_tenant.Status}")

        # List tenants
        all_tenants = tenant_service.list_tenants(db_session, 0, 10)
        print(f"All Tenants ({len(all_tenants)}):")
        for t in all_tenants:
            # Map to response schema for consistent output
            tenant_resp = schemas.TenantResponse.model_validate(t) # Pydantic V2
            # Pydantic V1: schemas.TenantResponse.from_orm(t)
            print(f"  - ID: {tenant_resp.tenantId}, Name: {tenant_resp.name}, Status: {tenant_resp.status}")

    except ValueError as ve:
        print(f"Error: {ve}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        db_session.close()
