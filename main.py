from database import engine, Base, SessionLocal
from sqlalchemy.orm import Session
import models # Ensure models are imported so Base knows about them
import schemas # For potential testing
from tenant_service import TenantService
from user_service import UserService

def create_db_tables():
    """
    Creates database tables defined in SQLAlchemy models.
    This is for initial setup and should ideally be replaced by migrations (Alembic)
    in a production environment.
    """
    print("Attempting to create database tables...")
    try:
        Base.metadata.create_all(bind=engine)
        print("Tables created successfully (if they didn't exist).")
    except Exception as e:
        print(f"Error creating tables: {e}")

def run_initial_tests():
    """
    A simple function to run some basic tests on services.
    This is for demonstration and would be replaced by proper unit/integration tests.
    """
    print("\nRunning initial service tests...")
    db: Session = SessionLocal()
    
    tenant_service = TenantService()
    user_service = UserService()

    test_tenant_name = "MainTestTenant"
    test_user_email = "maintest@example.com"
    
    try:
        # Clean up if exists from previous run (simple for testing)
        existing_user = user_service.get_user_by_email_and_tenant_id(db, test_user_email, None) # TenantId unknown yet
        # This cleanup is tricky as we don't know tenantId. A more robust cleanup would be needed.
        # For now, we rely on potential unique constraint errors or manual cleanup.

        existing_tenant_obj = db.query(models.Tenant).filter(models.Tenant.Name == test_tenant_name).first()
        if existing_tenant_obj:
            print(f"Tenant '{test_tenant_name}' already exists (ID: {existing_tenant_obj.TenantID}). Skipping creation.")
            test_tenant = schemas.TenantResponse.model_validate(existing_tenant_obj)
        else:
            print(f"Creating tenant '{test_tenant_name}'...")
            created_tenant_model = tenant_service.create_tenant(db, schemas.TenantCreate(name=test_tenant_name, status="Active"))
            test_tenant = schemas.TenantResponse.model_validate(created_tenant_model)
            print(f"Tenant created: {test_tenant.tenantId}")

        # Test User creation
        print(f"Attempting to create user '{test_user_email}' in tenant '{test_tenant.tenantId}'")
        user_in_db = user_service.get_user_by_email_and_tenant_id(db, test_user_email, test_tenant.tenantId)
        if user_in_db:
            print(f"User '{test_user_email}' already exists. Skipping creation.")
            test_user = schemas.UserResponse.model_validate(user_in_db)
        else:
            created_user_model = user_service.create_user(
                db,
                schemas.UserCreate(email=test_user_email, password="securePassword123", firstName="Main", lastName="Test"),
                test_tenant.tenantId
            )
            test_user = schemas.UserResponse.model_validate(created_user_model)
            print(f"User created: {test_user.userId}")

        # List tenants
        print("\nListing tenants...")
        tenants_models = tenant_service.list_tenants(db, limit=5)
        tenants_list = [schemas.TenantResponse.model_validate(t) for t in tenants_models]
        for t in tenants_list:
            print(f" - Tenant: {t.name} (ID: {t.tenantId})")
        
        # List users in the test tenant
        print(f"\nListing users in tenant '{test_tenant.name}'...")
        users_models = user_service.list_users_by_tenant(db, test_tenant.tenantId, limit=5)
        users_list = [schemas.UserResponse.model_validate(u) for u in users_models]
        for u in users_list:
            print(f" - User: {u.email} (ID: {u.userId})")

    except ValueError as ve:
        print(f"Service Error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    # 1. Create tables (run once or use Alembic)
    # create_db_tables()
    
    # 2. Run some example service interactions (optional)
    # run_initial_tests()

    print("\nIdentity Service Core Logic Setup.")
    print("To create database tables, uncomment 'create_db_tables()' in main.py and run this file.")
    print("To run sample service tests, uncomment 'run_initial_tests()' and run this file.")
    print("Ensure your DATABASE_URL environment variable is set correctly (e.g., in a .env file).")
    print("Example .env content:")
    print('DATABASE_URL="postgresql://your_user:your_password@your_host:your_port/your_database"')

# FastAPI app would be initialized here in a real scenario:
# from fastapi import FastAPI
# app = FastAPI()
# ... include routers ...
