import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession # Renamed to avoid conflict
from typing import Generator

from database import Base, get_db as app_get_db # Import from main app
from config import settings # To potentially override settings for tests

# Override database URL for testing - use SQLite in-memory
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False} # Needed for SQLite
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Fixture to create tables before tests and drop them after
@pytest.fixture(scope="session", autouse=True)
def create_test_tables():
    Base.metadata.create_all(bind=engine) # Create tables
    yield
    Base.metadata.drop_all(bind=engine) # Drop tables after test session

# Fixture for a database session, isolated per test
@pytest.fixture(scope="function")
def db_session() -> Generator[SQLAlchemySession, None, None]:
    """
    Pytest fixture to provide a SQLAlchemy database session for tests.
    Rolls back transactions to ensure test isolation.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback() # Ensure test isolation
    connection.close()

# If you need to override the app's `get_db` dependency for integration tests
# that might involve FastAPI test client:
# from main import app # Assuming your FastAPI app instance is in main.py
# def override_get_db():
#     try:
#         db = TestingSessionLocal()
#         yield db
#     finally:
#         db.close()
# app.dependency_overrides[app_get_db] = override_get_db


# Fixtures for services (can be defined here or in specific test files)
# These will use the db_session fixture for integration tests.
# For unit tests, services will be instantiated with mocked DBs.

@pytest.fixture(scope="function")
def user_service_testing(db_session: SQLAlchemySession):
    from user_service import UserService
    return UserService()

@pytest.fixture(scope="function")
def tenant_service_testing(db_session: SQLAlchemySession):
    from tenant_service import TenantService
    return TenantService()

@pytest.fixture(scope="function")
def permission_service_testing(db_session: SQLAlchemySession):
    from permission_service import PermissionService
    return PermissionService()

@pytest.fixture(scope="function")
def role_service_testing(permission_service_testing): # Depends on permission_service fixture
    from role_service import RoleService
    return RoleService(permission_service=permission_service_testing)

@pytest.fixture(scope="function")
def totp_service_testing():
    from totp_service import TOTPService
    # Need to ensure totp_service's cipher_suite is initialized correctly,
    # especially if SECRET_ENCRYPTION_KEY in config.settings is overridden for tests.
    # For now, assume config.settings is used as is.
    return TOTPService()


@pytest.fixture(scope="function")
def auth_service_testing(user_service_testing, totp_service_testing):
    from auth_service import AuthService
    return AuthService(user_service=user_service_testing, totp_service=totp_service_testing)

# Note on overriding settings:
# If you need to change settings like JWT_SECRET_KEY for tests,
# you can use pytest-mock or monkeypatch to temporarily change `config.settings` values.
# Example:
# @pytest.fixture(autouse=True)
# def override_test_settings(monkeypatch):
#     monkeypatch.setattr(settings, 'JWT_SECRET_KEY', 'test-secret-key')
#     monkeypatch.setattr(settings, 'SECRET_ENCRYPTION_KEY', Fernet.generate_key().decode()) # Fresh key for TOTP tests
#     # Re-initialize totp_service.cipher_suite if key changes
#     from totp_service import cipher_suite as real_cipher_suite, Fernet
#     from config import settings as test_settings_instance
#     if real_cipher_suite is None or test_settings_instance.SECRET_ENCRYPTION_KEY != settings.SECRET_ENCRYPTION_KEY:
#          # This is tricky; module-level cipher_suite is already initialized.
#          # Best to handle this by having TOTPService take the key as a constructor arg or re-init method.
#          # For now, this is a known complexity if SECRET_ENCRYPTION_KEY is changed per test.
#          pass
#
# For TOTPService's Fernet key, it's initialized at module load.
# If SECRET_ENCRYPTION_KEY is changed by monkeypatch, totp_service.cipher_suite won't update automatically.
# A robust way is to make TOTPService accept the key in its constructor or have a reinitialization method.
# For now, tests will use the globally configured SECRET_ENCRYPTION_KEY.
# If that key is a placeholder like "a-very-secure-encryption-key-32-bytes", it needs to be a valid Fernet key
# or Fernet initialization will fail in totp_service.py, and cipher_suite will be None.
# The placeholder in config.py is NOT a valid Fernet key.
# This needs to be addressed for totp_service tests to pass.
# I will generate a valid one and suggest it for the .env or ensure config.py has a default valid one for tests.

# Let's assume for now that config.settings.SECRET_ENCRYPTION_KEY is a VALID Fernet key
# for tests to run. The default placeholder in config.py is not.
# I will add a check in totp_service.py example usage to print a valid key for .env if needed.
# The conftest.py could also generate one if not set, but that's more complex.
# For this exercise, I'll assume the user will set a valid one in their .env or
# I will update the default in config.py to be a valid one for testing purposes.
# (Latter is easier for automated runs if .env is not present).
# I will update config.py default to a fixed, valid Fernet key for testing.
# This is not secure for production but makes tests runnable out-of-the-box.
