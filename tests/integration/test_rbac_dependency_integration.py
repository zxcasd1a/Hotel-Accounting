import pytest
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.testclient import TestClient
from typing import Dict, Any, List, Optional
import uuid

from sqlalchemy.orm import Session

# Assuming your main application setup and dependencies can be imported/reused
# For this test, we'll create a minimal FastAPI app.
from dependencies import RBACPermissionChecker, get_current_user_token_data # The dependency to test
from config import settings
from database import get_db as app_get_db, Base # For app override
from tests.conftest import TestingSessionLocal, engine as test_engine # Test DB setup

import schemas # For TokenData
from auth_service import AuthService # To generate tokens for testing
from user_service import UserService
from totp_service import TOTPService
from models import User as UserModel # For creating a dummy user

# Create a minimal FastAPI app for testing the dependency
test_app = FastAPI()

# -- Minimal app setup for testing --
# Override get_db for the test_app
def override_get_db_for_test_app():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

test_app.dependency_overrides[app_get_db] = override_get_db_for_test_app

# Dummy endpoint protected by the RBAC checker
@test_app.get("/protected_resource_read", dependencies=[Depends(RBACPermissionChecker(required_permissions=["test:read"]))])
async def protected_resource_read():
    return {"message": "You have read access!"}

@test_app.get("/protected_resource_write", dependencies=[Depends(RBACPermissionChecker(required_permissions=["test:write"]))])
async def protected_resource_write():
    return {"message": "You have write access!"}

@test_app.get("/protected_resource_multi", dependencies=[Depends(RBACPermissionChecker(required_permissions=["test:read", "test:execute"]))])
async def protected_resource_multi():
    return {"message": "You have multi access!"}
    
@test_app.get("/protected_resource_no_perms_needed", dependencies=[Depends(RBACPermissionChecker(required_permissions=None))])
async def protected_resource_no_perms_needed():
    return {"message": "Access granted, no specific permissions needed."}

# We need an AuthService instance to create tokens for our tests
# This setup is becoming a bit involved for a "unit" test of the dependency,
# but it's a good integration test for it.
# These services should ideally use the test DB session via fixtures.
# However, AuthService itself doesn't directly take db_session in constructor.
# Its methods do. For token creation, it doesn't always need DB.

# Simpler: Instantiate services directly for token generation.
# This part assumes that the services can be instantiated without a running FastAPI app context.
_test_user_service = UserService()
_test_totp_service = TOTPService()
_test_auth_service = AuthService(user_service=_test_user_service, totp_service=_test_totp_service)


client = TestClient(test_app)

# Helper to create a token for testing
def create_test_token_for_rbac_deps(
    user_id: str, 
    permissions: Optional[List[str]] = None, 
    roles: Optional[List[str]] = None,
    is_2fa_authenticated: bool = True
) -> str:
    return _test_auth_service.create_access_token(
        user_id=user_id,
        permissions_names=set(permissions) if permissions else set(),
        roles_names=roles or [],
        is_2fa_authenticated=is_2fa_authenticated
    )

# --- Tests ---
@pytest.fixture(scope="module", autouse=True)
def create_test_app_tables():
    # Create tables in the in-memory SQLite DB for this test module
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


def test_access_granted_with_correct_permission():
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["test:read"])
    response = client.get("/protected_resource_read", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "You have read access!"}

def test_access_denied_missing_permission():
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["other:perm"])
    response = client.get("/protected_resource_read", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Missing: test:read" in response.json()["detail"]

def test_access_denied_no_permissions_in_token_or_db_fallback_fails(
    # This test assumes the fallback to DB is also not granting the permission.
    # To test DB fallback properly, we'd need to populate the test DB via fixtures.
    # For now, assume if token perms are empty, and DB also doesn't grant it, it fails.
):
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=[]) # No permissions in token
    
    # If we want to test the fallback, we need to mock the user_service_instance in dependencies.py
    # or ensure the test DB is set up for the user_service to find the user and their (lack of) perms.
    # This setup is simpler if we assume the token is the source of truth or DB also denies.
    # For a true test of fallback, this would be more involved.

    response = client.get("/protected_resource_read", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Missing: test:read" in response.json()["detail"]


def test_access_granted_multiple_permissions_match():
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["test:read", "test:execute", "other:perm"])
    response = client.get("/protected_resource_multi", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "You have multi access!"}

def test_access_denied_multiple_permissions_one_missing():
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["test:read"]) # Missing test:execute
    response = client.get("/protected_resource_multi", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Missing: test:execute" in response.json()["detail"]

def test_access_denied_token_not_fully_authenticated():
    test_user_id = str(uuid.uuid4())
    token = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["test:read"], is_2fa_authenticated=False)
    response = client.get("/protected_resource_read", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Full authentication (including 2FA if enabled) required." in response.json()["detail"]

def test_access_granted_no_permissions_needed_endpoint():
    test_user_id = str(uuid.uuid4())
    # Even with no permissions or partial auth, if endpoint requires no perms, it should pass RBAC check
    # (but might be caught by other global auth checks if those are stricter)
    token_no_perms = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=[], is_2fa_authenticated=True)
    response = client.get("/protected_resource_no_perms_needed", headers={"Authorization": f"Bearer {token_no_perms}"})
    assert response.status_code == 200
    assert response.json() == {"message": "Access granted, no specific permissions needed."}

    token_partial_auth = create_test_token_for_rbac_deps(user_id=test_user_id, permissions=["test:read"], is_2fa_authenticated=False)
    response_partial = client.get("/protected_resource_no_perms_needed", headers={"Authorization": f"Bearer {token_partial_auth}"})
    assert response_partial.status_code == 200 # RBAC checker passes if no perms are required by the endpoint
    assert response_partial.json() == {"message": "Access granted, no specific permissions needed."}


def test_invalid_token_format_or_signature(test_app): # Renamed client to test_app for clarity
    # This tests get_current_user_token_data implicitly via the dependency
    response = client.get("/protected_resource_read", headers={"Authorization": "Bearer invalidtokenstring"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid authentication credentials" # From get_current_user_token_data

    wrong_key_token = jwt.encode({"sub": "user"}, "wrong-key", algorithm=settings.JWT_ALGORITHM)
    response_wrong_key = client.get("/protected_resource_read", headers={"Authorization": f"Bearer {wrong_key_token}"})
    assert response_wrong_key.status_code == status.HTTP_401_UNAUTHORIZED


# Note: Testing the DB fallback for permissions within RBACPermissionChecker via TestClient
# would require setting up a user in the test DB, ensuring they have specific roles/permissions,
# then crafting a token that *lacks* the 'permissions' claim but is otherwise valid.
# Then, the RBACPermissionChecker would hit the fallback.
# This means the UserService used by the dependency needs to interact with the test DB.
# The current setup of _test_auth_service uses a UserService that isn't tied to the test_app's DB session.
# For a full integration test of the fallback:
# 1. Ensure `dependencies.user_service_instance` uses the test DB. This is tricky as it's module-level.
#    One way is to use FastAPI's app dependency overrides for `user_service_instance` itself if it were a dependency.
#    Or, make `RBACPermissionChecker` take `user_service` as a `Depends`.
# 2. Create a user with roles/permissions in the test DB.
# 3. Generate token for this user *without* 'permissions' claim.
# 4. Hit endpoint, verify fallback logic.
# This level of testing is complex to set up correctly here. The unit tests for fallback provide some confidence.
# The current integration tests focus on permission checks using claims in the token.
