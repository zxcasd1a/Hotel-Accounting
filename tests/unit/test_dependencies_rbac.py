import pytest
from unittest.mock import MagicMock, Depends # Depends is not directly used in unit test call
from fastapi import HTTPException, status
import uuid

from dependencies import RBACPermissionChecker, get_current_user_token_data # For mocking its behavior
import schemas
# No direct DB interaction in RBACPermissionChecker if permissions are in token.
# If testing fallback, then mock db session and user_service.

@pytest.fixture
def mock_token_data_valid_user():
    return schemas.TokenData(
        sub=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        roles=["user"],
        permissions=["document:read", "document:write"],
        is_2fa_authenticated=True 
    )

@pytest.fixture
def mock_token_data_admin_user():
    return schemas.TokenData(
        sub=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        roles=["admin", "user"],
        permissions=["document:read", "document:write", "document:delete", "user:manage"],
        is_2fa_authenticated=True
    )

@pytest.fixture
def mock_token_data_no_permissions():
    return schemas.TokenData(
        sub=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        roles=["guest"],
        permissions=[],
        is_2fa_authenticated=True
    )

@pytest.fixture
def mock_token_data_not_2fa_authenticated():
     return schemas.TokenData(
        sub=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        roles=["user"],
        permissions=["document:read"],
        is_2fa_authenticated=False # Key for this test
    )


# Mock DB session and user_service for testing fallback permission fetching
@pytest.fixture
def mock_db_session_for_rbac():
    return MagicMock()

@pytest.fixture
def mock_user_service_for_rbac():
    from user_service import UserService # Import locally to avoid top-level mock issues potentially
    service = MagicMock(spec=UserService)
    return service


class TestRBACPermissionChecker:

    def test_access_granted_no_required_permissions(self, mock_token_data_valid_user: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=None) # No permissions required
        try:
            # Call directly, providing mocked dependencies that __call__ expects
            checker(token_data=mock_token_data_valid_user, db=mock_db_session_for_rbac) 
        except HTTPException:
            pytest.fail("HTTPException raised unexpectedly when no permissions required.")

    def test_access_granted_user_has_all_required_permissions(self, mock_token_data_valid_user: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=["document:read", "document:write"])
        try:
            checker(token_data=mock_token_data_valid_user, db=mock_db_session_for_rbac)
        except HTTPException:
            pytest.fail("HTTPException raised unexpectedly for sufficient permissions.")

    def test_access_granted_user_has_more_than_required_permissions(self, mock_token_data_admin_user: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=["document:read"])
        try:
            checker(token_data=mock_token_data_admin_user, db=mock_db_session_for_rbac)
        except HTTPException:
            pytest.fail("HTTPException raised unexpectedly when user has more than required.")

    def test_access_denied_user_lacks_one_permission(self, mock_token_data_valid_user: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=["document:read", "document:delete"])
        with pytest.raises(HTTPException) as excinfo:
            checker(token_data=mock_token_data_valid_user, db=mock_db_session_for_rbac)
        assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Missing: document:delete" in excinfo.value.detail

    def test_access_denied_user_lacks_all_permissions(self, mock_token_data_no_permissions: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=["document:read"])
        with pytest.raises(HTTPException) as excinfo:
            checker(token_data=mock_token_data_no_permissions, db=mock_db_session_for_rbac)
        assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Missing: document:read" in excinfo.value.detail

    def test_access_denied_not_fully_authenticated(self, mock_token_data_not_2fa_authenticated: schemas.TokenData, mock_db_session_for_rbac: MagicMock):
        checker = RBACPermissionChecker(required_permissions=["document:read"])
        with pytest.raises(HTTPException) as excinfo:
            checker(token_data=mock_token_data_not_2fa_authenticated, db=mock_db_session_for_rbac)
        assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Full authentication (including 2FA if enabled) required." in excinfo.value.detail
    
    def test_access_granted_not_fully_authenticated_but_no_perms_required(
        self, mock_token_data_not_2fa_authenticated: schemas.TokenData, mock_db_session_for_rbac: MagicMock
    ):
        # If an endpoint requires no permissions, it should pass even if not fully 2FA authenticated,
        # unless get_current_user_token_data or another preceding dependency enforces full auth.
        # The RBACPermissionChecker itself only enforces full auth IF permissions are required.
        checker = RBACPermissionChecker(required_permissions=None) 
        try:
            checker(token_data=mock_token_data_not_2fa_authenticated, db=mock_db_session_for_rbac)
        except HTTPException:
            pytest.fail("HTTPException raised for no required perms, even if not fully 2FA authed.")


    def test_fallback_permission_fetching_user_has_permission(
        self, mock_db_session_for_rbac: MagicMock, mock_user_service_for_rbac: MagicMock
    ):
        user_id = uuid.uuid4()
        # Token has no 'permissions' field or it's empty
        token_data_no_perms_in_claim = schemas.TokenData(
            sub=str(user_id), permissions=None, is_2fa_authenticated=True 
        ) 
        
        # Mock user_service to return permissions from DB
        mock_user_service_for_rbac.get_user_effective_permissions.return_value = {"db:read"}
        
        # Patch the user_service_instance within dependencies.py for this test
        with patch('dependencies.user_service_instance', mock_user_service_for_rbac):
            checker = RBACPermissionChecker(required_permissions=["db:read"])
            try:
                checker(token_data=token_data_no_perms_in_claim, db=mock_db_session_for_rbac)
            except HTTPException:
                pytest.fail("Fallback permission check failed.")
        
        mock_user_service_for_rbac.get_user_effective_permissions.assert_called_once_with(mock_db_session_for_rbac, user_id)

    def test_fallback_permission_fetching_user_lacks_permission(
        self, mock_db_session_for_rbac: MagicMock, mock_user_service_for_rbac: MagicMock
    ):
        user_id = uuid.uuid4()
        token_data_no_perms_in_claim = schemas.TokenData(
            sub=str(user_id), permissions=[], is_2fa_authenticated=True # Empty permissions list
        )
        
        mock_user_service_for_rbac.get_user_effective_permissions.return_value = {"other:perm"} # User has different perm from DB
        
        with patch('dependencies.user_service_instance', mock_user_service_for_rbac):
            checker = RBACPermissionChecker(required_permissions=["db:read"])
            with pytest.raises(HTTPException) as excinfo:
                checker(token_data=token_data_no_perms_in_claim, db=mock_db_session_for_rbac)
            assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
            assert "Missing: db:read" in excinfo.value.detail
        
        mock_user_service_for_rbac.get_user_effective_permissions.assert_called_once_with(mock_db_session_for_rbac, user_id)

# Note: Testing get_current_user_token_data and get_current_active_user would typically involve
# mocking oauth2_scheme (which is complex as it's a callable class) or using FastAPI's TestClient
# to simulate requests to protected endpoints. These are closer to integration tests for the dependency itself.
# The RBACPermissionChecker tests above directly invoke its __call__ method with mocked inputs,
# which is a valid unit testing approach for the checker's core logic.
