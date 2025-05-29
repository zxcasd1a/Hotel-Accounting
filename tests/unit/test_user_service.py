import pytest
from unittest.mock import MagicMock, patch, call
import uuid
from sqlalchemy.exc import IntegrityError

import models
import schemas
from user_service import UserService
from hashing import Hash # UserService uses Hash directly

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def user_service(): # No external service dependencies for UserService itself
    return UserService()

class TestUserService:

    def test_create_user_success(self, user_service: UserService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        user_data = schemas.UserCreate(
            email="test@example.com", 
            password="password123",
            firstName="Test",
            lastName="User"
        )
        mock_tenant = models.Tenant(TenantID=tenant_id)
        mock_db_session.query(models.Tenant).filter().first.return_value = mock_tenant
        
        # Mock get_or_create_2fa_record to avoid its internal DB calls during this unit test
        # We assume it works correctly and just ensure it's called.
        with patch.object(user_service, 'get_or_create_2fa_record') as mock_get_or_create_2fa:
            # Capture the added user object
            added_user_obj = None
            def capture_add(obj):
                nonlocal added_user_obj
                if isinstance(obj, models.User): # Ensure we capture the User model
                    added_user_obj = obj
            mock_db_session.add.side_effect = capture_add
            
            created_user = user_service.create_user(mock_db_session, user_data, tenant_id)

            assert added_user_obj is not None
            # add is called once for user, then get_or_create_2fa might call it if record is new
            # For this unit test, we care mostly about the user add.
            # mock_db_session.add.assert_any_call(added_user_obj) # Check user was added
            
            # commit is called for user, then for 2fa record if new. Here, at least once for user.
            mock_db_session.commit.assert_called() # Called at least once
            mock_db_session.refresh.assert_any_call(added_user_obj)

            assert added_user_obj.Email == user_data.email
            assert added_user_obj.TenantID == tenant_id
            assert Hash.verify_password(user_data.password, added_user_obj.PasswordHash)
            mock_get_or_create_2fa.assert_called_once_with(mock_db_session, added_user_obj.UserID)


    def test_create_user_tenant_not_found(self, user_service: UserService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        user_data = schemas.UserCreate(email="test@example.com", password="password")
        mock_db_session.query(models.Tenant).filter().first.return_value = None

        with pytest.raises(ValueError, match=f"Tenant with ID {tenant_id} not found"):
            user_service.create_user(mock_db_session, user_data, tenant_id)

    def test_create_user_email_exists(self, user_service: UserService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        user_data = schemas.UserCreate(email="test@example.com", password="password")
        mock_tenant = models.Tenant(TenantID=tenant_id)
        mock_db_session.query(models.Tenant).filter().first.return_value = mock_tenant
        
        # Simulate IntegrityError for unique constraint uq_users_tenant_email
        mock_integrity_error = IntegrityError("Mocked UE", params={}, orig=MagicMock())
        mock_integrity_error.orig.args = ("(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint 'uq_users_tenant_email'\nDETAIL:  Key (tenantid, email)=(..., test@example.com) already exists.\n",)
        mock_db_session.commit.side_effect = mock_integrity_error

        with pytest.raises(ValueError, match=f"User with email '{user_data.email}' already exists in this tenant"):
            user_service.create_user(mock_db_session, user_data, tenant_id)
        mock_db_session.rollback.assert_called_once()


    def test_get_user_by_id_found(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id, Email="test@example.com")
        mock_query = mock_db_session.query(models.User).options().filter().first
        mock_query.return_value = mock_user
        
        user = user_service.get_user_by_id(mock_db_session, user_id, include_roles_permissions=True)
        assert user == mock_user
        # Assert that options(joinedload(...)) was called if include_roles_permissions is True (complex)

    def test_update_user_success(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        original_user = models.User(UserID=user_id, Email="old@example.com", FirstName="Old")
        update_data = schemas.UserUpdate(email="new@example.com", firstName="New")

        with patch.object(user_service, 'get_user_by_id', return_value=original_user):
            updated_user = user_service.update_user(mock_db_session, user_id, update_data)
            assert updated_user.Email == "new@example.com"
            assert updated_user.FirstName == "New"
            mock_db_session.commit.assert_called_once()

    def test_update_user_admin_can_change_isactive(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        original_user = models.User(UserID=user_id, Email="user@example.com", IsActive=True)
        # Use UserAdminUpdate schema which includes isActive
        update_data = schemas.UserAdminUpdate(isActive=False) 

        with patch.object(user_service, 'get_user_by_id', return_value=original_user):
            updated_user = user_service.update_user(mock_db_session, user_id, update_data)
            assert updated_user.IsActive is False

    def test_update_user_non_admin_cannot_change_isactive_via_userupdate(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        original_user = models.User(UserID=user_id, Email="user@example.com", IsActive=True)
        # Use UserUpdate schema which might have isActive, but service logic should ignore it if not UserAdminUpdate
        update_data = schemas.UserUpdate(isActive=False) # Attempt to change isActive

        with patch.object(user_service, 'get_user_by_id', return_value=original_user):
            updated_user = user_service.update_user(mock_db_session, user_id, update_data)
            # IsActive should NOT have changed because UserUpdate was passed, not UserAdminUpdate
            assert updated_user.IsActive is True 


    def test_verify_user_password_correct(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        password = "password123"
        hashed_password = Hash.hash_password(password)
        mock_user = models.User(UserID=user_id, PasswordHash=hashed_password)
        
        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            assert user_service.verify_user_password(mock_db_session, user_id, password) is True

    def test_update_user_password_success(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        new_password = "newPassword456"
        mock_user = models.User(UserID=user_id, PasswordHash="old_hash")

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            result = user_service.update_user_password(mock_db_session, user_id, new_password)
            assert result is True
            assert Hash.verify_password(new_password, mock_user.PasswordHash)
            mock_db_session.commit.assert_called_once()

    # --- 2FA Record Tests ---
    def test_get_or_create_2fa_record_creates_if_not_exists(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        # Simulate 2FA record does not exist initially
        mock_db_session.query(models.TwoFactorAuth).filter().first.return_value = None 
        
        added_2fa_obj = None
        def capture_add_2fa(obj):
            nonlocal added_2fa_obj
            if isinstance(obj, models.TwoFactorAuth):
                 added_2fa_obj = obj
        mock_db_session.add.side_effect = capture_add_2fa

        record = user_service.get_or_create_2fa_record(mock_db_session, user_id)
        
        assert added_2fa_obj is not None
        mock_db_session.add.assert_called_once_with(added_2fa_obj)
        assert added_2fa_obj.UserID == user_id
        assert added_2fa_obj.IsEnabled is False
        assert record == added_2fa_obj # Should return the newly created record

    def test_get_or_create_2fa_record_returns_existing(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        existing_record = models.TwoFactorAuth(UserID=user_id, IsEnabled=True)
        mock_db_session.query(models.TwoFactorAuth).filter().first.return_value = existing_record
        
        record = user_service.get_or_create_2fa_record(mock_db_session, user_id)
        
        mock_db_session.add.assert_not_called() # Should not call add if record exists
        assert record == existing_record

    def test_is_user_2fa_enabled_true(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        # Mock user with 2FA enabled via relationship
        mock_user = models.User(UserID=user_id)
        mock_user.two_factor_auth = models.TwoFactorAuth(UserID=user_id, IsEnabled=True)

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            assert user_service.is_user_2fa_enabled(mock_db_session, user_id) is True
            
    def test_is_user_2fa_enabled_false(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id)
        mock_user.two_factor_auth = models.TwoFactorAuth(UserID=user_id, IsEnabled=False)
        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            assert user_service.is_user_2fa_enabled(mock_db_session, user_id) is False

    def test_is_user_2fa_enabled_no_record_fallback(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id)
        mock_user.two_factor_auth = None # Simulate relationship not loaded or no record

        # Fallback: get_2fa_record is called
        mock_db_session.query(models.TwoFactorAuth).filter().first.return_value = models.TwoFactorAuth(UserID=user_id, IsEnabled=False)
        
        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            assert user_service.is_user_2fa_enabled(mock_db_session, user_id) is False


    # --- RBAC Method Tests ---
    def test_assign_role_to_user_success(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        role_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id, TenantID=tenant_id, roles=[])
        mock_role = models.Role(RoleID=role_id, RoleName="Editor", TenantID=tenant_id, IsSystemRole=False)

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            mock_db_session.query(models.Role).filter().first.return_value = mock_role
            
            user = user_service.assign_role_to_user(mock_db_session, user_id, role_id)
            
            assert mock_role in user.roles
            mock_db_session.commit.assert_called_once()

    def test_assign_role_to_user_system_role(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        role_id = uuid.uuid4()
        tenant_id = uuid.uuid4() # User's tenant
        mock_user = models.User(UserID=user_id, TenantID=tenant_id, roles=[])
        mock_system_role = models.Role(RoleID=role_id, RoleName="SysViewer", TenantID=None, IsSystemRole=True)

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            mock_db_session.query(models.Role).filter().first.return_value = mock_system_role
            
            user_service.assign_role_to_user(mock_db_session, user_id, role_id)
            assert mock_system_role in mock_user.roles

    def test_assign_role_to_user_role_wrong_tenant(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        role_id = uuid.uuid4()
        user_tenant_id = uuid.uuid4()
        role_tenant_id = uuid.uuid4() # Different tenant
        
        mock_user = models.User(UserID=user_id, TenantID=user_tenant_id, roles=[])
        mock_role_other_tenant = models.Role(RoleID=role_id, RoleName="OtherTenantRole", TenantID=role_tenant_id, IsSystemRole=False)

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            mock_db_session.query(models.Role).filter().first.return_value = mock_role_other_tenant
            
            with pytest.raises(ValueError, match="does not belong to tenant"):
                user_service.assign_role_to_user(mock_db_session, user_id, role_id)


    def test_get_user_effective_permissions(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        perm1 = models.Permission(PermissionName="perm:read")
        perm2 = models.Permission(PermissionName="perm:write")
        perm3 = models.Permission(PermissionName="perm:delete") # In second role

        role1 = models.Role(RoleName="Viewer", permissions=[perm1, perm2])
        role2 = models.Role(RoleName="Editor", permissions=[perm2, perm3]) # Overlapping perm:write

        mock_user = models.User(UserID=user_id, roles=[role1, role2])

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user) as mock_get:
            permissions = user_service.get_user_effective_permissions(mock_db_session, user_id)
            
            mock_get.assert_called_once_with(mock_db_session, user_id, include_roles_permissions=True)
            assert permissions == {"perm:read", "perm:write", "perm:delete"}

    def test_get_user_effective_permissions_no_roles(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id, roles=[]) # No roles

        with patch.object(user_service, 'get_user_by_id', return_value=mock_user):
            permissions = user_service.get_user_effective_permissions(mock_db_session, user_id)
            assert permissions == set()
            
    def test_get_user_effective_permissions_user_not_found(self, user_service: UserService, mock_db_session: MagicMock):
        user_id = uuid.uuid4()
        with patch.object(user_service, 'get_user_by_id', return_value=None):
            permissions = user_service.get_user_effective_permissions(mock_db_session, user_id)
            assert permissions == set() # Should return empty set if user not found
