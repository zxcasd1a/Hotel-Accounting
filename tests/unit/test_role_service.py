import pytest
from unittest.mock import MagicMock, patch
import uuid
from sqlalchemy.exc import IntegrityError

import models
import schemas
from role_service import RoleService
from permission_service import PermissionService # RoleService depends on this

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def mock_permission_service():
    return MagicMock(spec=PermissionService)

@pytest.fixture
def role_service(mock_permission_service: MagicMock): # Inject mocked PermissionService
    return RoleService(permission_service=mock_permission_service)

class TestRoleService:

    def test_create_system_role_success(self, role_service: RoleService, mock_db_session: MagicMock):
        role_data = schemas.RoleCreate(roleName="SysAdmin", description="System Administrator", isSystemRole=True)
        
        # Mock get_role_by_name to return None (role doesn't exist yet)
        with patch.object(role_service, 'get_role_by_name', return_value=None) as mock_get_name:
            created_role = role_service.create_role(mock_db_session, role_data, tenant_id=None)
            
            mock_get_name.assert_called_once_with(mock_db_session, role_data.roleName, None)
            mock_db_session.add.assert_called_once()
            # The actual object added can be checked via mock_db_session.add.call_args[0][0]
            added_obj = mock_db_session.add.call_args[0][0]
            assert added_obj.RoleName == role_data.roleName
            assert added_obj.IsSystemRole is True
            assert added_obj.TenantID is None
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once()

    def test_create_tenant_role_success(self, role_service: RoleService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        role_data = schemas.RoleCreate(roleName="TenantAdmin", description="Tenant Administrator")
        
        mock_tenant = models.Tenant(TenantID=tenant_id, Name="Test Tenant")
        mock_db_session.query(models.Tenant).filter().first.return_value = mock_tenant # Simulate tenant exists

        with patch.object(role_service, 'get_role_by_name', return_value=None) as mock_get_name:
            created_role = role_service.create_role(mock_db_session, role_data, tenant_id=tenant_id)
            
            mock_get_name.assert_called_once_with(mock_db_session, role_data.roleName, tenant_id)
            added_obj = mock_db_session.add.call_args[0][0]
            assert added_obj.RoleName == role_data.roleName
            assert added_obj.IsSystemRole is False
            assert added_obj.TenantID == tenant_id
            mock_db_session.commit.assert_called_once()

    def test_create_role_tenant_not_found(self, role_service: RoleService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        role_data = schemas.RoleCreate(roleName="TenantAdmin")
        mock_db_session.query(models.Tenant).filter().first.return_value = None # Simulate tenant NOT found

        with pytest.raises(ValueError) as excinfo:
            role_service.create_role(mock_db_session, role_data, tenant_id=tenant_id)
        assert f"Tenant with ID {tenant_id} not found" in str(excinfo.value)

    def test_create_role_already_exists(self, role_service: RoleService, mock_db_session: MagicMock):
        role_data = schemas.RoleCreate(roleName="SysAdmin")
        existing_role_mock = models.Role(RoleName="SysAdmin", IsSystemRole=True)

        with patch.object(role_service, 'get_role_by_name', return_value=existing_role_mock) as mock_get_name:
            with pytest.raises(ValueError) as excinfo:
                role_service.create_role(mock_db_session, role_data, tenant_id=None)
            assert "Role with name 'SysAdmin' already exists in system" in str(excinfo.value)

    def test_get_role_by_id(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        mock_role = models.Role(RoleID=role_id, RoleName="TestRole")
        
        mock_query = mock_db_session.query.return_value
        mock_options = mock_query.options.return_value # For joinedload
        mock_filter = mock_options.filter.return_value
        mock_filter.first.return_value = mock_role

        role = role_service.get_role_by_id(mock_db_session, role_id)
        assert role == mock_role
        # Check that joinedload was called (more complex assertion)

    def test_list_system_roles(self, role_service: RoleService, mock_db_session: MagicMock):
        mock_roles = [models.Role(RoleName="SysRole1", IsSystemRole=True)]
        
        mock_query = mock_db_session.query.return_value
        mock_options = mock_query.options.return_value
        mock_filter = mock_options.filter.return_value # First filter for TenantID.is_(None)
        mock_filter_system = mock_filter.filter.return_value # Second filter for IsSystemRole == True
        mock_order_by = mock_filter_system.order_by.return_value
        mock_offset = mock_order_by.offset.return_value
        mock_offset.limit.return_value = mock_roles

        roles = role_service.list_roles(mock_db_session, tenant_id=None) # System roles
        assert roles == mock_roles
        # Add more assertions for filter calls if needed

    def test_update_role_name_success(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        original_role = models.Role(RoleID=role_id, RoleName="OldName", TenantID=None, IsSystemRole=True)
        update_data = schemas.RoleUpdate(roleName="NewName")

        with patch.object(role_service, 'get_role_by_id', return_value=original_role):
            # Mock get_role_by_name for duplicate check, should return None or the same role
            with patch.object(role_service, 'get_role_by_name', side_effect=[original_role, None]) as mock_check_name:
                 updated_role = role_service.update_role(mock_db_session, role_id, update_data)
                 assert updated_role.RoleName == "NewName"
                 mock_db_session.commit.assert_called_once()
                 # mock_check_name.assert_called_with(mock_db_session, "NewName", None) # check this call

    def test_update_role_name_conflict(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        original_role = models.Role(RoleID=role_id, RoleName="OldName", TenantID=None, IsSystemRole=True)
        conflicting_role = models.Role(RoleID=uuid.uuid4(), RoleName="NewName", TenantID=None, IsSystemRole=True)
        update_data = schemas.RoleUpdate(roleName="NewName")

        with patch.object(role_service, 'get_role_by_id', return_value=original_role):
            with patch.object(role_service, 'get_role_by_name', return_value=conflicting_role) as mock_check_name:
                with pytest.raises(ValueError) as excinfo:
                    role_service.update_role(mock_db_session, role_id, update_data)
                assert "Role with name 'NewName' already exists" in str(excinfo.value)


    def test_delete_role_success_no_users(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        # Mock role has an empty users_assigned list
        mock_role = models.Role(RoleID=role_id, RoleName="ToDelete", users_assigned=[]) 
        
        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            result = role_service.delete_role(mock_db_session, role_id)
            assert result is True
            mock_db_session.delete.assert_called_once_with(mock_role)
            mock_db_session.commit.assert_called_once()

    def test_delete_role_with_assigned_users(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        mock_user = models.User() # Simplified mock user
        mock_role = models.Role(RoleID=role_id, RoleName="InUseRole", users_assigned=[mock_user])

        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            with pytest.raises(ValueError) as excinfo:
                role_service.delete_role(mock_db_session, role_id)
            assert "cannot be deleted as it is currently assigned" in str(excinfo.value)


    def test_assign_permission_to_role_success(self, role_service: RoleService, mock_db_session: MagicMock, mock_permission_service: MagicMock):
        role_id = uuid.uuid4()
        perm_id = uuid.uuid4()
        mock_role = models.Role(RoleID=role_id, RoleName="TestRole", permissions=[]) # Start with no permissions
        mock_permission = models.Permission(PermissionID=perm_id, PermissionName="test:exec")

        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            mock_permission_service.get_permission_by_id.return_value = mock_permission
            
            role_service.assign_permission_to_role(mock_db_session, role_id, perm_id)
            
            assert mock_permission in mock_role.permissions
            mock_db_session.commit.assert_called_once()

    def test_assign_permission_to_role_already_assigned(self, role_service: RoleService, mock_db_session: MagicMock, mock_permission_service: MagicMock):
        role_id = uuid.uuid4()
        perm_id = uuid.uuid4()
        mock_permission = models.Permission(PermissionID=perm_id, PermissionName="test:exec")
        mock_role = models.Role(RoleID=role_id, RoleName="TestRole", permissions=[mock_permission]) # Permission already there

        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            mock_permission_service.get_permission_by_id.return_value = mock_permission
            
            # Should not raise error, should be idempotent
            returned_role = role_service.assign_permission_to_role(mock_db_session, role_id, perm_id)
            
            assert len(mock_role.permissions) == 1 # Still one
            mock_db_session.commit.assert_not_called() # No change, no commit
            assert returned_role == mock_role


    def test_remove_permission_from_role_success(self, role_service: RoleService, mock_db_session: MagicMock, mock_permission_service: MagicMock):
        role_id = uuid.uuid4()
        perm_id = uuid.uuid4()
        mock_permission = models.Permission(PermissionID=perm_id, PermissionName="test:exec")
        mock_role = models.Role(RoleID=role_id, RoleName="TestRole", permissions=[mock_permission]) # Permission is present

        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            mock_permission_service.get_permission_by_id.return_value = mock_permission
            
            role_service.remove_permission_from_role(mock_db_session, role_id, perm_id)
            
            assert mock_permission not in mock_role.permissions
            mock_db_session.commit.assert_called_once()

    def test_get_permissions_for_role(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        mock_perm1 = models.Permission(PermissionName="p1")
        mock_perm2 = models.Permission(PermissionName="p2")
        mock_role = models.Role(RoleID=role_id, RoleName="TestRole", permissions=[mock_perm1, mock_perm2])

        with patch.object(role_service, 'get_role_by_id', return_value=mock_role):
            permissions = role_service.get_permissions_for_role(mock_db_session, role_id)
            assert len(permissions) == 2
            assert mock_perm1 in permissions
            assert mock_perm2 in permissions

    def test_get_permissions_for_role_not_found(self, role_service: RoleService, mock_db_session: MagicMock):
        role_id = uuid.uuid4()
        with patch.object(role_service, 'get_role_by_id', return_value=None):
            with pytest.raises(ValueError) as excinfo:
                role_service.get_permissions_for_role(mock_db_session, role_id)
            assert "Role not found" in str(excinfo.value)

    # Add tests for count_roles and various scenarios of list_roles (tenant-specific, include_system_roles)
    def test_list_roles_tenant_specific_only(self, role_service: RoleService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        mock_roles_tenant = [models.Role(RoleName="TenantRole1", TenantID=tenant_id, IsSystemRole=False)]
        
        mock_query = mock_db_session.query.return_value
        mock_options = mock_query.options.return_value
        # Simulate filter for TenantID == tenant_id AND IsSystemRole == False
        # This requires two chained filter calls or a more complex `and_` condition mock
        mock_filter_tenant = mock_options.filter.return_value 
        mock_filter_issystem = mock_filter_tenant.filter.return_value
        
        mock_order_by = mock_filter_issystem.order_by.return_value
        mock_offset = mock_order_by.offset.return_value
        mock_offset.limit.return_value = mock_roles_tenant

        roles = role_service.list_roles(mock_db_session, tenant_id=tenant_id, include_system_roles=False)
        assert roles == mock_roles_tenant
        # Add assertions for filter calls if possible (complex with SQLAlchemy)

    def test_list_roles_tenant_with_system(self, role_service: RoleService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        mock_roles_combined = [
            models.Role(RoleName="TenantRole1", TenantID=tenant_id, IsSystemRole=False),
            models.Role(RoleName="SysRole1", TenantID=None, IsSystemRole=True)
        ]
        
        mock_query = mock_db_session.query.return_value
        mock_options = mock_query.options.return_value
        # Simulate filter for (TenantID == tenant_id) OR (IsSystemRole == True)
        mock_filter_combined = mock_options.filter.return_value # This filter would use OR
        
        mock_order_by = mock_filter_combined.order_by.return_value
        mock_offset = mock_order_by.offset.return_value
        mock_offset.limit.return_value = mock_roles_combined

        roles = role_service.list_roles(mock_db_session, tenant_id=tenant_id, include_system_roles=True)
        assert roles == mock_roles_combined
        # Add assertions for filter calls (complex)
