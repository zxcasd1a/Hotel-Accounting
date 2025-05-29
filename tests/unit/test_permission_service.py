import pytest
from unittest.mock import MagicMock, patch
import uuid
from sqlalchemy.exc import IntegrityError

import models
import schemas
from permission_service import PermissionService

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def permission_service():
    return PermissionService()

class TestPermissionService:
    def test_create_permission_success(self, permission_service: PermissionService, mock_db_session: MagicMock):
        permission_data = schemas.PermissionCreate(permissionName="test:read", description="Read test data")
        mock_permission_model = models.Permission(
            PermissionID=uuid.uuid4(),
            PermissionName=permission_data.permissionName,
            Description=permission_data.description
        )
        
        mock_db_session.add.return_value = None
        mock_db_session.commit.return_value = None
        mock_db_session.refresh.return_value = None # Side effect can be setting attributes on mock_permission_model if needed

        # Simulate that the add/commit/refresh assigns the object to the one passed to refresh
        def refresh_side_effect(obj):
            obj = mock_permission_model 
        mock_db_session.refresh.side_effect = refresh_side_effect


        created_permission = permission_service.create_permission(mock_db_session, permission_data)
        
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
        # mock_db_session.refresh.assert_called_once_with(mock_permission_model) # This check is tricky with new instance creation
        assert created_permission.PermissionName == permission_data.permissionName
        assert created_permission.Description == permission_data.description

    def test_create_permission_already_exists_by_name(self, permission_service: PermissionService, mock_db_session: MagicMock):
        permission_data = schemas.PermissionCreate(permissionName="test:read", description="Read test data")
        
        # Simulate IntegrityError for unique constraint violation on PermissionName
        # The error message check in service is specific, so make sure `e.orig` contains the constraint name
        mock_integrity_error = IntegrityError("Mocked IntegrityError", params={}, orig=MagicMock())
        mock_integrity_error.orig.args = ("(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint 'uq_permissions_permissionname'\nDETAIL:  Key (permissionname)=(test:read) already exists.\n",) # Simulate psycopg2 error message
        
        mock_db_session.commit.side_effect = mock_integrity_error

        with pytest.raises(ValueError) as excinfo:
            permission_service.create_permission(mock_db_session, permission_data)
        
        assert f"Permission with name '{permission_data.permissionName}' already exists." in str(excinfo.value)
        mock_db_session.rollback.assert_called_once()

    def test_get_permission_by_id_found(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        mock_permission = models.Permission(PermissionID=perm_id, PermissionName="test:read")
        
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = mock_permission

        permission = permission_service.get_permission_by_id(mock_db_session, perm_id)
        
        mock_db_session.query.assert_called_once_with(models.Permission)
        # Check that filter was called correctly (this is more involved to assert on SQLAlchemy expressions)
        # mock_query.filter.assert_called_once_with(models.Permission.PermissionID == perm_id) # Example, needs careful mocking
        assert permission == mock_permission

    def test_get_permission_by_id_not_found(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = None

        permission = permission_service.get_permission_by_id(mock_db_session, perm_id)
        assert permission is None

    def test_get_permission_by_name_found(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_name = "test:read"
        mock_permission = models.Permission(PermissionID=uuid.uuid4(), PermissionName=perm_name)
        
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = mock_permission

        permission = permission_service.get_permission_by_name(mock_db_session, perm_name)
        assert permission == mock_permission

    def test_list_permissions(self, permission_service: PermissionService, mock_db_session: MagicMock):
        mock_permissions = [models.Permission(PermissionName="p1"), models.Permission(PermissionName="p2")]
        
        mock_query = mock_db_session.query.return_value
        mock_order_by = mock_query.order_by.return_value
        mock_offset = mock_order_by.offset.return_value
        mock_offset.limit.return_value = mock_permissions

        permissions = permission_service.list_permissions(mock_db_session, skip=0, limit=10)
        assert permissions == mock_permissions
        mock_order_by.offset.assert_called_with(0)
        mock_offset.limit.assert_called_with(10)

    def test_count_permissions(self, permission_service: PermissionService, mock_db_session: MagicMock):
        mock_query = mock_db_session.query.return_value
        mock_query.count.return_value = 5
        
        count = permission_service.count_permissions(mock_db_session)
        assert count == 5

    def test_update_permission_success(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        original_permission = models.Permission(PermissionID=perm_id, PermissionName="test:edit", Description="Old desc")
        
        # Mock the get_permission_by_id call within update_permission
        with patch.object(permission_service, 'get_permission_by_id', return_value=original_permission) as mock_get:
            update_data = schemas.PermissionUpdate(description="New desc")
            updated_permission = permission_service.update_permission(mock_db_session, perm_id, update_data)
            
            mock_get.assert_called_once_with(mock_db_session, perm_id)
            mock_db_session.add.assert_called_once_with(original_permission)
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once_with(original_permission)
            
            assert updated_permission.Description == "New desc"
            assert updated_permission == original_permission # The same object is updated

    def test_update_permission_not_found(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        with patch.object(permission_service, 'get_permission_by_id', return_value=None) as mock_get:
            update_data = schemas.PermissionUpdate(description="New desc")
            result = permission_service.update_permission(mock_db_session, perm_id, update_data)
            assert result is None
            mock_db_session.add.assert_not_called()

    def test_delete_permission_success(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        mock_permission = models.Permission(PermissionID=perm_id, PermissionName="test:delete", roles_having_this_permission=[]) # No roles assigned
        
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = mock_permission

        result = permission_service.delete_permission(mock_db_session, perm_id)
        
        assert result is True
        mock_db_session.delete.assert_called_once_with(mock_permission)
        mock_db_session.commit.assert_called_once()

    def test_delete_permission_not_found(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = None

        result = permission_service.delete_permission(mock_db_session, perm_id)
        assert result is False
        mock_db_session.delete.assert_not_called()

    def test_delete_permission_assigned_to_role(self, permission_service: PermissionService, mock_db_session: MagicMock):
        perm_id = uuid.uuid4()
        # Simulate that the permission is assigned to a role
        mock_role = models.Role(RoleName="Test Role") # Simplified mock role
        mock_permission = models.Permission(
            PermissionID=perm_id, 
            PermissionName="test:delete", 
            roles_having_this_permission=[mock_role] # Assigned!
        )
        
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = mock_permission

        with pytest.raises(ValueError) as excinfo:
            permission_service.delete_permission(mock_db_session, perm_id)
        
        assert "cannot be deleted as it is currently assigned" in str(excinfo.value)
        mock_db_session.delete.assert_not_called()
        mock_db_session.rollback.assert_not_called() # No commit attempted, so no rollback in this path
                                                    # If delete was called, then rollback would be checked.
                                                    # The check for roles_having_this_permission happens before db.delete
