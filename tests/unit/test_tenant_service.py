import pytest
from unittest.mock import MagicMock, patch
import uuid
from sqlalchemy.exc import IntegrityError

import models
import schemas
from tenant_service import TenantService

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def tenant_service():
    return TenantService()

class TestTenantService:
    def test_create_tenant_success(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_data = schemas.TenantCreate(name="Test Tenant", status="Active")
        # The actual model instance is created inside the service method.
        # We need to check that db.add, commit, refresh are called, and the returned object matches data.

        # To capture the object passed to db.add:
        added_object_capture = None
        def capture_add(obj):
            nonlocal added_object_capture
            added_object_capture = obj
        mock_db_session.add.side_effect = capture_add
        
        # Simulate refresh populating the object (though not strictly necessary for this test's assertions)
        def refresh_side_effect(obj):
            obj.TenantID = uuid.uuid4() # Simulate DB assigning an ID
            # Other DB defaults like CreatedAt, UpdatedAt could be set here if needed for assertions
        mock_db_session.refresh.side_effect = refresh_side_effect

        created_tenant = tenant_service.create_tenant(mock_db_session, tenant_data)
        
        assert added_object_capture is not None
        mock_db_session.add.assert_called_once_with(added_object_capture)
        mock_db_session.commit.assert_called_once()
        mock_db_session.refresh.assert_called_once_with(added_object_capture)
        
        assert added_object_capture.Name == tenant_data.name
        assert added_object_capture.Status == tenant_data.status
        assert created_tenant == added_object_capture # Service should return the db model instance

    def test_create_tenant_integrity_error(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_data = schemas.TenantCreate(name="Existing Tenant")
        
        mock_integrity_error = IntegrityError("Mocked IntegrityError", params={}, orig="some db error")
        mock_db_session.commit.side_effect = mock_integrity_error

        with pytest.raises(ValueError) as excinfo:
            tenant_service.create_tenant(mock_db_session, tenant_data)
        
        assert "Could not create tenant. Integrity error" in str(excinfo.value)
        mock_db_session.rollback.assert_called_once()

    def test_get_tenant_by_id_found(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        mock_tenant = models.Tenant(TenantID=tenant_id, Name="Test Tenant")
        
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = mock_tenant

        tenant = tenant_service.get_tenant_by_id(mock_db_session, tenant_id)
        
        mock_db_session.query.assert_called_once_with(models.Tenant)
        # To assert filter: mock_query.filter.assert_called_once_with(models.Tenant.TenantID == tenant_id)
        # This requires more complex assertion on SQLAlchemy comparison objects.
        assert tenant == mock_tenant

    def test_get_tenant_by_id_not_found(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        mock_query = mock_db_session.query.return_value
        mock_filter = mock_query.filter.return_value
        mock_filter.first.return_value = None

        tenant = tenant_service.get_tenant_by_id(mock_db_session, tenant_id)
        assert tenant is None

    def test_list_tenants(self, tenant_service: TenantService, mock_db_session: MagicMock):
        mock_tenants_list = [models.Tenant(Name="T1"), models.Tenant(Name="T2")]
        
        mock_query = mock_db_session.query.return_value
        mock_offset = mock_query.offset.return_value
        mock_offset.limit.return_value = mock_tenants_list

        tenants = tenant_service.list_tenants(mock_db_session, skip=5, limit=15)
        
        mock_query.offset.assert_called_once_with(5)
        mock_offset.limit.assert_called_once_with(15)
        assert tenants == mock_tenants_list
        
    def test_count_tenants(self, tenant_service: TenantService, mock_db_session: MagicMock):
        mock_query = mock_db_session.query.return_value
        mock_query.count.return_value = 42
        
        count = tenant_service.count_tenants(mock_db_session)
        assert count == 42


    def test_update_tenant_success(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        original_tenant = models.Tenant(TenantID=tenant_id, Name="Old Name", Status="Active")
        update_data = schemas.TenantUpdate(name="New Name", status="Suspended")

        # Patch the get_tenant_by_id call within the update_tenant method
        with patch.object(tenant_service, 'get_tenant_by_id', return_value=original_tenant) as mock_get_by_id:
            updated_tenant = tenant_service.update_tenant(mock_db_session, tenant_id, update_data)
            
            mock_get_by_id.assert_called_once_with(mock_db_session, tenant_id)
            mock_db_session.add.assert_called_once_with(original_tenant) # add is called to mark dirty
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once_with(original_tenant)
            
            assert updated_tenant.Name == "New Name"
            assert updated_tenant.Status == "Suspended"
            assert updated_tenant == original_tenant # Should be the same instance

    def test_update_tenant_partial_update(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        original_tenant = models.Tenant(TenantID=tenant_id, Name="Original Name", Status="Active")
        update_data = schemas.TenantUpdate(name="Updated Name Only") # Status not provided

        with patch.object(tenant_service, 'get_tenant_by_id', return_value=original_tenant):
            updated_tenant = tenant_service.update_tenant(mock_db_session, tenant_id, update_data)
            
            assert updated_tenant.Name == "Updated Name Only"
            assert updated_tenant.Status == "Active" # Status should remain unchanged

    def test_update_tenant_not_found(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        update_data = schemas.TenantUpdate(name="New Name")

        with patch.object(tenant_service, 'get_tenant_by_id', return_value=None) as mock_get_by_id:
            result = tenant_service.update_tenant(mock_db_session, tenant_id, update_data)
            
            assert result is None
            mock_db_session.add.assert_not_called()
            mock_db_session.commit.assert_not_called()

    def test_update_tenant_integrity_error(self, tenant_service: TenantService, mock_db_session: MagicMock):
        tenant_id = uuid.uuid4()
        original_tenant = models.Tenant(TenantID=tenant_id, Name="Old Name")
        update_data = schemas.TenantUpdate(name="NameThatCausesIntegrityError")

        mock_integrity_error = IntegrityError("Mocked IntegrityError", params={}, orig="some db error")
        mock_db_session.commit.side_effect = mock_integrity_error
        
        with patch.object(tenant_service, 'get_tenant_by_id', return_value=original_tenant):
            with pytest.raises(ValueError) as excinfo:
                tenant_service.update_tenant(mock_db_session, tenant_id, update_data)
            
            assert "Could not update tenant. Integrity error" in str(excinfo.value)
            mock_db_session.rollback.assert_called_once()
