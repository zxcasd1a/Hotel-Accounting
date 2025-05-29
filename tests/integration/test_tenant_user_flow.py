import pytest
import uuid
from sqlalchemy.orm import Session # For type hinting, actual session from fixture

import models # To check DB directly if needed
import schemas
from tenant_service import TenantService
from user_service import UserService
from hashing import Hash # For checking password if necessary, though not usually done in flow tests

# Fixtures like db_session, tenant_service_testing, user_service_testing
# are expected to be defined in conftest.py

def test_tenant_creation_and_retrieval(db_session: Session, tenant_service_testing: TenantService):
    tenant_name = f"Integration Test Tenant {uuid.uuid4()}"
    tenant_create_data = schemas.TenantCreate(name=tenant_name, status="Active")
    
    # Create Tenant
    created_tenant_model = tenant_service_testing.create_tenant(db_session, tenant_create_data)
    assert created_tenant_model is not None
    assert created_tenant_model.TenantID is not None
    assert created_tenant_model.Name == tenant_name
    assert created_tenant_model.Status == "Active"

    # Retrieve Tenant by ID
    retrieved_tenant = tenant_service_testing.get_tenant_by_id(db_session, created_tenant_model.TenantID)
    assert retrieved_tenant is not None
    assert retrieved_tenant.TenantID == created_tenant_model.TenantID
    assert retrieved_tenant.Name == tenant_name

    # List Tenants (check if ours is in the list)
    all_tenants = tenant_service_testing.list_tenants(db_session, limit=100) # Assuming not too many tenants
    found_in_list = any(t.TenantID == created_tenant_model.TenantID for t in all_tenants)
    assert found_in_list

    # Count tenants
    initial_count = tenant_service_testing.count_tenants(db_session)
    assert initial_count > 0


def test_full_tenant_user_lifecycle(
    db_session: Session, 
    tenant_service_testing: TenantService, 
    user_service_testing: UserService
):
    # 1. Create Tenant
    tenant_name = f"Lifecycle Tenant {uuid.uuid4()}"
    tenant_create_data = schemas.TenantCreate(name=tenant_name, status="Active")
    tenant = tenant_service_testing.create_tenant(db_session, tenant_create_data)
    assert tenant is not None
    original_tenant_name = tenant.Name

    # 2. Create User in Tenant
    user_email = f"user_{uuid.uuid4()}@lifecycletest.com"
    user_password = "strongPassword123"
    user_create_data = schemas.UserCreate(
        email=user_email, 
        password=user_password, 
        firstName="Life", 
        lastName="Cycle"
    )
    user = user_service_testing.create_user(db_session, user_create_data, tenant.TenantID)
    assert user is not None
    assert user.Email == user_email
    assert user.TenantID == tenant.TenantID
    assert user.IsActive is True
    assert Hash.verify_password(user_password, user.PasswordHash) # Check password was hashed

    # 3. Retrieve User
    retrieved_user = user_service_testing.get_user_by_id(db_session, user.UserID)
    assert retrieved_user is not None
    assert retrieved_user.Email == user_email

    retrieved_user_by_email = user_service_testing.get_user_by_email_and_tenant_id(db_session, user_email, tenant.TenantID)
    assert retrieved_user_by_email is not None
    assert retrieved_user_by_email.UserID == user.UserID

    # 4. List Users in Tenant
    users_in_tenant = user_service_testing.list_users_by_tenant(db_session, tenant.TenantID)
    assert len(users_in_tenant) >= 1
    assert any(u.UserID == user.UserID for u in users_in_tenant)
    
    # Count users in tenant
    user_count = user_service_testing.count_users_by_tenant(db_session, tenant.TenantID)
    assert user_count >= 1


    # 5. Update User
    user_update_data = schemas.UserUpdate(firstName="UpdatedLife")
    updated_user = user_service_testing.update_user(db_session, user.UserID, user_update_data)
    assert updated_user is not None
    assert updated_user.FirstName == "UpdatedLife"
    assert updated_user.Email == user_email # Email not changed

    # Admin update (e.g., isActive)
    user_admin_update_data = schemas.UserAdminUpdate(isActive=False)
    updated_user_admin = user_service_testing.update_user(db_session, user.UserID, user_admin_update_data)
    assert updated_user_admin is not None
    assert updated_user_admin.IsActive is False

    # Reactivate
    user_admin_update_data_reactivate = schemas.UserAdminUpdate(isActive=True)
    user_service_testing.update_user(db_session, user.UserID, user_admin_update_data_reactivate)


    # 6. Update User Password
    new_password = "newStrongPassword456"
    password_updated = user_service_testing.update_user_password(db_session, user.UserID, new_password)
    assert password_updated is True
    db_user_recheck = user_service_testing.get_user_by_id(db_session, user.UserID) # Re-fetch
    assert Hash.verify_password(new_password, db_user_recheck.PasswordHash)
    assert not Hash.verify_password(user_password, db_user_recheck.PasswordHash) # Old password fails

    # 7. Update Tenant
    tenant_update_data = schemas.TenantUpdate(name=f"Updated {tenant_name}", status="Suspended")
    updated_tenant = tenant_service_testing.update_tenant(db_session, tenant.TenantID, tenant_update_data)
    assert updated_tenant is not None
    assert updated_tenant.Name == f"Updated {tenant_name}"
    assert updated_tenant.Status == "Suspended"
    assert updated_tenant.Name != original_tenant_name

    # 8. Deleting Tenant (should cascade and delete user due to FK ondelete="CASCADE" in models/DB)
    # This is harder to test cleanly without specific delete methods for cleanup.
    # If TenantService had a delete_tenant method, we'd call it.
    # For now, assume DB cascade works or manual cleanup for tests.
    # If we were to test user deletion:
    # user_service_testing.delete_user(db_session, user.UserID) # (if such a method existed)
    # assert user_service_testing.get_user_by_id(db_session, user.UserID) is None
    #
    # To test cascade, we'd need a TenantService.delete_tenant method.
    # Let's assume we add a simple delete for testing purposes or rely on test isolation for cleanup.
    # For this test, we won't delete to keep it focused on create/update/retrieve.
    # Cleanup is handled by transaction rollback in db_session fixture.

    # Check 2FA record was created for user
    two_fa_record = user_service_testing.get_2fa_record(db_session, user.UserID)
    assert two_fa_record is not None
    assert two_fa_record.UserID == user.UserID
    assert two_fa_record.IsEnabled is False # Default
    assert user.two_factor_auth is not None # Check relationship access
    assert user.two_factor_auth.IsEnabled is False
    
    is_2fa_enabled_check = user_service_testing.is_user_2fa_enabled(db_session, user.UserID)
    assert is_2fa_enabled_check is False
