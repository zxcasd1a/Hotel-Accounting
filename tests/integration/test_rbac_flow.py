import pytest
import uuid
from sqlalchemy.orm import Session

import models
import schemas
from user_service import UserService
from tenant_service import TenantService
from permission_service import PermissionService
from role_service import RoleService
from auth_service import AuthService 
from totp_service import TOTPService # For auth_service dependency

# Fixtures from conftest.py

@pytest.fixture(scope="module")
def rbac_services(db_session: Session): # Use a single session for module setup if possible
    permission_service = PermissionService()
    role_service = RoleService(permission_service)
    user_service = UserService()
    tenant_service = TenantService()
    # Auth service for token generation
    totp_service = TOTPService()
    auth_service = AuthService(user_service, totp_service)
    return permission_service, role_service, user_service, tenant_service, auth_service

@pytest.fixture(scope="module")
def setup_rbac_base_data(db_session: Session, rbac_services):
    perm_service, role_service, user_service, tenant_service, _ = rbac_services
    
    # Permissions
    perm_doc_read = perm_service.create_permission(db_session, schemas.PermissionCreate(permissionName="doc:read", description="Read documents"))
    perm_doc_write = perm_service.create_permission(db_session, schemas.PermissionCreate(permissionName="doc:write", description="Write documents"))
    perm_user_manage = perm_service.create_permission(db_session, schemas.PermissionCreate(permissionName="user:manage", description="Manage users"))
    db_session.commit()

    # Tenant
    tenant = tenant_service.create_tenant(db_session, schemas.TenantCreate(name=f"RBAC Tenant {uuid.uuid4()}"))
    db_session.commit()

    # Roles
    role_viewer = role_service.create_role(db_session, schemas.RoleCreate(roleName="DocumentViewer"), tenant_id=tenant.TenantID)
    role_editor = role_service.create_role(db_session, schemas.RoleCreate(roleName="DocumentEditor"), tenant_id=tenant.TenantID)
    role_sys_admin = role_service.create_role(db_session, schemas.RoleCreate(roleName="SystemAdmin", isSystemRole=True)) # System role
    db_session.commit()

    # Assign permissions to roles
    role_service.assign_permission_to_role(db_session, role_viewer.RoleID, perm_doc_read.PermissionID)
    role_service.assign_permission_to_role(db_session, role_editor.RoleID, perm_doc_read.PermissionID)
    role_service.assign_permission_to_role(db_session, role_editor.RoleID, perm_doc_write.PermissionID)
    role_service.assign_permission_to_role(db_session, role_sys_admin.RoleID, perm_user_manage.PermissionID)
    role_service.assign_permission_to_role(db_session, role_sys_admin.RoleID, perm_doc_read.PermissionID) # Sys admin can also read
    db_session.commit()
    
    # Users
    user1_email = f"rbac_user1_{uuid.uuid4()}@example.com"
    user1 = user_service.create_user(db_session, schemas.UserCreate(email=user1_email, password="password"), tenant.TenantID)
    
    user2_email = f"rbac_user2_{uuid.uuid4()}@example.com"
    user2 = user_service.create_user(db_session, schemas.UserCreate(email=user2_email, password="password"), tenant.TenantID)
    db_session.commit()

    return {
        "tenant": tenant,
        "user1": user1, "user2": user2,
        "role_viewer": role_viewer, "role_editor": role_editor, "role_sys_admin": role_sys_admin,
        "perm_doc_read": perm_doc_read, "perm_doc_write": perm_doc_write, "perm_user_manage": perm_user_manage
    }


class TestRBACFlow:

    def test_user_role_assignment_and_effective_permissions(
        self, db_session: Session, rbac_services, setup_rbac_base_data
    ):
        perm_service, role_service, user_service, _, _ = rbac_services
        data = setup_rbac_base_data

        user1 = data["user1"]
        role_viewer = data["role_viewer"]
        role_editor = data["role_editor"]

        # Assign 'DocumentViewer' role to user1
        user_service.assign_role_to_user(db_session, user1.UserID, role_viewer.RoleID)
        db_session.commit()
        
        # Check effective permissions for user1
        perms_user1 = user_service.get_user_effective_permissions(db_session, user1.UserID)
        assert {"doc:read"} == perms_user1

        # Assign 'DocumentEditor' role to user1 (now has Viewer and Editor)
        user_service.assign_role_to_user(db_session, user1.UserID, role_editor.RoleID)
        db_session.commit()
        
        perms_user1_updated = user_service.get_user_effective_permissions(db_session, user1.UserID)
        assert {"doc:read", "doc:write"} == perms_user1_updated

        # Check user's roles
        user1_roles = user_service.get_user_roles(db_session, user1.UserID)
        user1_role_names = {r.RoleName for r in user1_roles}
        assert {role_viewer.RoleName, role_editor.RoleName} == user1_role_names

        # Remove 'DocumentViewer' role from user1
        user_service.remove_role_from_user(db_session, user1.UserID, role_viewer.RoleID)
        db_session.commit()
        
        perms_user1_after_remove = user_service.get_user_effective_permissions(db_session, user1.UserID)
        # Still has doc:read and doc:write through DocumentEditor
        assert {"doc:read", "doc:write"} == perms_user1_after_remove 
                                                                    

    def test_system_role_assignment_and_permissions(
        self, db_session: Session, rbac_services, setup_rbac_base_data
    ):
        perm_service, role_service, user_service, _, _ = rbac_services
        data = setup_rbac_base_data

        user2 = data["user2"]
        role_sys_admin = data["role_sys_admin"] # This is a system role

        # Assign system role to user2
        user_service.assign_role_to_user(db_session, user2.UserID, role_sys_admin.RoleID)
        db_session.commit()

        perms_user2 = user_service.get_user_effective_permissions(db_session, user2.UserID)
        assert {data["perm_user_manage"].PermissionName, data["perm_doc_read"].PermissionName}.issubset(perms_user2)


    def test_jwt_token_contains_roles_and_permissions(
        self, db_session: Session, rbac_services, setup_rbac_base_data
    ):
        perm_service, role_service, user_service, _, auth_service = rbac_services
        data = setup_rbac_base_data
        user1 = data["user1"] # User1 has DocumentEditor by end of previous relevant test setup
                              # (but tests are isolated, so re-assign for clarity)

        # Ensure user1 has DocumentEditor role for this test
        current_roles = user_service.get_user_roles(db_session, user1.UserID)
        if not any(r.RoleID == data["role_editor"].RoleID for r in current_roles):
            user_service.assign_role_to_user(db_session, user1.UserID, data["role_editor"].RoleID)
            db_session.commit()
        # Also ensure viewer role is not assigned if we want precise permission set
        if any(r.RoleID == data["role_viewer"].RoleID for r in current_roles):
             user_service.remove_role_from_user(db_session, user1.UserID, data["role_viewer"].RoleID)
             db_session.commit()


        # Simulate successful login and token generation for user1
        # (assuming 2FA is not enabled or passed for this user for simplicity here)
        # The generate_final_tokens_for_user method fetches fresh roles/permissions
        token_response = auth_service.generate_final_tokens_for_user(db_session, user1, is_2fa_authenticated=True)
        
        assert token_response.accessToken is not None
        decoded_token = auth_service.decode_token(token_response.accessToken)

        assert decoded_token is not None
        assert decoded_token.sub == str(user1.UserID)
        
        # Expected roles and permissions from 'DocumentEditor'
        expected_roles = {data["role_editor"].RoleName}
        expected_permissions = {data["perm_doc_read"].PermissionName, data["perm_doc_write"].PermissionName}

        assert set(decoded_token.roles) == expected_roles
        assert set(decoded_token.permissions) == expected_permissions

    def test_role_permission_modification_reflects_in_user_permissions(
        self, db_session: Session, rbac_services, setup_rbac_base_data
    ):
        perm_service, role_service, user_service, _, auth_service = rbac_services
        data = setup_rbac_base_data
        user2 = data["user2"] # User for this test
        role_viewer = data["role_viewer"]
        perm_doc_write = data["perm_doc_write"] # A permission not initially in Viewer role

        # Assign Viewer role to user2
        user_service.assign_role_to_user(db_session, user2.UserID, role_viewer.RoleID)
        db_session.commit()

        initial_perms = user_service.get_user_effective_permissions(db_session, user2.UserID)
        assert {data["perm_doc_read"].PermissionName} == initial_perms
        assert data["perm_doc_write"].PermissionName not in initial_perms

        # Now, add 'doc:write' permission to the 'DocumentViewer' role
        role_service.assign_permission_to_role(db_session, role_viewer.RoleID, perm_doc_write.PermissionID)
        db_session.commit()
        
        # Verify user2 now has 'doc:write' permission
        updated_perms = user_service.get_user_effective_permissions(db_session, user2.UserID)
        assert {data["perm_doc_read"].PermissionName, perm_doc_write.PermissionName} == updated_perms

        # Test token generation reflects this change
        token_response_updated = auth_service.generate_final_tokens_for_user(db_session, user2, is_2fa_authenticated=True)
        decoded_updated = auth_service.decode_token(token_response_updated.accessToken)
        assert set(decoded_updated.permissions) == updated_perms
        
        # Remove 'doc:write' from 'DocumentViewer' role
        role_service.remove_permission_from_role(db_session, role_viewer.RoleID, perm_doc_write.PermissionID)
        db_session.commit()
        
        final_perms = user_service.get_user_effective_permissions(db_session, user2.UserID)
        assert {data["perm_doc_read"].PermissionName} == final_perms

    def test_list_roles_integration(self, db_session: Session, rbac_services, setup_rbac_base_data):
        perm_service, role_service, _, _, _ = rbac_services
        tenant = setup_rbac_base_data["tenant"]
        
        # List system roles
        system_roles = role_service.list_roles(db_session, tenant_id=None) # Default is system roles
        assert any(r.RoleName == setup_rbac_base_data["role_sys_admin"].RoleName for r in system_roles)
        for r in system_roles:
            assert r.IsSystemRole is True

        # List tenant roles
        tenant_roles = role_service.list_roles(db_session, tenant_id=tenant.TenantID)
        assert any(r.RoleName == setup_rbac_base_data["role_viewer"].RoleName for r in tenant_roles)
        assert any(r.RoleName == setup_rbac_base_data["role_editor"].RoleName for r in tenant_roles)
        for r in tenant_roles:
            assert r.TenantID == tenant.TenantID
            assert r.IsSystemRole is False
            
        # List tenant roles including system roles
        all_roles_for_tenant_view = role_service.list_roles(db_session, tenant_id=tenant.TenantID, include_system_roles=True)
        assert any(r.RoleName == setup_rbac_base_data["role_viewer"].RoleName for r in all_roles_for_tenant_view)
        assert any(r.RoleName == setup_rbac_base_data["role_sys_admin"].RoleName for r in all_roles_for_tenant_view)

    # Test deletion constraints (e.g., cannot delete role if in use)
    def test_delete_role_in_use_constraint(self, db_session: Session, rbac_services, setup_rbac_base_data):
        perm_service, role_service, user_service, _, _ = rbac_services
        user1 = setup_rbac_base_data["user1"]
        role_editor = setup_rbac_base_data["role_editor"]

        # Ensure user1 has role_editor
        user_service.assign_role_to_user(db_session, user1.UserID, role_editor.RoleID)
        db_session.commit()

        with pytest.raises(ValueError, match="cannot be deleted as it is currently assigned to one or more users"):
            role_service.delete_role(db_session, role_editor.RoleID)
            
    # Test deletion of permission in use constraint
    def test_delete_permission_in_use_constraint(self, db_session: Session, rbac_services, setup_rbac_base_data):
        perm_service, _, _, _, _ = rbac_services
        perm_doc_read = setup_rbac_base_data["perm_doc_read"] # This is assigned to Viewer and Editor

        with pytest.raises(ValueError, match="cannot be deleted as it is currently assigned to one or more roles"):
            perm_service.delete_permission(db_session, perm_doc_read.PermissionID)
