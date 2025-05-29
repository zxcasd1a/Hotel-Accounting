import pytest
import uuid
from sqlalchemy.orm import Session
from freezegun import freeze_time # For TOTP tests

import models
import schemas
from user_service import UserService
from tenant_service import TenantService
from auth_service import AuthService
from totp_service import TOTPService # For generating codes for test verification
from config import settings # For token configurations

# Fixtures db_session, services are from conftest.py

@pytest.fixture(scope="module")
def test_user_data() -> dict:
    user_uuid = uuid.uuid4()
    return {
        "email": f"auth_user_{user_uuid}@example.com",
        "password": "AuthPassword123!",
        "firstName": "AuthFlow",
        "lastName": "User"
    }

@pytest.fixture(scope="module") # Changed to module as user is created once for all tests here
def setup_test_user_and_tenant(
    db_session: Session, 
    tenant_service_testing: TenantService, 
    user_service_testing: UserService,
    test_user_data: dict
) -> models.User:
    tenant_name = f"AuthFlow Tenant {uuid.uuid4()}"
    tenant = tenant_service_testing.create_tenant(db_session, schemas.TenantCreate(name=tenant_name))
    
    user_create = schemas.UserCreate(**test_user_data)
    user = user_service_testing.create_user(db_session, user_create, tenant.TenantID)
    db_session.commit() # Ensure user is committed for this module-scoped fixture
    db_session.refresh(user) # Ensure all attributes are loaded
    return user


class TestAuthenticationFlow:

    def test_login_password_success_no_2fa(
        self, db_session: Session, auth_service_testing: AuthService, 
        setup_test_user_and_tenant: models.User, test_user_data: dict
    ):
        user_model = setup_test_user_and_tenant
        
        # Ensure 2FA is disabled for this test path
        two_fa_record = user_model.two_factor_auth
        if two_fa_record and two_fa_record.IsEnabled:
            two_fa_record.IsEnabled = False
            two_fa_record.SecretKey = None
            two_fa_record.RecoveryCodes = None
            db_session.commit()
            db_session.refresh(two_fa_record)

        authenticated_user, temp_token_or_error = auth_service_testing.login_password(
            db_session, test_user_data["email"], test_user_data["password"], str(user_model.TenantID)
        )

        assert authenticated_user is not None
        assert temp_token_or_error is None # No 2FA temp token expected
        assert authenticated_user.UserID == user_model.UserID
        
        # Now generate final tokens (API layer would do this)
        final_tokens = auth_service_testing.generate_final_tokens_for_user(db_session, authenticated_user, is_2fa_authenticated=False)
        assert final_tokens.accessToken is not None
        assert final_tokens.refreshToken is not None
        
        decoded_access = auth_service_testing.decode_token(final_tokens.accessToken)
        assert decoded_access.sub == str(user_model.UserID)
        assert decoded_access.is_2fa_authenticated is False


    def test_full_2fa_lifecycle_and_login(
        self, db_session: Session, auth_service_testing: AuthService, 
        totp_service_testing: TOTPService, # Need direct TOTP service for code generation
        user_service_testing: UserService, # To re-fetch user if needed
        setup_test_user_and_tenant: models.User, test_user_data: dict
    ):
        user = setup_test_user_and_tenant # User from fixture
        user_id = user.UserID
        tenant_id_str = str(user.TenantID)

        # --- 1. Setup 2FA: Start ---
        plain_secret, otp_uri = auth_service_testing.setup_2fa_start(db_session, user_id)
        assert plain_secret is not None
        assert otp_uri is not None
        
        db_session.refresh(user) # Refresh user to get updated two_factor_auth relationship
        assert user.two_factor_auth.SecretKey is not None
        assert user.two_factor_auth.IsEnabled is False

        # --- 2. Enable 2FA: Finish ---
        # Generate a valid TOTP code using the plain_secret
        with freeze_time("2023-01-01 12:00:00"): # Freeze time for consistent code
            totp_generator = pyotp.TOTP(plain_secret)
            valid_totp_code = totp_generator.now()
        
        recovery_codes, error = auth_service_testing.enable_2fa_finish(db_session, user_id, valid_totp_code)
        assert error is None
        assert recovery_codes is not None
        assert len(recovery_codes) > 0
        
        db_session.refresh(user.two_factor_auth) # Refresh the 2FA record
        assert user.two_factor_auth.IsEnabled is True
        assert user.two_factor_auth.RecoveryCodes is not None
        
        # --- 3. Login attempt: Password phase (should now require 2FA) ---
        authed_user_step1, temp_token = auth_service_testing.login_password(
            db_session, test_user_data["email"], test_user_data["password"], tenant_id_str
        )
        assert authed_user_step1 is not None
        assert temp_token is not None # Temporary token for 2FA step
        
        decoded_temp = auth_service_testing.decode_temp_token(temp_token)
        assert decoded_temp.sub == str(user_id)
        assert decoded_temp.type == "2fa_pending"

        # --- 4. Login attempt: 2FA TOTP code verification phase ---
        with freeze_time("2023-01-01 12:00:30"): # Simulate time passing slightly for new code
            totp_generator_login = pyotp.TOTP(plain_secret) # Use the same plain_secret
            login_totp_code = totp_generator_login.now()

        # The auth_service.verify_2fa_login_attempt is used internally by a conceptual API endpoint.
        # Let's simulate what that endpoint would do:
        # 1. Decode temp_token to get user_id (already did this: `decoded_temp.sub`)
        # 2. Call verify_2fa_login_attempt with that user_id and the new login_totp_code
        
        is_2fa_code_valid = auth_service_testing.verify_2fa_login_attempt(db_session, user_id, login_totp_code)
        assert is_2fa_code_valid is True
        
        # If valid, API layer would now issue final tokens
        user_service_testing.update_user_last_login(db_session, user_id) # Update last login
        final_tokens_2fa = auth_service_testing.generate_final_tokens_for_user(db_session, authed_user_step1, is_2fa_authenticated=True)
        assert final_tokens_2fa.accessToken is not None
        
        decoded_access_2fa = auth_service_testing.decode_token(final_tokens_2fa.accessToken)
        assert decoded_access_2fa.sub == str(user_id)
        assert decoded_access_2fa.is_2fa_authenticated is True

        # --- 5. Login attempt: 2FA Recovery code verification phase ---
        assert recovery_codes is not None and len(recovery_codes) > 0
        used_recovery_code = recovery_codes[0]

        # Simulate another login, password phase
        authed_user_step1_rec, temp_token_rec = auth_service_testing.login_password(
            db_session, test_user_data["email"], test_user_data["password"], tenant_id_str
        )
        assert temp_token_rec is not None

        # Verify with recovery code
        is_recovery_code_valid = auth_service_testing.verify_2fa_login_attempt(db_session, user_id, used_recovery_code)
        assert is_recovery_code_valid is True
        
        db_session.refresh(user.two_factor_auth)
        # Check if recovery code was invalidated (removed from the stored list)
        # This requires comparing stored RecoveryCodes before and after.
        # The service re-stores them comma-separated.
        remaining_hashed_codes = totp_service_testing.load_hashed_recovery_codes(user.two_factor_auth.RecoveryCodes)
        assert not totp_service_testing.verify_recovery_code(used_recovery_code, remaining_hashed_codes) # Original code should no longer be valid among remaining

        # --- 6. Disable 2FA ---
        disabled_ok, error_disable = auth_service_testing.disable_2fa(db_session, user_id)
        assert disabled_ok is True
        assert error_disable is None
        db_session.refresh(user.two_factor_auth)
        assert user.two_factor_auth.IsEnabled is False
        assert user.two_factor_auth.SecretKey is None
        assert user.two_factor_auth.RecoveryCodes is None

        # --- 7. Login after disabling 2FA (should not require 2FA) ---
        authed_user_final, temp_token_final = auth_service_testing.login_password(
            db_session, test_user_data["email"], test_user_data["password"], tenant_id_str
        )
        assert authed_user_final is not None
        assert temp_token_final is None # No 2FA temp token
        
        # --- 8. Regenerate Recovery Codes (first re-enable 2FA) ---
        # Re-enable 2FA to test regenerate
        plain_secret_re, _ = auth_service_testing.setup_2fa_start(db_session, user_id)
        with freeze_time("2023-01-01 12:05:00"):
            code_re_enable = pyotp.TOTP(plain_secret_re).now()
        old_recovery_codes, _ = auth_service_testing.enable_2fa_finish(db_session, user_id, code_re_enable)
        assert user.two_factor_auth.IsEnabled

        new_recovery_codes, error_regen = auth_service_testing.regenerate_recovery_codes(db_session, user_id)
        assert error_regen is None
        assert new_recovery_codes is not None
        assert new_recovery_codes != old_recovery_codes # Should be different
        db_session.refresh(user.two_factor_auth)
        # Verify one of the new codes and one of the old (old should fail)
        assert totp_service_testing.verify_recovery_code(new_recovery_codes[0], totp_service_testing.load_hashed_recovery_codes(user.two_factor_auth.RecoveryCodes))
        if old_recovery_codes: # Ensure old_recovery_codes were actually generated
             assert not totp_service_testing.verify_recovery_code(old_recovery_codes[0], totp_service_testing.load_hashed_recovery_codes(user.two_factor_auth.RecoveryCodes))


    def test_refresh_token(
        self, db_session: Session, auth_service_testing: AuthService, 
        setup_test_user_and_tenant: models.User
    ):
        user_model = setup_test_user_and_tenant
        
        # Generate an initial set of tokens
        initial_tokens = auth_service_testing.generate_final_tokens_for_user(db_session, user_model, is_2fa_authenticated=True) # Assume 2FA passed
        
        refresh_token_payload = auth_service_testing.decode_token(initial_tokens.refreshToken) # decode_token also works for refresh if claims are simple
        assert refresh_token_payload is not None
        assert refresh_token_payload.sub == str(user_model.UserID)

        # Simulate using the refresh token to get a new access token
        # This typically would be an API endpoint, but we test the service logic
        # The auth_service doesn't have a direct "refresh_existing_token" method that takes a refresh token string.
        # It has create_access_token. The API layer would decode refresh, validate, then call create_access_token.
        
        # Let's test the creation part based on decoded refresh token data
        new_access_token_str = auth_service_testing.create_access_token(
            user_id=refresh_token_payload.sub,
            tenant_id=refresh_token_payload.tenant_id,
            roles=refresh_token_payload.roles, # Roles might not be in refresh, fetch if needed
            permissions=set(refresh_token_payload.permissions or []), # Permissions might not be in refresh
            is_2fa_authenticated=refresh_token_payload.is_2fa_authenticated
        )
        assert new_access_token_str is not None
        new_access_payload = auth_service_testing.decode_token(new_access_token_str)
        assert new_access_payload.sub == str(user_model.UserID)
        assert new_access_payload.exp > refresh_token_payload.exp # New access token should have later expiry than refresh token's "iat" or original access "exp"
        assert new_access_payload.is_2fa_authenticated == refresh_token_payload.is_2fa_authenticated
        
        # A more complete refresh token flow test would involve:
        # 1. Storing refresh token (e.g., in DB or httpOnly cookie)
        # 2. An endpoint that accepts this refresh token
        # 3. Service logic to validate it (not expired, not revoked)
        # 4. If valid, issue new access token (and potentially new refresh token - rotation)
        # This is partially covered by testing the token creation and decoding.
        # The current auth_service doesn't manage refresh token state (e.g. revocation list).
        pass
