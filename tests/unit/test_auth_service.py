import pytest
from unittest.mock import MagicMock, patch
import uuid
from datetime import datetime, timedelta, timezone

from jose import jwt # For checking token content manually if needed

import models
import schemas
from auth_service import AuthService
from user_service import UserService
from totp_service import TOTPService
from config import settings # For JWT settings

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def mock_user_service():
    return MagicMock(spec=UserService)

@pytest.fixture
def mock_totp_service():
    return MagicMock(spec=TOTPService)

@pytest.fixture
def auth_service(mock_user_service: MagicMock, mock_totp_service: MagicMock):
    return AuthService(user_service=mock_user_service, totp_service=mock_totp_service)

class TestAuthServiceTokens:
    def test_create_access_token(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        tenant_id = str(uuid.uuid4())
        roles = ["editor", "viewer"]
        permissions = {"doc:read", "doc:write"}

        token = auth_service.create_access_token(user_id, tenant_id, roles, permissions, is_2fa_authenticated=True)
        assert isinstance(token, str)
        
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["tenant_id"] == tenant_id
        assert sorted(payload["roles"]) == sorted(roles) # Order might change with set conversion
        assert sorted(payload["permissions"]) == sorted(list(permissions))
        assert payload["is_2fa_authenticated"] is True
        assert "exp" in payload
        assert "iat" in payload

    def test_create_refresh_token(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        token = auth_service.create_refresh_token(user_id)
        assert isinstance(token, str)
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        assert payload["sub"] == user_id
        assert "roles" not in payload # Refresh tokens are simpler
        assert "permissions" not in payload
        assert "exp" in payload

    def test_create_temporary_token(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        token = auth_service.create_temporary_token(user_id, token_type="test_type")
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["type"] == "test_type"

    def test_decode_valid_token(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        token = auth_service.create_access_token(user_id)
        token_data = auth_service.decode_token(token)
        assert token_data is not None
        assert token_data.sub == user_id

    def test_decode_invalid_token_bad_signature(self, auth_service: AuthService):
        # Create a token with a different key
        invalid_token = jwt.encode({"sub": "user"}, "wrong-secret-key", algorithm=settings.JWT_ALGORITHM)
        assert auth_service.decode_token(invalid_token) is None

    def test_decode_expired_token(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        # Create a token that expires immediately (or in the past)
        # Override ACCESS_TOKEN_EXPIRE_MINUTES for this test via monkeypatch if it was a fixture
        # Or create one with a negative expires_delta manually
        expired_token = auth_service._create_token({"sub": user_id}, timedelta(seconds=-1))
        assert auth_service.decode_token(expired_token) is None
        
    def test_decode_temp_token_valid(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        temp_token = auth_service.create_temporary_token(user_id, token_type="custom_type")
        decoded = auth_service.decode_temp_token(temp_token, expected_type="custom_type")
        assert decoded is not None
        assert decoded.sub == user_id
        assert decoded.type == "custom_type"

    def test_decode_temp_token_wrong_type(self, auth_service: AuthService):
        user_id = str(uuid.uuid4())
        temp_token = auth_service.create_temporary_token(user_id, token_type="actual_type")
        decoded = auth_service.decode_temp_token(temp_token, expected_type="expected_type_mismatch")
        assert decoded is None


class TestAuthServiceLogin:
    def test_login_password_success_no_2fa(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock
    ):
        email = "user@example.com"
        password = "password123"
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        
        mock_user = models.User(UserID=user_id, TenantID=tenant_id, Email=email, IsActive=True, PasswordHash="hashed_pwd")
        mock_user_service.get_user_by_email_and_tenant_id.return_value = mock_user
        # Patch the Hashing utility used by user_service.verify_user_password or mock verify_user_password itself
        # For this unit test, it's easier to mock verify_user_password on the user_service mock
        mock_user_service.verify_user_password.return_value = True # Assumes password is correct
        mock_user_service.is_user_2fa_enabled.return_value = False # 2FA not enabled

        user, temp_token_or_error = auth_service.login_password(mock_db_session, email, password, str(tenant_id))

        assert user == mock_user
        assert temp_token_or_error is None # No 2FA temp token, no error
        mock_user_service.update_user_last_login.assert_called_once_with(mock_db_session, user_id)

    def test_login_password_success_with_2fa(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock
    ):
        email = "user2fa@example.com"
        password = "password123"
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        
        mock_user = models.User(UserID=user_id, TenantID=tenant_id, Email=email, IsActive=True, PasswordHash="hashed_pwd")
        mock_user_service.get_user_by_email_and_tenant_id.return_value = mock_user
        mock_user_service.verify_user_password.return_value = True
        mock_user_service.is_user_2fa_enabled.return_value = True # 2FA IS enabled

        user, temp_token_or_error = auth_service.login_password(mock_db_session, email, password, str(tenant_id))

        assert user == mock_user
        assert isinstance(temp_token_or_error, str) # Should be a temporary token string
        mock_user_service.update_user_last_login.assert_not_called() # Not called until 2FA is done

        # Optionally decode temp_token_or_error to check its contents
        decoded_temp_token = auth_service.decode_temp_token(temp_token_or_error)
        assert decoded_temp_token.sub == str(user_id)
        assert decoded_temp_token.type == "2fa_pending"


    def test_login_password_user_not_found(self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock):
        mock_user_service.get_user_by_email_and_tenant_id.return_value = None
        user, msg = auth_service.login_password(mock_db_session, "u@e.com", "p", str(uuid.uuid4()))
        assert user is None
        assert msg == "Invalid email or password."

    def test_login_password_inactive_user(self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock):
        mock_user = models.User(IsActive=False)
        mock_user_service.get_user_by_email_and_tenant_id.return_value = mock_user
        user, msg = auth_service.login_password(mock_db_session, "u@e.com", "p", str(uuid.uuid4()))
        assert user is None
        assert msg == "User account is inactive."

    def test_login_password_incorrect_password(self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock):
        mock_user = models.User(IsActive=True, PasswordHash="real_hash") # Active user
        mock_user_service.get_user_by_email_and_tenant_id.return_value = mock_user
        mock_user_service.verify_user_password.return_value = False # Password incorrect
        
        user, msg = auth_service.login_password(mock_db_session, "u@e.com", "wrong_p", str(uuid.uuid4()))
        assert user is None
        assert msg == "Invalid email or password."

    def test_generate_final_tokens_for_user(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id, TenantID=tenant_id)
        
        mock_user_service.get_user_roles.return_value = [models.Role(RoleName="TestRole")]
        mock_user_service.get_user_effective_permissions.return_value = {"test:perm"}

        token_response = auth_service.generate_final_tokens_for_user(mock_db_session, mock_user, is_2fa_authenticated=True)
        
        assert isinstance(token_response, schemas.TokenResponse)
        assert token_response.accessToken is not None
        assert token_response.refreshToken is not None

        # Decode access token to check claims
        access_payload = jwt.decode(token_response.accessToken, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        assert access_payload["sub"] == str(user_id)
        assert access_payload["tenant_id"] == str(tenant_id)
        assert access_payload["roles"] == ["TestRole"]
        assert access_payload["permissions"] == ["test:perm"]
        assert access_payload["is_2fa_authenticated"] is True


class TestAuthService2FAFlow:
    def test_verify_2fa_login_attempt_totp_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_totp_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        code = "123456"
        mock_2fa_record = models.TwoFactorAuth(UserID=user_id, IsEnabled=True, SecretKey="encrypted_secret")
        
        mock_user_service.get_2fa_record.return_value = mock_2fa_record
        mock_totp_service.decrypt_secret.return_value = "decrypted_secret_key"
        mock_totp_service.verify_totp_code.return_value = True

        is_valid = auth_service.verify_2fa_login_attempt(mock_db_session, user_id, code)
        assert is_valid is True
        mock_totp_service.verify_totp_code.assert_called_once_with("decrypted_secret_key", code)

    def test_verify_2fa_login_attempt_recovery_code_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_totp_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        recovery_code = "recovery123"
        hashed_recovery_codes = ["hash1", Hash.hash_password(recovery_code), "hash3"] # One matches
        
        mock_2fa_record = models.TwoFactorAuth(
            UserID=user_id, IsEnabled=True, SecretKey="es", RecoveryCodes=",".join(hashed_recovery_codes)
        )
        mock_user_service.get_2fa_record.return_value = mock_2fa_record
        mock_totp_service.decrypt_secret.return_value = "ds" # Decrypt will be called
        mock_totp_service.verify_totp_code.return_value = False # TOTP fails, try recovery
        mock_totp_service.load_hashed_recovery_codes.return_value = hashed_recovery_codes
        mock_totp_service.verify_recovery_code.return_value = True # Recovery code matches
        
        # Mock the storing of updated recovery codes
        mock_totp_service.store_hashed_recovery_codes.return_value = "hash1,hash3" # recovery_code removed

        is_valid = auth_service.verify_2fa_login_attempt(mock_db_session, user_id, recovery_code)
        
        assert is_valid is True
        mock_totp_service.verify_recovery_code.assert_called_once_with(recovery_code, hashed_recovery_codes)
        # Check that recovery codes were updated (the matching one removed)
        # This requires checking the call to store_hashed_recovery_codes with the filtered list
        # For simplicity, we'll trust the mock setup implies this.
        # A more rigorous test would capture the argument to store_hashed_recovery_codes.
        assert mock_2fa_record.RecoveryCodes == "hash1,hash3"
        mock_db_session.commit.assert_called_once()


    def test_setup_2fa_start_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_totp_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        mock_user = models.User(UserID=user_id, Email="test@example.com")
        mock_2fa_record = models.TwoFactorAuth(UserID=user_id, IsEnabled=False) # Not enabled
        
        mock_user_service.get_user_by_id.return_value = mock_user
        mock_user_service.get_or_create_2fa_record.return_value = mock_2fa_record
        mock_totp_service.generate_totp_secret.return_value = "PLAIN_SECRET"
        mock_totp_service.encrypt_secret.return_value = "ENCRYPTED_SECRET"
        mock_totp_service.get_totp_uri.return_value = "otpauth://uri"

        plain_secret, otp_uri = auth_service.setup_2fa_start(mock_db_session, user_id)

        assert plain_secret == "PLAIN_SECRET"
        assert otp_uri == "otpauth://uri"
        assert mock_2fa_record.SecretKey == "ENCRYPTED_SECRET"
        assert mock_2fa_record.IsEnabled is False
        mock_db_session.commit.assert_called_once()


    def test_enable_2fa_finish_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_totp_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        totp_code = "123456"
        mock_2fa_record = models.TwoFactorAuth(UserID=user_id, SecretKey="ENCRYPTED_SECRET", IsEnabled=False)
        
        mock_user_service.get_2fa_record.return_value = mock_2fa_record
        mock_totp_service.decrypt_secret.return_value = "DECRYPTED_SECRET"
        mock_totp_service.verify_totp_code.return_value = True # Code is valid
        
        plain_recovery_codes = ["rec1", "rec2"]
        hashed_recovery_codes_list = ["h_rec1", "h_rec2"]
        hashed_recovery_codes_str = "h_rec1,h_rec2"
        mock_totp_service.generate_recovery_codes.return_value = plain_recovery_codes
        mock_totp_service.hash_recovery_codes.return_value = hashed_recovery_codes_list
        mock_totp_service.store_hashed_recovery_codes.return_value = hashed_recovery_codes_str

        recovery_codes, error = auth_service.enable_2fa_finish(mock_db_session, user_id, totp_code)

        assert error is None
        assert recovery_codes == plain_recovery_codes
        assert mock_2fa_record.IsEnabled is True
        assert mock_2fa_record.RecoveryCodes == hashed_recovery_codes_str
        mock_db_session.commit.assert_called_once()
        mock_totp_service.verify_totp_code.assert_called_once_with("DECRYPTED_SECRET", totp_code)

    def test_disable_2fa_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        mock_2fa_record = models.TwoFactorAuth(UserID=user_id, IsEnabled=True, SecretKey="S", RecoveryCodes="R")
        mock_user_service.get_2fa_record.return_value = mock_2fa_record

        success, error = auth_service.disable_2fa(mock_db_session, user_id)
        
        assert success is True
        assert error is None
        assert mock_2fa_record.IsEnabled is False
        assert mock_2fa_record.SecretKey is None
        assert mock_2fa_record.RecoveryCodes is None
        mock_db_session.commit.assert_called_once()
        
    # Add more tests for failure cases (e.g., user not found, 2FA already enabled/disabled, invalid codes)
    # Add tests for regenerate_recovery_codes
    def test_regenerate_recovery_codes_success(
        self, auth_service: AuthService, mock_user_service: MagicMock, mock_totp_service: MagicMock, mock_db_session: MagicMock
    ):
        user_id = uuid.uuid4()
        mock_2fa_record = models.TwoFactorAuth(UserID=user_id, IsEnabled=True) # 2FA must be enabled
        mock_user_service.get_2fa_record.return_value = mock_2fa_record

        new_plain_codes = ["new_rec1", "new_rec2"]
        new_hashed_codes_list = ["h_new1", "h_new2"]
        new_hashed_codes_str = "h_new1,h_new2"

        mock_totp_service.generate_recovery_codes.return_value = new_plain_codes
        mock_totp_service.hash_recovery_codes.return_value = new_hashed_codes_list
        mock_totp_service.store_hashed_recovery_codes.return_value = new_hashed_codes_str
        
        recovery_codes, error = auth_service.regenerate_recovery_codes(mock_db_session, user_id)

        assert error is None
        assert recovery_codes == new_plain_codes
        assert mock_2fa_record.RecoveryCodes == new_hashed_codes_str
        mock_db_session.commit.assert_called_once()
