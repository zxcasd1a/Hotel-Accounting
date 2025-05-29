from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any, List, Set # Added Set
import uuid

from jose import JWTError, jwt
# from passlib.context import CryptContext # Not used directly for password hashing here

from config import settings
import schemas
import models
from user_service import UserService
from totp_service import TOTPService
from sqlalchemy.orm import Session
from hashing import Hash 

class AuthService:
    def __init__(self, user_service: UserService, totp_service: TOTPService):
        self.user_service = user_service
        self.totp_service = totp_service

    def _create_token(self, data: dict, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
        encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return encoded_jwt

    def create_access_token(self, user_id: str, tenant_id: Optional[str] = None, roles_names: Optional[List[str]] = None, permissions_names: Optional[Set[str]] = None, is_2fa_authenticated: bool = True) -> str:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = schemas.TokenData(
            sub=str(user_id),
            tenant_id=str(tenant_id) if tenant_id else None,
            roles=roles_names or [],
            permissions=list(permissions_names) if permissions_names else [], # Convert set to list for JSON
            is_2fa_authenticated=is_2fa_authenticated
        )
        return self._create_token(token_data.model_dump(exclude_none=True), expires_delta) # exclude_none for cleaner token

    def create_refresh_token(self, user_id: str, tenant_id: Optional[str] = None) -> str:
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode = {"sub": str(user_id)}
        if tenant_id:
            to_encode["tenant_id"] = str(tenant_id)
        return self._create_token(to_encode, expires_delta)

    def create_temporary_token(self, user_id: str, token_type: str = "2fa_pending", tenant_id: Optional[str] = None) -> str:
        expires_delta = timedelta(minutes=settings.TEMP_TOKEN_EXPIRE_MINUTES)
        token_data = schemas.TemporaryTokenData(
            sub=str(user_id),
            type=token_type,
            tenant_id=str(tenant_id) if tenant_id else None
        )
        return self._create_token(token_data.model_dump(exclude_none=True), expires_delta)
        
    def decode_token(self, token: str) -> Optional[schemas.TokenData]:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            if "sub" not in payload: 
                return None
            return schemas.TokenData(**payload)
        except JWTError:
            return None

    def decode_temp_token(self, token: str, expected_type: Optional[str] = "2fa_pending") -> Optional[schemas.TemporaryTokenData]:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            temp_token_data = schemas.TemporaryTokenData(**payload)
            if expected_type and temp_token_data.type != expected_type:
                return None
            return temp_token_data
        except JWTError:
            return None

    def login_password(self, db: Session, email: str, password: str, tenant_id_str: Optional[str] = None) \
            -> Tuple[Optional[models.User], Optional[str]]:
        if not tenant_id_str:
             return None, "Tenant ID must be provided for login."
        try:
            tenant_uuid = uuid.UUID(tenant_id_str)
        except ValueError:
            return None, "Invalid Tenant ID format."

        # Fetch user with roles and permissions to prepare for JWT claims if login is successful
        user = self.user_service.get_user_by_email_and_tenant_id(db, email, tenant_uuid, include_roles_permissions=True)

        if not user:
            return None, "Invalid email or password."
        if not user.IsActive:
            return None, "User account is inactive."
        
        if not self.user_service.verify_user_password(db, user.UserID, password): # verify_user_password doesn't need db if user object is passed
            # For consistency, can pass user object to verify_user_password if it's adapted
            # current user_service.verify_user_password fetches user by ID again.
            temp_user_for_pwd_check = self.user_service.get_user_by_id(db, user.UserID) # Re-fetch or adapt verify_user_password
            if not temp_user_for_pwd_check or not Hash.verify_password(password, temp_user_for_pwd_check.PasswordHash):
                 return None, "Invalid email or password."


        if self.user_service.is_user_2fa_enabled(db, user.UserID):
            temp_token = self.create_temporary_token(user_id=str(user.UserID), tenant_id=str(user.TenantID))
            return user, temp_token 
        
        self.user_service.update_user_last_login(db, user.UserID)
        # User object (already fetched with roles/permissions) is returned directly.
        # The API layer will then call another auth_service method to get final JWTs.
        return user, None 

    def generate_final_tokens_for_user(self, db: Session, user: models.User, is_2fa_authenticated: bool) -> schemas.TokenResponse:
        """
        Generates access and refresh tokens for a fully authenticated user.
        Fetches roles and permissions to embed in the access token.
        """
        user_roles_models = self.user_service.get_user_roles(db, user.UserID) # Ensure fresh roles
        user_permissions_set = self.user_service.get_user_effective_permissions(db, user.UserID)

        role_names = [role.RoleName for role in user_roles_models]
        
        access_token = self.create_access_token(
            user_id=str(user.UserID),
            tenant_id=str(user.TenantID),
            roles_names=role_names,
            permissions_names=user_permissions_set,
            is_2fa_authenticated=is_2fa_authenticated
        )
        refresh_token = self.create_refresh_token(
            user_id=str(user.UserID),
            tenant_id=str(user.TenantID)
        )
        return schemas.TokenResponse(accessToken=access_token, refreshToken=refresh_token)


    def verify_2fa_login_attempt(self, db: Session, user_id: uuid.UUID, code: str) -> bool:
        two_fa_record = self.user_service.get_2fa_record(db, user_id)
        if not two_fa_record or not two_fa_record.IsEnabled or not two_fa_record.SecretKey:
            return False

        decrypted_secret = self.totp_service.decrypt_secret(two_fa_record.SecretKey)
        if not decrypted_secret:
            return False 
            
        if self.totp_service.verify_totp_code(decrypted_secret, code):
            return True

        stored_hashed_codes = self.totp_service.load_hashed_recovery_codes(two_fa_record.RecoveryCodes)
        if self.totp_service.verify_recovery_code(code, stored_hashed_codes):
            new_hashed_codes = [hc for hc in stored_hashed_codes if not Hash.verify_password(code, hc)]
            two_fa_record.RecoveryCodes = self.totp_service.store_hashed_recovery_codes(new_hashed_codes)
            try:
                db.commit()
                return True
            except Exception:
                db.rollback()
                return False
        
        return False

    def setup_2fa_start(self, db: Session, user_id: uuid.UUID) -> Tuple[Optional[str], Optional[str]]:
        user = self.user_service.get_user_by_id(db, user_id)
        if not user:
            return None, "User not found."

        two_fa_record = self.user_service.get_or_create_2fa_record(db, user_id)
        if two_fa_record.IsEnabled:
            return None, "2FA is already enabled for this user."

        plain_secret = self.totp_service.generate_totp_secret()
        encrypted_secret = self.totp_service.encrypt_secret(plain_secret)
        if not encrypted_secret:
            return None, "Failed to secure 2FA secret. Server configuration error."

        two_fa_record.SecretKey = encrypted_secret
        two_fa_record.IsEnabled = False
        try:
            db.commit()
            db.refresh(two_fa_record)
            otp_uri = self.totp_service.get_totp_uri(user.Email, plain_secret)
            return plain_secret, otp_uri
        except Exception as e:
            db.rollback()
            return None, f"Database error during 2FA setup: {str(e)}"

    def enable_2fa_finish(self, db: Session, user_id: uuid.UUID, totp_code: str) -> Tuple[Optional[List[str]], Optional[str]]:
        two_fa_record = self.user_service.get_2fa_record(db, user_id)
        if not two_fa_record or not two_fa_record.SecretKey:
            return None, "2FA setup not initiated or secret key missing."
        if two_fa_record.IsEnabled: # Should not happen if setup_2fa_start was called correctly
            # However, if user retries this step, it's a valid check.
            # If already enabled, perhaps just return existing recovery codes or a message.
            # For now, let's assume this means an error in flow or re-attempt.
             return None, "2FA is already enabled. If you need new recovery codes, use the regenerate option."


        decrypted_secret = self.totp_service.decrypt_secret(two_fa_record.SecretKey)
        if not decrypted_secret:
             return None, "Failed to process 2FA secret. Verification failed."

        if not self.totp_service.verify_totp_code(decrypted_secret, totp_code):
            return None, "Invalid TOTP code."

        two_fa_record.IsEnabled = True
        
        recovery_codes_plain = self.totp_service.generate_recovery_codes()
        hashed_recovery_codes = self.totp_service.hash_recovery_codes(recovery_codes_plain)
        two_fa_record.RecoveryCodes = self.totp_service.store_hashed_recovery_codes(hashed_recovery_codes)
        
        try:
            db.commit()
            db.refresh(two_fa_record)
            return recovery_codes_plain, None
        except Exception as e:
            db.rollback()
            return None, f"Database error enabling 2FA: {str(e)}"

    def disable_2fa(self, db: Session, user_id: uuid.UUID) -> Tuple[bool, Optional[str]]:
        two_fa_record = self.user_service.get_2fa_record(db, user_id)
        if not two_fa_record or not two_fa_record.IsEnabled:
            return False, "2FA is not enabled for this user."

        two_fa_record.IsEnabled = False
        two_fa_record.SecretKey = None
        two_fa_record.RecoveryCodes = None
        try:
            db.commit()
            return True, None
        except Exception as e:
            db.rollback()
            return False, f"Database error disabling 2FA: {str(e)}"

    def regenerate_recovery_codes(self, db: Session, user_id: uuid.UUID) -> Tuple[Optional[List[str]], Optional[str]]:
        two_fa_record = self.user_service.get_2fa_record(db, user_id)
        if not two_fa_record or not two_fa_record.IsEnabled:
            return None, "2FA must be enabled to regenerate recovery codes."

        recovery_codes_plain = self.totp_service.generate_recovery_codes()
        hashed_recovery_codes = self.totp_service.hash_recovery_codes(recovery_codes_plain)
        two_fa_record.RecoveryCodes = self.totp_service.store_hashed_recovery_codes(hashed_recovery_codes)
        
        try:
            db.commit()
            return recovery_codes_plain, None
        except Exception as e:
            db.rollback()
            return None, f"Database error regenerating recovery codes: {str(e)}"

# Example usage notes from before remain relevant.
if __name__ == '__main__':
    print("AuthService updated. JWTs will now include roles and permissions if available during token creation.")
    pass
