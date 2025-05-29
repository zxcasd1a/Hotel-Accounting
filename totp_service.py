import pyotp
import base64
from cryptography.fernet import Fernet, InvalidToken
from typing import List, Optional

from config import settings
from hashing import Hash # For hashing recovery codes

# Initialize Fernet for encryption/decryption of TOTP secrets
# The key MUST be 32 url-safe base64-encoded bytes.
# Ensure SECRET_ENCRYPTION_KEY is correctly set in config from environment.
try:
    fernet_key = settings.SECRET_ENCRYPTION_KEY.encode('utf-8')
    if len(base64.urlsafe_b64decode(fernet_key)) != 32:
        raise ValueError("SECRET_ENCRYPTION_KEY must be 32 url-safe base64-encoded bytes.")
    cipher_suite = Fernet(fernet_key)
except Exception as e:
    print(f"CRITICAL: Fernet key for TOTP secret encryption is invalid or missing: {e}. Service will fail.")
    # In a real app, this should prevent startup or log a severe error.
    # For now, we'll let it proceed but TOTP encryption/decryption will fail.
    cipher_suite = None


class TOTPService:
    def generate_totp_secret(self) -> str:
        """Generates a new Base32 encoded TOTP secret."""
        return pyotp.random_base32()

    def encrypt_secret(self, secret: str) -> Optional[str]:
        """Encrypts the TOTP secret for storage."""
        if not cipher_suite:
            # This indicates a serious configuration error with the Fernet key.
            # Depending on policy, either raise an error or log and return None.
            # Raising an error is safer to prevent storing unencrypted secrets.
            raise RuntimeError("TOTP secret encryption is not available due to missing or invalid Fernet key.")
        
        encrypted_secret = cipher_suite.encrypt(secret.encode('utf-8'))
        return encrypted_secret.decode('utf-8')

    def decrypt_secret(self, encrypted_secret: str) -> Optional[str]:
        """Decrypts the stored TOTP secret."""
        if not cipher_suite:
            raise RuntimeError("TOTP secret decryption is not available due to missing or invalid Fernet key.")
        try:
            decrypted_secret = cipher_suite.decrypt(encrypted_secret.encode('utf-8'))
            return decrypted_secret.decode('utf-8')
        except InvalidToken:
            # This can happen if the token is malformed or the key is wrong
            # Log this event securely
            return None # Or raise a specific error


    def get_totp_uri(self, account_name: str, secret: str) -> str:
        """
        Generates the otpauth:// URI for QR code generation.
        Args:
            account_name: The email or username for display in the authenticator app.
            secret: The Base32 encoded TOTP secret.
        Returns:
            The otpauth:// URI string.
        """
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=account_name,
            issuer_name=settings.TOTP_ISSUER_NAME
        )

    def verify_totp_code(self, secret: str, code: str) -> bool:
        """
        Verifies a TOTP code against the user's secret.
        Args:
            secret: The user's Base32 encoded TOTP secret (decrypted).
            code: The TOTP code provided by the user.
        Returns:
            True if the code is valid, False otherwise.
        """
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code)

    def generate_recovery_codes(self, num_codes: int = 10, code_length: int = 10) -> List[str]:
        """
        Generates a list of unique, random recovery codes.
        These codes should be shown to the user once and stored hashed.
        """
        codes = []
        for _ in range(num_codes):
            # Generate a cryptographically secure random string
            # pyotp.random_base32 can be used for this, or os.urandom + base64 encoding
            code = pyotp.random_base32(length=code_length) # pyotp.random_base32 default length is 16, make it configurable if needed
            codes.append(code[:code_length]) # Ensure exact length
        return list(set(codes)) # Ensure uniqueness, though highly probable with random_base32

    def hash_recovery_codes(self, recovery_codes: List[str]) -> List[str]:
        """Hashes a list of recovery codes for storage."""
        return [Hash.hash_password(code) for code in recovery_codes]

    def verify_recovery_code(self, provided_code: str, stored_hashed_codes: List[str]) -> bool:
        """
        Verifies a provided recovery code against a list of stored hashed codes.
        If valid, the calling service is responsible for invalidating this code.
        """
        for hashed_code in stored_hashed_codes:
            if Hash.verify_password(provided_code, hashed_code):
                return True
        return False

    def store_hashed_recovery_codes(self, hashed_codes: List[str]) -> str:
        """
        Prepares hashed recovery codes for storage (e.g., as a comma-separated string).
        """
        return ",".join(hashed_codes)

    def load_hashed_recovery_codes(self, stored_str: Optional[str]) -> List[str]:
        """
        Loads hashed recovery codes from their stored string format.
        """
        if not stored_str:
            return []
        return stored_str.split(',')


# Example Usage (Illustrative)
if __name__ == "__main__":
    if not cipher_suite:
        print("Exiting example: Fernet cipher suite not initialized. Check SECRET_ENCRYPTION_KEY.")
    else:
        service = TOTPService()

        # Generate and encrypt/decrypt secret
        original_secret = service.generate_totp_secret()
        print(f"Original Secret: {original_secret}")

        encrypted = service.encrypt_secret(original_secret)
        print(f"Encrypted Secret: {encrypted}")

        decrypted = service.decrypt_secret(encrypted)
        print(f"Decrypted Secret: {decrypted}")
        assert decrypted == original_secret

        # Get TOTP URI
        uri = service.get_totp_uri("user@example.com", decrypted)
        print(f"TOTP URI: {uri}")

        # Verify code (requires an actual code from an authenticator app)
        # For testing, you can use pyotp to generate a current code:
        # test_totp_instance = pyotp.TOTP(decrypted)
        # current_code = test_totp_instance.now()
        # print(f"Current Code for testing: {current_code}")
        # is_valid = service.verify_totp_code(decrypted, current_code)
        # print(f"Code Verification (using current code): {is_valid}")

        # Recovery Codes
        recovery_codes = service.generate_recovery_codes(num_codes=5)
        print(f"Generated Recovery Codes: {recovery_codes}")

        hashed_codes = service.hash_recovery_codes(recovery_codes)
        print(f"Hashed Recovery Codes: {hashed_codes}")

        stored_hashed_str = service.store_hashed_recovery_codes(hashed_codes)
        print(f"Stored Hashed Recovery Codes String: {stored_hashed_str}")

        loaded_hashed_codes = service.load_hashed_recovery_codes(stored_hashed_str)
        assert loaded_hashed_codes == hashed_codes

        # Verify a recovery code
        if recovery_codes:
            code_to_test = recovery_codes[0]
            is_recovery_valid = service.verify_recovery_code(code_to_test, loaded_hashed_codes)
            print(f"Recovery code '{code_to_test}' validation: {is_recovery_valid}")
            
            is_recovery_invalid = service.verify_recovery_code("invalidcode", loaded_hashed_codes)
            print(f"Recovery code 'invalidcode' validation: {is_recovery_invalid}")
        else:
            print("No recovery codes generated to test verification.")
