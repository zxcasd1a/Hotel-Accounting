from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
from cryptography.fernet import Fernet # Import Fernet

load_dotenv() # Load environment variables from .env file

# Generate a default Fernet key for testing if not provided in .env
# This is for testability; in production, a securely managed key from .env is essential.
DEFAULT_FERNET_KEY = Fernet.generate_key().decode()

class Settings(BaseSettings):
    # Database settings
    DATABASE_URL: str = "postgresql://user:password@localhost/identitydb"

    # JWT Settings
    JWT_SECRET_KEY: str = "test-jwt-secret-key-please-change-in-prod" # Default for easier testing
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    TEMP_TOKEN_EXPIRE_MINUTES: int = 5

    # TOTP Settings
    TOTP_ISSUER_NAME: str = "TestApp" # Default for testing

    # Encryption key for 2FA secrets (Fernet)
    # A default valid key is provided for out-of-the-box testing.
    # In Production: This MUST be overridden by a securely generated key in .env
    SECRET_ENCRYPTION_KEY: str = DEFAULT_FERNET_KEY

    # Application specific
    APP_NAME: str = "IdentityService"
    API_V1_STR: str = "/api/v1"

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        # Pydantic settings are case-insensitive by default for environment variables

settings = Settings()

# Ensure the loaded SECRET_ENCRYPTION_KEY is valid for Fernet, otherwise totp_service will fail.
try:
    Fernet(settings.SECRET_ENCRYPTION_KEY.encode('utf-8'))
except ValueError as e:
    print(f"CRITICAL WARNING: Loaded SECRET_ENCRYPTION_KEY is invalid for Fernet: {e}")
    print("Please ensure a valid Fernet key is set in your .env file or as a default in config.py.")
    # In a real app, might raise an error here to prevent startup with invalid key.

# Example .env file content (user should create this for production):
# DATABASE_URL="postgresql://your_db_user:your_db_password@your_db_host:your_db_port/your_db_name"
# JWT_SECRET_KEY="<a_long_random_secure_string_for_jwt>"
# SECRET_ENCRYPTION_KEY="<a_32_byte_url_safe_base64_encoded_fernet_key_from_Fernet.generate_key()>"
# TOTP_ISSUER_NAME="My Awesome App"
# ACCESS_TOKEN_EXPIRE_MINUTES=60
# REFRESH_TOKEN_EXPIRE_DAYS=30
# TEMP_TOKEN_EXPIRE_MINUTES=10
