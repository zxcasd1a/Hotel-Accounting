import pytest
from config import settings, Settings # Import the instance and the class
from pydantic_settings import BaseSettings # For type checking

def test_settings_instance_exists():
    assert settings is not None
    assert isinstance(settings, BaseSettings) # Check if it's a Pydantic BaseSettings instance
    assert isinstance(settings, Settings)   # Check if it's an instance of our Settings class

def test_default_settings_are_loaded():
    # Check a few default values that we've set in config.py
    # These might be overridden by .env file, so these tests are for defaults when .env is not present or doesn't override them.
    # For more robust testing of .env loading, you might need to manipulate environment variables or use a test-specific .env
    
    # Assuming no .env file or it doesn't override these:
    assert settings.JWT_ALGORITHM == "HS256"
    assert settings.TOTP_ISSUER_NAME == "TestApp" # Default set in updated config.py
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS > 0
    assert settings.TEMP_TOKEN_EXPIRE_MINUTES > 0

    # Check that critical keys have some value (even if it's the default test one)
    assert settings.JWT_SECRET_KEY is not None
    assert settings.SECRET_ENCRYPTION_KEY is not None

def test_database_url_is_set():
    assert settings.DATABASE_URL is not None
    assert "postgresql" in settings.DATABASE_URL or "sqlite" in settings.DATABASE_URL # Depending on default/env

# To test .env overrides, you would typically:
# 1. Create a temporary .env file within your test setup.
# 2. Ensure python-dotenv reloads it (or pydantic-settings re-initializes).
# 3. Check if the settings reflect values from the temporary .env.
# This is more advanced and might require careful handling of the settings object lifecycle.
# For now, testing default load is sufficient for basic coverage.

# Example: Test that SECRET_ENCRYPTION_KEY is a valid Fernet key string (basic check)
def test_secret_encryption_key_format():
    from cryptography.fernet import Fernet
    try:
        Fernet(settings.SECRET_ENCRYPTION_KEY.encode('utf-8'))
    except ValueError:
        pytest.fail("SECRET_ENCRYPTION_KEY is not a valid Fernet key.")

# Note: The actual value of DEFAULT_FERNET_KEY in config.py is generated at import time of config.py.
# So, each test run might see a different DEFAULT_FERNET_KEY if config.py is re-imported or not cached.
# However, pydantic-settings typically loads and caches the settings instance.
# The test above just ensures the loaded key is valid for Fernet.
