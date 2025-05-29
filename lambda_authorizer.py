import os
import json
import re
from typing import Dict, Any, Optional

from jose import jwt, JWTError
from jose.exceptions import JOSEError # More specific JOSE errors if needed
# Boto3 is available in Lambda environment by default, used for AWS SDK calls (e.g., Secrets Manager)
# import boto3 
# from botocore.exceptions import ClientError

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger(service="identity-service-authorizer")
tracer = Tracer(service="identity-service-authorizer")

# --- Configuration - Load from Environment Variables ---
# These would be set in the Lambda function's configuration in CloudFormation
JWT_SECRET_OR_PUBLIC_KEY = os.environ.get("JWT_SECRET_OR_PUBLIC_KEY")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256") 
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE") 
JWT_ISSUER = os.environ.get("JWT_ISSUER") # Optional

# Example: If JWT_SECRET_OR_PUBLIC_KEY is an ARN for Secrets Manager
# This code would run during Lambda initialization (cold start)
# if JWT_SECRET_OR_PUBLIC_KEY and JWT_SECRET_OR_PUBLIC_KEY.startswith("arn:aws:secretsmanager"):
#     logger.info("JWT_SECRET_OR_PUBLIC_KEY is an ARN, attempting to fetch from Secrets Manager.")
#     try:
#         session = boto3.session.Session()
#         client = session.client(service_name='secretsmanager')
#         secret_value_response = client.get_secret_value(SecretId=JWT_SECRET_OR_PUBLIC_KEY)
#         JWT_SECRET_OR_PUBLIC_KEY = secret_value_response['SecretString']
#         logger.info("Successfully fetched JWT secret from Secrets Manager.")
#     except Exception as e:
#         logger.error(f"Failed to fetch JWT secret from Secrets Manager: {e}", exc_info=True)
#         JWT_SECRET_OR_PUBLIC_KEY = None # Critical failure, authorizer won't work


@logger.inject_lambda_context(log_event=True)
@tracer.capture_lambda_handler
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda authorizer for API Gateway HTTP API (payload format 2.0).
    Validates JWT from Authorization header and returns a simple response
    with isAuthorized True/False and a context map.
    """
    logger.debug("Authorizer event received.")

    if not JWT_SECRET_OR_PUBLIC_KEY:
        logger.error("CRITICAL: JWT_SECRET_OR_PUBLIC_KEY is not configured. Denying access.")
        return {"isAuthorized": False, "context": {"error": "AuthorizerMisconfigured", "message": "Key not configured."}}

    # For HTTP API payload 2.0, headers are typically lowercase.
    auth_header = event.get("headers", {}).get("authorization") 

    if not auth_header:
        logger.info("No Authorization header found.")
        return {"isAuthorized": False, "context": {"error": "MissingAuthorizationHeader"}}

    match = re.match(r"Bearer\s+(.+)", auth_header, re.IGNORECASE)
    if not match:
        logger.info("Authorization header is not a Bearer token.")
        return {"isAuthorized": False, "context": {"error": "InvalidAuthorizationHeaderFormat"}}
    
    token = match.group(1)
    
    try:
        logger.debug(f"Attempting to decode JWT with algorithm {JWT_ALGORITHM}.")
        
        # Define options for jwt.decode based on configured validations
        decode_options = {"verify_signature": True, "verify_exp": True}
        if JWT_AUDIENCE:
            decode_options["verify_aud"] = True
        if JWT_ISSUER:
            decode_options["verify_iss"] = True
            
        payload = jwt.decode(
            token,
            JWT_SECRET_OR_PUBLIC_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE if JWT_AUDIENCE else None, # Pass None if not verifying
            issuer=JWT_ISSUER if JWT_ISSUER else None       # Pass None if not verifying
            # options=decode_options # python-jose handles options implicitly based on args above
        )
        logger.info({"message": "JWT decoded successfully", "payload_sub": payload.get("sub")})

        user_id = payload.get("sub")
        if not user_id:
            logger.warn("Token is missing 'sub' (user_id) claim.")
            return {"isAuthorized": False, "context": {"error": "TokenMissingUserId"}}

        # CRITICAL CHECK: Ensure user has completed 2FA if it was part of the auth flow
        if not payload.get("is_2fa_authenticated", False):
            logger.warn(f"User {user_id} is not fully authenticated (is_2fa_authenticated claim is false or missing).")
            return {"isAuthorized": False, "context": {"error": "TwoFactorAuthenticationRequired"}}

        # Construct context to pass to backend.
        # Values must be string, number, or boolean.
        authorizer_context = {
            "principalId": str(user_id), 
            "userId": str(user_id), 
            "tenantId": str(payload.get("tenant_id")) if payload.get("tenant_id") is not None else None,
            "roles": ",".join(payload.get("roles", [])), # Convert list to CSV
            "permissions": ",".join(payload.get("permissions", [])), # Convert list to CSV
            "is_2fa_authenticated": str(payload.get("is_2fa_authenticated", "false")).lower(), # Ensure string "true" or "false"
        }
        # Filter out None values from context for cleaner output
        authorizer_context = {k: v for k, v in authorizer_context.items() if v is not None}
        
        return {
            "isAuthorized": True,
            "context": authorizer_context
        }

    except JWTError as e: # Covers expired, invalid signature, invalid aud/iss if options set, etc.
        logger.warn(f"JWT validation failed: {type(e).__name__} - {str(e)}")
        return {"isAuthorized": False, "context": {"error": "InvalidOrExpiredToken", "detail": str(e)}}
    except JOSEError as e: 
        logger.error(f"JOSE error during JWT processing: {type(e).__name__} - {str(e)}")
        return {"isAuthorized": False, "context": {"error": "TokenProcessingError", "detail": str(e)}}
    except Exception as e:
        logger.error(f"Unexpected error in authorizer: {type(e).__name__} - {str(e)}", exc_info=True)
        return {"isAuthorized": False, "context": {"error": "InternalServerErrorInAuthorizer"}}

# To generate a test token for local testing (using auth_service.py logic):
# from datetime import datetime, timedelta, timezone
# from config import settings as app_settings # Assuming your app's config
# test_payload = {
#     "sub": "test-user-id", "tenant_id": "test-tenant-id", 
#     "roles": ["user", "viewer"], "permissions": ["read:doc", "read:profile"], 
#     "is_2fa_authenticated": True,
#     "exp": datetime.now(timezone.utc) + timedelta(minutes=app_settings.ACCESS_TOKEN_EXPIRE_MINUTES),
#     "iat": datetime.now(timezone.utc),
#     "aud": app_settings.JWT_AUDIENCE, # Use audience from your app config
#     "iss": app_settings.JWT_ISSUER   # Use issuer from your app config
# }
# Ensure JWT_SECRET_OR_PUBLIC_KEY, JWT_ALGORITHM match between generating and validating.
# sample_token = jwt.encode(test_payload, app_settings.JWT_SECRET_KEY, algorithm=app_settings.JWT_ALGORITHM)
# print(f"Sample token for testing: {sample_token}")
```

The `lambda_authorizer.py` code has been updated for clarity and robustness, especially around how headers are accessed and how JWT claims are processed for the context map.

**Step 3: Update `api_gateway_identity_config.yaml`**

Now, I will update the CloudFormation template to:
1.  Define the IAM Role for the Lambda authorizer.
2.  Define the Lambda Function resource for the authorizer.
3.  Define the API Gateway Authorizer resource.
4.  Identify public routes and attach the authorizer to all other (protected) routes.
