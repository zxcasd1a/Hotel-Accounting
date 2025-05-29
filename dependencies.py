from typing import List, Optional, Set
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer #, SecurityScopes (more advanced, not used here yet)
from sqlalchemy.orm import Session
import uuid

from auth_service import AuthService
from user_service import UserService # To get user permissions if not in token
from totp_service import TOTPService # For AuthService instantiation
from config import settings
from database import get_db # To get DB session for fetching permissions if needed
import schemas
import models

# OAuth2PasswordBearer points to the token URL ( FastAPI will create this endpoint later)
# For now, it's just for defining how the token is extracted.
# The actual tokenUrl will be where clients go to get a token (e.g., /api/v1/auth/login)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login") 

# Instantiate services here or pass them if this becomes a class
# For simplicity, create instances. In a larger app, dependency injection frameworks might manage this.
user_service_instance = UserService()
totp_service_instance = TOTPService() # Assuming it doesn't need a db session for basic init
auth_service_instance = AuthService(user_service=user_service_instance, totp_service=totp_service_instance)


def get_current_user_token_data(token: str = Depends(oauth2_scheme)) -> schemas.TokenData:
    """
    Dependency to decode and validate JWT token.
    Returns the token data if valid.
    """
    token_data = auth_service_instance.decode_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not token_data.is_2fa_authenticated and not (token_data.type == "2fa_pending" if hasattr(token_data, "type") else False) : # Check if it's a full access token
         # This check might be too strict here if we want to allow partial access for some endpoints
         # For most protected resources, is_2fa_authenticated should be true.
         # If the token is a '2fa_pending' type, it shouldn't grant access to regular endpoints.
         # The TokenData schema was updated to include 'is_2fa_authenticated'.
         pass # Allow if is_2fa_authenticated is True, or if it's a special type of token for specific flows.
              # This specific check might be better suited for the permission dependency itself.

    return token_data

def get_current_active_user(
    token_data: schemas.TokenData = Depends(get_current_user_token_data),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Dependency to get the current authenticated user from the database.
    Ensures the user is active.
    """
    if token_data.sub is None: # sub should be user_id
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    try:
        user_id = uuid.UUID(token_data.sub)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user ID in token")

    user = user_service_instance.get_user_by_id(db, user_id=user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.IsActive:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    
    # Attach token data to user object if needed downstream, or just return user model
    # user.token_data = token_data # Example
    return user


class RBACPermissionChecker:
    def __init__(self, required_permissions: Optional[List[str]] = None):
        self.required_permissions = set(required_permissions) if required_permissions else set()

    def __call__(self, 
                 token_data: schemas.TokenData = Depends(get_current_user_token_data),
                 # current_user: models.User = Depends(get_current_active_user), # Alternative, if DB check always needed
                 db: Session = Depends(get_db) # Needed if fetching permissions from DB
                ) -> None:
        
        if not self.required_permissions: # If no permissions are required, access is granted
            return

        if not token_data.is_2fa_authenticated: # Ensure full authentication for permissioned endpoints
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Full authentication (including 2FA if enabled) required."
            )

        user_permissions: Set[str] = set()
        if token_data.permissions: # Prefer permissions from token if available and trustworthy
            user_permissions = set(token_data.permissions)
        else:
            # Fallback: If permissions are not in token, fetch from DB based on user_id (sub)
            # This is less efficient than embedding in token but more secure if roles change frequently
            # and tokens have long expiry.
            # For this to work, get_current_active_user should be used or user_id fetched from token_data.sub
            try:
                user_id = uuid.UUID(token_data.sub)
                # Note: This fetches permissions on every call if not in token.
                # Consider if this is the desired behavior vs relying on token's permissions claim.
                user_permissions = user_service_instance.get_user_effective_permissions(db, user_id)
            except ValueError:
                 raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid user ID in token for permission fetching.")
            except Exception: # Catch errors during permission fetching
                 raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not retrieve user permissions.")


        if not self.required_permissions.issubset(user_permissions):
            missing_perms = self.required_permissions - user_permissions
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions. Missing: {', '.join(missing_perms)}"
            )
        
        # Optionally, one could also check roles from token_data.roles if direct role checks are needed.
        # Example: if "admin_role" in token_data.roles: ...

# Usage in FastAPI endpoint:
# from dependencies import RBACPermissionChecker
#
# @app.get("/some-resource", dependencies=[Depends(RBACPermissionChecker(required_permissions=["resource:read"]))])
# async def read_resource(...):
#     return {"data": "sensitive resource data"}
#
# @app.post("/another-resource", dependencies=[Depends(RBACPermissionChecker(required_permissions=["resource:create", "another:action"]))])
# async def create_resource(...):
#     return {"message": "resource created"}

# This setup provides a flexible RBAC dependency.
# The AuthService needs to be updated to embed 'permissions' (set of permission names)
# and 'roles' (list of role names) into the JWT's TokenData upon successful login.
# If `token_data.permissions` is reliably populated, the DB fallback for permissions is less critical.
# The `is_2fa_authenticated` flag in `TokenData` is crucial for ensuring that sensitive operations
# are only allowed after full authentication.
