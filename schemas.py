from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
import uuid
from datetime import datetime

class ConfigBaseModel(BaseModel):
    model_config = {
        "from_attributes": True # Pydantic V2: replaces orm_mode
    }

# Tenant Schemas
class TenantCreate(BaseModel):
    name: str = Field(min_length=1)
    status: Optional[str] = Field(default="Active", pattern=r"^(Active|Suspended|Trial)$")

class TenantUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    status: Optional[str] = Field(None, pattern=r"^(Active|Suspended|Trial)$")

class TenantResponse(ConfigBaseModel):
    tenantId: uuid.UUID
    name: str
    status: str
    createdAt: datetime
    updatedAt: datetime

# User Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    firstName: Optional[str] = None
    lastName: Optional[str] = None

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    isActive: Optional[bool] = None

class UserSelfUpdate(BaseModel):
    email: Optional[EmailStr] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None

class UserResponse(ConfigBaseModel):
    userId: uuid.UUID
    tenantId: uuid.UUID
    email: EmailStr
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    isActive: bool
    lastLoginAt: Optional[datetime] = None
    createdAt: datetime
    updatedAt: datetime
    roles: Optional[List['RoleResponse']] = [] # Forward reference for RoleResponse

# Auth Schemas
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenantId: Optional[uuid.UUID] = None

class TokenResponse(BaseModel):
    accessToken: str
    refreshToken: str
    tokenType: str = "bearer"

class LoginSuccessResponse(TokenResponse):
    userId: uuid.UUID
    tenantId: uuid.UUID

class TwoFactorChallengeResponse(BaseModel):
    userId: uuid.UUID
    message: str = "Two-factor authentication required."
    # twoFactorSessionToken: str

class TwoFactorVerificationRequest(BaseModel):
    code: str

class TwoFactorSessionVerificationRequest(BaseModel):
    twoFactorSessionToken: str
    code: str

class RefreshTokenRequest(BaseModel):
    refreshToken: str

# 2FA Management Schemas
class TwoFactorSetupDetails(ConfigBaseModel):
    userId: uuid.UUID
    secretKey: str
    qrCodeUri: str

class TwoFactorSetupResponse(BaseModel):
    qrCodeUri: str
    recoveryCodes: Optional[List[str]] = None

class TwoFactorEnableRequest(BaseModel):
    code: str

class TwoFactorAuthStatusResponse(ConfigBaseModel):
    userId: uuid.UUID
    isEnabled: bool

class RecoveryCodesResponse(BaseModel):
    recoveryCodes: List[str]

# Token Data (JWT Claims)
class TokenData(BaseModel):
    sub: str # Subject (user_id)
    tenant_id: Optional[str] = None
    # roles list will contain role names or role IDs. Names are more convenient for direct use in checks.
    # If using role IDs, the RBAC dependency would need to fetch role names/permissions.
    # Storing role names directly in the token is common for stateless checks.
    roles: Optional[List[str]] = [] # List of role names
    permissions: Optional[List[str]] = [] # List of permission names, can be populated by auth_service
    is_2fa_authenticated: Optional[bool] = False

class TemporaryTokenData(BaseModel):
    sub: str
    type: str = "2fa_pending"
    tenant_id: Optional[str] = None

# --- RBAC Schemas ---

# Permission Schemas
class PermissionBase(BaseModel):
    permissionName: str = Field(..., pattern=r"^[a-zA-Z0-9_:]+$") # e.g., resource:action
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class PermissionUpdate(BaseModel): # Permissions are often static, but if updatable:
    description: Optional[str] = None

class PermissionResponse(ConfigBaseModel, PermissionBase): # Inherit from PermissionBase for common fields
    permissionId: uuid.UUID
    createdAt: datetime
    updatedAt: datetime

# Role Schemas
class RoleBase(BaseModel):
    roleName: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    # tenantId will be a path parameter for tenant-specific, or absent for system roles in service logic
    isSystemRole: Optional[bool] = False # Can be set at creation, or derived if tenantId is null

class RoleUpdate(BaseModel):
    roleName: Optional[str] = None
    description: Optional[str] = None

class RoleResponse(ConfigBaseModel, RoleBase): # Inherit from RoleBase
    roleId: uuid.UUID
    tenantId: Optional[uuid.UUID] = None
    isSystemRole: bool
    createdAt: datetime
    updatedAt: datetime
    permissions: Optional[List[PermissionResponse]] = [] # Include assigned permissions

# UserResponse needs to be updated after RoleResponse is defined to avoid forward ref issues if not handled by Pydantic version
UserResponse.model_rebuild() # Pydantic v2 method to rebuild schema if forward refs were used

# Assignment Schemas
class RolePermissionAssignmentRequest(BaseModel):
    permissionId: uuid.UUID
    # roleId is path param

class UserRoleAssignmentRequest(BaseModel):
    roleId: uuid.UUID
    # userId is path param

# Paginated Responses
class PaginatedTenantResponse(BaseModel):
    limit: int
    offset: int
    total: int
    items: List[TenantResponse]

class PaginatedUserResponse(BaseModel):
    limit: int
    offset: int
    total: int
    items: List[UserResponse] # Each UserResponse will include its roles

class PaginatedRoleResponse(BaseModel):
    limit: int
    offset: int
    total: int
    items: List[RoleResponse]

class PaginatedPermissionResponse(BaseModel):
    limit: int
    offset: int
    total: int
    items: List[PermissionResponse]
