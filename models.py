import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column # For modern SQLAlchemy type hinting if used
from sqlalchemy.sql import func 
from database import Base

# Association Table for UserRoles (Many-to-Many)
UserRoles = Table(
    "UserRoles",
    Base.metadata,
    Column("UserID", UUID(as_uuid=True), ForeignKey("Users.UserID", ondelete="CASCADE"), primary_key=True),
    Column("RoleID", UUID(as_uuid=True), ForeignKey("Roles.RoleID", ondelete="CASCADE"), primary_key=True),
    Column("AssignedAt", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

# Association Table for RolePermissions (Many-to-Many)
RolePermissions = Table(
    "RolePermissions",
    Base.metadata,
    Column("RoleID", UUID(as_uuid=True), ForeignKey("Roles.RoleID", ondelete="CASCADE"), primary_key=True),
    Column("PermissionID", UUID(as_uuid=True), ForeignKey("Permissions.PermissionID", ondelete="CASCADE"), primary_key=True),
    Column("AssignedAt", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

class Tenant(Base):
    __tablename__ = "Tenants"

    TenantID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    Name = Column(String(255), nullable=False)
    Status = Column(String(50), nullable=False, default='Active')
    CreatedAt = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    UpdatedAt = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    # Relationship for tenant-specific roles
    roles = relationship("Role", back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Tenant(TenantID='{self.TenantID}', Name='{self.Name}', Status='{self.Status}')>"

class User(Base):
    __tablename__ = "Users"

    UserID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    TenantID = Column(UUID(as_uuid=True), ForeignKey("Tenants.TenantID", ondelete="CASCADE"), nullable=False, index=True)
    Email = Column(String(255), nullable=False, index=True)
    PasswordHash = Column(String(255), nullable=False)
    FirstName = Column(String(100), nullable=True)
    LastName = Column(String(100), nullable=True)
    IsActive = Column(Boolean, nullable=False, default=True)
    LastLoginAt = Column(DateTime(timezone=True), nullable=True)
    CreatedAt = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    UpdatedAt = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    tenant = relationship("Tenant", back_populates="users")
    two_factor_auth = relationship("TwoFactorAuth", back_populates="user", uselist=False, cascade="all, delete-orphan")
    
    # Many-to-Many relationship with Role through UserRoles table
    roles = relationship("Role", secondary=UserRoles, back_populates="users_assigned")

    # Unique constraint for (TenantID, Email) - already in SQL schema, but good to note
    __table_args__ = (UniqueConstraint('TenantID', 'Email', name='uq_users_tenant_email'),)


    def __repr__(self):
        return f"<User(UserID='{self.UserID}', Email='{self.Email}', TenantID='{self.TenantID}')>"

class TwoFactorAuth(Base):
    __tablename__ = "TwoFactorAuth"

    UserID = Column(UUID(as_uuid=True), ForeignKey("Users.UserID", ondelete="CASCADE"), primary_key=True)
    SecretKey = Column(Text, nullable=True) 
    IsEnabled = Column(Boolean, nullable=False, default=False)
    RecoveryCodes = Column(Text, nullable=True)
    CreatedAt = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    UpdatedAt = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="two_factor_auth")

    def __repr__(self):
        return f"<TwoFactorAuth(UserID='{self.UserID}', IsEnabled='{self.IsEnabled}')>"

class Permission(Base):
    __tablename__ = "Permissions"

    PermissionID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    PermissionName = Column(String(255), nullable=False, unique=True, index=True) # e.g., "user:create"
    Description = Column(Text, nullable=True)
    CreatedAt = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    UpdatedAt = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationship for RolePermissions (indirectly linked to Role)
    roles_having_this_permission = relationship("Role", secondary=RolePermissions, back_populates="permissions")

    def __repr__(self):
        return f"<Permission(PermissionID='{self.PermissionID}', PermissionName='{self.PermissionName}')>"

class Role(Base):
    __tablename__ = "Roles"

    RoleID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # TenantID is NULL for system-level roles
    TenantID = Column(UUID(as_uuid=True), ForeignKey("Tenants.TenantID", ondelete="CASCADE"), nullable=True, index=True) 
    RoleName = Column(String(255), nullable=False)
    Description = Column(Text, nullable=True)
    IsSystemRole = Column(Boolean, nullable=False, default=False) # True if TenantID is NULL
    CreatedAt = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    UpdatedAt = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationship to Tenant (for tenant-specific roles)
    tenant = relationship("Tenant", back_populates="roles")
    
    # Many-to-Many relationship with User through UserRoles table
    users_assigned = relationship("User", secondary=UserRoles, back_populates="roles")
    
    # Many-to-Many relationship with Permission through RolePermissions table
    permissions = relationship("Permission", secondary=RolePermissions, back_populates="roles_having_this_permission")

    # Unique constraint for (TenantID, RoleName) - already in SQL schema
    # For system roles (TenantID IS NULL), RoleName must be globally unique.
    # The SQL schema handles this with a conditional unique index for PostgreSQL.
    # For other DBs, this might need application-level enforcement or a more complex constraint.
    # SQLAlchemy can define this as:
    __table_args__ = (
        UniqueConstraint('TenantID', 'RoleName', name='uq_roles_tenant_rolename'),
        # Potentially a CheckConstraint for IsSystemRole and TenantID consistency:
        # CheckConstraint('(TenantID IS NULL AND IsSystemRole = TRUE) OR (TenantID IS NOT NULL AND IsSystemRole = FALSE)', 
        #                 name='chk_role_system_tenant_consistency')
        # However, IsSystemRole is more of a derived/managed flag based on TenantID presence.
    )

    def __repr__(self):
        return f"<Role(RoleID='{self.RoleID}', RoleName='{self.RoleName}', TenantID='{self.TenantID}', IsSystemRole='{self.IsSystemRole}')>"
