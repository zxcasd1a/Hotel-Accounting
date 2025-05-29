-- Database Schema for IdentityService

-- Tenants Table
CREATE TABLE Tenants (
    TenantID UUID PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    Status VARCHAR(50) NOT NULL DEFAULT 'Active', -- e.g., Active, Suspended, Trial
    CreatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users Table
CREATE TABLE Users (
    UserID UUID PRIMARY KEY,
    TenantID UUID NOT NULL,
    Email VARCHAR(255) NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL,
    FirstName VARCHAR(100),
    LastName VARCHAR(100),
    IsActive BOOLEAN NOT NULL DEFAULT TRUE,
    LastLoginAt TIMESTAMP WITH TIME ZONE,
    CreatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (TenantID) REFERENCES Tenants(TenantID) ON DELETE CASCADE,
    UNIQUE (TenantID, Email) -- Email must be unique within a tenant
);

CREATE INDEX idx_users_tenant_id ON Users(TenantID);
CREATE INDEX idx_users_email ON Users(Email); -- For faster lookups by email, though covered by unique constraint, explicit index can be beneficial

-- TwoFactorAuth Table
CREATE TABLE TwoFactorAuth (
    UserID UUID PRIMARY KEY,
    SecretKey TEXT, -- Encrypted
    IsEnabled BOOLEAN NOT NULL DEFAULT FALSE,
    RecoveryCodes TEXT, -- Encrypted, comma-separated list or JSON array of codes
    CreatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

-- Permissions Table
CREATE TABLE Permissions (
    PermissionID UUID PRIMARY KEY,
    PermissionName VARCHAR(255) NOT NULL UNIQUE, -- e.g., "user:create", "invoice:read"
    Description TEXT,
    CreatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_permissions_permission_name ON Permissions(PermissionName);

-- Roles Table
CREATE TABLE Roles (
    RoleID UUID PRIMARY KEY,
    TenantID UUID, -- NULL for system-level roles
    RoleName VARCHAR(255) NOT NULL,
    Description TEXT,
    IsSystemRole BOOLEAN NOT NULL DEFAULT FALSE,
    CreatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (TenantID) REFERENCES Tenants(TenantID) ON DELETE CASCADE,
    UNIQUE (TenantID, RoleName) -- RoleName must be unique within a tenant
    -- For system roles (TenantID IS NULL), RoleName must be globally unique.
    -- This can be handled by a partial unique index if the DB supports it, or application logic.
    -- Example for PostgreSQL:
    -- CREATE UNIQUE INDEX idx_roles_system_role_name ON Roles (RoleName) WHERE TenantID IS NULL;
);

CREATE INDEX idx_roles_tenant_id ON Roles(TenantID);
-- Note: A separate unique index for system roles (where TenantID is NULL) might be needed
-- depending on DB capabilities to enforce global uniqueness for system roles.
-- For instance, in PostgreSQL:
-- CREATE UNIQUE INDEX unique_system_role_name ON Roles (RoleName) WHERE TenantID IS NULL;
-- For other databases, this might need to be enforced at the application level or via triggers.

-- RolePermissions Junction Table
CREATE TABLE RolePermissions (
    RoleID UUID NOT NULL,
    PermissionID UUID NOT NULL,
    AssignedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (RoleID, PermissionID),
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID) ON DELETE CASCADE,
    FOREIGN KEY (PermissionID) REFERENCES Permissions(PermissionID) ON DELETE CASCADE
);

CREATE INDEX idx_rolepermissions_role_id ON RolePermissions(RoleID);
CREATE INDEX idx_rolepermissions_permission_id ON RolePermissions(PermissionID);

-- UserRoles Junction Table
CREATE TABLE UserRoles (
    UserID UUID NOT NULL,
    RoleID UUID NOT NULL,
    AssignedAt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (UserID, RoleID),
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE,
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID) ON DELETE CASCADE
);

CREATE INDEX idx_userroles_user_id ON UserRoles(UserID);
CREATE INDEX idx_userroles_role_id ON UserRoles(RoleID);

-- Trigger function to update UpdatedAt columns automatically (Example for PostgreSQL)
-- Similar mechanisms exist for other databases (e.g., ON UPDATE CURRENT_TIMESTAMP for MySQL)

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.UpdatedAt = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply the trigger to tables
CREATE TRIGGER update_tenants_updated_at
BEFORE UPDATE ON Tenants
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON Users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_twofactorauth_updated_at
BEFORE UPDATE ON TwoFactorAuth
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at
BEFORE UPDATE ON Permissions
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at
BEFORE UPDATE ON Roles
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Note: Junction tables (RolePermissions, UserRoles) typically don't have an UpdatedAt column
-- as their records represent a relationship established at AssignedAt. If modification
-- of the relationship itself (other than creation/deletion) is a concept, then an
-- UpdatedAt column could be added.

-- Further considerations for production:
-- 1. Database-specific optimizations.
-- 2. For `Roles.RoleName` uniqueness:
--    - In PostgreSQL, the conditional unique index `CREATE UNIQUE INDEX idx_roles_system_role_name ON Roles (RoleName) WHERE TenantID IS NULL;`
--      and `UNIQUE (TenantID, RoleName)` cover all cases.
--    - For MySQL, you might need two separate columns and application logic, or use a trigger to enforce this.
--      Alternatively, make RoleName globally unique and manage tenant-specific naming conventions at the application layer if needed.
--      However, the `UNIQUE (TenantID, RoleName)` constraint as defined is generally sufficient if system roles are handled by ensuring TenantID is NULL
--      and non-system roles always have a TenantID. The global uniqueness for system roles (TenantID IS NULL) would then require an additional check/index.
--      A simple approach for MySQL would be to make RoleName globally unique if the number of system roles is small and their names are distinct
--      enough not to clash with tenant-defined roles, or prefix tenant roles.
--      The current `UNIQUE (TenantID, RoleName)` allows different tenants to have a role named "Manager",
--      and a system role "System Admin" (with TenantID NULL) would also be unique.
--      The only gap is preventing two system roles (TenantID IS NULL) from having the same name.
--      A simple way to enforce this is ensure `IsSystemRole = TRUE` implies `TenantID IS NULL`.
--      And then have `UNIQUE (RoleName, IsSystemRole, TenantID)` - but this gets complex.
--      The provided `UNIQUE (TenantID, RoleName)` and a separate PostgreSQL-style conditional index for system roles is the cleanest.
--      Without conditional indexes, application-level checks or a trigger would be needed for full system role name uniqueness.
-- 3. Encryption for SecretKey and RecoveryCodes should be handled at the application layer before storing.
--    The database columns are TEXT; they store the encrypted string.
-- 4. Audit logging: Consider separate audit tables or using database features for more detailed change tracking.
-- 5. Soft deletes: If soft deletes are required (marking records as deleted instead of actually removing them),
--    add an `IsDeleted BOOLEAN` or `DeletedAt TIMESTAMP` column to relevant tables.
-- 6. Password Hashing: Ensure strong, salted hashing algorithms (e.g., Argon2, bcrypt) are used at the application layer.
--    `PasswordHash VARCHAR(255)` should be large enough for these hashes.
