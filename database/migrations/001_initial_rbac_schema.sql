-- CloudShield MSSP Platform Relational RBAC & Authorization Schema
-- Migration: 001_initial_rbac_schema.sql

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    upn TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT,
    password_hash TEXT,
    password_salt TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_mfa_enabled INTEGER NOT NULL DEFAULT 0,
    auth_provider TEXT NOT NULL DEFAULT 'Local',
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS team_memberships (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_in_team TEXT NOT NULL DEFAULT 'Member',
    joined_at TEXT NOT NULL,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(team_id, user_id)
);

CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    report_mode TEXT NOT NULL DEFAULT 'Consolidated',
    selected_package TEXT NOT NULL DEFAULT 'PKG-10',
    connection_status TEXT NOT NULL DEFAULT 'LiveConnected',
    health_status TEXT NOT NULL DEFAULT 'Healthy',
    secure_score REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    name_tr TEXT NOT NULL,
    name_en TEXT NOT NULL,
    category TEXT NOT NULL,
    product_family TEXT NOT NULL,
    plugin_folder TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS customer_services (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    service_level TEXT NOT NULL DEFAULT 'Managed',
    status TEXT NOT NULL DEFAULT 'Onboarded', -- Onboarded, Suspended, Disabled
    onboarded_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    UNIQUE(customer_id, service_id)
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    is_platform_role INTEGER NOT NULL DEFAULT 0,
    is_system INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id TEXT PRIMARY KEY,
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS access_assignments (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL, -- 'User' or 'Team'
    subject_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    customer_scope TEXT NOT NULL DEFAULT 'ALL', -- 'ALL' or 'Specific'
    customer_id TEXT, -- NULL if customer_scope is 'ALL'
    service_scope TEXT NOT NULL DEFAULT 'ALL', -- 'ALL' or 'Specific'
    service_id TEXT, -- NULL if service_scope is 'ALL'
    valid_from TEXT NOT NULL,
    valid_to TEXT, -- NULL means permanent
    is_temporary INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    approval_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_conditions (
    id TEXT PRIMARY KEY,
    assignment_id TEXT NOT NULL,
    condition_type TEXT NOT NULL, -- 'IpRange', 'TimeOfDay', 'RequireMfa', 'RequireApproval'
    condition_value TEXT NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES access_assignments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_approvals (
    id TEXT PRIMARY KEY,
    requester_id TEXT NOT NULL,
    approver_id TEXT,
    requested_role_id TEXT NOT NULL,
    customer_id TEXT,
    service_id TEXT,
    duration_hours INTEGER NOT NULL DEFAULT 8,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending', -- 'Pending', 'Approved', 'Rejected', 'Expired'
    decision_reason TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    FOREIGN KEY (requester_id) REFERENCES users(id),
    FOREIGN KEY (approver_id) REFERENCES users(id),
    FOREIGN KEY (requested_role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL, -- AUTH_ALLOW, AUTH_DENY, ROLE_ASSIGN, ROLE_REMOVE, CUSTOMER_ASSIGN, etc.
    user_id TEXT,
    user_upn TEXT,
    customer_id TEXT,
    service_id TEXT,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL, -- 'ALLOW' or 'DENY'
    reason TEXT,
    ip_address TEXT,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_assignments_subject ON access_assignments(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_customer_services ON customer_services(customer_id, service_id);
