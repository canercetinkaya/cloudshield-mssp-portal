-- CloudShield MSSP Platform Migration 005: License Intelligence & Security Value Realization
-- Data structures for Subscribed SKUs, Service Plans, User Personas, Workload Value Reconciliation & Snapshots

CREATE TABLE IF NOT EXISTS tenant_license_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    sku_id TEXT NOT NULL,
    sku_part_number TEXT NOT NULL,
    display_name TEXT NOT NULL,
    prepaid_units INTEGER NOT NULL DEFAULT 0,
    consumed_units INTEGER NOT NULL DEFAULT 0,
    suspended_units INTEGER NOT NULL DEFAULT 0,
    warning_units INTEGER NOT NULL DEFAULT 0,
    capability_status TEXT NOT NULL DEFAULT 'Enabled',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, snapshot_date, sku_id)
);

CREATE INDEX IF NOT EXISTS idx_lic_inv_tenant_date ON tenant_license_inventory(tenant_id, snapshot_date);

CREATE TABLE IF NOT EXISTS tenant_user_license_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_principal_name TEXT NOT NULL,
    account_enabled INTEGER NOT NULL DEFAULT 1,
    user_type TEXT NOT NULL DEFAULT 'Member',
    department TEXT,
    job_title TEXT,
    usage_location TEXT,
    assigned_skus_json TEXT NOT NULL,
    assigned_plans_json TEXT NOT NULL,
    assigned_by_group INTEGER NOT NULL DEFAULT 0,
    persona_type TEXT NOT NULL,
    risk_indicators_json TEXT,
    value_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, snapshot_date, user_id)
);

CREATE INDEX IF NOT EXISTS idx_lic_prof_tenant_date ON tenant_user_license_profiles(tenant_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_lic_prof_user ON tenant_user_license_profiles(tenant_id, user_principal_name);

CREATE TABLE IF NOT EXISTS license_value_realization_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    period TEXT NOT NULL,
    total_licenses INTEGER NOT NULL DEFAULT 0,
    assigned_licenses INTEGER NOT NULL DEFAULT 0,
    idle_licenses INTEGER NOT NULL DEFAULT 0,
    total_users INTEGER NOT NULL DEFAULT 0,
    licensed_active_users INTEGER NOT NULL DEFAULT 0,
    unlicensed_active_users INTEGER NOT NULL DEFAULT 0,
    inactive_licensed_users INTEGER NOT NULL DEFAULT 0,
    duplicate_entitlement_users INTEGER NOT NULL DEFAULT 0,
    missing_prerequisite_addons INTEGER NOT NULL DEFAULT 0,
    service_health_score REAL NOT NULL DEFAULT 100.0,
    overall_value_index REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, period)
);

CREATE INDEX IF NOT EXISTS idx_lic_sum_tenant_period ON license_value_realization_summary(tenant_id, period);

CREATE TABLE IF NOT EXISTS workload_license_reconciliation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    period TEXT NOT NULL,
    workload_code TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    entitlement_count INTEGER NOT NULL DEFAULT 0,
    assignment_count INTEGER NOT NULL DEFAULT 0,
    service_plan_active_count INTEGER NOT NULL DEFAULT 0,
    configuration_active_count INTEGER NOT NULL DEFAULT 0,
    telemetry_active_count INTEGER NOT NULL DEFAULT 0,
    realization_status TEXT NOT NULL,
    gap_description TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, period, workload_code)
);

CREATE INDEX IF NOT EXISTS idx_workload_rec_tenant ON workload_license_reconciliation(tenant_id, period);

CREATE TABLE IF NOT EXISTS license_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    period TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, period)
);

CREATE INDEX IF NOT EXISTS idx_lic_snap_tenant ON license_snapshots(tenant_id, period);
