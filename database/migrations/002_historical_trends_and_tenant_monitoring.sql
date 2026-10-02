-- CloudShield MSSP Platform Migration 002: Historical Trends & Tenant Credential Monitoring
-- SQLite Relational Schema for 12-Month Time-Series Metrics and Secret Lifecycle

CREATE TABLE IF NOT EXISTS tenant_historical_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    period TEXT NOT NULL,
    service_code TEXT NOT NULL,
    secure_score REAL DEFAULT 0.0,
    threats_blocked INTEGER DEFAULT 0,
    critical_incidents INTEGER DEFAULT 0,
    dlp_violations INTEGER DEFAULT 0,
    phishing_blocked INTEGER DEFAULT 0,
    pim_activations INTEGER DEFAULT 0,
    device_compliance_pct REAL DEFAULT 0.0,
    hours_saved REAL DEFAULT 0.0,
    cost_avoidance_usd REAL DEFAULT 0.0,
    recorded_at TEXT NOT NULL,
    raw_summary_json TEXT,
    UNIQUE(tenant_id, period, service_code)
);

CREATE INDEX IF NOT EXISTS idx_hist_tenant_period ON tenant_historical_metrics(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_hist_tenant_service ON tenant_historical_metrics(tenant_id, service_code);

CREATE TABLE IF NOT EXISTS tenant_credential_health (
    tenant_id TEXT PRIMARY KEY,
    auth_type TEXT DEFAULT 'ClientSecret',
    secret_expiry_date TEXT,
    cert_expiry_date TEXT,
    last_preflight_check TEXT,
    last_preflight_status TEXT,
    days_until_expiry INTEGER,
    health_status TEXT DEFAULT 'Healthy',
    updated_at TEXT NOT NULL
);
