-- CloudShield MSSP Platform Migration 003: Managed Service Activities & KPI Provenance
-- Schema for Verifiable Engineering Activities and Immutable Metric Provenance

CREATE TABLE IF NOT EXISTS managed_service_activities (
    activity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    service_code TEXT NOT NULL,
    period TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    ticket_ref TEXT,
    engineer_role TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    status TEXT NOT NULL,
    related_risk TEXT,
    related_target TEXT,
    requires_approval INTEGER DEFAULT 0,
    approved_by TEXT,
    outcome TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    hours_spent REAL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_act_tenant_period ON managed_service_activities(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_act_service ON managed_service_activities(service_code);

CREATE TABLE IF NOT EXISTS kpi_provenance_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    period TEXT NOT NULL,
    service_code TEXT NOT NULL,
    kpi_id TEXT NOT NULL,
    metric_value TEXT,
    source_api TEXT NOT NULL,
    query_used TEXT,
    data_freshness TEXT,
    trust_level TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    completeness_status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kpi_prov_tenant_period ON kpi_provenance_records(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_kpi_prov_kpi_id ON kpi_provenance_records(kpi_id);
