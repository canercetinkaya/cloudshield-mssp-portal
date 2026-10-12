-- CloudShield MSSP Platform Migration 004: Observed Technical Improvements
-- Completely replaces Ticket/CR/Manual engineering logging with automated telemetry-derived improvements.
-- Sources: Purview AuditLog, Entra DirectoryAudit, MDE SecurityCenter Audit, MDCA DiscoveredApp Events.

CREATE TABLE IF NOT EXISTS observed_technical_improvements (
    improvement_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    service_code TEXT NOT NULL,
    period TEXT NOT NULL,
    category TEXT NOT NULL,
    component TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    technical_impact TEXT NOT NULL,
    telemetry_source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_imp_tenant_period ON observed_technical_improvements(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_imp_service ON observed_technical_improvements(service_code);
