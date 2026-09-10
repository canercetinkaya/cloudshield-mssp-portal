# CloudShield MSSP Platform - Data Provenance & Traceability Architecture

## 1. Overview
In enterprise security reporting, ungrounded synthetic data or ambiguous metric origins destroy customer trust. The CloudShield platform binds every visible metric to an explicit data origin and collection status.

## 2. Metric Provenance Schema
Every KPI object records kpiId, serviceCode, value, unit, sourceQueryIds, dataOrigin, collectionStatus, collectedAtUtc, and synthetic.

## 3. Operational Guarantees
- Zero Incident Verified posture: Missing telemetry is never converted to arbitrary zeros; reports explicitly distinguish zero verified events from missing permissions.
- Absolute compliance claims are rejected by test gates.
