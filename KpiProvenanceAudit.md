# CloudShield MSSP Platform - KPI Provenance & Telemetry Lineage Audit

**Audit Version:** 2.0.0-AUDIT  
**Date:** 2026-09-10  
**Evaluator:** Principal Security Architect & Lead DevSecOps Auditor  
**Scope:** Verification of KPI Cards, Provenance Attributes, Catalog Mappings, and Permission Bounds.  
**Audited Artifacts:**  
- `Engine/Output/Emre-TestTenant/2026-08/Rapor_Emre-TestTenant_2026-08.html`  
- `Engine/Output/Emre-TestTenant/2026-08/Rapor_Emre-TestTenant_2026-08_MDE.html`  
- `Engine/Output/Emre-TestTenant/2026-08/Rapor_Emre-TestTenant_2026-08_Purview.html`  
- `Engine/KQL/query-metadata/catalog-index.json`  
- `Engine/Config/service-catalog.json`  
- `docs/security/permission-matrix.md`  

---

## 1. Executive Summary: Provenance Audit Findings

Every customer-facing metric must carry auditable cryptographic and operational lineage. The audit revealed **three major provenance failures**:

1. **Total Absence in Consolidated Report:** The primary customer artifact (`Rapor_Emre-TestTenant_2026-08.html`) contains **zero** `data-kpi-id`, `data-source-query`, or `data-origin` attributes on its summary cards.
2. **Catalog Index Misalignment:** In the single-service reports (`_MDE.html` and `_Purview.html`), the `data-source-query` attributes contain **informal ad-hoc strings** (e.g. `'DeviceEvents | count'`, `'Active / TotalAD'`) instead of formal Query Catalog identifiers (`MS-MDE-001`, `MS-MDE-002`, etc.).
3. **Synthetic / Mock Origin in Customer Storage:** The customer `data.json` produced by the portal workflow recorded `availabilityState: "DryRunMock"` rather than live authenticated telemetry, failing the actual data separation mandate.

---

## 2. Provenance Mapping Verification Table

| Report Artifact | Card / KPI Title | `data-kpi-id` | `data-source-query` | `QueryCatalog` Match? | `data-origin` | `PermissionMatrix` Scope | Audit Verdict |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- | :---: |
| **Consolidated** | Toplam Otonom Bloklama | *Missing* | *Missing* | **NO (None)** | *Missing* | `ThreatHunting.Read.All` | **FAIL: Missing Provenance** |
| **Consolidated** | Toplam Hassas Veri Eşleşmesi | *Missing* | *Missing* | **NO (None)** | *Missing* | `InformationProtectionPolicy.Read.All` | **FAIL: Missing Provenance** |
| **MDE Single** | Toplam Cihaz (Envanter) | `KPI-MDE-01` | `DeviceEvents \| count` | **NO (Ad-hoc)** | `MDE DeviceInventory` | `Machine.Read.All` | **FAIL: Uncataloged Query** |
| **MDE Single** | Aktif / Görünür Uç Nokta | `KPI-MDE-02` | `HeartbeatEvents` | **NO (Ad-hoc)** | `MDE DeviceEvents` | `Machine.Read.All` | **FAIL: Uncataloged Query** |
| **MDE Single** | Algılayıcı Kapsama Oranı | `KPI-MDE-03` | `Active / TotalAD` | **NO (Ad-hoc)** | `MDE / Intune` | `DeviceManagementManagedDevices.Read.All` | **FAIL: Uncataloged Query** |
| **MDE Single** | TVM Güvenlik Uyum Oranı | `KPI-MDE-04` | `DeviceTvmSoftwareInventory` | **NO (Ad-hoc)** | `MDE Vulnerabilities` | `Vulnerability.Read.All` | **FAIL: Uncataloged Query** |
| **Purview Single** | Toplam Kural Eşleşmesi | `KPI-PRV-01` | `DlpEvents \| count` | **NO (Ad-hoc)** | `Purview AuditLog` | `SecurityEvents.Read.All` | **FAIL: Uncataloged Query** |
| **Purview Single** | Otonom Engellenen Olay | `KPI-PRV-02` | `Action == Block` | **NO (Ad-hoc)** | `Purview PolicyEngine` | `SecurityEvents.Read.All` | **FAIL: Uncataloged Query** |
| **Purview Single** | Kural Koruma Oranı | `KPI-PRV-03` | `Blocked / Total` | **NO (Ad-hoc)** | `Purview Metrics` | `SecurityEvents.Read.All` | **FAIL: Uncataloged Query** |
| **Purview Single** | Kullanıcı Kural Aşımları | `KPI-PRV-04` | `UserOverrides \| count` | **NO (Ad-hoc)** | `Purview AuditEvents` | `AuditLog.Read.All` | **FAIL: Uncataloged Query** |

---

## 3. Query Catalog & Permission Matrix Consistency

### 3.1 Catalog Resolution Failure
In `Engine/KQL/query-metadata/catalog-index.json`, formal query definitions are indexed by standardized IDs:
- `MS-MDE-001`: Ransomware File Activity (`DeviceFileEvents`, `DeviceProcessEvents`)
- `MS-MDE-002`: LSASS Memory Dumping (`DeviceProcessEvents`, `DeviceEvents`)
- `MS-MDE-003`: LOLBins Command Line Execution (`DeviceProcessEvents`)
- `MS-DLP-001`: Bulk Sensitive Data Exfiltration (`DlpEvents`)

The report generator bypassed these catalog records and directly inserted pseudo-query strings (`"DeviceEvents | count"`), making automated query provenance verification impossible.

### 3.2 Permission Matrix Compliance
Permissions defined in `docs/security/permission-matrix.md` are correctly restricted to **least-privilege read-only** application scopes:
- No write permissions (`Machine.ReadWrite`, `SecurityEvents.ReadWrite`) are requested.
- CBA (Certificate-Based Authentication) is enforced for multi-tenant GDAP isolation.

---

## 4. Required Architecture Changes

1. **Update `render_kpi_cell` Callers:**
   Replace informal query strings with official IDs from `catalog-index.json`:
   - `KPI-MDE-01` \(\rightarrow\) `query_id="MS-MDE-001"` (or dedicated inventory query `MS-MDE-INV-01`).
   - `KPI-PRV-01` \(\rightarrow\) `query_id="MS-DLP-001"`.
2. **Instrument Consolidated Report Cards:**
   Update `build_golden_consolidated_html` to emit `data-kpi-id`, `data-source-query`, and `data-origin` on all summary cards.
3. **Enforce Strict Origin Segregation:**
   Block generation of customer-facing artifacts when `availabilityState == "DryRunMock"` unless explicitly marked with a high-visibility `TestArtifact` banner.
