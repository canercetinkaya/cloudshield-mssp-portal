# CloudShield MSSP Platform - Operational Evidence & Service Value Audit

**Audit Title:** Deep-Layer Operational Evidence & Value Attribution Integrity Audit  
**Date:** 2026-09-10  
**Audit Entity:** KoçSistem MSSP Operations Review Board  
**Target Artifacts:**  
- `Data/manual-service-activities.json`  
- `Portal/api/report_generator.py` (Attribution Grids L234-L310)  
- `Engine/Output/Emre-TestTenant/2026-08/data.json`  
- `Engine/Output/Emre-TestTenant/2026-08/Rapor_Emre-TestTenant_2026-08.html`  

---

## 1. Executive Summary: Evidence Verification Findings

A rigorous operational audit was performed on the reported **9 MDE Analyst Actions**, **6 Purview DLP Actions**, **22.5 Saved Hours**, and **~0.1 FTE**.

| Metric | Claimed Value in Report | Authoritative Source State | Audit Status | Blocking Reason |
| :--- | :---: | :---: | :---: | :--- |
| **MDE Analyst Actions** | 9 Aksiyon | Static Runbook Reference `RB-MDE-2026-08-01` | **REJECTED AS EVIDENCE** | No individual execution records found; Runbook ID cited as action proof |
| **Purview DLP Actions** | 6 Aksiyon | Static Runbook Reference `RB-DLP-2026-08-02` | **REJECTED AS EVIDENCE** | No individual execution records found; Runbook ID cited as action proof |
| **Total Interventions** | 15 Aksiyon | Counter in Fixture/Mock | **UNSUBSTANTIATED** | Only 3 tenant activities exist in `manual-service-activities.json` |
| **Saved Engineering Hours** | 22.5 Saat | Synthetic Multiplier (`actions * 1.5`) | **DISQUALIFIED** | 1.5x multiplier in code; timesheet worklog shows only 9.5 hours |
| **FTE Equivalent** | 0.14 FTE (formerly 1.2 FTE) | `ApprovedHours / 160` | **CHANGES_REQUIRED** | Divisor formula correct (160h), but input hours are synthetic |

---

## 2. KoçSistem Action Evidence Audit (MDE 9 & DLP 6 Actions)

### 2.1 The Runbook vs. Execution Record Fallacy
In `report_generator.py`:
```python
# Line 728: MDE Attribution
evidence_id = "RB-MDE-2026-08-01"

# Line 868: Purview Attribution
evidence_id = "RB-DLP-2026-08-02"
```
The generator links **9 MDE actions** to a single static string `"RB-MDE-2026-08-01"` and **6 DLP actions** to `"RB-DLP-2026-08-02"`.  
**Auditor Finding:** A Runbook ID designates standard operating procedure instructions; it **does NOT constitute proof of completed execution**.

### 2.2 Trace to Audited Activity Database (`Data/manual-service-activities.json`)
The platform maintains an authoritative activity log in `Data/manual-service-activities.json`. A complete query for `Emre-TestTenant` reveals exactly **three (3)** recorded activities:

| Activity ID | Service Code | Activity Type | Performed At (UTC) | Evidence Ref | Hours Spent | Approval Status | Data Origin |
| :--- | :---: | :--- | :---: | :--- | :---: | :---: | :---: |
| `ACT-20260901-001` | `SVC-PRV-DLP` | PolicyTuning | 2026-09-02T10:30:00Z | `CHANGE-REQ-2026-089` | 3.5 | Completed | ProductionLog |
| `ACT-20260904-002` | `SVC-PRV-DLP` | FalsePositiveMitigation | 2026-09-04T14:15:00Z | `TICKET-MSSP-48192` | 2.0 | Completed | ProductionLog |
| `ACT-20260905-003` | `SVC-MDE` | PostureHardening | 2026-09-05T09:00:00Z | `SEC-POSTURE-2026-014` | 4.0 | Completed | ProductionLog |

### 2.3 Contradictions Discovered:
1. **Count Discrepancy:** The database contains **1 MDE action** and **2 DLP actions** (total 3 actions). The reports present **9 MDE** and **6 DLP** (total 15 actions). The extra 12 actions lack individual execution tickets.
2. **Automated vs. Manual Boundary:** In MDE, automated investigation and remediation (AIR) events were not cleanly separated from human analyst worklogs in the raw collector script.
3. **Execution Traceability:** Every claimed customer action must resolve to a discrete `ActionId` containing `PerformedAtUtc`, `EvidenceReference`, and `ApprovalStatus`.

---

## 3. Saved Hours & FTE Capacity Analysis

### 3.1 Uncovering the Synthetic 1.5x Multiplier
Inspection of `Portal/api/report_generator.py` reveals the exact mathematical origin of the **22.5 saved hours**:
```python
# report_generator.py Line 732 (MDE):
saved_hours = float(kpis.get("TasarrufEdilenSaat") or round(analyst_actions * 1.5, 1))

# report_generator.py Line 872 (Purview DLP):
saved_hours = float(kpis.get("KazanilanZamanSaat") or round(eng_effort * 1.5, 1))
```
- For MDE (9 actions): \(9 \times 1.5 = 13.5\text{ hours}\).
- For Purview (6 actions): \(6 \times 1.5 = 9.0\text{ hours}\).
- Total Consolidated: \(13.5 + 9.0 = 22.5\text{ hours}\).

**Auditor Verdict:** The reported 22.5 hours does **NOT** originate from ticket worklogs or measured execution times. It is derived entirely from an arbitrary hardcoded coefficient (`* 1.5`).

### 3.2 Real vs. Claimed Hours Comparison:
- **Actual Logged Worklog Hours:** \(3.5 + 2.0 + 4.0 = \mathbf{9.5\text{ hours}}\).
- **Reported Synthetic Hours:** \(\mathbf{22.5\text{ hours}}\).
- **Inflation Factor:** \(236.8\%\) unverified inflation.

### 3.3 FTE Capacity Formula Audit:
- Standard Formula: \(\text{FTE} = \frac{\text{ApprovedSavedHours}}{160}\).
- Under 9.5 audited hours: \(\text{FTE} = \frac{9.5}{160} = \mathbf{0.06\text{ FTE}}\).
- Under 22.5 synthetic hours: \(\text{FTE} = \frac{22.5}{160} = \mathbf{0.14\text{ FTE}}\).
- **Directive Compliance:** The previous author eliminated the arbitrary fallback `if ($fteKapasite -lt 0.8) { $fteKapasite = 1.2 }`, which is positive. However, claiming *\"Kazanılan Efor (~0.1 FTE)\"* based on a synthetic multiplier still violates customer governance standards.

---

## 4. Remediation Directives for Production Release

1. **Mandate Individual Execution Records:**
   Replace single runbook strings with discrete `EvidenceRecord` arrays pulled directly from `Data/manual-service-activities.json`.
2. **Eliminate Synthetic Multipliers:**
   Remove `round(analyst_actions * 1.5, 1)`. If `TasarrufEdilenSaat` is not logged in approved timesheets, render `"N/A"` or `"Doğrulanmış Süre Kaydı Yok"`.
3. **FTE Card Suppression:**
   When verified hours are 0 or unbacked, display `0.0 FTE` with label `Doğrulanmış İş Gücü Tasarrufu Kaydı Bulunmuyor`. Never claim capacity gain without ticket worklogs.
