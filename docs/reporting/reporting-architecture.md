# CloudShield MSSP Platform - Report Generation Lifecycle & Architecture

**Document Version:** 2.0.0  
**Classification:** Core Reporting Architecture  

---

## 1. End-to-End Report Generation Lifecycle

The report compilation pipeline follows an immutable 9-stage progression from raw cloud telemetry to signed A4 vector PDFs:

```mermaid
flowchart TD
    Collector["1. Telemetry Collector<br/>(PowerShell 7.4 / Graph API / KQL)"]
    --> Normalization["2. Data Normalization<br/>(Availability State & k-Anonymity)"]
    --> KpiEngine["3. KPI Calculation Engine<br/>(Strict Arithmetic & Non-Zero Denominators)"]
    --> ProvenanceEngine["4. Provenance Engine<br/>(QueryCatalog & Permission Matrix Binding)"]
    --> QualityGate["5. Semantic Quality Gate<br/>(14 Automated Semantic Failure Rules)"]
    --> DecisionFramework["6. Four-Quadrant Decision Framework<br/>(Approved, Pending, Deferred, Recommended)"]
    --> ExecutiveReport["7. C-Level Executive Brief<br/>(6 Mandatory Questions & 4 Value Pillars)"]
    --> TechnicalReport["8. Service Technical Scorecards<br/>(KQL Telemetry Tables & Anomaly Deltas)"]
    --> Rendering["9. HTML & Vector PDF Rendering<br/>(A4 Print Layout via Headless Edge/Chrome)"]
```

---

## 2. Dual Output Format Strategy

1. **Interactive HTML (`.html`):**
   - Responsive web preview embedded in the CloudShield MSSP Portal.
   - Preserves complete `data-*` attributes for automated compliance audits.
2. **Vector A4 PDF (`.pdf`):**
   - High-fidelity printable report generated via Chromium `--headless=new --print-to-pdf`.
   - Formatted for boardroom presentation with exact page budgets and vector typography.
