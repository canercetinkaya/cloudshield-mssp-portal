# CloudShield MSSP Platform - Service Capability Matrix

**Document Version:** 2.0.0  
**Classification:** Functional Capability Matrix  

---

## 1. Capability Classification Tiers

Each service module is classified into one of three operational tiers:

1. **Fully Automated Reporting (`FullReporting`):** Complete end-to-end data collection via Microsoft Graph Application permissions and Advanced Hunting KQL. Full executive cards, tables, and trend deltas rendered.
2. **Partial / Delegated Reporting (`DelegatedReporting`):** Telemetry requires interactive user delegation or delegated PIM activation (e.g. `SVC-ENTRA-PIM`). Disclosed on Page 1.
3. **Portal-Only / Advisory (`AdvisoryOnly`):** Features requiring deep interactive investigation in the native Microsoft Security / Purview portal. Supported via GDAP deep links rather than automated batch reporting.
