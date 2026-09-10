# CloudShield MSSP Platform - Data Source & Telemetry Matrix

**Document Version:** 2.0.0  
**Classification:** Technical Telemetry Matrix  

---

## 1. Live API & Advanced Hunting Telemetry Mapping

| Service Code | Live Microsoft API Endpoint | Advanced Hunting KQL Tables | Primary Entity Analyzed |
| :--- | :--- | :--- | :--- |
| **`SVC-MDE`** | `https://api.securitycenter.microsoft.com/api/machines` | `DeviceInfo`, `DeviceAlertEvents`, `DeviceEvents` | Endpoint devices, sensors, vulnerabilities |
| **`SVC-MDO`** | `https://graph.microsoft.com/v1.0/security/alerts_v2` | `EmailEvents`, `EmailPostDeliveryEvents` | Inbound emails, malware, phishing campaigns |
| **`SVC-MDI`** | `https://graph.microsoft.com/v1.0/security/alerts_v2` | `IdentityLogonEvents`, `IdentityQueryEvents` | Active Directory logons, Kerberos tickets |
| **`SVC-MDCA`**| `https://graph.microsoft.com/v1.0/security/alerts_v2` | `CloudAppEvents` | SaaS applications, OAuth grants, shadow IT |
| **`SVC-XDR`** | `https://graph.microsoft.com/v1.0/security/incidents` | Unified Incident Graph | Correlated cross-domain attack stories |
| **`SVC-PRV-DLP`**| `https://graph.microsoft.com/v1.0/security/alerts_v2` | `DlpEvents` | Data exfiltration, USB copies, overrides |
| **`SVC-PRV-CLASS`**| `https://graph.microsoft.com/v1.0/informationProtection`| Audit logs | Sensitivity labels, classified files |
| **`SVC-PRV-GOV`**| `https://graph.microsoft.com/v1.0/recordsManagement` | Audit logs | Retention labels, expired records, disposals |
