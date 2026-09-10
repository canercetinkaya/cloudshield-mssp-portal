# CloudShield MSSP Platform - Permission Matrix & Least-Privilege Scopes

**Document Version:** 2.0.0  
**Classification:** Security Architecture Specification  

---

## 1. Least-Privilege Access Strategy

CloudShield enforces strict Granular Delegated Admin Privileges (GDAP) and read-only Microsoft Graph / Defender application permissions:

| Service Code | Module Name | Microsoft Graph / Defender Scope | Permission Type | Operational Justification |
| :--- | :--- | :--- | :---: | :--- |
| **`SVC-MDE`** | Defender for Endpoint | `Machine.Read.All`<br>`ThreatHunting.Read.All` | Application | Device inventory, sensor health, and KQL hunting. |
| **`SVC-MDO`** | Defender for Office 365 | `SecurityAlert.Read.All`<br>`ThreatHunting.Read.All` | Application | Phishing volumes, malware delivery, and ZAP telemetry. |
| **`SVC-MDI`** | Defender for Identity | `SecurityAlert.Read.All`<br>`IdentityQueryEvents` | Application | Identity threat alerts and domain controller telemetry. |
| **`SVC-MDCA`**| Defender for Cloud Apps | `CloudAppEvents.Read.All` | Application | Shadow IT discovery and OAuth application risks. |
| **`SVC-XDR`** | Defender XDR Incidents | `SecurityIncident.Read.All` | Application | Multi-stage incident correlation and MTTR calculation. |
| **`SVC-PRV-DLP`** | Purview DLP | `SecurityEvents.Read.All`<br>`AuditLog.Read.All` | Application | DLP rule matches, blocks, and user overrides. |
| **`SVC-PRV-CLASS`**| Information Protection | `InformationProtectionPolicy.Read.All` | Application | Sensitivity label taxonomy and SIT match volumes. |
| **`SVC-PRV-GOV`**| Purview Governance | `RecordsManagement.Read.All` | Application | Retention label adoption and records management. |
| **`SVC-PRV-RISK`**| Insider Risk Management | `SecurityAlert.Read.All` (Isolated App) | Application | Sensitive internal anomaly indicators (strict isolation). |
| **`SVC-AI-SECURITY`**| Purview AI Hub | `Audit.General` (Management API) | Application | Enterprise Copilot and GenAI interaction telemetry. |

---

## 2. Zero High-Privilege Roles

The platform strictly prohibits:
- `Directory.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`
- `Global Administrator` or `Security Administrator` role assignments.
