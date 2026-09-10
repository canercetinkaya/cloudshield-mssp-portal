# CloudShield MSSP Platform - Service Catalog & Supported Modules

**Document Version:** 2.0.0  
**Classification:** Service Catalog  

---

## 1. The 12 Supported Enterprise Services

CloudShield supports modular reporting across the entire Microsoft Defender XDR and Microsoft Purview product suites:

| Service Code | Service Name | Management Tier | Primary Telemetry Sources |
| :--- | :--- | :---: | :--- |
| **`SVC-MDE`** | Microsoft Defender for Endpoint | Managed EDR | `DeviceInfo`, `DeviceEvents`, `DeviceProcessEvents` |
| **`SVC-MDO`** | Microsoft Defender for Office 365 | Managed Email | `EmailEvents`, `EmailPostDeliveryEvents`, ZAP |
| **`SVC-MDI`** | Microsoft Defender for Identity | Managed Identity | `IdentityLogonEvents`, `IdentityQueryEvents` |
| **`SVC-MDCA`**| Microsoft Defender for Cloud Apps | Managed CASB | `CloudAppEvents`, `OAuthAppGovernance` |
| **`SVC-XDR`** | Microsoft Defender XDR Unified | Managed XDR | `/security/incidents`, Multi-Stage Correlation |
| **`SVC-INTUNE`**| Microsoft Intune Compliance | Device Posture | `/deviceManagement/managedDevices` |
| **`SVC-ENTRA-PIM`**| Entra ID Protection & PIM | Identity Governance| `/identityProtection/riskyUsers`, PIM Logs |
| **`SVC-PRV-DLP`**| Microsoft Purview DLP | Data Protection | `DlpEvents`, `/security/alerts_v2` |
| **`SVC-PRV-CLASS`**| Purview Information Protection | Classification | `/informationProtection/policy/labels` |
| **`SVC-PRV-GOV`**| Purview Data Lifecycle & Records | Data Lifecycle | `/recordsManagement/retentionLabels` |
| **`SVC-PRV-RISK`**| Purview Insider Risk Management | Internal Threats | Insider Risk Policies (Isolated Profile) |
| **`SVC-AI-SECURITY`**| Purview AI Hub & GenAI Security | AI Governance | Management API `Audit.General`, Copilot Events |
