# Master Architecture Specification

## 1. Product Vision & Scope
**CloudShield MSSP Portal** is an enterprise-grade managed security and compliance reporting engine designed for KoçSistem MSSP operations. It interfaces directly with Microsoft Defender XDR and Microsoft Purview to generate C-Level executive reports, compliance scorecards, and threat hunting insights for enterprise clients.

### Core Architectural Principle: 100% Dynamic Data Shell
- Reports are **Data Shells**: templates contain zero hardcoded metrics, zero mock incident numbers, and zero hallucinated financial cost avoidances.
- If live telemetry is present, tables populate dynamically from validated API/KQL collectors.
- If a tenant experiences zero threats/incidents during a reporting window, the system renders a verified **Zero Incident Verified** / **Proaktif Uyum Güvencesi** posture rather than fabricating numbers.

---

## 2. Multi-Tenant Architecture & Data Isolation
1. **Tenant Segregation:**
   - Every tenant is registered in `Data/tenants.json` with an explicit `TenantId`, `TenantType` (`Live` vs `Sandbox`), and dedicated authentication configuration.
   - Live tenant operations execute strictly in isolated memory sessions.
   - Temporary artifacts are written to `Engine/Output/<TenantId>/<Period>/` and never leak across tenant boundaries.

2. **Least Privilege & Role Boundaries:**
   - **No Wide Admin Roles:** The platform never uses `Global Administrator` or `Company Administrator`.
   - **Read-Only Scopes:** All live data collection uses granular read-only Graph/MDE scopes (`SecurityAlert.Read.All`, `ThreatHunting.Read.All`, `InformationProtectionPolicy.Read.All`).
   - **Service Delegation:** KoçSistem engineer access is governed by Microsoft GDAP (Granular Delegated Admin Privileges).
   - **Zero SOC Rule:** Cleartext credentials, API keys, and client secrets are strictly prohibited from codebase and git tracking. Managed Identities and Azure Key Vault are mandatory.

---

## 3. Service Portfolio (12 Enterprise Services)
The engine provides unified reporting across 12 distinct managed service modules:
1. `SVC-MDE`: Microsoft Defender for Endpoint (EDR, TVM, ASR)
2. `SVC-MDO`: Microsoft Defender for Office 365 (Anti-Phish, Safe Attachments, ZAP)
3. `SVC-MDI`: Microsoft Defender for Identity (Kerberos, DC Telemetry, Lateral Movement)
4. `SVC-MDCA`: Microsoft Defender for Cloud Apps (Shadow IT, App Governance, OAuth)
5. `SVC-XDR`: Integrated Microsoft Defender XDR (Cross-domain Incident Correlation)
6. `SVC-ENTRA`: Entra ID Protection & Privileged Identity Management (PIM)
7. `SVC-PRV-DLP`: Microsoft Purview Data Loss Prevention (Endpoint, Exchange, SharePoint, Teams)
8. `SVC-PRV-CLASS`: Microsoft Purview Information Protection (Sensitivity Labels, SITs)
9. `SVC-PRV-GOV`: Microsoft Purview Data Lifecycle Management & Records Management
10. `SVC-PRV-RISK`: Microsoft Purview Insider Risk Management & Adaptive Protection
11. `SVC-PRV-DSPM`: Microsoft Purview Data Security Posture Management (DSPM)
12. `SVC-AI-SECURITY`: Microsoft Purview AI Hub & Defender for Cloud Apps GenAI Protection (Copilot / ChatGPT security)

---

## 4. Execution Workflow
`mermaid
graph TD
    A[Web Portal / API Trigger] --> B[Engine/Invoke-CloudShieldSecurityReporting.ps1]
    B --> C[Core/Authentication.psm1 Token Broker]
    C --> D[Service Plugins / KQL Collectors]
    D --> E[Data/tenants/<Tenant>/data.json]
    E --> F[Portal/api/report_generator.py]
    F --> G[HTML Executive Report]
    G --> H[Edge/Chromium Headless PDF Engine]
`
