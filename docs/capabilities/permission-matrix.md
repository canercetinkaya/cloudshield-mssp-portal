# CloudShield MSSP Permission Matrix

Minimum required Microsoft Graph and WindowsDefenderATP application permissions per service and authentication profile, conforming strictly to the Principle of Least Privilege (PoLP).

| Perm ID | Resource | Permission Name | Type | Auth Profile | Admin Consent | Required License / SKU | Dependent Services |
|:---|:---|:---|:---:|:---|:---:|:---|:---|
| **PERM-MDE-001** | Microsoft Graph | `ThreatHunting.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDE P2 / E5 | SVC-MDE, SVC-MDO, SVC-MDI, SVC-MDCA |
| **PERM-MDE-002** | Microsoft Graph | `SecurityAlert.Read.All` | Application | `CoreSecurityReporting` | **Yes** | Defender Suite / E5 | SVC-MDE, SVC-MDO, SVC-MDI, SVC-MDCA, SVC-XDR, SVC-PRV-DLP |
| **PERM-MDE-003** | WindowsDefenderATP | `Machine.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDE P1/P2 | SVC-MDE |
| **PERM-MDE-004** | WindowsDefenderATP | `AdvancedQuery.Read.All`| Application | `CoreSecurityReporting` | **Yes** | MDE P2 | SVC-MDE |
| **PERM-MDO-001** | Microsoft Graph | `SecurityAlert.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDO P1/P2 | SVC-MDO |
| **PERM-MDO-002** | Microsoft Graph | `ThreatHunting.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDO P2 | SVC-MDO |
| **PERM-MDI-001** | Microsoft Graph | `SecurityAlert.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDI | SVC-MDI |
| **PERM-MDI-002** | Microsoft Graph | `IdentityRiskyUser.Read.All`| Application | `CoreSecurityReporting` | **Yes** | Entra ID P2 | SVC-MDI |
| **PERM-MDCA-001**| Microsoft Graph | `SecurityAlert.Read.All` | Application | `CoreSecurityReporting` | **Yes** | MDCA | SVC-MDCA |
| **PERM-MDCA-002**| Microsoft Graph | `Application.Read.All` | Application | `CoreSecurityReporting` | **Yes** | Entra ID P1/P2 | SVC-MDCA |
| **PERM-XDR-001** | Microsoft Graph | `SecurityIncident.Read.All`| Application | `CoreSecurityReporting` | **Yes** | Defender XDR | SVC-XDR |
| **PERM-INTUNE-001**| Microsoft Graph| `DeviceManagementManagedDevices.Read.All` | Application | `CoreSecurityReporting` | **Yes** | Intune P1 | SVC-INTUNE |
| **PERM-INTUNE-002**| Microsoft Graph| `DeviceManagementConfiguration.Read.All` | Application | `CoreSecurityReporting` | **Yes** | Intune P1 | SVC-INTUNE |
| **PERM-PIM-001** | Microsoft Graph | `RoleManagement.Read.Directory` | Application | `CoreSecurityReporting` | **Yes** | Entra ID P1/P2 | SVC-ENTRA-PIM |
| **PERM-PIM-002** | Microsoft Graph | `PrivilegedAccess.Read.AzureADGroup` | Application | `CoreSecurityReporting` | **Yes** | Entra ID Governance | SVC-ENTRA-PIM |
| **PERM-PRV-001** | Microsoft Graph | `InformationProtectionPolicy.Read.All` | Application | `PurviewReporting` | **Yes** | Purview MIP E3/E5 | SVC-PRV-DLP, SVC-PRV-CLASS |
| **PERM-PRV-002** | Microsoft Graph | `SecurityAlert.Read.All` | Application | `PurviewReporting` | **Yes** | Purview DLP E5 | SVC-PRV-DLP |
| **PERM-PRV-003** | Microsoft Graph | `RecordsManagement.Read.All`| Application | `PurviewReporting` | **Yes** | Purview DLM/Records E5 | SVC-PRV-GOV |
| **PERM-PRV-004** | Microsoft Graph | `SecurityAlert.Read.All` | Application | `SensitiveComplianceReporting` | **Yes** | Purview Insider Risk E5 | SVC-PRV-RISK (Isolated App) |
| **PERM-AI-001**  | Microsoft Graph | `AuditLog.Read.All` | Application | `PurviewReporting` | **Yes** | Purview Audit E5 / Copilot | SVC-AI-SECURITY |

## Principle of Least Privilege (PoLP) Directives
1. **Read-Only Scope**: No `ReadWrite`, `Directory.AccessAsUser.All`, or `RoleManagement.ReadWrite.Directory` permissions are ever requested for reporting.
2. **App-Profile Isolation**: Sensitive compliance telemetry (`SVC-PRV-RISK`) must run under an isolated Entra ID application registration with restricted administrator access.
