# Unsupported, Portal-Only, and Delegated Capabilities

This document provides explicit transparency regarding metrics, settings, and telemetry that cannot be collected automatically via Application-Only APIs in an unattended service model.

## 1. Portal-Only Capabilities (Manual Export Required)
The following features do not currently offer a supported public Application-Only REST API or PowerShell cmdlet suitable for unattended daemon collection:
- **Purview DLP Policy Simulation Matches**: Simulation mode evaluations must be viewed directly inside Microsoft Purview Compliance Portal or exported manually via CSV.
- **Communication Compliance Forensic Message Bodies**: Granular unmasked message content review requires active investigator delegated session with supervisory RBAC in Purview Portal.
- **Defender for Cloud Apps Cloud Discovery Raw Log Ingestion Uploads**: Manual firewall log uploads are portal-managed operations.
- **Intune Remote Action History (Wipe / Retire logs older than 30 days)**: Only active device states are exposed via Graph; legacy audit actions require manual audit log query.

## 2. Delegated-Only Endpoints (Prohibited for Unattended Schedulers)
In accordance with CloudShield security standards, delegated user authentication is **prohibited** for monthly background Task Scheduler runs:
- `ExchangePowerShell` cmdlets requiring interactive multi-factor authentication (MFA).
- Security & Compliance PowerShell cmdlets that lack app-only certificate support (`Connect-IPPSSession` interactive modes).
- User-delegated Graph endpoints (`/me/` or delegative search).

## 3. Deprecated APIs Explicitly Blocked
- Deprecated Azure AD Graph (`graph.windows.net`) endpoints.
- Deprecated Entra PIM `privilegedAccess` beta endpoints (superseded by `/roleManagement/directory/`).
- MDE legacy OData v1 alert endpoints (superseded by Graph `/security/alerts_v2`).

## 4. Availability Flagging Rule
When any of the above items are selected in an ad-hoc or extended report:
- The system flags them with `PortalOnly` or `ManualExportOnly`.
- Under no circumstances does the engine substitute zero or fabricated mock numbers.
