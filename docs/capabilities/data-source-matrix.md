# CloudShield MSSP Data Source Matrix

Official Microsoft APIs, cmdlets, Advanced Hunting tables, and endpoints utilized across all 12 services with lookback limits and availability states.

| Query ID | Service | Data Source Target | Official Endpoint / Method | API Version | Availability State | Lookback Limit | Throttling Limits |
|:---|:---|:---|:---|:---:|:---|:---:|:---|
| **QRY-GRAPH-SECURE-SCORE** | All | Microsoft Graph | `GET /v1.0/security/secureScores?$top=1` | v1.0 (GA) | `SupportedAppOnly` | 90 Days | 300 req/min |
| **QRY-GRAPH-ALERTS-V2** | XDR, MDE, MDO, MDI, MDCA, DLP | Microsoft Graph | `GET /v1.0/security/alerts_v2` | v1.0 (GA) | `SupportedAppOnly` | 30 Days | 1000 req/min |
| **QRY-GRAPH-INCIDENTS** | SVC-XDR | Microsoft Graph | `GET /v1.0/security/incidents` | v1.0 (GA) | `SupportedAppOnly` | 30 Days | 500 req/min |
| **QRY-GRAPH-THREAT-HUNTING** | MDE, MDO, MDI, MDCA | Microsoft Graph | `POST /v1.0/security/runHuntingQuery` | v1.0 (GA) | `SupportedAdvancedHunting` | 30 Days | 45 req/min, 15 concurrent |
| **QRY-MDE-MACHINES** | SVC-MDE | WindowsDefenderATP | `GET /api/machines?$top=500` | v1.0 (GA) | `SupportedAppOnly` | 30 Days | 100 req/min |
| **QRY-INTUNE-DEVICES** | SVC-INTUNE | Microsoft Graph | `GET /v1.0/deviceManagement/managedDevices` | v1.0 (GA) | `SupportedAppOnly` | 30 Days | 1000 req/min |
| **QRY-ENTRA-ROLES** | SVC-ENTRA-PIM | Microsoft Graph | `GET /v1.0/roleManagement/directory/roleAssignments` | v1.0 (GA) | `SupportedAppOnly` | Realtime | 500 req/min |
| **QRY-PRV-LABELS** | SVC-PRV-CLASS | Microsoft Graph | `GET /v1.0/security/informationProtection/sensitivityLabels` | v1.0 (GA) | `SupportedAppOnly` | Realtime | 300 req/min |
| **QRY-PRV-RETENTION** | SVC-PRV-GOV | Microsoft Graph | `GET /v1.0/security/labels/retentionLabels` | v1.0 (GA) | `SupportedAppOnly` | Realtime | 300 req/min |
| **QRY-PRV-AUDIT-AI** | SVC-AI-SECURITY | Microsoft Graph | `GET /v1.0/auditLogs/directoryAudits` | v1.0 (GA) | `SupportedAppOnly` | 30 Days | 300 req/min |

## Data Availability Semantics
The platform enforces strict AvailabilityStates. Data is **never** coerced to zero when unavailable:
- **SupportedAppOnly**: Officially validated daemon/application-only API without user intervention.
- **SupportedAdvancedHunting**: Direct Defender KQL execution via Graph Security API.
- **DerivedFromSupportedFields**: Metrics mathematically calculated from valid telemetry objects.
- **NoData**: Successful query execution, but zero events recorded in the tenant within lookback period.
- **PermissionMissing**: Tenant application registration lacks the required scope or admin consent.
- **NotLicensed**: The customer tenant does not possess the requisite SKU/license.
- **CollectionFailed**: Network/API error during collection; flagged with diagnostic correlation ID.
