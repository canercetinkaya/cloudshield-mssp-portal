# Token Broker Specification

## 1. Authentication Architecture
The Token Broker resides in `Engine/Core/Authentication.psm1` and provides managed, least-privilege Entra ID tokens with zero cleartext secret exposure.

### Key Capabilities
- **Authentication Profiles:** Granular permission boundaries per functional area.
- **Certificate-Based Authentication (CBA):** Support for X.509 client certificates (Azure Key Vault / Local Cert Store).
- **In-Memory Token Caching:** Caches tokens per `(TenantId + TargetResource + AppProfile)` with 5-minute pre-expiration renewal.
- **401/403 Circuit Breakers:** Graceful degradation with explicit `AvailabilityState` logging.

---

## 2. Authentication Profiles
1. `CoreSecurityReporting`:
   - Target: Microsoft Graph & MDE dedicated API.
   - Required Scopes: `SecurityAlert.Read.All`, `ThreatHunting.Read.All`, `Machine.Read.All`.
2. `PurviewReporting`:
   - Target: Purview / Microsoft Graph Security.
   - Required Scopes: `InformationProtectionPolicy.Read.All`, `SecurityAlert.Read.All`.
3. `SensitiveComplianceReporting`:
   - Target: Compliance Center / Security Center.
   - Required Scopes: `AuditLog.Read.All`, `RecordsManagement.Read.All`.
4. `ReportMailSender`:
   - Target: Exchange Online / Graph Mail.
   - Required Scopes: `Mail.Send` (scoped strictly to MSSP notification mailbox).

---

## 3. Cache Key & Session Reuse
Tokens are stored in-memory in `$script:TokenCache`:
```powershell
$cacheKey = "$($PlatformConfig.CustomerConfig.TenantId):$TargetResource:$AppProfile"
```
Before requesting a new token from Entra ID endpoint, the Token Broker checks if a valid, unexpired token exists. If expiry is within 300 seconds, an autonomous renewal is executed.
