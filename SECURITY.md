# Security Policy & Zero-Trust Posture

## 1. Supported Versions
Security updates, vulnerability patches, and zero-day remediations are actively maintained for the following releases:

| Version | Release Tag | Status | Supported |
| :--- | :--- | :--- | :---: |
| **v2.5.x** | `v2.5.13-PILOT` | Active Pilot Release | ✅ Supported |
| **v2.4.x** | `v2.4.x` | Deprecated | ❌ End of Life |
| **< v2.4** | Legacy | Deprecated | ❌ Unsupported |

---

## 2. Zero-Trust Security & DevSecOps Principles
CloudShield MSSP Platform adheres to strict enterprise DevSecOps standards and Microsoft Zero-Trust Architecture:

### A. Zero Plaintext Credentials in Git
* **No Hardcoded Secrets:** No customer tenant secrets, certificates, API tokens, or administrator passwords may ever be committed to the Git repository.
* **Environment Variable Injection:** Portal credentials and secret keys must be supplied via secure container runtime environment variables or Azure Key Vault references.
* **Automated Pre-Commit & CI Scanning:** All pull requests and commits are automatically scanned by Gitleaks, TruffleHog, and CodeQL SAST.
* **Local Isolation:** Local configuration overrides (`Data/tenants.local.json`, `Data/auth.local.json`, `Data/*.db`) are strictly excluded via `.gitignore`.

### B. Customer Identity & Key Vault Isolation
* **Managed Identity Authentication:** In cloud production (Azure Container Apps), backend services authenticate against Azure Key Vault via Managed Identity (IMDS / OIDC), requiring zero hardcoded storage connection strings or vault secrets.
* **Least-Privilege RBAC:** The Container App identity is assigned strictly the `Key Vault Secrets User` role (read-only in memory). Write or administrative privileges are strictly prohibited.
* **In-Memory Credential Lifecycle:** Tenant authentication tokens retrieved from Entra ID / Microsoft Graph are scoped in memory and destroyed upon report compilation. No tokens or decrypted private keys are persisted to disk.

### C. Server-Side RBAC & Session Security
* **Mandatory Entra ID SSO in Pilot:** In the Pilot channel (`CLOUDSHIELD_RELEASE_CHANNEL=pilot`), local password authentication (`/api/auth/login`) is strictly disabled (returns `403 Forbidden` with `"ssoRequired": true`). All portal authentication requires Microsoft Entra ID OIDC SSO (`/api/auth/sso`).
* **8-Stage Authorization Decision Chain:** Every incoming API request passes an 8-stage authorization pipeline evaluating identity active state, permission checks, customer scope, service scope, time bounds, separation of duties, and audit emissions (`Portal/api/rbac_engine.py`).
* **Zero Trust Least Privilege for Administrators:** Administrative roles (`PlatformAdmin`) are strictly prohibited from automatic access to customer confidential data (reports). Platform administrators do not inherit customer-level content visibility without an explicit customer assignment or approved CloudShield JIT Temporary Access Elevation.
* **CloudShield JIT Temporary Access Elevation:** Operators require time-bounded, approval-gated Just-In-Time access elevation (compatible with Microsoft Entra PIM zero standing privileges principles) to perform customer-specific investigations.
* **Separation of Duties (SoD):** The engineer who creates or triggers a report cannot approve that report. Approvals require independent customer or lead engineer ratification.
* **Multi-Dimensional Scoping:** Access is strictly bounded by Customer ID and Subscribed Service ID, preventing cross-tenant and cross-service data leakage.
* **Session Security & Cookie Hardening:** Session tokens (`CS_SESSION`) use cryptographically secure 256-bit entropy, enforced with `HttpOnly; SameSite=Strict; Path=/` flags.

### D. Data Privacy & KVKK / GDPR Compliance
* **Zero Raw Data Persistence:** No raw customer payloads, email bodies, file contents, or personal records are stored on disk.
* **k-Anonymity Dynamic Masking:** Sensitive customer identifiers, User Principal Names (UPNs), and filenames are masked before rendering (`c***.c***@domain.com`, `Mali_Rapor_***.xlsx`) with an anonymity threshold ($k \ge 3$).
* **Audit Logs Hygiene:** Runtime operational and authorization audit logs are immutably preserved in the database / Azure Log Analytics and strictly excluded from Git repository tracking.

---

## 3. Reporting a Vulnerability
We take the security of CloudShield MSSP Platform and our customer tenants extremely seriously. If you identify a security vulnerability or potential credential exposure, please follow our coordinated disclosure policy:

> [!CAUTION]
> **DO NOT** file public GitHub issues for security vulnerabilities, potential secret exposures, or remote code execution risks.

### Vulnerability Reporting Process:
1. **Contact Security Operations:** Email the DevSecOps Lead directly at:
   * Primary: `security@cloudshield-mssp.com`
   * Corporate MSSP: `mssp-security@kocsistem.com.tr`
   * DevSecOps Team: `devsecops@cloudshield-mssp.com`
2. **Include Technical Details:**
   * Detailed description of the vulnerability.
   * Affected endpoints, modules, or scripts (e.g., `/api/v1/auth/login`, `Portal/api/rbac_engine.py`, `Engine/Core/Authentication.psm1`).
   * Proof-of-concept (PoC) steps or minimal reproduction script.
   * Assessment of exploitability and impact (CVSS score if available).

### Response SLAs:
* **Initial Acknowledgment:** Within 12 hours.
* **Severity Assessment & Reproduction:** Within 24 hours.
* **Hotfix & Deployment to Production:** Within 48 hours for Critical / High severity findings.
* **Coordinated Disclosure:** We kindly request that you refrain from disclosing the issue publicly until a hotfix has been verified and deployed to production.
