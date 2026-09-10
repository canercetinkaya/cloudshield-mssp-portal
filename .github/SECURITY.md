# Security Policy & Zero-Trust Governance

## 1. Supported Versions

Security updates, vulnerability patches, and zero-day remediations are actively maintained for the following releases:

| Version | Release Tag | Status | Supported |
| :--- | :--- | :--- | :--- |
| **v2.5.x** | `v2.5.10-PILOT` | **Active Release** | :white_check_mark: Supported |
| **v2.4.x** | `v2.4.x` | Deprecated | :x: End of Life |
| **< v2.4** | Legacy | Deprecated | :x: Unsupported |

---

## 2. Zero-Trust Security & DevSecOps Principles

CloudShield MSSP Platform adheres to strict enterprise DevSecOps standards and Microsoft Zero-Trust Architecture:

### A. Zero Plaintext Credentials in Git
1. **No Hardcoded Secrets:** No customer tenant secrets, certificates, API tokens, or administrator passwords may ever be committed to the Git repository.
2. **Environment Variable Injection:** Portal credentials (`PORTAL_ADMIN_USER`, `PORTAL_ADMIN_PASSWORD`) must be supplied via secure container runtime environment variables or Azure Key Vault references.
3. **Automated Pre-Commit & CI Scanning:** All pull requests and commits are automatically scanned by **Gitleaks**, **TruffleHog**, and **CodeQL SAST**.
4. **Local Isolation:** Local configuration overrides (`Data/tenants.local.json`, `Data/auth.local.json`) are strictly excluded via `.gitignore`.

### B. Customer Identity & Key Vault Isolation
- **Managed Identity Authentication:** In cloud production (Azure Container Apps), backend services authenticate against Azure Key Vault via Managed Identity (IMDS / OIDC), requiring zero hardcoded storage connection strings or vault secrets.
- **Least-Privilege RBAC:** The Container App identity is assigned strictly the `Key Vault Secrets User` role (read-only in memory). Write or administrative privileges are strictly prohibited.
- **In-Memory Credential Lifecycle:** Tenant authentication tokens retrieved from Entra ID / Microsoft Graph are scoped in memory and destroyed upon report compilation. No tokens or decrypted private keys are persisted to disk.

### C. Data Privacy & KVKK / GDPR Compliance
- **Zero Raw Data Persistence:** No raw customer payloads, email bodies, file contents, or personal records are stored on disk.
- **k-Anonymity Dynamic Masking:** Sensitive customer identifiers, User Principal Names (UPNs), and filenames are masked before rendering (`c***.c***@domain.com`).
- **Audit Logs Hygiene:** Runtime operational logs are strictly kept in transient storage or exported to Azure Log Analytics; they are excluded from Git repository tracking.

---

## 3. Reporting a Vulnerability

We take the security of CloudShield MSSP Platform and our customer tenants extremely seriously. If you identify a security vulnerability or potential credential exposure, please follow our coordinated disclosure policy:

> [!CAUTION]
> **DO NOT** file public GitHub issues for security vulnerabilities, potential secret exposures, or remote code execution risks.

### Vulnerability Reporting Process:
1. **Contact Security Operations:** Email the DevSecOps Lead directly at:
   - **Primary:** `security@cloudshield-mssp.com`
   - **DevSecOps Team:** `devsecops@cloudshield-mssp.com`
2. **Include Technical Details:**
   - Detailed description of the vulnerability.
   - Affected endpoints, modules, or scripts (e.g., `/api/auth/login`, `KqlQueryEngine.psm1`).
   - Proof-of-concept (PoC) steps or minimal reproduction script.
   - Assessment of exploitability and impact (CVSS score if available).
3. **Response SLAs:**
   - **Initial Acknowledgment:** Within 12 hours.
   - **Severity Assessment & Reproduction:** Within 24 hours.
   - **Hotfix & Deployment to Production:** Within 48 hours for Critical / High severity findings.
4. **Coordinated Disclosure:** We kindly request that you refrain from disclosing the issue publicly until a hotfix has been verified and deployed to production.
