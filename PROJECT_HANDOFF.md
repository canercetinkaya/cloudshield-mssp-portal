# CloudShield MSSP Platform - Comprehensive Project Handoff & Knowledge Base
# Document Version: 2.5.13
# Target Audience: Incoming AI Models, Lead Architects, and DevSecOps Engineers

---

# 1. EXECUTIVE SUMMARY & PLATFORM MISSION

**CloudShield MSSP Platform** (v2.5.13-PILOT) is an enterprise-grade Multi-Tenant Managed Security Service Provider (MSSP) Security & Compliance Reporting Engine and SaaS Web Portal. It was engineered specifically for **KoçSistem Managed Security Services** to deliver executive-level monthly governance reports to C-level executives (CISOs, CIOs, Board Members) and SOC/SecOps teams.

### Core Value Proposition
1. **Telemetry Ingestion:** Connects via Microsoft Graph API and Defender XDR APIs to extract telemetry from Microsoft Defender (Endpoint, Office 365, Identity, Cloud Apps), Microsoft Purview (DLP, Risk & Compliance, Information Protection, Governance), and Entra ID.
2. **Zero-Fiction Semantic Reporting:** Enforces strict provenance and 14 automated quality gates. Every metric links to a verified query ID (`sourceQueryId`). Zero placeholder recommendations, zero unverified "100%" claims, and zero fabricated numbers.
3. **Enterprise RBAC & Multi-Tenant Isolation:** Complete server-side authorization engine with 6 discrete roles, 13 granular permissions, two-dimensional isolation (Customer + Subscribed Service), Separation of Duties (SoD), and immutable audit logging.
4. **Zero-Dependency Architecture:** Core API, web server, and RBAC engine utilize the **Python 3 Standard Library** (`http.server`, `sqlite3`, `hashlib`, etc.), eliminating external pip supply chain vulnerabilities and ensuring instant, lightweight container startup.
5. **High-Fidelity Presentation:** Generates pixel-perfect executive HTML reports and automated headless Edge/Chrome-printed PDF documents with custom customer branding, executive summaries, and actionable decision backlogs.

---

# 2. ARCHITECTURAL LAYERS & TECHNOLOGY STACK

```
+-------------------------------------------------------------------------------+
|                                CLIENT LAYER                                   |
|   Web Browser (Single Page App)  |  Executive PDF Readers  |  REST API Clients  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                             PORTAL API LAYER                                  |
|   Portal/api/server.py (Python http.server, REST Endpoints, Cookie Auth)      |
|   Portal/api/rbac_handlers.py (REST Handlers for RBAC, Tenants, Reports)       |
|   Portal/api/report_generator.py (Jinja2-like Engine, HTML & PDF Compilation) |
+-------------------------------------------------------------------------------+
                     |                                       |
                     v                                       v
+------------------------------------+   +--------------------------------------+
|       AUTHORIZATION ENGINE         |   |         PERSISTENCE LAYER            |
|   Portal/api/rbac_engine.py        |   |   database/db.py (SQLite Provider)   |
|   - 6 Roles, 13 Granular Perms     |   |   database/migrations/*.sql          |
|   - Two-Dimensional Scoping        |   |   Data/cloudshield_rbac.db           |
|   - Separation of Duties (SoD)     |   |   Data/report_registry.json          |
|   - Cryptographic Audit Log        |   |   Data/tenants.json                  |
+------------------------------------+   +--------------------------------------+
                     |
                     v
+-------------------------------------------------------------------------------+
|                         POWERSHELL REPORTING ENGINE                           |
|   Engine/Invoke-CloudShieldSecurityReporting.ps1                              |
|   Engine/Core/ (PluginLoader, Normalization, PrivacyEngine, HealthCheck)      |
|   Engine/Plugins/ (DefenderEndpoint, PurviewDlp, PurviewGovernance, etc.)     |
|   Headless Browser (Edge / Chrome --headless --print-to-pdf)                  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                         CLOUD INFRASTRUCTURE & AZURE                          |
|   Azure Container Apps (ACA) | Azure Key Vault (Managed Identity IMDS/OIDC)  |
|   Docker/Dockerfile (mcr.microsoft.com/powershell:7.4 + Python 3.11 + Chrome) |
+-------------------------------------------------------------------------------+
```

### Component Details
* **Backend Runtime:** Python 3.10+ (Python 3.11 recommended).
* **Execution Scripting:** PowerShell Core 7.4+ (`pwsh`) on Linux; Windows PowerShell 5.1 or `pwsh` on Windows.
* **Database:** SQLite 3 with Write-Ahead Logging (`WAL`), transactional consistency, and foreign key constraints.
* **Frontend:** Modern Vanilla JavaScript (ES6+), CSS3 Flexbox/Grid, Dark Mode UI, SVG charts, no heavy node_modules build steps.
* **Containerization:** Multi-stage Docker container deployed to Azure Container Apps with ingress on port 8080.

---

# 3. VERIFIED AND COMPLETED MODULES

The following systems are implemented, tested, and operational in `v2.5.13-PILOT`:

### A. Role-Based Access Control (RBAC) Engine (`Portal/api/rbac_engine.py`)
* **6 Production Roles:**
  1. `PlatformAdmin`: Unrestricted system administration, customer onboarding, user management.
  2. `MsspSecurityArchitect`: Senior security engineering, report generation, report approval, PIM approval.
  3. `MsspOperator`: Tier-1/2 security analyst, report draft generation, collector execution.
  4. `CustomerCiso`: Customer executive, authorized report viewing and downloading for assigned tenant.
  5. `CustomerSecOps`: Customer technical contact, assigned tenant data viewing.
  6. `Auditor`: Read-only compliance auditor across audit trails and generated artifacts.
* **13 Discrete Permissions:**
  `report:create`, `report:view`, `report:approve`, `report:download`, `tenant:view`, `tenant:manage`, `service:view`, `service:manage`, `user:view`, `user:manage`, `audit:view`, `pim:request`, `pim:approve`.
* **Two-Dimensional Isolation:** Access requires both `has_permission(perm)` AND `is_customer_authorized(user, customer_id)` AND `is_service_authorized(customer_id, service_id)`.
* **Separation of Duties (SoD):**
  * `assert_sod_report_approval(creator_id, approver_id)`: Throws error if report creator attempts to approve their own report.
  * `assert_sod_pim_approval(requester_id, approver_id)`: Throws error if PIM privilege escalation requester attempts to approve their own grant.
* **Session Hardening:** Cryptographically secure 256-bit entropy cookies (`CS_SESSION`), `HttpOnly`, `SameSite=Strict`, `Secure`.

### B. Reporting Pipeline & 14 Quality Gates (`test_report_quality_gate.py`)
* Evaluates 14 mandatory semantic assertions across generated reports:
  * Gate 1: Zero mock/static metrics in production reports.
  * Gate 2: Full provenance lineage (`sourceQueryId` resolved in Query Catalog).
  * Gate 3: Mathematical sum consistency (e.g. Total Incidents = Cleaned + Blocked + Quarantined).
  * Gate 4: Zero Incident Verification limitation disclaimer required when incidents = 0.
  * Gate 5: Evidence-backed KoçSistem operational activities.
  * Gate 6: Strict k-Anonymity privacy threshold ($k \ge 3$) and deterministic SHA-256 masking.
  * Gate 7: Decision backlog contains only real, actionable items; empty categories render clean zero-states.
  * Gates 8-14: Executive storytelling, visual hierarchy, disclaimer compliance, and PDF print integrity.

### C. Collector Plugins (`Engine/Plugins/`)
* Standard plugin contract (`Invoke-PluginCollection`) returning normalized telemetry objects:
  * `DefenderEndpoint.Plugin.psm1`: Malware, ASR, Device Health, TVM vulnerabilities.
  * `PurviewDlp.Plugin.psm1`: DLP policy matches, exfiltration channels, override events.
  * `PurviewGovernance.Plugin.psm1`: Data map, asset classification, sensitivity hygiene.
  * `PurviewRiskCompliance.Plugin.psm1`: Insider risk alerts, communication compliance.
  * Additional plugins: `DefenderOffice`, `DefenderIdentity`, `DefenderCloudApps`, `EntraGovernance`, `IntuneCompliance`, `DefenderXdr`.

---

# 4. DIRECTORY & REPOSITORY MAP

```
KocSistemMSSPPortal/
|-- ARCHITECTURE.md                  # Master architecture document (19 topics, 5 Mermaid diagrams)
|-- CONTRIBUTING.md                  # Contributor guide, PR rules, branch standards
|-- DEPLOYMENT.md                    # Docker container & Azure Container Apps deployment guide
|-- PROJECT_HANDOFF.md               # This authoritative handoff document
|-- README.md                        # Platform root overview and navigation
|-- SECURITY.md                      # Zero Trust posture, secrets policy, vulnerability SLAs
|-- version.json                     # Canonical platform version manifest (v2.5.13-PILOT)
|-- requirements.txt                 # Runtime Python dependencies specification (Standard Library)
|-- requirements-dev.txt             # Development & testing Python dependencies (pytest, black, etc.)
|-- .env.example                     # Environment configuration template
|-- setup_project.sh                 # Turnkey setup script for Linux/macOS/Containers
|-- setup_project.ps1                # Turnkey setup script for Windows PowerShell
|-- Start-LocalPortal.ps1            # Windows local portal launcher with browser launch
|
|-- Azure/                           # Azure deployment artifacts
|   |-- main.bicep                   # Bicep IaC for Container App, Key Vault, Managed Identity
|   |-- deploy_aca.py                # Automated Azure Container Apps deployment helper
|   |-- deploy-to-azure.sh           # Azure CLI deployment shell script
|   +-- parameters.json              # Azure deployment parameter definitions
|
|-- Data/                            # Runtime database and data files
|   |-- cloudshield_rbac.db          # Active SQLite database (users, roles, perms, audit_logs)
|   |-- report_registry.json         # Index of generated reports and approval statuses
|   |-- tenants.json                 # Customer tenant metadata
|   |-- version.json                 # Synced version manifest copy
|   +-- manual-service-activities.json # Verified KoçSistem operational evidence records
|
|-- database/                        # Database management layer
|   |-- db.py                        # SQLite provider, migrations runner, password hasher (PBKDF2)
|   +-- migrations/
|       +-- 001_initial_rbac_schema.sql # Canonical DDL schema for all RBAC and audit tables
|
|-- Docker/                          # Containerization files
|   |-- Dockerfile                   # Multi-stage image: pwsh 7.4 + Python 3.11 + Chrome + fonts
|   |-- docker-compose.yml           # Local multi-container compose definition
|   +-- entrypoint.sh                # Container startup: DB init, test check, server launch
|
|-- docs/                            # Modular platform documentation
|   |-- repository-consistency-review.md # Repository audit and alignment review
|   |-- architecture/                # System architecture, provenance, collection health
|   |-- governance/                  # Evidence models, encoding standards, safe sync
|   |-- quality/                     # Semantic gates, golden fixtures, review lifecycles
|   |-- reporting/                   # Decision frameworks, storytelling contracts, value models
|   |-- security/                    # RBAC model, authentication, permission matrix, privacy
|   +-- services/                    # Service catalog, capability matrices, data sources
|
|-- Engine/                          # PowerShell Core reporting engine
|   |-- Invoke-CloudShieldSecurityReporting.ps1 # Primary reporting orchestrator
|   |-- Config/service-catalog.json  # 12-service master catalog configuration
|   |-- Core/                        # Engine modules (Auth, Normalization, Privacy, HealthCheck)
|   +-- Plugins/                     # 10+ Microsoft Security & Purview collector plugins
|
|-- Portal/                          # Web Portal & REST API Server
|   |-- api/
|   |   |-- server.py                # HTTP server, routing, REST endpoints, static file server
|   |   |-- rbac_engine.py           # Core RBAC authorization logic and audit logger
|   |   |-- rbac_handlers.py         # REST request handlers for RBAC management
|   |   +-- report_generator.py      # HTML report generation and Edge/Chrome PDF compilation
|   +-- web/
|       |-- index.html               # Main Single Page Application interface
|       +-- rbac_portal.js           # Client-side RBAC administration tab & modal handlers
|
+-- test_*.py                        # Automated test suites
    |-- test_rbac_authorization.py   # RBAC & authorization security assertions (9/9 pass)
    |-- test_report_quality_gate.py  # 14 semantic quality gate assertions (10.0/10.0 pass)
    +-- test_post_remediation_independent_gate.py # Independent multi-role verification (21/21 pass)
```

---

# 5. DATA STORES, MIGRATIONS & SEED DATA WORKFLOW

### Database Architecture (`Data/cloudshield_rbac.db`)
The platform uses SQLite 3 with the following relational schema defined in `database/migrations/001_initial_rbac_schema.sql`:
1. `users`: User identity, email, PBKDF2 hashed password, active/disabled flag, customer binding.
2. `roles`: Standard roles (`PlatformAdmin`, `MsspSecurityArchitect`, etc.).
3. `permissions`: 13 discrete system permissions.
4. `role_permissions`: Many-to-many role-to-permission grants.
5. `user_roles`: User-role assignments with optional expiry (`expires_at`) for JIT/PIM access.
6. `customers`: Customer accounts (`id`, `code`, `name`, `status`).
7. `services`: 12 Microsoft security and purview service catalog items.
8. `customer_services`: Subscribed services per customer (`ACTIVE`, `SUSPENDED`, `CANCELLED`).
9. `user_customer_access`: Explicit tenant scoping for MSSP staff.
10. `user_service_access`: Explicit service entitlement for operators.
11. `reports`: Generated report metadata, customer binding, and creator ID.
12. `report_approvals`: Multi-stage approval records (`SUBMITTED`, `APPROVED`, `REJECTED`).
13. `audit_logs`: Immutable cryptographic audit trail of all access checks and admin events.

### Automatic Database Initialization & Seeding
When `init_db()` in `database/db.py` runs (called automatically on server boot or via `setup_project.sh` / `setup_project.ps1`):
1. Applies `001_initial_rbac_schema.sql` if tables do not exist.
2. Seeds default permissions and standard role mappings.
3. Seeds default demo customer (`tenant-002`, "Contoso Global Enterprise").
4. Seeds 12 standard services from the service catalog.
5. Links active services to the customer.
6. Creates the bootstrap `admin` account with hashed password from `PORTAL_ADMIN_PASSWORD` (or fallback).

---

# 6. CONFIGURATION & ENVIRONMENT VARIABLES

Copy `.env.example` to `.env`. The platform reads configuration from environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | TCP port for HTTP API and Web Portal |
| `CLOUDSHIELD_ENV` | `development` | Environment mode (`development`, `staging`, `production`) |
| `CLOUDSHIELD_RELEASE_CHANNEL` | `pilot` | Release channel (`pilot`, `stable`) |
| `CLOUDSHIELD_DB_PATH` | `Data/cloudshield_rbac.db` | File path for SQLite database |
| `PORTAL_ADMIN_USER` | `admin` | Bootstrap platform administrator username |
| `PORTAL_ADMIN_PASSWORD` | *(fallback)* | Bootstrap administrator password (mandatory in production) |
| `AZURE_KEYVAULT_URL` | *(KeyVault URI)* | Production Azure Key Vault URI for tenant secret storage |
| `IDENTITY_ENDPOINT` | *(auto in ACA)* | Azure Managed Identity IMDS endpoint |
| `IDENTITY_HEADER` | *(auto in ACA)* | Azure Managed Identity authentication header |
| `AZURE_RESOURCE_GROUP` | `rg-cloudshield-mssp` | Azure Resource Group for Container Apps deployment |
| `CONTAINER_APP_NAME` | `ca-cloudshield-portal` | Azure Container App service name |
| `GHCR_PAT` | - | GitHub Personal Access Token for container publishing |

---

# 7. ROADMAP & LOGICAL NEXT STEPS (FOR INCOMING DEVELOPER / AI)

When continuing development on CloudShield, follow this prioritized sequence:

### Priority 1: Entra ID Corporate Single Sign-On (SSO / OIDC)
* **Status:** Local mock SSO endpoint exists (`/api/auth/sso`).
* **Goal:** Implement full OpenID Connect / OAuth 2.0 authorization code flow against Microsoft Entra ID (`login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`).
* **Implementation Location:** `Portal/api/server.py` and `Portal/api/rbac_handlers.py`. Replace mock SSO claims extraction with JWT validation using Microsoft public keys (JWKS).

### Priority 2: Automated Scheduled Report Dispatcher (Cron Worker)
* **Status:** Reports are currently triggered manually via the portal UI (`/api/reports/generate`) or CLI.
* **Goal:** Build a lightweight background worker or Azure Container Apps Job that triggers monthly reporting cycles on the 1st of each month for all active customer subscriptions.
* **Implementation Location:** New script `Portal/api/scheduler.py` or Azure Container App Job definition.

### Priority 3: Webhook & Notification Dispatcher (Teams & Email)
* **Status:** Reports compile and persist in `Engine/Output/` and `report_registry.json`.
* **Goal:** When a report enters `PENDING_APPROVAL` or is `APPROVED`, send automated notification cards to Microsoft Teams webhook and customer executive emails with secure download links.
* **Implementation Location:** `Portal/api/rbac_handlers.py` in `approve_report_handler`.

### Priority 4: Microsoft Purview Copilot & Generative AI Security Collector
* **Status:** `PurviewAiSecurity` plugin contract exists.
* **Goal:** Expand plugin to query Microsoft Graph Beta API for Copilot for Security and Microsoft 365 Copilot prompt/response DLP risk events.
* **Implementation Location:** `Engine/Plugins/PurviewAiSecurity/PurviewAiSecurity.Plugin.psm1`.

---

# 8. CRITICAL GOTCHAS, RULES & KNOWN NUANCES

To avoid breaking working functionality, any AI model or engineer modifying this codebase must obey these rules:

1. **Strict Zero-Pip Standard:**
   * Do **NOT** add third-party pip packages (e.g. `fastapi`, `flask`, `sqlalchemy`, `pydantic`) to `Portal/api/`. The core server deliberately runs on Python's built-in `http.server` and `sqlite3`. This keeps the Docker image tiny, ultra-secure, and capable of starting in under 2 seconds.
2. **Quality Gate Integrity Rule:**
   * Never modify HTML strings to bypass quality tests or hide bad values. The 14 semantic quality gates in `test_report_quality_gate.py` inspect the **underlying KPI JSON and data lineage**. The correct fix is always at the collector/normalization layer.
3. **Single-Source Versioning:**
   * The version is defined in `version.json`. When bumping versions, update `version.json`, `Data/version.json`, `Docker/Dockerfile`, and `ARCHITECTURE.md` simultaneously.
4. **Edge/Chrome Headless Requirement:**
   * HTML reports can be generated without any browser. However, generating `.pdf` files requires Chrome or Edge. In Linux containers, Google Chrome is installed at `/usr/bin/google-chrome`. On Windows, the engine searches standard paths for `msedge.exe`.
5. **Cross-Platform Path Handling:**
   * Always use `os.path.join` in Python and `Join-Path` in PowerShell. Do not hardcode forward or backslashes.
6. **Separation of Duties (SoD) Testing:**
   * When testing report approvals, remember that a user cannot approve a report they generated. You must authenticate as a different user with the `report:approve` permission (e.g., `MsspSecurityArchitect`).

---

# 9. INSTANT STARTUP COMMANDS

### On Windows:
```powershell
# Run automated setup and verification
.\setup_project.ps1

# Launch local portal in default browser
.\Start-LocalPortal.ps1 -Port 8080
```

### On Linux / macOS / Docker:
```bash
# Run automated setup and verification
chmod +x setup_project.sh
./setup_project.sh

# Launch local portal
python3 Portal/api/server.py 8080
```

### Using Docker:
```bash
docker build -t cloudshield-portal:v2.5.13 -f Docker/Dockerfile .
docker run -p 8080:8080 -e PORTAL_ADMIN_PASSWORD=YourPassword123! cloudshield-portal:v2.5.13
```

### Run All Unit & Security Tests:
```bash
python -m unittest test_rbac_authorization.py test_post_remediation_independent_gate.py test_report_quality_gate.py
```
