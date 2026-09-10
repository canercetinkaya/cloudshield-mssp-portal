# Contributing to CloudShield MSSP Platform

Thank you for your interest in contributing to the **CloudShield MSSP Platform**. As an enterprise managed security and Purview/Defender compliance reporting platform, we uphold the highest DevSecOps and code quality standards.

---

## 🏛️ Architectural Guardrails

Before submitting any code or documentation, you must adhere to these foundational principles:

### 1. Zero Plain-Text Secrets in Git
- **Never commit credentials, passwords, tokens, certificates, or customer API secrets.**
- Local test tenant overrides belong strictly in `Data/tenants.local.json` or `Engine/Config/*.local.json` (which are ignored by `.gitignore`).
- All environment passwords (`PORTAL_ADMIN_PASSWORD`) must be supplied via runtime environment variables or Azure Key Vault references.
- Every commit is audited via automated GitHub Actions (`secret-scanning.yml`, `codeql.yml`).

### 2. Separation of Duties: Engineering vs. SOC
- **Zero 24/7 SOC Confusion:** CloudShield is engineered strictly for **MSSP Purview & Defender Security Engineering** (governance, DLP policy lifecycle, posture optimization, and executive reporting).
- Alert triage and 24/7 SOC operations operate as an independent peer tier. Do not introduce unauthorized `SOC` / `SVC-SOC` references into the codebase.

### 3. Data Privacy & k-Anonymity (GDPR / KVKK)
- No customer payloads or raw message bodies may be written to disk.
- All user identifiers and sensitive resource names must be dynamically masked using `Engine/Core/PrivacyEngine.psm1`.

---

## 🛠️ Local Development & Environment Setup

### Prerequisites
- **Python:** 3.10+ (standard library only; zero unnecessary external pip packages)
- **PowerShell:** 7.4+ Core (cross-platform)
- **Git:** 2.40+

### Starting the Local Platform
```powershell
# 1. Set environment variables (optional for local testing)
$env:PORTAL_ADMIN_USER = "admin"
$env:PORTAL_ADMIN_PASSWORD = "YourSecureLocalPassword123!"

# 2. Launch the portal server
python Portal/api/server.py 8080

# 3. Access in browser: http://localhost:8080
```

---

## 🧪 Quality Assurance & Test Verification

All contributions must pass the comprehensive 50-point automated QA suite before opening a Pull Request:

```powershell
# 1. Syntax & compilation check
python -m py_compile Portal/api/server.py Portal/api/report_generator.py

# 2. Run end-to-end automated platform validation
python test_comprehensive_qa.py
```

### Acceptance Criteria:
- `summary.passed`: 50 / 50 tests passing
- `summary.failed`: 0
- Concurrency isolation verified (zero race conditions, zero orphaned config files in `Engine/Data/temp/`)
- Zero simulated/mock customer tenants in production configurations.

---

## 🌿 Git Branching & Commit Conventions

We follow a structured Git flow:

- `main`: Production-ready, live-deployed branch (`v2.5.6-LIVE`).
- `feature/<name>`: New reporting capabilities or dashboard enhancements.
- `fix/<issue>`: Bug fixes or rendering adjustments.
- `security/<cve>`: Security hardening, secret remediation, or dependency patches.

### Commit Message Standards
Use clear Conventional Commit prefixes:
- `feat: add Microsoft Purview Copilot AI risk reporting plugin`
- `fix: resolve responsive table overflow in vector PDF renderer`
- `sec: enforce HMAC constant-time password comparison in auth endpoint`
- `docs: update Azure Key Vault RBAC architecture guide`

---

## 📬 Submitting a Pull Request

1. Fork or branch from `main`.
2. Implement your changes following DevSecOps standards.
3. Verify that `git status` shows no stray logs, caches, or `.jsonl` files.
4. Run `python test_comprehensive_qa.py`.
5. Open a Pull Request using the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
6. Ensure all CI checks (CI/CD, Secret Scanning, CodeQL) pass.
