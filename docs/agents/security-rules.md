# Security Architecture & DevSecOps Rules

## 1. Zero SOC Rule (Strict Quality Gate)
- Non-markdown files (`Engine/`, `Portal/`, `Data/`, scripts) must have **zero** occurrences of sensitive tokens, passwords, or plain-text credentials.
- All secrets must be injected via Environment Variables (`PORTAL_ADMIN_PASSWORD`) or fetched via Managed Identity from Azure Key Vault.

## 2. Multi-Tenant Boundary Protection
- Memory isolation between tenants during parallel runs.
- Output artifacts strictly isolated in `Engine/Output/<TenantId>/<Period>/`.
- Read-only Graph scopes enforced across all collectors.

## 3. GitHub Repository Hygiene
- Git tracking must ignore all local caches, logs, temp tokens, and tenant payloads (`.gitignore`).
- Secret scanning (`secret-scanning.yml`) and CodeQL static analysis (`codeql.yml`) run on every push and PR.
