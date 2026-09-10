# Subagent Task Assignment Matrix

Subagents must load and strictly adhere to their assigned knowledge base documents:

| Subagent Name | Role | Primary Assigned Docs | Core Responsibility |
|---|---|---|---|
| `sec_architect` | Principal Security Architect | `master-architecture.md`, `security-rules.md`, `token-broker.md` | Tenant isolation, Least Privilege, Zero Trust, GDAP |
| `customer_ciso` | Customer CISO Executive | `master-architecture.md`, `kpi-rules.md`, `service-catalog.md` | Executive value, ROI narrative, Zero Incident verification |
| `compliance_lead` | Regulatory Compliance Lead | `master-architecture.md`, `purview-rules.md`, `kpi-rules.md` | KVKK/GDPR alignment, PrivacyEngine k-Anonymity, SIT mapping |
| `qa_engineer` | QA Automation Engineer | `kpi-rules.md`, `review-process.md`, `service-catalog.md` | Pester test execution, dynamic shell validation, regression tests |
| `github_architect` | DevSecOps & Repo Architect | `security-rules.md`, `review-process.md` | GitHub Actions, secret scanning, version sync, documentation |
