# Contributing to CloudShield MSSP Platform

Thank you for contributing to **CloudShield MSSP Platform**!

---

## 1. Core Engineering Principles

1. **Implementation is the Source of Truth:** Documentation, tests, and API schemas must describe only what actually executes in code.
2. **Zero External Dependencies:** The backend REST API server (`Portal/api/server.py`) and authorization engine run strictly on Python 3 Standard Library. Do not introduce third-party pip dependencies.
3. **Single-Source Versioning:** Never edit version strings manually across files. Always use the authoritative version tool:
   ```bash
   python Engine/Core/Update-Version.py "feat(module): description of changes"
   ```

---

## 2. Automated Quality Gates & Verification

Before submitting any Pull Request, you must execute and pass all quality suites:

```powershell
# 1. Python Syntax & Module Compilation
python -m py_compile Portal/api/server.py Portal/api/report_generator.py Portal/api/rbac_engine.py Portal/api/rbac_handlers.py database/db.py

# 2. Automated Semantic Report Quality Gate (14 rules)
python test_report_quality_gate.py

# 3. Independent Post-Remediation Verification Gate (21 tests)
python test_post_remediation_independent_gate.py

# 4. Enterprise RBAC & Authorization Suite (9 security tests)
python test_rbac_authorization.py
```

---

## 3. Pull Request Guidelines

- **Branch Naming:** `feat/feature-name`, `fix/bug-name`, `docs/doc-update`.
- **Commit Messages:** Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).
- **No Force Pushing to Main:** Direct pushes to `main` must maintain passing CI/CD checks.
