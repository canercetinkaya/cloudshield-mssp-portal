# Code Review & Quality Gates

## 1. Quality Gates (Pre-Release)
1. **Zero SOC Gate:** Pass automated scan across all non-markdown files.
2. **Pester / Python Test Suite:** All 30 engine unit tests and API tests must pass.
3. **Dynamic Data Shell Verification:** Verified that empty tenant runs output zero static mock numbers.
4. **Git Hygiene Gate:** No uncommitted artifacts, temp logs, or credentials.

## 2. Automated Release & Sync
- Every production-ready commit must trigger `Engine/Core/Update-Version.py`.
- Versioning format: `v2.5.x-LIVE` with timestamped build number (`YYYY.MM.DD.build`).
- Auto-sync updates `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `Data/version.json` simultaneously.
