# CloudShield MSSP Platform - Single-Source Versioning Architecture

**Document Version:** 2.0.0  
**Classification:** Release Governance  

---

## 1. Single Source of Truth (`version.json`)

To prevent version drift across microservices and documentation, platform versioning is governed exclusively by `version.json` at the repository root:

```json
{
  "version": "2.5.13",
  "release": "v2.5.13-PILOT",
  "build": "2026.09.11.1",
  "channel": "pilot",
  "build_number": 13,
  "environment": "pilot",
  "productionReady": false,
  "commit": "auto"
}
```

---

## 2. Automated Synchronization Pipeline

The script `Engine/Core/Update-Version.py` orchestrates automatic synchronization across all dependent files:
- `Data/version.json`
- `Portal/api/server.py` (via dynamic `get_version_info()`)
- `README.md` (badges and changelog table)
- `docs/` references

---

## 3. Release Channel Decoupling

- **`pilot` Channel:** Allows active continuous deployment to Azure Container Apps for integration validation without certifying general production availability (`productionReady: false`).
- **`production` Channel:** Requires 100% sign-off from all 6 independent review gates before `productionReady: true` can be tagged.
