# Final Commit Plan

**Branch:** `pilot/controlled-pilot-finalization`
**Version manifest (both `version.json` and `Data/version.json`):** `2.5.15` / `v2.5.15-PILOT` / build `2026.09.16.1`
**Release discipline (per AI_PROJECT_RULES.md §3):** `channel = pilot`, `productionReady = false` (unchanged)
**Prepared from:** `git status` + the two version manifests. No code, docs, tests, or validations were run.

---

## 1. Files to Commit

### 1a. Modified implementation / test files (task-owned changes)
| File | Rationale |
| :--- | :--- |
| `Portal/api/report_generator.py` | UTF-8 fail-closed PDF fallback; removal of lossy ASCII transliteration (`to_ascii_safe`) |
| `Portal/api/server.py` | Explicit UTF-8 stdout/stderr console configuration |
| `Start-LocalPortal.ps1` | UTF-8 console + child-process env for the launcher |
| `Engine/Tests/Test-Platform.ps1` | Structured UTF-8 `platform-test-results.json` emission |
| `test_comprehensive_qa.py` | UTF-8 subprocess decoding; real Turkish corpus + diacritic-coverage assertions |

### 1b. Modified implementation files — **classify as pre-existing / user-owned**
The following were already modified in the working tree and are not clearly attributable to this task. Per AI_PROJECT_RULES.md §3 ("Treat uncommitted pre-existing changes as owned by the user"), include **only if the project owner explicitly authorizes**:
| File | Note |
| :--- | :--- |
| `Portal/api/rbac_engine.py` | Pre-existing change — confirm ownership |
| `database/db.py` | Pre-existing change — confirm ownership |
| `test_post_remediation_independent_gate.py` | Pre-existing change — confirm ownership |
| `test_rbac_authorization.py` | Pre-existing change — confirm ownership |

### 1c. Untracked documents / evidence (commit only if in scope)
Governance and validation artifacts that are candidate additions:
| File | Suggested action |
| :--- | :--- |
| `AI_PROJECT_RULES.md` | Commit (controlled governance artifact) |
| `TurkishLanguageComplianceReport.md` | Commit (task deliverable) |
| `AuthenticationGapAnalysis.md` | Commit only if authorized |
| `AuthenticationRemediationDesign.md` | Commit only if authorized |
| `AuthenticationImplementationPlan.md` | Commit only if authorized |
| `Stage1ATestRemediationReport.md` | Commit only if authorized |
| `Stage1AValidationReport.md` | Commit only if authorized |
| `Stage1AValidationReport.json` | Commit only if authorized (validation evidence) |
| `Stage1BPermissionValidationReport.md` | Commit only if authorized |
| `Stage1FinalValidationReport.md` | Commit only if authorized |
| `W5FixValidationReport.md` | Commit only if authorized |
| `PilotReadinessAndProductRoadmap.md` | Commit only if authorized |
| `run_stage1a_validation.py` | Commit only if authorized (test harness) |
| `tests/helpers/` | Commit only if authorized (test helpers) |
| `FinalCommitPlan.md` | This file — commit only if authorized |

> **Rule:** Do not `git add -A`. Stage files explicitly.

---

## 2. Files NOT to Commit

| Path | Reason |
| :--- | :--- |
| `.continue/` | Local AI tooling state — never committed |
| `.worktreeinclude` | Local worktree configuration — never committed |
| Any `.env` (if present) | Secrets |
| `*.local.json` (e.g. `Data/auth.local.json`) | Local credentials/configuration (AI_PROJECT_RULES.md §3) |
| `Data/cloudshield_rbac.db*` | Local runtime database / WAL files (no local DBs in git) |
| Secrets, API keys, private keys, certificates (`*.pfx`, `*.pem`) | Prohibited (AI_PROJECT_RULES.md §3) |
| Raw customer data / PII-bearing artifacts | Prohibited (AI_PROJECT_RULES.md §12) |
| `Engine/Output/**` customer report artifacts | Generated customer reports (unless sanitized test artifacts are explicitly allowed) |
| `Portal/api/__pycache__/`, `*.pyc` | Build/cache output |

---

## 3. Generated Artifacts to Exclude

| Artifact | Reason |
| :--- | :--- |
| `qa_test_results.json` | Generated, git-ignored QA output (regenerates on each run) |
| `Engine/Output/platform-test-results.json` | Generated engine-test output |
| `Engine/Output/**` (HTML/PDF reports) | Generated report artifacts |
| `Stage1AValidationReport.json` | Generated validation output — include only as deliberate evidence, not by default |
| `__pycache__/`, `*.pyc`, `*.pyo` | Python cache |
| `Data/cloudshield_rbac.db-wal`, `-shm` | SQLite transient files |

---

## 4. Recommended Commit Message

```
fix(utf8): fail-closed Turkish PDF rendering and UTF-8 test/console integrity

- report_generator: remove lossy to_ascii_safe transliteration; fail closed
  with Utf8ComplianceError when no embeddable Unicode font is available;
  embed Type0/Identity-H Unicode font to preserve Turkish diacritics
- server: force UTF-8 stdout/stderr console streams on Windows
- Start-LocalPortal: set UTF-8 console encoding and PYTHONUTF8/PYTHONIOENCODING
- Test-Platform.ps1: emit BOM-less UTF-8 platform-test-results.json
- test_comprehensive_qa: explicit UTF-8 subprocess decoding; real Turkish
  corpus with diacritic-coverage and byte-stability assertions (Gate 4)

Channel: pilot | productionReady: false
```

---

## 5. Current & Recommended Next Version
 
- **Current:** `2.5.15` / `v2.5.15-PILOT` (build `2026.09.16.1`)
- **Recommended next:** `2.5.16` / `v2.5.16-PILOT` (build `2026.09.17.1`)
- **Channel:** `pilot` (unchanged) — **`productionReady` must remain `false`**
- **Sync requirement (AI_PROJECT_RULES.md / PROJECT_HANDOFF.md §8):** update `version.json`, `Data/version.json`, `Docker/Dockerfile`, and `ARCHITECTURE.md` in the same commit when bumping.

---

## 6. Is the Repository Ready for GitHub Push?

**NO**

Reasons (per AI_PROJECT_RULES.md §3 and §21):
- Working tree is **not clean**: multiple modified files plus many untracked documents/harnesses are unstaged.
- **Pre-existing user-owned changes** (`rbac_engine.py`, `database/db.py`, two test files) must be explicitly classified and authorized before inclusion.
- Several untracked artifacts must be triaged: **commit** (governance/evidence) vs **exclude** (`.continue/`, generated outputs).
- No commit has been created, tests/validations have not been run as part of this step, and the **Controlled Pilot exit gates (§21) are not evidenced** as passing for this revision.
- `productionReady = false` and channel `pilot` must be preserved; no production release is authorized.

**Condition to become YES:** explicit owner authorization of the file list, successful required test/CI evidence for the controlled-pilot scope, a clean staged tree, and confirmation that only intended files are committed — then push to the pilot branch (never `main`, per §3).
