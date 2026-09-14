# CloudShield MSSP Platform — Authentication Implementation Plan

**Branch:** `pilot/controlled-pilot-finalization`
**Companion documents:** `AuthenticationGapAnalysis.md` (findings), `AuthenticationRemediationDesign.md` (design), `docs/security/authentication-architecture.md` (intended target)
**Scope:** Authentication only. This document maps the design to **file-level, function-level work items**.
**Status:** Planning only. No code modified, no patches generated, nothing implemented.

**Risk scale used below:**
- **Low** — localized, reversible, no contract change, easily unit-tested.
- **Medium** — touches a shared function or runtime behavior; needs integration tests; reversible but wider blast radius.
- **High** — affects authentication/authorization boundary, session validity, or bootstrap; requires staged rollout and regression sign-off.

**How to read the tables:** each row is a discrete work item. "Test impact" names the existing tests/layers touched and the new tests required. No implementation detail exceeds the level of the design document.

---

## 0. Work-Item Index (by file)

| # | Item | Primary file(s) | Design § |
|:--|:--|:--|:--|
| W1 | OIDC authorize endpoint | `Portal/api/server.py` | §1.3 |
| W2 | OIDC callback + token exchange | `Portal/api/server.py` | §1.4 |
| W3 | `id_token` / JWKS validation module | `Portal/api/` (new module) + `Portal/api/server.py` | §1.5 |
| W4 | OIDC config relocation | `Portal/api/server.py`, `Data/auth_config.json`, env | §1.6 |
| W5 | Remove fake SSO handler | `Portal/api/server.py` | §2 |
| W6 | Identity → RBAC `user` dict builder | `Portal/api/rbac_engine.py` (helper) + `Portal/api/server.py` | §3 |
| W7 | Remove fallback password branch | `Portal/api/rbac_engine.py` | §4.1 |
| W8 | Remove seed literals | `database/db.py` | §4.1 |
| W9 | Authentication gate + allow-list | `Portal/api/server.py` | §5.2 |
| W10 | Guard unguarded routes | `Portal/api/server.py` | §5.3 |
| W11 | Fix `/api/users/me` unauth identity | `Portal/api/server.py` | §5.4 |
| W12 | `/api/auth/config` read hygiene | `Portal/api/server.py` | §5.4 |
| W13 | CSPRNG tokens + shared issuance helper | `Portal/api/server.py` | §6.1 |
| W14 | Persistent session store + migration | `Portal/api/session_store.py` (new), `database/migrations/*.sql`, `Portal/api/server.py` | §6.2 |
| W15 | Session lifecycle (idle/absolute/rotation/revocation) | `Portal/api/session_store.py`, `Portal/api/server.py` | §6.3 |
| W16 | Cookie `Secure` + drop `?token=` | `Portal/api/server.py` | §6.4 |
| W17 | Real `/api/auth/test` check | `Portal/api/server.py` | §5.3 |
| W18 | Audit reason alignment | `Portal/api/rbac_engine.py` (call sites only) | §7.1 |
| W19 | Config/docs/test alignment | `test_comprehensive_qa.py`, `SECURITY.md`, `README.md`, `docs/security/authentication-architecture.md` | §2.4 |

---

## 1. Item 1 — Real Microsoft Entra OIDC

### W1 — `/api/auth/entra/authorize` endpoint

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `MSSPPortalHandler.do_GET` (new `elif path == "/api/auth/entra/authorize":` branch, placed alongside existing auth branches) |
| **Expected change** | Add a new GET branch that: generates `state`, `nonce`, `code_verifier` via `secrets`; computes `code_challenge = BASE64URL(SHA256(code_verifier))`; persists a short-lived login-attempt record (see W14 store / new `auth_flows` table); and returns a `302` redirect to the Entra `/authorize` endpoint with the required query parameters. No existing branch is modified. |
| **Estimated risk** | **Low** — purely additive route; no shared code path altered; unknown-path behavior unchanged. |
| **Test impact** | New integration test: `GET /api/auth/entra/authorize` returns `302` with `state`, `nonce`, `code_challenge`, `code_challenge_method=S256` present and a valid `redirect_uri`. Existing tests unaffected. |

### W2 — `/api/auth/entra/callback` endpoint + token exchange

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `MSSPPortalHandler.do_GET` (new `elif path == "/api/auth/entra/callback":` branch) |
| **Expected change** | Add a new GET branch that: (a) validates `state` against the stored login-attempt record and consumes it single-use (on failure → `AUTH_DENY`, `400`); (b) exchanges `code`+`code_verifier` at the Entra token endpoint via `urllib.request` (already imported) with client auth from config; (c) invokes the W3 validation module on the returned `id_token`; (d) on success hands to W6 (identity mapping) and W13/W14 (session issuance). Never reads identity from a raw UPN. |
| **Estimated risk** | **Medium** — new network call and the central login completion path; no shared function changed, but correctness gates all OIDC logins. |
| **Test impact** | New tests (against a mocked IdP): happy-path callback issues a session; missing/replayed/expired `state` → `400`; token-endpoint failure → `401`. Existing local-login tests unaffected. |

### W3 — `id_token` / JWKS validation module

| Field | Detail |
|:--|:--|
| **File** | New module `Portal/api/oidc_validator.py` (new); imported by `Portal/api/server.py` |
| **Function** | New: `validate_id_token(id_token, tenant_id, client_id, expected_nonce, allowed_tenants, allowed_domains)` and internal helpers (`_fetch_jwks`, `_select_key_by_kid`, `_verify_rs256`, `_validate_claims`). Mirrors import-fallback style used by existing modules. |
| **Expected change** | Implement the ordered validation of Design §1.5: structure → `alg==RS256` pinning → JWKS `kid` resolution (cached, rotation-aware) → RS256 signature verify → `iss`/`aud`/`exp`/`nbf`/`nonce` → tenant/domain allow-list. Single fail-closed return with a reason code; no side effects. |
| **Estimated risk** | **High** — this is the cryptographic trust anchor for all OIDC identity. A defect here is a potential authentication bypass. Requires the §6/Appendix-B architecture decision (stdlib RSA verify vs. one vetted dependency). |
| **Test impact** | New unit tests with fixtures: valid token; tampered signature; `alg=none`; wrong `iss`/`aud`; expired/`nbf` skew; `nonce` mismatch; unknown `kid` triggers refetch; disallowed tenant/domain. No existing test touched. |

### W4 — OIDC configuration relocation

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` (new config resolver, analogous to `get_admin_credentials()`); `Data/auth_config.json` (content only) |
| **Function** | New helper e.g. `get_oidc_config()` in `server.py`; new module reads it via parameter passing, not direct file access. |
| **Expected change** | Add an env-first resolver for `client_id`, `tenant_id`, authority, `redirect_uri`, `allowed_tenants`, `allowed_domains`, `require_mfa` (secret retained only for client auth via env/Key Vault). Reduce `Data/auth_config.json` to non-secret, non-identity UI settings; remove committed `ClientId`/`TenantId`/`CertificateThumbprint` literals. |
| **Estimated risk** | **Low** — configuration plumbing; additive resolver; no auth logic changed. |
| **Test impact** | New test asserting OIDC routes fail closed with a clear error when config is absent. Verify `Data/auth_config.json` no longer contains identity/secret literals via a grep-style assertion in CI. |

---

## 2. Item 2 — Removal of Fake SSO

### W5 — Remove `/api/auth/sso` handler

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `MSSPPortaldHandler.do_POST` — the `elif path == "/api/auth/sso":` branch (entire block, including the unknown-UPN `else:` branch that fabricates `usr-architect-sso`). |
| **Expected change** | Per Design §2.2, either (a) delete the branch so the route falls through to `404`, or (b) replace the branch body with a `302` redirect to `/api/auth/entra/authorize`. The block that constructs a `user` dict from `body["upn"]` and the fabricated-admin fallback are removed in full. |
| **Estimated risk** | **High** — removes an active login path; any client/tooling calling `/api/auth/sso` breaks by design. Must be coordinated with frontend and QA. |
| **Test impact** | **Invert** the existing QA SSO tests in `test_comprehensive_qa.py` (which currently assert the stub returns `success:true`/token). New assertions: unknown UPN rejected; no session issued from a body identity. Frontend login flow test updated to the OIDC start route. |

### W6 — Identity → RBAC `user` dict builder

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/rbac_engine.py` (new shared helper) + `Portal/api/server.py` (called by W2 callback; also reused by the dev login path). |
| **Function** | New helper e.g. `build_user_profile(user_row, conn)` in `rbac_engine.py`, factoring the existing dict-assembly already present in `authenticate_user()`; consumed by callback. |
| **Expected change** | Extract/duplicate the current safe assembly (id, upn, displayName, roles, isPlatformAdmin, permissions, assignments, `AssignedTenants`, `tenantScope`, `initials`) into a single helper. Resolution rule: pre-provisioned `users` row required; unknown UPN → deny (`403`, `UnknownIdentity`); inactive → deny (`UserAccountDisabled`). **No auto-provisioning, no elevation.** `evaluate_access()` itself is **not** modified. |
| **Estimated risk** | **Medium** — refactoring shared profile-building; must produce byte-for-byte the same keys the RBAC engine and routes consume. |
| **Test impact** | Regression: existing `authenticate_user()` behavior unchanged (dev login). New tests: callback with pre-provisioned UPN builds correct scoped profile; unknown UPN denied; disabled user denied. Verify `AssignedTenants` derivation matches existing. |

### W18 — Audit reason alignment (SSO-related)

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/rbac_engine.py` / call sites in `server.py` |
| **Function** | `record_audit_event` call sites only (function body unchanged). |
| **Expected change** | Ensure `EntraIdOidcAuthenticationSuccessful` is emitted only by the real OIDC callback (W2); add reason codes `InvalidOrReplayedState`, `IdTokenValidationFailed`, `UnknownIdentity` per Design §7.1. |
| **Estimated risk** | **Low** — audit metadata only. |
| **Test impact** | Extend audit assertions in `test_comprehensive_qa.py` to check the new reason codes appear on the correct paths. |

---

## 3. Item 3 — Removal of Fallback Passwords

### W7 — Remove fallback password branch

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/rbac_engine.py` |
| **Function** | `authenticate_user()` |
| **Expected change** | Remove the two lines: `if not is_valid and password in ("CloudShield2026!*", "SecurePass2026!*"): is_valid = True`. A failed `verify_password()` becomes a hard failure. The PBKDF2 verification path, active-user check, and audit emission are unchanged. |
| **Estimated risk** | **Medium** — changes login-failure semantics for the dev-only path; correct intent, but must confirm no legitimate flow relied on the literals. |
| **Test impact** | `test_comprehensive_qa.py`: the "wrong password → 403/401" test must now also confirm the literals are **rejected**. New test: `CloudShield2026!*` / `SecurePass2026!*` no longer authenticate. |

### W8 — Remove seed literals

| Field | Detail |
|:--|:--|
| **File** | `database/db.py` |
| **Function** | `seed_default_data()` |
| **Expected change** | Stop seeding the bootstrap admin with `hash_password("CloudShield2026!*")` and imported users with `hash_password("SecurePass2026!*")`. Seed the admin / imported users with no usable password hash (NULL) or an undisclosed random value, aligning with the env/`Data/auth.local.json` pattern in `server.py::get_admin_credentials()`. `hash_password()`/`verify_password()` unchanged. |
| **Estimated risk** | **High** — changes bootstrap/initial state; a wrong key/column write could lock out admin provisioning. Requires migration/recovery coordination and a clean-DB test. |
| **Test impact** | Clean-DB init test: admin row exists with no literal-based hash; DEV login achievable via env/`auth.local.json`. Verify no `CloudShield2026!*` / `SecurePass2026!*` string remains in DB seed or source (CI grep). |

---

## 4. Item 4 — Authentication Enforcement for All APIs

### W9 — Authentication gate + public allow-list

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `MSSPPortaldHandler.do_GET` / `do_POST` / `do_PUT` / `do_DELETE` (a shared gate invoked at the top of each, before route dispatch) |
| **Expected change** | Add a single authentication gate that, for any `/api/*` route not on the public allow-list (`/api/health`, `/api/version`, OIDC start/callback, dev `/api/auth/login`), resolves `get_current_user()` and returns `401` when `None`. Existing route→handler mapping preserved; gate precedes existing branches. |
| **Estimated risk** | **High** — touches all four HTTP verbs and the whole route surface; a mis-scoped allow-list could lock out required routes. |
| **Test impact** | Broad regression across `test_comprehensive_qa.py`: every non-public API call without a token must now return `401`. Public allow-list routes must still return `200`. Must add explicit allow-list coverage tests. |

### W10 — Guard previously unguarded routes with existing permissions

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `do_GET` (`/api/users`, `/api/auth/config`, `/api/services`, `/api/activities`, `/api/dispatch`, `/api/dispatch/history`, `/api/stats/global`, `/api/kql/*`), `do_POST` (`/api/tenants`, `/api/users`, `/api/dispatch/schedule`, `/api/dispatch/send`, `/api/stats/sync`, `/api/activities`, `/api/auth/test`), `do_PUT` (`/api/tenants/*`, `/api/users/*`, `/api/auth/config`), `do_DELETE` (`/api/tenants/*`, `/api/users/*`). |
| **Expected change** | For each listed branch, add an `evaluate_access(user, <existing permission>, ...)` check using the §5.3 mapping (e.g., `customers:manage`, `roles:manage`, `assignments:manage`, `customers:view`, `services:view`). Read-only admin lists use existing view permissions; mutations use existing manage permissions. No new permissions introduced. |
| **Estimated risk** | **Medium** — uses existing permission catalog; risk is over-restriction of an operational route. Each mapping must be validated against seeded role→permission grants in `db.py`. |
| **Test impact** | New tests per route group: authorized role → `200`; under-privileged role → `403`; anonymous → `401`. Extend existing RBAC tests to cover these routes. Confirm `PlatformAdmin` non-customer-content management scope still passes via `evaluate_access` Stage 2. |

### W11 — Fix `/api/users/me` unauthenticated identity

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `do_GET` — `elif path == "/api/users/me":` branch (`else:` clause that returns the hard-coded `admin@cloudshield-mssp.com` / `PlatformAdmin` profile). |
| **Expected change** | Remove the hard-coded `else:` profile; when `get_current_user()` is `None`, return `401`. Authenticated branch (session-derived profile) unchanged. |
| **Estimated risk** | **Low** — single branch; clearly wrong behavior removed. |
| **Test impact** | Update frontend/session bootstrap tests expecting an anonymous profile; new test: unauthenticated `GET /api/users/me` → `401`. |

### W12 — `/api/auth/config` read hygiene

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py`; `Data/auth_config.json` (content) |
| **Function** | `do_GET` — `elif path == "/api/auth/config":` branch. |
| **Expected change** | Require authentication (via W9) and return only non-sensitive, non-identity config to callers; never disclose secrets/identifiers. (PUT already covered by W10 with admin permission.) |
| **Estimated risk** | **Low** — response shaping only. |
| **Test impact** | New test: anonymous `GET /api/auth/config` → `401`; authenticated response contains no secret/identity literals. |

### W17 — Real `/api/auth/test` connectivity check

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `do_POST` — `elif path == "/api/auth/test":` branch (currently returns a canned "Validated" response). |
| **Expected change** | Replace the canned payload with a real Entra discovery/JWKS reachability check (via `urllib.request`), returning genuine reachability status; keep it admin-only (W10). |
| **Estimated risk** | **Low** — additive network probe on an admin-only route; existing tests expecting the canned message must change. |
| **Test impact** | Update `test_comprehensive_qa.py` `POST /api/auth/test` assertion to the real result shape; add an offline/unreachable path test. |

---

## 5. Item 5 — Session Hardening

### W13 — CSPRNG tokens + shared issuance helper

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `do_POST` — `login` branch and (previously) `sso` branch; new helper e.g. `issue_session(user, ip, ua)` and `_new_session_token()`. |
| **Expected change** | Replace `tok = uuid.uuid4().hex + uuid.uuid4().hex` with `secrets.token_urlsafe(32)`; funnel both login (dev) and OIDC callback through one issuance helper. `secrets` is already imported. |
| **Estimated risk** | **Medium** — central session issuance; must be applied consistently or a weaker path remains. |
| **Test impact** | New test asserting token length/entropy properties and single-issuance path; existing login tests updated for the new token shape. |

### W14 — Persistent, revocable session store + migration

| Field | Detail |
|:--|:--|
| **File** | New `Portal/api/session_store.py`; new `database/migrations/00X_sessions.sql`; consumed by `Portal/api/server.py`. |
| **Function** | New module functions: `create_session(...)`, `get_session(token)`, `touch_session(...)`, `revoke_session(token)`, `revoke_all_for_user(user_id)`. `MSSPPortaldHandler.get_current_user()` reimplemented to delegate to the store. Migration applied by existing `init_db()` (`database/db.py` reads `MIGRATIONS_DIR`). |
| **Expected change** | Replace the in-memory `SESSIONS = {}` dict with a SQLite `sessions` table (fields per Design §6.2: `token_hash` PK, `user_id`, `created_at`, `last_seen_at`, `expires_at`, `idle_expires_at`, `ip`, `user_agent`, `auth_provider`, `revoked`). Store only the token **hash**. `get_current_user()` keeps its `user` dict/`None` contract but reads from the store. Reuse migration framework already in `db.py`. |
| **Estimated risk** | **High** — changes the core session lookup used by every authenticated request; schema addition + lookup-path rewrite. Needs concurrency and migration-forward tests. |
| **Test impact** | Regression: all authenticated tests must pass with the store-backed `get_current_user()`. New tests: session persists across process restart; unknown token → `None`; token stored hashed (raw token not present in DB); migration applies cleanly on an existing DB. |

### W15 — Session lifecycle: idle/absolute timeouts, rotation, revocation

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/session_store.py`, `Portal/api/server.py` |
| **Function** | `get_session`/`touch_session` (timeout enforcement); `logout` branch (`do_POST`); optional admin revoke-all. |
| **Expected change** | Enforce 60-min idle and 12-h absolute lifetimes (configurable); rotate token on authentication; `logout` revokes the record; add admin "revoke-all for user" (and optional revoke-on-user-disable). `user` dict contract unchanged. |
| **Estimated risk** | **Medium** — behavioral change to session validity windows; mis-tuned timeouts could frustrate operators or weaken posture. |
| **Test impact** | New tests: idle-expired session → `401`; absolute-expired → `401`; revoked → `401`; rotation invalidates predecessor; logout removes record. |

### W16 — Cookie `Secure` + drop `?token=` query fallback

| Field | Detail |
|:--|:--|
| **File** | `Portal/api/server.py` |
| **Function** | `login`/`sso`/`logout` `Set-Cookie` emissions; `get_current_user()` token extraction. |
| **Expected change** | Add `Secure` to `Set-Cookie` for `CS_SESSION` (consider `__Host-` prefix); logout clears with matching attributes. Remove the `?token=` query-parameter branch in `get_current_user()`; accept only `Authorization: Bearer` header or `CS_SESSION` cookie. |
| **Estimated risk** | **Medium** — removing query-param tokens can break any client that relied on links carrying `?token=`; secure-cookie flag requires HTTPS in the target deployment. |
| **Test impact** | Update any test relying on `?token=`; new tests: request with only `?token=` → `401`; header/cookie still work; `Set-Cookie` includes `Secure`. |

---

## 6. Cross-Cutting / Alignment Items

### W19 — Docs, config, and QA test alignment

| Field | Detail |
|:--|:--|
| **File** | `test_comprehensive_qa.py`, `SECURITY.md`, `README.md`, `docs/security/authentication-architecture.md`, `Data/auth_config.json` |
| **Function** | QA auth-test functions (SSO/login blocks); documentation prose. |
| **Expected change** | Invert the SSO QA test to assert rejection of unknown identities and OIDC-only non-dev auth; correct docs to describe only implemented behavior; ensure config carries no identity/secret literals. |
| **Estimated risk** | **Low** — non-runtime artifacts. |
| **Test impact** | The QA suite itself is the artifact; ensure the new assertions run in CI and that no test still passes by exercising the removed stub. |

---

## 7. Recommended Sequencing (from Design §7.3)

| Stage | Work items | Rationale |
|:--|:--|:--|
| **1. Containment** | W5, W7, W8, W11, W12 | Highest risk reduction per change; removes backdoors and unauthenticated admin leakage. |
| **2. Coverage** | W9, W10, W6, W17, W18 | Closes anonymous route access; feeds only trustworthy identities into the untouched RBAC engine. |
| **3. Hardening** | W13, W14, W15, W16 | Token/session integrity; depends on the issuance helper and store. |
| **4. Real Identity** | W1, W2, W3, W4 | Delivers OIDC end-to-end; flips pilot to require OIDC. |
| **5. Posture** | MFA/`amr` claim enforcement, step-up, revocation-on-disable (Design §3.3, §6.3) | Non-blocking enhancements atop the verified flow. |

---

## 8. Aggregate Risk & Test Summary

| Risk | Items |
|:--|:--|
| **High** | W3 (crypto validation), W5 (remove SSO path), W8 (seed/bootstrap), W9 (global gate), W14 (session store) |
| **Medium** | W2, W6, W7, W10, W13, W15, W16 |
| **Low** | W1, W4, W11, W12, W17, W18, W19 |

| File | Work items touching it |
|:--|:--|
| `Portal/api/server.py` | W1, W2, W4, W5, W9, W10, W11, W12, W13, W14, W15, W16, W17 |
| `Portal/api/rbac_engine.py` | W6, W7, W18 (audit call sites only; **not** `evaluate_access` logic) |
| `database/db.py` | W8 |
| New `Portal/api/oidc_validator.py` | W3 |
| New `Portal/api/session_store.py` | W14, W15 |
| New `database/migrations/00X_sessions.sql` | W14 |
| `Data/auth_config.json` | W4, W12 |
| `test_comprehensive_qa.py` | W5, W7, W10, W11, W12, W13, W15, W16, W17, W19 |
| Docs (`SECURITY.md`, `README.md`, `docs/security/authentication-architecture.md`) | W19 |

---

## 9. Preservation Guarantees (explicit)

- **RBAC architecture untouched:** `evaluate_access()` and its 8-stage chain are **not** in any work item's change scope. W6 builds the `user` dict it consumes; W10 adds call sites using **existing** permission codes.
- **Report authorization untouched:** `reports:generate|download|approve` routes and their `evaluate_access(..., customer_id, service_ids, sod_context)` calls are not modified.
- **Customer scope isolation untouched:** Stage 4 (`customer_scope`/`customer_id`) unchanged; tokens carry no scope authority.
- **Service scope isolation untouched:** Stage 5 (`service_scope`/`service_code`) unchanged; scope re-derived from `access_assignments` per request.
- **No redesign:** no new authorization model, no data-model redesign, no route-dispatch rewrite beyond the single authentication gate (W9).

## Appendix — Single required architecture decision

RSA/RS256 `id_token` signature verification (W3): implement with standard-library primitives (`hashlib` + modular exponentiation) **or** formally authorize exactly one vetted crypto dependency. This is the only external-dependency question in the plan; all other items are standard-library-compatible.

**No code has been modified, no patches generated, and nothing implemented by this document.**
