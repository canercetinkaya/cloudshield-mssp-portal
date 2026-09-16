# CloudShield MSSP Platform — Authentication Remediation Design

**Branch:** `pilot/controlled-pilot-finalization`
**Companion documents:** `AuthenticationGapAnalysis.md` (findings), `docs/security/authentication-architecture.md` (intended target)
**Scope:** Authentication only — identity establishment, session lifecycle, credential handling, and the authentication contract with the existing authorization engine.
**Status:** Design only. No code changes, no patches, no platform redesign.

---

## 0. Design Principles & Non-Negotiable Constraints

This remediation is additive and surgical. It changes **how identity is established and proven**, not **how authorization is decided**. The following are preserved without alteration:

| Constraint | Preserved invariant |
|:---|:---|
| **Preserve existing RBAC architecture** | The 8-Stage Authorization Decision Chain in `evaluate_access()` and its `user`-dict contract remain the sole authorization authority. Authentication's only job is to produce a trustworthy `user` dict (or `None`). |
| **Preserve existing report authorization model** | `reports:generate`, `reports:download`, `reports:approve` continue to flow through `evaluate_access()` with `customer_id` + `service_ids` + `sod_context`, unchanged. |
| **Preserve customer scope isolation** | Customer scoping (Stage 4, `customer_scope`/`customer_id`) is untouched. Authentication never widens scope. |
| **Preserve service scope isolation** | Service scoping (Stage 5, `service_scope`/`service_code`) is untouched. Authentication never widens scope. |
| **Zero-Pip posture** | Solution must remain achievable within the Python standard library, or explicitly flag any deviation for architecture review. |
| **No redesign** | No new authorization model, no data-model redesign, no rewrite of route dispatch. |

**Single governing rule of this design:** *authentication produces identity; authorization consumes identity.* The changes below repair identity production so that the existing, correct authorization engine is fed with a trustworthy subject — nothing more.

### 0.1 The authentication ↔ authorization seam (must remain stable)

The existing code already defines a clean seam that this design deliberately keeps intact:

- `get_current_user()` (in `server.py`) resolves a session token → returns a `user` dict or `None`.
- `evaluate_access(user, permission, customer_id, service_ids, resource, ip_address, sod_context)` consumes that dict and runs the 8 stages.
- All RBAC handlers (`handle_rbac_get/post/delete`) and protected routes already begin with `get_current_user()` then `evaluate_access(...)`.

**Design decision:** Every remediation item below flows through this seam. We replace the *contents* of identity (how `user` is obtained and proven) and *extend the seam's coverage* (ensure every route actually calls it). We do **not** change the seam's signature, the `user` dict's consumed keys, or `evaluate_access()`'s logic.

---

## 1. Item 1 — Real Microsoft Entra OIDC

**Goal:** Replace the identity-assertion stub with a genuine OpenID Connect Authorization Code Flow + PKCE against Microsoft Entra ID, producing identity from a cryptographically verified `id_token`.

### 1.1 Flow selection

- **Flow:** Authorization Code Flow (web app, confidential client) + PKCE (`S256`).
- **Response type:** `code`. **Scopes:** `openid profile email` (offline_access only if refresh is later required; not in initial scope).
- **Client authentication at token endpoint:** certificate-based (preferred, consistent with the data-plane `Engine/Core/Authentication.psm1` precedent) or client secret. Secret must originate from environment/Key Vault — never from `Data/auth_config.json`.

### 1.2 New endpoints (additive; do not alter existing routes)

| Endpoint | Method | Responsibility |
|:---|:---|:---|
| `/api/auth/entra/authorize` | GET | Begin login. Produce & server-side-store `state`, `nonce`, PKCE `code_verifier`; 302 to Entra `.../oauth2/v2.0/authorize`. |
| `/api/auth/entra/callback` | GET | Complete login. Validate `state`; exchange `code`+`code_verifier` at token endpoint; validate `id_token`; resolve identity → RBAC `user` dict; mint session. |

These are **new** routes. The existing `/api/auth/verify`, `/api/auth/logout`, and protected downstream routes keep their contracts.

### 1.3 `/api/auth/entra/authorize` — design

1. Generate three independent cryptographic values using `secrets`:
   - `state = secrets.token_urlsafe(32)` (CSRF binding, single-use)
   - `nonce = secrets.token_urlsafe(32)` (replay binding into `id_token`)
   - `code_verifier = secrets.token_urlsafe(64)`; `code_challenge = BASE64URL(SHA256(code_verifier))`
2. Persist a **short-lived, server-side** login-attempt record keyed by `state` containing: `nonce`, `code_verifier`, `created_at`, client context (IP, optionally a signed cookie marker). TTL ≈ 10 minutes. Store in the same SQLite layer used elsewhere (`get_db()`), or a dedicated `auth_flows` table added by a new migration.
3. 302-redirect to:
   `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize`
   with parameters: `client_id`, `response_type=code`, `redirect_uri`, `scope=openid profile email`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, `response_mode=query`.
4. `{tenant_id}` and `client_id` come from configuration/env, not hard-coded literals.

### 1.4 `/api/auth/entra/callback` — design

1. **CSRF/state gate (before any token work):** look up the stored record by `state`. If missing, expired, or already consumed → delete record, emit `AUTH_DENY` (`InvalidOrReplayedState`), return `400`. Consume (single-use) the record immediately.
2. **Code exchange:** `POST .../{tenant_id}/oauth2/v2.0/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`, and client auth (certificate assertion or secret). `code_verifier` is read from the stored record — never from the query string.
3. **Receive** `id_token` (required) and proceed to §1.5. Failure → `AUTH_DENY`, `401`.
4. On success, hand off to §3 (identity → RBAC mapping) and §5 (session issuance). The callback **never** accepts a raw UPN.

### 1.5 `id_token` validation (mandatory, fail-closed)

Validation is performed server-side, in order, with a single failure mode (deny + audit):

1. **Structure:** three Base64URL segments; decode header & claims JSON.
2. **Algorithm pinning:** require `alg == RS256`. Reject `none` and any symmetric algorithm (prevents algorithm-confusion).
3. **Key resolution (JWKS):** fetch signing keys from the tenant discovery document (`.../{tenant_id}/discovery/v2.0/keys`); select the key by `kid`. Cache keys with rotation handling (re-fetch on unknown `kid`; respect cache TTL). Fetch via `urllib.request` (already imported).
4. **Signature:** verify RS256 signature over `header.payload` using the resolved public key. Standard-library implementation uses `hashlib` + modular exponentiation for RSA verify (or an explicitly-reviewed vetted dependency — see §6 deviation note).
5. **`iss`:** must equal `https://login.microsoftonline.com/{tenant_id}/v2.0`.
6. **`aud`:** must equal the configured `client_id`.
7. **`exp` / `nbf`:** current time within validity with small clock skew tolerance.
8. **`nonce`:** must equal the `nonce` stored for this `state` (replay protection).
9. **Tenant/domain allow-list:** `tid` (or validated `iss` tenant) must be in the allowed tenants; UPN/email domain must be in allowed domains. Enforced from configuration.

Any failure emits an `AUTH_DENY` audit event (via the existing `record_audit_event`) with a precise reason code, and returns a generic error to the client (no internal detail leakage).

### 1.6 Configuration relocation

- `client_id`, `tenant_id`, authority, redirect URI, allowed tenants/domains, and `require_mfa` are read from **environment variables / Key Vault**, mirroring `get_admin_credentials()`'s env-first pattern.
- `Data/auth_config.json` retains only non-secret, non-identity settings for UI display; the hard-coded `ClientId`/`TenantId`/`CertificateThumbprint` values are removed from source-controlled config (they are inert today, but must not remain as misleading literals).

---

## 2. Item 2 — Removal of Fake SSO

**Goal:** Eliminate the `/api/auth/sso` identity-assertion path entirely, while keeping real Entra OIDC (§1) and the dev-only local password path (`/api/auth/login`, already pilot-gated).

### 2.1 What is removed

The present `POST /api/auth/sso` behavior is removed in full, specifically:
- Trusting a caller-supplied `upn`/`username` from the request body as proof of identity.
- The "unknown UPN → fabricated global `PlatformAdmin`" fallback branch (the `else:` block that constructs `usr-architect-sso` with `isPlatformAdmin: True`, `AssignedTenants: ["ALL"]`).
- The misleading `reason="EntraIdOidcAuthenticationSuccessful"` audit semantics on a non-OIDC path.

### 2.2 Disposition of the route

Two acceptable dispositions (choose one at implementation time; both preserve contracts):

1. **Retire the route** — remove the handler. Clients are migrated to `/api/auth/entra/authorize`. Any residual call to `/api/auth/sso` returns `404`/`410`.
2. **Repurpose as a strict alias** — `/api/auth/sso` returns `302` to `/api/auth/entra/authorize` (a convenience redirect only), and **never** accepts or trusts a body-supplied identity.

In both dispositions the invariant holds: **a session is never issued from a body-supplied identity.**

### 2.3 Interaction with the RBAC seam

Because the fake `sso` currently produces a `PlatformAdmin` `user` dict that flows straight into `evaluate_access`, removing it restores the intended property that `evaluate_access` only ever receives identities that trace to verified authentication. No change to `evaluate_access` is required — the fix is upstream of the seam.

### 2.4 Test & documentation alignment (design intent, not code)

- QA (`test_comprehensive_qa.py`) must assert that unknown identities are **rejected** and that OIDC is the only non-dev authentication path — the current test that treats the stub's success as a pass must be inverted.
- `docs/security/authentication-architecture.md`, `SECURITY.md`, and `README.md` are corrected to describe only implemented behavior.

---

## 3. Identity → RBAC mapping (shared by Items 1 & 2)

This section defines the contract that keeps the RBAC architecture and tenant/service isolation intact.

### 3.1 Resolution rules

- After §1.5 validation, resolve the subject to an existing row in `users` by **UPN**.
- **Pre-provisioning required:** if no matching `users` row exists, **deny** (`403`) and emit `AUTH_DENY` (`UnknownIdentity`). **No auto-provisioning. No elevation. No fabricated admin.**
- If the row exists but `is_active = 0`, deny with `UserAccountDisabled` (reusing the existing reason semantics).

### 3.2 Building the `user` dict (contract-preserving)

The callback constructs the identical `user` dict shape currently consumed by `evaluate_access()` and downstream handlers — sourced **only** from the database, exactly as `authenticate_user()` already does:

- `id`, `upn`, `username`, `displayName`, `email`, `department`
- `roles` (from `get_effective_assignments`), `role`, `isPlatformAdmin`
- `permissions` (aggregated from assignments)
- `assignments`
- `AssignedTenants` (derived: `customer_id` values for `Specific` scopes, or `["ALL"]` when a global assignment exists — mirroring existing derivation)
- `tenantScope`, `initials`, `authProvider = "EntraID_OIDC"`, `isMfaEnabled`

**Crucially**, no field is invented client-side. Customer scope and service scope remain expressed exclusively by the DB `access_assignments` rows, which `evaluate_access()` re-reads on every request. This is what guarantees **customer scope isolation** and **service scope isolation** are preserved: the token carries no scope authority; scope is always re-derived server-side from the assignment table.

### 3.3 MFA claim handling (posture, non-blocking for core items)

- When `require_mfa` is configured true, validate the presence of `amr`/`acrs` (or equivalent) indicating MFA; otherwise deny. This is a claim check on the already-validated token — it does not alter authorization logic.

---

## 4. Item 3 — Removal of Fallback Passwords

**Goal:** Eliminate the shared, hard-coded credentials that function as an authentication backdoor, without breaking the legitimate (dev-only) password path or the hashing scheme.

### 4.1 What is removed

1. **In `rbac_engine.authenticate_user()`:** the fallback branch
   `if not is_valid and password in ("CloudShield2026!*", "SecurePass2026!*"): is_valid = True`
   is removed. After removal, a failed `verify_password()` is a hard failure. The PBKDF2-HMAC-SHA256 verification path and its failure semantics are unchanged.
2. **In `database/db.py` `seed_default_data()`:**
   - The bootstrap admin is **no longer** seeded with the literal `"CloudShield2026!*"`.
   - Imported users are **no longer** seeded with the literal `"SecurePass2026!*"`.

### 4.2 Replacement strategy (design intent)

- **Bootstrap admin:** seed the `users` row with **no usable password hash** (NULL or an unguessable random value that is never disclosed), and force credential establishment through the governed flow. `server.py`'s `get_admin_credentials()` already generates a random secret in `Data/auth.local.json` (git-ignored via `Data/*.local.json`) — the seed should align with that pattern rather than embedding a literal. In Entra-enforced deployments the bootstrap admin logs in via OIDC; local password is dev-only.
- **Imported users:** seed with NULL password hash unless an explicit, externally-supplied secret is provided at provisioning time. Passwordless-by-default; local password can be set only through an out-of-band governed process for non-pilot/dev.
- **Hashing unchanged:** `hash_password()` / `verify_password()` (PBKDF2-HMAC-SHA256, per-user random salt, `hmac.compare_digest`) remain exactly as-is — this item removes literals, not the algorithm.

### 4.3 Interaction with Item 1/2

Removing the fallback plus §3.1's "no auto-provision, no elevation" rule closes the two independent paths (local-password backdoor and fake-SSO elevation) by which an unverified subject could previously obtain a privileged `user` dict. `evaluate_access` is untouched.

### 4.4 Operator note (design, not code)

Because this changes bootstrap behavior, the design includes an explicit provisioning/recovery step for the admin (env-supplied `PORTAL_ADMIN_PASSWORD`, or OIDC first-login), so no legitimate access path depends on a hard-coded secret.

---

## 5. Item 4 — Authentication Enforcement for All APIs

**Goal:** Guarantee that **every** API route is gated by the existing authentication seam before it executes, with deny-by-default, without changing the authorization model.

### 5.1 Discovery (from current `server.py`)

Two categories exist today:

- **Already gated** (call `get_current_user()` and/or `evaluate_access()`): `/api/rbac/*`, report generate/approve/download, tenant `/test`.
- **Ungated** (no authentication check): `/api/users` (GET+POST), `/api/auth/config` (GET+PUT), `/api/tenants` (POST) and PUT/DELETE `/api/tenants/*`, PUT/DELETE `/api/users/*`, `/api/dispatch`, `/api/dispatch/history`, `/api/dispatch/schedule`, `/api/dispatch/send`, `/api/stats/global`, `/api/stats/sync`, `/api/activities` (GET+POST), `/api/services`, `/api/kql/catalog`, `/api/kql/packages`, `/api/auth/test`.

### 5.2 Design: a single enforcement seam (no redesign of handlers)

Introduce an **authentication gate** at the dispatch boundary, layered *before* existing handler logic, that preserves the current route→handler mapping:

- **Allow-list of public routes** (the only unauthenticated endpoints): `/api/health`, `/api/version`, the OIDC start/callback routes (`/api/auth/entra/authorize`, `/api/auth/entra/callback`), and the dev-only `/api/auth/login` (which is already pilot-gated). Everything else is protected by default.
- **Gate behavior:** for any non-public API route, resolve `get_current_user()`. If `None` → return `401` (deny by default). This mirrors `evaluate_access()`'s existing `DenyByDefault: AnonymousUser` posture but applies it at the route boundary so that even routes lacking a permission-specific check are no longer anonymous.
- **Authorization remains with `evaluate_access()`:** the gate proves *authentication*; per-route permission/scope decisions continue to be made by `evaluate_access()` exactly as today. For routes that currently perform an authorization decision, nothing changes; for routes that currently perform none, the gate at minimum enforces authentication, and the design recommends adding the appropriate `evaluate_access()` permission for state-changing admin routes (mapping stated in §5.3) — a **configuration of existing permissions**, not new authorization logic.

### 5.3 Recommended permission mapping (reuses existing permission catalog)

These reuse permissions already seeded in `db.py`; no new authorization concepts are introduced:

| Route group | Authentication | Authorization (existing permission) |
|:---|:---|:---|
| `/api/users` (GET) | required | `assignments:view` or `roles:view` (read) |
| `/api/users/*` (PUT/DELETE), `/api/users` (POST) | required | `roles:manage` / `assignments:manage` (user lifecycle) |
| `/api/auth/config` (GET/PUT) | required | `roles:manage` or a settings-scoped permission (admin-only) |
| `/api/tenants*` (mutations) | required | `customers:manage` |
| `/api/dispatch*` | required | `customers:manage` / `matrix:manage` |
| `/api/stats/*`, `/api/activities`, `/api/services`, `/api/kql/*` | required | `customers:view` / `services:view` (read) |
| `/api/auth/test` | required | admin-only; replace canned result with real discovery/JWKS reachability check |

### 5.4 `/api/users/me` and `/api/auth/config`

- **`/api/users/me`**: remove the unauthenticated hard-coded `PlatformAdmin` profile branch; when `get_current_user()` is `None`, return `401`. When authenticated, continue returning the session-derived profile (already correct).
- **`/api/auth/config` GET**: return only non-sensitive, non-identity configuration to authenticated callers; never disclose secrets/identifiers.

### 5.5 Guarantee of preserved isolation

Because the gate only *adds* authentication and delegates authorization to the untouched `evaluate_access()`, customer scope isolation and service scope isolation are unaffected — and are in fact strengthened, since previously-anonymous admin routes can no longer be reached without an identity that `evaluate_access()` can scope.

---

## 6. Item 5 — Session Hardening

**Goal:** Make issued sessions cryptographically strong, server-side authoritative, revocable, correctly transported, and time-bounded — while keeping the `get_current_user()` → `user` dict contract intact.

### 6.1 Token generation

- Replace `tok = uuid.uuid4().hex + uuid.uuid4().hex` (both in `login` and `sso`) with a CSPRNG token: `secrets.token_urlsafe(32)` (≥256 bits). Implemented once in a shared issuance helper used by both the OIDC callback (§1) and the dev login.
- Store **only a hash** of the token server-side (e.g., SHA-256) — never the raw token — so a session-store read does not yield a usable credential.

### 6.2 Session store (persistent, revocable)

- Replace the process-local `SESSIONS = {}` dict with a **server-side session record** persisted in the existing SQLite database (new migration `sessions` table), reusing `get_db()`. Proposed fields: `token_hash` (PK), `user_id`, `created_at`, `last_seen_at`, `expires_at` (absolute), `idle_expires_at`, `ip`, `user_agent`, `auth_provider`, `revoked` flag.
- `get_current_user()` continues to return a `user` dict or `None`, but now (a) looks up by token **hash**, (b) enforces absolute lifetime **and** idle timeout, (c) checks the `revoked` flag, and (d) re-validates `users.is_active` at the session layer (in addition to `evaluate_access` Stage 1). The function's external contract is unchanged; only its internals are hardened.

### 6.3 Lifecycle controls

- **Idle timeout:** 60 minutes (configurable). **Absolute lifetime:** 12 hours (configurable). Aligns behavior with the documented policy.
- **Rotation:** rotate the session token on authentication and on privilege/session events (e.g., after step-up), invalidating the predecessor.
- **Revocation:** `logout` revokes the specific record; add an admin "revoke-all for user" capability (set `revoked = 1` for all of a user's records) — enabled by the persistent store. Optionally revoke on user-disable.
- **Concurrency / context binding:** record IP and User-Agent; treat mismatch as a signal (strict-binding or re-validation depending on deployment). No change to the `user` dict contract.

### 6.4 Cookie & transport

- Issue `Set-Cookie: CS_SESSION=<tok>; Path=/; HttpOnly; Secure; SameSite=Strict` (add the missing `Secure`; consider `__Host-` prefix). Logout clears with matching attributes and `Max-Age=0`.
- **Remove the `?token=` query fallback** in `get_current_user()`: accept the token only from the `Authorization: Bearer` header or the `CS_SESSION` cookie. This prevents token leakage via URLs/logs/Referer.

### 6.5 Preservation of RBAC / report / scope models

Session hardening changes only *how a token is validated and stored*. The resulting `user` dict, the `evaluate_access()` call sites, the report authorization flow, and tenant/service scoping are all unchanged. Non-RBAC but now-authenticated routes (Item 4) gain the same session validation as RMAC routes.

### 6.6 Zero-Pip note

All of §6 is achievable with the standard library (`secrets`, `hashlib`, `sqlite3`, `datetime`). The only potential external dependency in this entire design is RSA signature verification in §1.5(4); it must either be implemented from stdlib primitives (`hashlib` + `pow()`-based RSA verify) or an explicit architecture decision must authorize one vetted dependency (e.g., a JOSE library). This is called out as the single required architecture decision.

---

## 7. Cross-Cutting: Audit, Configuration, and Ordering

### 7.1 Audit events (reuses `record_audit_event`, unchanged)

| Situation | event_type | decision | reason (example) |
|:---|:---|:---|:---|
| OIDC login success | `AUTH_ALLOW` | ALLOW | `EntraIdOidcAuthenticationSuccessful` (now truthful) |
| State missing/expired/replayed | `AUTH_DENY` | DENY | `InvalidOrReplayedState` |
| Signature/claims invalid | `AUTH_DENY` | DENY | `IdTokenValidationFailed` |
| Unknown identity / not pre-provisioned | `AUTH_DENY` | DENY | `UnknownIdentity` |
| Disabled account | `AUTH_DENY` | DENY | `UserAccountDisabled` |
| Unauthenticated protected route | `AUTH_DENY` | DENY | `DenyByDefault: AnonymousUser` |
| Logout / revocation | `AUTH_LOGOUT` / `AUTH_DENY` | ALLOW/DENY | `UserLoggedOut` / `SessionRevoked` |

Restored the "Entra" labels to only ever mean "validated OIDC."

### 7.2 Configuration & secret handling

- Secrets (client secret / certificate, admin password) from env/Key Vault only.
- Non-secret identity settings (client id, tenant, redirect URI, allowed tenants/domains, mfa requirement) from env/config, with git-ignored local overrides (consistent with `Data/*.local.json`).

### 7.3 Recommended ordering (each step independently shippable; RBAC untouched)

1. **Containment:** Items 2 & 3 (remove fake SSO, remove fallback passwords) + §5.4 (`/api/users/me`, `/api/auth/config` read hygiene). Highest risk-reduction per unit of change.
2. **Coverage:** Item 4 (authentication gate + allow-list + permission mapping).
3. **Hardening:** Item 5 (CSPRNG tokens, persistent revocable store, cookie `Secure`, drop `?token=`).
4. **Real identity:** Item 1 (OIDC authorize/callback, JWKS validation, identity mapping), flipping the pilot to require OIDC end-to-end.
5. **Posture:** MFA/`amr` claim enforcement, step-up re-validation, revocation-on-disable.

### 7.4 Acceptance criteria (design-level)

- No session is ever issued from a body-supplied identity; the only non-dev basis is a validated Entra `id_token`.
- No hard-coded literal credential exists in source or DB seed.
- Every API route is reachable only through the authentication seam (deny-by-default), except the explicit public allow-list.
- Sessions are CSPRNG-derived, stored hashed, server-side revocable, correctly cookie-flagged, and time-bounded.
- `evaluate_access()`, the report authorization model, and customer/service scoping are provably unchanged (verified by inspection: no modifications to that code path).

---

## 8. Explicit Non-Goals (to honor "do not redesign the platform")

- No change to `evaluate_access()` logic, the 8-stage chain, or the SoD rules.
- No change to the report authorization model (`reports:generate|download|approve` flow).
- No change to customer scope or service scope semantics or the `access_assignments` model.
- No new authorization framework, policy engine, or permission taxonomy (permission mapping in §5.3 reuses the existing catalog).
- No route/handler re-architecture beyond the single authentication gate.
- No modifications to the data-plane service authentication (`Engine/Core/Authentication.psm1`).

## Appendix A — Contract preservation checklist

| Contract | Preserved by | Verification |
|:---|:---|:---|
| RBAC architecture | Items 1–5 only feed `get_current_user()`/`evaluate_access()` | No diff to `evaluate_access()` §2–§6 stages |
| Report authorization | callback builds identical `user` dict; report routes untouched | report routes still call `evaluate_access` with same args |
| Customer scope isolation | scope re-read from `access_assignments` each request | Stage 4 unchanged |
| Service scope isolation | scope re-read from `access_assignments` each request | Stage 5 unchanged |
| `get_current_user()` contract | returns `user` dict or `None` | signature & return shape unchanged |
| Dev-only local login | `/api/auth/login` pilot gate unchanged | remains 403 in pilot |

## Appendix B — Single required architecture decision

RSA/RS256 signature verification for `id_token` (§1.5 step 4): implement with standard-library primitives, or formally authorize exactly one vetted crypto dependency. Everything else in this design is standard-library-compatible. No code or patches are produced by this document.
