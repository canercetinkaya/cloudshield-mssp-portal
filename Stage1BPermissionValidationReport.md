# Stage 1B Permission Mapping Validation Report

**Scope:** Validation of the permission strings used by the Stage 1B W9/W10 hardening
changes in `Portal/api/server.py`, against the authoritative RBAC definition.

**Analysis type:** Static, read-only. No production code, tests, or seed data were
modified. No database was queried; the canonical definitions were read from the
seed routine.

**Date:** 2026-09-09
**Reviewer:** Automated static analysis

---

## 1. Sources Inspected

| Artifact | Path | Role in this analysis |
| :--- | :--- | :--- |
| Server (Stage 1B guards) | `Portal/api/server.py` | Consumer — every Stage 1B `evaluate_access()` call site |
| Authorization engine | `Portal/api/rbac_engine.py` | Decision logic (`evaluate_access`, platform-admin bypass, scope checks) |
| RBAC schema | `database/migrations/001_initial_rbac_schema.sql` | Table/column definitions for `permissions`, `roles`, `role_permissions` |
| **Permission + role seed** | `database/db.py` → `seed_default_data()` | **Authoritative** permission catalog and role→permission grants |
| Permission catalog (Graph) | `Engine/Config/permission-catalog.json` | Microsoft Graph app-permission catalog (**different namespace** — see §6) |
| Permission catalog (Graph) | `config/catalog/permission-catalog.json` | Duplicate of the above |
| Permission matrix doc | `docs/security/permission-matrix.md` | Graph scope documentation |
| Existing RBAC handlers | `Portal/api/rbac_handlers.py` | Pre-existing `evaluate_access()` call sites (baseline) |

> **Note on the two "permission catalogs":** `Engine/Config/permission-catalog.json`
> and `config/catalog/permission-catalog.json` contain Microsoft **Graph application
> permission** scopes (`ThreatHunting.Read.All`, `SecurityAlert.Read.All`, …). These
> are **not** the platform RBAC permission codes consumed by `evaluate_access()`.
> They are a distinct namespace (see §6) and play no role in Stage 1B authorization.

### 1.1 How the authoritative permission set is defined

`database/db.py` `seed_default_data()` is the single source of truth for platform
RBAC. It defines **21 permission codes** across 9 domains:

```
reports:view  reports:generate  reports:download  reports:review  reports:approve
customers:view  customers:manage
services:view   services:manage
matrix:view     matrix:manage
teams:view      teams:manage
roles:view      roles:manage
assignments:view  assignments:manage
approvals:request  approvals:decide
audit:view      simulator:run
```

It also defines **6 roles** and the `role_permissions` grants (quoted verbatim in §3).

---

## 2. Stage 1B Permission Inventory

The Stage 1B changes add **30 `evaluate_access()` call sites** across the four HTTP
verbs, using **8 distinct permission codes**. Because several guards are written as
"primary permission OR fallback permission", the effective set is:

| # | Permission | Occurrences | Kind |
| :-: | :--- | :-: | :--- |
| 1 | `customers:view` | 2 | read |
| 2 | `customers:manage` | 9 | mutation |
| 3 | `services:view` | 3 | read |
| 4 | `roles:view` | 1 | read |
| 5 | `roles:manage` | 5 | mutation |
| 6 | `assignments:view` | 1 | read |
| 7 | `assignments:manage` | 3 | mutation |
| 8 | `matrix:manage` | 6 | mutation |

**Total distinct permissions: 8.** All 8 are used verbatim in `database/db.py`
(`permissions_data`), so **there are no invalid / misspelled permission names**.

### 2.1 Exact guard → route → permission mapping

| Line(s) | Method | Route (branch) | Permission(s) — OR logic |
| :-: | :-: | :--- | :--- |
| 709/711 | GET | `/api/users` | `roles:view` **OR** `assignments:view` |
| 738 | GET | `/api/services` | `services:view` |
| 757 | GET | `/api/activities` | `customers:view` |
| 858 | GET | `/api/stats/global` | `customers:view` |
| 957/959 | GET | `/api/dispatch` | `customers:manage` **OR** `matrix:manage` |
| 1014/1016 | GET | `/api/dispatch/history` | `customers:manage` **OR** `matrix:manage` |
| 1035 | GET | `/api/kql/catalog` | `services:view` |
| 1104 | GET | `/api/kql/packages` | `services:view` |
| 1612 | POST | `/api/tenants` | `customers:manage` |
| 1693/1695 | POST | `/api/dispatch/schedule` | `customers:manage` **OR** `matrix:manage` |
| 1754/1756 | POST | `/api/dispatch/send` | `customers:manage` **OR** `matrix:manage` |
| 1853/1855 | POST | `/api/users` | `roles:manage` **OR** `assignments:manage` |
| 1884/1886 | POST | `/api/stats/sync` | `customers:manage` **OR** `matrix:manage` |
| 1953 | POST | `/api/auth/test` | `roles:manage` |
| 1990/1992 | POST | `/api/activities` | `customers:manage` **OR** `matrix:manage` |
| 2813 | PUT | `/api/tenants/{id}` | `customers:manage` |
| 2846/2848 | PUT | `/api/users/{id}` | `roles:manage` **OR** `assignments:manage` |
| 2880 | PUT | `/api/auth/config` | `roles:manage` |
| 2913 | DELETE | `/api/tenants/{id}` | `customers:manage` |
| 2944/2946 | DELETE | `/api/users/{id}` | `roles:manage` **OR** `assignments:manage` |

---

## 3. Existing permission use (`rbac_handlers.py` + `server.py` PRE-1B)

Stage 1B permissions reused the same namespace already in use elsewhere:

| Permission | Also used by (existing code) |
| :--- | :--- |
| `roles:view` | `rbac_handlers.py` `/api/rbac/dashboard`, `/api/rbac/roles` |
| `customers:view` | `rbac_handlers.py` `/api/rbac/customers` |
| `matrix:view` | `rbac_handlers.py` `/api/rbac/customer-services` |
| `matrix:manage` | `rbac_handlers.py` customer-services onboard/suspend/disable |
| `assignments:view` | `rbac_handlers.py` `/api/rbac/assignments` |
| `audit:view` | `rbac_handlers.py` `/api/rbac/audit` |
| `teams:view` | `rbac_handlers.py` `/api/rbac/teams` |
| `roles:manage`, `reports:*` | `server.py` and RBAC engine |

This confirms Stage 1B introduced **no new permission vocabulary**.

---

## 4. Per-Permission Existence & Role Coverage

Role→permission grants as defined in `database/db.py` `seed_default_data()`:

```
PlatformAdmin       : ALL 21 permissions
SecurityEngineer    : reports:view, reports:generate, reports:download, reports:review,
                      customers:view, services:view, matrix:view, teams:view,
                      approvals:request, simulator:run
ComplianceSpecialist: reports:view, reports:generate, reports:download, reports:review,
                      customers:view, services:view, matrix:view, teams:view,
                      approvals:request, simulator:run
CustomerCISO        : reports:view, reports:download, reports:review, reports:approve,
                      customers:view, services:view, matrix:view
Auditor             : reports:view, reports:download, audit:view, customers:view,
                      services:view, roles:view, assignments:view, teams:view, matrix:view
ServiceOperator     : reports:view, customers:view, services:view, matrix:view
```

### 4.1 Coverage table for the 8 Stage 1B permissions

| Permission | Exists? | PlatformAdmin | SecurityEng. | ComplianceSp. | CustomerCISO | Auditor | ServiceOperator |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `customers:view` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `customers:manage` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `services:view` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `roles:view` | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `roles:manage` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `assignments:view` | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `assignments:manage` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `matrix:manage` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

*(✅ = role holds the permission in seed data; ❌ = role does not hold it.)*

**Observation:** four of the eight Stage 1B permissions — `customers:manage`,
`roles:manage`, `assignments:manage`, `matrix:manage` — are granted **only** to
`PlatformAdmin`. This is expected for mutating operations but is the key input to
the reachability analysis in §5.

### 4.2 Platform-admin bypass interaction

In `evaluate_access()`, Stage 2 grants an unconditional ALLOW to any platform role
**unless** the requested permission is in `CUSTOMER_CONTENT_PERMISSIONS`
(`reports:view`, `reports:download`, `reports:create`, `reports:generate`,
`reports:review`, `reports:approve`).

**None of the 8 Stage 1B permissions are customer-content permissions.** Therefore
`PlatformAdmin` (and any role flagged `is_platform_role`) is ALLOWed by Stage 2 on
**every** Stage 1B guard, regardless of scope — before Stage 3–5 ever run.

---

## 5. Reachability Analysis (Endpoints That Could Become Unreachable)

### 5.1 Method

An endpoint becomes *unreachable for a role* only if the role neither:
1. holds one of the guard's permissions, **nor**
2. is a platform role (Stage 2 bypass).

Because OR-fallbacks broaden access, each route is reachable if **any** of its
listed permissions is held by the caller (or the caller is a platform role).

### 5.2 Result: No endpoint is globally unreachable

`PlatformAdmin` passes every guard, so **every Stage 1B-guarded endpoint remains
reachable by at least one role**. There are no "dead" endpoints in the strict sense.

### 5.3 Result: Endpoints now restricted to PlatformAdmin *only* (non-admin lockout)

The following endpoints are reachable **only** by `PlatformAdmin` (or another
`is_platform_role`), because their guard permission(s) are held by no non-platform
role. For all other roles these endpoints are now effectively **403-locked**:

| Endpoint | Guard permission(s) | Non-admin roles with access |
| :--- | :--- | :--- |
| `GET /api/dispatch` | `customers:manage` OR `matrix:manage` | none |
| `GET /api/dispatch/history` | `customers:manage` OR `matrix:manage` | none |
| `POST /api/tenants` | `customers:manage` | none |
| `POST /api/dispatch/schedule` | `customers:manage` OR `matrix:manage` | none |
| `POST /api/dispatch/send` | `customers:manage` OR `matrix:manage` | none |
| `POST /api/stats/sync` | `customers:manage` OR `matrix:manage` | none |
| `POST /api/activities` | `customers:manage` OR `matrix:manage` | none |
| `POST /api/auth/test` | `roles:manage` | none |
| `PUT /api/tenants/{id}` | `customers:manage` | none |
| `PUT /api/auth/config` | `roles:manage` | none |
| `DELETE /api/tenants/{id}` | `customers:manage` | none |

`POST /api/users`, `PUT /api/users/{id}`, `DELETE /api/users/{id}` are guarded by
`roles:manage` OR `assignments:manage`; both are PlatformAdmin-only, so these are
**also PlatformAdmin-only**.

### 5.4 Endpoints reachable by additional non-admin roles

| Endpoint | Guard | Reachable by (besides PlatformAdmin) |
| :--- | :--- | :--- |
| `GET /api/users` | `roles:view` OR `assignments:view` | **Auditor** |
| `GET /api/services` | `services:view` | SecurityEngineer, ComplianceSpecialist, CustomerCISO, Auditor, ServiceOperator |
| `GET /api/kql/catalog` | `services:view` | same as above |
| `GET /api/kql/packages` | `services:view` | same as above |
| `GET /api/activities` | `customers:view` | all 5 non-admin roles |
| `GET /api/stats/global` | `customers:view` | all 5 non-admin roles |

### 5.5 Operator-visibility regression risk (functional)

`GET /api/dispatch`, `GET /api/dispatch/history`, `GET /api/kql/catalog`,
`GET /api/kql/packages`, `GET /api/activities`, `GET /api/stats/global` are
**read-only** endpoints. The Stage 1B guards assign them **mutating** permissions
(`customers:manage` / `matrix:manage`) or a broad read permission (`customers:view`,
`services:view`).

- For `dispatch` and `dispatch/history` this is the notable finding: a **read** is
  gated behind a **write**-class permission (`customers:manage` / `matrix:manage`),
  so no read-only operational role (SecurityEngineer, ComplianceSpecialist,
  Auditor, ServiceOperator, CustomerCISO) can view dispatch configuration/history.
  Whether this is intended least-privilege behaviour or an over-restriction should
  be confirmed by the design owner (see §7, Finding F1).

---

## 6. Namespace Separation (False-Positive Avoidance)

The Graph app-permission catalogs (`Engine/Config/permission-catalog.json`,
`config/catalog/permission-catalog.json`) and `docs/security/permission-matrix.md`
list scopes such as:

```
ThreatHunting.Read.All, SecurityAlert.Read.All, Machine.Read.All,
SecurityIncident.Read.All, InformationProtectionPolicy.Read.All, …
```

These are **Microsoft Graph / Defender application permissions** used by the
reporting engine to call Microsoft APIs. They are **never** passed to
`evaluate_access()` and are **not** comparable to platform RBAC codes such as
`customers:view`. No Stage 1B guard references this namespace, so there is no
cross-namespace mistake.

---

## 7. Findings

| ID | Severity | Finding |
| :-: | :--- | :--- |
| **F1** | **Medium (design)** | Read-only dispatch/schedule/history endpoints are gated by **mutating** permissions (`customers:manage` OR `matrix:manage`). No read-only role can access them. Confirm whether this over-restricts legitimate monitoring accounts, or whether a `dispatch:view`-style read permission should exist. |
| **F2** | **Low (documentation)** | `matrix:manage` is reused as a fallback for dispatch endpoints. Semantically `matrix:manage` is "service matrix management"; using it as an OR for dispatch read/write is a mild permission-semantics stretch. |
| **F3** | **Info** | `POST /api/activities` and `GET /api/activities` use **different** permission classes: GET → `customers:view` (broad), POST → `customers:manage` OR `matrix:manage` (admin-only). Consistent with read/write split, but worth noting the GET is far more permissive than the POST. |
| **F4** | **Info** | All 8 Stage 1B permissions exist in seed data; **no invalid permission names** were found. |
| **F5** | **Info (positive)** | No Stage 1B-guarded endpoint is globally unreachable: `PlatformAdmin` passes every guard via the Stage 2 platform bypass. |

**Invalid permission names identified:** **none.**

---

## 8. Conclusion

1. **All 8 Stage 1B permission codes are valid** — each is defined in
   `database/db.py::seed_default_data()` `permissions_data` and used verbatim.
2. **No misspelled, deprecated, or unknown permission** appears in any Stage 1B
   `evaluate_access()` call site.
3. **PlatformAdmin can reach all 20 guarded routes** (Stage 2 bypass, since none of
   the 8 permissions are customer-content permissions). No endpoint is dead.
4. **Eleven endpoints become PlatformAdmin-only** for non-platform roles (all
   dispatch, tenant, stats-sync, activities-write, auth/test, auth/config routes).
5. **Six endpoints remain reachable by additional non-admin roles** (users-list →
   Auditor; services/kql → all readers; activities/stats-global read → all readers).
6. The one item warranting a design decision is **F1/F2**: read-only dispatch
   endpoints require write-class permissions, which may or may not match intended
   least-privilege posture.

**No code, test, or seed-data changes are recommended by this analysis itself —
the report is informational; items F1/F2 are flagged for design-owner review only.**
