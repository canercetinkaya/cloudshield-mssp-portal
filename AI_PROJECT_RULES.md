# CloudShield AI Project Rules

**Document class:** Controlled engineering policy  
**Applies to:** Human developers, AI agents, reviewers, CI automation, release automation  
**Default authority:** Mandatory unless an explicit project-owner exception is recorded  
**Change control:** Project-owner approval required  

## 1. Purpose

This file is the mandatory engineering instruction set for every AI agent, developer, reviewer, and automation working on the CloudShield MSSP Platform.

Before changing any file, the acting agent must read:

1. `AI_PROJECT_RULES.md`
2. `PROJECT_HANDOFF.md`
3. `AuthenticationGapAnalysis.md`
4. `AuthenticationRemediationDesign.md`
5. `AuthenticationImplementationPlan.md`
6. The latest validation and release reports applicable to the active branch

Implementation and runtime behavior are the source of truth. Documentation claims, release summaries, test names, screenshots, and previous agent statements are not evidence unless verified against the current branch.

---

## 2. Mandatory Working Method

Every task must follow this sequence:

```text
Verify repository and branch
→ Read applicable project rules and plans
→ Inspect current implementation
→ Apply only the requested scope
→ Run relevant negative and positive tests
→ Review the diff
→ Produce validation evidence
→ Stop before commit or push unless explicitly authorized
```

Agents must not start a new architecture cycle when the existing architecture can support the requested change.

Agents must not create additional planning documents unless explicitly requested or required as a deliverable.

Agents must not approve their own implementation solely through self-authored tests.

---

## 3. Git and Repository Safety

- Never push directly to `main`.
- Never force-push.
- Never delete a branch or tag without explicit authorization.
- Never overwrite an existing release tag.
- Never commit secrets, API keys, credentials, private keys, customer raw data, local databases, or PII-bearing artifacts.
- Never commit generated customer reports unless the repository policy explicitly allows sanitized test artifacts.
- Always report the active branch and tested commit in validation outputs.
- Treat uncommitted pre-existing changes as owned by the user. Do not revert, overwrite, or include them unless explicitly authorized.
- Before editing, inspect `git status` and distinguish pre-existing changes from task changes.
- Before completion, report changed files, test results, and remaining blockers.

Current release discipline:

```text
channel = pilot
productionReady = false
```

These values must not be changed without an explicit production release decision.

---

## 4. Authentication Rules

### 4.1 Prohibited behavior

The following are strictly forbidden:

- Re-enabling the retired caller-supplied identity behavior on `POST /api/auth/sso`.
- Creating a session from a caller-supplied `upn`, username, email address, or role without cryptographic identity proof.
- Fabricating a `PlatformAdmin` or global session for an unknown identity.
- Adding fallback or shared passwords.
- Accepting `CloudShield2026!*`, `SecurePass2026!*`, or any other repository-known password as a universal credential.
- Falling back to local authentication after failed Entra authentication.
- Enabling local authentication in Pilot or Production.
- Accepting session tokens from URL query parameters.
- Presenting simulated SSO as Microsoft Entra OIDC.

### 4.2 Current W5 containment rule

Until real Microsoft Entra OIDC is implemented and validated:

```text
POST /api/auth/sso → 410 Gone
No token
No session
No user resolution
AUTH_DENY audit event
```

Any regression that makes this endpoint issue a session is a critical release blocker.

### 4.3 Target Entra authentication

The target portal authentication flow is:

```text
Microsoft Entra ID
→ Authorization Code Flow
→ PKCE
→ state and nonce validation
→ authorization-code exchange
→ ID token validation
→ JWKS signature verification
→ issuer, audience, expiry, not-before and tenant validation
→ tenant ID + object ID identity mapping
→ CloudShield server-side session
```

Identity must be keyed by validated `tid + oid`. UPN or email may be used only as display metadata.

Unknown or inactive identities must be denied. They must never be auto-elevated.

### 4.4 Local authentication

Local authentication may exist only for an explicitly named development profile.

It must be disabled by default in:

- Pilot
- UAT exposed to external users
- Production

Local authentication must never be silently enabled by tests, startup scripts, or remediation tooling.

---

## 5. Central API Authentication Rules

The API authentication posture is deny by default.

Only explicitly approved public routes may be accessible anonymously, such as:

- `GET /api/health`
- `GET /api/version`
- required OIDC start and callback routes when implemented
- required static login assets

Every other `/api/*` route must require authentication before route-specific logic runs.

Response semantics:

```text
Missing or invalid identity → 401 Unauthorized
Authenticated but insufficient authorization → 403 Forbidden
Retired endpoint → 410 Gone
Unavailable optional capability → 501 Not Implemented or governed NotConfigured state
```

Never use optional enforcement patterns such as:

```python
if user:
    enforce_authorization()
```

Protected routes must enforce authentication unconditionally.

---

## 6. RBAC and Authorization Rules

The existing authorization chain is authoritative:

```text
Identity
→ Platform Role
→ Permission
→ Customer Scope
→ Service Scope
→ Conditions
→ Separation of Duties
→ Allow or Deny
→ Audit Event
```

Mandatory rules:

- Do not bypass `evaluate_access()`.
- Do not move authorization decisions to the browser.
- UI visibility is not authorization.
- Do not trust customer IDs, service IDs, roles, scopes, or permissions supplied by the client.
- Re-read effective assignments server-side.
- Preserve deny-by-default behavior.
- Preserve customer isolation.
- Preserve service isolation.
- Preserve consolidated-report all-service-scope evaluation.
- Preserve report creator versus approver separation.
- Preserve access requester versus approver separation.
- `PlatformAdmin` does not automatically receive customer-content access.
- Access administration does not automatically grant report or telemetry access.
- Temporary access must be explicit, approved, time-bounded, and auditable.

Do not describe application-local temporary access as Microsoft Entra PIM unless actual Entra PIM state is validated.

Preferred term until that integration exists:

```text
CloudShield JIT Temporary Access
```

---

## 7. Report Authorization Rules

- Customer reports must be resolved through a report registry and report ID.
- Path-based customer report download must not be used as an authorization mechanism.
- The legacy `GET /api/reports/download?file=` route must not serve customer artifacts.
- Report download must enforce authentication, customer scope, every constituent service scope, report state, storage-root confinement, and audit logging.
- Consolidated reports require access to all included services.
- Partial hiding of unauthorized service sections is not a substitute for report authorization.
- Report generation, viewing, download, review, approval, and dispatch must be separately permissioned where applicable.

---

## 8. Reporting Integrity Rules

CloudShield follows evidence-backed, zero-fiction reporting.

### 8.1 KPI provenance

Every customer-facing KPI must resolve to approved metadata:

- KPI ID
- service code
- source query ID
- data origin
- collector run ID
- collection status
- reporting period
- calculation version
- synthetic flag
- evidence ID where required

Raw query text is not a catalog identifier.

Unknown, fixture, mock, display-only, or synthetic provenance must not appear in Pilot or Production customer outputs.

### 8.2 Data and calculation integrity

- Do not fabricate metrics.
- Do not use action-count multipliers to calculate saved hours.
- Do not calculate FTE without an approved methodology and evidence.
- `ActualEffortHours` is delivery effort, not automatically customer time saved.
- If evidence or methodology is unavailable, display `N/A`, not zero.
- Do not calculate a percentage when the denominator is zero, missing, invalid, or unavailable.
- Parent totals and child totals must be mathematically consistent.
- Failed or incomplete collections must not render as successful zero-value KPI cards.

### 8.3 Operational evidence

A runbook proves a procedure exists. A runbook does not prove an action was executed.

Count customer-facing operations only when an eligible execution record includes:

- Action ID
- customer ID
- service code
- execution timestamp
- evidence type
- evidence reference
- approved status
- non-synthetic flag

Draft, rejected, unapproved, synthetic, out-of-scope, and runbook-only records must not enter customer totals.

### 8.4 Claims and language

Do not claim or imply:

- guaranteed security
- guaranteed compliance
- full protection
- legal certification
- legal non-repudiation
- immutable proof without verified immutable storage
- zero incidents means zero risk

SHA-256 metadata may be described only as a technical integrity comparison record.

---

## 9. Dispatch Rules

The platform must never claim a report was delivered unless the configured provider confirms delivery acceptance and evidence is recorded.

Forbidden behavior:

- hard-coded `Delivered`
- hard-coded latency
- claiming Microsoft Graph SendMail without making the call
- updating customer status to delivered based only on a local JSON write

If dispatch is not configured:

```text
status = NotConfigured
delivered = false
```

The portal must show an honest unavailable or not-configured state.

---

## 10. Session Rules

Target session requirements:

- CSPRNG-generated tokens
- only token hashes stored server-side
- persistent, revocable session store
- idle timeout
- absolute lifetime
- logout invalidation
- cookie invalidation
- disabled-user revalidation
- assignment and membership re-evaluation
- Secure cookie in Pilot and Production
- HttpOnly
- SameSite=Strict
- Path=/
- no query-string session tokens

Until shared persistent sessions are implemented, multi-replica or scale-to-zero limitations must be documented accurately.

---

## 11. UTF-8 and Turkish Language Rules

CloudShield is UTF-8 by default across the repository and runtime.

### 11.1 Required corpus

The following text must round-trip without loss through every supported customer-facing path:

```text
İstanbul
KoçSistem
Güvenlik
Şifre
İhlal
Çözüm
Uyumluluk
Öncelik
Yönetici Özeti
```

### 11.2 Mandatory surfaces

UTF-8 must be preserved in:

- source files
- Portal UI
- API JSON responses
- JSON persistence
- SQLite fields
- audit logs
- report HTML
- report PDF
- email subjects
- email bodies
- PowerShell file IO
- Python file IO
- generated artifacts
- validation reports

### 11.3 Prohibited approaches

- Do not repair mojibake using word-specific regex replacements.
- Do not transliterate Turkish characters to ASCII in customer-facing output.
- Do not silently replace invalid characters.
- Do not rely on implicit system encoding.
- Do not mark terminal rendering artifacts as source corruption without byte-level verification.

### 11.4 Required implementation discipline

- Use explicit UTF-8 for every text read and write.
- Use `ensure_ascii=False` for customer-facing JSON where appropriate.
- Declare UTF-8 in HTML and HTTP response headers.
- Use Unicode-capable fonts and rendering paths for PDF output.
- If a Unicode PDF engine or font is unavailable, fail closed with a clear error. Do not silently transliterate.
- Configure PowerShell and Python output encoding explicitly where console output is part of supported operation.
- Add automated UTF-8 regression tests using the required corpus.

Distinguish:

```text
Source corruption
Customer-visible rendering defect
Developer-console rendering artifact
```

Only confirmed root causes may be modified.

---

## 12. Privacy Rules

Privacy transformation must occur before customer artifact persistence:

```text
Raw collection
→ Normalization
→ Privacy classification
→ Masking or suppression
→ Persistence-safe model
→ KPI calculation
→ Rendering
```

Do not rely only on HTML masking.

Customer outputs must not expose:

- access tokens
- API keys
- secrets
- private keys
- raw UPNs when not required
- email bodies
- message subjects
- DLP matched content
- Insider Risk identities
- Communication Compliance content
- Copilot prompts or responses
- sensitive file names or paths

Fixture, DryRun, mock, and synthetic data must be isolated from customer artifact directories.

---

## 13. Audit Rules

Audit events must record, where applicable:

- event ID
- timestamp
- actor
- action
- resource
- customer
- service
- decision
- reason
- IP address
- correlation ID
- relevant details

Both ALLOW and DENY decisions must be recorded for protected operations.

Use accurate terminology:

```text
Application-controlled append-only audit trail
```

Do not call SQLite audit storage immutable, tamper-proof, tamper-evident, WORM, or legally non-repudiable unless those properties are separately implemented and verified.

---

## 14. Test Rules

- Tests must use isolated temporary databases and artifacts.
- Tests must never modify production or developer data files.
- Tests must not enable local authentication in Pilot.
- Tests must not fabricate production sessions.
- Tests must not bypass `evaluate_access()`.
- Tests must not depend on stale hashes or repository-known credentials.
- Test credentials must be random and test-only.
- Tests must clean up temporary files and processes.
- Negative tests must prove insecure legacy behavior is rejected.
- Existing assertions must not be weakened merely to obtain a passing result.
- When a test and implementation disagree, determine which behavior matches the security requirement before changing either.
- A test name, report claim, or previous PASS is not evidence by itself.

Minimum protected scenarios include:

- arbitrary UPN SSO rejection
- anonymous protected-route rejection
- cross-customer denial
- cross-service denial
- expired assignment denial
- revoked assignment denial
- disabled user denial
- report creator self-approval denial
- requester self-approval denial
- PlatformAdmin customer-content denial without explicit scope
- legacy report-download denial
- hard-coded credential rejection
- UTF-8 round-trip preservation
- fixture and DryRun isolation

---

## 15. AI Agent Behavior Rules

Every AI agent must:

- read this file before work;
- inspect the current branch and working tree;
- preserve user-owned uncommitted changes;
- obey the requested task scope;
- prefer root-cause fixes over superficial output edits;
- stop if the requested fix requires weakening authentication, authorization, privacy, provenance, or audit controls;
- report uncertainty rather than fabricate evidence;
- clearly separate implemented, partially implemented, planned, and externally blocked states;
- avoid repeated architecture and documentation cycles when implementation is required;
- avoid generating qualitative scores from deterministic tests;
- not modify independent tests solely to make them pass;
- run relevant tests after changes;
- produce a concise completion summary with evidence.

Agents must not:

- trust prior release reports without verification;
- treat documentation as implementation;
- create broad unrelated refactors;
- silently enable unsafe development settings;
- claim completion when runtime validation has not occurred;
- commit or push unless explicitly instructed;
- recommend another open-ended task when the current task can be completed.

---


## 16. AI Startup and Context Recovery Procedure

Before any analysis, implementation, remediation, validation, documentation, release, or publication task, every AI agent must complete the following startup procedure:

1. Read `AI_PROJECT_RULES.md` completely.
2. Read `PROJECT_HANDOFF.md` completely.
3. Read the latest applicable validation report for the active branch.
4. Read the active remediation or implementation plan, if one exists.
5. Run or inspect:
   - active repository root;
   - active branch;
   - remote configuration;
   - latest commits;
   - working-tree status;
   - current version manifest.
6. Identify pre-existing user-owned changes and exclude them from the task scope unless explicitly authorized.
7. Inspect the actual implementation files affected by the requested task.
8. Confirm the exact task scope, allowed files, prohibited files, tests, and completion criteria from the user's instruction.

The startup procedure must not become a new analysis cycle. Its purpose is to recover context quickly and prevent work on an incorrect branch, stale checkout, outdated document, or unrelated implementation.

If the active branch, expected commits, or required source files are missing, stop implementation and return:

```text
INVALID_REPOSITORY_CONTEXT
```

Do not modify files until repository context is valid.

---

## 17. AI Implementation Discipline and Duplicate-Path Prevention

AI agents must prefer correction or extension of the existing authoritative implementation over creation of parallel alternatives.

Do not create duplicate or competing implementations for:

- authentication;
- session management;
- authorization;
- RBAC;
- report generation;
- report download;
- dispatch;
- customer storage;
- service catalog;
- audit storage;
- privacy transformation;
- KPI provenance;
- quality gates;
- version management.

Before creating a new module, endpoint, database table, configuration source, helper, or workflow, verify that an existing authoritative implementation cannot be safely extended.

When a new component is necessary, the completion report must explain:

- why the existing component could not be extended;
- which component becomes authoritative;
- how old paths are retired;
- how callers are migrated;
- how duplicate behavior is prevented;
- which regression tests prove that only the authoritative path remains active.

Temporary compatibility paths must:

- be explicitly labeled;
- be disabled by default;
- have a removal condition;
- never weaken authentication, authorization, privacy, or evidence requirements;
- never be described as the final architecture.

---

## 18. Customer and Pilot Tenant Onboarding Rules

Every customer and Pilot tenant must be onboarded through a controlled, auditable process.

Mandatory onboarding data includes:

- customer ID;
- customer code;
- display name;
- Entra tenant ID where applicable;
- environment classification;
- Pilot or Production status;
- active service subscriptions;
- reporting period and timezone;
- approved data sources;
- required application permissions;
- customer contacts and operational owners;
- report approvers;
- support and escalation contacts;
- retention and privacy settings;
- onboarding approval evidence.

Mandatory onboarding rules:

- A customer must have at least one active `CustomerService` relation before collection or reporting.
- Service codes must resolve to the authoritative service catalog.
- Customer configuration must not contain raw secrets.
- Secrets and certificates must be resolved from approved secure storage.
- Tenant connectivity tests must use real provider responses and must never return canned success.
- A failed connectivity, permission, licensing, or collection check must be visible in Collection Health.
- A tenant must not be marked ready solely because configuration files exist.
- Pilot tenants must have an explicit approved Pilot scope and named internal owner.
- Test tenants, fixtures, and synthetic tenants must be clearly classified and isolated.
- Customer deletion, suspension, service disablement, and offboarding must require authorization and audit evidence.
- Tenant deletion must not silently delete regulated evidence or customer artifacts contrary to retention policy.

Pilot onboarding validation must include:

```text
Identity and access
→ Tenant connectivity
→ Permission validation
→ Service subscription validation
→ Collection health
→ Privacy validation
→ Report generation
→ Report authorization
→ Customer review
→ Pilot approval
```

---

## 19. Multi-Tenant Safety and Data Boundary Rules

Cross-tenant access, aggregation, search, export, caching, logging, artifact reuse, and inference are forbidden unless an explicitly authorized platform-level operational use case exists and customer data remains isolated.

Mandatory controls:

- Customer A data must never enter Customer B reports, API responses, logs, caches, exports, prompts, or artifacts.
- Customer scope must be enforced server-side for reads and writes.
- Service scope must be enforced inside the selected customer scope.
- Report registry records must bind artifacts to the correct customer and service set.
- Storage keys must be confined to the approved customer artifact root.
- File-path text, folder name, report title, or client-supplied customer label must never be treated as authorization evidence.
- Search results, dashboards, statistics, and activity feeds must be customer-scoped.
- Background jobs and dispatch jobs must carry an immutable customer context through the full execution path.
- Cache keys must include customer and, where relevant, service scope.
- Correlation IDs must not cause customer data to be joined across tenant boundaries.
- Pseudonymization values must not enable cross-customer correlation unless explicitly approved.
- Shared operational dashboards must show only approved aggregate data and must never expose customer-sensitive fields by default.

Required negative tests include:

- cross-customer API read;
- cross-customer API mutation;
- cross-customer report generation;
- cross-customer report download;
- cross-customer report approval;
- cross-customer search;
- cross-customer dispatch;
- cross-customer cache reuse;
- manipulated report ID;
- manipulated storage key;
- missing customer context;
- unknown customer context.

Any confirmed cross-tenant leakage is a Critical severity release blocker.

---

## 20. Executive Report and Customer Experience Rules

CloudShield reports must communicate defensible customer value, not merely expose technical telemetry.

Every customer-facing executive report must provide, when supported by evidence:

- reporting scope and period;
- collection-health summary;
- executive summary;
- key risks and material changes;
- security and compliance trends;
- service-level findings;
- KoçSistem operational actions with execution evidence;
- customer-owned actions;
- decision backlog;
- owners and target timelines when approved;
- limitations and unavailable-data disclosures;
- methodology and provenance references;
- report approval state.

Customer-facing report rules:

- Do not present unavailable data as zero.
- Do not present failed collection as positive status.
- Do not show empty decorative sections.
- Do not fabricate recommendations, action owners, due dates, or ROI.
- Do not calculate saved hours or FTE without approved methodology and evidence.
- Do not rank or label employees as risky individuals.
- Do not expose sensitive identities, prompts, matched content, message bodies, or file paths.
- Do not use page-count targets that clip or suppress content.
- Do not use visual design to conceal limitations or collection failures.
- Every recommendation must be linked to evidence, scope, owner type, and expected outcome.
- Technical detail must remain available without overwhelming the executive summary.

Minimum visual and usability checks:

- readable at standard browser zoom;
- readable in generated PDF;
- Turkish glyphs preserved;
- tables and cards do not clip;
- headings are not orphaned;
- status colors have accompanying text;
- accessibility is not dependent on color alone;
- generated report remains usable across supported browser and PDF paths.

A technically correct report that is misleading, unreadable, unactionable, or unsupported by evidence is not Pilot ready.

---

## 21. Controlled Pilot Release Exit Criteria

`READY_FOR_CONTROLLED_PILOT` may be issued only when all mandatory Pilot gates pass on the active release candidate.

### Gate 1: Repository and version

- Correct branch and commit verified.
- Working tree and pre-existing changes documented.
- `version.json`, deployed version, branch, and tested commit are consistent.
- `channel = pilot`.
- `productionReady = false`.

### Gate 2: Authentication

- No caller-supplied identity can create a session.
- Retired SSO stub remains fail-closed until real OIDC is validated.
- Local authentication is disabled in Pilot.
- No hard-coded or fallback credential is accepted.
- Protected APIs reject anonymous requests.
- Session and logout behavior meet the approved Pilot scope.

### Gate 3: Authorization

- RBAC tests pass.
- Customer isolation tests pass.
- Service isolation tests pass.
- Platform administrators require explicit customer-content scope.
- Report authorization and SoD tests pass.
- Temporary access is explicit, approved, time-bounded, and auditable.

### Gate 4: Reporting integrity

- KPI provenance resolves.
- Calculation and zero-denominator tests pass.
- Operational actions resolve to execution evidence.
- Collection failures and unavailable data are disclosed correctly.
- No synthetic, fixture, DryRun, or mock data exists in Pilot customer output.

### Gate 5: Privacy and language

- Privacy scans pass across JSON, HTML, PDF, logs, manifests, and artifacts.
- UTF-8 and Turkish round-trip tests pass for all customer-facing paths.
- No customer-visible mojibake or ASCII transliteration remains.

### Gate 6: Artifact and workflow

- Report is generated through the actual portal workflow.
- Run ID, correlation ID, customer context, service set, and tested commit are recorded.
- HTML and PDF content-preservation checks pass.
- Report registry and download authorization pass.
- Dispatch reports actual provider state and never fabricates delivery.

### Gate 7: CI and independent verification

- Required test suites run in CI or a documented equivalent controlled pipeline.
- Negative tests pass.
- Independent verification is performed against runtime behavior and generated artifacts.
- No blocking Critical or High finding remains inside the approved Pilot scope.

Controlled Pilot approval must define:

- approved customers;
- approved services;
- approved roles;
- authentication mode;
- report types;
- operational owner;
- monitoring requirements;
- rollback triggers;
- incident escalation path;
- limitations;
- Production blockers.

Controlled Pilot approval does not imply Production approval.

---

## 22. Rule Governance and Change Control

`AI_PROJECT_RULES.md` is a controlled project-governance artifact.

Mandatory governance rules:

- Changes require explicit approval from the project owner.
- AI agents must not modify this file unless the user explicitly requests a rule change.
- Every rule change must include a reason, affected sections, security impact, and compatibility impact.
- Rules must not be weakened merely to make current implementation or tests pass.
- Temporary exceptions must be explicit, time-bounded, owned, documented, and approved.
- An exception must identify compensating controls and an exit condition.
- Conflicts are resolved in this order:

```text
Explicit project-owner instruction
→ AI_PROJECT_RULES.md
→ Approved security and architecture decisions
→ Active implementation plan
→ Current implementation
→ Tests
→ Documentation and prior agent reports
```

Implementation remains the factual source of current behavior, but current behavior does not override an approved security rule. A conflict between implementation and this file is a defect or an approved exception, not an automatic rule change.

Rule changes must be reviewed for effects on:

- security;
- privacy;
- RBAC;
- customer isolation;
- service isolation;
- reporting integrity;
- UTF-8 compliance;
- testing;
- release gates;
- customer experience;
- operational support.

---

## 23. Current Engineering State

At the time this rule set was created, the validated direction is:

```text
Stage 1A containment: implemented and validated
Stage 1B central API authentication and route guards: implemented and validated
W5 fake SSO retirement: implemented and validated as 410 Gone
Real Microsoft Entra OIDC: not yet implemented
Persistent shared session store: not yet implemented
Controlled Pilot: not approved until remaining mandatory gates pass
Production: not approved
```

The acting agent must verify these statements against the current branch before relying on them.

---

## 24. Mandatory Completion Report

Every implementation task must return:

1. Active branch.
2. Tested commit or working-tree base.
3. Files changed.
4. Pre-existing files intentionally not changed.
5. Requirement mapping.
6. Positive tests run.
7. Negative tests run.
8. Runtime evidence.
9. Remaining blockers.
10. Git status.
11. Final task result: `PASS`, `PARTIAL`, `BLOCKED`, or `FAIL`.

No task may be marked `PASS` when a requirement in the explicit task scope remains unverified.
