# CloudShield v2.5.15-PILOT UX Improvement Release Notes

## Executive Summary
Following the controlled pilot review recorded in PortalExperienceReview.md, all **HIGH** and **MEDIUM** severity findings (as well as visual polish items F-01 through F-08) have been implemented directly in the CloudShield MSSP Portal codebase without modifying backend architecture, authentication mechanisms, or RBAC boundaries.

Version bumped from 2.5.14-PILOT to **2.5.15-PILOT** (Build: 2026.09.16.1).

---

## 1. Traceability & Finding Matrix

| ID | Category / Component | Severity | Description | Status in v2.5.15 |
| :--- | :--- | :--- | :--- | :--- |
| **F-01** | Dashboard Usability | **HIGH** | Multi-tenant vs single-tenant view confusion. Selecting a tenant showed global fleet tiles without customer-specific context. | **Resolved**: Single-tenant executive cockpit (#singleTenantCockpit) dynamically activates upon selecting any specific tenant, displaying the 4-Pillar Service Value Attribution Model. |
| **F-02** | Executive Experience | **HIGH** | Static executive decision framework lacking interactivity and operational triage actions. | **Resolved**: Interactive 4-quadrant Customer Decision Framework with real-time approval buttons (pproveDecision) that log actions and update UI state. |
| **F-03** | Dashboard Usability | **MEDIUM** | Misleading zero-state indicators (e.g. green '0' incidents without positive confirmation; poor icon contrast). | **Resolved**: Semantic indicators with positive reinforcement badges ('Zero Incident Verified') and high-contrast shield iconography (a-shield-halved). |
| **F-04** | Tenant Onboarding | **HIGH** | Rudimentary tenant table lacking search/filtering; basic modal missing ID guidance and consent links. | **Resolved**: Dual view toggle (Cards vs Table), instant search bar, status filter pills, and a 3-step Tenant Onboarding Wizard with live GUID regex validation and Entra ID consent URL generator. |
| **F-05** | Reporting Studio | **MEDIUM** | Truncated service names in checkbox selector causing ambiguous report generation scope. | **Resolved**: Replaced truncated labels with full unclipped service names, responsive flex layout, and clear category badges. |
| **F-06** | Visual Polish | **LOW** | Repetitive double-plus syntax (++) on primary action buttons across the portal. | **Resolved**: Standardized clean button iconography (<i class="fa-solid fa-plus me-1"></i>) across all views. |
| **F-07** | Reporting Studio | **MEDIUM** | Scheduled Dispatch form disconnected from active tenant selection and had low save action discoverability. | **Resolved**: Form dynamically synchronizes with active customer tenant (loadDispatchView()) and prominent card header action button added. |
| **F-08** | Executive Experience | **MEDIUM** | Single tenant view lacked C-Level Executive Briefing answering the 6 core customer questions. | **Resolved**: 6-Question C-Level Executive Briefing cards integrated into single-tenant cockpit. |

---

## 2. Visual Proof: Before & After Verifications

| Finding | Before (v2.5.14-PILOT) | After (v2.5.15-PILOT) |
| :--- | :--- | :--- |
| **F-01 / F-03 Dashboard** | docs/screenshots/02_dashboard_global.png | docs/screenshots/02_dashboard_global_after.png |
| **F-01 / F-08 Single Tenant Cockpit** | Global fleet aggregate shown unconditionally | docs/screenshots/03_dashboard_tenant002_cockpit_after.png |
| **F-04 Tenant Directory** | Simple card list without search or filter | docs/screenshots/04_tenants_table_and_filter_after.png |
| **F-04 Onboarding Wizard** | Single-step unvalidated form | docs/screenshots/05_tenant_onboarding_wizard_after.png |
| **F-05 Reporting Studio** | Truncated checkbox service labels | docs/screenshots/06_reporting_studio_untruncated_after.png |
| **F-07 Scheduled Dispatch** | Blank tenant fields on tab switch | docs/screenshots/07_scheduled_dispatch_populated_after.png |

---

## 3. Modified Files

1. **Portal/web/index.html**:
   - Single-tenant executive cockpit & 4-Pillar Service Value Attribution Model.
   - 6-Question C-Level Executive Briefing container.
   - Interactive Customer Decision Framework with triage actions.
   - Tenant directory dual view (cards & compact table), search bar, status filter pills.
   - 3-Step Tenant Onboarding Wizard with live regex GUID validation and Entra ID consent URL generator.
   - Untruncated service names in Reporting Studio.
   - Removed double-plus syntax from action buttons.
   - Scheduled Dispatch auto-sync with active tenant.
   - In-portal interactive report preview modal.
   - Bearer token fetch interceptor for authenticated API communication.
2. **ersion.json & Data/version.json**: Bumped to 2.5.15 / 2.5.15-PILOT.
3. **README.md**: Updated documentation to reflect v2.5.15-PILOT.
4. **ARCHITECTURE.md**: Version bump and changelog alignment.
5. **Docker/Dockerfile**: Environment and metadata updated to v2.5.15.
6. **PROJECT_HANDOFF.md**: Added Section 3.D detailing UX enhancements and verification.
7. **docs/screenshots/**: Verification screenshots captured via headless browser.

---

## 4. Remaining Backlog (Post-Pilot / Phase 3)
- Multi-region Azure Key Vault automated replication verification.
- Bi-directional webhook dispatch for third-party ITSM (ServiceNow/Jira) ticket synchronization.
- Dark / Light high-contrast theme toggle for accessibility standards compliance.
