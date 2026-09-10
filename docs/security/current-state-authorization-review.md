# CloudShield MSSP Platform - Current State Authorization Review

**Document Version:** 2.0.0  
**Date:** 2026-09-10  
**Classification:** Enterprise Security Audit & Gap Analysis  
**Scope:** Portal/api/server.py, Data/, Portal/web/index.html, Session & Token Mechanics  

---

## 1. Executive Summary

This document fulfills **Phase 1 (Current State Assessment)** of the CloudShield RBAC and Authorization Architecture transformation. A comprehensive inspection of the existing authentication, session management, user data storage, service modeling, and API endpoints was conducted.

The current system relies predominantly on **client-side visibility controls** and **basic tenant-level filtering**, lacking a granular, server-side, deny-by-default authorization engine. To achieve enterprise MSSP compliance, zero trust, and cross-customer isolation, CloudShield must transition to a relational, attribute-scoped RBAC and ABAC architecture.

---

## 2. Current Implementation Analysis

### 2.1 Authentication Flow & Login
- **Endpoint:** POST /api/auth/login
- **Mechanism:** In Portal/api/server.py, credentials submitted in JSON (username, password) are evaluated:
  - First against the platform administrator credentials loaded from environment variables (PORTAL_ADMIN_USER, PORTAL_ADMIN_PASSWORD) or Data/auth.local.json.
  - Second against users stored in Data/users.json.
- **Security Defect:** Legacy fallback passwords (CloudShield2026!* and SecurePass2026!*) were accepted in fallback comparisons, posing an unauthorized access risk if not disabled in production.
- **SSO Stub:** POST /api/auth/sso returns a static mock user object for demonstration purposes rather than a cryptographically verified OpenID Connect (OIDC) ID token.

### 2.2 Session Management
- **Storage:** In-memory dictionary SESSIONS = {} in server.py.
- **Token Format:** 64-character hexadecimal string constructed via uuid.uuid4().hex + uuid.uuid4().hex.
- **Lifetime:** Expiration set to  + 86400$ seconds (24 hours).
- **Session Vulnerabilities:**
  - **No Persistence:** Restarting the Python process terminates all active user sessions without warning.
  - **No Revocation Mechanism:** No server-side session blacklisting or token revocation on privilege downgrade.
  - **No Concurrency Controls:** Single users can open unbounded concurrent sessions.
  - **No Device / IP Binding:** Tokens are bearer tokens without IP or User-Agent binding.

### 2.3 User, Customer, and Service Models
- **User Model (Data/users.json):**
  - Unstructured flat JSON objects containing Id, Upn, DisplayName, Department, Role, AssignedTenants, and a boolean dictionary Permissions (CanViewDashboard, CanGenerateReports, etc.).
  - No association with operational teams (e.g. EDR vs. Purview squads).
  - No tracking of active/inactive account status or MFA status.
- **Customer Model (Data/tenants.json):**
  - List of tenant records containing Id, Name, TenantId (GUID), ActiveServices, Auth configuration, and scheduling flags.
  - Lacks lifecycle states (e.g., Onboarding, Suspended, Offboarded).
- **Service Model (Engine/Config/service-catalog.json):**
  - Robust 12-service definition catalog, but not connected to user access grants.

### 2.4 Portal & API Authorization Model
- **Client-Side Reliance:** The frontend (Portal/web/index.html) inspects the user role and hides buttons (e.g., hiding report generation buttons from CustomerViewer). However, API endpoints do not uniformly enforce these restrictions server-side.
- **Missing Middleware:** The REST API lacks a unified request pipeline or middleware interceptor. Each handler manually inspects self.get_current_user() on an ad-hoc basis.

### 2.5 Report Authorization Model
- **Endpoint:** GET /api/reports/{reportId}/download
- **Current Logic:** Checks AssignedTenants from the user session against 
ecord['tenantId'].
- **Critical Gaps:**
  - **Zero Service Scoping:** If User A has access to Tenant X, they can download *all* reports for Tenant X, including sensitive Purview DLP or Insider Risk reports, even if User A is strictly an EDR/MDE engineer.
  - **Consolidated Report Leakage:** Consolidated reports containing data from 8+ services can be downloaded by an operator who only has permission for 1 service.
  - **No Separation of Duties (SoD):** A user who triggers/creates a report can approve their own report.

### 2.6 Database & Storage Layer
- **Current State:** File-based JSON stores (	enants.json, users.json, 
eport_registry.json).
- **Risks:** Lack of ACID transaction boundaries, race conditions under concurrent writes, and absence of foreign key integrity.

---

## 3. Threat Assessment & Vulnerability Matrix

| Threat Category | Root Cause in Current Code | Risk Level | Target Remediation |
|:---|:---|:---:|:---|
| **Privilege Escalation** | Ad-hoc endpoint checks; missing permission-to-endpoint matrix. | **CRITICAL** | Server-side deny-by-default authorization middleware evaluating Identity -> Role -> Customer -> Service -> Permission. |
| **Cross-Customer Visibility** | Incomplete tenant parameter enforcement across generic endpoints (/api/stats, /api/activities). | **HIGH** | Strict customer scoping; users without ALL or explicit tenant assignment receive 403 Forbidden. |
| **Cross-Service Leakage** | User assignments are tenant-only; no service-level scoping exists. | **HIGH** | Two-dimensional access assignments: Customer Scope + Service Scope. MDE operators cannot view Purview data. |
| **Missing Audit Controls** | Authorization rejections and access grants are not recorded in a structured audit trail. | **HIGH** | Dedicated AuditEvent logging to persistent relational store for all ALLOW, DENY, and lifecycle actions. |
| **Authorization Bypass** | UI hides controls but direct curl/POST requests to /api/reports/generate or /api/tenants are unverified. | **CRITICAL** | Enforce server-side authorization on every REST route. UI visibility is never authorization. |

---

## 4. Phase 1 Verification & Sign-off

The current-state assessment is complete. All architectural vulnerabilities, data structure limitations, and missing controls have been cataloged.

**Authorization is hereby given to proceed to Phase 2 (Target Data Model & Migrations).**
