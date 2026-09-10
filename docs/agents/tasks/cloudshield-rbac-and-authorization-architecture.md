# CloudShield RBAC & Authorization Architecture Specification

**Authoritative Specification File**  
**Classification:** Enterprise Security & Authorization Standard  

## Execution Mode
Implementation required.
Documentation alone is not sufficient.
Architecture diagrams alone are not sufficient.
Database schemas alone are not sufficient.
The task is complete only when the authorization model is implemented and observable from the CloudShield portal.

## Phase 1: Current State Assessment
Inspect the current implementation and document:
- authentication flow, login flow, session management, user model, customer model, service model, portal authorization model, report authorization model, admin authorization model, current database schema, API authorization middleware.
Identify:
- privilege escalation paths, cross-customer visibility risks, service scope gaps, missing audit controls, authorization bypass opportunities.
Generate: docs/security/current-state-authorization-review.md. Do not start implementation before the review is completed.

## Phase 2: Target Data Model
Implement:
- Organization, User, Team, TeamMembership, Customer, Service, CustomerService, Role, Permission, RolePermission, AccessAssignment, AccessCondition, AccessApproval, AuditEvent.
Create proper migrations. Preserve existing production data. No destructive migration is allowed.
Produce: database/migrations/* and docs/security/rbac-data-model.md.

## Phase 3: Authentication
Review current login implementation. Migrate toward Microsoft Entra ID (OpenID Connect, Authorization Code Flow, PKCE, MFA support, Conditional Access compatibility) while preserving backward compatibility.
Document: docs/security/authentication-architecture.md.

## Phase 4: Authorization Engine
Implement authorization middleware. Decision chain:
Identity -> Platform Role -> Customer Scope -> Service Scope -> Permission -> Conditions -> Approval State -> Decision.
All authorization decisions must be server-side. UI visibility is never authorization. Implement deny-by-default.

## Phase 5: Customer Service Matrix
Implement: Customer <-> CustomerService <-> Service.
Support: service onboarding, service offboarding, service suspension, service disablement, service-level assignment.
Portal must expose Customer Service Matrix through administration UI.

## Phase 6: Access Assignment Engine
Implement AccessAssignment supporting:
- Team assignments, User assignments, Customer scope, Service scope, Time-bounded access, Approval workflows.
All access changes must be auditable.

## Phase 7: Admin Portal
Update portal. New pages required:
1. Authorization Dashboard
2. Customers
3. Services
4. Customer Service Matrix
5. Teams
6. Role Catalog
7. Permission Catalog
8. Access Assignments
9. Access Reviews
10. Authorization Audit
11. Effective Access Simulator
Every page must be functional. No placeholder UI.

## Phase 8: Report Authorization
Implement authorization for: dashboard access, report generation, report review, report download, report approval.
A user may only access: assigned customer + assigned service.
Consolidated reports must be evaluated against all included services. Zero report visibility leakage.

## Phase 9: Audit Architecture
Implement audit events for: Allow, Deny, Role Assignment, Role Removal, Customer Assignment, Customer Removal, Service Assignment, Service Removal, Report Access, Report Download, Report Approval.
Every authorization decision must be logged.

## Phase 10: Security Controls
Implement Separation of Duties (Report creator != Report approver, Access administrator != Customer content reviewer), PIM-ready authorization, Sensitive-service rules, Session controls, Conditional-access compliance.

## Phase 11: Portal Validation
Create automated tests:
- Customer A cannot access Customer B
- MDE operator cannot access Purview
- Expired assignment cannot access portal resources
- Disabled user cannot access portal resources
- Consolidated report cannot leak non-assigned services

## Phase 12: Visible Portal Changes
Launch application locally, verify pages render, verify navigation, verify authorization controls, audit logging, assignment workflows, access review workflow. Provide screenshots and evidence.
