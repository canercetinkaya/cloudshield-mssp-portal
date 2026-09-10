# CloudShield MSSP Platform — Security Policy & Posture

**Current Release:** `v2.5.13-PILOT`  
**Classification:** Enterprise Security & Governance  

---

## 1. Zero Trust Architecture

CloudShield adheres strictly to Microsoft Zero Trust and Least Privilege principles:
- **Verify Explicitly:** Every request is authenticated and authorized against the active session and permission matrix.
- **Use Least-Privileged Access:** Telemetry ingestion modules utilize read-only Graph and MDE permissions (`SecurityIncident.Read.All`, `Device.Read.All`, `InformationProtectionPolicy.Read.All`).
- **Assume Breach:** Strict customer and service two-dimensional scoping prevents lateral movement and cross-tenant data leakage.

---

## 2. Server-Side Authorization Controls

Authorization is enforced exclusively at the server level via `Portal/api/rbac_engine.py`:
- **Deny-by-Default:** Any unauthenticated request or unmapped permission results in an immediate `401 Unauthorized` or `403 Forbidden`.
- **Customer Isolation:** Users bound to Customer A cannot view or trigger reports for Customer B.
- **Service Isolation:** Security engineers bound to MDE cannot generate Purview DLP reports.
- **Separation of Duties (SoD):**
  - Report creators cannot approve their own reports.
  - PIM privilege escalation requesters cannot approve their own access grants.

---

## 3. Privacy-by-Design & Compliance

- **KVKK & GDPR Compliance:** Sensitive user data is pseudonymized (`a***.y***@domain.com`); file names are masked (`Mali_Rapor_***.xlsx`).
- **k-Anonymity Threshold ($k=5$):** Groups with fewer than 5 impacted identities are aggregated to eliminate individual surveillance risks.
- **Qualified Technical Integrity:** Rapor disclaimers strictly state that cryptographic SHA-256 hashes verify technical file integrity without asserting legal non-repudiation.

---

## 4. Reporting a Security Vulnerability

If you discover a security vulnerability in CloudShield, please report it privately:
- **Security Contact:** `security@cloudshield-mssp.com`
- **Response SLA:** Initial acknowledgment within 24 hours; remediation timeline within 7 business days.
- **Zero Public Disclosure:** Do not open public GitHub issues for potential security vulnerabilities or credential disclosures.
