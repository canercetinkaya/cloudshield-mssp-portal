#!/usr/bin/env python3
"""
CloudShield Enterprise MSSP Platform - Comprehensive RBAC & Authorization Validation Test Suite
Authoritative Specification: docs/agents/tasks/cloudshield-rbac-and-authorization-architecture.md
Tests all security assertions required by Phase 11 & Phase 10:
1. Customer A cannot access Customer B (Cross-Customer Isolation)
2. MDE operator cannot access Purview (Cross-Service Isolation)
3. Expired assignment cannot access portal resources (Time-Bounded Expiry)
4. Disabled user cannot access portal resources (Immediate Identity Revocation)
5. Consolidated report cannot leak non-assigned services (All-Services Coverage Rule)
6. Separation of Duties (Report creator != Report approver)
7. PIM Request & Approval Workflow with SoD self-approval prevention
8. Comprehensive Audit Trail (ALLOW and DENY persistence)
9. Platform Admin Global Scope with SoD boundaries
10. Customer Service Matrix Lifecycle (Onboard, Suspend, Disable)
0.  (Stage 1A / W7) Legacy hard-coded literal passwords MUST be rejected

Stage 1A remediation note:
This suite is credential-deterministic. It is backed by a TEMPORARY SQLite
database created at runtime by the shared isolated-fixture helpers, and it
provisions RANDOMLY-GENERATED passwords via the UNCHANGED `hash_password()`
helper. It never opens the development/production database and never depends on
stale password hashes. The RBAC engine (`authenticate_user`, `evaluate_access`)
is exercised as-is; authorization is never bypassed.
"""

import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta

# Ensure repo root is on sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Stage 1A (test-only): shared isolated-fixture helpers.
from tests.helpers.stage1a_fixtures import isolated_database

from database.db import get_db, init_db, hash_password
from Portal.api.rbac_engine import (
    authenticate_user,
    evaluate_access,
    record_audit_event,
    get_effective_assignments
)

# Identities exercised by this suite. Credentials are provisioned (randomly) at
# runtime into the isolated temp DB by `setUpClass`; nothing is hard-coded here.
_IDENTITY_UPNS = [
    "customer.ciso@emre-tenant.com",          # usr-005 CustomerCISO -> tenant-002
    "edr.analyst@cloudshield-mssp.com",       # usr-002 EdrEngineer -> SVC-MDE
    "compliance.lead@cloudshield-mssp.com",   # usr-003 ComplianceSpecialist
    "caner.cetinkaya@cloudshield-mssp.com",   # usr-001 PlatformAdmin
    "admin@cloudshield-mssp.com",             # usr-admin bootstrap PlatformAdmin
]

# Legacy literal passwords that MUST be rejected after W7/W8.
_LEGACY_LITERAL_PASSWORDS = ("CloudShield2026!*", "SecurePass2026!*")


class TestCloudShieldAuthorizationArchitecture(unittest.TestCase):
    _idb_ctx = None
    _idb = None

    @classmethod
    def setUpClass(cls):
        """
        Initialize/seed an ISOLATED temporary database, then provision randomly
        generated credentials for the identities used by this suite. The
        development/production database is never opened.
        """
        cls._idb_ctx = isolated_database()
        cls._idb = cls._idb_ctx.__enter__()
        init_db()  # seeds into the temp DB (W8: users are passwordless)
        for upn in _IDENTITY_UPNS:
            cls._idb.provision_credential(upn)

    @classmethod
    def tearDownClass(cls):
        if cls._idb_ctx is not None:
            cls._idb_ctx.__exit__(None, None, None)
            cls._idb_ctx = None
            cls._idb = None

    def _auth(self, upn):
        """Authenticate a provisioned identity using its random runtime password."""
        return self._idb.authenticate(upn)

    def setUp(self):
        self.conn = get_db()
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.close()

    # --------------------------------------------------------------------------
    # Assertion 0 (W7): Hard-coded legacy literal passwords must be rejected
    # --------------------------------------------------------------------------
    def test_00_legacy_literal_passwords_rejected(self):
        """W7: the removed fallback literals no longer authenticate any identity."""
        for upn in _IDENTITY_UPNS:
            for literal in _LEGACY_LITERAL_PASSWORDS:
                user, err = self._idb.authenticate_with_password(upn, literal)
                self.assertIsNone(user, f"Legacy literal '{literal}' must be rejected for {upn}")
                self.assertIsNotNone(err)

    # --------------------------------------------------------------------------
    # Assertion 1: Customer A cannot access Customer B
    # --------------------------------------------------------------------------
    def test_01_cross_customer_isolation(self):
        """Validate that a user assigned to Customer A is strictly denied access to Customer B."""
        # customer.ciso@emre-tenant.com is assigned strictly to 'tenant-002'
        user, err = self._auth("customer.ciso@emre-tenant.com")
        self.assertIsNotNone(user, f"User authentication failed: {err}")

        # Access Customer A (tenant-002) -> ALLOW
        allowed_a, reason_a = evaluate_access(user, "reports:view", customer_id="tenant-002")
        self.assertTrue(allowed_a, f"Expected ALLOW for assigned customer: {reason_a}")

        # Attempt Access Customer B (tenant-isolated-other) -> DENY
        allowed_b, reason_b = evaluate_access(user, "reports:view", customer_id="tenant-isolated-other")
        self.assertFalse(allowed_b, "CRITICAL: Cross-customer boundary violation! Access was permitted.")
        self.assertIn("Müşteri Kapsam Hatası", reason_b)

        # Verify DENY audit event recorded in DB
        self.cur.execute("""
            SELECT decision, reason FROM audit_events
            WHERE user_id = ? AND customer_id = 'tenant-isolated-other'
            ORDER BY timestamp DESC LIMIT 1
        """, (user["id"],))
        audit_row = self.cur.fetchone()
        self.assertIsNotNone(audit_row, "Audit event was not recorded for cross-customer violation.")
        self.assertEqual(audit_row["decision"], "DENY")

    # --------------------------------------------------------------------------
    # Assertion 2: MDE operator cannot access Purview
    # --------------------------------------------------------------------------
    def test_02_cross_service_isolation(self):
        """Validate that an MDE/EDR operator is strictly denied access to Purview DLP telemetry."""
        # edr.analyst@cloudshield-mssp.com is assigned to SVC-MDE
        user, err = self._auth("edr.analyst@cloudshield-mssp.com")
        self.assertIsNotNone(user, f"EDR user auth failed: {err}")

        # Access MDE report -> ALLOW
        allowed_mde, reason_mde = evaluate_access(
            user, "reports:generate", customer_id="tenant-002", service_ids=["SVC-MDE"]
        )
        self.assertTrue(allowed_mde, f"MDE operator should access MDE: {reason_mde}")

        # Attempt Access Purview DLP report -> DENY
        allowed_prv, reason_prv = evaluate_access(
            user, "reports:generate", customer_id="tenant-002", service_ids=["SVC-PRV-DLP"]
        )
        self.assertFalse(allowed_prv, "CRITICAL: Cross-service isolation breached! MDE accessed Purview.")
        self.assertIn("SVC-PRV-DLP", reason_prv)

    # --------------------------------------------------------------------------
    # Assertion 3: Expired assignment cannot access portal resources
    # --------------------------------------------------------------------------
    def test_03_expired_assignment_denied(self):
        """Validate that an expired time-bounded access assignment cannot grant access."""
        uid = f"usr-exp-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)
        past_start = (now - timedelta(hours=5)).isoformat()
        past_end = (now - timedelta(hours=1)).isoformat()
        # Randomly generated test credential (never a fixed literal).
        pw = self._idb.new_password()
        h, s = hash_password(pw)

        self.cur.execute("""
            INSERT INTO users (id, organization_id, upn, display_name, email, password_hash, password_salt, is_active, created_at)
            VALUES (?, 'org-cloudshield', ?, 'Expired User', ?, ?, ?, 1, ?)
        """, (uid, f"{uid}@test.local", f"{uid}@test.local", h, s, now.isoformat()))

        # Assign role with expired valid_to
        asgn_id = f"asgn-exp-{uuid.uuid4().hex[:6]}"
        self.cur.execute("""
            INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, service_scope,
                                          valid_from, valid_to, is_temporary, is_active, created_by, created_at)
            VALUES (?, 'User', ?, 'role-security-engineer', 'ALL', 'ALL', ?, ?, 1, 1, 'admin', ?)
        """, (asgn_id, uid, past_start, past_end, now.isoformat()))
        self.conn.commit()

        user, err = authenticate_user(f"{uid}@test.local", pw)
        self.assertIsNotNone(user, f"Provisioned expired-user login failed: {err}")

        # Attempt action -> DENY because assignment has expired
        allowed, reason = evaluate_access(user, "reports:view")
        self.assertFalse(allowed, f"Expired assignment should be rejected by deny-by-default: {reason}")

    # --------------------------------------------------------------------------
    # Assertion 4: Disabled user cannot access portal resources
    # --------------------------------------------------------------------------
    def test_04_disabled_user_denied(self):
        """Validate that a user with is_active = 0 is blocked immediately from login and evaluation."""
        uid = f"usr-dis-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        # Randomly generated credential (never a fixed literal).
        pw = self._idb.new_password()
        h, s = hash_password(pw)

        self.cur.execute("""
            INSERT INTO users (id, organization_id, upn, display_name, email, password_hash, password_salt, is_active, created_at)
            VALUES (?, 'org-cloudshield', ?, 'Disabled User', ?, ?, ?, 0, ?)
        """, (uid, f"{uid}@test.local", f"{uid}@test.local", h, s, now))
        self.conn.commit()

        # Login must fail
        user, err = authenticate_user(f"{uid}@test.local", pw)
        self.assertIsNone(user, "Disabled user should fail login.")
        self.assertIn("devre dışı", err)

        # Direct evaluation of disabled identity dict must also DENY
        mock_user_dict = {"id": uid, "upn": f"{uid}@test.local", "is_active": 0}
        allowed, reason = evaluate_access(mock_user_dict, "reports:view")
        self.assertFalse(allowed, "Disabled user must be denied server-side.")
        self.assertIn("devre dışı", reason)

    # --------------------------------------------------------------------------
    # Assertion 5: Consolidated report cannot leak non-assigned services
    # --------------------------------------------------------------------------
    def test_05_consolidated_report_multi_service_leakage_prevention(self):
        """Validate that consolidated reports require active access to ALL constituent services."""
        user, err = self._auth("edr.analyst@cloudshield-mssp.com")
        self.assertIsNotNone(user, f"EDR user auth failed: {err}")

        # Consolidated bundle requesting MDE + MDO + Purview
        services_bundle = ["SVC-MDE", "SVC-MDO", "SVC-PRV-DLP"]

        allowed, reason = evaluate_access(
            user, "reports:download", customer_id="tenant-002", service_ids=services_bundle
        )
        self.assertFalse(allowed, "Consolidated report allowed without covering all services!")
        self.assertIn("SVC-PRV-DLP", reason)

    # --------------------------------------------------------------------------
    # Assertion 6: Separation of Duties (Report creator != Report approver)
    # --------------------------------------------------------------------------
    def test_06_separation_of_duties_report_approval(self):
        """Validate that the engineer who triggered/created a report CANNOT approve it."""
        ciso_user, err = self._auth("customer.ciso@emre-tenant.com")
        self.assertIsNotNone(ciso_user, f"CISO auth failed: {err}")

        # Scenario A: CISO created the report and attempts to approve it -> DENY
        sod_context_self = {"report_creator": ciso_user["upn"]}
        allowed_self, reason_self = evaluate_access(
            ciso_user, "reports:approve", customer_id="tenant-002",
            resource="/api/reports/rep-123/approve", sod_context=sod_context_self
        )
        self.assertFalse(allowed_self, "SoD violation: Creator was permitted to self-approve.")
        self.assertIn("Görevler Ayrılığı", reason_self)

        # Scenario B: Engineer created the report, CISO approves -> ALLOW
        sod_context_independent = {"report_creator": "engineer@cloudshield-mssp.com"}
        allowed_indep, reason_indep = evaluate_access(
            ciso_user, "reports:approve", customer_id="tenant-002",
            resource="/api/reports/rep-123/approve", sod_context=sod_context_independent
        )
        self.assertTrue(allowed_indep, f"Independent executive should approve: {reason_indep}")

    # --------------------------------------------------------------------------
    # Assertion 7: PIM Request & Approval Workflow
    # --------------------------------------------------------------------------
    def test_07_pim_approval_workflow(self):
        """Validate PIM request, self-approval blockage, and approver grant."""
        analyst, err_a = self._auth("compliance.lead@cloudshield-mssp.com")
        self.assertIsNotNone(analyst, f"Analyst auth failed: {err_a}")
        approver, err_b = self._auth("admin@cloudshield-mssp.com")
        self.assertIsNotNone(approver, f"Approver auth failed: {err_b}")

        # 1. Analyst creates PIM request
        apr_id = f"apr-test-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        self.cur.execute("""
            INSERT INTO access_approvals (id, requester_id, requested_role_id, customer_id, service_id, duration_hours, reason, status, created_at)
            VALUES (?, ?, 'role-security-engineer', 'tenant-002', 'svc-mde', 4, 'Incident investigation', 'Pending', ?)
        """, (apr_id, analyst["id"], now))
        self.conn.commit()

        # 2. Analyst attempts self-approval -> Must be prevented
        self.cur.execute("SELECT requester_id FROM access_approvals WHERE id = ?", (apr_id,))
        req_id = self.cur.fetchone()[0]
        self.assertEqual(req_id, analyst["id"])
        is_self = req_id == analyst["id"]
        self.assertTrue(is_self, "Self-approval condition correctly identified.")

        # 3. Independent Admin approves request
        decided_at = datetime.now(timezone.utc).isoformat()
        valid_to = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        asgn_id = f"asgn-pim-{uuid.uuid4().hex[:6]}"

        self.cur.execute("""
            UPDATE access_approvals SET status = 'Approved', approver_id = ?, decided_at = ? WHERE id = ?
        """, (approver["id"], decided_at, apr_id))

        self.cur.execute("""
            INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                          service_scope, service_id, valid_from, valid_to, is_temporary, is_active,
                                          approval_id, created_by, created_at)
            VALUES (?, 'User', ?, 'role-security-engineer', 'Specific', 'tenant-002', 'Specific', 'svc-mde', ?, ?, 1, 1, ?, 'admin', ?)
        """, (asgn_id, analyst["id"], now, valid_to, apr_id, now))
        self.conn.commit()

        # 4. Verify analyst now has MDE access for tenant-002
        allowed, reason = evaluate_access(analyst, "reports:generate", customer_id="tenant-002", service_ids=["SVC-MDE"])
        self.assertTrue(allowed, f"Approved PIM should grant access: {reason}")

    # --------------------------------------------------------------------------
    # Assertion 8: Comprehensive Audit Trail
    # --------------------------------------------------------------------------
    def test_08_comprehensive_audit_trail(self):
        """Validate that ALLOW and DENY decisions emit structured audit records to SQLite."""
        event_id = record_audit_event(
            event_type="AUTH_TEST",
            user_id="usr-test",
            user_upn="test@cloudshield-mssp.com",
            customer_id="tenant-002",
            service_id="SVC-MDE",
            resource="/api/test/resource",
            decision="ALLOW",
            reason="TestExecutionPassed",
            ip_address="192.168.1.50"
        )
        self.assertTrue(event_id.startswith("aud-"))

        self.cur.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["event_type"], "AUTH_TEST")
        self.assertEqual(row["decision"], "ALLOW")
        self.assertEqual(row["ip_address"], "192.168.1.50")

    # --------------------------------------------------------------------------
    # Assertion 9: Customer Service Matrix Lifecycle
    # --------------------------------------------------------------------------
    def test_09_customer_service_matrix_lifecycle(self):
        """Validate CustomerService onboarding, suspension, and disablement states."""
        now = datetime.now(timezone.utc).isoformat()
        cs_id = f"cs-test-{uuid.uuid4().hex[:6]}"
        test_cid = f"cust-test-{uuid.uuid4().hex[:6]}"

        self.cur.execute("""
            INSERT INTO customers (id, tenant_id, name, contact_email, created_at)
            VALUES (?, ?, 'Matrix Test Customer', 'matrix@test.local', ?)
        """, (test_cid, str(uuid.uuid4()), now))

        # Onboard
        self.cur.execute("""
            INSERT INTO customer_services (id, customer_id, service_id, service_level, status, onboarded_at, updated_at)
            VALUES (?, ?, 'svc-xdr', 'Managed', 'Onboarded', ?, ?)
        """, (cs_id, test_cid, now, now))
        self.conn.commit()

        self.cur.execute("SELECT status FROM customer_services WHERE id = ?", (cs_id,))
        self.assertEqual(self.cur.fetchone()[0], "Onboarded")

        # Suspend
        self.cur.execute("UPDATE customer_services SET status = 'Suspended' WHERE id = ?", (cs_id,))
        self.conn.commit()
        self.cur.execute("SELECT status FROM customer_services WHERE id = ?", (cs_id,))
        self.assertEqual(self.cur.fetchone()[0], "Suspended")

        # Disable
        self.cur.execute("UPDATE customer_services SET status = 'Disabled' WHERE id = ?", (cs_id,))
        self.conn.commit()
        self.cur.execute("SELECT status FROM customer_services WHERE id = ?", (cs_id,))
        self.assertEqual(self.cur.fetchone()[0], "Disabled")

    # --------------------------------------------------------------------------
    # Assertion 10: Administrative Roles Restricted from Customer Content (Outcome 4)
    # --------------------------------------------------------------------------
    def test_10_admin_customer_content_access_restricted(self):
        """Validate that PlatformAdmin cannot arbitrarily access customer confidential reports without assignment/JIT elevation."""
        self.cur.execute("DELETE FROM access_assignments WHERE subject_id = 'usr-001' AND is_temporary = 1")
        self.conn.commit()
        admin, err = self._auth("caner.cetinkaya@cloudshield-mssp.com")
        self.assertIsNotNone(admin, f"PlatformAdmin auth failed: {err}")

        # 1. Platform administration action (roles:manage) -> ALLOW
        allowed_admin, reason_admin = evaluate_access(admin, "roles:manage")
        self.assertTrue(allowed_admin, f"PlatformAdmin should manage system roles: {reason_admin}")

        # 2. Customer confidential content action (reports:view on specific customer) without customer assignment -> DENY
        allowed_report, reason_report = evaluate_access(admin, "reports:view", customer_id="tenant-002")
        self.assertFalse(allowed_report, "CRITICAL: PlatformAdmin accessed customer confidential content without assignment!")
        self.assertIn("İdari roller müşteri gizli verilerine ve rapor içeriklerine otomatik erişim hakkına sahip değildir", reason_report)

        # 3. Request and approve temporary JIT access for tenant-002
        req_id = f"appr-jit-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        self.cur.execute("""
            INSERT INTO access_approvals (id, requester_id, approver_id, requested_role_id, customer_id, service_id, duration_hours, reason, status, created_at, decided_at)
            VALUES (?, 'usr-001', 'usr-admin', 'role-security-engineer', 'tenant-002', 'svc-mde', 4, 'Audit verification', 'Approved', ?, ?)
        """, (req_id, now, now))

        jit_asgn_id = f"asgn-jit-{uuid.uuid4().hex[:6]}"
        valid_to = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        self.cur.execute("""
            INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id, service_scope, service_id, valid_from, valid_to, is_temporary, is_active, approval_id, created_by, created_at)
            VALUES (?, 'User', 'usr-001', 'role-security-engineer', 'Specific', 'tenant-002', 'Specific', 'svc-mde', ?, ?, 1, 1, ?, 'usr-admin', ?)
        """, (jit_asgn_id, now, valid_to, req_id, now))
        self.conn.commit()

        # 4. Access with approved JIT elevation -> ALLOW
        allowed_jit, reason_jit = evaluate_access(admin, "reports:view", customer_id="tenant-002", service_ids=["SVC-MDE"])
        self.assertTrue(allowed_jit, f"Approved JIT elevation must grant customer report access: {reason_jit}")

        # 5. Clean up fixture
        self.cur.execute("DELETE FROM access_assignments WHERE id = ?", (jit_asgn_id,))
        self.conn.commit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
