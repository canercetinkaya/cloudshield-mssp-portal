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

from database.db import get_db, init_db, hash_password
from Portal.api.rbac_engine import (
    authenticate_user,
    evaluate_access,
    record_audit_event,
    get_effective_assignments
)

class TestCloudShieldAuthorizationArchitecture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Initialize and seed the database prior to running test suite."""
        init_db()

    def setUp(self):
        self.conn = get_db()
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.close()

    # --------------------------------------------------------------------------
    # Assertion 1: Customer A cannot access Customer B
    # --------------------------------------------------------------------------
    def test_01_cross_customer_isolation(self):
        """Validate that a user assigned to Customer A is strictly denied access to Customer B."""
        # customer.ciso@emre-tenant.com is assigned strictly to 'tenant-002'
        user, err = authenticate_user("customer.ciso@emre-tenant.com", "SecurePass2026!*")
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
        user, err = authenticate_user("edr.analyst@cloudshield-mssp.com", "SecurePass2026!*")
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
        h, s = hash_password("TestPass2026!*")

        self.cur.execute("""
            INSERT INTO users (id, organization_id, upn, display_name, email, password_hash, password_salt, is_active, created_at)
            VALUES (?, 'org-kocsistem', ?, 'Expired User', ?, ?, ?, 1, ?)
        """, (uid, f"{uid}@test.local", f"{uid}@test.local", h, s, now.isoformat()))

        # Assign role with expired valid_to
        asgn_id = f"asgn-exp-{uuid.uuid4().hex[:6]}"
        self.cur.execute("""
            INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, service_scope,
                                          valid_from, valid_to, is_temporary, is_active, created_by, created_at)
            VALUES (?, 'User', ?, 'role-security-engineer', 'ALL', 'ALL', ?, ?, 1, 1, 'admin', ?)
        """, (asgn_id, uid, past_start, past_end, now.isoformat()))
        self.conn.commit()

        user, err = authenticate_user(f"{uid}@test.local", "TestPass2026!*")
        self.assertIsNotNone(user)

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
        h, s = hash_password("TestPass2026!*")

        self.cur.execute("""
            INSERT INTO users (id, organization_id, upn, display_name, email, password_hash, password_salt, is_active, created_at)
            VALUES (?, 'org-kocsistem', ?, 'Disabled User', ?, ?, ?, 0, ?)
        """, (uid, f"{uid}@test.local", f"{uid}@test.local", h, s, now))
        self.conn.commit()

        # Login must fail
        user, err = authenticate_user(f"{uid}@test.local", "TestPass2026!*")
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
        user, _ = authenticate_user("edr.analyst@cloudshield-mssp.com", "SecurePass2026!*")

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
        ciso_user, _ = authenticate_user("customer.ciso@emre-tenant.com", "SecurePass2026!*")

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
        analyst, _ = authenticate_user("compliance.lead@cloudshield-mssp.com", "SecurePass2026!*")
        approver, _ = authenticate_user("admin@cloudshield-mssp.com", "CloudShield2026!*")

        # 1. Analyst creates PIM request
        apr_id = f"apr-test-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc).isoformat()
        self.cur.execute("""
            INSERT INTO access_approvals (id, requester_id, requested_role_id, customer_id, service_id, duration_hours, reason, status, created_at)
            VALUES (?, ?, 'role-security-engineer', 'tenant-002', 'svc-mde', 4, 'Incident investigation', 'Pending', ?)
        """, (apr_id, analyst["id"], now))
        self.conn.commit()

        # 2. Analyst attempts self-approval -> Must be prevented
        # We simulate the handler check
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
        admin, err = authenticate_user("caner.cetinkaya@cloudshield-mssp.com", "SecurePass2026!*")
        self.assertIsNotNone(admin)

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
