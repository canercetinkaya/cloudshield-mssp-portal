# CloudShield MSSP Platform - Smart Enterprise Tenant Onboarding Test Suite
# Tests:
# 1. POST /api/tenants/preflight-validate (Deny-by-default unauth, invalid GUID format check, live Entra check)
# 2. POST /api/tenants with full 4-step smart fields (Industry, SLA Tier, Logo base64, Credential Expiry, Customer User)
# 3. Database synchronization (customers, customer_services, tenant_credential_health, tenant_historical_metrics)
# 4. Customer portal user isolation provisioning (CustomerCISO user creation and access assignment)
# 5. GET /api/tenants/{id}/logo serving uploaded corporate logo

import os
import sys
import json
import base64
import unittest
import urllib.request
import urllib.error
import threading
import time

_CUR_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.dirname(_CUR_DIR) if os.path.basename(_CUR_DIR) == "tests" else _CUR_DIR
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api import server
from database.db import init_db, get_db, get_tenant_credential_health, get_tenant_trends

TEST_PORT = 18096
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


class TestSmartTenantOnboarding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.tenants_backup = None
        if os.path.exists(server.TENANTS_FILE):
            with open(server.TENANTS_FILE, "r", encoding="utf-8") as f:
                cls.tenants_backup = f.read()

        cls.admin_token = "test-token-smart-onboarding-admin"
        admin_user = {
            "Id": "usr-admin",
            "id": "usr-admin",
            "upn": "admin@cloudshield-mssp.com",
            "displayName": "Platform Administrator",
            "Role": "PlatformAdmin",
            "AssignedTenants": ["ALL"],
            "auth_provider": "EntraID"
        }
        server.save_session(cls.admin_token, admin_user, expires_in=7200)

        import http.server
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", TEST_PORT), server.MSSPPortalHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        if cls.tenants_backup is not None:
            with open(server.TENANTS_FILE, "w", encoding="utf-8") as f:
                f.write(cls.tenants_backup)
        test_logo = os.path.join(server.LOGOS_DIR, "tenant-enterprise-qa.png")
        if os.path.exists(test_logo):
            try:
                os.remove(test_logo)
            except Exception:
                pass

    def _post(self, path, payload, token=None):
        url = f"{BASE_URL}{path}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, body

    def _get(self, path, token=None):
        url = f"{BASE_URL}{path}"
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                return resp.status, resp.headers.get("Content-Type"), data
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type"), e.read()

    def test_01_preflight_unauth_denied(self):
        """Unauthenticated requests to preflight-validate must be rejected (401/403)"""
        status, body = self._post("/api/tenants/preflight-validate", {
            "tenantId": "c9c0ee10-6398-473c-9681-d2fffaa55531"
        })
        self.assertIn(status, (401, 403))

    def test_02_preflight_invalid_guid_format(self):
        """Preflight with malformed GUID must return 400 Bad Request with clear diagnostic"""
        status, body = self._post("/api/tenants/preflight-validate", {
            "tenantId": "not-a-valid-guid-123"
        }, token=self.admin_token)
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("status"), "InvalidGuidFormat")

    def test_03_preflight_live_entra_validation(self):
        """Preflight with valid GUID checks Microsoft Entra OpenID endpoint"""
        # Testing genuine tenant GUID c9c0ee10-6398-473c-9681-d2fffaa55531
        status, body = self._post("/api/tenants/preflight-validate", {
            "tenantId": "c9c0ee10-6398-473c-9681-d2fffaa55531",
            "clientId": "b715103d-ff46-4717-a9b5-cba6427cbe01",
            "authMethod": "Certificate",
            "certExpiryDate": "2027-06-30T00:00:00Z"
        }, token=self.admin_token)
        # Should succeed or return network error (in case of offline CI/CD)
        self.assertIn(status, (200, 502))
        if status == 200:
            self.assertTrue(body.get("success"))
            self.assertEqual(body.get("status"), "PreflightVerified")
            self.assertIn("c9c0ee10", body.get("issuer", ""))
            self.assertGreater(body.get("latencyMs", 0), 0)
            self.assertGreater(body.get("daysUntilExpiry", 0), 100)

    def test_04_smart_enterprise_onboarding_full_flow(self):
        """Full 4-step onboarding creates tenant in JSON, syncs SQLite, initializes trends, and provisions user"""
        # 1x1 transparent PNG pixel in base64
        tiny_png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

        payload = {
            "Id": "tenant-enterprise-qa",
            "Name": "KocSistem Enterprise Test Tenant",
            "TenantId": "99999999-8888-7777-6666-555555555555",
            "ContactEmail": "ciso@enterprise-test.com",
            "Industry": "Finans & Bankacılık",
            "ServiceSlaTier": "Gold",
            "AssignedTeam": "Core-MSSP",
            "AuthMethod": "Certificate",
            "ClientId": "88888888-7777-6666-5555-444444444444",
            "CertificateThumbprint": "ABCDEF1234567890",
            "CertExpiryDate": "2027-12-31T00:00:00Z",
            "ActiveServices": [
                "SVC-MDE", "SVC-MDO", "SVC-XDR", "SVC-PRV-DLP", "SVC-INTUNE"
            ],
            "ReportMode": "Consolidated",
            "ReportLanguage": "TR",
            "ScheduleFrequency": "Monthly",
            "DispatchDay": 1,
            "DispatchTime": "09:00",
            "RecipientEmails": ["ciso@enterprise-test.com", "soc-lead@enterprise-test.com"],
            "AttachPdf": True,
            "AttachHtml": True,
            "LogoData": tiny_png,
            "CreateCustomerUser": True,
            "CustomerUser": {
                "displayName": "Enterprise CISO Executive",
                "email": "ciso@enterprise-test.com",
                "role": "CustomerCISO"
            }
        }

        status, body = self._post("/api/tenants", payload, token=self.admin_token)
        self.assertEqual(status, 201)
        self.assertTrue(body.get("success"))
        created_tenant = body.get("tenant", {})
        self.assertEqual(created_tenant.get("Id"), "tenant-enterprise-qa")
        self.assertEqual(created_tenant.get("ServiceSlaTier"), "Gold")
        self.assertEqual(created_tenant.get("Industry"), "Finans & Bankacılık")
        self.assertEqual(len(created_tenant.get("ActiveServices")), 5)

        # 1. Verify SQLite customers table
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id = ?", ("tenant-enterprise-qa",))
        cust = cur.fetchone()
        self.assertIsNotNone(cust)
        self.assertEqual(cust["name"], "KocSistem Enterprise Test Tenant")
        self.assertEqual(cust["contact_email"], "ciso@enterprise-test.com")

        # 2. Verify SQLite customer_services table
        cur.execute("SELECT * FROM customer_services WHERE customer_id = ?", ("tenant-enterprise-qa",))
        svcs = cur.fetchall()
        self.assertEqual(len(svcs), 5)
        for s in svcs:
            self.assertEqual(s["service_level"], "Gold")
            self.assertEqual(s["status"], "Onboarded")

        # 3. Verify SQLite tenant_credential_health table
        cur.execute("SELECT * FROM tenant_credential_health WHERE tenant_id = ?", ("tenant-enterprise-qa",))
        cred = cur.fetchone()
        self.assertIsNotNone(cred)
        self.assertEqual(cred["auth_type"], "Certificate")
        self.assertGreater(cred["days_until_expiry"], 100)
        self.assertEqual(cred["health_status"], "Healthy")

        # 4. Verify SQLite tenant_historical_metrics baseline snapshot
        cur.execute("SELECT * FROM tenant_historical_metrics WHERE tenant_id = ?", ("tenant-enterprise-qa",))
        metrics = cur.fetchall()
        self.assertGreaterEqual(len(metrics), 1)

        # 5. Verify isolated Customer Portal User
        cur.execute("SELECT * FROM users WHERE email = ?", ("ciso@enterprise-test.com",))
        c_user = cur.fetchone()
        self.assertIsNotNone(c_user)
        self.assertEqual(c_user["display_name"], "Enterprise CISO Executive")

        cur.execute("SELECT * FROM access_assignments WHERE subject_id = ? AND customer_id = ?", (c_user["id"], "tenant-enterprise-qa"))
        asgn = cur.fetchone()
        self.assertIsNotNone(asgn)
        self.assertEqual(asgn["customer_scope"], "Specific")
        self.assertEqual(asgn["role_id"], "role-customer-ciso")

        conn.close()

        # 6. Verify logo serving endpoint
        l_status, l_type, l_data = self._get("/api/tenants/tenant-enterprise-qa/logo")
        self.assertEqual(l_status, 200)
        self.assertIn("image/png", l_type)
        self.assertGreater(len(l_data), 0)


if __name__ == "__main__":
    unittest.main()
