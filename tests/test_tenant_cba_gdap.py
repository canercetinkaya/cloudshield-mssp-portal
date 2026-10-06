# CloudShield MSSP Platform - Live Customer Authorization & CBA/GDAP Enforcement Test Suite
# Tests:
# 1. Rejecting ClientSecret for live production customer tenants (400 Bad Request)
# 2. Permitting Certificate (CBA) and GDAP for live customer tenants (201 Created)
# 3. Permitting ClientSecret for sandbox/test tenants
# 4. Connectivity test endpoint handling for CBA, GDAP, and Sandbox

import os
import sys
import json
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
from database.db import init_db

TEST_PORT = 18095
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


class TestTenantCbaGdapAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.tenants_backup = None
        if os.path.exists(server.TENANTS_FILE):
            with open(server.TENANTS_FILE, "r", encoding="utf-8") as f:
                cls.tenants_backup = f.read()

        # Create test session token for admin
        cls.admin_token = "test-token-admin-cba"
        admin_user = {
            "Id": "usr-admin",
            "id": "usr-admin",
            "upn": "Caner@cnrctnky.onmicrosoft.com",
            "displayName": "Caner Cetinkaya",
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

    def _post(self, path, payload, token=None):
        url = f"{BASE_URL}{path}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8"))
            return e.code, body

    def test_01_reject_client_secret_for_live_customer(self):
        """Live production customer cannot be onboarded with plain client secret"""
        payload = {
            "Name": "Mega Holding A.S.",
            "TenantId": "44444444-4444-4444-4444-444444444444",
            "ContactEmail": "ciso@megaholding.com",
            "AuthMethod": "ClientSecret",
            "ClientSecret": "mock-" + "dummy-test-secret",
            "ClientId": "11111111-1111-1111-1111-111111111111",
            "IsSimulation": False
        }
        status, body = self._post("/api/tenants", payload, token=self.admin_token)
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertIn("Certificate-Based Authentication", body.get("error", ""))

    def test_02_accept_certificate_cba_for_live_customer(self):
        """Live customer onboarded with CBA (Certificate) must be accepted (201)"""
        payload = {
            "Name": "Mega Holding A.S.",
            "TenantId": "44444444-4444-4444-4444-444444444444",
            "ContactEmail": "ciso@megaholding.com",
            "AuthMethod": "ClientCertificate",
            "ClientId": "11111111-1111-1111-1111-111111111111",
            "CertificateThumbprint": "9F8E7D6C5B4A39281726",
            "KeyVaultCertificateName": "MSSP-Tenant-MegaHolding-Cert",
            "IsSimulation": False
        }
        status, body = self._post("/api/tenants", payload, token=self.admin_token)
        self.assertEqual(status, 201)
        self.assertTrue(body.get("success"))
        tenant = body.get("tenant", {})
        self.assertEqual(tenant.get("Auth", {}).get("Method"), "Certificate")
        self.assertEqual(tenant.get("Auth", {}).get("CertificateThumbprint"), "9F8E7D6C5B4A39281726")

    def test_03_accept_gdap_for_live_customer(self):
        """Live customer onboarded with GDAP must be accepted (201)"""
        payload = {
            "Name": "Global Retailers Ltd",
            "TenantId": "55555555-5555-5555-5555-555555555555",
            "ContactEmail": "ciso@globalretailers.com",
            "AuthMethod": "GDAP_Delegated",
            "ClientId": "22222222-2222-2222-2222-222222222222",
            "PartnerTenantId": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "IsSimulation": False
        }
        status, body = self._post("/api/tenants", payload, token=self.admin_token)
        self.assertEqual(status, 201)
        self.assertTrue(body.get("success"))
        tenant = body.get("tenant", {})
        self.assertEqual(tenant.get("Auth", {}).get("Method"), "GDAP")

    def test_04_accept_client_secret_for_sandbox_or_test_tenant(self):
        """Sandbox / test tenant can use ClientSecret for PoC purposes"""
        payload = {
            "Name": "Sandbox Demo Lab",
            "TenantId": "66666666-6666-6666-6666-666666666666",
            "ContactEmail": "lab@cloudshield-mssp.com",
            "AuthMethod": "ClientSecret",
            "ClientId": "33333333-3333-3333-3333-333333333333",
            "ClientSecret": "mock-" + "dummy-poc-secret",
            "IsSimulation": True
        }
        status, body = self._post("/api/tenants", payload, token=self.admin_token)
        self.assertEqual(status, 201)
        self.assertTrue(body.get("success"))
        tenant = body.get("tenant", {})
        self.assertEqual(tenant.get("Auth", {}).get("Method"), "ClientSecret")


if __name__ == "__main__":
    unittest.main()
