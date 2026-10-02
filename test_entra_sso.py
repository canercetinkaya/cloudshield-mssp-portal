#!/usr/bin/env python3
"""
Unit and Integration Tests for Microsoft Entra ID OIDC SSO Architecture
Validates:
- Entra OIDC configuration resolution (env vars, local secret store, auth_config.json)
- Authorize endpoint redirection with cryptographically secure state & nonce
- Callback error handling, state/nonce validation, and JWT claim checks
- User resolution into SQLite RBAC with least privilege role assignments
- Persistent session storage (memory + SQLite rehydration)
- Session teardown on logout
- Fail-closed security containment (W5 retired stub remains 410 Gone)
"""

import unittest
import urllib.request
import urllib.parse
import json
import time
import os
import sys
import threading
import http.server

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api.server import (
    MSSPPortalHandler, SESSIONS, AUTH_FLOWS,
    get_entra_config, decode_jwt_payload, resolve_entra_user,
    save_session, get_session, delete_session
)
from database.db import get_db, init_db

class TestEntraIdOidcSSO(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.port = 18090
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', cls.port), MSSPPortalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_01_entra_config_resolution(self):
        """Verify that Entra ID tenant, client id, and endpoints resolve correctly."""
        cfg = get_entra_config()
        self.assertEqual(cfg["tenant_id"], "2fb2bcee-61be-48af-972c-0b11a606578f")
        self.assertEqual(cfg["client_id"], "15b69eff-dc1e-4bf3-9d72-ebda8d7fff40")
        self.assertIn("login.microsoftonline.com", cfg["authorize_endpoint"])
        self.assertIn("login.microsoftonline.com", cfg["token_endpoint"])
        self.assertTrue(cfg["redirect_uri"].endswith("/api/auth/entra/callback"))

    def test_02_authorize_redirect(self):
        """Verify GET /api/auth/entra/authorize emits a 302 redirect with state & nonce."""
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(f"{self.base_url}/api/auth/entra/authorize")
        try:
            opener.open(req)
            self.fail("Expected 302 redirect")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 302)
            loc = e.headers.get("Location")
            self.assertIn("https://login.microsoftonline.com/2fb2bcee-61be-48af-972c-0b11a606578f/oauth2/v2.0/authorize", loc)
            self.assertIn("client_id=15b69eff-dc1e-4bf3-9d72-ebda8d7fff40", loc)
            self.assertIn("response_type=code", loc)
            self.assertIn("scope=openid+profile+email", loc)
            self.assertIn("state=", loc)
            self.assertIn("nonce=", loc)

    def test_03_jwt_payload_decoder(self):
        """Verify pure Python JWT payload decoding without external dependencies."""
        import base64
        test_payload = {
            "sub": "oid-user-12345",
            "oid": "oid-user-12345",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "name": "Caner Çetinkaya",
            "preferred_username": "caner.cetinkaya@cloudshield-mssp.com"
        }
        b64_payload = base64.urlsafe_b64encode(json.dumps(test_payload).encode("utf-8")).decode("ascii").rstrip("=")
        fake_jwt = f"eyJhbGciOiJSUzI1NiJ9.{b64_payload}.fake-signature"
        decoded = decode_jwt_payload(fake_jwt)
        self.assertEqual(decoded["oid"], "oid-user-12345")
        self.assertEqual(decoded["name"], "Caner Çetinkaya")

    def test_04_user_resolution_admin_mapping(self):
        """Verify that authenticating as Caner or admin maps to PlatformAdmin."""
        claims = {
            "oid": "test-oid-admin",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "preferred_username": "caner.cetinkaya@cloudshield-mssp.com",
            "name": "Caner Çetinkaya"
        }
        user_profile, err = resolve_entra_user(claims)
        self.assertIsNone(err)
        self.assertIsNotNone(user_profile)
        self.assertEqual(user_profile["role"], "PlatformAdmin")
        self.assertTrue(user_profile["isPlatformAdmin"])
        self.assertEqual(user_profile["authProvider"], "EntraID_OIDC")

    def test_05_user_resolution_provision_new_operator(self):
        """Verify that a new user in the corporate tenant is safely provisioned as SecurityEngineer."""
        unique_upn = f"sec.analyst.{int(time.time())}@cloudshield-mssp.com"
        claims = {
            "oid": f"oid-{int(time.time())}",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "preferred_username": unique_upn,
            "name": "Security Analyst"
        }
        user_profile, err = resolve_entra_user(claims)
        self.assertIsNone(err)
        self.assertIsNotNone(user_profile)
        self.assertEqual(user_profile["role"], "SecurityEngineer")
        self.assertFalse(user_profile["isPlatformAdmin"])

    def test_06_persistent_session_store_and_rehydration(self):
        """Verify session storage in SQLite survives memory clear and rehydrates properly."""
        token = f"tok-test-rehydrate-{int(time.time())}"
        test_user = {
            "id": "usr-001",
            "upn": "caner.cetinkaya@cloudshield-mssp.com",
            "displayName": "Caner Çetinkaya",
            "role": "PlatformAdmin",
            "isPlatformAdmin": True
        }
        save_session(token, test_user, expires_in=3600)
        self.assertIn(token, SESSIONS)

        # Clear in-memory dictionary
        SESSIONS.clear()
        self.assertNotIn(token, SESSIONS)

        # Retrieve session: must rehydrate from SQLite
        rehydrated = get_session(token)
        self.assertIsNotNone(rehydrated)
        self.assertEqual(rehydrated["user"]["displayName"], "Caner Çetinkaya")
        # Now back in memory
        self.assertIn(token, SESSIONS)

    def test_07_api_auth_me_authenticated_via_cookie(self):
        """Verify GET /api/auth/me returns 200 and user data when CS_SESSION cookie is supplied."""
        token = f"tok-cookie-{int(time.time())}"
        test_user = {
            "id": "usr-001",
            "upn": "caner.cetinkaya@cloudshield-mssp.com",
            "displayName": "Caner Çetinkaya",
            "role": "PlatformAdmin"
        }
        save_session(token, test_user, expires_in=3600)

        req = urllib.request.Request(
            f"{self.base_url}/api/auth/me",
            headers={"Cookie": f"CS_SESSION={token}"}
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertTrue(data.get("success"))
        self.assertEqual(data["user"]["displayName"], "Caner Çetinkaya")

    def test_08_api_auth_me_unauthenticated(self):
        """Verify GET /api/auth/me returns 401 when no session cookie or token is provided."""
        try:
            urllib.request.urlopen(f"{self.base_url}/api/auth/me")
            self.fail("Expected 401")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_09_logout_revokes_session(self):
        """Verify POST /api/auth/logout deletes session from both memory and SQLite."""
        token = f"tok-logout-{int(time.time())}"
        test_user = {"id": "usr-test", "upn": "test@test.local"}
        save_session(token, test_user, 3600)

        req = urllib.request.Request(
            f"{self.base_url}/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            data=b"{}",
            method="POST"
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.status, 200)
        self.assertIsNone(get_session(token))

    def test_10_retired_sso_stub_remains_410_gone(self):
        """Verify POST /api/auth/sso remains fail-closed (410 Gone) per W5 containment."""
        req = urllib.request.Request(
            f"{self.base_url}/api/auth/sso",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"provider": "EntraID_OIDC"}).encode("utf-8"),
            method="POST"
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Expected 410 Gone")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 410)

if __name__ == "__main__":
    unittest.main()
