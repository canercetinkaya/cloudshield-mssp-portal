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

_CUR_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.dirname(_CUR_DIR) if os.path.basename(_CUR_DIR) == "tests" else _CUR_DIR
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api.server import (
    MSSPPortalHandler, SESSIONS, AUTH_FLOWS,
    get_entra_config, decode_jwt_payload, resolve_entra_user,
    save_session, get_session, delete_session,
    create_stateless_oauth_state, verify_stateless_oauth_state,
    create_session_token, verify_session_token, get_session_secret
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
            self.assertIn("sso_reload=true", loc)
            self.assertEqual(e.headers.get("Content-Length"), "0")

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
        """Verify that authenticating as Caner (corporate UPN or email) maps to PlatformAdmin."""
        claims_corp = {
            "oid": "test-oid-admin",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "preferred_username": "Caner@cnrctnky.onmicrosoft.com",
            "email": "Caner@cnrctnky.onmicrosoft.com",
            "name": "Caner Çetinkaya"
        }
        user_profile, err = resolve_entra_user(claims_corp)
        self.assertIsNone(err)
        self.assertIsNotNone(user_profile)
        self.assertEqual(user_profile["role"], "PlatformAdmin")
        self.assertTrue(user_profile["isPlatformAdmin"])
        self.assertEqual(user_profile["authProvider"], "EntraID_OIDC")

    def test_05_block_consumer_and_unauthorized_accounts(self):
        """Verify that personal consumer accounts (e.g. outlook.com) and foreign tenants are strictly blocked."""
        # 1. Block consumer email (e.g. canercetinkaya@outlook.com)
        claims_consumer = {
            "oid": "consumer-oid-999",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "preferred_username": "canercetinkaya@outlook.com",
            "email": "canercetinkaya@outlook.com",
            "name": "Caner Çetinkaya"
        }
        profile, err = resolve_entra_user(claims_consumer)
        self.assertIsNone(profile)
        self.assertIsNotNone(err)
        self.assertIn("Bireysel Hesap Girişi Engellendi", err)

        # 2. Block foreign tenant ID
        claims_foreign_tenant = {
            "oid": "corp-user-foreign",
            "tid": "9188040d-6c67-4c5b-b112-36a304b66dad",  # Consumer MSA tenant or foreign org
            "preferred_username": "user@foreign-company.com",
            "email": "user@foreign-company.com"
        }
        profile, err = resolve_entra_user(claims_foreign_tenant)
        self.assertIsNone(profile)
        self.assertIsNotNone(err)
        self.assertIn("Yetkisiz Kiracı Erişimi", err)

        # 3. Block unenrolled corporate user (Strict pre-enrollment)
        claims_unenrolled = {
            "oid": "corp-user-unenrolled",
            "tid": "2fb2bcee-61be-48af-972c-0b11a606578f",
            "preferred_username": "unknown.person@cnrctnky.onmicrosoft.com",
            "email": "unknown.person@cnrctnky.onmicrosoft.com"
        }
        profile, err = resolve_entra_user(claims_unenrolled)
        self.assertIsNone(profile)
        self.assertIsNotNone(err)
        self.assertIn("Yetkisiz Kullanıcı", err)

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
        self.assertEqual(data.get("token"), token)

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

    def test_11_sso_redirect_html_cookie_and_localstorage(self):
        """Verify _render_auth_redirect_html sets SameSite=Lax cookie and writes token/user to localStorage."""
        from io import BytesIO
        token = "tok-redirect-test-12345"
        test_user = {"id": "usr-001", "displayName": "Caner Çetinkaya"}

        class DummyHandler:
            def __init__(self):
                self.headers_sent = []
                self.status_code = None
                self.wfile = BytesIO()
            def send_response(self, code):
                self.status_code = code
            def send_header(self, k, v):
                self.headers_sent.append((k, v))
            def end_headers(self):
                pass

        dh = DummyHandler()
        MSSPPortalHandler._render_auth_redirect_html(dh, token=token, user=test_user)
        self.assertEqual(dh.status_code, 200)
        cookie_header = next((v for k, v in dh.headers_sent if k == "Set-Cookie"), "")
        self.assertIn("SameSite=Lax", cookie_header)
        self.assertIn(f"CS_SESSION={token}", cookie_header)

        html_output = dh.wfile.getvalue().decode("utf-8")
        self.assertIn(f"localStorage.setItem('cloudshield_auth_token', \"{token}\")", html_output)
        self.assertIn("localStorage.setItem('cloudshield_user'", html_output)
        self.assertIn("Caner Çetinkaya", html_output)

    def test_12_stateless_oauth_state_hmac(self):
        """Verify HMAC-signed stateless OAuth state encodes and decodes PKCE verifier with tamper protection."""
        nonce = "test-nonce-12345"
        cv = "test-pkce-verifier-string-with-sufficient-entropy-987654321"
        ru = "https://example.com/api/auth/entra/callback"

        # 1. State creation & valid decoding
        state = create_stateless_oauth_state(nonce, cv, ru)
        self.assertIn(".", state)
        payload, err = verify_stateless_oauth_state(state)
        self.assertIsNone(err)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["n"], nonce)
        self.assertEqual(payload["cv"], cv)
        self.assertEqual(payload["ru"], ru)

        # 2. Tampered state must fail verification
        tampered_state = state[:-3] + ("A" if state[-1] != "A" else "B")
        payload, err = verify_stateless_oauth_state(tampered_state)
        self.assertIsNone(payload)
        self.assertIn("İmza doğrulaması başarısız", err)

        # 3. Expired state (> 900s) must fail verification
        payload, err = verify_stateless_oauth_state(state, max_age_seconds=-1)
        self.assertIsNone(payload)
        self.assertIn("OAuth state süresi dolmuş", err)

    def test_13_auth_flows_table_has_code_verifier(self):
        """Verify SQLite auth_flows table contains the code_verifier column to prevent silent drop."""
        conn = get_db()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(auth_flows)")
        columns = [row[1] for row in cur.fetchall()]
        conn.close()
        self.assertIn("code_verifier", columns)
        self.assertIn("nonce", columns)
        self.assertIn("redirect_uri", columns)
        self.assertIn("created_at", columns)

    def test_14_self_contained_hmac_session_token(self):
        """Verify stateless HMAC-SHA256 session tokens unpack zero-I/O user profile and resist tampering."""
        test_user = {
            "id": "usr-001",
            "upn": "caner@cnrctnky.onmicrosoft.com",
            "displayName": "Caner Çetinkaya",
            "role": "PlatformAdmin",
            "isPlatformAdmin": True
        }
        token = create_session_token(test_user, expires_in=3600)
        self.assertTrue(token.startswith("cst."))
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

        # 1. Verification of valid token
        payload, err = verify_session_token(token)
        self.assertIsNone(err)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["uid"], "usr-001")
        self.assertEqual(payload["u"]["displayName"], "Caner Çetinkaya")

        # 2. get_session must rehydrate without DB or memory dependency
        SESSIONS.clear()  # wipe in-memory cache to prove zero-I/O rehydration
        sess = get_session(token)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["user"]["id"], "usr-001")
        self.assertEqual(sess["user"]["role"], "PlatformAdmin")

        # 3. Tampered token signature must fail
        tampered_token = token[:-4] + ("WXYZ" if not token.endswith("WXYZ") else "ABCD")
        tampered_payload, tampered_err = verify_session_token(tampered_token)
        self.assertIsNone(tampered_payload)
        self.assertIn("İmza doğrulaması başarısız", tampered_err)

        # 4. Expired token must fail
        expired_token = create_session_token(test_user, expires_in=-10)
        exp_payload, exp_err = verify_session_token(expired_token)
        self.assertIsNone(exp_payload)
        self.assertIn("Oturum süresi dolmuş", exp_err)

    def test_15_deterministic_secret_and_redirect_query_token(self):
        """Verify get_session_secret is deterministic, and redirect HTML carries auth_token in query."""
        from io import BytesIO
        secret1 = get_session_secret()
        secret2 = get_session_secret()
        self.assertEqual(secret1, secret2)
        self.assertEqual(len(secret1), 64)  # SHA-256 hex digest

        token = create_session_token({"id": "usr-001", "displayName": "Caner Çetinkaya"})
        class DummyHandler:
            def __init__(self):
                self.headers_sent = []
                self.status_code = None
                self.wfile = BytesIO()
            def send_response(self, code):
                self.status_code = code
            def send_header(self, k, v):
                self.headers_sent.append((k, v))
            def end_headers(self):
                pass

        dh = DummyHandler()
        MSSPPortalHandler._render_auth_redirect_html(dh, token=token, user={"id": "usr-001"})
        html_output = dh.wfile.getvalue().decode("utf-8")
        self.assertIn(f"window.location.replace(\"/?auth_token=", html_output)
        self.assertIn("sessionStorage.setItem('cloudshield_auth_token'", html_output)

if __name__ == "__main__":
    unittest.main()

