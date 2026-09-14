#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Stage 1A Isolated Test Fixtures
===========================================================

TEST-ONLY helpers shared by the Stage 1A remediation test suites. They are not
imported by any production module.

Guarantees provided to tests:
  * Every test runs against a freshly-created TEMPORARY SQLite database; the
    development/production database (`Data/cloudshield_rbac.db`) is never
    opened or written.
  * Credentials are randomly generated at runtime, held only in memory, and
    written only into the temp database. No credential is ever persisted into
    the repository.
  * Temporary databases and spawned server processes are cleaned up on exit.
  * No production file, authentication path, or server-startup behavior is
    modified. The unmodified server/rbac code is exercised as-is.
  * Pilot local authentication is NEVER enabled (`CLOUDSHIELD_ALLOW_LOCAL_AUTH`
    is not set for the server subprocess).
  * `evaluate_access()` is always invoked (never bypassed); no PlatformAdmin
    session is fabricated through any production endpoint.

Public API:
    isolated_database()      -> context manager yielding an IsolatedDatabase
    isolated_server()        -> context manager yielding an IsolatedServer
    rand_password()          -> cryptographically random password string
"""

import contextlib
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(_HERE, "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

_LAUNCHER = os.path.join(_HERE, "_isolated_server_launcher.py")


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------
def rand_password() -> str:
    """Return a cryptographically-random password (never persisted to repo)."""
    return "Qa!" + secrets.token_urlsafe(18)


# ---------------------------------------------------------------------------
# In-process isolated database
# ---------------------------------------------------------------------------
class IsolatedDatabase:
    """
    Owns a temporary SQLite database and rebinds `database.db.DB_PATH` to it
    for the duration of the context. Provides helpers to authenticate a
    provisioned identity and to evaluate access through the UNCHANGED engine.
    """

    def __init__(self, tmp_dir: str):
        self._tmp_dir = tmp_dir
        self.db_path = os.path.join(tmp_dir, "stage1a_isolated.db")
        self._prev_db_path = None
        self._credentials = {}  # upn(lower) -> generated password (in-memory only)

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        import database.db as dbmod
        self._prev_db_path = dbmod.DB_PATH
        dbmod.DB_PATH = self.db_path
        # Apply migrations + seed (W8 seeds users WITHOUT literal passwords).
        dbmod.init_db()
        return self

    def __exit__(self, exc_type, exc, tb):
        import database.db as dbmod
        if self._prev_db_path is not None:
            dbmod.DB_PATH = self._prev_db_path
        # Best-effort cleanup; also cleared by the surrounding temp dir removal.
        for p in (self.db_path,):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        self._credentials.clear()
        return False

    # -- provisioning ------------------------------------------------------
    def new_password(self) -> str:
        """Generate (but do not persist) a fresh random password string."""
        return rand_password()

    def password_for(self, upn: str):
        """Return the generated password previously provisioned for an identity, if any."""
        return self._credentials.get(upn.lower())

    def provision_credential(self, upn: str) -> str:
        """
        Set a freshly-generated random password for an already-seeded user
        (matched by UPN). Uses the UNCHANGED `hash_password()` helper and writes
        ONLY to the temp database. Returns the generated password.
        """
        from database.db import get_db, hash_password
        pw = rand_password()
        h, s = hash_password(pw)
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ?, password_salt = ?, is_active = 1 WHERE LOWER(upn) = ?",
            (h, s, upn.lower()),
        )
        conn.commit()
        conn.close()
        self._credentials[upn.lower()] = pw
        return pw

    def _conn(self):
        from database.db import get_db
        return get_db()

    # -- engine passthrough (never bypasses evaluate_access) ---------------
    def authenticate(self, upn: str):
        """Authenticate a provisioned identity through the real `authenticate_user()`."""
        from Portal.api.rbac_engine import authenticate_user
        pw = self._credentials.get(upn.lower())
        if pw is None:
            raise KeyError(f"No provisioned credential for {upn!r}; call provision_credential() first.")
        return authenticate_user(upn, pw)

    def authenticate_with_password(self, upn: str, password: str):
        """Authenticate with an arbitrary password (used to prove literals are rejected)."""
        from Portal.api.rbac_engine import authenticate_user
        return authenticate_user(upn, password)

    def evaluate(self, user, permission, **kwargs):
        """Delegate to the real `evaluate_access()` (never reimplemented/bypassed)."""
        from Portal.api.rbac_engine import evaluate_access
        return evaluate_access(user, permission, **kwargs)

    def get_user_id(self, upn: str) -> str:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE LOWER(upn) = ?", (upn.lower(),))
        row = cur.fetchone()
        conn.close()
        return row["id"] if row else ""


@contextlib.contextmanager
def isolated_database():
    """Yield an IsolatedDatabase backed by a temporary directory/database."""
    with tempfile.TemporaryDirectory(prefix="cs_stage1a_db_") as tmp_dir:
        with IsolatedDatabase(tmp_dir) as idb:
            yield idb


# ---------------------------------------------------------------------------
# Out-of-process isolated server
# ---------------------------------------------------------------------------
def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class IsolatedServer:
    """A subprocess running the UNMODIFIED server against a temp database."""

    def __init__(self, tmp_dir: str):
        self._tmp_dir = tmp_dir
        self.db_path = os.path.join(tmp_dir, "stage1a_server_isolated.db")
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._proc = None

    def __enter__(self):
        env = dict(os.environ)
        env["CS_TEST_DB_PATH"] = self.db_path
        # Intentionally DO NOT set CLOUDSHIELD_ALLOW_LOCAL_AUTH: Pilot local
        # authentication must remain disabled for the entire test run.
        env.pop("CLOUDSHIELD_ALLOW_LOCAL_AUTH", None)
        self._proc = subprocess.Popen(
            [sys.executable, _LAUNCHER, str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=ROOT_DIR,
        )
        deadline = time.time() + 40
        while time.time() < deadline:
            try:
                req = urllib.request.Request(f"{self.base_url}/api/health")
                with urllib.request.urlopen(req, timeout=1.5):
                    return self
            except Exception:
                if self._proc.poll() is not None:
                    break
                time.sleep(0.3)
        self.stop()
        raise RuntimeError("Isolated test server failed to become healthy.")

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass
        return False

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    # -- HTTP helpers ------------------------------------------------------
    def get(self, path, token=None, timeout=10):
        return self._request("GET", path, token=token, timeout=timeout)

    def post(self, path, body=None, token=None, timeout=30):
        return self._request("POST", path, body=body, token=token, timeout=timeout)

    def _request(self, method, path, body=None, token=None, timeout=10):
        import json
        url = f"{self.base_url}{path}"
        headers = {"User-Agent": "CloudShield-Stage1A-Tests/1.0"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw
                return resp.status, parsed, None
        except urllib.error.HTTPError as he:
            raw = he.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw
            return he.code, parsed, None
        except Exception as e:  # pragma: no cover - network hiccup
            return 0, None, str(e)


@contextlib.contextmanager
def isolated_server():
    """Yield an IsolatedServer (unmodified server, temp DB, local auth disabled)."""
    with tempfile.TemporaryDirectory(prefix="cs_stage1a_srv_") as tmp_dir:
        with IsolatedServer(tmp_dir) as srv:
            yield srv
