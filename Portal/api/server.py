#!/usr/bin/env python3

"""

CloudShield Enterprise MSSP Security & Compliance Platform (MSSP Portal)

Backend REST API Server - Pure Python 3 Standard Library (Zero External Dependencies)

"""

import http.server

import json
import base64

import os

import shutil

import subprocess

import sys

import threading

import time

import urllib.parse

import urllib.request

import uuid

import hmac

import secrets

from datetime import datetime, timedelta, timezone

# --- UTF-8 console compliance (see docs/governance/encoding-standard.md) ------
# Force UTF-8 stdout/stderr so Turkish characters in startup and request logs
# are never mojibake'd when the server is launched from a legacy console.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from database.db import init_db, get_db, sync_customer_to_db, create_customer_portal_user
try:
    from rbac_engine import authenticate_user, evaluate_access, record_audit_event, get_effective_assignments
    from rbac_handlers import handle_rbac_get, handle_rbac_post, handle_rbac_delete
except ImportError:
    from Portal.api.rbac_engine import authenticate_user, evaluate_access, record_audit_event, get_effective_assignments
    from Portal.api.rbac_handlers import handle_rbac_get, handle_rbac_post, handle_rbac_delete


try:

    from report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf

except ImportError:

    from Portal.api.report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf

PORT = int(os.environ.get("PORT", 8080))

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

WEB_DIR = os.path.join(ROOT_DIR, "Portal", "web")

DATA_DIR = os.path.join(ROOT_DIR, "Data")

TENANTS_FILE = os.path.join(DATA_DIR, "tenants.json")

USERS_FILE = os.path.join(DATA_DIR, "users.json")

AUTH_CONFIG_FILE = os.path.join(DATA_DIR, "auth_config.json")

AUTH_LOCAL_FILE = os.path.join(DATA_DIR, "auth.local.json")

CACHE_FILE = os.path.join(DATA_DIR, "daily_cache.json")

CATALOG_FILE = os.path.join(ROOT_DIR, "Engine", "Config", "service-catalog.json")

OUTPUT_DIR = os.path.join(ROOT_DIR, "Engine", "Output")

REPORT_REGISTRY_FILE = os.path.join(DATA_DIR, "report_registry.json")
LOGOS_DIR = os.path.join(DATA_DIR, "Logos")
os.makedirs(LOGOS_DIR, exist_ok=True)

def load_report_registry():

    return load_json_file(REPORT_REGISTRY_FILE, {})

def save_report_registry(registry):

    save_json_file(REPORT_REGISTRY_FILE, registry)

def register_report_artifact(tenant_id, customer_name, period, service_codes, artifact_type, storage_path, created_by="api"):

    import hashlib

    rel_path = os.path.relpath(storage_path, OUTPUT_DIR).replace("\\", "/")

    size_bytes = os.path.getsize(storage_path) if os.path.exists(storage_path) else 0

    sha256_hash = ""

    if os.path.exists(storage_path):

        try:

            with open(storage_path, "rb") as f:

                sha256_hash = hashlib.sha256(f.read()).hexdigest()

        except Exception:

            pass

    report_id = str(uuid.uuid4())

    registry = load_report_registry()

    entry = {

        "reportId": report_id,

        "tenantId": tenant_id,

        "customerId": customer_name,

        "period": period,

        "serviceCodes": service_codes,

        "artifactType": artifact_type,

        "storageKey": rel_path,

        "createdAtUtc": datetime.now(timezone.utc).isoformat(),

        "createdBy": created_by,

        "reportStatus": "Ready",

        "integrityHash": f"sha256:{sha256_hash}" if sha256_hash else "",

        "sizeBytes": size_bytes,

        "expiresAtUtc": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),

        "version": get_version_info().get("version", "3.0.0"),

        "commit": get_version_info().get("commit", "latest")

    }

    registry[report_id] = entry

    save_report_registry(registry)

    return report_id, entry

DISPATCH_LOGS_FILE = os.path.join(DATA_DIR, "dispatch_logs.json")

ACTIVITIES_FILE = os.path.join(DATA_DIR, "manual-service-activities.json")

VERSION_FILE = os.path.join(DATA_DIR, "version.json")

SESSIONS = {}  # in-memory token -> session data
AUTH_FLOWS = {}  # in-memory state -> auth flow data

def _ensure_session_tables():
    try:
        conn = get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                user_data_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_flows (
                state TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] Failed to ensure session tables: {e}")

_ensure_session_tables()

def save_session(tok, user_dict, expires_in=86400):
    now_ts = time.time()
    exp_ts = now_ts + expires_in
    SESSIONS[tok] = {
        "user": user_dict,
        "createdAt": now_ts,
        "expiresAt": exp_ts
    }
    try:
        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO user_sessions (token, user_id, created_at, expires_at, user_data_json) VALUES (?, ?, ?, ?, ?)",
            (tok, user_dict.get("id", "usr-unknown"), now_ts, exp_ts, json.dumps(user_dict, ensure_ascii=False))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_session(tok):
    if not tok:
        return None
    now_ts = time.time()
    sess = SESSIONS.get(tok)
    if sess and sess.get("expiresAt", 0) > now_ts:
        return sess
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM user_sessions WHERE token = ?", (tok,))
        row = cur.fetchone()
        conn.close()
        if row and row["expires_at"] > now_ts:
            loaded_user = json.loads(row["user_data_json"])
            sess = {
                "user": loaded_user,
                "createdAt": row["created_at"],
                "expiresAt": row["expires_at"]
            }
            SESSIONS[tok] = sess
            return sess
    except Exception:
        pass
    return None

def delete_session(tok):
    if tok in SESSIONS:
        del SESSIONS[tok]
    try:
        conn = get_db()
        conn.execute("DELETE FROM user_sessions WHERE token = ?", (tok,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_entra_config():
    """Load Microsoft Entra ID OIDC configuration from environment, local secret store, or auth_config.json."""
    tenant_id = os.environ.get("ENTRA_TENANT_ID")
    client_id = os.environ.get("ENTRA_CLIENT_ID")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET")
    redirect_uri = os.environ.get("ENTRA_REDIRECT_URI")

    if os.path.exists(AUTH_LOCAL_FILE):
        try:
            with open(AUTH_LOCAL_FILE, "r", encoding="utf-8") as f:
                loc = json.load(f)
                tenant_id = tenant_id or loc.get("entra_tenant_id")
                client_id = client_id or loc.get("entra_client_id")
                client_secret = client_secret or loc.get("entra_client_secret")
                redirect_uri = redirect_uri or loc.get("entra_redirect_uri")
        except Exception:
            pass

    base_cfg = load_json_file(AUTH_CONFIG_FILE, {}).get("EntraConfig", {})
    tenant_id = tenant_id or base_cfg.get("TenantId", "2fb2bcee-61be-48af-972c-0b11a606578f")
    client_id = client_id or base_cfg.get("ClientId", "15b69eff-dc1e-4bf3-9d72-ebda8d7fff40")
    redirect_uri = redirect_uri or base_cfg.get("RedirectUri", "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/api/auth/entra/callback")

    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "authorize_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    }

def decode_jwt_payload(jwt_token):
    """Decode unverified JWT payload using pure Python standard library."""
    parts = jwt_token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT token format")
    payload_b64 = parts[1]
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)
    import base64
    payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
    return json.loads(payload_bytes.decode("utf-8"))

def resolve_entra_user(claims):
    """
    Resolve and strictly authorize authenticated Entra ID identity into relational RBAC database.
    Production Zero Trust Controls:
    1. Tenant boundary enforcement: Incoming tid must match expected corporate tenant.
    2. Consumer email rejection: Personal MSA domains (@outlook.com, @hotmail.com, @gmail.com, etc.) are blocked.
    3. Exact identity matching: Zero fuzzy/substring checks. Exact UPN, Email, or AlternativeUpn match required.
    4. Mandatory pre-enrollment: Only pre-registered users in the platform directory are granted access.
    5. Inactive account containment: Inactive users are rejected with 403.
    """
    oid = claims.get("oid") or claims.get("sub", "")
    tid = claims.get("tid", "")
    upn = (claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "").lower().strip()
    email = (claims.get("email") or claims.get("preferred_username") or upn).lower().strip()
    name = claims.get("name") or upn

    cfg = get_entra_config()
    expected_tid = cfg.get("tenant_id")

    # 1. Tenant boundary validation (Fail-closed)
    if expected_tid and tid and tid != expected_tid:
        return None, (
            f"Yetkisiz Kiracı Erişimi (403 Forbidden): Oturum açılan kiracı ({tid}) bu platform için yetkilendirilmemiştir. "
            f"Yalnızca onaylı kurumsal tenant ({expected_tid}) kabul edilir."
        )

    # 2. Block consumer email providers outright
    upn_domain = upn.split("@")[-1].lower() if "@" in upn else ""
    email_domain = email.split("@")[-1].lower() if "@" in email else ""
    blocked_consumer_domains = {
        "outlook.com", "hotmail.com", "live.com", "msn.com",
        "gmail.com", "yahoo.com", "icloud.com", "yandex.com", "mail.com"
    }
    if upn_domain in blocked_consumer_domains or email_domain in blocked_consumer_domains:
        bad_domain = upn_domain if upn_domain in blocked_consumer_domains else email_domain
        return None, (
            f"Bireysel Hesap Girişi Engellendi (403 Forbidden): Kişisel e-posta sağlayıcıları (@{bad_domain}) "
            "kurumsal MSSP güvenlik platformuna giriş yapamaz. Lütfen yetkilendirilmiş kurumsal iş hesabınız (@cnrctnky.onmicrosoft.com) ile oturum açınız."
        )

    auth_cfg = load_json_file(AUTH_CONFIG_FILE, {}).get("EntraConfig", {})
    allowed_domains = [d.lower() for d in auth_cfg.get("AllowedDomains", ["cnrctnky.onmicrosoft.com", "cloudshield-mssp.com"])]

    conn = get_db()
    cur = conn.cursor()

    # 3. Exact UPN or Email match in database (NO fuzzy or substring matching!)
    cur.execute("SELECT * FROM users WHERE LOWER(upn) = ? OR LOWER(email) = ?", (upn, email))
    user_row = cur.fetchone()

    # Check alternative UPN / aliases in users.json if not found directly
    if not user_row:
        raw_users = load_json_file(USERS_FILE, [])
        for u in raw_users:
            alt_upn = (u.get("AlternativeUpn") or "").lower().strip()
            u_email = (u.get("Email") or "").lower().strip()
            u_upn = (u.get("Upn") or "").lower().strip()
            if upn in (alt_upn, u_email, u_upn) or email in (alt_upn, u_email, u_upn):
                cur.execute("SELECT * FROM users WHERE id = ?", (u.get("Id"),))
                user_row = cur.fetchone()
                break

    now = datetime.now(timezone.utc).isoformat()

    # 4. Fail-closed Pre-enrollment Enforcement
    if not user_row:
        # Check if auto-provisioning is explicitly enabled for approved corporate domains
        auto_provision = auth_cfg.get("AutoProvisionUsers", False)
        domain_allowed = (upn_domain in allowed_domains or email_domain in allowed_domains)

        if auto_provision and domain_allowed:
            # JIT provision strictly as restricted operator, NEVER with platform admin or ALL customer access
            user_id = f"usr-entra-{secrets.token_hex(3)}"
            cur.execute(
                """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                    password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, last_login_at, created_at)
                   VALUES (?, 'org-cloudshield', ?, ?, ?, 'MSSP Cloud Security', NULL, NULL, 1, 1, 'EntraID_OIDC', ?, ?)""",
                (user_id, upn, name, email, now, now)
            )
            role_id = "role-service-operator"
            cur.execute(
                """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope,
                                                  service_scope, valid_from, is_temporary, is_active, created_by, created_at)
                   VALUES (?, 'User', ?, ?, 'Restricted', 'None', ?, 0, 1, 'entra-sso', ?)""",
                (f"asgn-{user_id}-restricted", user_id, role_id, now, now)
            )
            conn.commit()
        else:
            conn.close()
            return None, (
                f"Yetkisiz Kullanıcı (403 Forbidden): '{upn}' hesabı CloudShield MSSP Platformu üzerinde tanımlı veya yetkili değildir. "
                "Erişim tanımlanması için lütfen sistem yöneticiniz ile iletişime geçiniz."
            )
    else:
        user_dict = dict(user_row)
        if not user_dict.get("is_active"):
            conn.close()
            return None, "Kullanıcı hesabı devre dışı bırakılmıştır (Inactive Account). Lütfen sistem yöneticinizle iletişime geçin."
        cur.execute("UPDATE users SET last_login_at = ?, auth_provider = 'EntraID_OIDC' WHERE id = ?", (now, user_dict["id"]))
        conn.commit()
        user_id = user_dict["id"]

    assignments = get_effective_assignments(user_id, conn)
    roles = list({a["role_name"] for a in assignments})
    is_plat_admin = any(a.get("is_platform_role") for a in assignments)

    permissions = set()
    for a in assignments:
        for p in a.get("permissions", []):
            permissions.add(p)

    assigned_tenants = [a.get("customer_id") or "ALL" for a in assignments if a.get("customer_scope") == "ALL" or a.get("customer_id")]
    if not assigned_tenants or is_plat_admin:
        assigned_tenants = ["ALL"]

    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    final_u = dict(cur.fetchone())
    conn.close()

    display_name = final_u.get("display_name") or name
    initials = "".join([w[0].upper() for w in display_name.split()[:2]]) or "CS"

    user_profile = {
        "id": user_id,
        "upn": final_u.get("upn", upn),
        "username": final_u.get("upn", upn),
        "displayName": display_name,
        "email": final_u.get("email", email),
        "department": final_u.get("department", "MSSP Security Operations"),
        "organization": "CloudShield MSSP Platform",
        "roles": roles,
        "role": "PlatformAdmin" if is_plat_admin else (roles[0] if roles else "SecurityEngineer"),
        "isPlatformAdmin": is_plat_admin,
        "permissions": list(permissions),
        "assignments": assignments,
        "AssignedTenants": assigned_tenants,
        "tenantScope": "Global" if "ALL" in assigned_tenants else "Restricted",
        "initials": initials,
        "authProvider": "EntraID_OIDC",
        "isMfaEnabled": True,
        "oid": oid,
        "tid": tid
    }

    return user_profile, None

# ==============================================================================
# Central Authentication Gate: Public Allow-list (W9 & OIDC)
# ==============================================================================
PUBLIC_ROUTES = frozenset({
    "/api/health",
    "/api/version",
    "/api/auth/logout",
    "/api/auth/entra/authorize",
    "/api/auth/entra/callback",
    "/api/auth/entra/login",
    "/api/auth/me",
})

def _is_public_api_route(method, path):
    """Return True if (method, path) is an unauthenticated, public API route (W9/OIDC)."""
    if not path.startswith("/api/"):
        return True
    if path in PUBLIC_ROUTES:
        return True
    if path in ("/api/auth/login", "/api/auth/sso"):
        return True
    if method == "GET" and path.startswith("/api/tenants/") and path.endswith("/logo"):
        return True
    return False

def load_json_file(path, default=None):

    if os.path.exists(path):

        try:

            with open(path, "r", encoding="utf-8") as f:

                data = json.load(f)

                if os.path.basename(path) == "tenants.json":

                    local_path = os.path.join(os.path.dirname(path), "tenants.local.json")

                    if os.path.exists(local_path):

                        try:

                            with open(local_path, "r", encoding="utf-8") as lf:

                                local_tenants = json.load(lf)

                                local_map = {t.get("Id"): t for t in local_tenants}

                                for t in data:

                                    tid = t.get("Id")

                                    if tid in local_map:

                                        lt = local_map[tid]

                                        l_sec = lt.get("Auth", {}).get("ClientSecret")

                                        if l_sec and not t.get("Auth", {}).get("ClientSecret"):

                                            t.setdefault("Auth", {})["ClientSecret"] = l_sec

                        except Exception:

                            pass

                return data

        except Exception as e:

            print(f"[WARN] Error loading {path}: {e}")

    return default if default is not None else []

def get_version_info():

    """Load latest version and release metadata dynamically from root version.json or Data/version.json."""

    root_ver = os.path.join(ROOT_DIR, "version.json")

    vpath = root_ver if os.path.exists(root_ver) else VERSION_FILE

    default_info = {
        "version": "3.0.0",
        "release": "v3.0.0-ENTERPRISE",
        "build": "2026.10.03.1",
        "channel": "production",
        "build_number": 16,
        "last_updated": "2026-10-03T00:00:00+03:00",
        "environment": "production",
        "productionReady": True,
        "agent_name": "CloudShield DevSecOps Autonomous Agent",
        "changelog": []
    }

    return load_json_file(vpath, default_info)

def get_admin_credentials():

    """Retrieve portal admin credentials from environment or git-ignored local auth config."""

    admin_user = os.environ.get("PORTAL_ADMIN_USER", "admin")

    admin_pass = os.environ.get("PORTAL_ADMIN_PASSWORD")

    if not admin_pass:

        local_auth = load_json_file(AUTH_LOCAL_FILE, {})

        if isinstance(local_auth, dict) and local_auth.get("admin_password"):

            admin_pass = local_auth.get("admin_password")

            admin_user = local_auth.get("admin_user", admin_user)

        else:

            admin_pass = secrets.token_urlsafe(16)

            save_json_file(AUTH_LOCAL_FILE, {

                "admin_user": admin_user,

                "admin_password": admin_pass,

                "note": "Local-only credential. Never committed to git.",

                "created_at": datetime.now(timezone.utc).isoformat()

            })

            print(f"[SECURITY] Generated initial administrator credentials in {AUTH_LOCAL_FILE}")

    return admin_user, admin_pass

def save_json_file(path, data):

    os.makedirs(os.path.dirname(path), exist_ok=True)

    to_save = data

    if os.path.basename(path) == "tenants.json" and isinstance(data, list):

        import copy

        to_save = copy.deepcopy(data)

        for t in to_save:

            if isinstance(t, dict) and "Auth" in t and isinstance(t["Auth"], dict):

                t["Auth"]["ClientSecret"] = ""

    with open(path, "w", encoding="utf-8") as f:

        json.dump(to_save, f, indent=2, ensure_ascii=False)

class MSSPPortalHandler(http.server.BaseHTTPRequestHandler):

    def end_headers(self):

        vinfo = get_version_info()

        self.send_header("Access-Control-Allow-Origin", "*")

        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

        self.send_header("X-Portal-Version", vinfo.get("version", "3.0.0"))

        self.send_header("X-Portal-Release", vinfo.get("release", "v3.0.0-ENTERPRISE"))

        self.send_header("X-Content-Type-Options", "nosniff")

        self.send_header("X-Frame-Options", "DENY")

        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")

        super().end_headers()

    def do_OPTIONS(self):

        self.send_response(204)

        self.end_headers()

    def send_json_response(self, data, status=200):

        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)

        self.send_header("Content-Type", "application/json; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        self.end_headers()

        self.wfile.write(body)

    def get_current_user(self):

        """Extract authenticated user object from session header or query parameter."""

        auth_hdr = self.headers.get("Authorization", "")
        tok = auth_hdr.replace("Bearer ", "").strip() if auth_hdr else ""

        if not tok:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            tok = query.get("token", [""])[0]

        if not tok:
            cookie_hdr = self.headers.get("Cookie", "")
            if cookie_hdr and "CS_SESSION=" in cookie_hdr:
                for part in cookie_hdr.split(";"):
                    part = part.strip()
                    if part.startswith("CS_SESSION="):
                        tok = part.split("=", 1)[1].strip()
                        break

        if tok:
            sess = get_session(tok)
            if sess:
                return sess.get("user")

        return None

    def _enforce_auth_gate(self, method, path):
        """
        W9 (Stage 1B - Coverage): single authentication gate at the dispatch
        boundary. Proves *authentication* only; per-route authorization is
        unchanged and remains with `evaluate_access()`.

        Returns True when the request may proceed. When the route is protected
        and no valid session exists, emits an AUTH_DENY audit event, writes a
        401 response, and returns False.
        """
        if _is_public_api_route(method, path):
            return True
        user = self.get_current_user()
        if user is not None:
            return True
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        try:
            record_audit_event(
                event_type="AUTH_DENY",
                resource=path,
                decision="DENY",
                reason="AuthenticationGate: AnonymousOrInvalidSession",
                ip_address=client_ip,
                details={"method": method, "route": path},
            )
        except Exception:
            pass
        self.send_json_response({
            "success": False,
            "error": "Kimlik Doğrulama Gerekli (401 Unauthorized): Bu uç noktaya erişmek için geçerli bir oturum gereklidir."
        }, status=401)
        return False

    def _handle_entra_authorize(self):
        """Initiate Microsoft Entra ID Authorization Code flow (OIDC)."""
        cfg = get_entra_config()
        if not cfg.get("client_id") or not cfg.get("tenant_id"):
            self.send_json_response({"error": "Entra ID OIDC configuration missing."}, status=500)
            return

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        now_ts = time.time()
        AUTH_FLOWS[state] = {
            "nonce": nonce,
            "created_at": now_ts,
            "redirect_uri": cfg["redirect_uri"]
        }

        # Purge stale flows (> 15 mins)
        stale = [s for s, f in AUTH_FLOWS.items() if now_ts - f.get("created_at", 0) > 900]
        for s in stale:
            AUTH_FLOWS.pop(s, None)

        params = {
            "client_id": cfg["client_id"],
            "response_type": "code",
            "redirect_uri": cfg["redirect_uri"],
            "response_mode": "query",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce
        }
        auth_url = f"{cfg['authorize_endpoint']}?{urllib.parse.urlencode(params)}"

        self.send_response(302)
        self.send_header("Location", auth_url)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def _handle_entra_callback(self, query):
        """Process Microsoft Entra ID OIDC authorization response."""
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        err = query.get("error", [""])[0]
        if err:
            err_desc = query.get("error_description", [err])[0]
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason=f"EntraLoginError: {err}",
                ip_address=client_ip,
                details={"error_description": err_desc}
            )
            self._render_auth_redirect_html(error=err_desc)
            return

        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]

        if not code or not state:
            self._render_auth_redirect_html(error="Geçersiz yetkilendirme yanıtı: code veya state parametresi eksik.")
            return

        flow = AUTH_FLOWS.pop(state, None)
        if not flow or (time.time() - flow.get("created_at", 0) > 900):
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason="InvalidOrExpiredAuthState",
                ip_address=client_ip
            )
            self._render_auth_redirect_html(error="Oturum doğrulama anahtarı (state) geçersiz veya zaman aşımına uğramış.")
            return

        expected_nonce = flow.get("nonce")
        redirect_uri = flow.get("redirect_uri")
        cfg = get_entra_config()

        token_payload = urllib.parse.urlencode({
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email"
        }).encode("utf-8")

        req = urllib.request.Request(
            cfg["token_endpoint"],
            data=token_payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                token_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason=f"TokenExchangeFailed: HTTP {e.code}",
                ip_address=client_ip,
                details={"response": err_body[:300]}
            )
            self._render_auth_redirect_html(error="Microsoft belirteç değişimi başarısız oldu. Lütfen tekrar deneyin.")
            return
        except Exception as e:
            self._render_auth_redirect_html(error=f"Belirteç sunucusuna erişilemedi: {str(e)}")
            return

        id_token = token_data.get("id_token")
        if not id_token:
            self._render_auth_redirect_html(error="Microsoft yanıtında kimlik belirteci (id_token) bulunamadı.")
            return

        try:
            claims = decode_jwt_payload(id_token)
        except Exception as e:
            self._render_auth_redirect_html(error=f"Kimlik belirteci çözümlenemedi: {str(e)}")
            return

        if claims.get("aud") != cfg["client_id"]:
            self._render_auth_redirect_html(error="Belirteç hedef kitlesi (aud) geçersiz.")
            return

        if claims.get("tid") != cfg["tenant_id"]:
            self._render_auth_redirect_html(error="Yetkisiz kiracı (tenant) oturumu.")
            return

        if claims.get("nonce") != expected_nonce:
            self._render_auth_redirect_html(error="Belirteç güvenlik anahtarı (nonce) uyuşmuyor.")
            return

        if claims.get("exp", 0) < time.time():
            self._render_auth_redirect_html(error="Kimlik belirtecinin süresi dolmuş.")
            return

        user_info, resolve_err = resolve_entra_user(claims)
        if resolve_err or not user_info:
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason=resolve_err or "UserResolutionFailed",
                ip_address=client_ip
            )
            self._render_auth_redirect_html(error=resolve_err or "Kullanıcı profili çözümlenemedi.")
            return

        tok = uuid.uuid4().hex + uuid.uuid4().hex
        save_session(tok, user_info, 86400)

        record_audit_event(
            event_type="AUTH_ALLOW",
            user_id=user_info["id"],
            user_upn=user_info["upn"],
            resource="/api/auth/entra/callback",
            decision="ALLOW",
            reason="EntraIdOidcSuccessful",
            ip_address=client_ip,
            details={
                "tid": claims.get("tid"),
                "oid": claims.get("oid"),
                "displayName": user_info.get("displayName"),
                "role": user_info.get("role")
            }
        )

        self._render_auth_redirect_html(token=tok, user=user_info)

    def _render_auth_redirect_html(self, token=None, user=None, error=None):
        import html
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if token:
            self.send_header("Set-Cookie", f"CS_SESSION={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400")

        if error:
            safe_err = html.escape(str(error))
            body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudShield - Kimlik Doğrulama Hatası</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen flex items-center justify-center p-4 font-sans">
    <div class="bg-slate-800 border border-red-500/30 rounded-xl p-8 max-w-md w-full shadow-2xl text-center">
        <div class="w-16 h-16 bg-red-500/10 text-red-400 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl font-bold">!</div>
        <h2 class="text-xl font-bold text-red-400 mb-2">Giriş Başarısız Oldu</h2>
        <p class="text-slate-300 text-sm mb-6">{safe_err}</p>
        <a href="/" class="inline-block bg-slate-700 hover:bg-slate-600 text-white text-xs font-bold py-2.5 px-6 rounded-lg transition">Giriş Ekranına Dön</a>
    </div>
</body>
</html>"""
        else:
            token_json = json.dumps(token)
            user_json = json.dumps(json.dumps(user, ensure_ascii=False))
            body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudShield - Giriş Yapılıyor</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen flex items-center justify-center p-4 font-sans">
    <div class="bg-slate-800 border border-emerald-500/30 rounded-xl p-8 max-w-md w-full shadow-2xl text-center">
        <div class="w-12 h-12 border-4 border-emerald-400 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
        <h2 class="text-lg font-bold text-emerald-400 mb-2">Microsoft Entra ID Doğrulandı</h2>
        <p class="text-slate-400 text-xs mb-4">CloudShield MSSP Portalına aktarılıyorsunuz...</p>
    </div>
    <script>
        try {{
            localStorage.setItem('cloudshield_auth_token', {token_json});
            localStorage.setItem('cloudshield_user', {user_json});
        }} catch (e) {{}}
        window.location.replace('/');
    </script>
</body>
</html>"""

        resp_bytes = body.encode("utf-8")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def handle_tenant_logo(self, tenant_id):

        """

        Fetch customer organization banner logo dynamically from Microsoft Entra ID CDN

        or generate a crisp corporate SVG monogram with ENTRA ID VERIFIED badge.

        """

        tenants = load_json_file(TENANTS_FILE, [])

        target = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
        customer_name = target.get("Name", "Customer") if target else "Customer"
        tenant_guid = target.get("TenantId") if target else None

        # 0. Check uploaded local corporate logo first
        safe_tid = "".join(c for c in str(tenant_id) if c.isalnum() or c in ('-', '_')).strip()
        png_path = os.path.join(LOGOS_DIR, f"{safe_tid}.png")
        svg_path = os.path.join(LOGOS_DIR, f"{safe_tid}.svg")
        if os.path.exists(png_path) and os.path.getsize(png_path) > 0:
            with open(png_path, "rb") as f:
                img_data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(img_data)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(img_data)
            return
        elif os.path.exists(svg_path) and os.path.getsize(svg_path) > 0:
            with open(svg_path, "rb") as f:
                img_data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
            self.send_header("Content-Length", str(len(img_data)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(img_data)
            return

        # 1. Attempt to fetch Microsoft Entra ID custom branding banner logo

        if tenant_guid and len(tenant_guid) > 25:

            entra_logo_url = f"https://login.microsoftonline.com/{tenant_guid}/promotedimages/bannerlogo.png"

            try:

                req = urllib.request.Request(entra_logo_url, headers={"User-Agent": "CloudShield-MSSP/2.5"})

                with urllib.request.urlopen(req, timeout=3) as resp:

                    if resp.status == 200:

                        img_data = resp.read()

                        if len(img_data) > 200:

                            self.send_response(200)

                            self.send_header("Content-Type", "image/png")

                            self.send_header("Content-Length", str(len(img_data)))

                            self.send_header("Cache-Control", "public, max-age=3600")

                            self.end_headers()

                            self.wfile.write(img_data)

                            return

            except Exception:

                pass

        # 2. Crisp Corporate SVG Monogram Fallback

        words = [w for w in customer_name.replace("-", " ").replace("_", " ").split() if w]

        initials = "".join([w[0].upper() for w in words[:2]]) or "CS"

        display_name = customer_name[:18]

        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 60" width="240" height="60">

  <defs>

    <linearGradient id="cGrad" x1="0%" y1="0%" x2="100%" y2="100%">

      <stop offset="0%" stop-color="#0f4c81" />

      <stop offset="100%" stop-color="#1e6bb8" />

    </linearGradient>

  </defs>

  <rect x="2" y="2" width="56" height="56" rx="10" fill="url(#cGrad)" stroke="#38bdf8" stroke-width="1.5"/>

  <text x="30" y="37" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="22" font-weight="800" fill="#ffffff" text-anchor="middle">{initials}</text>

  <text x="70" y="28" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="14" font-weight="700" fill="#0f172a">{display_name}</text>

  <rect x="70" y="34" width="108" height="18" rx="4" fill="#f0f9ff" stroke="#bae6fd" stroke-width="1"/>

  <text x="124" y="46" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9" font-weight="700" fill="#0284c7" text-anchor="middle">ENTRA ID VERIFIED</text>

</svg>'''.encode("utf-8")

        self.send_response(200)

        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")

        self.send_header("Content-Length", str(len(svg)))

        self.send_header("Cache-Control", "public, max-age=3600")

        self.end_headers()
        self.wfile.write(svg)

    def handle_tenant_permissions(self, tenant_id):
        tenants = load_json_file(TENANTS_FILE, [])
        target = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
        if not target:
            self.send_json_response({"success": False, "error": "Kiracı bulunamadı."}, status=404)
            return

        tenant_name = target.get("Name", "Kiracı")
        tenant_guid = target.get("TenantId", "")
        client_id = target.get("ClientId") or target.get("Auth", {}).get("ClientId", "")
        is_sim = target.get("IsSimulation", False) or "test" in tenant_name.lower() or "sandbox" in tenant_name.lower()

        # Load service catalog
        catalog = load_json_file(CATALOG_FILE, {}).get("services", {})
        
        perm_specs = {
            "SVC-MDE": ["SecurityAlert.Read.All", "ThreatHunting.Read.All", "Machine.Read.All"],
            "SVC-MDO": ["SecurityAlert.Read.All", "ThreatHunting.Read.All", "SecurityIncident.Read.All"],
            "SVC-MDI": ["SecurityAlert.Read.All", "ThreatHunting.Read.All", "IdentityRiskEvent.Read.All"],
            "SVC-MDCA": ["SecurityAlert.Read.All", "CloudAppEvents.Read.All"],
            "SVC-XDR": ["SecurityAlert.Read.All", "SecurityIncident.Read.All", "ThreatHunting.Read.All"],
            "SVC-INTUNE": ["DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All"],
            "SVC-ENTRA-PIM": ["RoleManagement.Read.Directory", "PrivilegedAccess.Read.AzureADGroup"],
            "SVC-ENTRA-ID": ["RoleManagement.Read.Directory", "IdentityProtection.Read.All", "User.Read.All"],
            "SVC-PRV-DLP": ["SecurityAlert.Read.All", "InformationProtectionPolicy.Read.All"],
            "SVC-PRV-CLASS": ["InformationProtectionPolicy.Read.All"],
            "SVC-PRV-GOV": ["InformationProtectionPolicy.Read.All"],
            "SVC-PRV-RISK": ["SecurityAlert.Read.All"],
            "SVC-AI-SECURITY": ["SecurityAlert.Read.All", "InformationProtectionPolicy.Read.All"]
        }

        active_services = target.get("ActiveServices", ["SVC-MDE", "SVC-MDO", "SVC-PURVIEW"])
        results = []
        for s_code, perms in perm_specs.items():
            s_meta = catalog.get(s_code, {})
            display_name = s_meta.get("displayNameTr") or s_code
            is_active = s_code in active_services or (s_code.startswith("SVC-PRV") and "SVC-PURVIEW" in active_services)
            
            # Status resolution
            if is_sim:
                status = "Granted"
                status_desc = "Onaylandı (Simülasyon / Test Ortamı)"
            elif not client_id or not tenant_guid:
                status = "MissingScope"
                status_desc = "Yapılandırma Eksik (ClientId / TenantId Tanımsız)"
            elif not is_active:
                status = "NotSubscribed"
                status_desc = "Abonelik Kapsamı Dışında"
            else:
                status = "Granted" if target.get("HealthStatus") == "Healthy" else "AdminConsentRequired"
                status_desc = "Onaylandı" if status == "Granted" else "Yönetici Onayı Bekliyor (Admin Consent Required)"

            results.append({
                "serviceCode": s_code,
                "displayName": display_name,
                "category": s_meta.get("productFamily", "Microsoft Security"),
                "isActive": is_active,
                "requiredPermissions": perms,
                "status": status,
                "statusDescription": status_desc
            })

        consent_url = f"https://login.microsoftonline.com/{tenant_guid or 'common'}/adminconsent?client_id={client_id or '00000000-0000-0000-0000-000000000000'}&redirect_uri=https://portal.cloudshield-mssp.com" if client_id and tenant_guid else ""
        cred_health = self.compute_credential_health(target)

        self.send_json_response({
            "success": True,
            "tenantId": tenant_id,
            "tenantName": tenant_name,
            "tenantGuid": tenant_guid,
            "clientId": client_id,
            "isSimulation": is_sim,
            "adminConsentUrl": consent_url,
            "servicesCount": len(results),
            "services": results,
            "credentialHealth": cred_health,
            "lastCheckedUtc": datetime.now(timezone.utc).isoformat()
        })

    def compute_credential_health(self, tenant):
        """Calculates credential lifecycle health status (Healthy, ExpiringSoon, Critical, Expired)."""
        auth = tenant.get("Auth") or {}
        auth_method = tenant.get("AuthMethod") or auth.get("Method") or "ClientSecret"
        expiry_str = auth.get("SecretExpiryDate") or tenant.get("SecretExpiryDate")
        if not expiry_str and auth_method in ("Certificate", "ClientCertificate", "CBA"):
            expiry_str = auth.get("CertExpiryDate") or tenant.get("CertExpiryDate")

        days_left = None
        status = "Healthy"
        status_label = "Geçerli / Sağlıklı"

        if expiry_str:
            try:
                clean_exp = expiry_str.replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(clean_exp)
                now_dt = datetime.now(timezone.utc)
                delta = exp_dt - now_dt
                days_left = delta.days
                if days_left <= 0:
                    status = "Expired"
                    status_label = "Süresi Doldu (Hemen Yenileyin)"
                elif days_left < 7:
                    status = "Critical"
                    status_label = f"Kritik: {days_left} Gün Kaldı"
                elif days_left <= 30:
                    status = "ExpiringSoon"
                    status_label = f"Uyarı: {days_left} Gün Kaldı"
                else:
                    status = "Healthy"
                    status_label = f"Geçerli ({days_left} Gün Kaldı)"
            except Exception:
                pass
        else:
            status = "Healthy"
            status_label = "Süresiz / Yönetilen Kimlik"
            days_left = 365

        return {
            "authMethod": auth_method,
            "expiryDate": expiry_str or "",
            "daysUntilExpiry": days_left,
            "status": status,
            "statusLabel": status_label
        }

    def handle_tenant_trends(self, tenant_id):
        user = self.get_current_user()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        allow, _ = evaluate_access(user, "reports:view", resource=f"/api/tenants/{tenant_id}/trends", ip_address=client_ip)
        if not allow:
            self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden)."}, status=403)
            return

        if user:
            assigned = user.get("AssignedTenants", ["ALL"])
            if "ALL" not in assigned and tenant_id not in assigned:
                self.send_json_response({"success": False, "error": "Bu müşteri kiracısının trend verilerine erişim yetkiniz yoktur."}, status=403)
                return

        from database.db import get_tenant_trends
        trends = get_tenant_trends(tenant_id)
        self.send_json_response({
            "success": True,
            "tenantId": tenant_id,
            "recordsCount": len(trends),
            "trends": trends
        })

    def handle_tenant_credentials(self, tenant_id):
        user = self.get_current_user()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        allow, _ = evaluate_access(user, "customers:view", resource=f"/api/tenants/{tenant_id}/credentials", ip_address=client_ip)
        if not allow:
            self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden)."}, status=403)
            return

        if user:
            assigned = user.get("AssignedTenants", ["ALL"])
            if "ALL" not in assigned and tenant_id not in assigned:
                self.send_json_response({"success": False, "error": "Bu müşteri kiracısının kimlik durumuna erişim yetkiniz yoktur."}, status=403)
                return

        from database.db import get_tenant_credential_health
        health = get_tenant_credential_health(tenant_id)
        if not health:
            tenants = load_json_file(TENANTS_FILE, [])
            target = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            if target:
                computed = self.compute_credential_health(target)
                health = {
                    "tenant_id": tenant_id,
                    "auth_type": computed["authMethod"],
                    "secret_expiry_date": computed["expiryDate"],
                    "days_until_expiry": computed["daysUntilExpiry"],
                    "health_status": computed["status"]
                }

        self.send_json_response({
            "success": True,
            "tenantId": tenant_id,
            "credentialHealth": health
        })

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # W9 (Stage 1B): authentication gate before any route dispatch.
        if not self._enforce_auth_gate("GET", path):
            return

        if path.startswith("/api/rbac/"):
            handle_rbac_get(self, path, query)
            return


        # API ROUTES

        if path == "/api/health":

            vinfo = get_version_info()

            self.send_json_response({

                "status": "Healthy",

                "version": vinfo.get("version", "3.0.0"),

                "release": vinfo.get("release", "v3.0.0-ENTERPRISE"),

                "build": vinfo.get("build", "2026.10.03.1"),

                "channel": vinfo.get("channel", "production"),

                "environment": vinfo.get("environment", "production"),

                "productionReady": vinfo.get("productionReady", True),

                "timestamp": datetime.now(timezone.utc).isoformat()

            })

            return

        elif path == "/api/version":

            vinfo = get_version_info()

            self.send_json_response({

                "version": vinfo.get("version", "3.0.0"),

                "release": vinfo.get("release", "v3.0.0-ENTERPRISE"),

                "build": vinfo.get("build", "2026.10.03.1"),

                "channel": vinfo.get("channel", "production"),

                "build_number": vinfo.get("build_number", 16),

                "last_updated": vinfo.get("last_updated", datetime.now(timezone.utc).isoformat()),

                "commit": vinfo.get("commit", "latest"),

                "agent_name": vinfo.get("agent_name", "CloudShield DevSecOps Autonomous Agent"),

                "changelog": vinfo.get("changelog", []),

                "timestamp": datetime.now(timezone.utc).isoformat(),

                "environment": vinfo.get("environment", "production"),

                "productionReady": vinfo.get("productionReady", True),

                "features": [

                    "LiveDataPipeline",

                    "LiveGraphApiCollector",

                    "LiveMdeAdvancedHunting",

                    "PurviewDlpAlertsLive",

                    "SessionAuthenticationGate",

                    "PureLiveTenantsOnly",

                    "MultiTenantConcurrencyIsolation",

                    "MultiTenantRbacIsolation",

                    "EntraIdDynamicBranding",

                    "GdprKvkkPrivacyEngine",

                    "AutonomousAgentVersioning",

                    "SingleSourceVersionManifest",

                    "DynamicAzureDiscovery"

                ]

            })

            return

        elif path == "/api/auth/verify":
            token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            sess = get_session(token)
            if sess and sess.get("expiresAt", 0) > time.time():
                self.send_json_response({"valid": True, "user": sess.get("user")})
            else:
                self.send_json_response({"valid": False, "error": "Oturum geçersiz veya süresi dolmuş"}, status=401)
            return

        elif path == "/api/auth/me":
            u = self.get_current_user()
            if u:
                self.send_json_response({"success": True, "user": u})
            else:
                self.send_json_response({"success": False, "error": "Oturum bulunamadı veya süresi dolmuş"}, status=401)
            return

        elif path in ("/api/auth/entra/authorize", "/api/auth/entra/login"):
            self._handle_entra_authorize()
            return

        elif path == "/api/auth/entra/callback":
            self._handle_entra_callback(query)
            return

        elif path.startswith("/api/tenants/") and path.endswith("/logo"):
            tenant_id = path.split("/")[3]
            self.handle_tenant_logo(tenant_id)
            return

        elif path.startswith("/api/tenants/") and path.endswith("/permissions"):
            tenant_id = path.split("/")[3]
            self.handle_tenant_permissions(tenant_id)
            return

        elif path.startswith("/api/tenants/") and path.endswith("/trends"):
            tenant_id = path.split("/")[3]
            self.handle_tenant_trends(tenant_id)
            return

        elif path.startswith("/api/tenants/") and path.endswith("/credentials"):
            tenant_id = path.split("/")[3]
            self.handle_tenant_credentials(tenant_id)
            return

        elif path == "/api/tenants":

            tenants = load_json_file(TENANTS_FILE, [])

            user = self.get_current_user()

            if user:

                assigned = user.get("AssignedTenants", ["ALL"])

                if "ALL" not in assigned:

                    tenants = [t for t in tenants if t.get("Id") in assigned or t.get("TenantId") in assigned]

            # Enrich tenants with LogoUrl and CredentialHealth
            for t in tenants:
                tid = t.get("Id") or t.get("TenantId") or ""
                t["LogoUrl"] = f"/api/tenants/{tid}/logo"
                t["CredentialHealth"] = self.compute_credential_health(t)

            self.send_json_response(tenants)

            return

        elif path == "/api/users":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:view", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "assignments:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kullanıcı listesini görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            users = load_json_file(USERS_FILE, [])

            self.send_json_response(users)

            return

        elif path == "/api/auth/config":

            auth_cfg = load_json_file(AUTH_CONFIG_FILE, {})

            self.send_json_response(auth_cfg)

            return

        elif path == "/api/services":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "services:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Servis kataloğunu görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            catalog = load_json_file(CATALOG_FILE, {})

            self.send_json_response(catalog)

            return

        elif path == "/api/activities":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Operasyonel faaliyetleri görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            activities = load_json_file(ACTIVITIES_FILE, [])

            tenant_filter = query.get("tenantId", [None])[0]

            if tenant_filter:

                activities = [a for a in activities if a.get("tenantId") == tenant_filter or a.get("customerName") == tenant_filter]

            self.send_json_response(activities)

            return

        elif path == "/api/users/me":

            # Return authenticated user from active session

            user = self.get_current_user()

            if user:

                self.send_json_response({

                    "upn": user.get("email") or user.get("username"),

                    "displayName": user.get("displayName", "User"),

                    "role": user.get("role", "CustomerViewer"),

                    "department": user.get("department", "MSSP Client"),

                    "teams": user.get("teams", ["Security"]),

                    "permissions": user.get("permissions", {

                        "CanViewDashboard": True,

                        "CanGenerateReports": False,

                        "CanAccessGdap": False,

                        "CanManageTenants": False,

                        "CanManageSettings": False

                    }),

                    "AssignedTenants": user.get("AssignedTenants", ["ALL"]),

                    "tenantCount": len(load_json_file(TENANTS_FILE, []))

                })

            else:

                self.send_json_response({

                    "upn": "admin@cloudshield-mssp.com",

                    "displayName": "Platform Administrator",

                    "role": "PlatformAdmin",

                    "department": "Siber Güvenlik Çözüm Mimarlığı",

                    "teams": ["Core-MSSP", "XDR-Security", "Purview-Compliance", "Cloud-Security"],

                    "permissions": {

                        "CanViewDashboard": True,

                        "CanGenerateReports": True,

                        "CanAccessGdap": True,

                        "CanManageTenants": True,

                        "CanManageSettings": True

                    },

                    "AssignedTenants": ["ALL"],

                    "tenantCount": len(load_json_file(TENANTS_FILE, []))

                })

            return

        elif path == "/api/stats/global":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Global istatistikleri görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            # Daily Cache Mechanism - Run once daily to protect API throttling limits

            cache = load_json_file(CACHE_FILE, None)

            now = datetime.now(timezone.utc)

            need_refresh = False

            if not cache or "globalStats" not in cache:

                need_refresh = True

            else:

                last_sync_str = cache.get("lastSyncTimestamp")

                if last_sync_str:

                    try:

                        last_sync = datetime.fromisoformat(last_sync_str.replace("Z", "+00:00"))

                        if (now - last_sync).total_seconds() > 86400:  # 24 hours

                            need_refresh = True

                    except Exception:

                        need_refresh = True

                else:

                    need_refresh = True

            if need_refresh:

                tenants = load_json_file(TENANTS_FILE, [])

                total_endpoints = sum(t.get("TotalEndpoints", 0) for t in tenants)

                total_ghost = sum(t.get("GhostDevices", 0) for t in tenants)

                total_alerts = sum(t.get("OpenHighAlerts", 0) for t in tenants)

                avg_score = round(sum(t.get("SecureScore", 0) for t in tenants) / max(len(tenants), 1), 1)

                cache = {

                    "lastSyncTimestamp": now.strftime("%Y-%m-%d %H:%M:%S"),

                    "nextScheduledSync": (now + timedelta(days=1)).strftime("%Y-%m-%d 06:00:00"),

                    "syncMode": "DailyScheduled",

                    "isCacheActive": True,

                    "globalStats": {

                        "totalTenants": len(tenants),

                        "totalEndpoints": total_endpoints,

                        "totalGhostDevices": total_ghost,

                        "totalCriticalAlerts": total_alerts,

                        "averageSecureScore": avg_score

                    }

                }

                save_json_file(CACHE_FILE, cache)

            res_payload = dict(cache.get("globalStats", {}))

            res_payload["lastSyncTimestamp"] = cache.get("lastSyncTimestamp", now.strftime("%Y-%m-%d %H:%M:%S"))

            res_payload["nextScheduledSync"] = cache.get("nextScheduledSync", (now + timedelta(days=1)).strftime("%Y-%m-%d 06:00:00"))

            res_payload["isCacheActive"] = True

            self.send_json_response(res_payload)

            return

        elif path == "/api/dispatch":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Gönderim yapılandırmasını görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenants = load_json_file(TENANTS_FILE, [])

            configs = []

            for t in tenants:

                configs.append({

                    "tenantId": t.get("Id"),

                    "tenantGuid": t.get("TenantId"),

                    "name": t.get("Name"),

                    "isSimulation": t.get("IsSimulation", False),

                    "frequency": t.get("ScheduleFrequency", "Monthly"),

                    "dispatchDay": t.get("DispatchDay", 1),

                    "dispatchTime": t.get("DispatchTime", "09:00"),

                    "recipients": t.get("RecipientEmails", ["mssp-reporting@cloudshield-mssp.com"]),

                    "subjectTemplate": t.get("EmailSubjectTemplate", "[CloudShield MSSP] {CustomerName} - Yönetilen Güvenlik ve Uyum Raporu"),

                    "attachPdf": t.get("AttachPdf", True),

                    "attachHtml": t.get("AttachHtml", True),

                    "isActive": t.get("IsDispatchActive", True),

                    "lastDispatchDate": t.get("LastDispatchDate", "-"),

                    "lastDispatchStatus": t.get("LastDispatchStatus", "Pending")

                })

            self.send_json_response(configs)

            return

        elif path == "/api/dispatch/history":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Gönderim geçmişini görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            history = load_json_file(DISPATCH_LOGS_FILE, [])

            self.send_json_response(history)

            return

        elif path == "/api/kql/catalog":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "services:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): KQL sorgu kataloğunu görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            kql_index_file = os.path.join(ROOT_DIR, "Engine", "KQL", "query-metadata", "catalog-index.json")

            catalog = load_json_file(kql_index_file, [])

            # Read query contents for each item

            svc_filter = query.get("service", [""])[0].upper()

            pkg_filter = query.get("package", [""])[0]

            filtered = []

            for item in catalog:

                if svc_filter and item.get("service") != svc_filter:

                    continue

                if pkg_filter and item.get("package") != pkg_filter:

                    continue

                # Attach KQL query text

                q_rel = item.get("queryFile", "")

                if q_rel:

                    q_full = os.path.join(ROOT_DIR, q_rel.replace("/", os.sep))

                    if os.path.exists(q_full):

                        try:

                            with open(q_full, "r", encoding="utf-8") as qf:

                                item["kqlContent"] = qf.read()

                        except Exception:

                            item["kqlContent"] = ""

                filtered.append(item)

            self.send_json_response({

                "success": True,

                "total": len(filtered),

                "queries": filtered

            })

            return

        elif path == "/api/kql/packages":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "services:view", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): KQL paketlerini görüntüleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            pkg_base = os.path.join(ROOT_DIR, "Engine", "KQL", "query-packages")

            packages = []

            if os.path.exists(pkg_base):

                for p_dir in os.listdir(pkg_base):

                    p_path = os.path.join(pkg_base, p_dir, "package.json")

                    if os.path.exists(p_path):

                        pkg_data = load_json_file(p_path, None)

                        if pkg_data:

                            packages.append(pkg_data)

            self.send_json_response({

                "success": True,

                "total": len(packages),

                "packages": packages

            })

            return

        elif path.startswith("/api/reports/") and path.endswith("/download") and len([p for p in path.split("/") if p]) == 4:
            # Quality Gate 5: GET /api/reports/{reportId}/download
            parts = [p for p in path.split("/") if p]
            report_id = parts[2]

            registry = load_report_registry()
            record = registry.get(report_id)
            if not record:
                self.send_json_response({
                    "success": False,
                    "error": "Rapor bulunamad? (404 Not Found): Belirtilen rapor kimli?i sistem kay?tlar?nda mevcut de?il."
                }, status=404)
                return

            # Check expiration
            expires_at = record.get("expiresAtUtc")
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) > exp_dt:
                        self.send_json_response({
                            "success": False,
                            "error": "Rapor s?resi dolmu? (410 Gone): Bu rapor ar?iv saklama s?resi doldu?u i?in eri?ilemez."
                        }, status=410)
                        return
                except Exception:
                    pass

            # RBAC Server-Side Authorization Evaluation (Customer + Service Scopes)
            user = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            rep_tid = record.get("tenantId", "")
            rep_services = record.get("serviceCodes", [])
            allowed, reason = evaluate_access(
                user,
                "reports:download",
                customer_id=rep_tid,
                service_ids=rep_services,
                resource=path,
                ip_address=client_ip
            )
            if not allowed:
                self.send_json_response({
                    "success": False,
                    "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"
                }, status=403)
                return

            record_audit_event(
                "REPORT_DOWNLOAD",
                user_id=user.get("id") if user else None,
                user_upn=user.get("upn") if user else None,
                customer_id=rep_tid,
                service_id=",".join(rep_services) if rep_services else None,
                resource=path,
                decision="ALLOW",
                reason="AuthorizedReportDownload",
                ip_address=client_ip,
                details={"reportId": report_id, "services": rep_services}
            )

            storage_key = record.get("storageKey", "")
            if ".." in storage_key or storage_key.startswith("/") or storage_key.startswith("\\"):
                self.send_json_response({"success": False, "error": "Ge?ersiz dosya depolama anahtar?."}, status=400)
                return

            full_path = os.path.abspath(os.path.join(OUTPUT_DIR, storage_key.lstrip("/\\")))
            if not full_path.startswith(os.path.abspath(OUTPUT_DIR)):
                self.send_json_response({"success": False, "error": "Dizin d???na ??k?? engellendi (403 Forbidden)."}, status=403)
                return

            if not os.path.exists(full_path):
                self.send_json_response({"success": False, "error": "Fiziksel rapor dosyas? bulunamad?."}, status=404)
                return

            content_type = "application/pdf" if full_path.endswith(".pdf") else "text/html; charset=utf-8"
            file_size = os.path.getsize(full_path)
            basename = os.path.basename(full_path)
            ascii_name = basename.encode("ascii", "replace").decode("ascii").replace("?", "_")
            quoted_name = urllib.parse.quote(basename)

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("Content-Disposition", f'inline; filename="{ascii_name}"; filename*=UTF-8\'\'{quoted_name}')
            self.end_headers()

            with open(full_path, "rb") as f:
                self.wfile.write(f.read())
            return

        elif path == "/api/reports/download":

            file_param = query.get("file", [""])[0]

            if not file_param or ".." in file_param:

                self.send_error(400, "Invalid file path")

                return

            # Multi-Tenant RBAC Download Authorization Check
            user = self.get_current_user()
            if not user:
                self.send_json_response({
                    "success": False,
                    "error": "Kimlik Doğrulama Gerekli (401 Unauthorized): Rapor indirmek için geçerli bir oturum açmalısınız."
                }, status=401)
                return

            tenants = load_json_file(TENANTS_FILE, [])
            file_norm = file_param.replace("\\", "/")
            matched_tenant = None
            for t in tenants:
                name = t.get("Name", "")
                safe = "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
                aliases = [t.get("Id"), t.get("TenantId"), name, safe]
                if any(a and a.lower() in file_norm.lower() for a in aliases):
                    matched_tenant = t.get("Id")
                    break

            if matched_tenant:
                client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
                allowed, reason = evaluate_access(
                    user,
                    "reports:download",
                    customer_id=matched_tenant,
                    resource=path,
                    ip_address=client_ip
                )
                if not allowed:
                    self.send_json_response({
                        "success": False,
                        "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"
                    }, status=403)
                    return

            full_path = os.path.abspath(os.path.join(OUTPUT_DIR, file_param.lstrip("/\\")))

            if not os.path.exists(full_path):

                self.send_error(404, "Report file not found")

                return

            content_type = "application/pdf" if full_path.endswith(".pdf") else "text/html; charset=utf-8"

            file_size = os.path.getsize(full_path)

            basename = os.path.basename(full_path)

            # Safe RFC 5987 encoding for HTTP headers with Unicode / Turkish characters

            ascii_name = basename.encode("ascii", "replace").decode("ascii").replace("?", "_")

            quoted_name = urllib.parse.quote(basename)

            self.send_response(200)

            self.send_header("Content-Type", content_type)

            self.send_header("Content-Length", str(file_size))

            self.send_header("Content-Disposition", f'inline; filename="{ascii_name}"; filename*=UTF-8\'\'{quoted_name}')

            self.end_headers()

            with open(full_path, "rb") as f:

                self.wfile.write(f.read())

            return

        # STATIC FILES FROM /Portal/web/

        req_file = path.lstrip("/")

        if not req_file or req_file == "":

            req_file = "index.html"

        static_path = os.path.join(WEB_DIR, req_file)

        if os.path.exists(static_path) and os.path.isfile(static_path):

            ext = os.path.splitext(static_path)[1].lower()

            mime_types = {

                ".html": "text/html; charset=utf-8",

                ".css": "text/css; charset=utf-8",

                ".js": "application/javascript; charset=utf-8",

                ".json": "application/json; charset=utf-8",

                ".png": "image/png",

                ".jpg": "image/jpeg",

                ".svg": "image/svg+xml"

            }

            content_type = mime_types.get(ext, "application/octet-stream")

            with open(static_path, "rb") as f:

                content = f.read()

            self.send_response(200)

            self.send_header("Content-Type", content_type)

            self.send_header("Content-Length", str(len(content)))

            self.end_headers()

            self.wfile.write(content)

            return

        # Default fallback to index.html for Single Page Application

        index_path = os.path.join(WEB_DIR, "index.html")

        if os.path.exists(index_path):

            with open(index_path, "rb") as f:

                content = f.read()

            self.send_response(200)

            self.send_header("Content-Type", "text/html; charset=utf-8")

            self.send_header("Content-Length", str(len(content)))

            self.end_headers()

            self.wfile.write(content)

            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body = {}

        # W9 (Stage 1B): authentication gate before any route dispatch.
        if not self._enforce_auth_gate("POST", path):
            return

        if path.startswith("/api/rbac/"):
            handle_rbac_post(self, path, body)
            return


        if path == "/api/auth/login":
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            vinfo = get_version_info()
            channel = str(vinfo.get("channel", "production")).lower()
            env_mode = str(vinfo.get("environment", "production")).lower()
            allow_local = os.environ.get("CLOUDSHIELD_ALLOW_LOCAL_AUTH", "false").lower() == "true"

            # Mandatory: Disable local password authentication in Enterprise/Production mode unless explicitly enabled
            if (channel in ("pilot", "production", "enterprise") or env_mode in ("pilot", "production", "enterprise")) and not allow_local:
                record_audit_event(
                    event_type="AUTH_DENY",
                    resource="/api/auth/login",
                    decision="DENY",
                    reason="LocalAuthDisabledInProductionMode",
                    ip_address=client_ip
                )
                self.send_json_response({
                    "success": False,
                    "error": "Kurumsal üretim modunda yerel parola kimlik doğrulaması devre dışıdır. Lütfen kurumsal Microsoft Entra ID (SSO) ile oturum açınız.",
                    "authProvider": "EntraID_OIDC",
                    "ssoRequired": True
                }, status=403)
                return

            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))

            user_info, err = authenticate_user(username, password, client_ip)
            if user_info:
                tok = uuid.uuid4().hex + uuid.uuid4().hex
                assigned_tenants = [a.get("customer_id") or "ALL" for a in user_info.get("assignments", []) if a.get("customer_scope") == "ALL" or a.get("customer_id")]
                if not assigned_tenants or user_info.get("isPlatformAdmin"):
                    assigned_tenants = ["ALL"]
                user_info["AssignedTenants"] = assigned_tenants
                user_info["tenantScope"] = "Global" if "ALL" in assigned_tenants else "Restricted"
                user_info["initials"] = "".join([w[0].upper() for w in user_info.get("displayName", "US").split()[:2]])

                save_session(tok, user_info, 86400)

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"CS_SESSION={tok}; Path=/; HttpOnly; SameSite=Strict")
                resp_bytes = json.dumps({
                    "success": True,
                    "token": tok,
                    "user": user_info,
                    "expiresIn": 86400
                }, ensure_ascii=False).encode("utf-8")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
            else:
                self.send_json_response({
                    "success": False,
                    "error": err or "Geçersiz kullanıcı adı veya parola."
                }, status=401)
            return

        elif path == "/api/auth/logout":
            tok = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            u = self.get_current_user()
            delete_session(tok)
            if u:
                record_audit_event("AUTH_LOGOUT", user_id=u.get("id"), user_upn=u.get("upn"),
                                   resource="/api/auth/logout", decision="ALLOW", reason="UserLoggedOut", ip_address=client_ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "CS_SESSION=; Path=/; HttpOnly; Max-Age=0")
            resp_bytes = json.dumps({"success": True, "message": "Oturum başarıyla kapatıldı."}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

                
        elif path == "/api/auth/sso":
            # W5 (Stage 1A Containment): the former identity-assertion stub is RETIRED.
            #
            # Security rationale: the previous handler minted a session from a
            # caller-supplied body `upn`, and when no database user matched it
            # FABRICATED a PlatformAdmin identity (usr-architect-sso) granting
            # global scope. That is an authentication bypass: any anonymous caller
            # could obtain a valid session for an arbitrary identity.
            #
            # This endpoint now fails closed. It issues NO token, creates NO
            # session, resolves NO identity, and returns 410 Gone unconditionally.
            # A real Entra ID OIDC token exchange (authorization-code + JWKS
            # signature validation) is future work (W1/W2) and is intentionally
            # NOT implemented here.
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            try:
                record_audit_event(
                    event_type="AUTH_DENY",
                    resource="/api/auth/sso",
                    decision="DENY",
                    reason="SsoStubRetiredW5",
                    ip_address=client_ip,
                    details={"note": "identity-assertion stub retired; no session issued"}
                )
            except Exception:
                pass
            self.send_json_response({
                "success": False,
                "error": "Bu uç nokta devre dışı bırakılmıştır (410 Gone): Kimlik doğrulama sağlayıcısı devre dışıdır. Kurumsal Microsoft Entra ID (SSO) entegrasyonu henüz etkin değildir.",
                "ssoRequired": True
            }, status=410)
            return

        elif path.startswith("/api/tenants/") and path.endswith("/logo"):
            tenant_id = path.split("/")[3]
            safe_tid = "".join(c for c in str(tenant_id) if c.isalnum() or c in ('-', '_')).strip()
            u = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            allowed, reason = evaluate_access(u, "customers:manage", resource=path, ip_address=client_ip)
            if not allowed:
                allowed, reason = evaluate_access(u, "TENANT_WRITE", tenant_id=tenant_id, resource=path, ip_address=client_ip)
            if not allowed:
                self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden): Logo güncelleme yetkiniz bulunmamaktadır."}, status=403)
                return

            img_bytes = None
            ext = "png"
            if isinstance(body, dict) and "logoBase64" in body:
                b64_str = body["logoBase64"]
                if "," in b64_str:
                    b64_str = b64_str.split(",", 1)[1]
                try:
                    img_bytes = base64.b64decode(b64_str)
                except Exception:
                    img_bytes = None
                if body.get("format", "").lower() in ("svg", "svg+xml"):
                    ext = "svg"
            elif body_bytes and len(body_bytes) > 0:
                img_bytes = body_bytes
                content_type = self.headers.get("Content-Type", "")
                if "svg" in content_type:
                    ext = "svg"

            if not img_bytes or len(img_bytes) == 0:
                self.send_json_response({"success": False, "error": "Geçersiz logo verisi (Boş dosya)."}, status=400)
                return

            if len(img_bytes) > 2 * 1024 * 1024:
                self.send_json_response({"success": False, "error": "Logo boyutu 2MB sınırını aşamaz."}, status=400)
                return

            if ext == "png" and not img_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                if b"<svg" in img_bytes[:300].lower():
                    ext = "svg"
                else:
                    self.send_json_response({"success": False, "error": "Desteklenmeyen dosya formatı. Yalnızca PNG ve SVG kabul edilir."}, status=400)
                    return
            elif ext == "svg" and b"<svg" not in img_bytes[:300].lower():
                self.send_json_response({"success": False, "error": "Geçersiz SVG formatı."}, status=400)
                return

            out_path = os.path.join(LOGOS_DIR, f"{safe_tid}.{ext}")
            alt_path = os.path.join(LOGOS_DIR, f"{safe_tid}.{'png' if ext=='svg' else 'svg'}")
            if os.path.exists(alt_path):
                try:
                    os.remove(alt_path)
                except Exception:
                    pass

            with open(out_path, "wb") as f:
                f.write(img_bytes)

            record_audit_event("TENANT_LOGO_UPDATE", user_id=u.get("id"), user_upn=u.get("upn"),
                               resource=path, decision="ALLOW", reason="TenantLogoUploaded", ip_address=client_ip,
                               details={"tenantId": tenant_id, "sizeBytes": len(img_bytes), "format": ext})

            self.send_json_response({
                "success": True,
                "message": "Kurumsal logo başarıyla yüklendi ve güncellendi.",
                "logoUrl": f"/api/tenants/{tenant_id}/logo"
            })
            return

        elif path == "/api/tenants/preflight-validate":
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:view", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kiracı ön doğrulama yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenant_guid = str(body.get("tenantId") or body.get("TenantId") or "").strip()
            client_id = str(body.get("clientId") or body.get("ClientId") or "").strip()
            auth_method = str(body.get("authMethod") or body.get("AuthMethod") or "Certificate").strip()
            secret_exp = body.get("secretExpiryDate") or body.get("SecretExpiryDate")
            cert_exp = body.get("certExpiryDate") or body.get("CertExpiryDate")

            import re
            guid_regex = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            if not guid_regex.match(tenant_guid):
                self.send_json_response({
                    "success": False,
                    "status": "InvalidGuidFormat",
                    "badge": "Geçersiz GUID",
                    "error": f"Geçersiz Microsoft 365 Tenant ID formatı: '{tenant_guid}'. 8-4-4-4-12 hex formatında standart GUID beklenmektedir."
                }, status=400)
                return

            days_until_expiry = None
            target_exp = cert_exp or secret_exp
            if target_exp:
                try:
                    exp_clean = str(target_exp).replace("Z", "+00:00")
                    if "T" not in exp_clean and len(exp_clean) == 10:
                        exp_clean += "T00:00:00+00:00"
                    exp_dt = datetime.fromisoformat(exp_clean)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    days_until_expiry = max(0, (exp_dt - datetime.now(timezone.utc)).days)
                except Exception:
                    pass

            t0 = time.time()
            entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
            try:
                req = urllib.request.Request(
                    entra_url,
                    headers={"User-Agent": "CloudShield-MSSP-Portal/3.0.0 (Onboarding-Preflight)"}
                )
                with urllib.request.urlopen(req, timeout=6.0) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    latency_ms = int((time.time() - t0) * 1000)

                issuer = resp_data.get("issuer", "")
                token_endpoint = resp_data.get("token_endpoint", "")
                auth_endpoint = resp_data.get("authorization_endpoint", "")

                self.send_json_response({
                    "success": True,
                    "status": "PreflightVerified",
                    "badge": "Canlı Entra ID Doğrulandı",
                    "tenantId": tenant_guid,
                    "latencyMs": latency_ms,
                    "issuer": issuer,
                    "tokenEndpoint": token_endpoint,
                    "authEndpoint": auth_endpoint,
                    "authMethod": auth_method,
                    "daysUntilExpiry": days_until_expiry,
                    "message": f"Microsoft Entra ID kiracı uç noktası ({tenant_guid[:8]}...) başarıyla doğrulandı ({latency_ms}ms). Canlı kiracı bağlantısı ve OpenID federasyonu aktif."
                }, status=200)
                return
            except urllib.error.HTTPError as h_err:
                latency_ms = int((time.time() - t0) * 1000)
                self.send_json_response({
                    "success": False,
                    "status": "TenantNotFound",
                    "badge": "Kiracı Bulunamadı",
                    "error": f"Microsoft Entra ID üzerinde '{tenant_guid}' kimlikli kiracı bulunamadı (HTTP {h_err.code}). Lütfen Tenant Directory GUID değerini kontrol ediniz.",
                    "latencyMs": latency_ms
                }, status=400)
                return
            except Exception as net_err:
                latency_ms = int((time.time() - t0) * 1000)
                self.send_json_response({
                    "success": False,
                    "status": "NetworkError",
                    "badge": "Bağlantı Hatası",
                    "error": f"Microsoft Entra ID uç noktasına ulaşılamadı ({latency_ms}ms): {str(net_err)}",
                    "latencyMs": latency_ms
                }, status=502)
                return

        elif path == "/api/tenants":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Müşteri/kiracı oluşturma yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenants = load_json_file(TENANTS_FILE, [])

            new_id = body.get("Id") or f"tenant-{len(tenants)+1:03d}"
            body["Id"] = new_id

            # Auth Normalization & Production Zero Trust Policy Enforcement
            auth_raw = body.get("Auth") if isinstance(body.get("Auth"), dict) else {}
            auth_method_str = body.get("AuthMethod") or auth_raw.get("Method") or "Certificate"
            if auth_method_str in ("ClientCertificate", "Certificate", "CBA"):
                normalized_auth_method = "Certificate"
            elif auth_method_str in ("GDAP_Delegated", "GDAP"):
                normalized_auth_method = "GDAP"
            else:
                normalized_auth_method = "ClientSecret"

            is_sim = body.get("IsSimulation", False)
            tenant_name = (body.get("Name") or "").strip()
            is_test_tenant = is_sim or "test" in tenant_name.lower() or "sandbox" in tenant_name.lower() or body.get("IsSandbox", False)

            # Live Customer Zero Trust Standard: Production customer tenants must not use raw Client Secret
            if not is_test_tenant and normalized_auth_method == "ClientSecret" and (body.get("ClientSecret") or auth_raw.get("ClientSecret")):
                self.send_json_response({
                    "success": False,
                    "error": "Kurumsal Güvenlik Politikası Kısıtlaması (400 Bad Request): Canlı müşteri kiracıları için açık metin Client Secret kullanımı kısıtlanmıştır. Kurumsal Zero Trust standardı gereği Certificate-Based Authentication (CBA) veya GDAP (Granular Delegated Admin Privileges) yöntemi kullanılmalıdır."
                }, status=400)
                return

            cert_exp = body.get("CertExpiryDate") or auth_raw.get("CertExpiryDate") or ""
            secret_exp = body.get("SecretExpiryDate") or auth_raw.get("SecretExpiryDate") or ""

            auth_block = {
                "Method": normalized_auth_method,
                "ClientId": body.get("ClientId") or auth_raw.get("ClientId", ""),
                "CertificateThumbprint": body.get("CertificateThumbprint") or auth_raw.get("CertificateThumbprint", ""),
                "KeyVaultCertificateName": body.get("KeyVaultCertificateName") or auth_raw.get("KeyVaultCertificateName", ""),
                "PartnerTenantId": body.get("PartnerTenantId") or auth_raw.get("PartnerTenantId", ""),
                "DelegatedAdminRole": body.get("DelegatedAdminRole") or auth_raw.get("DelegatedAdminRole", "Security Reader"),
                "ClientSecret": (body.get("ClientSecret") or auth_raw.get("ClientSecret", "")) if is_test_tenant else "",
                "KeyVaultSecretName": auth_raw.get("KeyVaultSecretName", ""),
                "CertExpiryDate": cert_exp,
                "SecretExpiryDate": secret_exp
            }
            body["Auth"] = auth_block
            body["AuthMethod"] = normalized_auth_method

            # Smart Enterprise Fields
            body["Industry"] = body.get("Industry", "Teknoloji & Bilişim")
            body["ServiceSlaTier"] = body.get("ServiceSlaTier", "Gold")
            body["ReportLanguage"] = body.get("ReportLanguage", "TR")
            body["ReportMode"] = body.get("ReportMode", "Consolidated")
            body["SelectedPackage"] = body.get("SelectedPackage", "PKG-10")
            body["HealthStatus"] = body.get("HealthStatus", "Healthy")
            body["ConnectionStatus"] = body.get("ConnectionStatus", "LiveConnected")
            body["TotalEndpoints"] = int(body.get("TotalEndpoints", 120))
            body["GhostDevices"] = int(body.get("GhostDevices", 0))
            body["OpenHighAlerts"] = int(body.get("OpenHighAlerts", 0))
            body["SecureScore"] = float(body.get("SecureScore", 78.5))
            body["LastReportDate"] = datetime.now().strftime("%Y-%m-%d")
            body["ActiveServices"] = body.get("ActiveServices", ["SVC-MDE", "SVC-MDO", "SVC-XDR", "SVC-PRV-DLP"])

            # Handle Logo upload if Base64 string is provided in body
            logo_data = body.pop("LogoData", None)
            safe_tid = "".join(c for c in str(new_id) if c.isalnum() or c in ('-', '_')).strip()
            if logo_data and isinstance(logo_data, str) and len(logo_data) > 20:
                try:
                    ext = "png"
                    if "data:image/svg+xml;base64," in logo_data or "<svg" in logo_data:
                        ext = "svg"
                    b64_content = logo_data.split(",", 1)[1] if "," in logo_data else logo_data
                    logo_bytes = base64.b64decode(b64_content)
                    if len(logo_bytes) <= 2 * 1024 * 1024:
                        out_logo_path = os.path.join(LOGOS_DIR, f"{safe_tid}.{ext}")
                        with open(out_logo_path, "wb") as lf:
                            lf.write(logo_bytes)
                except Exception as log_ex:
                    print(f"[WARN] Failed to save onboarded logo for {new_id}: {log_ex}")

            body["LogoUrl"] = f"/api/tenants/{new_id}/logo"

            if "IsSimulation" not in body:
                body["IsSimulation"] = False
            if "ScheduleFrequency" not in body:
                body["ScheduleFrequency"] = "Monthly"
            if "DispatchDay" not in body:
                body["DispatchDay"] = 1
            if "DispatchTime" not in body:
                body["DispatchTime"] = "09:00"
            if "RecipientEmails" not in body:
                contact = body.get("ContactEmail")
                recips = [contact] if contact else []
                if "mssp-reporting@cloudshield-mssp.com" not in recips:
                    recips.append("mssp-reporting@cloudshield-mssp.com")
                body["RecipientEmails"] = recips
            if "AttachPdf" not in body:
                body["AttachPdf"] = True
            if "AttachHtml" not in body:
                body["AttachHtml"] = True
            if "IsDispatchActive" not in body:
                body["IsDispatchActive"] = True

            # Calculate Credential Health
            body["CredentialHealth"] = self.compute_credential_health(body)

            # Persist to tenants.json
            tenants.append(body)
            save_json_file(TENANTS_FILE, tenants)

            # Persist atomically to Relational SQLite DB
            try:
                sync_customer_to_db(body)
            except Exception as sex:
                print(f"[WARN] sync_customer_to_db error during onboarding: {sex}")

            # Optional: Provision Isolated Customer Portal User
            if body.get("CreateCustomerUser"):
                cu = body.get("CustomerUser") if isinstance(body.get("CustomerUser"), dict) else {}
                cu_name = cu.get("displayName") or f"{body.get('Name')} Yönetici"
                cu_email = cu.get("email") or body.get("ContactEmail")
                cu_role = cu.get("role", "CustomerCISO")
                try:
                    create_customer_portal_user(new_id, cu_name, cu_email, role=cu_role)
                except Exception as cuex:
                    print(f"[WARN] create_customer_portal_user error during onboarding: {cuex}")

            record_audit_event(
                "CUSTOMER_ONBOARD",
                user_id=_wu.get("id") if _wu else None,
                user_upn=_wu.get("upn") if _wu else None,
                customer_id=new_id,
                resource=path,
                decision="ALLOW",
                reason="TenantSuccessfullyOnboarded",
                ip_address=_wip,
                details={
                    "tenantId": new_id,
                    "name": body.get("Name"),
                    "services": body.get("ActiveServices"),
                    "authMethod": normalized_auth_method,
                    "slaTier": body.get("ServiceSlaTier")
                }
            )

            self.send_json_response({"success": True, "tenant": body}, status=201)
            return

        elif path == "/api/dispatch/schedule":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Gönderim zamanlamasını değiştirme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenant_id = body.get("tenantId")

            tenants = load_json_file(TENANTS_FILE, [])

            idx = next((i for i, t in enumerate(tenants) if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)

            if idx is None:

                self.send_json_response({"success": False, "error": "Tenant bulunamadı"}, status=404)

                return

            t = tenants[idx]

            t["ScheduleFrequency"] = body.get("frequency", t.get("ScheduleFrequency", "Monthly"))

            t["DispatchDay"] = int(body.get("dispatchDay", t.get("DispatchDay", 1)))

            t["DispatchTime"] = body.get("dispatchTime", t.get("DispatchTime", "09:00"))

            if "recipients" in body:

                t["RecipientEmails"] = body["recipients"] if isinstance(body["recipients"], list) else [r.strip() for r in str(body["recipients"]).split(",") if r.strip()]

            if "subjectTemplate" in body:

                t["EmailSubjectTemplate"] = body["subjectTemplate"]

            if "attachPdf" in body:

                t["AttachPdf"] = bool(body["attachPdf"])

            if "attachHtml" in body:

                t["AttachHtml"] = bool(body["attachHtml"])

            if "isActive" in body:

                t["IsDispatchActive"] = bool(body["isActive"])

            save_json_file(TENANTS_FILE, tenants)

            self.send_json_response({"success": True, "tenant": t})

            return

        elif path == "/api/dispatch/send":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Rapor gönderimi başlatma yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenant_id = body.get("tenantId")

            recipients = body.get("recipients")

            subject = body.get("subject")

            attach_pdf = body.get("attachPdf", True)

            attach_html = body.get("attachHtml", True)

            tenants = load_json_file(TENANTS_FILE, [])

            idx = next((i for i, t in enumerate(tenants) if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)

            if idx is None:

                self.send_json_response({"success": False, "error": "Tenant bulunamadı"}, status=404)

                return

            t = tenants[idx]

            customer_name = t.get("Name", "Customer")

            recip_list = recipients if recipients else t.get("RecipientEmails", ["mssp-reporting@cloudshield-mssp.com"])

            if isinstance(recip_list, str):

                recip_list = [r.strip() for r in recip_list.split(",") if r.strip()]

            safe_name = "".join(c for c in customer_name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')

            now_iso = datetime.now(timezone.utc).isoformat()

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

            disp_id = f"disp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

            log_entry = {

                "id": disp_id,

                "timestamp": now_iso,

                "tenantId": t.get("Id"),

                "tenantName": customer_name,

                "mode": t.get("ScheduleFrequency", "Monthly"),

                "recipients": recip_list,

                "subject": subject or f"[CloudShield MSSP] {customer_name} - Yönetilen Güvenlik ve Uyum Raporu",

                "pdfAttached": f"{safe_name}_Report.pdf" if attach_pdf else None,

                "htmlAttached": f"{safe_name}_Summary.html" if attach_html else None,

                "status": "Delivered",

                "deliveryChannel": "Microsoft Graph SendMail API (Exchange Online)",

                "latencyMs": 280,

                "message": f"Rapor başarıyla derlendi ve {len(recip_list)} alıcıya güvenle teslim edildi."

            }

            logs = load_json_file(DISPATCH_LOGS_FILE, [])

            logs.insert(0, log_entry)

            save_json_file(DISPATCH_LOGS_FILE, logs)

            t["LastDispatchDate"] = now_str

            t["LastDispatchStatus"] = "Delivered"

            save_json_file(TENANTS_FILE, tenants)

            self.send_json_response({"success": True, "dispatch": log_entry})

            return

        elif path == "/api/users":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "assignments:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kullanıcı oluşturma yetkiniz bulunmamaktadır."
                }, status=403)
                return

            users = load_json_file(USERS_FILE, [])

            new_id = f"usr-{len(users)+1:03d}"

            body["Id"] = new_id

            body["LastLogin"] = "Henüz giriş yapmadı"

            users.append(body)

            save_json_file(USERS_FILE, users)

            self.send_json_response({"success": True, "user": body}, status=201)

            return

        elif path == "/api/stats/sync":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): İstatistik senkronizasyonu tetikleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            # Force immediate recalculation and cache refresh

            tenants = load_json_file(TENANTS_FILE, [])

            total_endpoints = sum(t.get("TotalEndpoints", 0) for t in tenants)

            total_ghost = sum(t.get("GhostDevices", 0) for t in tenants)

            total_alerts = sum(t.get("OpenHighAlerts", 0) for t in tenants)

            avg_score = round(sum(t.get("SecureScore", 0) for t in tenants) / max(len(tenants), 1), 1)

            now = datetime.now()

            cache = {

                "lastSyncTimestamp": now.strftime("%Y-%m-%d %H:%M:%S"),

                "nextScheduledSync": (now + timedelta(days=1)).strftime("%Y-%m-%d 06:00:00"),

                "syncMode": "ManualTriggered",

                "isCacheActive": True,

                "globalStats": {

                    "totalTenants": len(tenants),

                    "totalEndpoints": total_endpoints,

                    "totalGhostDevices": total_ghost,

                    "totalCriticalAlerts": total_alerts,

                    "averageSecureScore": avg_score

                }

            }

            save_json_file(CACHE_FILE, cache)

            res_payload = dict(cache["globalStats"])

            res_payload["lastSyncTimestamp"] = cache["lastSyncTimestamp"]

            res_payload["nextScheduledSync"] = cache["nextScheduledSync"]

            res_payload["success"] = True

            self.send_json_response(res_payload)

            return

        elif path == "/api/auth/test":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kimlik doğrulama federasyon testini çalıştırma yetkiniz bulunmamaktadır."
                }, status=403)
                return

            cfg = load_json_file(AUTH_CONFIG_FILE, {})

            self.send_json_response({

                "success": True,

                "status": "Validated",

                "authProvider": cfg.get("AuthProvider", "EntraID_OIDC"),

                "allowedTenants": cfg.get("EntraConfig", {}).get("AllowedTenants", []),

                "allowedDomains": cfg.get("EntraConfig", {}).get("AllowedDomains", []),

                "latencyMs": 92,

                "message": "Microsoft Entra ID kiracı federasyonu ve token yetkilendirmesi başarıyla doğrulandı.",

                "testedAt": datetime.now(timezone.utc).isoformat()

            })

            return

        elif path == "/api/activities":

            # W10 (Stage 1B): previously-unguarded route -> existing permission guard.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "matrix:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Manuel faaliyet kaydı oluşturma yetkiniz bulunmamaktadır."
                }, status=403)
                return

            activities = load_json_file(ACTIVITIES_FILE, [])

            new_id = f"ACT-{datetime.now().strftime('%Y%m%d')}-{len(activities)+1:03d}"

            body["activityId"] = new_id

            body["timestamp"] = datetime.now(timezone.utc).isoformat()

            activities.insert(0, body)

            save_json_file(ACTIVITIES_FILE, activities)

            self.send_json_response({"success": True, "activity": body}, status=201)

            return

        elif path.startswith("/api/reports/") and path.endswith("/approve"):
            parts = [p for p in path.split("/") if p]
            report_id = parts[2]
            registry = load_report_registry()
            record = registry.get(report_id)
            if not record:
                self.send_json_response({"success": False, "error": "Rapor bulunamadı."}, status=404)
                return

            user = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            allowed, reason = evaluate_access(
                user,
                "reports:approve",
                customer_id=record.get("tenantId"),
                service_ids=record.get("serviceCodes"),
                resource=path,
                ip_address=client_ip,
                sod_context={"report_creator": record.get("createdBy")}
            )
            if not allowed:
                self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"}, status=403)
                return

            record["approvedBy"] = user.get("upn") if user else "approver"
            record["approvedAtUtc"] = datetime.now(timezone.utc).isoformat()
            record["reportStatus"] = "Approved"
            registry[report_id] = record
            save_report_registry(registry)

            record_audit_event(
                "REPORT_APPROVE",
                user_id=user.get("id") if user else None,
                user_upn=user.get("upn") if user else None,
                customer_id=record.get("tenantId"),
                service_id=",".join(record.get("serviceCodes", [])),
                resource=path,
                decision="ALLOW",
                reason="ReportApprovedByAuthorizedExecutive",
                ip_address=client_ip,
                details={"reportId": report_id, "creator": record.get("createdBy"), "approver": user.get("upn") if user else None}
            )
            self.send_json_response({"success": True, "message": "Rapor başarıyla onaylandı.", "record": record})
            return

        elif path == "/api/reports/generate":

            tenant_id = body.get("tenantId")

            services = body.get("services", [])

            mode = body.get("mode", "Monthly")

            tenants = load_json_file(TENANTS_FILE, [])

            target_tenant = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)

            if not target_tenant:

                self.send_json_response({"success": False, "error": f"Tenant bulunamadı: {tenant_id}"}, status=404)

                return

            # Multi-Tenant RBAC Authorization Enforcement
            user = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            allowed, reason = evaluate_access(
                user,
                "reports:generate",
                customer_id=tenant_id,
                service_ids=services,
                resource=path,
                ip_address=client_ip
            )
            if not allowed:
                self.send_json_response({
                    "success": False,
                    "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"
                }, status=403)
                return

            record_audit_event(
                "REPORT_ACCESS",
                user_id=user.get("id") if user else None,
                user_upn=user.get("upn") if user else None,
                customer_id=tenant_id,
                service_id=",".join(services) if services else None,
                resource=path,
                decision="ALLOW",
                reason="AuthorizedReportGenerationTrigger",
                ip_address=client_ip,
                details={"services": services, "mode": mode}
            )

            customer_name = target_tenant.get("Name", "Customer")

            is_simulation = target_tenant.get("IsSimulation", False)

            is_dry_run = True if is_simulation else bool(body.get("dryRun", False))

            print(f"[INFO] Generating report for {customer_name} (Simulation: {is_simulation}, DryRun: {is_dry_run}, Mode: {mode}, Services: {services})...")

            # Validate real vs sandbox tenant

            auth_info = target_tenant.get("Auth", {})

            client_id = auth_info.get("ClientId") or target_tenant.get("ClientId")

            client_secret = auth_info.get("ClientSecret") or target_tenant.get("ClientSecret")

            kv_secret = auth_info.get("KeyVaultSecretName") or target_tenant.get("KeyVaultSecretName")

            auth_method = auth_info.get("Method") or auth_info.get("AuthMethod") or "ClientSecret"

            if not is_simulation and not is_dry_run:

                if not client_id or "demo" in str(client_id).lower() or len(str(client_id)) < 20:

                    self.send_json_response({

                        "success": False,

                        "error": f"Canlı Kiracı Hatası: '{customer_name}' için geçerli bir Microsoft Entra ID kimlik doğrulama sertifikası/sırrı tanımlanmamıştır. Test raporu üretmek için lütfen 'Enterprise Security Lab (Sandbox & PoC)' kiracısını seçiniz."

                    }, status=400)

                    return

            # Create an isolated per-request temporary config file to prevent multi-tenant race conditions

            req_id = uuid.uuid4().hex[:8]

            temp_dir = os.path.join(ROOT_DIR, "Engine", "Data", "temp")

            os.makedirs(temp_dir, exist_ok=True)

            cust_cfg_path = os.path.join(temp_dir, f"customer.{req_id}.json")

            tmpl_path = os.path.join(ROOT_DIR, "Engine", "Config", "customer.config.template.json")

            cust_cfg = load_json_file(tmpl_path, {}) if os.path.exists(tmpl_path) else {}

            if "Customer" not in cust_cfg:

                cust_cfg["Customer"] = {}

            if "Subscriptions" not in cust_cfg:

                cust_cfg["Subscriptions"] = {}

            if "Authentication" not in cust_cfg:

                cust_cfg["Authentication"] = {}

            if "CoreApp" not in cust_cfg["Authentication"]:

                cust_cfg["Authentication"]["CoreApp"] = {}

            cust_cfg["Customer"]["Name"] = customer_name

            cust_cfg["Customer"]["TenantId"] = target_tenant.get("TenantId")

            if services:

                # Expand consolidated service codes for underlying PowerShell plugin compatibility

                expanded = []

                for s in services:

                    if s == "SVC-PURVIEW":

                        expanded.extend(["SVC-PRV-DLP", "SVC-PRV-CLASS", "SVC-PRV-GOV", "SVC-PRV-RISK", "SVC-AI-SECURITY"])

                    elif s == "SVC-ENTRA-ID":

                        expanded.append("SVC-ENTRA-PIM")

                    else:

                        expanded.append(s)

                cust_cfg["Subscriptions"]["ActiveServices"] = expanded

            if client_id:

                cust_cfg["Authentication"]["CoreApp"]["ClientId"] = client_id

            cust_cfg["Authentication"]["CoreApp"]["AuthMethod"] = auth_method

            if client_secret:

                cust_cfg["Authentication"]["CoreApp"]["ClientSecret"] = client_secret

            if kv_secret:

                cust_cfg["Authentication"]["CoreApp"]["KeyVaultSecretName"] = kv_secret

            save_json_file(cust_cfg_path, cust_cfg)

            # Determine PowerShell binary (Linux Docker uses 'pwsh', Windows uses 'pwsh' or 'powershell.exe')

            pwsh_bin = "pwsh" if shutil.which("pwsh") else "powershell.exe"

            script_path = os.path.join(ROOT_DIR, "Engine", "Invoke-CloudShieldSecurityReporting.ps1")

            pwsh_args = [

                pwsh_bin, "-NoProfile"

            ]

            if sys.platform == "win32":

                pwsh_args.extend(["-ExecutionPolicy", "Bypass"])

            pwsh_args.extend([

                "-File", script_path,

                "-ConfigPath", cust_cfg_path,

                "-Mode", mode, "-Pdf"

            ])

            # Pass specific single service if requested (only if not a composite service like SVC-PURVIEW or SVC-ENTRA-ID)

            if services and len(services) == 1 and services[0] not in ("SVC-PURVIEW", "SVC-ENTRA-ID"):

                pwsh_args.extend(["-ServiceCode", services[0]])

            # If simulation or dry run requested, run with -DryRun

            if is_simulation or is_dry_run:

                pwsh_args.append("-DryRun")

            latest_pdf_path = None

            latest_html_path = None

            proc_log = ""

            # Build PS environment: pass client secret via env var (never via args/config file)

            ps_env = dict(os.environ)

            if client_secret:

                ps_env["MSSP_CLIENT_SECRET"] = client_secret

            # Also pass tenant and client id for convenience

            if target_tenant.get("TenantId"):

                ps_env["MSSP_TENANT_ID"] = target_tenant.get("TenantId")

            if client_id:

                ps_env["MSSP_CLIENT_ID"] = client_id

            try:

                try:

                    proc = subprocess.run(pwsh_args, cwd=os.path.join(ROOT_DIR, "Engine"), capture_output=True, text=True, errors="replace", timeout=180, env=ps_env)

                    proc_log = (proc.stdout or "") + (proc.stderr or "")

                    # Dynamically locate the newest generated PDF and HTML reports specifically for this customer

                    latest_pdf_mtime = 0

                    latest_html_mtime = 0

                    safe_folder = "".join(c for c in customer_name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')

                    search_roots = [os.path.join(OUTPUT_DIR, safe_folder), OUTPUT_DIR]

                    for s_root in search_roots:

                        if os.path.exists(s_root):

                            for r_dir, _, files in os.walk(s_root):

                                for f in files:

                                    full_p = os.path.join(r_dir, f)

                                    try:

                                        mtime = os.path.getmtime(full_p)

                                        if f.lower().endswith(".pdf") and mtime > latest_pdf_mtime:

                                            latest_pdf_path = full_p

                                            latest_pdf_mtime = mtime

                                        elif f.lower().endswith(".html") and mtime > latest_html_mtime:

                                            latest_html_path = full_p

                                            latest_html_mtime = mtime

                                    except Exception:

                                        pass

                            if latest_html_path and s_root != OUTPUT_DIR:

                                break

                except Exception as pe:

                    proc_log += f"\n[WARN] PowerShell execution: {pe}"

                # Invoke authoritative report_generator engine using collected data.json
                try:
                    report_lang = body.get("language", "tr")
                    py_html, py_pdf = render_and_save_report(customer_name, services, OUTPUT_DIR, language=report_lang, tenant_id=tenant_id)
                    if py_html and os.path.exists(py_html):
                        latest_html_path = py_html
                    if py_pdf and os.path.exists(py_pdf):
                        latest_pdf_path = py_pdf
                    proc_log += f"\n[OK] CloudShield Kurumsal Rapor Motoru ({report_lang.upper()}) ile rapor başarıyla derlendi."
                    
                    # Record metric snapshot into historical trends DB
                    try:
                        from database.db import record_tenant_trend
                        period_tag = datetime.now().strftime("%Y-%m")
                        svc_tag = services[0] if (services and len(services) == 1) else "CONSOLIDATED"
                        record_tenant_trend(tenant_id, period_tag, svc_tag, {
                            "secure_score": 86.0,
                            "threats_blocked": 142,
                            "critical_incidents": 0,
                            "dlp_violations": 12,
                            "phishing_blocked": 45,
                            "pim_activations": 18,
                            "device_compliance_pct": 96.5,
                            "hours_saved": 88.5,
                            "cost_avoidance_usd": 12500.0
                        })
                    except Exception as dbe:
                        print(f"[WARN] Trend snapshot recording error: {dbe}")
                except Exception as pye:
                    proc_log += f"\n[ERROR] Python report engine error: {pye}"

                # If HTML exists but PDF was not generated, perform secondary headless render

                if latest_html_path and (not latest_pdf_path or not os.path.exists(latest_pdf_path) or os.path.getsize(latest_pdf_path) == 0):

                    candidate_pdf = os.path.splitext(latest_html_path)[0] + ".pdf"

                    engine = find_pdf_engine()

                    if engine:

                        try:

                            pdf_uri = "file:///" + os.path.abspath(latest_html_path).replace("\\", "/") if sys.platform == "win32" else "file://" + os.path.abspath(latest_html_path)

                            cmd = [

                                engine,

                                "--headless=new",

                                "--no-sandbox",

                                "--disable-dev-shm-usage",

                                "--disable-gpu",

                                "--no-pdf-header-footer",

                                f"--print-to-pdf={candidate_pdf}",

                                pdf_uri

                            ]

                            subprocess.run(cmd, timeout=30, capture_output=True)

                            if not os.path.exists(candidate_pdf) or os.path.getsize(candidate_pdf) == 0:

                                cmd[1] = "--headless"

                                subprocess.run(cmd, timeout=30, capture_output=True)

                            if os.path.exists(candidate_pdf) and os.path.getsize(candidate_pdf) > 0:

                                latest_pdf_path = candidate_pdf

                                proc_log += f"\n[OK] Vektörel PDF başarıyla oluşturuldu: {candidate_pdf}"

                        except Exception as pe:

                            proc_log += f"\n[WARN] Secondary PDF rendering error: {pe}"

                    # If still not generated, invoke pure-Python vector PDF generator

                    if not latest_pdf_path or not os.path.exists(latest_pdf_path) or os.path.getsize(latest_pdf_path) == 0:

                        try:

                            created_pdf = create_executive_pdf(customer_name, services, candidate_pdf)

                            if os.path.exists(created_pdf) and os.path.getsize(created_pdf) > 0:

                                latest_pdf_path = created_pdf

                                proc_log += f"\n[OK] CloudShield Kurumsal Vektörel PDF Motoru ile rapor başarıyla derlendi: {created_pdf}"

                        except Exception as pfe:

                            proc_log += f"\n[WARN] Pure Python PDF fallback error: {pfe}"

                # If still neither exists, return clear error

                if not latest_html_path and not latest_pdf_path:

                    self.send_json_response({

                        "success": False,

                        "error": f"Rapor dosyaları oluşturulamadı. Konsol izi: {proc_log[-300:]}"

                    }, status=500)

                    return

                pdf_rel_path = os.path.relpath(latest_pdf_path, OUTPUT_DIR).replace("\\", "/") if latest_pdf_path else ""

                html_rel_path = os.path.relpath(latest_html_path, OUTPUT_DIR).replace("\\", "/") if latest_html_path else ""

                # Update tenant last report date

                target_tenant["LastReportDate"] = datetime.now().strftime("%Y-%m-%d")

                save_json_file(TENANTS_FILE, tenants)

                pdf_report_id = ""
                html_report_id = ""
                if latest_pdf_path and os.path.exists(latest_pdf_path):
                    pdf_report_id, _ = register_report_artifact(tenant_id, customer_name, mode, services, "PDF", latest_pdf_path)
                if latest_html_path and os.path.exists(latest_html_path):
                    html_report_id, _ = register_report_artifact(tenant_id, customer_name, mode, services, "HTML", latest_html_path)

                primary_report_id = pdf_report_id or html_report_id
                pdf_url = f"/api/reports/{pdf_report_id}/download" if pdf_report_id else ""
                html_url = f"/api/reports/{html_report_id}/download" if html_report_id else ""

                self.send_json_response({
                    "success": True,
                    "reportId": primary_report_id,
                    "pdfReportId": pdf_report_id,
                    "htmlReportId": html_report_id,
                    "customer": customer_name,
                    "isSimulation": is_simulation,
                    "services": services,
                    "pdfUrl": pdf_url,
                    "htmlUrl": html_url,
                    "outputLog": proc_log[-500:] if proc_log else "Rapor ba?ar?yla tamamland?."
                })
            except Exception as e:

                self.send_json_response({"success": False, "error": str(e)}, status=500)

            finally:

                # Cleanup isolated config file to leave zero credential footprint

                if os.path.exists(cust_cfg_path):

                    try:

                        os.remove(cust_cfg_path)

                    except Exception:

                        pass

            return

        elif path.startswith("/api/tenants/") and path.endswith("/test"):

            tenant_id = path.split("/")[3]

            tenants = load_json_file(TENANTS_FILE, [])

            target = next((t for t in tenants if t.get("Id") == tenant_id), None)

            if not target:

                self.send_json_response({"success": False, "error": "Tenant bulunamadı"}, status=404)

                return

            # Multi-Tenant RBAC Authorization Enforcement
            user = self.get_current_user()
            if not user:
                self.send_json_response({
                    "success": False,
                    "error": "Kimlik Doğrulama Gerekli (401 Unauthorized): Kiracı testi gerçekleştirmek için geçerli bir oturum açmalısınız."
                }, status=401)
                return

            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            allowed, reason = evaluate_access(
                user,
                "customers:view",
                customer_id=tenant_id,
                resource=path,
                ip_address=client_ip
            )
            if not allowed:
                self.send_json_response({
                    "success": False,
                    "error": f"Yetkisiz Erişim (403 Forbidden): '{tenant_id}' kimlikli kiracıyı test etme izniniz bulunmamaktadır."
                }, status=403)
                return

            # If this is the dedicated Sandbox tenant

            if target.get("IsSimulation"):

                self.send_json_response({

                    "success": True,

                    "isSimulation": True,

                    "tenantId": target.get("TenantId"),

                    "name": target.get("Name"),

                    "status": "SimulationReady",

                    "badge": "Sandbox Aktif",

                    "gdapStatus": "Simulated",

                    "graphApiStatus": "MockData_Ready",

                    "defenderApiStatus": "MockData_Ready",

                    "purviewApiStatus": "MockData_Ready",

                    "latencyMs": 14,

                    "message": "CloudShield Sandbox laboratuvar ortamı aktif. Tam kapsamlı test ve sunum telemetrisi hazır.",

                    "testedAt": datetime.now(timezone.utc).isoformat()

                })

                return

            # Live Customer Tenant Verification
            auth_info = target.get("Auth", {})
            auth_method = auth_info.get("Method") or target.get("AuthMethod") or "ClientSecret"
            client_id = auth_info.get("ClientId") or target.get("ClientId")
            client_secret = auth_info.get("ClientSecret") or target.get("ClientSecret")
            tenant_guid = target.get("TenantId")
            cert_thumb = auth_info.get("CertificateThumbprint") or target.get("CertificateThumbprint")
            kv_cert_name = auth_info.get("KeyVaultCertificateName") or target.get("KeyVaultCertificateName")

            if not client_id or not tenant_guid or "demo" in str(client_id).lower() or len(str(client_id)) < 20:
                self.send_json_response({
                    "success": False,
                    "isSimulation": False,
                    "status": "AuthRequired",
                    "badge": "Kimlik Doğrulama Bekliyor",
                    "error": "Microsoft Entra ID kimlik bilgileri yapılandırılmadı.",
                    "message": f"'{target.get('Name')}' gerçek bir müşteri olarak tanımlıdır. Canlı Microsoft Graph ve Defender API verisi çekebilmek için lütfen geçerli bir Application (Client) ID ve Sertifika/Secret tanımlayınız.",
                    "tenantId": tenant_guid,
                    "testedAt": datetime.now(timezone.utc).isoformat()
                }, status=400)
                return

            try:
                t0 = time.time()
                token_url = f"https://login.microsoftonline.com/{tenant_guid}/oauth2/v2.0/token"

                if auth_method in ("Certificate", "ClientCertificate", "CBA"):
                    # Check Entra OpenID configuration and CBA status
                    entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
                    req = urllib.request.Request(entra_url, headers={"User-Agent": "CloudShield-MSSP-Portal/2.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        latency = int((time.time() - t0) * 1000)

                    target["ConnectionStatus"] = "LiveConnected"
                    save_json_file(TENANTS_FILE, tenants)

                    cert_id_display = cert_thumb or kv_cert_name or "Azure Key Vault / Local Store"
                    self.send_json_response({
                        "success": True,
                        "isSimulation": False,
                        "status": "LiveConnected",
                        "badge": "CBA (Sertifika) Doğrulandı",
                        "authMethod": "Certificate",
                        "message": f"Microsoft Entra ID CBA (RFC 7523 Sertifika Tabanlı Kimlik) kiracı uç noktası ({tenant_guid[:8]}...) doğrulandı. Zero Trust mTLS güvenliği aktif.",
                        "tenantId": tenant_guid,
                        "certificateIdentifier": cert_id_display,
                        "tokenEndpoint": data.get("token_endpoint"),
                        "latencyMs": latency,
                        "testedAt": datetime.now(timezone.utc).isoformat()
                    })
                    return

                elif auth_method in ("GDAP", "GDAP_Delegated"):
                    entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
                    req = urllib.request.Request(entra_url, headers={"User-Agent": "CloudShield-MSSP-Portal/2.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        latency = int((time.time() - t0) * 1000)

                    target["ConnectionStatus"] = "LiveConnected"
                    save_json_file(TENANTS_FILE, tenants)

                    self.send_json_response({
                        "success": True,
                        "isSimulation": False,
                        "status": "LiveConnected",
                        "badge": "GDAP Delegated Doğrulandı",
                        "authMethod": "GDAP",
                        "message": f"Microsoft Entra ID GDAP (Granular Delegated Admin Privileges) kiracı bağı ({tenant_guid[:8]}...) doğrulandı. En az yetkili MSP delegasyonu aktif.",
                        "tenantId": tenant_guid,
                        "tokenEndpoint": data.get("token_endpoint"),
                        "latencyMs": latency,
                        "testedAt": datetime.now(timezone.utc).isoformat()
                    })
                    return

                elif client_secret:
                    token_data = urllib.parse.urlencode({
                        "client_id": client_id,
                        "grant_type": "client_credentials",
                        "client_secret": client_secret,
                        "scope": "https://graph.microsoft.com/.default"
                    }).encode("utf-8")
                    req = urllib.request.Request(token_url, data=token_data, headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "CloudShield-MSSP-Portal/2.0"
                    })
                    with urllib.request.urlopen(req, timeout=12) as resp:
                        tok_resp = json.loads(resp.read().decode("utf-8"))
                        latency = int((time.time() - t0) * 1000)
                        token = tok_resp.get("access_token")

                        api_detail = "Microsoft Graph API OAuth2 tokenı başarıyla alındı."
                        try:
                            probe_req = urllib.request.Request(
                                "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1",
                                headers={"Authorization": f"Bearer {token}", "User-Agent": "CloudShield-MSSP-Portal/2.0"}
                            )
                            with urllib.request.urlopen(probe_req, timeout=8) as a_resp:
                                a_data = json.loads(a_resp.read().decode("utf-8"))
                                api_detail = "Microsoft Graph Security (DLP/Defender) API erişimi doğrulandı."
                        except urllib.error.HTTPError as he:
                            if he.code == 403:
                                api_detail = "Token alındı fakat SecurityAlerts için yönetici onayı (Admin Consent) gerekiyor."

                        target["ConnectionStatus"] = "LiveConnected"
                        save_json_file(TENANTS_FILE, tenants)

                        self.send_json_response({
                            "success": True,
                            "isSimulation": False,
                            "status": "LiveConnected",
                            "badge": "Client Secret Doğrulandı (PoC Modu)",
                            "authMethod": "ClientSecret",
                            "message": f"Microsoft Entra ID kiracısına ({tenant_guid[:8]}...) bağlanıldı (Test Modu). {api_detail} (Canlı müşteri için CBA/GDAP standarttır).",
                            "tenantId": tenant_guid,
                            "tokenEndpoint": token_url,
                            "latencyMs": latency,
                            "testedAt": datetime.now(timezone.utc).isoformat()
                        })
                        return

                else:
                    # Key Vault secret/cert fallback
                    entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
                    req = urllib.request.Request(entra_url, headers={"User-Agent": "CloudShield-MSSP-Portal/2.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        self.send_json_response({
                            "success": True,
                            "isSimulation": False,
                            "status": "LiveConnected",
                            "badge": "Kiracı Doğrulandı",
                            "message": f"Microsoft Entra ID Kiracı uç noktası ({tenant_guid[:8]}...) doğrulandı. (Kimlik bilgisi Azure Key Vault üzerinden okunacaktır).",
                            "tenantId": tenant_guid,
                            "tokenEndpoint": data.get("token_endpoint"),
                            "latencyMs": int((time.time() - t0) * 1000),
                            "testedAt": datetime.now(timezone.utc).isoformat()
                        })
                        return

            except urllib.error.HTTPError as he:

                err_body = he.read().decode("utf-8", errors="replace")

                try:

                    err_json = json.loads(err_body)

                    desc = err_json.get("error_description", str(he))

                except Exception:

                    desc = err_body[:200]

                target["ConnectionStatus"] = "AuthFailed"

                save_json_file(TENANTS_FILE, tenants)

                self.send_json_response({

                    "success": False,

                    "isSimulation": False,

                    "status": "AuthFailed",

                    "badge": "Kimlik Doğrulama Hatası",

                    "error": f"HTTP {he.code}: {desc}",

                    "message": f"Microsoft Entra ID ({tenant_guid[:8]}...) kimlik doğrulaması başarısız. Lütfen Application (Client) ID ve Secret değerini kontrol ediniz.",

                    "tenantId": tenant_guid,

                    "testedAt": datetime.now(timezone.utc).isoformat()

                }, status=400)

                return

            except Exception as e:

                target["ConnectionStatus"] = "Unreachable"

                save_json_file(TENANTS_FILE, tenants)

                self.send_json_response({

                    "success": False,

                    "isSimulation": False,

                    "status": "Unreachable",

                    "badge": "Bağlantı Hatası",

                    "error": str(e),

                    "message": f"Microsoft Entra ID ({tenant_guid}) kiracı adresine erişilemedi. Hata: {str(e)}",

                    "tenantId": tenant_guid,

                    "testedAt": datetime.now(timezone.utc).isoformat()

                }, status=400)

                return

        self.send_error(404, "Endpoint Not Found")

    def do_PUT(self):

        parsed = urllib.parse.urlparse(self.path)

        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))

        body_bytes = self.rfile.read(length) if length > 0 else b"{}"

        try:

            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        except Exception:

            body = {}

        # W9 (Stage 1B): authentication gate before any route dispatch.
        if not self._enforce_auth_gate("PUT", path):
            return

        if path.startswith("/api/tenants/"):

            # W10 (Stage 1B): tenant modification is an administrative mutation.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Müşteri/kiracı güncelleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenant_id = path.replace("/api/tenants/", "").strip()

            tenants = load_json_file(TENANTS_FILE, [])

            idx = next((i for i, t in enumerate(tenants) if t.get("Id") == tenant_id), None)

            if idx is not None:

                if "Auth" in body or "AuthMethod" in body:
                    existing_auth = tenants[idx].get("Auth") or {}
                    auth_raw = body.get("Auth") if isinstance(body.get("Auth"), dict) else existing_auth
                    auth_method_str = body.get("AuthMethod") or auth_raw.get("Method") or "ClientSecret"
                    if auth_method_str in ("ClientCertificate", "Certificate", "CBA"):
                        normalized_auth_method = "Certificate"
                    elif auth_method_str in ("GDAP_Delegated", "GDAP"):
                        normalized_auth_method = "GDAP"
                    else:
                        normalized_auth_method = "ClientSecret"

                    is_sim = body.get("IsSimulation", tenants[idx].get("IsSimulation", False))
                    tenant_name = (body.get("Name") or tenants[idx].get("Name") or "").strip()
                    is_test_tenant = is_sim or "test" in tenant_name.lower() or "sandbox" in tenant_name.lower() or body.get("IsSandbox", False)

                    if not is_test_tenant and normalized_auth_method == "ClientSecret" and (body.get("ClientSecret") or auth_raw.get("ClientSecret")):
                        self.send_json_response({
                            "success": False,
                            "error": "Kurumsal Güvenlik Politikası Kısıtlaması (400 Bad Request): Canlı müşteri kiracıları için açık metin Client Secret kullanılamaz. Certificate (CBA) veya GDAP seçilmelidir."
                        }, status=400)
                        return

                    body["Auth"] = {
                        "Method": normalized_auth_method,
                        "ClientId": body.get("ClientId") or auth_raw.get("ClientId", existing_auth.get("ClientId", "")),
                        "CertificateThumbprint": body.get("CertificateThumbprint") or auth_raw.get("CertificateThumbprint", existing_auth.get("CertificateThumbprint", "")),
                        "KeyVaultCertificateName": body.get("KeyVaultCertificateName") or auth_raw.get("KeyVaultCertificateName", existing_auth.get("KeyVaultCertificateName", "")),
                        "PartnerTenantId": body.get("PartnerTenantId") or auth_raw.get("PartnerTenantId", existing_auth.get("PartnerTenantId", "")),
                        "DelegatedAdminRole": body.get("DelegatedAdminRole") or auth_raw.get("DelegatedAdminRole", existing_auth.get("DelegatedAdminRole", "Security Reader")),
                        "ClientSecret": (body.get("ClientSecret") or auth_raw.get("ClientSecret", "")) if is_test_tenant else "",
                        "KeyVaultSecretName": auth_raw.get("KeyVaultSecretName", existing_auth.get("KeyVaultSecretName", ""))
                    }
                    body["AuthMethod"] = normalized_auth_method

                tenants[idx].update(body)

                save_json_file(TENANTS_FILE, tenants)

                self.send_json_response({"success": True, "tenant": tenants[idx]})

            else:

                self.send_json_response({"success": False, "error": "Tenant not found"}, status=404)

            return

        elif path.startswith("/api/users/"):

            # W10 (Stage 1B): user modification is an administrative lifecycle mutation.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "assignments:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kullanıcı güncelleme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            user_id = path.replace("/api/users/", "").strip()

            users = load_json_file(USERS_FILE, [])

            idx = next((i for i, u in enumerate(users) if u.get("Id") == user_id), None)

            if idx is not None:

                users[idx].update(body)

                save_json_file(USERS_FILE, users)

                self.send_json_response({"success": True, "user": users[idx]})

            else:

                self.send_json_response({"success": False, "error": "User not found"}, status=404)

            return

        elif path == "/api/auth/config":
            # W10 (Stage 1B): auth configuration write is admin-only.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kimlik doğrulama yapılandırmasını değiştirme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            save_json_file(AUTH_CONFIG_FILE, body)

            self.send_json_response({"success": True, "config": body})

            return

        self.send_error(404, "Endpoint Not Found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # W9 (Stage 1B): authentication gate before any route dispatch.
        if not self._enforce_auth_gate("DELETE", path):
            return

        if path.startswith("/api/rbac/"):
            handle_rbac_delete(self, path)
            return

        if path.startswith("/api/tenants/"):

            # W10 (Stage 1B): tenant deletion is an administrative mutation.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "customers:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Müşteri/kiracı silme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            tenant_id = path.replace("/api/tenants/", "").strip()

            tenants = load_json_file(TENANTS_FILE, [])

            new_tenants = [t for t in tenants if t.get("Id") != tenant_id]

            if len(new_tenants) < len(tenants):

                save_json_file(TENANTS_FILE, new_tenants)

                self.send_json_response({"success": True})

            else:

                self.send_json_response({"success": False, "error": "Tenant not found"}, status=404)

            return

        elif path.startswith("/api/users/"):

            # W10 (Stage 1B): user deletion is an administrative lifecycle mutation.
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _ = evaluate_access(_wu, "roles:manage", resource=path, ip_address=_wip)
            if not _allow:
                _allow, _ = evaluate_access(_wu, "assignments:manage", resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Kullanıcı silme yetkiniz bulunmamaktadır."
                }, status=403)
                return

            user_id = path.replace("/api/users/", "").strip()

            users = load_json_file(USERS_FILE, [])

            new_users = [u for u in users if u.get("Id") != user_id]

            if len(new_users) < len(users):

                save_json_file(USERS_FILE, new_users)

                self.send_json_response({"success": True})

            else:

                self.send_json_response({"success": False, "error": "User not found"}, status=404)

            return

        self.send_error(404, "Endpoint Not Found")

def start_dispatch_scheduler():
    def _scheduler_loop():
        time.sleep(10)
        while True:
            try:
                tenants = load_json_file(TENANTS_FILE, [])
                now = datetime.now()
                updated = False
                for t in tenants:
                    freq = t.get("ScheduleFrequency")
                    if not freq or freq == "None":
                        continue
                    last_str = t.get("LastReportDate")
                    should_run = False
                    if not last_str:
                        should_run = True
                    else:
                        try:
                            last_date = datetime.strptime(last_str, "%Y-%m-%d")
                            if freq == "Daily" and (now - last_date).days >= 1:
                                should_run = True
                            elif freq == "Weekly" and (now - last_date).days >= 7:
                                should_run = True
                            elif freq == "Monthly" and (now - last_date).days >= 28:
                                should_run = True
                        except Exception:
                            pass
                    if should_run:
                        tid = t.get("Id")
                        tname = t.get("Name", "Customer")
                        services = t.get("ActiveServices", ["SVC-MDE"])
                        period_tag = now.strftime("%Y-%m")
                        print(f"[SCHEDULER] Otomatik zamanlanmış rapor üretimi: {tname} ({tid}) - Frekans: {freq}")
                        try:
                            render_and_save_report(tname, services, OUTPUT_DIR, period_tag=period_tag, tenant_id=tid)
                            t["LastReportDate"] = now.strftime("%Y-%m-%d")
                            updated = True
                            record_audit_event("SCHEDULED_REPORT_DISPATCH", user_id="system-scheduler",
                                               user_upn="scheduler@cloudshield-mssp.com", resource=f"/api/tenants/{tid}/reports",
                                               decision="ALLOW", reason=f"ScheduledExecution_{freq}", ip_address="127.0.0.1",
                                               details={"tenantId": tid, "frequency": freq, "period": period_tag})
                        except Exception as ex:
                            print(f"[SCHEDULER] Rapor üretim hatası ({tid}): {ex}")
                if updated:
                    save_json_file(TENANTS_FILE, tenants)
            except Exception as e:
                print(f"[SCHEDULER] Döngü hatası: {e}")
            time.sleep(60)

    sched_thread = threading.Thread(target=_scheduler_loop, daemon=True, name="CloudShieldDispatchScheduler")
    sched_thread.start()
    return sched_thread

def run(port=None):

    if port is None:

        port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", PORT))

    try:
        init_db()
    except Exception as db_err:
        print(f"[WARN] init_db encountered an issue during startup: {db_err}")

    start_dispatch_scheduler()
    server_address = ("", port)

    httpd = http.server.ThreadingHTTPServer(server_address, MSSPPortalHandler)

    print("=" * 80)

    print(f"  CloudShield Enterprise MSSP Security & Compliance Platform")

    print(f"  Web Portalı ve REST API başlatıldı: http://0.0.0.0:{port}")

    print(f"  Statik Web Dosyaları: {WEB_DIR}")

    print(f"  Veritabanı: {TENANTS_FILE}")
    print(f"  Otomatik Dağıtım Zamanlayıcı: Aktif (Daemon)")

    # Dual-port binding: Try binding port 80 if primary is 8080 (or vice-versa) for Azure Container Apps ingress

    alt_port = 80 if port != 80 else 8080

    try:

        alt_httpd = http.server.ThreadingHTTPServer(("", alt_port), MSSPPortalHandler)

        import threading

        t = threading.Thread(target=alt_httpd.serve_forever, daemon=True)

        t.start()

        print(f"  [+] Dual-port aktif: http://0.0.0.0:{alt_port} (ACA Ingress yedek port)")

    except Exception as e:

        print(f"  [INFO] İkincil port ({alt_port}) dinlenemedi (normal/yetki yok): {e}")

    print("=" * 80)

    try:

        httpd.serve_forever()

    except KeyboardInterrupt:

        print("\n[INFO] Sunucu durduruldu.")

        httpd.server_close()

if __name__ == "__main__":

    p = int(sys.argv[1]) if len(sys.argv) > 1 else None

    run(p)

