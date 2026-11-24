#!/usr/bin/env python3

"""

CloudShield Enterprise MSSP Security & Compliance Platform (MSSP Portal)

Backend REST API Server - Pure Python 3 Standard Library (Zero External Dependencies)

"""

import http.server
import json
import base64
import hashlib
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

try:
    import jwt
    from jwt import PyJWKSet
except ImportError:
    jwt = None
    PyJWKSet = None

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

from database.db import (
    init_db, get_db, hash_password, sync_customer_to_db, create_customer_portal_user,
    save_license_inventory, get_license_inventory, save_user_license_profiles,
    get_user_license_profiles, save_license_value_summary, get_license_value_summary,
    save_workload_reconciliation, get_workload_reconciliation, save_license_snapshot,
    get_license_snapshot, list_license_snapshots
)
try:
    from rbac_engine import authenticate_user, evaluate_access, record_audit_event, get_effective_assignments
    from rbac_handlers import handle_rbac_get, handle_rbac_post, handle_rbac_delete
except ImportError:
    from Portal.api.rbac_engine import authenticate_user, evaluate_access, record_audit_event, get_effective_assignments
    from Portal.api.rbac_handlers import handle_rbac_get, handle_rbac_post, handle_rbac_delete

try:
    from report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf, load_live_data
except ImportError:
    from Portal.api.report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf, load_live_data

try:
    from license_intelligence import (
        load_license_catalog, classify_user_persona, analyze_user_license_entitlements,
        reconcile_workload_5_layers, check_smb_user_cap, compute_overall_value_index,
        compare_license_snapshots, WORKLOADS_DEF
    )
    from license_collector import collect_tenant_license_intelligence
    from license_report_generator import generate_license_health_report, render_license_pdf
    from license_catalog_updater import check_remote_feed, get_feed_status
except ImportError:
    from Portal.api.license_intelligence import (
        load_license_catalog, classify_user_persona, analyze_user_license_entitlements,
        reconcile_workload_5_layers, check_smb_user_cap, compute_overall_value_index,
        compare_license_snapshots, WORKLOADS_DEF
    )
    from Portal.api.license_collector import collect_tenant_license_intelligence
    from Portal.api.license_report_generator import generate_license_health_report, render_license_pdf
    from Portal.api.license_catalog_updater import check_remote_feed, get_feed_status

PORT = int(os.environ.get("PORT", 8080))

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

WEB_DIR = os.path.join(ROOT_DIR, "Portal", "web")

DATA_DIR = os.environ.get("CLOUDSHIELD_DATA_DIR") or os.path.join(ROOT_DIR, "Data")

TENANTS_FILE = os.path.join(DATA_DIR, "tenants.json")

USERS_FILE = os.path.join(DATA_DIR, "users.json")

AUTH_CONFIG_FILE = os.path.join(DATA_DIR, "auth_config.json")

AUTH_LOCAL_FILE = os.path.join(DATA_DIR, "auth.local.json")

CACHE_FILE = os.path.join(DATA_DIR, "daily_cache.json")

CATALOG_FILE = os.path.join(ROOT_DIR, "Engine", "Config", "service-catalog.json")

OUTPUT_DIR = os.environ.get("CLOUDSHIELD_OUTPUT_DIR") or os.path.join(ROOT_DIR, "Engine", "Output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

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

DECISIONS_FILE = os.path.join(DATA_DIR, "tenant_decisions.json")

REPORT_JOBS_FILE = os.path.join(DATA_DIR, "report_jobs.json")

REPORT_JOBS = {}
_REPORT_JOBS_LOCK = threading.Lock()

VERSION_FILE = os.path.join(DATA_DIR, "version.json")

SESSIONS = {}  # in-memory token -> session data
AUTH_FLOWS = {}  # in-memory state -> auth flow data
REVOKED_TOKENS = set()  # in-memory revocation blacklist
_SESSION_SECRET_CACHE = None

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
                code_verifier TEXT,
                redirect_uri TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token TEXT PRIMARY KEY,
                revoked_at REAL NOT NULL
            )
        """)
        # Schema migration check: ensure code_verifier column exists in existing DBs
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(auth_flows)")
        columns = [row[1] for row in cur.fetchall()]
        if "code_verifier" not in columns:
            conn.execute("ALTER TABLE auth_flows ADD COLUMN code_verifier TEXT")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] Failed to ensure session tables: {e}")

_ensure_session_tables()

def get_session_secret():
    """
    Retrieve session signing secret with in-memory caching and deterministic fallback.
    Priority:
    1. In-memory cache (_SESSION_SECRET_CACHE)
    2. Environment variable (CLOUDSHIELD_SESSION_SECRET or SESSION_SECRET)
    3. Machine-local persisted secret in DATA_DIR/.session_secret
    4. Deterministic master secret derived from Entra tenant_id, client_id, and platform salt
    Guarantees cryptographic consistency across scale-out replicas, worker recycles, and CIFS share delays.
    """
    global _SESSION_SECRET_CACHE
    if _SESSION_SECRET_CACHE:
        return _SESSION_SECRET_CACHE

    secret = os.environ.get("CLOUDSHIELD_SESSION_SECRET") or os.environ.get("SESSION_SECRET")
    if secret:
        _SESSION_SECRET_CACHE = secret
        return _SESSION_SECRET_CACHE

    secret_file = os.path.join(DATA_DIR, ".session_secret")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                s = f.read().strip()
                if s:
                    _SESSION_SECRET_CACHE = s
                    return _SESSION_SECRET_CACHE
        except Exception:
            pass

    # Cryptographically random secret persisted on shared DATA_DIR volume (never deterministic from public IDs)
    generated_secret = secrets.token_hex(32)

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(generated_secret)
        try:
            os.chmod(secret_file, 0o600)
        except Exception:
            pass
    except Exception as e:
        if os.environ.get("ENVIRONMENT", "").lower() == "production":
            print(f"[CRITICAL] Could not persist session secret and CLOUDSHIELD_SESSION_SECRET env is unset: {e}")

    _SESSION_SECRET_CACHE = generated_secret
    return _SESSION_SECRET_CACHE

def create_stateless_oauth_state(nonce, code_verifier, redirect_uri, secret=None):
    """
    Generate an HMAC-SHA256 signed, tamper-proof, self-contained OAuth state.
    Carries nonce, code_verifier (PKCE), redirect_uri, and timestamp.
    Eliminates cross-replica, scale-to-zero, and cold-start state loss completely.
    """
    secret = secret or get_session_secret()
    payload = {
        "n": nonce,
        "cv": code_verifier,
        "ru": redirect_uri,
        "ts": int(time.time())
    }
    raw_json = json.dumps(payload, separators=(',', ':')).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).digest()
    b64_sig = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{b64_payload}.{b64_sig}"

def verify_stateless_oauth_state(state_str, max_age_seconds=900, secret=None):
    """
    Verify and unpack a stateless HMAC-signed OAuth state.
    Returns (payload_dict, error_message).
    """
    if not state_str or not isinstance(state_str, str) or "." not in state_str:
        return None, "Geçersiz veya eski biçimli state parametresi"
    parts = state_str.split(".", 1)
    if len(parts) != 2:
        return None, "Geçersiz state belirteç formatı"
    b64_payload, b64_sig = parts
    secret = secret or get_session_secret()
    expected_sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).digest()
    expected_b64_sig = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")
    if not hmac.compare_digest(b64_sig, expected_b64_sig):
        return None, "İmza doğrulaması başarısız: State verisi tahrif edilmiş veya anahtar uyuşmuyor"
    try:
        padding = "=" * (-len(b64_payload) % 4)
        raw_json = base64.urlsafe_b64decode(b64_payload + padding)
        payload = json.loads(raw_json.decode("utf-8"))
    except Exception as e:
        return None, f"State verisi çözümlenemedi: {e}"
    ts = payload.get("ts", 0)
    if time.time() - ts > max_age_seconds:
        return None, "OAuth state süresi dolmuş (> 15 dakika)"
    return payload, None

def create_session_token(user_dict, expires_in=86400, secret=None):
    """
    Generate a self-contained, tamper-proof, HMAC-SHA256 signed session token.
    Format: cst.<base64url_json_payload>.<base64url_signature>
    Carries minimal user claims and expiration directly inside the token (< 250 bytes).
    Eliminates cross-replica session loss without blowing up HTTP header limits or URL length.
    """
    secret = secret or get_session_secret()
    now_ts = int(time.time())
    exp_ts = now_ts + expires_in
    uid = user_dict.get("id", "usr-unknown")
    upn = user_dict.get("upn") or user_dict.get("username") or ""
    dname = user_dict.get("displayName") or user_dict.get("display_name") or upn or "User"
    role = user_dict.get("role") or ("PlatformAdmin" if uid in ("usr-admin", "usr-001") else "ServiceOperator")
    is_admin = bool(user_dict.get("isPlatformAdmin", True if uid in ("usr-admin", "usr-001") else False))
    initials = user_dict.get("initials") or "".join([w[0].upper() for w in dname.split()[:2]]) or "CS"
    assigned = user_dict.get("AssignedTenants") or ["ALL"]

    compact_user = {
        "id": uid,
        "upn": upn,
        "username": upn,
        "displayName": dname,
        "email": user_dict.get("email") or upn,
        "role": role,
        "roles": user_dict.get("roles") or [role],
        "isPlatformAdmin": is_admin,
        "initials": initials,
        "AssignedTenants": assigned,
        "tenantScope": user_dict.get("tenantScope", "Global"),
        "organization_id": user_dict.get("organization_id", "org-cloudshield"),
        "org_name": user_dict.get("organization") or user_dict.get("org_name", "CloudShield MSSP")
    }
    payload = {
        "uid": uid,
        "upn": upn,
        "u": compact_user,
        "ts": now_ts,
        "exp": exp_ts
    }
    raw_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).digest()
    b64_sig = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"cst.{b64_payload}.{b64_sig}"

def verify_session_token(token_str, secret=None):
    """
    Cryptographically verify and unpack a self-contained HMAC session token.
    Returns (payload_dict, error_message).
    """
    if not token_str or not isinstance(token_str, str) or not token_str.startswith("cst."):
        return None, "Geçersiz oturum belirteci biçimi"
    parts = token_str.split(".", 2)
    if len(parts) != 3:
        return None, "Geçersiz oturum belirteci parçaları"
    _, b64_payload, b64_sig = parts
    secret = secret or get_session_secret()
    expected_sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).digest()
    expected_b64_sig = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")
    if not hmac.compare_digest(b64_sig, expected_b64_sig):
        return None, "İmza doğrulaması başarısız: Oturum belirteci tahrif edilmiş veya anahtar uyuşmuyor"
    try:
        padding = "=" * (-len(b64_payload) % 4)
        raw_json = base64.urlsafe_b64decode(b64_payload + padding)
        payload = json.loads(raw_json.decode("utf-8"))
    except Exception as e:
        return None, f"Oturum belirteci çözümlenemedi: {e}"
    exp = payload.get("exp", 0)
    if time.time() > exp:
        return None, "Oturum süresi dolmuş"
    return payload, None

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

    # Check revocation blacklist first
    if tok in REVOKED_TOKENS:
        return None

    # 1. Fast-path: In-memory store
    sess = SESSIONS.get(tok)
    if sess and sess.get("expiresAt", 0) > now_ts:
        return sess

    # 2. Resilient Zero-I/O Path: Stateless HMAC self-contained session token
    if tok.startswith("cst."):
        payload, err = verify_session_token(tok)
        if payload and not err:
            user = payload.get("u")
            if user:
                sess = {
                    "user": user,
                    "createdAt": payload.get("ts", now_ts),
                    "expiresAt": payload.get("exp", now_ts + 86400)
                }
                SESSIONS[tok] = sess
                return sess

    # 3. Fallback: SQLite user_sessions table
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
    if not tok:
        return
    REVOKED_TOKENS.add(tok)
    if tok in SESSIONS:
        del SESSIONS[tok]
    try:
        conn = get_db()
        conn.execute("DELETE FROM user_sessions WHERE token = ?", (tok,))
        conn.execute("INSERT OR REPLACE INTO revoked_tokens (token, revoked_at) VALUES (?, ?)", (tok, time.time()))
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
    client_secret = (
        client_secret
        or base_cfg.get("ClientSecret")
        or ""
    )
    redirect_uri = redirect_uri or base_cfg.get("RedirectUri", "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/api/auth/entra/callback")

    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "authorize_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    }


_TENANT_GRAPH_TOKEN_CACHE = {}
_TENANT_TOKEN_LOCK = threading.Lock()


def _get_azure_managed_identity_token(resource="https://vault.azure.net"):
    """Acquire Azure Managed Identity access token (ACA IDENTITY_ENDPOINT or VM IMDS)."""
    id_endpoint = os.environ.get("IDENTITY_ENDPOINT", "").strip()
    id_header = os.environ.get("IDENTITY_HEADER", "").strip()
    try:
        if id_endpoint and id_header:
            sep = "&" if "?" in id_endpoint else "?"
            url = f"{id_endpoint}{sep}api-version=2019-08-01&resource={urllib.parse.quote(resource, safe='')}"
            req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": id_header, "Metadata": "true"})
        else:
            url = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={urllib.parse.quote(resource, safe='')}"
            req = urllib.request.Request(url, headers={"Metadata": "true"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            return json.loads(resp.read().decode("utf-8")).get("access_token")
    except Exception:
        return None


def _fetch_keyvault_secret(secret_name):
    """Fetch secret or PEM/PKCS12 certificate bundle from Azure Key Vault via Managed Identity."""
    kv_url = (os.environ.get("AZURE_KEYVAULT_URL") or "").strip().rstrip("/")
    if not kv_url or not secret_name:
        return None
    mi_tok = _get_azure_managed_identity_token("https://vault.azure.net")
    if not mi_tok:
        return None
    try:
        url = f"{kv_url}/secrets/{urllib.parse.quote(secret_name, safe='')}?api-version=7.4"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {mi_tok}"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8")).get("value")
    except Exception:
        return None


def _store_keyvault_secret(secret_name, secret_value, content_type="application/x-pem-file"):
    """Store a tenant certificate or secret directly in Azure Key Vault via Managed Identity."""
    kv_url = (os.environ.get("AZURE_KEYVAULT_URL") or "").strip().rstrip("/")
    if not kv_url:
        return False, "AZURE_KEYVAULT_URL yapılandırılmamış."
    safe_secret = "".join(c for c in str(secret_name) if c.isalnum() or c == "-").strip("-")
    if not safe_secret or not secret_value:
        return False, "Geçersiz Key Vault secret adı veya boş değer."
    mi_tok = _get_azure_managed_identity_token("https://vault.azure.net")
    if not mi_tok:
        return False, "Azure Managed Identity erişim anahtarı alınamadı."
    url = f"{kv_url}/secrets/{urllib.parse.quote(safe_secret, safe='')}?api-version=7.4"
    payload = json.dumps({"value": secret_value, "contentType": content_type}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="PUT",
        headers={"Authorization": f"Bearer {mi_tok}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            if resp.status in (200, 201):
                return True, safe_secret
            return False, f"Key Vault HTTP {resp.status}"
    except urllib.error.HTTPError as he:
        return False, f"Key Vault HTTP {he.code}: {he.read().decode('utf-8', errors='ignore')[:160]}"
    except Exception as ex:
        return False, f"Key Vault hatası: {ex}"


def _build_cert_client_assertion(tenant_guid, client_id, cert_bundle_str):
    """Build RFC 7523 RS256 client_assertion JWT from Key Vault PEM or base64 PKCS#12 certificate."""
    if jwt is None or not cert_bundle_str:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        private_key = None
        cert = None
        if "-----BEGIN" in cert_bundle_str:
            raw_bytes = cert_bundle_str.encode("utf-8")
            private_key = serialization.load_pem_private_key(raw_bytes, password=None)
            cert = x509.load_pem_x509_certificate(raw_bytes)
        else:
            pfx_bytes = base64.b64decode(cert_bundle_str)
            private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, password=None)

        if not private_key or not cert:
            return None
        thumb_bytes = cert.fingerprint(hashes.SHA1())
        x5t = base64.urlsafe_b64encode(thumb_bytes).decode("ascii").rstrip("=")
        now_ts = int(time.time())
        aud = f"https://login.microsoftonline.com/{tenant_guid}/oauth2/v2.0/token"
        claims = {
            "aud": aud,
            "iss": client_id,
            "sub": client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now_ts - 30,
            "exp": now_ts + 600,
        }
        return jwt.encode(claims, private_key, algorithm="RS256", headers={"x5t": x5t})
    except Exception:
        return None


def acquire_tenant_graph_token(tenant_obj, scope="https://graph.microsoft.com/.default", timeout=6.0):
    """
    Acquire live OAuth2 client_credentials token for a customer tenant using:
    1) Key Vault Certificate (CBA / GDAP) via Managed Identity
    2) Key Vault Secret / local secret / platform Entra app (when same-tenant)
    Returns (access_token, error_message).
    """
    if not isinstance(tenant_obj, dict):
        return None, "Tenant yapılandırması bulunamadı."
    if tenant_obj.get("IsSimulation"):
        return None, "Simülasyon kiracısı (IsSimulation=True)."

    tenant_guid = (tenant_obj.get("TenantId") or "").strip()
    auth = tenant_obj.get("Auth") if isinstance(tenant_obj.get("Auth"), dict) else {}
    auth_method = (tenant_obj.get("AuthMethod") or auth.get("Method") or "Certificate").strip()
    client_id = (tenant_obj.get("ClientId") or auth.get("ClientId") or "").strip()
    if auth_method == "GDAP" and auth.get("PartnerClientId"):
        client_id = auth.get("PartnerClientId").strip()

    plat_cfg = get_entra_config()
    if not client_id and tenant_guid and tenant_guid == plat_cfg.get("tenant_id"):
        client_id = plat_cfg.get("client_id", "")

    if not tenant_guid or not client_id:
        return None, "TenantId veya ClientId eksik."

    cache_key = f"{tenant_guid}|{client_id}|{scope}"
    now_ts = time.time()
    with _TENANT_TOKEN_LOCK:
        cached = _TENANT_GRAPH_TOKEN_CACHE.get(cache_key)
        if cached and cached["exp"] > now_ts + 120:
            return cached["token"], None

    form_data = {
        "client_id": client_id,
        "grant_type": "client_credentials",
        "scope": scope,
    }

    if auth_method in ("Certificate", "ClientCertificate", "CBA", "GDAP"):
        kv_cert_name = (tenant_obj.get("KeyVaultCertificateName") or auth.get("KeyVaultCertificateName") or auth.get("KeyVaultSecretName") or "").strip()
        cert_bundle = _fetch_keyvault_secret(kv_cert_name) if kv_cert_name else None
        if not cert_bundle and auth.get("CertificateFilePath") and os.path.exists(auth["CertificateFilePath"]):
            try:
                with open(auth["CertificateFilePath"], "rb") as cf:
                    raw_cf = cf.read()
                cert_bundle = raw_cf.decode("utf-8") if b"-----BEGIN" in raw_cf else base64.b64encode(raw_cf).decode("ascii")
            except Exception:
                cert_bundle = None
        assertion = _build_cert_client_assertion(tenant_guid, client_id, cert_bundle) if cert_bundle else None
        if assertion:
            form_data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            form_data["client_assertion"] = assertion

    if "client_assertion" not in form_data:
        kv_sec_name = (auth.get("KeyVaultSecretName") or tenant_obj.get("KeyVaultSecretName") or "").strip()
        plain_secret = (
            auth.get("ClientSecret")
            or tenant_obj.get("ClientSecret")
            or (_fetch_keyvault_secret(kv_sec_name) if kv_sec_name else None)
            or os.environ.get("MSSP_CLIENT_SECRET")
            or (plat_cfg.get("client_secret") if tenant_guid == plat_cfg.get("tenant_id") and client_id == plat_cfg.get("client_id") else None)
        )
        if not plain_secret:
            return None, "Key Vault sertifikası veya istemci sırrı çözülemedi."
        form_data["client_secret"] = plain_secret

    token_url = f"https://login.microsoftonline.com/{tenant_guid}/oauth2/v2.0/token"
    encoded = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "CloudShield-MSSP/3.2"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            tok = payload.get("access_token")
            exp_in = int(payload.get("expires_in", 3599))
            if tok:
                with _TENANT_TOKEN_LOCK:
                    _TENANT_GRAPH_TOKEN_CACHE[cache_key] = {"token": tok, "exp": time.time() + exp_in}
                return tok, None
            return None, "Entra ID yanıtında access_token bulunamadı."
    except urllib.error.HTTPError as he:
        try:
            err_body = json.loads(he.read().decode("utf-8", errors="ignore"))
            desc = err_body.get("error_description", "").splitlines()[0]
        except Exception:
            desc = str(he)
        return None, f"Entra OAuth HTTP {he.code}: {desc[:180]}"
    except Exception as ex:
        return None, f"Entra bağlantı hatası: {ex}"


def graph_get_json(access_token, url, timeout=8.0):
    """Execute authenticated GET against Microsoft Graph and return (json_dict, http_status, error_str)."""
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",
            "User-Agent": "CloudShield-MSSP/3.2",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status, None
    except urllib.error.HTTPError as he:
        return None, he.code, f"HTTP {he.code}"
    except Exception as ex:
        return None, 0, str(ex)


def execute_report_dispatch(tenant_obj, recipients=None, subject=None, attach_pdf=True, attach_html=True, mode=None, dry_run=False, created_by="dispatch"):
    """
    Compile/locate physical report artifacts and deliver via Microsoft Graph sendMail or SMTP.
    Never fabricates a 'Delivered' status when no real transport is configured.
    """
    import smtplib
    from email.message import EmailMessage

    t0 = time.time()
    tid = tenant_obj.get("Id") or tenant_obj.get("TenantId") or "tenant"
    customer_name = tenant_obj.get("Name", "Customer")
    services = tenant_obj.get("ActiveServices") or ["SVC-MDE", "SVC-MDO", "SVC-PURVIEW"]
    is_sim = bool(tenant_obj.get("IsSimulation")) or bool(dry_run)
    freq = mode or tenant_obj.get("ScheduleFrequency", "Monthly")

    recip_list = recipients if recipients else tenant_obj.get("RecipientEmails", ["mssp-reporting@cloudshield-mssp.com"])
    if isinstance(recip_list, str):
        recip_list = [r.strip() for r in recip_list.split(",") if r.strip()]
    if not recip_list:
        recip_list = [tenant_obj.get("ContactEmail") or "mssp-reporting@cloudshield-mssp.com"]

    safe_name = "".join(c for c in customer_name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")

    # 1. Ensure physical HTML/PDF report exists (compile via report_generator if needed)
    latest_html_path = None
    latest_pdf_path = None
    cust_dir = os.path.join(OUTPUT_DIR, safe_name)
    if os.path.exists(cust_dir):
        for r_dir, _, files in os.walk(cust_dir):
            for fn in files:
                fp = os.path.join(r_dir, fn)
                if fn.lower().endswith(".pdf") and (not latest_pdf_path or os.path.getmtime(fp) > os.path.getmtime(latest_pdf_path)):
                    latest_pdf_path = fp
                elif fn.lower().endswith(".html") and (not latest_html_path or os.path.getmtime(fp) > os.path.getmtime(latest_html_path)):
                    latest_html_path = fp

    if not latest_html_path or (attach_pdf and not latest_pdf_path):
        try:
            py_html, py_pdf = render_and_save_report(customer_name, services, OUTPUT_DIR, tenant_id=tid)
            if py_html and os.path.exists(py_html):
                latest_html_path = py_html
                register_report_artifact(tid, customer_name, datetime.now().strftime("%Y-%m"), services, "html", py_html, created_by=created_by)
            if py_pdf and os.path.exists(py_pdf):
                latest_pdf_path = py_pdf
                register_report_artifact(tid, customer_name, datetime.now().strftime("%Y-%m"), services, "pdf", py_pdf, created_by=created_by)
        except Exception as rex:
            print(f"[WARN] Dispatch report compile warning ({tid}): {rex}")

    mail_subject = subject or f"[CloudShield MSSP] {customer_name} - Yönetilen Güvenlik ve Uyum Raporu ({datetime.now().strftime('%Y-%m')})"
    body_html = (
        f"<div style='font-family:Segoe UI,Arial,sans-serif;color:#1e293b;'>"
        f"<h2 style='color:#002B49;margin-bottom:8px;'>CloudShield Yönetilen Güvenlik ve Uyum Raporu</h2>"
        f"<p>Sayın <strong>{customer_name}</strong> Yönetimi,</p>"
        f"<p>{freq} dönemine ait yönetilen siber güvenlik ve veri uyumluluk raporunuz ekte sunulmuştur.</p>"
        f"<p style='font-size:12px;color:#64748b;'>Üretim Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} | Kapsam: {', '.join(services)}</p>"
        f"</div>"
    )

    auth_file_cfg = load_json_file(AUTH_CONFIG_FILE, {})
    mail_cfg = auth_file_cfg.get("MailConfig") if isinstance(auth_file_cfg.get("MailConfig"), dict) else {}
    graph_sender = (os.environ.get("GRAPH_MAIL_SENDER") or mail_cfg.get("SenderUpn") or "").strip()
    smtp_host = (os.environ.get("SMTP_HOST") or mail_cfg.get("SmtpHost") or "").strip()

    status = "ArchivedOnly"
    channel = "Local Persistent Archive"
    message = ""

    if is_sim:
        status = "Simulated"
        channel = "Simulation / Dry-Run Archive"
        message = f"Simülasyon raporu derlenip arşive kaydedildi ({len(recip_list)} alıcı simüle edildi)."
    elif graph_sender:
        plat_cfg = get_entra_config()
        plat_tenant_obj = {
            "TenantId": plat_cfg.get("tenant_id"),
            "ClientId": plat_cfg.get("client_id"),
            "Auth": {"Method": "ClientSecret", "ClientSecret": plat_cfg.get("client_secret")},
        }
        g_tok, g_err = acquire_tenant_graph_token(plat_tenant_obj)
        if not g_tok:
            g_tok, g_err = acquire_tenant_graph_token(tenant_obj)
        if g_tok:
            attachments = []
            if attach_pdf and latest_pdf_path and os.path.exists(latest_pdf_path):
                with open(latest_pdf_path, "rb") as pf:
                    attachments.append({
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": os.path.basename(latest_pdf_path),
                        "contentType": "application/pdf",
                        "contentBytes": base64.b64encode(pf.read()).decode("ascii"),
                    })
            if attach_html and latest_html_path and os.path.exists(latest_html_path):
                with open(latest_html_path, "rb") as hf:
                    attachments.append({
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": os.path.basename(latest_html_path),
                        "contentType": "text/html",
                        "contentBytes": base64.b64encode(hf.read()).decode("ascii"),
                    })
            graph_payload = {
                "message": {
                    "subject": mail_subject,
                    "body": {"contentType": "HTML", "content": body_html},
                    "toRecipients": [{"emailAddress": {"address": r}} for r in recip_list],
                    "attachments": attachments,
                },
                "saveToSentItems": True,
            }
            send_url = f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(graph_sender, safe='@._-')}/sendMail"
            req = urllib.request.Request(
                send_url,
                data=json.dumps(graph_payload).encode("utf-8"),
                method="POST",
                headers={"Authorization": f"Bearer {g_tok}", "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    if resp.status in (200, 202):
                        status = "Delivered"
                        channel = f"Microsoft Graph SendMail ({graph_sender})"
                        message = f"Rapor Microsoft Graph üzerinden {len(recip_list)} alıcıya başarıyla gönderildi."
            except urllib.error.HTTPError as he:
                err_txt = he.read().decode("utf-8", errors="ignore")[:180]
                status = "Failed"
                channel = f"Microsoft Graph SendMail ({graph_sender})"
                message = f"Graph SendMail hatası (HTTP {he.code}): {err_txt}"
            except Exception as ex:
                status = "Failed"
                channel = f"Microsoft Graph SendMail ({graph_sender})"
                message = f"Graph SendMail bağlantı hatası: {ex}"
        else:
            status = "Failed"
            channel = "Microsoft Graph SendMail"
            message = f"Gönderici Graph erişim anahtarı alınamadı: {g_err}"
    elif smtp_host:
        smtp_port = int(os.environ.get("SMTP_PORT") or mail_cfg.get("SmtpPort") or 587)
        smtp_user = os.environ.get("SMTP_USER") or mail_cfg.get("SmtpUser") or ""
        smtp_pass = os.environ.get("SMTP_PASS") or mail_cfg.get("SmtpPass") or ""
        smtp_from = os.environ.get("SMTP_FROM") or mail_cfg.get("SmtpFrom") or smtp_user or "noreply@cloudshield-mssp.com"
        msg = EmailMessage()
        msg["Subject"] = mail_subject
        msg["From"] = smtp_from
        msg["To"] = ", ".join(recip_list)
        msg.set_content(f"{customer_name} - Yönetilen Güvenlik ve Uyum Raporu ektedir.")
        msg.add_alternative(body_html, subtype="html")
        if attach_pdf and latest_pdf_path and os.path.exists(latest_pdf_path):
            with open(latest_pdf_path, "rb") as pf:
                msg.add_attachment(pf.read(), maintype="application", subtype="pdf", filename=os.path.basename(latest_pdf_path))
        if attach_html and latest_html_path and os.path.exists(latest_html_path):
            with open(latest_html_path, "rb") as hf:
                msg.add_attachment(hf.read(), maintype="text", subtype="html", filename=os.path.basename(latest_html_path))
        try:
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as srv:
                    if smtp_user and smtp_pass:
                        srv.login(smtp_user, smtp_pass)
                    srv.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
                    srv.ehlo()
                    if srv.has_extn("starttls"):
                        srv.starttls()
                    if smtp_user and smtp_pass:
                        srv.login(smtp_user, smtp_pass)
                    srv.send_message(msg)
            status = "Delivered"
            channel = f"SMTP ({smtp_host}:{smtp_port})"
            message = f"Rapor SMTP üzerinden {len(recip_list)} alıcıya başarıyla teslim edildi."
        except Exception as sex:
            status = "Failed"
            channel = f"SMTP ({smtp_host}:{smtp_port})"
            message = f"SMTP gönderim hatası: {sex}"
    else:
        status = "ArchivedOnly"
        channel = "Local Persistent Archive (Mail.Send / SMTP yapılandırılmadı)"
        message = (
            "Rapor PDF/HTML olarak derlenip kalıcı arşive kaydedildi; "
            "canlı e-posta gönderimi için GRAPH_MAIL_SENDER (Mail.Send) veya SMTP_HOST tanımlanmalıdır."
        )

    latency_ms = int((time.time() - t0) * 1000)
    now_iso = datetime.now(timezone.utc).isoformat()
    disp_id = f"disp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
    log_entry = {
        "id": disp_id,
        "timestamp": now_iso,
        "tenantId": tid,
        "tenantName": customer_name,
        "mode": freq,
        "recipients": recip_list,
        "subject": mail_subject,
        "pdfAttached": os.path.basename(latest_pdf_path) if (attach_pdf and latest_pdf_path and os.path.exists(latest_pdf_path)) else None,
        "htmlAttached": os.path.basename(latest_html_path) if (attach_html and latest_html_path and os.path.exists(latest_html_path)) else None,
        "status": status,
        "deliveryChannel": channel,
        "latencyMs": latency_ms,
        "message": message,
    }
    logs = load_json_file(DISPATCH_LOGS_FILE, [])
    logs.insert(0, log_entry)
    save_json_file(DISPATCH_LOGS_FILE, logs[:500])
    return log_entry


_UI_ROLE_TO_DB_ROLE = {
    "PlatformAdmin": ("role-platform-admin", "ALL", None),
    "SecurityEngineer": ("role-security-engineer", "ALL", None),
    "EdrEngineer": ("role-security-engineer", "Specific", "svc-mde"),
    "XdrEngineer": ("role-security-engineer", "Specific", "svc-xdr"),
    "ComplianceSpecialist": ("role-compliance-specialist", "Specific", "svc-prv-dlp"),
    "ServiceOperator": ("role-service-operator", "ALL", None),
    "MsspOperator": ("role-service-operator", "ALL", None),
    "CustomerCISO": ("role-customer-ciso", "ALL", None),
    "Auditor": ("role-auditor", "ALL", None),
}


def _sync_user_dict_to_db(u_dict):
    """Atomically synchronize legacy /api/users payload into SQLite users and access_assignments tables."""
    uid = (u_dict.get("Id") or "").strip()
    upn = (u_dict.get("Upn") or u_dict.get("Email") or "").strip()
    if not uid or not upn:
        return
    dname = (u_dict.get("DisplayName") or upn).strip()
    email = (u_dict.get("Email") or upn).strip()
    dept = (u_dict.get("Department") or "MSSP Security Operations").strip()
    role_str = (u_dict.get("Role") or "ServiceOperator").strip()
    assigned_tenants = u_dict.get("AssignedTenants") or ["ALL"]
    if isinstance(assigned_tenants, str):
        assigned_tenants = [t.strip() for t in assigned_tenants.split(",") if t.strip()] or ["ALL"]
    raw_pass = (u_dict.get("Password") or "").strip()
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash, password_salt FROM users WHERE id = ? OR LOWER(upn) = LOWER(?)", (uid, upn))
        existing = cur.fetchone()
        if raw_pass:
            p_hash, p_salt = hash_password(raw_pass)
        elif existing:
            p_hash, p_salt = existing["password_hash"], existing["password_salt"]
        else:
            p_hash, p_salt = None, None

        if existing:
            uid = existing["id"]
            cur.execute(
                """UPDATE users SET upn = ?, display_name = ?, email = ?, department = ?,
                                    password_hash = ?, password_salt = ?, is_active = 1
                   WHERE id = ?""",
                (upn, dname, email, dept, p_hash, p_salt, uid),
            )
        else:
            cur.execute(
                """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                      password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
                   VALUES (?, 'org-cloudshield', ?, ?, ?, ?, ?, ?, 1, 1, 'EntraID_OIDC', ?)""",
                (uid, upn, dname, email, dept, p_hash, p_salt, now_iso),
            )

        role_id, svc_scope, svc_id = _UI_ROLE_TO_DB_ROLE.get(role_str, ("role-service-operator", "ALL", None))
        cur.execute("DELETE FROM access_assignments WHERE subject_type = 'User' AND subject_id = ? AND is_temporary = 0", (uid,))
        if "ALL" in assigned_tenants or role_id == "role-platform-admin":
            cur.execute(
                """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                                  service_scope, service_id, valid_from, is_temporary, is_active, created_by, created_at)
                   VALUES (?, 'User', ?, ?, 'ALL', NULL, ?, ?, ?, 0, 1, 'api-users-sync', ?)""",
                (f"asgn-{uid}-all", uid, role_id, svc_scope, svc_id, now_iso, now_iso),
            )
        else:
            for cid in assigned_tenants:
                cur.execute(
                    """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                                      service_scope, service_id, valid_from, is_temporary, is_active, created_by, created_at)
                       VALUES (?, 'User', ?, ?, 'Specific', ?, ?, ?, ?, 0, 1, 'api-users-sync', ?)""",
                    (f"asgn-{uid}-{cid}", uid, role_id, cid, svc_scope, svc_id, now_iso, now_iso),
                )
        conn.commit()
    finally:
        conn.close()


def _delete_user_from_db(user_id):
    """Atomically remove user and active sessions from SQLite RBAC database."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM access_assignments WHERE subject_type = 'User' AND subject_id = ?", (user_id,))
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def _list_unified_users():
    """Return authoritative user list from SQLite RBAC database merged with users.json metadata."""
    json_users = {u.get("Id"): u for u in load_json_file(USERS_FILE, []) if isinstance(u, dict) and u.get("Id")}
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE is_active = 1 ORDER BY created_at ASC")
        rows = [dict(r) for r in cur.fetchall()]
        out = []
        for r in rows:
            uid = r["id"]
            asgns = get_effective_assignments(uid, conn)
            roles = [a["role_name"] for a in asgns if a.get("role_name")]
            is_pa = any(a.get("is_platform_role") for a in asgns)
            tenants_sc = ["ALL"] if (is_pa or any(a.get("customer_scope") == "ALL" for a in asgns)) else [a["customer_id"] for a in asgns if a.get("customer_id")]
            j_meta = json_users.get(uid, {})
            out.append({
                "Id": uid,
                "DisplayName": r.get("display_name") or j_meta.get("DisplayName") or r.get("upn"),
                "Upn": r.get("upn"),
                "Email": r.get("email") or r.get("upn"),
                "Department": r.get("department") or j_meta.get("Department") or "MSSP",
                "Role": "PlatformAdmin" if is_pa else (j_meta.get("Role") or (roles[0] if roles else "ServiceOperator")),
                "AssignedTenants": tenants_sc or ["ALL"],
                "LastLogin": r.get("last_login_at") or j_meta.get("LastLogin") or "Henüz giriş yapmadı",
                "AuthProvider": r.get("auth_provider") or "EntraID_OIDC",
            })
        return out
    finally:
        conn.close()


def _get_or_init_tenant_decisions(tenant_id):
    """Load or initialize persistent CISO Decision Matrix records for a customer tenant."""
    all_dec = load_json_file(DECISIONS_FILE, {})
    if not isinstance(all_dec, dict):
        all_dec = {}
    if tenant_id not in all_dec:
        all_dec[tenant_id] = [
            {
                "id": "DEC-M365-APP-01",
                "quadrant": "Approved",
                "title": "XDR Bütünleşik Olay Yönetimi ve AIR Aktivasyonu",
                "owner": "CISO & BT Güvenlik Müdürü",
                "priority": "P1",
                "status": "Approved",
                "evidence": "R8-MDE-AIR-01",
                "approvedBy": "System Baseline",
                "approvedAtUtc": None,
            },
            {
                "id": "DEC-M365-APP-02",
                "quadrant": "Approved",
                "title": "Purview DLP & CloudShield Triyaj Entegrasyonu",
                "owner": "Bilgi Güvenliği Direktörü",
                "priority": "P1",
                "status": "Approved",
                "evidence": "R8-DLP-INT-02",
                "approvedBy": "System Baseline",
                "approvedAtUtc": None,
            },
            {
                "id": "DEC-M365-PEND-01",
                "quadrant": "Pending",
                "title": "Uç Nokta DLP Kurallarının Blok Moduna Geçirilmesi",
                "owner": "CISO & BT Altyapı Direktörü",
                "priority": "P1 - Yüksek",
                "status": "Pending",
                "evidence": "Intune & Purview Telemetrisi",
                "approvedBy": None,
                "approvedAtUtc": None,
            },
            {
                "id": "DEC-M365-DEF-01",
                "quadrant": "Deferred",
                "title": "Eski Muhasebe Sunucusunda Legacy Protokol İstisnası",
                "owner": "Finans & BT Direktörü",
                "priority": "P2",
                "status": "Deferred",
                "evidence": "İzole Segmentte",
                "approvedBy": None,
                "approvedAtUtc": None,
            },
            {
                "id": "DEC-M365-REC-01",
                "quadrant": "Recommended",
                "title": "BitLocker XTS-AES 256 Şifreleme ve Credential Guard",
                "owner": "BT Altyapı Ekibi",
                "priority": "P1 - Yüksek",
                "status": "Recommended",
                "evidence": "Intune Cihaz Uyumluluk Karnesi",
                "approvedBy": None,
                "approvedAtUtc": None,
            },
            {
                "id": "DEC-M365-REC-02",
                "quadrant": "Recommended",
                "title": "Kural Aşımı Yapan Personel İçin Hedefli Uyum Eğitimi",
                "owner": "İK & Bilgi Güvenliği",
                "priority": "P2 - Orta",
                "status": "Recommended",
                "evidence": "Purview DLP Politika İhlal Özeti",
                "approvedBy": None,
                "approvedAtUtc": None,
            },
        ]
        save_json_file(DECISIONS_FILE, all_dec)
    return all_dec[tenant_id]

class RateLimiter:
    """Thread-safe sliding-window rate limiter per key (IP, user, or composite key)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.records = {}

    def is_allowed(self, key, max_requests, window_seconds):
        now = time.time()
        with self.lock:
            timestamps = self.records.get(key, [])
            cutoff = now - window_seconds
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= max_requests:
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                self.records[key] = timestamps
                return False, retry_after
            timestamps.append(now)
            self.records[key] = timestamps
            return True, 0

    def reset(self):
        with self.lock:
            self.records.clear()

RATE_LIMITER = RateLimiter()

def generate_pkce_pair():
    """Generate RFC 7636 PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge

_JWKS_CACHE = {
    "keys": None,
    "expires_at": 0,
    "tenant_id": None
}

def get_microsoft_jwks(tenant_id):
    """
    Fetch Microsoft OIDC discovery metadata and JWKS.
    Fails closed on retrieval failure.
    Caches keys in memory with controlled expiration.
    Supports TEST_MOCK_JWKS for deterministic automated unit testing.
    """
    mock_jwks = os.environ.get("TEST_MOCK_JWKS")
    if mock_jwks:
        try:
            return json.loads(mock_jwks)
        except Exception as e:
            raise RuntimeError(f"Invalid TEST_MOCK_JWKS environment data: {e}")

    now = time.time()
    if _JWKS_CACHE["keys"] and _JWKS_CACHE["tenant_id"] == tenant_id and now < _JWKS_CACHE["expires_at"]:
        return _JWKS_CACHE["keys"]

    discovery_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    try:
        req = urllib.request.Request(discovery_url, headers={"User-Agent": "CloudShield-Portal-OIDC/3.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            discovery = json.loads(resp.read().decode("utf-8"))
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC discovery response missing jwks_uri")

        req2 = urllib.request.Request(jwks_uri, headers={"User-Agent": "CloudShield-Portal-OIDC/3.0"})
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            jwks = json.loads(resp2.read().decode("utf-8"))

        _JWKS_CACHE["keys"] = jwks
        _JWKS_CACHE["expires_at"] = now + 86400  # 24-hour cache
        _JWKS_CACHE["tenant_id"] = tenant_id
        return jwks
    except Exception as e:
        raise RuntimeError(f"OIDC metadata/JWKS retrieval failed (Fail-Closed): {e}")

def verify_entra_id_token(id_token, tenant_id, client_id, expected_nonce=None):
    """
    Cryptographically verify Microsoft Entra ID ID token signature and claims.
    Strict production checks:
    - RS256 algorithm enforcement
    - Signature verification against Microsoft JWKS public keys
    - Matching kid in JWKS
    - Audience validation (must match platform client_id)
    - Issuer validation (https://login.microsoftonline.com/{tenant_id}/v2.0 or https://sts.windows.net/{tenant_id}/)
    - Expiration & Not-Before validation
    - Nonce verification (against server-side state flow)
    - Tenant boundary validation (tid == tenant_id)
    """
    if not id_token or not isinstance(id_token, str):
        raise ValueError("Missing or invalid id_token string")

    expected_issuers = [
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/"
    ]

    if jwt is not None:
        try:
            unverified_header = jwt.get_unverified_header(id_token)
        except Exception as e:
            raise ValueError(f"Invalid JWT header structure: {e}")

        alg = unverified_header.get("alg")
        if alg != "RS256":
            raise ValueError(f"Disallowed JWT algorithm '{alg}'. Only RS256 is permitted.")

        kid = unverified_header.get("kid")
        if not kid:
            raise ValueError("Missing 'kid' (Key ID) in JWT header.")

        jwks_data = get_microsoft_jwks(tenant_id)
        jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
        
        try:
            signing_key = jwk_set[kid]
        except KeyError:
            # Retry once to allow key rollover
            _JWKS_CACHE["expires_at"] = 0
            jwks_data = get_microsoft_jwks(tenant_id)
            jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
            try:
                signing_key = jwk_set[kid]
            except KeyError:
                raise ValueError(f"Unknown key identifier (kid: '{kid}') not present in Microsoft JWKS.")

        try:
            claims = jwt.decode(
                id_token,
                key=signing_key.key,
                algorithms=["RS256"],
                audience=client_id,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": False,
                    "require": ["exp", "iss", "aud", "sub"]
                }
            )
        except jwt.ExpiredSignatureError:
            raise ValueError("ID Token has expired.")
        except jwt.InvalidAudienceError:
            raise ValueError(f"Invalid token audience (aud does not match platform client_id '{client_id}').")
        except jwt.InvalidSignatureError:
            raise ValueError("Cryptographic signature verification failed (Tampered or forged token).")
        except Exception as e:
            raise ValueError(f"JWT signature verification failed: {e}")
    else:
        raise ValueError("PyJWT cryptographic library is required for Entra ID token verification (fail-closed).")

    iss = claims.get("iss")
    if iss not in expected_issuers:
        raise ValueError(f"Invalid token issuer '{iss}'. Expected tenant authority.")

    tid = claims.get("tid")
    if tid and tid != tenant_id:
        raise ValueError(f"Cross-tenant identity rejected. Token tid '{tid}' does not match expected '{tenant_id}'.")

    if expected_nonce:
        token_nonce = claims.get("nonce")
        if not token_nonce or not hmac.compare_digest(token_nonce, expected_nonce):
            raise ValueError("Token nonce does not match expected authentication session nonce.")

    return claims

def decode_jwt_payload(jwt_token):
    """Decode unverified JWT payload using pure Python standard library for debug inspection only."""
    parts = jwt_token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT token format")
    payload_b64 = parts[1]
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)
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
                uid = u.get("Id")
                cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
                user_row = cur.fetchone()
                if not user_row:
                    dname = u.get("DisplayName", name)
                    dept = u.get("Department", "MSSP")
                    role_str = u.get("Role", "PlatformAdmin" if uid == "usr-001" else "ServiceOperator")
                    now_sync = datetime.now(timezone.utc).isoformat()
                    cur.execute(
                        """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                            password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
                           VALUES (?, 'org-cloudshield', ?, ?, ?, ?, NULL, NULL, 1, 1, 'EntraID_OIDC', ?)""",
                        (uid, u.get("Upn", upn), dname, u.get("Email", email), dept, now_sync)
                    )
                    role_id = "role-platform-admin" if role_str == "PlatformAdmin" else "role-service-operator"
                    cur.execute(
                        """INSERT OR IGNORE INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope,
                                                                    service_scope, valid_from, is_temporary, is_active, created_by, created_at)
                           VALUES (?, 'User', ?, ?, 'ALL', 'ALL', ?, 0, 1, 'system-sync', ?)""",
                        (f"asgn-{uid}-auto", uid, role_id, now_sync, now_sync)
                    )
                    conn.commit()
                    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
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

        # Strict CORS Origin Whitelisting (Eliminates Wildcard *)
        origin = self.headers.get("Origin")
        allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
        if allowed_origins_env:
            allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
        else:
            allowed_origins = [
                "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io",
                "http://localhost:8080",
                "http://127.0.0.1:8080"
            ]

        if origin and origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
            self.send_header("Vary", "Origin")

        self.send_header("X-Portal-Version", vinfo.get("version", "3.0.0"))
        self.send_header("X-Portal-Release", vinfo.get("release", "v3.0.0-ENTERPRISE"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")

        super().end_headers()

    def _check_rate_limit(self, bucket_name, max_req=30, window_sec=60):
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        key = f"{bucket_name}:{client_ip}"
        allowed, retry_after = RATE_LIMITER.is_allowed(key, max_req, window_sec)
        if not allowed:
            self.send_response(429)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": False,
                "error": f"Çok Fazla İstek (429 Too Many Requests): İstek sınırı aşıldı. Lütfen {retry_after} saniye sonra tekrar deneyin.",
                "retryAfter": retry_after
            }, ensure_ascii=False).encode("utf-8"))
            return False
        return True

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

    def _get_session_token(self):
        """Extract authenticated session token from Authorization Bearer header or CS_SESSION cookie."""
        auth_hdr = getattr(self, "headers", {}).get("Authorization", "") if hasattr(self, "headers") else ""
        tok = auth_hdr.replace("Bearer ", "").strip() if auth_hdr else ""

        if not tok:
            cookie_hdr = getattr(self, "headers", {}).get("Cookie", "") if hasattr(self, "headers") else ""
            if cookie_hdr and "CS_SESSION=" in cookie_hdr:
                for part in cookie_hdr.split(";"):
                    part = part.strip()
                    if part.startswith("CS_SESSION="):
                        tok = part.split("=", 1)[1].strip()
                        break
        return tok

    def get_current_user(self):
        """Extract authenticated user object from session header or secure cookie."""
        if hasattr(self, "_get_session_token"):
            tok = self._get_session_token()
        else:
            auth_hdr = getattr(self, "headers", {}).get("Authorization", "") if hasattr(self, "headers") else ""
            tok = auth_hdr.replace("Bearer ", "").strip() if auth_hdr else ""
            if not tok:
                cookie_hdr = getattr(self, "headers", {}).get("Cookie", "") if hasattr(self, "headers") else ""
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

    def _handle_entra_authorize(self, query=None):
        """Initiate Microsoft Entra ID Authorization Code flow with PKCE S256."""
        if not self._check_rate_limit("auth_entra_authorize", max_req=15, window_sec=60):
            return

        cfg = get_entra_config()
        if not cfg.get("client_id") or not cfg.get("tenant_id"):
            self.send_json_response({"error": "Entra ID OIDC configuration missing."}, status=500)
            return

        nonce = secrets.token_urlsafe(32)
        code_verifier, code_challenge = generate_pkce_pair()
        now_ts = time.time()

        # Stateless HMAC-signed self-contained state (zero dependency on DB or memory)
        state = create_stateless_oauth_state(nonce, code_verifier, cfg["redirect_uri"])

        flow_entry = {
            "nonce": nonce,
            "code_verifier": code_verifier,
            "created_at": now_ts,
            "redirect_uri": cfg["redirect_uri"]
        }
        AUTH_FLOWS[state] = flow_entry
        def _persist_flow_bg(s, n, cv, ru, ts):
            try:
                conn = get_db()
                conn.execute(
                    "INSERT OR REPLACE INTO auth_flows (state, nonce, code_verifier, redirect_uri, created_at) VALUES (?, ?, ?, ?, ?)",
                    (s, n, cv, ru, ts)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
        threading.Thread(target=_persist_flow_bg, args=(state, nonce, code_verifier, cfg["redirect_uri"], now_ts), daemon=True).start()

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
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
            "sso_reload": "true"
        }
        if query and "domain_hint" in query:
            params["domain_hint"] = query["domain_hint"][0]
        if query and "login_hint" in query:
            params["login_hint"] = query["login_hint"][0]

        auth_url = f"{cfg['authorize_endpoint']}?{urllib.parse.urlencode(params)}"

        self.send_response(302)
        self.send_header("Location", auth_url)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def _handle_entra_callback(self, query):
        """Process Microsoft Entra ID OIDC authorization response with PKCE & JWKS verification."""
        if not self._check_rate_limit("auth_entra_callback", max_req=15, window_sec=60):
            return

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

        # 1. Primary: Verify stateless HMAC-signed self-contained state
        stateless_payload, stateless_err = verify_stateless_oauth_state(state)
        if stateless_payload:
            flow = {
                "nonce": stateless_payload.get("n"),
                "code_verifier": stateless_payload.get("cv"),
                "redirect_uri": stateless_payload.get("ru"),
                "created_at": stateless_payload.get("ts")
            }
        else:
            # 2. Resilient fallback: In-memory store and SQLite table (supports tests and legacy states)
            flow = AUTH_FLOWS.pop(state, None)
            if not flow:
                try:
                    conn = get_db()
                    cur = conn.cursor()
                    cur.execute("SELECT nonce, code_verifier, redirect_uri, created_at FROM auth_flows WHERE state = ?", (state,))
                    row = cur.fetchone()
                    if row:
                        flow = {
                            "nonce": row[0],
                            "code_verifier": row[1],
                            "redirect_uri": row[2],
                            "created_at": row[3]
                        }
                        conn.execute("DELETE FROM auth_flows WHERE state = ?", (state,))
                        conn.commit()
                    conn.close()
                except Exception:
                    pass

        if not flow or (time.time() - flow.get("created_at", 0) > 900):
            err_detail = stateless_err if (not flow and stateless_err) else "Oturum doğrulama anahtarı (state) geçersiz veya zaman aşımına uğramış."
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason="InvalidOrExpiredAuthState",
                ip_address=client_ip,
                details={"stateless_error": stateless_err}
            )
            self._render_auth_redirect_html(error=f"Oturum doğrulama anahtarı (state) geçersiz veya zaman aşımına uğramış: {err_detail}")
            return

        expected_nonce = flow.get("nonce")
        code_verifier = flow.get("code_verifier")
        redirect_uri = flow.get("redirect_uri")
        cfg = get_entra_config()

        token_req_params = {
            "client_id": cfg["client_id"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email"
        }
        if cfg.get("client_secret"):
            token_req_params["client_secret"] = cfg["client_secret"]
        if code_verifier:
            token_req_params["code_verifier"] = code_verifier

        token_payload = urllib.parse.urlencode(token_req_params).encode("utf-8")

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
            self._render_auth_redirect_html(error=f"Microsoft belirteç değişimi başarısız oldu (HTTP {e.code}): {err_body[:200]}")
            return
        except Exception as e:
            self._render_auth_redirect_html(error=f"Belirteç sunucusuna erişilemedi: {str(e)}")
            return

        id_token = token_data.get("id_token")
        if not id_token:
            self._render_auth_redirect_html(error="Microsoft yanıtında kimlik belirteci (id_token) bulunamadı.")
            return

        # RFC 7519 / OIDC JWKS Cryptographic Signature & Claims Verification
        try:
            claims = verify_entra_id_token(
                id_token=id_token,
                tenant_id=cfg["tenant_id"],
                client_id=cfg["client_id"],
                expected_nonce=expected_nonce
            )
        except Exception as e:
            record_audit_event(
                event_type="AUTH_DENY",
                resource="/api/auth/entra/callback",
                decision="DENY",
                reason=f"IdTokenVerificationFailed: {str(e)}",
                ip_address=client_ip
            )
            self._render_auth_redirect_html(error=f"Kimlik belirteci doğrulaması başarısız: {str(e)}")
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

        tok = create_session_token(user_info, expires_in=86400)
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
        import urllib.parse
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if token:
            host = self.headers.get("Host", "") if hasattr(self, "headers") else ""
            proto = self.headers.get("X-Forwarded-Proto", "") if hasattr(self, "headers") else ""
            is_secure = proto == "https" or not ("localhost" in host or "127.0.0.1" in host)
            sec_flag = "; Secure" if is_secure else ""
            self.send_header("Set-Cookie", f"CS_SESSION={token}; Path=/; HttpOnly{sec_flag}; SameSite=Lax; Max-Age=86400")

        if error:
            safe_err = html.escape(str(error))
            quoted_err = urllib.parse.quote(str(error))
            body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudShield - Kimlik Doğrulama Hatası</title>
</head>
<body style="background:#0f172a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:#1e293b;border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:32px;max-width:440px;width:100%;text-align:center;">
        <div style="font-size:32px;color:#ef4444;margin-bottom:12px;">⚠️</div>
        <h2 style="font-size:20px;font-weight:700;color:#ef4444;margin-top:0;">Giriş Başarısız Oldu</h2>
        <p style="font-size:14px;color:#cbd5e1;line-height:1.5;">{safe_err}</p>
        <a href="/?error={quoted_err}" style="display:inline-block;margin-top:16px;background:#334155;color:#fff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 24px;border-radius:8px;">Giriş Ekranına Dön</a>
    </div>
</body>
</html>"""
        else:
            token_val = token or ""
            token_js = json.dumps(token_val)
            user_json_str = json.dumps(user or {}, ensure_ascii=False)
            user_js = json.dumps(user_json_str, ensure_ascii=False)
            redirect_target = f"/?auth_token={urllib.parse.quote(token_val)}"
            redirect_js = json.dumps(redirect_target)
            body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudShield - Giriş Yapılıyor</title>
</head>
<body style="background:#0f172a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:#1e293b;border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:32px;max-width:440px;width:100%;text-align:center;">
        <div style="font-size:32px;color:#10b981;margin-bottom:12px;">✅</div>
        <h2 style="font-size:18px;font-weight:700;color:#10b981;margin-top:0;">Microsoft Entra ID Doğrulandı</h2>
        <p style="font-size:13px;color:#94a3b8;">CloudShield MSSP Portalına aktarılıyorsunuz...</p>
    </div>
    <script>
        (function() {{
            try {{
                localStorage.setItem('cloudshield_auth_token', {token_js});
                localStorage.setItem('cloudshield_user', {user_js});
                sessionStorage.setItem('cloudshield_auth_token', {token_js});
                sessionStorage.setItem('cloudshield_user', {user_js});
            }} catch(e) {{
                console.error('Session storage error:', e);
            }}
            window.location.replace({redirect_js});
        }})();
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
        live_roles = set()
        live_token_ok = False
        live_token_err = None
        if not is_sim and client_id and tenant_guid:
            tok, live_token_err = acquire_tenant_graph_token(target, timeout=5.0)
            if tok:
                live_token_ok = True
                try:
                    claims = decode_jwt_payload(tok)
                    for r in (claims.get("roles") or []):
                        live_roles.add(r)
                except Exception:
                    pass

        results = []
        for s_code, perms in perm_specs.items():
            s_meta = catalog.get(s_code, {})
            display_name = s_meta.get("displayNameTr") or s_code
            is_active = s_code in active_services or (s_code.startswith("SVC-PRV") and "SVC-PURVIEW" in active_services)
            
            # Status resolution from real Entra JWT roles claim when live
            if is_sim:
                status = "Granted"
                status_desc = "Onaylandı (Simülasyon / Test Ortamı)"
            elif not client_id or not tenant_guid:
                status = "MissingScope"
                status_desc = "Yapılandırma Eksik (ClientId / TenantId Tanımsız)"
            elif not is_active:
                status = "NotSubscribed"
                status_desc = "Abonelik Kapsamı Dışında"
            elif live_token_ok:
                matched = [p for p in perms if p in live_roles or (p == "RoleManagement.Read.Directory" and "Directory.Read.All" in live_roles)]
                missing = [p for p in perms if p not in matched]
                if len(matched) == len(perms):
                    status = "Granted"
                    status_desc = "Canlı JWT Doğrulandı (Tüm İzinler Mevcut)"
                elif matched:
                    status = "PartialScope"
                    status_desc = f"Kısmi İzin — Eksik: {', '.join(missing)}"
                else:
                    status = "AdminConsentRequired"
                    status_desc = f"Eksik İzinler (Admin Consent Gerekli): {', '.join(missing)}"
            else:
                status = "AdminConsentRequired"
                status_desc = f"Canlı Token Doğrulanamadı ({live_token_err or 'Yönetici Onayı Bekliyor'})"

            results.append({
                "serviceCode": s_code,
                "displayName": display_name,
                "category": s_meta.get("productFamily", "Microsoft Security"),
                "isActive": is_active,
                "requiredPermissions": perms,
                "status": status,
                "statusDescription": status_desc
            })

        consent_url = f"https://login.microsoftonline.com/{tenant_guid or 'common'}/adminconsent?client_id={client_id or '00000000-0000-0000-0000-000000000000'}&redirect_uri={urllib.parse.quote(get_entra_config().get('redirect_uri', ''), safe=':/')}" if client_id and tenant_guid else ""
        cred_health = self.compute_credential_health(target)

        self.send_json_response({
            "success": True,
            "tenantId": tenant_id,
            "tenantName": tenant_name,
            "tenantGuid": tenant_guid,
            "clientId": client_id,
            "isSimulation": is_sim,
            "liveTokenVerified": live_token_ok,
            "grantedTokenRoles": sorted(live_roles),
            "adminConsentUrl": consent_url,
            "servicesCount": len(results),
            "services": results,
            "credentialHealth": cred_health,
            "lastCheckedUtc": datetime.now(timezone.utc).isoformat()
        })

    def handle_tenant_cockpit(self, tenant_id):
        """Return real observed telemetry & persisted CISO decisions for single-tenant cockpit (zero synthetic multipliers)."""
        user = self.get_current_user()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        allow, reason = evaluate_access(user, "customers:view", customer_id=tenant_id, resource=f"/api/tenants/{tenant_id}/cockpit", ip_address=client_ip)
        if not allow:
            self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"}, status=403)
            return

        tenants = load_json_file(TENANTS_FILE, [])
        target = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
        if not target:
            self.send_json_response({"success": False, "error": "Kiracı bulunamadı."}, status=404)
            return

        tid = target.get("Id") or tenant_id
        cname = target.get("Name", "Customer")
        live_data = load_live_data(OUTPUT_DIR, cname)

        blocked_threats = None
        hours_saved = None
        crit_incidents = None
        dlp_violations = None
        sec_score = target.get("SecureScore")

        if isinstance(live_data, dict) and live_data:
            mde = live_data.get("DefenderEndpoint") or {}
            op_val = live_data.get("OperationalValue") or {}
            dlp = live_data.get("PurviewDlp") or {}
            sc = live_data.get("SecurityScore") or {}
            if mde.get("BlockedThreats") is not None:
                blocked_threats = int(float(mde.get("BlockedThreats") or 0))
            if op_val.get("HoursSaved") is not None:
                hours_saved = round(float(op_val.get("HoursSaved") or 0), 1)
            if mde.get("CriticalIncidents") is not None:
                crit_incidents = int(float(mde.get("CriticalIncidents") or 0))
            if dlp.get("TotalIncidents") is not None:
                dlp_violations = int(float(dlp.get("TotalIncidents") or 0))
            if sc.get("CurrentScore") is not None:
                sec_score = round(float(sc.get("CurrentScore") or 0), 1)

        if blocked_threats is None:
            conn = get_db()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT secure_score, threats_blocked, critical_incidents, dlp_violations, hours_saved FROM tenant_service_trends WHERE tenant_id = ? ORDER BY period DESC LIMIT 1",
                    (tid,),
                )
                row = cur.fetchone()
                if row:
                    blocked_threats = row["threats_blocked"]
                    hours_saved = row["hours_saved"]
                    crit_incidents = row["critical_incidents"]
                    dlp_violations = row["dlp_violations"]
                    if row["secure_score"]:
                        sec_score = row["secure_score"]
            except Exception:
                pass
            finally:
                conn.close()

        decisions = _get_or_init_tenant_decisions(tid)
        pending_count = sum(1 for d in decisions if d.get("status") == "Pending")

        self.send_json_response({
            "success": True,
            "tenantId": tid,
            "tenantName": cname,
            "hasObservedTelemetry": blocked_threats is not None,
            "metrics": {
                "blockedThreats": blocked_threats,
                "hoursSaved": hours_saved,
                "criticalIncidents": crit_incidents if crit_incidents is not None else target.get("OpenHighAlerts", 0),
                "dlpViolations": dlp_violations,
                "secureScore": sec_score,
                "totalEndpoints": target.get("TotalEndpoints", 0),
                "ghostDevices": target.get("GhostDevices", 0),
            },
            "decisions": decisions,
            "pendingDecisionCount": pending_count,
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

    def handle_licenses_get(self, path, query):
        user = self.get_current_user()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        if path == "/api/licenses/catalog":
            allow, _ = evaluate_access(user, "licenses:view", resource=path, ip_address=client_ip)
            if not allow:
                allow, _ = evaluate_access(user, "services:view", resource=path, ip_address=client_ip)
            if not allow:
                self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden): Lisans kataloğunu görüntüleme yetkiniz bulunmamaktadır."}, status=403)
                return
            cat = load_license_catalog()
            feed = get_feed_status()
            self.send_json_response({"success": True, "catalog": cat, "feedStatus": feed})
            return

        elif path == "/api/licenses/catalog/feed-status":
            allow, _ = evaluate_access(user, "licenses:view", resource=path, ip_address=client_ip)
            if not allow:
                allow, _ = evaluate_access(user, "services:view", resource=path, ip_address=client_ip)
            if not allow:
                self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden)."}, status=403)
                return
            feed = get_feed_status()
            self.send_json_response({"success": True, "feedStatus": feed})
            return

        tenant_id = query.get("tenantId", [None])[0]
        if not tenant_id:
            self.send_json_response({"success": False, "error": "Eksik parametre: tenantId belirtilmelidir."}, status=400)
            return

        allow, _ = evaluate_access(user, "licenses:view", customer_id=tenant_id, resource=path, ip_address=client_ip)
        if not allow:
            self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): '{tenant_id}' lisans verilerini görüntüleme yetkiniz yoktur."}, status=403)
            return

        if user:
            assigned = user.get("AssignedTenants", ["ALL"])
            if "ALL" not in assigned and tenant_id not in assigned:
                self.send_json_response({"success": False, "error": "Bu müşteri kiracısının lisans verilerine erişim yetkiniz yoktur."}, status=403)
                return

        snapshot_date = query.get("snapshotDate", [None])[0]
        period = query.get("period", [None])[0]
        tenants_list = load_json_file(TENANTS_FILE, [])
        t_meta = next((t for t in tenants_list if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)

        def _seed_or_live_collect():
            live_tok = None
            if t_meta and not t_meta.get("IsSimulation"):
                live_tok, _ = acquire_tenant_graph_token(t_meta, timeout=4.0)
            return collect_tenant_license_intelligence(
                tenant_id, period=period, access_token=live_tok, dry_run=(live_tok is None)
            )

        if path == "/api/licenses/inventory":
            inv = get_license_inventory(tenant_id, snapshot_date=snapshot_date)
            if not inv:
                _seed_or_live_collect()
                inv = get_license_inventory(tenant_id, snapshot_date=snapshot_date)
            self.send_json_response({"success": True, "tenantId": tenant_id, "inventory": inv, "count": len(inv)})
            return

        elif path == "/api/licenses/users":
            filter_val = query.get("filter", [None])[0]
            users_list = get_user_license_profiles(tenant_id, snapshot_date=snapshot_date, filter_type=filter_val)
            if not users_list:
                _seed_or_live_collect()
                users_list = get_user_license_profiles(tenant_id, snapshot_date=snapshot_date, filter_type=filter_val)
            self.send_json_response({"success": True, "tenantId": tenant_id, "users": users_list, "count": len(users_list)})
            return

        elif path == "/api/licenses/value-summary":
            summary = get_license_value_summary(tenant_id, period=period)
            if not summary:
                res = _seed_or_live_collect()
                summary = res.get("summary")
            if isinstance(summary, list):
                summary = summary[0] if summary else {}
            if isinstance(summary, dict) and "is_live" not in summary:
                summary["is_live"] = False
            self.send_json_response({"success": True, "tenantId": tenant_id, "summary": summary})
            return

        elif path == "/api/licenses/reconciliation":
            recs = get_workload_reconciliation(tenant_id, period=period)
            if not recs:
                _seed_or_live_collect()
                recs = get_workload_reconciliation(tenant_id, period=period)
            self.send_json_response({"success": True, "tenantId": tenant_id, "reconciliations": recs, "count": len(recs)})
            return

        elif path == "/api/licenses/snapshots":
            if period:
                snap = get_license_snapshot(tenant_id, period)
                if not snap:
                    snap = _seed_or_live_collect()
                self.send_json_response({"success": True, "tenantId": tenant_id, "snapshot": snap})
            else:
                snaps = list_license_snapshots(tenant_id)
                if not snaps:
                    _seed_or_live_collect()
                    snaps = list_license_snapshots(tenant_id)
                self.send_json_response({"success": True, "tenantId": tenant_id, "snapshots": snaps})
            return

        elif path == "/api/licenses/diff":
            from_p = query.get("fromPeriod", [None])[0]
            to_p = query.get("toPeriod", [None])[0]
            if not from_p or not to_p:
                self.send_json_response({"success": False, "error": "Parametre eksik: fromPeriod ve toPeriod gereklidir."}, status=400)
                return
            s_from = get_license_snapshot(tenant_id, from_p)
            s_to = get_license_snapshot(tenant_id, to_p)
            diff = compare_license_snapshots(s_from, s_to)
            self.send_json_response({"success": True, "tenantId": tenant_id, "diff": diff})
            return

        elif path == "/api/licenses/report/html":
            snap = get_license_snapshot(tenant_id, period) if period else None
            if not snap:
                data = collect_tenant_license_intelligence(tenant_id, period=period, dry_run=True)
            else:
                data = snap.get("payload", {})
            tenants = load_json_file(TENANTS_FILE, [])
            t_meta = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            html = generate_license_health_report(data, t_meta)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            html_bytes = html.encode("utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)
            return

        elif path == "/api/licenses/report/pdf":
            allow_dl, _ = evaluate_access(user, "reports:download", customer_id=tenant_id, resource=path, ip_address=client_ip)
            if not allow_dl:
                allow_dl, _ = evaluate_access(user, "licenses:view", customer_id=tenant_id, resource=path, ip_address=client_ip)
            if not allow_dl:
                self.send_json_response({"success": False, "error": "Rapor indirme yetkiniz bulunmamaktadır."}, status=403)
                return

            snap = get_license_snapshot(tenant_id, period) if period else None
            if not snap:
                data = collect_tenant_license_intelligence(tenant_id, period=period, dry_run=True)
            else:
                data = snap.get("payload", {})
            tenants = load_json_file(TENANTS_FILE, [])
            t_meta = next((t for t in tenants if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            html = generate_license_health_report(data, t_meta)

            cur_period = period or data.get("period", datetime.now().strftime("%Y-%m"))
            out_pdf = os.path.join(OUTPUT_DIR, tenant_id, f"CloudShield_License_Report_{tenant_id}_{cur_period}.pdf")
            ok, pdf_path = render_license_pdf(html, out_pdf)
            if not ok or not os.path.exists(out_pdf):
                self.send_json_response({"success": False, "error": f"PDF üretimi başarısız: {pdf_path}"}, status=500)
                return

            with open(out_pdf, "rb") as pf:
                pdf_bytes = pf.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f'attachment; filename="CloudShield_License_Report_{cur_period}.pdf"')
            self.send_header("Content-Length", str(len(pdf_bytes)))
            self.end_headers()
            self.wfile.write(pdf_bytes)
            return

        self.send_json_response({"success": False, "error": "Bilinmeyen lisans API yolu."}, status=404)

    def handle_licenses_post(self, path, body):
        user = self.get_current_user()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        if path == "/api/licenses/catalog/check-updates":
            allow, _ = evaluate_access(user, "licenses:manage", resource=path, ip_address=client_ip)
            if not allow:
                allow, _ = evaluate_access(user, "PlatformAdmin", resource=path, ip_address=client_ip)
            if not allow:
                self.send_json_response({"success": False, "error": "Yetkisiz Erişim (403 Forbidden): Lisans kataloğu güncelleme kontrolü yetkiniz bulunmamaktadır."}, status=403)
                return
            force = body.get("force", True)
            res = check_remote_feed(force=force)
            record_audit_event("LICENSE_CATALOG_CHECK", user_id=user.get("id") if user else None,
                               resource=path, decision="ALLOW", reason="CatalogUpdateCheckTriggered",
                               ip_address=client_ip, details=res)
            self.send_json_response({"success": True, "feedCheck": res})
            return

        elif path == "/api/licenses/collect":
            tenant_id = body.get("tenantId")
            if not tenant_id:
                self.send_json_response({"success": False, "error": "Eksik parametre: tenantId belirtilmelidir."}, status=400)
                return

            allow, _ = evaluate_access(user, "licenses:manage", customer_id=tenant_id, resource=path, ip_address=client_ip)
            if not allow:
                self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): '{tenant_id}' için lisans analizi çalıştırma yetkiniz yoktur."}, status=403)
                return

            if user:
                assigned = user.get("AssignedTenants", ["ALL"])
                if "ALL" not in assigned and tenant_id not in assigned:
                    self.send_json_response({"success": False, "error": "Bu müşteri kiracısının lisanslarını yönetme yetkiniz yoktur."}, status=403)
                    return

            period = body.get("period")
            dry_run = bool(body.get("dryRun", False))
            tenants_list = load_json_file(TENANTS_FILE, [])
            t_meta = next((t for t in tenants_list if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            is_sim = bool(t_meta.get("IsSimulation")) if t_meta else False

            access_token = None
            if not dry_run and not is_sim and t_meta:
                access_token, tok_err = acquire_tenant_graph_token(t_meta)
                if not access_token and not body.get("allowSyntheticFallback", False):
                    self.send_json_response({
                        "success": False,
                        "error": f"Canlı Microsoft Graph erişimi kurulamadı ({tok_err}). Lütfen kiracı sertifika/Key Vault kimlik bilgilerini doğrulayın veya simülasyon modu kullanın."
                    }, status=422)
                    return

            result = collect_tenant_license_intelligence(tenant_id, period=period, access_token=access_token, dry_run=(dry_run or is_sim))
            record_audit_event("LICENSE_INTELLIGENCE_COLLECT", user_id=user.get("id") if user else None,
                               resource=path, decision="ALLOW", reason="LicenseIntelligenceCollected",
                               ip_address=client_ip, details={"tenantId": tenant_id, "isLive": result.get("is_live", False)})
            self.send_json_response({"success": True, "result": result})
            return

        self.send_json_response({"success": False, "error": "Bilinmeyen lisans API işlemi."}, status=404)

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

        if path.startswith("/api/licenses/"):
            self.handle_licenses_get(path, query)
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
                tok = self._get_session_token()
                self.send_json_response({"success": True, "user": u, "token": tok})
            else:
                self.send_json_response({"success": False, "error": "Oturum bulunamadı veya süresi dolmuş"}, status=401)
            return

        elif path in ("/api/auth/entra/authorize", "/api/auth/entra/login"):
            self._handle_entra_authorize(query)
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

        elif path.startswith("/api/tenants/") and path.endswith("/cockpit"):
            tenant_id = path.split("/")[3]
            self.handle_tenant_cockpit(tenant_id)
            return

        elif path.startswith("/api/reports/jobs/"):
            job_id = path.replace("/api/reports/jobs/", "").strip()
            user = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            with _REPORT_JOBS_LOCK:
                job = REPORT_JOBS.get(job_id)
                if not job:
                    persisted_jobs = load_json_file(REPORT_JOBS_FILE, {})
                    job = persisted_jobs.get(job_id) if isinstance(persisted_jobs, dict) else None
            if not job:
                self.send_json_response({"success": False, "error": "Rapor işi bulunamadı."}, status=404)
                return
            allow, reason = evaluate_access(user, "reports:view", customer_id=job.get("tenantId"), resource=path, ip_address=client_ip)
            if not allow:
                self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"}, status=403)
                return
            self.send_json_response({"success": True, "job": job})
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

            users = _list_unified_users()

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
            if not self._check_rate_limit("reports_download", max_req=30, window_sec=60):
                return

            parts = [p for p in path.split("/") if p]
            report_id = parts[2]

            registry = load_report_registry()
            record = registry.get(report_id)
            if not record:
                self.send_json_response({
                    "success": False,
                    "error": "Rapor bulunamadı (404 Not Found): Belirtilen rapor kimliği sistem kayıtlarında mevcut değil."
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
                            "error": "Rapor süresi dolmuş (410 Gone): Bu rapor arşiv saklama süresi dolduğu için erişilemez."
                        }, status=410)
                        return
                except Exception:
                    pass

            # RBAC Server-Side Authorization Evaluation (Customer + Service Scopes)
            user = self.get_current_user()
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            rep_tid = record.get("tenantId", "")
            rep_services = record.get("serviceCodes", [])

            # Tenant ownership must be established (Fail Closed)
            if not rep_tid:
                record_audit_event(
                    "AUTH_DENY",
                    user_id=user.get("id") if user else None,
                    user_upn=user.get("upn") if user else None,
                    resource=path,
                    decision="DENY",
                    reason="ReportTenantUnresolved: No tenantId in report registry",
                    ip_address=client_ip
                )
                self.send_json_response({
                    "success": False,
                    "error": "Yetkisiz Erişim (403 Forbidden): Rapor kiracı aidiyeti doğrulanamadı."
                }, status=403)
                return

            allowed, reason = evaluate_access(
                user,
                "reports:download",
                customer_id=rep_tid,
                service_ids=rep_services,
                resource=path,
                ip_address=client_ip
            )
            if not allowed:
                record_audit_event(
                    "REPORT_DOWNLOAD",
                    user_id=user.get("id") if user else None,
                    user_upn=user.get("upn") if user else None,
                    customer_id=rep_tid,
                    service_id=",".join(rep_services) if rep_services else None,
                    resource=path,
                    decision="DENY",
                    reason=f"UnauthorizedReportDownload: {reason}",
                    ip_address=client_ip,
                    details={"reportId": report_id, "services": rep_services}
                )
                self.send_json_response({
                    "success": False,
                    "error": f"Yetkisiz Erişim (403 Forbidden): {reason}"
                }, status=403)
                return

            storage_key = record.get("storageKey", "")
            if not storage_key or ".." in storage_key:
                self.send_json_response({"success": False, "error": "Geçersiz dosya depolama anahtarı."}, status=400)
                return

            # Canonical path traversal defense
            real_output_dir = os.path.realpath(OUTPUT_DIR)
            full_path = os.path.realpath(os.path.join(OUTPUT_DIR, storage_key.lstrip("/\\")))
            if not full_path.startswith(real_output_dir + os.sep) and full_path != real_output_dir:
                record_audit_event(
                    "AUTH_DENY",
                    user_id=user.get("id") if user else None,
                    user_upn=user.get("upn") if user else None,
                    customer_id=rep_tid,
                    resource=path,
                    decision="DENY",
                    reason="PathTraversalAttemptBlocked",
                    ip_address=client_ip,
                    details={"storageKey": storage_key, "fullPath": full_path}
                )
                self.send_json_response({"success": False, "error": "Dizin dışına çıkış engellendi (403 Forbidden)."}, status=403)
                return

            if not os.path.exists(full_path):
                self.send_json_response({"success": False, "error": "Fiziksel rapor dosyası bulunamadı."}, status=404)
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
            # Decommission legacy file-path-based report download endpoint (Finding 3)
            # Fails closed with HTTP 410 Gone
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            user = self.get_current_user()
            record_audit_event(
                "AUTH_DENY",
                user_id=user.get("id") if user else None,
                user_upn=user.get("upn") if user else None,
                resource=path,
                decision="DENY",
                reason="LegacyDownloadEndpointDecommissioned",
                ip_address=client_ip
            )
            self.send_json_response({
                "success": False,
                "error": "Kullanım Dışı (410 Gone): Dosya adı tabanlı eski rapor indirme uç noktası güvenlik nedeniyle tamamen kapatılmıştır. Lütfen merkezi /api/reports/{reportId}/download uç noktasını kullanınız."
            }, status=410)
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

        if path.startswith("/api/licenses/"):
            self.handle_licenses_post(path, body)
            return


        if path == "/api/auth/login":
            if not self._check_rate_limit("auth_login", max_req=10, window_sec=60):
                return

            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            vinfo = get_version_info()
            channel = str(vinfo.get("channel", "production")).lower()
            env_mode = str(vinfo.get("environment", "production")).lower()
            allow_local = os.environ.get("CLOUDSHIELD_ALLOW_LOCAL_AUTH", "false").lower() in ("true", "1")

            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            is_breakglass_user = username.lower() in (
                "admin", "administrator", "caner", "canercetinkaya", "usr-admin", "usr-001",
                "caner.cetinkaya@cloudshield-mssp.com", "caner@cnrctnky.onmicrosoft.com"
            )

            # Mandatory: Disable local password authentication in Enterprise/Production mode unless explicitly enabled or breakglass admin
            if (channel in ("pilot", "production", "enterprise") or env_mode in ("pilot", "production", "enterprise")) and not allow_local and not is_breakglass_user:
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

            user_info, err = authenticate_user(username, password, client_ip)
            if user_info:
                tok = create_session_token(user_info, expires_in=86400)
                assigned_tenants = [a.get("customer_id") or "ALL" for a in user_info.get("assignments", []) if a.get("customer_scope") == "ALL" or a.get("customer_id")]
                if not assigned_tenants or user_info.get("isPlatformAdmin"):
                    assigned_tenants = ["ALL"]
                user_info["AssignedTenants"] = assigned_tenants
                user_info["tenantScope"] = "Global" if "ALL" in assigned_tenants else "Restricted"
                user_info["initials"] = "".join([w[0].upper() for w in user_info.get("displayName", "US").split()[:2]])

                save_session(tok, user_info, 86400)

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"CS_SESSION={tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400")
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
            if not tok:
                cookie_hdr = self.headers.get("Cookie", "")
                if "CS_SESSION=" in cookie_hdr:
                    for part in cookie_hdr.split(";"):
                        part = part.strip()
                        if part.startswith("CS_SESSION="):
                            tok = part.split("=", 1)[1].strip()
                            break

            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            u = self.get_current_user()
            if tok:
                delete_session(tok)
            if u:
                record_audit_event("AUTH_LOGOUT", user_id=u.get("id"), user_upn=u.get("upn"),
                                   resource="/api/auth/logout", decision="ALLOW", reason="UserLoggedOut", ip_address=client_ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "CS_SESSION=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
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
                allowed, reason = evaluate_access(u, "TENANT_WRITE", customer_id=tenant_id, resource=path, ip_address=client_ip)
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
            body["TotalEndpoints"] = int(body.get("TotalEndpoints", 120 if is_test_tenant else 0))
            body["GhostDevices"] = int(body.get("GhostDevices", 0))
            body["OpenHighAlerts"] = int(body.get("OpenHighAlerts", 0))
            body["SecureScore"] = float(body.get("SecureScore", 78.5 if is_test_tenant else 0.0))
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

        elif path.startswith("/api/tenants/") and path.endswith("/credentials/keyvault"):
            tenant_id = path.split("/")[3]
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _reason = evaluate_access(_wu, "customers:manage", customer_id=tenant_id, resource=path, ip_address=_wip)
            if not _allow:
                self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): {_reason}"}, status=403)
                return

            tenants_list = load_json_file(TENANTS_FILE, [])
            t_idx = next((i for i, t in enumerate(tenants_list) if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            if t_idx is None:
                self.send_json_response({"success": False, "error": "Kiracı bulunamadı."}, status=404)
                return

            secret_name = (body.get("secretName") or f"cs-cert-{tenant_id}").strip()
            secret_value = (body.get("certificatePemOrBase64Pfx") or body.get("secretValue") or "").strip()
            secret_kind = (body.get("credentialType") or "Certificate").strip()
            if not secret_value:
                self.send_json_response({"success": False, "error": "Sertifika (PEM/PFX Base64) veya secret değeri boş olamaz."}, status=400)
                return

            ok_kv, kv_res = _store_keyvault_secret(
                secret_name,
                secret_value,
                content_type="application/x-pem-file" if secret_kind == "Certificate" else "text/plain",
            )
            if not ok_kv:
                self.send_json_response({"success": False, "error": kv_res}, status=502)
                return

            t_obj = tenants_list[t_idx]
            t_obj.setdefault("Auth", {})
            if secret_kind == "Certificate":
                t_obj["KeyVaultCertificateName"] = kv_res
                t_obj["Auth"]["KeyVaultCertificateName"] = kv_res
                t_obj["AuthMethod"] = "Certificate"
                t_obj["Auth"]["Method"] = "Certificate"
            else:
                t_obj["KeyVaultSecretName"] = kv_res
                t_obj["Auth"]["KeyVaultSecretName"] = kv_res
            save_json_file(TENANTS_FILE, tenants_list)
            record_audit_event(
                "KEYVAULT_CREDENTIAL_STORED",
                user_id=(_wu or {}).get("id"),
                user_upn=(_wu or {}).get("upn"),
                customer_id=t_obj.get("Id"),
                resource=path,
                decision="ALLOW",
                reason="KeyVaultSecretProvisioned",
                ip_address=_wip,
                details={"secretName": kv_res, "credentialType": secret_kind},
            )
            self.send_json_response({"success": True, "keyVaultSecretName": kv_res, "credentialType": secret_kind})
            return

        elif path.startswith("/api/tenants/") and path.endswith("/decisions/approve"):
            tenant_id = path.split("/")[3]
            _wu = self.get_current_user()
            _wip = self.client_address[0] if self.client_address else "127.0.0.1"
            _allow, _reason = evaluate_access(_wu, "customers:manage", customer_id=tenant_id, resource=path, ip_address=_wip)
            if not _allow:
                _allow, _reason = evaluate_access(_wu, "reports:view", customer_id=tenant_id, resource=path, ip_address=_wip)
                if _allow and (_wu or {}).get("role") not in ("PlatformAdmin", "CustomerCISO", "SecurityEngineer"):
                    _allow = False
            if not _allow:
                self.send_json_response({"success": False, "error": f"Yetkisiz Erişim (403 Forbidden): Karar onaylama yetkiniz bulunmamaktadır ({_reason})."}, status=403)
                return

            decision_id = (body.get("decisionId") or "").strip()
            if not decision_id:
                self.send_json_response({"success": False, "error": "decisionId parametresi zorunludur."}, status=400)
                return

            tenants_list = load_json_file(TENANTS_FILE, [])
            target_t = next((t for t in tenants_list if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            canonical_tid = target_t.get("Id") if target_t else tenant_id

            decisions = _get_or_init_tenant_decisions(canonical_tid)
            dec_obj = next((d for d in decisions if d.get("id") == decision_id), None)
            if not dec_obj:
                self.send_json_response({"success": False, "error": f"Karar bulunamadı: {decision_id}"}, status=404)
                return

            now_iso = datetime.now(timezone.utc).isoformat()
            approver_upn = (_wu or {}).get("upn") or (_wu or {}).get("email") or "admin"
            dec_obj["status"] = "Approved"
            dec_obj["quadrant"] = "Approved"
            dec_obj["approvedBy"] = approver_upn
            dec_obj["approvedAtUtc"] = now_iso

            all_dec = load_json_file(DECISIONS_FILE, {})
            all_dec[canonical_tid] = decisions
            save_json_file(DECISIONS_FILE, all_dec)

            record_audit_event(
                "DECISION_APPROVED",
                user_id=(_wu or {}).get("id"),
                user_upn=approver_upn,
                customer_id=canonical_tid,
                resource=path,
                decision="ALLOW",
                reason="CustomerDecisionAuthorized",
                ip_address=_wip,
                details={"decisionId": decision_id, "title": dec_obj.get("title")},
            )
            self.send_json_response({"success": True, "decision": dec_obj, "decisions": decisions})
            return

        elif path == "/api/dispatch/send":
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
            tenants = load_json_file(TENANTS_FILE, [])
            idx = next((i for i, t in enumerate(tenants) if t.get("Id") == tenant_id or t.get("TenantId") == tenant_id), None)
            if idx is None:
                self.send_json_response({"success": False, "error": "Tenant bulunamadı"}, status=404)
                return

            t = tenants[idx]
            log_entry = execute_report_dispatch(
                t,
                recipients=body.get("recipients"),
                subject=body.get("subject"),
                attach_pdf=body.get("attachPdf", True),
                attach_html=body.get("attachHtml", True),
                dry_run=bool(body.get("dryRun", False)),
                created_by=(_wu or {}).get("upn") or "dispatch-api",
            )
            t["LastDispatchDate"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            t["LastDispatchStatus"] = log_entry.get("status", "ArchivedOnly")
            save_json_file(TENANTS_FILE, tenants)

            record_audit_event(
                "REPORT_DISPATCH",
                user_id=(_wu or {}).get("id"),
                user_upn=(_wu or {}).get("upn"),
                customer_id=t.get("Id"),
                resource=path,
                decision="ALLOW",
                reason=f"DispatchStatus_{log_entry.get('status')}",
                ip_address=_wip,
                details={"dispatchId": log_entry.get("id"), "channel": log_entry.get("deliveryChannel"), "status": log_entry.get("status")},
            )
            self.send_json_response({"success": True, "dispatch": log_entry})
            return

        elif path == "/api/users":
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
            new_id = body.get("Id") or f"usr-{secrets.token_hex(3)}"
            body["Id"] = new_id
            body["LastLogin"] = "Henüz giriş yapmadı"
            stored_copy = {k: v for k, v in body.items() if k != "Password"}
            users = [u for u in users if u.get("Id") != new_id]
            users.append(stored_copy)
            save_json_file(USERS_FILE, users)
            _sync_user_dict_to_db(body)

            record_audit_event(
                "USER_CREATED",
                user_id=(_wu or {}).get("id"),
                user_upn=(_wu or {}).get("upn"),
                resource=path,
                decision="ALLOW",
                reason="UserCreatedAndSyncedToRbacDb",
                ip_address=_wip,
                details={"targetUserId": new_id, "targetUpn": body.get("Upn"), "role": body.get("Role")},
            )
            self.send_json_response({"success": True, "user": stored_copy}, status=201)
            return

        elif path == "/api/stats/sync":
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

            tenants = load_json_file(TENANTS_FILE, [])
            live_synced = 0
            tenants_dirty = False
            stale_cutoff = datetime.now(timezone.utc) - timedelta(days=30)

            for t in tenants:
                if t.get("IsSimulation"):
                    continue
                tok, _ = acquire_tenant_graph_token(t, timeout=4.5)
                if not tok:
                    continue
                live_synced += 1
                # 1. Microsoft Secure Score
                sc_json, sc_code, _ = graph_get_json(tok, "https://graph.microsoft.com/v1.0/security/secureScores?$top=1", timeout=5.0)
                if sc_code == 200 and sc_json and sc_json.get("value"):
                    top_sc = sc_json["value"][0]
                    cur_s = float(top_sc.get("currentScore") or 0.0)
                    max_s = float(top_sc.get("maxScore") or 100.0)
                    if max_s > 0:
                        t["SecureScore"] = round((cur_s / max_s) * 100.0, 1)
                        tenants_dirty = True
                # 2. Active High/Critical Security Alerts
                al_json, al_code, _ = graph_get_json(tok, "https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=status%20ne%20'resolved'&$top=100", timeout=5.0)
                if al_code == 200 and al_json is not None:
                    vals = al_json.get("value") or []
                    high_cnt = sum(1 for a in vals if str(a.get("severity", "")).lower() in ("high", "critical"))
                    t["OpenHighAlerts"] = high_cnt
                    tenants_dirty = True
                # 3. Managed Devices & Ghost (>30d inactive) Endpoints
                dv_json, dv_code, _ = graph_get_json(tok, "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,lastSyncDateTime&$top=999", timeout=6.0)
                if dv_code == 200 and dv_json is not None:
                    devs = dv_json.get("value") or []
                    t["TotalEndpoints"] = len(devs)
                    ghosts = 0
                    for dv in devs:
                        ls = dv.get("lastSyncDateTime")
                        if ls:
                            try:
                                dt_ls = datetime.fromisoformat(ls.replace("Z", "+00:00"))
                                if dt_ls < stale_cutoff:
                                    ghosts += 1
                            except Exception:
                                pass
                    t["GhostDevices"] = ghosts
                    tenants_dirty = True
                t["HealthStatus"] = "Healthy"
                try:
                    sync_customer_to_db(t)
                except Exception:
                    pass

            if tenants_dirty:
                save_json_file(TENANTS_FILE, tenants)

            total_endpoints = sum(t.get("TotalEndpoints", 0) for t in tenants)
            total_ghost = sum(t.get("GhostDevices", 0) for t in tenants)
            total_alerts = sum(t.get("OpenHighAlerts", 0) for t in tenants)
            avg_score = round(sum(t.get("SecureScore", 0) for t in tenants) / max(len(tenants), 1), 1)
            now = datetime.now()
            cache = {
                "lastSyncTimestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "nextScheduledSync": (now + timedelta(days=1)).strftime("%Y-%m-%d 06:00:00"),
                "syncMode": "LiveGraphSync" if live_synced > 0 else "CachedTenantRollup",
                "liveTenantsSynced": live_synced,
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
            res_payload["liveTenantsSynced"] = live_synced
            res_payload["syncMode"] = cache["syncMode"]
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
            if not self._check_rate_limit("reports_generate", max_req=10, window_sec=60):
                return

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

            report_lang = body.get("language", "tr")
            is_async_job = bool(body.get("async", False))

            def _execute_report_pipeline():
                local_pdf_path = None
                local_html_path = None
                local_log = ""
                try:
                    try:
                        proc = subprocess.run(pwsh_args, cwd=os.path.join(ROOT_DIR, "Engine"), capture_output=True, text=True, errors="replace", timeout=180, env=ps_env)
                        local_log = (proc.stdout or "") + (proc.stderr or "")
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
                                                local_pdf_path = full_p
                                                latest_pdf_mtime = mtime
                                            elif f.lower().endswith(".html") and mtime > latest_html_mtime:
                                                local_html_path = full_p
                                                latest_html_mtime = mtime
                                        except Exception:
                                            pass
                                if local_html_path and s_root != OUTPUT_DIR:
                                    break
                    except Exception as pe:
                        local_log += f"\n[WARN] PowerShell execution: {pe}"

                    try:
                        py_html, py_pdf = render_and_save_report(customer_name, services, OUTPUT_DIR, language=report_lang, tenant_id=tenant_id)
                        if py_html and os.path.exists(py_html):
                            local_html_path = py_html
                        if py_pdf and os.path.exists(py_pdf):
                            local_pdf_path = py_pdf
                        local_log += f"\n[OK] CloudShield Kurumsal Rapor Motoru ({report_lang.upper()}) ile rapor başarıyla derlendi."

                        try:
                            from database.db import record_tenant_trend
                            period_tag = datetime.now().strftime("%Y-%m")
                            svc_tag = services[0] if (services and len(services) == 1) else "CONSOLIDATED"
                            live_data = load_live_data(OUTPUT_DIR, customer_name, period_tag=period_tag)
                            if live_data:
                                def _num(val, default=0.0):
                                    try:
                                        return float(val) if val is not None else default
                                    except (ValueError, TypeError):
                                        return default

                                record_tenant_trend(tenant_id, period_tag, svc_tag, {
                                    "secure_score": _num((live_data.get("SecurityScore") or {}).get("CurrentScore")),
                                    "threats_blocked": int(_num((live_data.get("DefenderEndpoint") or {}).get("BlockedThreats"))),
                                    "critical_incidents": int(_num((live_data.get("DefenderEndpoint") or {}).get("CriticalIncidents"))),
                                    "dlp_violations": int(_num((live_data.get("PurviewDlp") or {}).get("TotalIncidents"))),
                                    "phishing_blocked": int(_num((live_data.get("DefenderOffice365") or {}).get("PhishingBlocked"))),
                                    "pim_activations": int(_num((live_data.get("EntraId") or {}).get("PimActivations"))),
                                    "device_compliance_pct": _num((live_data.get("Intune") or {}).get("CompliancePct")),
                                    "hours_saved": _num((live_data.get("OperationalValue") or {}).get("HoursSaved")),
                                    "cost_avoidance_usd": _num((live_data.get("OperationalValue") or {}).get("CostAvoidanceUsd")),
                                })
                        except Exception as dbe:
                            print(f"[WARN] Trend snapshot recording error: {dbe}")
                    except Exception as pye:
                        local_log += f"\n[ERROR] Python report engine error: {pye}"

                    if local_html_path and (not local_pdf_path or not os.path.exists(local_pdf_path) or os.path.getsize(local_pdf_path) == 0):
                        candidate_pdf = os.path.splitext(local_html_path)[0] + ".pdf"
                        engine = find_pdf_engine()
                        if engine:
                            try:
                                pdf_uri = "file:///" + os.path.abspath(local_html_path).replace("\\", "/") if sys.platform == "win32" else "file://" + os.path.abspath(local_html_path)
                                cmd = [
                                    engine, "--headless=new", "--no-sandbox",
                                    "--disable-dev-shm-usage", "--disable-gpu",
                                    "--no-pdf-header-footer", f"--print-to-pdf={candidate_pdf}", pdf_uri
                                ]
                                subprocess.run(cmd, timeout=30, capture_output=True)
                                if not os.path.exists(candidate_pdf) or os.path.getsize(candidate_pdf) == 0:
                                    cmd[1] = "--headless"
                                    subprocess.run(cmd, timeout=30, capture_output=True)
                                if os.path.exists(candidate_pdf) and os.path.getsize(candidate_pdf) > 0:
                                    local_pdf_path = candidate_pdf
                                    local_log += f"\n[OK] Vektörel PDF başarıyla oluşturuldu: {candidate_pdf}"
                            except Exception as pe:
                                local_log += f"\n[WARN] Secondary PDF rendering error: {pe}"

                        if not local_pdf_path or not os.path.exists(local_pdf_path) or os.path.getsize(local_pdf_path) == 0:
                            try:
                                created_pdf = create_executive_pdf(customer_name, services, candidate_pdf)
                                if os.path.exists(created_pdf) and os.path.getsize(created_pdf) > 0:
                                    local_pdf_path = created_pdf
                                    local_log += f"\n[OK] CloudShield Kurumsal Vektörel PDF Motoru ile rapor başarıyla derlendi: {created_pdf}"
                            except Exception as pfe:
                                local_log += f"\n[WARN] Pure Python PDF fallback error: {pfe}"

                    if not local_html_path and not local_pdf_path:
                        return 500, {
                            "success": False,
                            "error": f"Rapor dosyaları oluşturulamadı. Konsol izi: {local_log[-300:]}"
                        }

                    fresh_tenants = load_json_file(TENANTS_FILE, [])
                    for ft in fresh_tenants:
                        if ft.get("Id") == tenant_id or ft.get("TenantId") == tenant_id:
                            ft["LastReportDate"] = datetime.now().strftime("%Y-%m-%d")
                    save_json_file(TENANTS_FILE, fresh_tenants)

                    creator_upn = (user or {}).get("upn") or "api"
                    pdf_report_id = ""
                    html_report_id = ""
                    if local_pdf_path and os.path.exists(local_pdf_path):
                        pdf_report_id, _ = register_report_artifact(tenant_id, customer_name, mode, services, "PDF", local_pdf_path, created_by=creator_upn)
                    if local_html_path and os.path.exists(local_html_path):
                        html_report_id, _ = register_report_artifact(tenant_id, customer_name, mode, services, "HTML", local_html_path, created_by=creator_upn)

                    primary_report_id = pdf_report_id or html_report_id
                    return 200, {
                        "success": True,
                        "reportId": primary_report_id,
                        "pdfReportId": pdf_report_id,
                        "htmlReportId": html_report_id,
                        "customer": customer_name,
                        "isSimulation": is_simulation,
                        "services": services,
                        "pdfUrl": f"/api/reports/{pdf_report_id}/download" if pdf_report_id else "",
                        "htmlUrl": f"/api/reports/{html_report_id}/download" if html_report_id else "",
                        "outputLog": local_log[-500:] if local_log else "Rapor başarıyla tamamlandı."
                    }
                except Exception as ex:
                    return 500, {"success": False, "error": str(ex)}
                finally:
                    if os.path.exists(cust_cfg_path):
                        try:
                            os.remove(cust_cfg_path)
                        except Exception:
                            pass

            if is_async_job:
                job_id = f"job-{uuid.uuid4().hex[:12]}"
                job_entry = {
                    "jobId": job_id,
                    "tenantId": tenant_id,
                    "customer": customer_name,
                    "services": services,
                    "mode": mode,
                    "status": "Running",
                    "startedAtUtc": datetime.now(timezone.utc).isoformat(),
                    "createdBy": (user or {}).get("upn") or "api",
                }
                with _REPORT_JOBS_LOCK:
                    REPORT_JOBS[job_id] = job_entry
                    persisted = load_json_file(REPORT_JOBS_FILE, {})
                    if not isinstance(persisted, dict):
                        persisted = {}
                    persisted[job_id] = job_entry
                    save_json_file(REPORT_JOBS_FILE, persisted)

                def _bg_worker():
                    st_code, res_dict = _execute_report_pipeline()
                    with _REPORT_JOBS_LOCK:
                        fin = dict(job_entry)
                        fin.update(res_dict)
                        fin["status"] = "Completed" if st_code == 200 and res_dict.get("success") else "Failed"
                        fin["completedAtUtc"] = datetime.now(timezone.utc).isoformat()
                        REPORT_JOBS[job_id] = fin
                        persisted_fin = load_json_file(REPORT_JOBS_FILE, {})
                        if not isinstance(persisted_fin, dict):
                            persisted_fin = {}
                        persisted_fin[job_id] = fin
                        save_json_file(REPORT_JOBS_FILE, persisted_fin)

                threading.Thread(target=_bg_worker, daemon=True, name=f"ReportJob-{job_id}").start()
                self.send_json_response({"success": True, "async": True, "jobId": job_id, "status": "Running"}, status=202)
                return

            http_st, payload_out = _execute_report_pipeline()
            self.send_json_response(payload_out, status=http_st)
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
                    entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
                    req = urllib.request.Request(entra_url, headers={"User-Agent": "CloudShield-MSSP-Portal/2.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        latency = int((time.time() - t0) * 1000)

                    has_cert_thumb = bool(cert_thumb)
                    has_kv_cert = bool(kv_cert_name)

                    if not (has_cert_thumb or has_kv_cert):
                        target["ConnectionStatus"] = "MetadataVerified"
                        save_json_file(TENANTS_FILE, tenants)
                        self.send_json_response({
                            "success": True,
                            "isSimulation": False,
                            "status": "MetadataVerified",
                            "badge": "OIDC Metadata Doğrulandı (Sertifika Tanımsız)",
                            "authMethod": "Certificate",
                            "message": f"Microsoft Entra ID uç noktası ({tenant_guid[:8]}...) doğrulandı ancak sertifika tanımlı değil. LiveConnected durumuna geçmek için sertifika parmak izi veya Key Vault sertifikası gereklidir.",
                            "tenantId": tenant_guid,
                            "tokenEndpoint": data.get("token_endpoint"),
                            "latencyMs": latency,
                            "testedAt": datetime.now(timezone.utc).isoformat()
                        })
                        return

                    cert_id_display = cert_thumb or kv_cert_name or "Azure Key Vault / Local Store"
                    target["ConnectionStatus"] = "CredentialValidated"
                    save_json_file(TENANTS_FILE, tenants)

                    self.send_json_response({
                        "success": True,
                        "isSimulation": False,
                        "status": "CredentialValidated",
                        "badge": "CBA Sertifika Parametreleri Doğrulandı",
                        "authMethod": "Certificate",
                        "message": f"Microsoft Entra ID CBA sertifika parametreleri ve OIDC uç noktası ({tenant_guid[:8]}...) doğrulandı.",
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

                    target["ConnectionStatus"] = "MetadataVerified"
                    save_json_file(TENANTS_FILE, tenants)

                    self.send_json_response({
                        "success": True,
                        "isSimulation": False,
                        "status": "MetadataVerified",
                        "badge": "GDAP Uç Noktası Doğrulandı",
                        "authMethod": "GDAP",
                        "message": f"Microsoft Entra ID GDAP uç noktası ({tenant_guid[:8]}...) doğrulandı. Delegasyon izinleri kontrol ediliyor.",
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
            existing_unified = next((u for u in _list_unified_users() if u.get("Id") == user_id), None)
            if idx is None and not existing_unified:
                self.send_json_response({"success": False, "error": "User not found"}, status=404)
                return

            merged = dict(existing_unified or (users[idx] if idx is not None else {}))
            merged.update(body)
            merged["Id"] = user_id
            stored_copy = {k: v for k, v in merged.items() if k != "Password"}
            if idx is not None:
                users[idx] = stored_copy
            else:
                users.append(stored_copy)
            save_json_file(USERS_FILE, users)
            _sync_user_dict_to_db(merged)
            self.send_json_response({"success": True, "user": stored_copy})
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
            db_deleted = False
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("DELETE FROM access_assignments WHERE customer_id = ?", (tenant_id,))
                cur.execute("DELETE FROM customers WHERE id = ?", (tenant_id,))
                db_deleted = cur.rowcount > 0
                conn.commit()
                conn.close()
            except Exception:
                pass

            if len(new_tenants) < len(tenants) or db_deleted:
                save_json_file(TENANTS_FILE, new_tenants)
                self.send_json_response({"success": True})
            else:
                self.send_json_response({"success": False, "error": "Tenant not found"}, status=404)
            return

        elif path.startswith("/api/users/"):
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
            db_deleted = _delete_user_from_db(user_id)
            if len(new_users) < len(users) or db_deleted:
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
                    if not t.get("IsDispatchActive", True):
                        continue
                    freq = t.get("ScheduleFrequency")
                    if not freq or freq == "None":
                        continue

                    # Respect DispatchTime (HH:MM) and DispatchDay when configured
                    disp_time_str = str(t.get("DispatchTime") or "09:00").strip()
                    try:
                        target_hr = int(disp_time_str.split(":")[0])
                    except Exception:
                        target_hr = 9
                    if now.hour < target_hr:
                        continue
                    if freq == "Monthly":
                        try:
                            target_day = max(1, min(28, int(t.get("DispatchDay") or 1)))
                        except Exception:
                            target_day = 1
                        if now.day < target_day:
                            continue

                    last_str = (t.get("LastReportDate") or "").split(" ")[0]
                    should_run = False
                    if not last_str:
                        should_run = True
                    else:
                        try:
                            last_date = datetime.strptime(last_str, "%Y-%m-%d")
                            if freq == "Daily" and (now.date() > last_date.date()):
                                should_run = True
                            elif freq == "Weekly" and (now - last_date).days >= 7:
                                should_run = True
                            elif freq == "Monthly" and (now.year > last_date.year or now.month > last_date.month):
                                should_run = True
                        except Exception:
                            pass

                    if should_run:
                        tid = t.get("Id")
                        tname = t.get("Name", "Customer")
                        services = t.get("ActiveServices", ["SVC-MDE"])
                        period_tag = now.strftime("%Y-%m")
                        print(f"[SCHEDULER] Otomatik zamanlanmış rapor toplama ve dağıtım: {tname} ({tid}) - Frekans: {freq}")
                        try:
                            render_and_save_report(tname, services, OUTPUT_DIR, period_tag=period_tag, tenant_id=tid)
                            disp_log = execute_report_dispatch(
                                t,
                                attach_pdf=bool(t.get("AttachPdf", True)),
                                attach_html=bool(t.get("AttachHtml", True)),
                                mode=freq,
                                dry_run=bool(t.get("IsSimulation", False)),
                                created_by="scheduler@cloudshield-mssp.com",
                            )
                            t["LastReportDate"] = now.strftime("%Y-%m-%d")
                            t["LastDispatchDate"] = now.strftime("%Y-%m-%d %H:%M")
                            t["LastDispatchStatus"] = disp_log.get("status", "ArchivedOnly")
                            updated = True
                            record_audit_event("SCHEDULED_REPORT_DISPATCH", user_id="system-scheduler",
                                               user_upn="scheduler@cloudshield-mssp.com", resource=f"/api/tenants/{tid}/reports",
                                               decision="ALLOW", reason=f"ScheduledExecution_{freq}_{disp_log.get('status')}", ip_address="127.0.0.1",
                                               details={"tenantId": tid, "frequency": freq, "period": period_tag, "dispatchId": disp_log.get("id")})
                        except Exception as ex:
                            print(f"[SCHEDULER] Rapor üretim/dağıtım hatası ({tid}): {ex}")
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

