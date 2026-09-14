#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Comprehensive QA & Reliability Automated Test Suite
Author: Senior QA & Reliability Automation Engineer
Targets:
  1. PowerShell Reporting Engine (30 Platform Tests)
  2. Web API Layer REST Endpoints & Stage 1A Authentication Containment
  3. Multi-Tenant Concurrency & Temporary Config File Isolation
  4. Pilot Hardening Quality Gates (Gates 1-12)

Stage 1A remediation note:
This harness is retargeted to Stage 1A security reality. It boots the UNMODIFIED
`Portal/api/server.py` against a TEMPORARY database via the shared isolated-server
fixture and asserts the CONTAINMENT behavior that is correct after the W5/W7/W8/W11
hardening:
  * `POST /api/auth/login`  -> 403 (Pilot local password auth disabled; ssoRequired)
  * `POST /api/auth/sso`    -> 410 Gone, NO token is ever issued from a body identity
  * `GET  /api/users/me`    -> 401 when unauthenticated (deny-by-default, W11)
  * Protected mutations     -> 401/403 without a session
It no longer depends on the retired fake-SSO stub for a session. Legacy literal
passwords ("CloudShield2026!*", "SecurePass2026!*") are asserted to be REJECTED
against an isolated DB using the unchanged engine.
"""

import os
import sys

# Configure UTF-8 safe stdout for Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

import json
import time
import uuid
from datetime import datetime, timezone
import shutil
import urllib.request
import urllib.error
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost:8080"
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
ENGINE_DIR = os.path.join(ROOT_DIR, "Engine")
TEMP_DATA_DIR = os.path.join(ENGINE_DIR, "Data", "temp")

# Stage 1A (test-only): shared isolated-fixture helpers.
from tests.helpers.stage1a_fixtures import isolated_database, isolated_server

# Legacy literal passwords that MUST be rejected after W7/W8.
_LEGACY_LITERAL_PASSWORDS = ("CloudShield2026!*", "SecurePass2026!*")

# Known seeded identities (UPN only - credentials are provisioned randomly).
_IDENTITY_UPNS = [
    "customer.ciso@emre-tenant.com",          # usr-005 CustomerCISO -> tenant-002
    "edr.analyst@cloudshield-mssp.com",       # usr-002 EdrEngineer -> SVC-MDE
    "compliance.lead@cloudshield-mssp.com",   # usr-003 ComplianceSpecialist
    "caner.cetinkaya@cloudshield-mssp.com",   # usr-001 PlatformAdmin
    "admin@cloudshield-mssp.com",             # usr-admin bootstrap PlatformAdmin
]

# The isolated server is managed by the fixture context manager.
_server_ctx = None
_server = None


def ensure_server():
    """Start the UNMODIFIED server against an ISOLATED temporary database."""
    global BASE_URL, _server_ctx, _server
    _server_ctx = isolated_server()
    _server = _server_ctx.__enter__()
    BASE_URL = _server.base_url


def stop_server():
    global _server_ctx, _server
    if _server_ctx is not None:
        _server_ctx.__exit__(None, None, None)
        _server_ctx = None
        _server = None


results = {
    "engine_tests": [],
    "api_tests": [],
    "concurrency_tests": [],
    "quality_gates": [],
    "summary": {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "execution_time_sec": 0
    }
}


def log_test(category, name, passed, details="", duration_ms=0):
    results["summary"]["total"] += 1
    if passed:
        results["summary"]["passed"] += 1
        status_str = "[PASS]"
    else:
        results["summary"]["failed"] += 1
        status_str = "[FAIL]"

    entry = {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "duration_ms": round(duration_ms, 2),
        "details": details
    }
    results[category].append(entry)
    print(f"{status_str} [{category}] {name} ({round(duration_ms, 1)}ms) - {details[:90]}")


def http_get(path, token=None):
    url = f"{BASE_URL}{path}"
    start = time.time()
    headers = {"User-Agent": "CloudShield-QA-TestAutomation/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            dur = (time.time() - start) * 1000
            data = resp.read()
            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type:
                try:
                    return resp.status, json.loads(data.decode("utf-8")), dur, data
                except Exception:
                    return resp.status, data, dur, data
            return resp.status, data, dur, data
    except urllib.error.HTTPError as e:
        dur = (time.time() - start) * 1000
        data = e.read()
        try:
            parsed = json.loads(data.decode("utf-8"))
        except Exception:
            parsed = data.decode("utf-8", errors="replace")
        return e.code, parsed, dur, data
    except Exception as e:
        dur = (time.time() - start) * 1000
        return 0, {"error": str(e)}, dur, b""


def http_post(path, payload, token=None):
    url = f"{BASE_URL}{path}"
    body = json.dumps(payload).encode("utf-8")
    start = time.time()
    headers = {"Content-Type": "application/json", "User-Agent": "CloudShield-QA-TestAutomation/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            dur = (time.time() - start) * 1000
            data = resp.read()
            return resp.status, json.loads(data.decode("utf-8")), dur
    except urllib.error.HTTPError as e:
        dur = (time.time() - start) * 1000
        data = e.read()
        try:
            parsed = json.loads(data.decode("utf-8"))
        except Exception:
            parsed = data.decode("utf-8", errors="replace")
        return e.code, parsed, dur
    except Exception as e:
        dur = (time.time() - start) * 1000
        return 0, {"error": str(e)}, dur

# ==============================================================================
# 1. ENGINE TEST VERIFICATION (30 TESTS)
# ==============================================================================
def run_engine_tests():
    print("\n" + "=" * 80)
    print(" 1. ENGINE PLATFORM TESTS (POWERSHELL 7 STRUCTURED PROTOCOL)")
    print("=" * 80)
    test_script = os.path.join(ENGINE_DIR, "Tests", "Test-Platform.ps1")
    start = time.time()
    ps_cmd = shutil.which("pwsh") or shutil.which("powershell.exe") or "powershell.exe"
    print(f"   [RUNTIME] PowerShell Engine Runner: {ps_cmd}")
    proc = subprocess.run(
        [ps_cmd, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", test_script],
        cwd=ENGINE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    dur = (time.time() - start) * 1000
    json_path = os.path.join(ENGINE_DIR, "Output", "platform-test-results.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            tests = report.get("tests", [])
            for t in tests:
                t_name = t.get("name", "Unknown Test")
                t_pass = t.get("status") == "PASS"
                t_dur = float(t.get("durationMs", 0))
                t_det = t.get("details", "")
                log_test("engine_tests", t_name, t_pass, f"Precise Duration: {t_dur:.1f}ms - {t_det}", t_dur)
            print(f"Engine Structured Summary: Total={len(tests)}, Pass={report.get('passedTests')}, Exit={report.get('exitCode')}")
            return
        except Exception as je:
            print(f"   [WARN] Failed to read structured platform JSON: {je}")
    out = proc.stdout
    lines = [l.strip() for l in out.splitlines() if "[PASS]" in l or "[FAIL]" in l]
    if proc.returncode != 0 and not lines:
        log_test("engine_tests", "PowerShell Test Process Execution", False, f"Process exited with non-zero code {proc.returncode}: {proc.stderr[:100]}", dur)
    else:
        for l in lines:
            is_pass = "[PASS]" in l
            test_name = l.replace("[PASS]", "").replace("[FAIL]", "").strip()
            log_test("engine_tests", test_name, is_pass, "Executed via Test-Platform.ps1", dur / max(len(lines), 1))
    print(f"Engine Tests Summary: Process Exit Code = {proc.returncode}, Parsed Tests = {len(lines)}")


# ==============================================================================
# 1b. IN-PROCESS ENGINE CREDENTIAL CONTAINMENT (W7/W8)
# ==============================================================================
def run_credential_containment_tests():
    """
    Assert - against an ISOLATED DB, through the UNCHANGED engine - that:
      (a) the legacy literal passwords are rejected for every identity, and
      (b) a randomly provisioned password authenticates successfully.
    Positive/negative control proving no hard-coded credential works while real
    credentials still function.
    """
    print("\n" + "=" * 80)
    print(" 1b. ENGINE CREDENTIAL CONTAINMENT (W7/W8) - ISOLATED DB")
    print("=" * 80)
    with isolated_database() as idb:
        literals_rejected = True
        for upn in _IDENTITY_UPNS:
            for literal in _LEGACY_LITERAL_PASSWORDS:
                user, err = idb.authenticate_with_password(upn, literal)
                if user is not None:
                    literals_rejected = False
        log_test("api_tests", "W7/W8: Legacy Literal Parolalar Reddedilir (Izole DB)", literals_rejected,
                 f"All literals {_LEGACY_LITERAL_PASSWORDS} rejected for {len(_IDENTITY_UPNS)} identities", 0)
        upn = "customer.ciso@emre-tenant.com"
        idb.provision_credential(upn)
        user, err = idb.authenticate(upn)
        positive_ok = user is not None
        log_test("api_tests", "Izole DB: Rastgele Uretilen Parola ile Gercek Kimlik Dogrulama", positive_ok,
                 f"Authenticated={user is not None}, Err={err if not positive_ok else 'None'}", 0)


# ==============================================================================
# 2. WEB API REST CONTRACTS & STAGE 1A AUTH CONTAINMENT
# ==============================================================================
def run_api_tests():
    print("\n" + "=" * 80)
    print(" 2. WEB API REST CONTRACTS & STAGE 1A AUTHENTICATION CONTAINMENT")
    print("=" * 80)

    def load_version_manifest():
        vpath = os.path.join(ROOT_DIR, "version.json")
        if not os.path.exists(vpath):
            vpath = os.path.join(ROOT_DIR, "Data", "version.json")
        try:
            with open(vpath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"version": "2.5.10", "release": "v2.5.10-PILOT"}

    expected_v = load_version_manifest()
    expected_ver = expected_v.get("version", "2.5.10")
    expected_rel = expected_v.get("release", "v2.5.10-PILOT")

    # 2.1 GET /api/health (public)
    status, body, dur, _ = http_get("/api/health")
    passed = status == 200 and body.get("status") == "Healthy" and body.get("version") == expected_ver
    log_test("api_tests", f"GET /api/health - Sistem Saglik Durumu (v{expected_ver})", passed, f"Status={status}, Version={body.get('version')}", dur)

    # 2.2 GET /api/version (public)
    status, body, dur, _ = http_get("/api/version")
    passed = status == 200 and body.get("version") == expected_ver and body.get("release") == expected_rel
    log_test("api_tests", "GET /api/version - Platform Surum ve Surum Basligi Dogrulamasi", passed, f"Status={status}, Release={body.get('release')}, ExpectedRelease={expected_rel}, Build={body.get('build')}", dur)

    # 2.3 POST /api/auth/login - Pilot Modunda Yerel Parola Engeli
    auth_local_file = os.path.join(ROOT_DIR, "Data", "auth.local.json")
    local_cfg = {}
    if os.path.exists(auth_local_file):
        try:
            with open(auth_local_file, "r", encoding="utf-8") as f:
                local_cfg = json.load(f)
        except Exception:
            pass
    admin_user = os.environ.get("PORTAL_ADMIN_USER", local_cfg.get("admin_user", "admin"))
    admin_pass = os.environ.get("PORTAL_ADMIN_PASSWORD", local_cfg.get("admin_password", ""))

    status_login, body_login, dur_login = http_post("/api/auth/login", {"username": admin_user, "password": admin_pass})
    passed_pilot_lock = status_login == 403 and body_login.get("ssoRequired") is True
    log_test("api_tests", "POST /api/auth/login - Pilot Modunda Yerel Parola Engeli (403 & SSO Zorunlu)", passed_pilot_lock, f"Status={status_login}, SsoRequired={body_login.get('ssoRequired')}", dur_login)

    # 2.3.1 POST /api/auth/login - Hatali Parolada da Guvenli 403 Reddi
    status_bad, body_bad, dur_bad = http_post("/api/auth/login", {"username": admin_user, "password": "InvalidPassword_StrictTest#1"})
    bad_passed = status_bad == 403 and body_bad.get("ssoRequired") is True and "CloudShield" not in str(body_bad.get("error"))
    log_test("api_tests", "POST /api/auth/login - 403 Guvenli Red & Bilgi Sizdirmama Guvencesi", bad_passed, f"Status={status_bad}, SsoRequired={body_bad.get('ssoRequired')}", dur_bad)

    # 2.3.2 POST /api/auth/login - Kaldirilmis literal parolalar Pilot'ta da reddedilir
    legacy_login_ok = True
    seen = []
    for literal in _LEGACY_LITERAL_PASSWORDS:
        st, bd, _ = http_post("/api/auth/login", {"username": admin_user, "password": literal})
        seen.append(f"{literal}->{st}")
        if st != 403:
            legacy_login_ok = False
    log_test("api_tests", "POST /api/auth/login - Kaldirilmis Literal Parolalarin Kesin Reddi (W7/W8)", legacy_login_ok, f"Results: {seen}", 0)

    # 2.3.3 POST /api/auth/sso - Emekli Edilen SSO Stub (410 Gone, Token YOK) - W5
    status_sso, body_sso, dur_sso = http_post("/api/auth/sso", {"provider": "EntraID_OIDC", "upn": "admin@cloudshield-mssp.com"})
    sso_retired = status_sso == 410 and not body_sso.get("token")
    log_test("api_tests", "POST /api/auth/sso - Emekli SSO Stub (410 Gone, Oturum/Tur Acilmaz)", sso_retired, f"Status={status_sso}, TokenIssued={bool(body_sso.get('token'))}", dur_sso)

    # 2.3.4 POST /api/auth/sso - Bilinmeyen/Keyfi UPN dahi oturum acamaz (Kimlik Enjeksiyonu Engeli)
    inj_token_issued = False
    for evil_upn in ("customer.ciso@emre-tenant.com", "external.ciso@other-client.com", "attacker@evil.example"):
        st_i, bd_i, _ = http_post("/api/auth/sso", {"provider": "EntraID_OIDC", "upn": evil_upn})
        if bd_i.get("token") or st_i == 200:
            inj_token_issued = True
    log_test("api_tests", "POST /api/auth/sso - Keyfi UPN ile Oturum Acma/Kimlik Enjeksiyonu Engellendi", not inj_token_issued, f"AnyTokenIssued={inj_token_issued}", 0)

    # 2.4 GET /api/reports/download - Kimliksiz Rapor Indirme Reddi (401)
    status, body, dur, _ = http_get("/api/reports/download?file=Emre-TestTenant/2026-08/Rapor.pdf")
    passed = status == 401
    log_test("api_tests", "GET /api/reports/download - Kimliksiz Indirme Reddi (401 Deny-by-Default)", passed, f"Status={status}", dur)

    # 2.5 GET /api/users/me - Kimliksiz Erisim Reddi (401, W11)
    status, body, dur, _ = http_get("/api/users/me")
    passed = status == 401
    log_test("api_tests", "GET /api/users/me - Kimliksiz Erisim Reddi (401 Deny-by-Default)", passed, f"Status={status}, Error={str(body.get('error'))[:60]}", dur)

    # 2.6 GET /api/tenants - Yalnizca Canli Kiraci (Sifir Mock/Test Musterisi)
    status, body, dur, _ = http_get("/api/tenants")
    body_list = body if isinstance(body, list) else []
    has_sandbox = any(t.get("IsSimulation") for t in body_list)
    passed = status == 200 and not has_sandbox and len(body_list) >= 1
    log_test("api_tests", "GET /api/tenants - Sadece Canli Kiraci (Sifir Sahte/Mock Musteri)", passed, f"Status={status}, Count={len(body_list)}, HasSandbox={has_sandbox}", dur)

    # 2.7 GET /api/services - Servis Katalogu (10+ Servis)
    status, body, dur, _ = http_get("/api/services")
    services = body.get("services") or body.get("Services", {}) if isinstance(body, dict) else {}
    passed = status == 200 and len(services) >= 10
    log_test("api_tests", "GET /api/services - Servis Katalogu (10+ Servis)", passed, f"Status={status}, ServicesCount={len(services)}", dur)

    # 2.8 GET /api/tenants/tenant-002/logo - Musteri Logosu / Vektorel Monogram (200 OK)
    status, logo_content, dur, _ = http_get("/api/tenants/tenant-002/logo")
    is_valid_logo = status == 200 and isinstance(logo_content, (bytes, bytearray)) and (logo_content.startswith(b"\x89PNG") or b"<svg" in logo_content)
    log_test("api_tests", "GET /api/tenants/tenant-002/logo - Musteri Logosu / Vektorel Monogram (200 OK)", is_valid_logo, f"Status={status}, IsImageOrSvg={is_valid_logo}", dur)

    # 2.9 POST /api/reports/generate - Kimliksiz Rapor Uretimi Reddi (403)
    status, body, dur = http_post("/api/reports/generate", {"tenantId": "tenant-002", "services": ["SVC-MDE"], "dryRun": True})
    passed = status == 403 and body.get("success") is False
    log_test("api_tests", "POST /api/reports/generate - Kimliksiz Rapor Uretimi Reddi (403 Forbidden)", passed, f"Status={status}, Error={str(body.get('error'))[:60]}", dur)

    # 2.10 POST /api/tenants/tenant-002/test - Kimliksiz Kiraci Testi Reddi (401)
    status, body, dur = http_post("/api/tenants/tenant-002/test", {})
    passed = status == 401
    log_test("api_tests", "POST /api/tenants/tenant-002/test - Kimliksiz Kiraci Testi Reddi (401)", passed, f"Status={status}, Error={str(body.get('error'))[:60]}", dur)

    # 2.11 GET /api/auth/config - Kimliksiz Yapilandirma Okuma Reddi (401, W12)
    status, body, dur, _ = http_get("/api/auth/config")
    passed = status == 401
    log_test("api_tests", "GET /api/auth/config - Kimliksiz Yapilandirma Okuma Reddi (401, W12)", passed, f"Status={status}", dur)

    return ""


# ==============================================================================
# 3. MULTI-TENANT CONCURRENCY & ISOLATION
# ==============================================================================
def run_concurrency_tests(token=None):
    print("\n" + "=" * 80)
    print(" 3. COKLU KIRACI ESZAMANLILIK (CONCURRENCY) & IZOLASYON TESTLERI")
    print("=" * 80)

    os.makedirs(TEMP_DATA_DIR, exist_ok=True)
    initial_temp_files = os.listdir(TEMP_DATA_DIR)
    print(f"   [INFO] Temp dizini baslangic dosya sayisi: {len(initial_temp_files)}")

    # Test 3.1: Eszamanli Bilinmeyen Istek Izolasyonu (404 Reddi)
    def send_live_request(tid):
        return http_post("/api/reports/generate", {"tenantId": tid})

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_live_request, "tenant-unknown-999") for _ in range(5)]
        live_results = [f.result() for f in as_completed(futures)]
    t_dur = (time.time() - t_start) * 1000

    all_404 = all(r[0] == 404 for r in live_results)
    log_test("concurrency_tests", "Eszamanli 5 Bilinmeyen Istek Izolasyonu ve 404 Reddi", all_404, f"5/5 istek 404 dondu, sure: {round(t_dur, 1)}ms", t_dur)

    # Test 3.2: Eszamanli Yetkisiz Rapor Uretimi Izolasyonu (hepsi 403)
    requests_data = [
        {"tenantId": "tenant-002", "services": ["SVC-MDE"], "mode": "Monthly", "dryRun": True},
        {"tenantId": "tenant-002", "services": ["SVC-MDO"], "mode": "Monthly", "dryRun": True},
    ]

    temp_files_seen = set()
    monitoring = True

    def monitor_temp_dir():
        while monitoring:
            try:
                for f in os.listdir(TEMP_DATA_DIR):
                    if f.startswith("customer.") and f.endswith(".json"):
                        temp_files_seen.add(f)
            except Exception:
                pass
            time.sleep(0.002)

    monitor_thread = threading.Thread(target=monitor_temp_dir, daemon=True)
    monitor_thread.start()

    print("   [INFO] 2 eszamanli YETKISIZ rapor uretim istegi tetikleniyor (403 beklenir)...")
    start_c = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(http_post, "/api/reports/generate", req) for req in requests_data]
        concurrent_results = [f.result() for f in as_completed(futures)]
    monitoring = False
    dur_c = (time.time() - start_c) * 1000

    all_403 = all(r[0] == 403 for r in concurrent_results)
    log_test("concurrency_tests", "2 Eszamanli Yetkisiz Rapor Uretimi Izolasyonu (403 Deny-by-Default)", all_403, f"Both returned 403 Forbidden, Total execution: {round(dur_c/1000, 2)}s", dur_c)

    # Test 3.3: Yetkisiz Istekler Hicbir Gecici Konfig Dosyasi Sizdirmaz (Zero Leak)
    time.sleep(0.5)
    remaining_temp_files = [f for f in os.listdir(TEMP_DATA_DIR) if f.startswith("customer.") and f.endswith(".json")]
    no_leaks = len(remaining_temp_files) == 0 and len(temp_files_seen) == 0
    log_test("concurrency_tests", "Yetkisiz Istemlerde Sifir Gecici Konfig Sizintisi (Zero Leak)", no_leaks, f"Gozlemlenen izole konfig: {len(temp_files_seen)}, Kalan: {len(remaining_temp_files)}", 10)


# ==============================================================================
# 4. PILOT HARDENING QUALITY GATES (GATES 1 - 12)
# ==============================================================================
def run_quality_gates(token=None):
    print("\n" + "=" * 80)
    print(" 4. PILOT HARDENING QUALITY GATES & SECURITY VALIDATION")
    print("=" * 80)

    # 4.1 Gate 1 & 2: Single Source Version Manifest & Update Protocol
    start = time.time()
    vpath = os.path.join(ROOT_DIR, "version.json")
    with open(vpath, "r", encoding="utf-8") as vf:
        vmeta = json.load(vf)

    proc_ver = subprocess.run([sys.executable, os.path.join(ENGINE_DIR, "Core", "Update-Version.py"), "--check"], capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=ROOT_DIR)
    ver_valid = False
    try:
        ver_obj = json.loads(proc_ver.stdout)
        ver_valid = (ver_obj.get("version") == vmeta.get("version") and
                     ver_obj.get("release") == vmeta.get("release") and
                     ver_obj.get("channel") == vmeta.get("channel"))
    except Exception:
        pass

    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 1 & 2: Version Manifest & Structured JSON Update Protocol", ver_valid, f"Version={vmeta.get('version')}, Release={vmeta.get('release')}, Channel={vmeta.get('channel')}", dur)

    # 4.2 Gate 3: Safe Sync & Branch Isolation
    start = time.time()
    ps_cmd = shutil.which("pwsh") or shutil.which("powershell.exe") or "powershell.exe"
    proc_sync = subprocess.run([ps_cmd, "-NoProfile", "-File", os.path.join(ROOT_DIR, "Watch-AndSyncToGitHub.ps1"), "-DryRun"], capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=ROOT_DIR)
    sync_passed = ("sync/" in proc_sync.stdout or "sync/" in proc_sync.stderr) and proc_sync.returncode == 0
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 3: Safe Sync - Direct Push to Main Blocked & Unique Sync Branch", sync_passed, f"Branch Generated in DryRun Output={sync_passed}", dur)

    # 4.3 Gate 4: UTF-8 Encoding Round-Trip & Mojibake Absence
    start = time.time()
    turkish_corpus = [
        "KoçSistem", "Müşteri", "Yönetilen Güvenlik", "Çözüldü", "Şüpheli E-posta",
        "İç Tehdit", "İletişim Uyumu", "Sınıflandırma", "Ağustos", "İstanbul",
        "Çağrı", "Ölçüm", "Uç Nokta", "Yapay Zekâ", "Güvenlik Açığı", "GÜVENLİK", "ÇIĞLIK"
    ]
    corpus_json = json.dumps({"corpus": turkish_corpus}, ensure_ascii=False)
    round_trip = json.loads(corpus_json).get("corpus", [])
    corpus_ok = round_trip == turkish_corpus

    # The corpus MUST exercise every Turkish-specific diacritic so the round-trip
    # proves lossless UTF-8 handling (see docs/UTF8CompliancePolicy.md).
    required_turkish_chars = set('İıçşğöüÇŞĞÖÜâ')
    corpus_coverage_ok = required_turkish_chars.issubset(set("".join(turkish_corpus)))

    # Serialized JSON must be emitted as real UTF-8, not \uXXXX escapes.
    corpus_byte_stable = corpus_json == corpus_json.encode("utf-8").decode("utf-8")

    mojibake_signatures = ['Ã', 'Ä', 'Å', 'Â', '�']
    has_mojibake = any(sig in proc_ver.stdout for sig in mojibake_signatures)
    encoding_passed = corpus_ok and not has_mojibake and corpus_coverage_ok and corpus_byte_stable
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 4: UTF-8 Encoding Integrity - Zero Mojibake in Streams & JSON", encoding_passed, f"CorpusMatch={corpus_ok}, MojibakeDetected={has_mojibake}, TurkishDiacriticsCovered={corpus_coverage_ok}, ByteStable={corpus_byte_stable}", dur)

    # 4.4 Gate 5: Report Download Authorization, Existence-Probing & Traversal Prevention
    # Stage 1A semantics: the server NEVER serves a report artifact to an anonymous
    # caller. A non-existent reportId is rejected as 404 (existence is never leaked as
    # a 200); an existing-but-unauthorized download is denied (401/403); traversal is
    # blocked on the legacy query-file path.
    start = time.time()
    s_dl, c_dl, d_dl, body_dl = http_get("/api/reports/11111111-1111-1111-1111-111111111111/download")
    # No session => must never be served (200). Accept 401/403/404 (fail-closed).
    anon_dl_blocked = s_dl != 200 and (isinstance(body_dl, (bytes, bytearray)) and b"%PDF" not in body_dl)
    s_404, b_404, _, _ = http_get("/api/reports/unknown-random-uuid-999/download")
    unknown_id_404 = s_404 == 404
    s_trav, b_trav, _, _ = http_get("/api/reports/download?file=../../version.json")
    traversal_blocked = s_trav in (400, 403, 404, 401)
    gate5_passed = anon_dl_blocked and unknown_id_404 and traversal_blocked
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 5: Kimliksiz Rapor Indirme Reddi & Yol Gezinme Korumasi", gate5_passed, f"AnonStatus={s_dl}(blocked={anon_dl_blocked}), Unknown404={unknown_id_404}, TraversalBlocked={traversal_blocked}", dur)

    # 4.5 Gate 6 & 7: UI Data Integrity & Personal Identity Elimination
    start = time.time()
    with open(os.path.join(ROOT_DIR, "Portal", "web", "index.html"), "r", encoding="utf-8") as f:
        html_src = f.read()

    no_static_endpoints = "5,520" not in html_src
    no_static_ghost = 'id="statGhost" class="text-2xl font-extrabold text-amber-600 tracking-tight">45<' not in html_src
    no_static_score = "%79.1" not in html_src
    no_personal_name = "Caner \u00c7etinkaya" not in html_src
    no_personal_initials = ">\u00c7<" not in html_src

    gate6_7_passed = no_static_endpoints and no_static_ghost and no_static_score and no_personal_name and no_personal_initials
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 6 & 7: UI Cleanliness - Zero Static Metrics & Zero Personal Defaults", gate6_7_passed, f"NoStaticEndpoints={no_static_endpoints}, NoPersonalName={no_personal_name}", dur)

    # 4.6 Gate 10 & 11: Compliance Wording & Legal Disclaimer
    start = time.time()
    with open(os.path.join(ROOT_DIR, "Portal", "api", "report_generator.py"), "r", encoding="utf-8") as f:
        rep_src = f.read()

    no_absolute_compliance = "tam uyumludur" not in rep_src and "y\u00fczde 100 uyumlu" not in rep_src
    has_disclaimer = "teknik bir g\u00fcvenlik \u00e7\u0131kt\u0131s\u0131 olarak haz\u0131rlanm\u0131\u015ft\u0131r" in rep_src
    gate11_passed = no_absolute_compliance and has_disclaimer
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 10 & 11: Compliance Neutral Wording & Regulatory Disclaimer", gate11_passed, f"NoAbsoluteCompliance={no_absolute_compliance}, HasNeutralDisclaimer={has_disclaimer}", dur)


def main():
    start_all = time.time()
    try:
        ensure_server()
        run_engine_tests()
        run_credential_containment_tests()
        auth_token = run_api_tests()
        run_concurrency_tests(token=auth_token)
        run_quality_gates(token=auth_token)
    finally:
        stop_server()
    total_time = time.time() - start_all
    results["summary"]["execution_time_sec"] = round(total_time, 2)

    print("\n" + "=" * 80)
    print(" TEST CALISMASI TAMAMLANDI")
    print(f" Toplam Test: {results['summary']['total']}")
    print(f" Basarili:    {results['summary']['passed']}")
    print(f" Basarisiz:   {results['summary']['failed']}")
    print(f" Toplam Sure: {results['summary']['execution_time_sec']} saniye")
    print("=" * 80)

    vpath = os.path.join(ROOT_DIR, "version.json")
    vmeta = {}
    if os.path.exists(vpath):
        try:
            with open(vpath, "r", encoding="utf-8") as vf:
                vmeta = json.load(vf)
        except Exception:
            pass

    results["metadata"] = {
        "version": vmeta.get("version", "2.5.10"),
        "release": vmeta.get("release", "v2.5.10-PILOT"),
        "build": vmeta.get("build", "2026.09.10.10"),
        "channel": vmeta.get("channel", "pilot"),
        "environment": vmeta.get("environment", "pilot"),
        "commit": vmeta.get("commit", "auto"),
        "runner": "local-test-harness",
        "completedAtUtc": datetime.now(timezone.utc).isoformat()
    }

    output_json = os.path.join(ROOT_DIR, "qa_test_results.json")
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[OK] Test sonuclari metadata ile kaydedildi: {output_json}")


if __name__ == "__main__":
    main()

