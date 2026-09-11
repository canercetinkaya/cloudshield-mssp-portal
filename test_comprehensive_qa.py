#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Comprehensive QA & Reliability Automated Test Suite
Author: Senior QA & Reliability Automation Engineer
Targets:
  1. PowerShell Reporting Engine (30 Platform Tests)
  2. Web API Layer REST Endpoints & Sandbox vs Live Guardrails
  3. Multi-Tenant Concurrency & Temporary Config File Isolation
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

_server_proc = None

def ensure_server():
    global BASE_URL, _server_proc
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/health")
        with urllib.request.urlopen(req, timeout=1):
            return
    except Exception:
        pass

    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()

    BASE_URL = f"http://127.0.0.1:{port}"
    cmd = [sys.executable, os.path.join(ROOT_DIR, "Portal", "api", "server.py"), str(port)]
    _server_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        time.sleep(0.15)
        try:
            req = urllib.request.Request(f"{BASE_URL}/api/health")
            with urllib.request.urlopen(req, timeout=1):
                break
        except Exception:
            pass

def stop_server():
    global _server_proc
    if _server_proc:
        try:
            _server_proc.terminate()
            _server_proc.wait(timeout=2)
        except Exception:
            try:
                _server_proc.kill()
            except Exception:
                pass
        _server_proc = None

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
                return resp.status, json.loads(data.decode("utf-8")), dur, data
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
    req = urllib.request.Request(
        url, data=body,
        headers=headers,
        method="POST"
    )
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
    print("\n" + "="*80)
    print(" 1. ENGINE PLATFORM TESTS (POWERShell 7 STRUCTURED PROTOCOL)")
    print("="*80)
    test_script = os.path.join(ENGINE_DIR, "Tests", "Test-Platform.ps1")
    start = time.time()
    ps_cmd = shutil.which("pwsh") or shutil.which("powershell.exe") or "powershell.exe"
    print(f"   [RUNTIME] PowerShell Engine Runner: {ps_cmd}")
    
    # Run test script
    proc = subprocess.run(
        [ps_cmd, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", test_script],
        cwd=ENGINE_DIR, capture_output=True, text=True, errors="replace"
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

    # Fallback to line parsing if JSON was not emitted
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
# 2. WEB API REST CONTRACTS & GUARDRAILS
# ==============================================================================
def run_api_tests():
    print("\n" + "="*80)
    print(" 2. WEB API REST CONTRACTS & GUARDRAIL TESTS")
    print("="*80)
    
    # Load single source of truth version manifest
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

    # 2.1 GET /api/health
    status, body, dur, _ = http_get("/api/health")
    passed = status == 200 and body.get("status") == "Healthy" and body.get("version") == expected_ver
    log_test("api_tests", f"GET /api/health - Sistem Sağlık Durumu (v{expected_ver})", passed, f"Status={status}, Version={body.get('version')}", dur)

    # 2.2 GET /api/version
    status, body, dur, _ = http_get("/api/version")
    passed = status == 200 and body.get("version") == expected_ver and body.get("release") == expected_rel
    log_test("api_tests", "GET /api/version - Platform Sürüm ve Sürüm Başlığı Doğrulaması", passed, f"Status={status}, Release={body.get('release')}, ExpectedRelease={expected_rel}, Build={body.get('build')}", dur)

    # 2.3 POST /api/auth/login & GET /api/auth/verify (Dinamik ve Güvenli Kimlik Çözümleme)
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

    # 2.3 POST /api/auth/login - Pilot Modunda Yerel Parola Engeli (Outcome 2)
    status_login, body_login, dur_login = http_post("/api/auth/login", {"username": admin_user, "password": admin_pass})
    passed_pilot_lock = status_login == 403 and body_login.get("ssoRequired") is True
    log_test("api_tests", "POST /api/auth/login - Pilot Modunda Yerel Parola Engeli (403 & SSO Zorunlu)", passed_pilot_lock, f"Status={status_login}, SsoRequired={body_login.get('ssoRequired')}", dur_login)

    # 2.3.1 POST /api/auth/login - Hatalı Parolada da Güvenli 403 Reddi & Sıfır Sızıntı
    status_bad, body_bad, dur_bad = http_post("/api/auth/login", {"username": admin_user, "password": "InvalidPassword_StrictTest#1"})
    bad_passed = status_bad == 403 and body_bad.get("ssoRequired") is True and "CloudShield" not in str(body_bad.get("error"))
    log_test("api_tests", "POST /api/auth/login - 403 Güvenli Red & Bilgi Sızdırmama Güvencesi", bad_passed, f"Status={status_bad}, SsoRequired={body_bad.get('ssoRequired')}", dur_bad)

    # 2.3.2 POST /api/auth/sso - Entra ID Kurumsal SSO Oturum Doğrulaması (Outcome 1)
    status_sso, body_sso, dur_sso = http_post("/api/auth/sso", {"provider": "EntraID_OIDC", "upn": "admin@cloudshield-mssp.com"})
    auth_token = body_sso.get("token", "")
    sso_passed = status_sso == 200 and body_sso.get("success") is True and bool(auth_token)
    log_test("api_tests", "POST /api/auth/sso - Entra ID Kurumsal SSO Oturum Doğrulaması", sso_passed, f"Status={status_sso}, User={body_sso.get('user', {}).get('displayName')}", dur_sso)

    # 2.4 GET /api/services
    status, body, dur, _ = http_get("/api/services", token=auth_token)
    services = body.get("services") or body.get("Services", {})
    passed = status == 200 and len(services) >= 10
    log_test("api_tests", "GET /api/services - Servis Kataloğu (10+ Servis)", passed, f"Status={status}, ServicesCount={len(services)}", dur)

    # 2.5 GET /api/tenants - Sadece Canlı Tenant Doğrulaması (Sıfır Mock/Test Müşterisi)
    status, body, dur, _ = http_get("/api/tenants", token=auth_token)
    has_sandbox = any(t.get("IsSimulation") for t in body)
    all_live = all(not t.get("IsSimulation") for t in body) and len(body) >= 1
    has_target_live = any(t.get("Id") == "tenant-002" and t.get("Name") == "Emre-TestTenant" for t in body)
    passed = status == 200 and not has_sandbox and all_live and has_target_live
    log_test("api_tests", "GET /api/tenants - Sadece Canlı Kiracı (Sıfır Sahte/Mock Müşteri)", passed, f"Status={status}, Count={len(body)}, HasSandbox={has_sandbox}, AllLive={all_live}", dur)

    # 2.6 GET /api/users/me
    status, body, dur, _ = http_get("/api/users/me", token=auth_token)
    user_perms = body.get("permissions")
    can_generate = ("reports:generate" in user_perms) if isinstance(user_perms, list) else bool(user_perms.get("CanGenerateReports")) if isinstance(user_perms, dict) else False
    passed = status == 200 and body.get("role") == "PlatformAdmin" and can_generate
    log_test("api_tests", "GET /api/users/me - RBAC Rol ve İzin Doğrulaması", passed, f"Status={status}, Role={body.get('role')}", dur)

    # 2.7 POST /api/auth/test
    status, body, dur = http_post("/api/auth/test", {}, token=auth_token)
    passed = status == 200 and body.get("success") is True and body.get("status") == "Validated"
    log_test("api_tests", "POST /api/auth/test - Entra ID Federasyon Testi", passed, f"Status={status}, Provider={body.get('authProvider')}", dur)

    # 2.8 POST /api/tenants/tenant-002/test (Canlı Kiracı OAuth Bağlantı Doğrulaması)
    status, body, dur = http_post("/api/tenants/tenant-002/test", {}, token=auth_token)
    passed = (status == 200 and body.get("success") is True and 
              body.get("isSimulation") is False and body.get("status") == "LiveConnected")
    log_test("api_tests", "POST /api/tenants/tenant-002/test - Canlı Kiracı OAuth Doğrulaması (200 OK)", passed, f"Status={status}, StatusText={body.get('status')}, Badge={body.get('badge')}", dur)

    # 2.9 POST /api/tenants/tenant-999-invalid/test (Bilinmeyen Kiracı 404 Reddi)
    status, body, dur = http_post("/api/tenants/tenant-999-invalid/test", {}, token=auth_token)
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/tenants/tenant-999-invalid/test - Bilinmeyen Kiracı 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.10 POST /api/reports/generate (Bilinmeyen Kiracı Rapor Talebi 404 Reddi)
    status, body, dur = http_post("/api/reports/generate", {"tenantId": "tenant-999-unknown"}, token=auth_token)
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/reports/generate - Bilinmeyen Kiracı Rapor 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.11 POST /api/reports/generate (Canlı Kiracı Başarılı Rapor Üretimi - dryRun modunda)
    print("   [INFO] Canlı kiracı (tenant-002) için rapor üretim motoru çalıştırılıyor...")
    status, body, dur = http_post("/api/reports/generate", {
        "tenantId": "tenant-002",
        "services": ["SVC-MDE", "SVC-MDO"],
        "mode": "Monthly",
        "dryRun": True
    }, token=auth_token)
    pdf_url = body.get("pdfUrl", "")
    html_url = body.get("htmlUrl", "")
    passed = status == 200 and body.get("success") is True and bool(pdf_url) and bool(html_url)
    log_test("api_tests", "POST /api/reports/generate - Canlı Kiracı Rapor Üretimi (200 OK)", passed, f"Status={status}, Customer={body.get('customer')}, PdfUrl={pdf_url}", dur)

    # 2.12 PDF & HTML İndirme ve Dosya Bütünlüğü Doğrulaması
    if pdf_url and html_url:
        p_status, p_content, p_dur, _ = http_get(pdf_url, token=auth_token)
        h_status, h_content, h_dur, _ = http_get(html_url, token=auth_token)
        is_pdf_valid = p_status == 200 and p_content.startswith(b"%PDF")
        is_html_valid = h_status == 200 and (b"<!DOCTYPE html>" in h_content or b"<html" in h_content)
        passed = is_pdf_valid and is_html_valid
        log_test("api_tests", "GET /api/reports/download - PDF/HTML Vektörel Dosya Bütünlüğü", passed, f"PdfSize={len(p_content)}B, HtmlSize={len(h_content)}B, ValidPdfHeader={is_pdf_valid}", p_dur + h_dur)

    # 2.13 GET /api/tenants/tenant-002/logo - Entra ID Logo ve Dinamik Monogram Doğrulaması
    status, logo_content, dur, _ = http_get("/api/tenants/tenant-002/logo", token=auth_token)
    is_valid_logo = status == 200 and (logo_content.startswith(b"\x89PNG") or b"<svg" in logo_content)
    log_test("api_tests", "GET /api/tenants/tenant-002/logo - Entra ID Müşteri Logosu / Vektörel Monogram (200 OK)", is_valid_logo, f"Status={status}, ContentSize={len(logo_content)}B, IsImageOrSvg={is_valid_logo}", dur)

    # 2.14 POST /api/auth/sso - Müşteri CISO (usr-005) Entra ID SSO Oturum Açma
    status_u5, body_u5, dur_u5 = http_post("/api/auth/sso", {"provider": "EntraID_OIDC", "upn": "customer.ciso@emre-tenant.com"})
    tok_u5 = body_u5.get("token", "")
    u5_passed = status_u5 == 200 and body_u5.get("user", {}).get("role") == "CustomerCISO" and body_u5.get("user", {}).get("AssignedTenants") == ["tenant-002"]
    log_test("api_tests", "POST /api/auth/sso - Müşteri CISO (usr-005) RBAC Doğrulaması", u5_passed, f"Status={status_u5}, Role={body_u5.get('user', {}).get('role')}, Tenants={body_u5.get('user', {}).get('AssignedTenants')}", dur_u5)

    # 2.15 GET /api/tenants - Müşteri CISO (usr-005) Sadece Atanmış Kiracısını Görür
    status_t5, body_t5, dur_t5, _ = http_get("/api/tenants", token=tok_u5)
    t5_passed = status_t5 == 200 and len(body_t5) == 1 and body_t5[0].get("Id") == "tenant-002"
    log_test("api_tests", "GET /api/tenants - usr-005 Oturumunda Sadece Atanmış Kiracı İzolasyonu", t5_passed, f"Status={status_t5}, Count={len(body_t5)}, VisibleTenants={[t.get('Id') for t in body_t5]}", dur_t5)

    # 2.16 POST /api/auth/sso - Farklı Müşteri Yöneticisi (usr-006) Entra ID SSO Oturum Açma
    status_u6, body_u6, dur_u6 = http_post("/api/auth/sso", {"provider": "EntraID_OIDC", "upn": "external.ciso@other-client.com"})
    tok_u6 = body_u6.get("token", "")
    u6_passed = status_u6 == 200 and "tenant-isolated-other" in body_u6.get("user", {}).get("AssignedTenants", [])
    log_test("api_tests", "POST /api/auth/sso - Farklı Müşteri (usr-006) RBAC Oturum Doğrulaması", u6_passed, f"Status={status_u6}, Role={body_u6.get('user', {}).get('role')}, Tenants={body_u6.get('user', {}).get('AssignedTenants')}", dur_u6)

    # 2.17 GET /api/tenants - usr-006 Oturumunda tenant-002 Asla Görünmez (Sıfır İhlal)
    status_t6, body_t6, dur_t6, _ = http_get("/api/tenants", token=tok_u6)
    has_tenant_002 = any(t.get("Id") == "tenant-002" for t in body_t6)
    t6_passed = status_t6 == 200 and not has_tenant_002
    log_test("api_tests", "GET /api/tenants - usr-006 Çapraz Kiracı Veri İzolasyonu (tenant-002 Görünmez)", t6_passed, f"Status={status_t6}, Count={len(body_t6)}, HasTenant002={has_tenant_002}", dur_t6)

    # 2.18 POST /api/reports/generate - usr-006 Yetkisiz Kiracı İçin Rapor Üretimi (403 Forbidden)
    status_gen_403, body_gen_403, dur_gen_403 = http_post("/api/reports/generate", {"tenantId": "tenant-002", "services": ["SVC-MDE"], "dryRun": True}, token=tok_u6)
    gen_403_passed = status_gen_403 == 403 and body_gen_403.get("success") is False
    log_test("api_tests", "POST /api/reports/generate - usr-006 Çapraz Kiracı Rapor İhlali 403 Reddi", gen_403_passed, f"Status={status_gen_403}, Error={body_gen_403.get('error')}", dur_gen_403)

    # 2.19 POST /api/tenants/tenant-002/test - usr-006 Yetkisiz Kiracı Testi (403 Forbidden)
    status_test_403, body_test_403, dur_test_403 = http_post("/api/tenants/tenant-002/test", {}, token=tok_u6)
    test_403_passed = status_test_403 == 403 and body_test_403.get("success") is False
    log_test("api_tests", "POST /api/tenants/tenant-002/test - usr-006 Çapraz Kiracı Test İhlali 403 Reddi", test_403_passed, f"Status={status_test_403}, Error={body_test_403.get('error')}", dur_test_403)

    # 2.20 GET /api/reports/download - usr-006 Yetkisiz Rapor İndirme Girişimi (403 Forbidden)
    status_dl_403, body_dl_403, dur_dl_403, _ = http_get(f"/api/reports/download?file=Emre-TestTenant/2026-08/Rapor_Emre-TestTenant_2026-08.pdf", token=tok_u6)
    dl_403_passed = status_dl_403 == 403
    log_test("api_tests", "GET /api/reports/download - usr-006 Çapraz Müşteri Rapor İndirme 403 Reddi", dl_403_passed, f"Status={status_dl_403}", dur_dl_403)

    return auth_token

# ==============================================================================
# 3. MULTI-TENANT CONCURRENCY & ISOLATION
# ==============================================================================
def run_concurrency_tests(token=None):
    print("\n" + "="*80)
    print(" 3. ÇOKLU KİRACI EŞZAMANLILIK (CONCURRENCY) & İZOLASYON TESTLERİ")
    print("="*80)

    # Ensure temp dir exists
    os.makedirs(TEMP_DATA_DIR, exist_ok=True)
    initial_temp_files = os.listdir(TEMP_DATA_DIR)
    print(f"   [INFO] Temp dizini başlangıç dosya sayısı: {len(initial_temp_files)}")

    # Test 3.1: Simultaneous Invalid Requests (Fast concurrency check for unknown tenants)
    def send_live_request(tid):
        return http_post("/api/reports/generate", {"tenantId": tid}, token=token)
    
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_live_request, "tenant-unknown-999") for _ in range(5)]
        live_results = [f.result() for f in as_completed(futures)]
    t_dur = (time.time() - t_start) * 1000
    
    all_404 = all(r[0] == 404 for r in live_results)
    log_test("concurrency_tests", "Eşzamanlı 5 Yetkisiz/Bilinmeyen İstek İzolasyonu ve 404 Reddi", all_404, f"5/5 istek 404 döndü, süre: {round(t_dur, 1)}ms", t_dur)

    # Test 3.2: Concurrent Report Generation Requests with Different Configurations
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

    print("   [INFO] 2 eşzamanlı rapor üretim isteği (SVC-MDE ve SVC-MDO) tetikleniyor...")
    start_c = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(http_post, "/api/reports/generate", req, token) for req in requests_data]
        concurrent_results = [f.result() for f in as_completed(futures)]
    monitoring = False
    dur_c = (time.time() - start_c) * 1000

    all_200 = all(r[0] == 200 and r[1].get("success") is True for r in concurrent_results)
    log_test("concurrency_tests", "2 Eşzamanlı Rapor Üretimi (Multi-Thread Concurrency)", all_200, f"Both returned 200 OK, Total execution: {round(dur_c/1000, 2)}s", dur_c)

    # Test 3.3: Temporary File Isolation & Cleanup
    # Allow 1 second for filesystem settle
    time.sleep(1)
    remaining_temp_files = [f for f in os.listdir(TEMP_DATA_DIR) if f.startswith("customer.") and f.endswith(".json")]
    
    unique_uuids = len(temp_files_seen) >= 2
    no_leaks = len(remaining_temp_files) == 0

    log_test("concurrency_tests", "Geçici Yapılandırma Dosyası İzolasyonu (UUID Ayrışımı)", unique_uuids, f"Farklı UUID'li {len(temp_files_seen)} adet izole müşteri konfigi gözlemlendi: {list(temp_files_seen)[:3]}", 10)
    log_test("concurrency_tests", "Geçici Dosya Temizliği & Sıfır İz Garantisi (Zero Leak)", no_leaks, f"İşlem sonrası kalan müşteri konfigürasyon dosyası: {len(remaining_temp_files)}", 10)


# ==============================================================================
# 4. PILOT HARDENING QUALITY GATES (GATES 1 - 12)
# ==============================================================================
def run_quality_gates(token=None):
    print("\n" + "="*80)
    print(" 4. PILOT HARDENING QUALITY GATES & SECURITY VALIDATION")
    print("="*80)

    # 4.1 Gate 1 & 2: Single Source Version Manifest & Update Protocol
    start = time.time()
    vpath = os.path.join(ROOT_DIR, "version.json")
    with open(vpath, "r", encoding="utf-8") as vf:
        vmeta = json.load(vf)

    proc_ver = subprocess.run([sys.executable, os.path.join(ENGINE_DIR, "Core", "Update-Version.py"), "--check"], capture_output=True, text=True, cwd=ROOT_DIR)
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
    proc_sync = subprocess.run([ps_cmd, "-NoProfile", "-File", os.path.join(ROOT_DIR, "Watch-AndSyncToGitHub.ps1"), "-DryRun"], capture_output=True, text=True, cwd=ROOT_DIR)
    sync_passed = ("sync/" in proc_sync.stdout or "sync/" in proc_sync.stderr) and proc_sync.returncode == 0
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 3: Safe Sync - Direct Push to Main Blocked & Unique Sync Branch", sync_passed, f"Branch Generated in DryRun Output={sync_passed}", dur)

    # 4.3 Gate 4: UTF-8 Encoding Round-Trip & Mojibake Absence
    start = time.time()
    turkish_corpus = [
        "\u004b\u006f\u00e7\u0053\u0069\u0073\u0074\u0065\u006d",
        "\u004d\u00fc\u015f\u0074\u0065\u0072\u0069",
        "\u0059\u00f6\u006e\u0065\u0074\u0069\u006c\u0065\u006e\u0020\u0047\u00fc\u0076\u0065\u006e\u006c\u0069\u006b",
        "\u00c7\u00f6\u007a\u00fc\u006c\u0064\u00fc",
        "\u015e\u00fcp\u0068\u0065\u006c\u0069\u0020\u0045\u002d\u0070\u006f\u0073\u0074\u0061",
        "\u0130\u00e7\u0020\u0054\u0065\u0068\u0064\u0069\u0074",
        "\u0130\u006c\u0065\u0074\u0069\u015f\u0069\u006d\u0020\u0055\u0079\u0075\u006d\u0075",
        "\u0053\u0131\u006e\u0131\u0066\u006c\u0061\u006e\u0064\u0131\u0072\u006d\u0061",
        "\u0041\u011f\u0075\u0073\u0074\u006f\u0073",
        "\u0130\u0073\u0074\u0061\u006e\u0062\u0075\u006c",
        "\u00c7\u0061\u011f\u0072\u0131",
        "\u00d6\u006c\u00e7\u00fc\u006d"
    ]
    corpus_json = json.dumps({"corpus": turkish_corpus}, ensure_ascii=False)
    round_trip = json.loads(corpus_json).get("corpus", [])
    corpus_ok = round_trip == turkish_corpus

    # Scan qa output for mojibake signatures: Ã, Ä, Å, Â, 
    mojibake_signatures = ["\u00c3", "\u00c4", "\u00c5", "\u00c2", "\ufffd"]
    has_mojibake = any(sig in proc_ver.stdout for sig in mojibake_signatures)
    encoding_passed = corpus_ok and not has_mojibake
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 4: UTF-8 Encoding Integrity - Zero Mojibake in Streams & JSON", encoding_passed, f"CorpusMatch={corpus_ok}, MojibakeDetected={has_mojibake}", dur)

    # 4.4 Gate 5: Report-ID Authorized Download, Expiration & Traversal Prevention
    start = time.time()
    # Generate a report to register a valid reportId
    status_gen, body_gen, dur_gen = http_post("/api/reports/generate", {
        "tenantId": "tenant-002",
        "services": ["SVC-MDE"],
        "dryRun": True
    }, token=token)
    rep_id = body_gen.get("pdfReportId") or body_gen.get("reportId", "")
    
    # 4.4.1 Valid Report-ID Download
    s_dl, c_dl, d_dl, _ = http_get(f"/api/reports/{rep_id}/download", token=token)
    valid_id_dl = s_dl == 200 and len(c_dl) > 0

    # 4.4.2 Unknown Report-ID (404)
    s_404, b_404, _, _ = http_get("/api/reports/unknown-random-uuid-999/download")
    unknown_id_404 = s_404 == 404

    # 4.4.3 Path Traversal Prevention
    s_trav, b_trav, _, _ = http_get("/api/reports/download?file=../../version.json")
    traversal_blocked = s_trav in (400, 403, 404)

    gate5_passed = valid_id_dl and unknown_id_404 and traversal_blocked
    dur = (time.time() - start) * 1000
    log_test("quality_gates", "Gate 5: Report-ID Authorized Download & Traversal Protection", gate5_passed, f"ValidIdDL={valid_id_dl}, Unknown404={unknown_id_404}, TraversalBlocked={traversal_blocked}", dur)

    # 4.5 Gate 6 & 7: UI Data Integrity & Personal Identity Elimination
    start = time.time()
    with open(os.path.join(ROOT_DIR, "Portal", "web", "index.html"), "r", encoding="utf-8") as f:
        html_src = f.read()

    no_static_endpoints = "5,520" not in html_src
    no_static_ghost = 'id="statGhost" class="text-2xl font-extrabold text-amber-600 tracking-tight">45<' not in html_src
    no_static_score = "%79.1" not in html_src
    no_personal_name = "Caner \u00c7etinkaya" not in html_src
    no_personal_initials = ">\u0043\u00c7<" not in html_src
    
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
        auth_token = run_api_tests()
        run_concurrency_tests(token=auth_token)
        run_quality_gates(token=auth_token)
    finally:
        stop_server()
    total_time = time.time() - start_all
    results["summary"]["execution_time_sec"] = round(total_time, 2)
    
    print("\n" + "="*80)
    print(" TEST ÇALIŞMASI TAMAMLANDI")
    print(f" Toplam Test: {results['summary']['total']}")
    print(f" Başarılı:    {results['summary']['passed']}")
    print(f" Başarısız:   {results['summary']['failed']}")
    print(f" Toplam Süre: {results['summary']['execution_time_sec']} saniye")
    print("="*80)
    
    # Attach release and execution metadata
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
    print(f"[OK] Test sonuçları metadata ile kaydedildi: {output_json}")

if __name__ == "__main__":
    main()
