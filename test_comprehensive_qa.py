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

results = {
    "engine_tests": [],
    "api_tests": [],
    "concurrency_tests": [],
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
        return 0, str(e), dur, b""

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
    print(" 1. ENGINE PLATFORM TESTS (30 PS TESTS)")
    print("="*80)
    test_script = os.path.join(ENGINE_DIR, "Tests", "Test-Platform.ps1")
    start = time.time()
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", test_script],
        cwd=ENGINE_DIR, capture_output=True, text=True, errors="replace"
    )
    dur = (time.time() - start) * 1000
    out = proc.stdout
    lines = [l.strip() for l in out.splitlines() if "[PASS]" in l or "[FAIL]" in l]
    
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
    
    # 2.1 GET /api/health
    status, body, dur, _ = http_get("/api/health")
    passed = status == 200 and body.get("status") == "Healthy" and "2.5.0" in body.get("version", "")
    log_test("api_tests", "GET /api/health - Sistem Sağlık Durumu (v2.5.0)", passed, f"Status={status}, Version={body.get('version')}", dur)

    # 2.2 GET /api/version
    status, body, dur, _ = http_get("/api/version")
    passed = status == 200 and body.get("version") == "2.5.0" and body.get("release") == "v2.5.0-LIVE"
    log_test("api_tests", "GET /api/version - Platform Sürüm ve Sürüm Başlığı Doğrulaması", passed, f"Status={status}, Release={body.get('release')}, Build={body.get('build')}", dur)

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

    status, body, dur = http_post("/api/auth/login", {"username": admin_user, "password": admin_pass})
    auth_token = body.get("token", "")
    passed = status == 200 and body.get("success") is True and bool(auth_token)
    log_test("api_tests", "POST /api/auth/login - Platform Admin Oturum Açma (Sıfır Hardcode)", passed, f"Status={status}, Role={body.get('user', {}).get('role')}", dur)

    # 2.3.1 POST /api/auth/login (Hatalı Parola Reddi & Bilgi Sızdırmama Güvencesi)
    status_bad, body_bad, dur_bad = http_post("/api/auth/login", {"username": admin_user, "password": "InvalidPassword_StrictTest#1"})
    bad_passed = status_bad == 401 and body_bad.get("success") is False and "CloudShield" not in str(body_bad)
    log_test("api_tests", "POST /api/auth/login - 401 Yetkisiz Giriş & Hata Mesajında Sıfır Sızıntı", bad_passed, f"Status={status_bad}, GenericError={body_bad.get('error')}", dur_bad)

    # 2.3.2 POST /api/auth/sso (Entra ID Kurumsal SSO Endpoint Doğrulaması)
    status_sso, body_sso, dur_sso = http_post("/api/auth/sso", {"provider": "EntraID_OIDC"})
    sso_passed = status_sso == 200 and body_sso.get("success") is True and bool(body_sso.get("token"))
    log_test("api_tests", "POST /api/auth/sso - Entra ID Kurumsal SSO Oturum Doğrulaması", sso_passed, f"Status={status_sso}, User={body_sso.get('user', {}).get('displayName')}", dur_sso)

    # 2.4 GET /api/services
    status, body, dur, _ = http_get("/api/services")
    services = body.get("services") or body.get("Services", {})
    passed = status == 200 and len(services) >= 10
    log_test("api_tests", "GET /api/services - Servis Kataloğu (10+ Servis)", passed, f"Status={status}, ServicesCount={len(services)}", dur)

    # 2.5 GET /api/tenants - Sadece Canlı Tenant Doğrulaması (Sıfır Mock/Test Müşterisi)
    status, body, dur, _ = http_get("/api/tenants")
    has_sandbox = any(t.get("IsSimulation") for t in body)
    all_live = all(not t.get("IsSimulation") for t in body) and len(body) >= 1
    has_target_live = any(t.get("Id") == "tenant-002" and t.get("Name") == "Emre-TestTenant" for t in body)
    passed = status == 200 and not has_sandbox and all_live and has_target_live
    log_test("api_tests", "GET /api/tenants - Sadece Canlı Kiracı (Sıfır Sahte/Mock Müşteri)", passed, f"Status={status}, Count={len(body)}, HasSandbox={has_sandbox}, AllLive={all_live}", dur)

    # 2.6 GET /api/users/me
    status, body, dur, _ = http_get("/api/users/me")
    passed = status == 200 and body.get("role") == "PlatformAdmin" and body.get("permissions", {}).get("CanGenerateReports") is True
    log_test("api_tests", "GET /api/users/me - RBAC Rol ve İzin Doğrulaması", passed, f"Status={status}, Role={body.get('role')}", dur)

    # 2.7 POST /api/auth/test
    status, body, dur = http_post("/api/auth/test", {})
    passed = status == 200 and body.get("success") is True and body.get("status") == "Validated"
    log_test("api_tests", "POST /api/auth/test - Entra ID Federasyon Testi", passed, f"Status={status}, Provider={body.get('authProvider')}", dur)

    # 2.8 POST /api/tenants/tenant-002/test (Canlı Kiracı OAuth Bağlantı Doğrulaması)
    status, body, dur = http_post("/api/tenants/tenant-002/test", {})
    passed = (status == 200 and body.get("success") is True and 
              body.get("isSimulation") is False and body.get("status") == "LiveConnected")
    log_test("api_tests", "POST /api/tenants/tenant-002/test - Canlı Kiracı OAuth Doğrulaması (200 OK)", passed, f"Status={status}, StatusText={body.get('status')}, Badge={body.get('badge')}", dur)

    # 2.9 POST /api/tenants/tenant-999-invalid/test (Bilinmeyen Kiracı 404 Reddi)
    status, body, dur = http_post("/api/tenants/tenant-999-invalid/test", {})
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/tenants/tenant-999-invalid/test - Bilinmeyen Kiracı 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.10 POST /api/reports/generate (Bilinmeyen Kiracı Rapor Talebi 404 Reddi)
    status, body, dur = http_post("/api/reports/generate", {"tenantId": "tenant-999-unknown"})
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/reports/generate - Bilinmeyen Kiracı Rapor 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.11 POST /api/reports/generate (Canlı Kiracı Başarılı Rapor Üretimi - dryRun modunda)
    print("   [INFO] Canlı kiracı (tenant-002) için rapor üretim motoru çalıştırılıyor...")
    status, body, dur = http_post("/api/reports/generate", {
        "tenantId": "tenant-002",
        "services": ["SVC-MDE", "SVC-MDO"],
        "mode": "Monthly",
        "dryRun": True
    })
    pdf_url = body.get("pdfUrl", "")
    html_url = body.get("htmlUrl", "")
    passed = status == 200 and body.get("success") is True and bool(pdf_url) and bool(html_url)
    log_test("api_tests", "POST /api/reports/generate - Canlı Kiracı Rapor Üretimi (200 OK)", passed, f"Status={status}, Customer={body.get('customer')}, PdfUrl={pdf_url}", dur)

    # 2.12 PDF & HTML İndirme ve Dosya Bütünlüğü Doğrulaması
    if pdf_url and html_url:
        p_status, p_content, p_dur, _ = http_get(pdf_url)
        h_status, h_content, h_dur, _ = http_get(html_url)
        is_pdf_valid = p_status == 200 and p_content.startswith(b"%PDF")
        is_html_valid = h_status == 200 and (b"<!DOCTYPE html>" in h_content or b"<html" in h_content)
        passed = is_pdf_valid and is_html_valid
        log_test("api_tests", "GET /api/reports/download - PDF/HTML Vektörel Dosya Bütünlüğü", passed, f"PdfSize={len(p_content)}B, HtmlSize={len(h_content)}B, ValidPdfHeader={is_pdf_valid}", p_dur + h_dur)

    # 2.13 GET /api/tenants/tenant-002/logo - Entra ID Logo ve Dinamik Monogram Doğrulaması
    status, logo_content, dur, _ = http_get("/api/tenants/tenant-002/logo")
    is_valid_logo = status == 200 and (logo_content.startswith(b"\x89PNG") or b"<svg" in logo_content)
    log_test("api_tests", "GET /api/tenants/tenant-002/logo - Entra ID Müşteri Logosu / Vektörel Monogram (200 OK)", is_valid_logo, f"Status={status}, ContentSize={len(logo_content)}B, IsImageOrSvg={is_valid_logo}", dur)

    # 2.14 POST /api/auth/login - Müşteri CISO (usr-005) Oturum Açma
    status_u5, body_u5, dur_u5 = http_post("/api/auth/login", {"username": "customer.ciso@emre-tenant.com", "password": admin_pass})
    tok_u5 = body_u5.get("token", "")
    u5_passed = status_u5 == 200 and body_u5.get("user", {}).get("role") == "CustomerCISO" and body_u5.get("user", {}).get("AssignedTenants") == ["tenant-002"]
    log_test("api_tests", "POST /api/auth/login - Müşteri CISO (usr-005) RBAC Doğrulaması", u5_passed, f"Status={status_u5}, Role={body_u5.get('user', {}).get('role')}, Tenants={body_u5.get('user', {}).get('AssignedTenants')}", dur_u5)

    # 2.15 GET /api/tenants - Müşteri CISO (usr-005) Sadece Atanmış Kiracısını Görür
    status_t5, body_t5, dur_t5, _ = http_get("/api/tenants", token=tok_u5)
    t5_passed = status_t5 == 200 and len(body_t5) == 1 and body_t5[0].get("Id") == "tenant-002"
    log_test("api_tests", "GET /api/tenants - usr-005 Oturumunda Sadece Atanmış Kiracı İzolasyonu", t5_passed, f"Status={status_t5}, Count={len(body_t5)}, VisibleTenants={[t.get('Id') for t in body_t5]}", dur_t5)

    # 2.16 POST /api/auth/login - Farklı Müşteri Yöneticisi (usr-006) Oturum Açma
    status_u6, body_u6, dur_u6 = http_post("/api/auth/login", {"username": "external.ciso@other-client.com", "password": admin_pass})
    tok_u6 = body_u6.get("token", "")
    u6_passed = status_u6 == 200 and body_u6.get("user", {}).get("role") == "CustomerViewer" and body_u6.get("user", {}).get("AssignedTenants") == ["tenant-isolated-other"]
    log_test("api_tests", "POST /api/auth/login - Farklı Müşteri (usr-006) RBAC Oturum Doğrulaması", u6_passed, f"Status={status_u6}, Role={body_u6.get('user', {}).get('role')}, Tenants={body_u6.get('user', {}).get('AssignedTenants')}", dur_u6)

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

# ==============================================================================
# 3. MULTI-TENANT CONCURRENCY & ISOLATION
# ==============================================================================
def run_concurrency_tests():
    print("\n" + "="*80)
    print(" 3. ÇOKLU KİRACI EŞZAMANLILIK (CONCURRENCY) & İZOLASYON TESTLERİ")
    print("="*80)

    # Ensure temp dir exists
    os.makedirs(TEMP_DATA_DIR, exist_ok=True)
    initial_temp_files = os.listdir(TEMP_DATA_DIR)
    print(f"   [INFO] Temp dizini başlangıç dosya sayısı: {len(initial_temp_files)}")

    # Test 3.1: Simultaneous Invalid Requests (Fast concurrency check for unknown tenants)
    def send_live_request(tid):
        return http_post("/api/reports/generate", {"tenantId": tid})
    
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
            time.sleep(0.01)

    monitor_thread = threading.Thread(target=monitor_temp_dir, daemon=True)
    monitor_thread.start()

    print("   [INFO] 2 eşzamanlı rapor üretim isteği (SVC-MDE ve SVC-MDO) tetikleniyor...")
    start_c = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(http_post, "/api/reports/generate", req) for req in requests_data]
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

def main():
    start_all = time.time()
    run_engine_tests()
    run_api_tests()
    run_concurrency_tests()
    total_time = time.time() - start_all
    results["summary"]["execution_time_sec"] = round(total_time, 2)
    
    print("\n" + "="*80)
    print(" TEST ÇALIŞMASI TAMAMLANDI")
    print(f" Toplam Test: {results['summary']['total']}")
    print(f" Başarılı:    {results['summary']['passed']}")
    print(f" Başarısız:   {results['summary']['failed']}")
    print(f" Toplam Süre: {results['summary']['execution_time_sec']} saniye")
    print("="*80)
    
    output_json = os.path.join(ROOT_DIR, "qa_test_results.json")
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[OK] Test sonuçları kaydedildi: {output_json}")

if __name__ == "__main__":
    main()
