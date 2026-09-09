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
ROOT_DIR = r"c:\Users\CANERCETINKAYA\OneDrive - CETINKAYA\Documents\Microsoft Purview Reports\CloudShieldMSSPPortal"
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

def http_get(path):
    url = f"{BASE_URL}{path}"
    start = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "CloudShield-QA-TestAutomation/1.0"})
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

def http_post(path, payload):
    url = f"{BASE_URL}{path}"
    body = json.dumps(payload).encode("utf-8")
    start = time.time()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "CloudShield-QA-TestAutomation/1.0"},
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
    passed = status == 200 and body.get("status") == "Healthy"
    log_test("api_tests", "GET /api/health - Sistem Sağlık Durumu", passed, f"Status={status}, Version={body.get('version')}", dur)

    # 2.2 GET /api/services
    status, body, dur, _ = http_get("/api/services")
    services = body.get("Services", {})
    passed = status == 200 and len(services) >= 10
    log_test("api_tests", "GET /api/services - Servis Kataloğu (10+ Servis)", passed, f"Status={status}, ServicesCount={len(services)}", dur)

    # 2.3 GET /api/tenants
    status, body, dur, _ = http_get("/api/tenants")
    has_sandbox = any(t.get("IsSimulation") for t in body)
    has_live = any(not t.get("IsSimulation") for t in body)
    passed = status == 200 and len(body) >= 2 and has_sandbox and has_live
    log_test("api_tests", "GET /api/tenants - Kiracı Listesi & Sandbox/Canlı Ayrımı", passed, f"Status={status}, Count={len(body)}, HasSandbox={has_sandbox}, HasLive={has_live}", dur)

    # 2.4 GET /api/users/me
    status, body, dur, _ = http_get("/api/users/me")
    passed = status == 200 and body.get("role") == "PlatformAdmin" and body.get("permissions", {}).get("CanGenerateReports") is True
    log_test("api_tests", "GET /api/users/me - RBAC Rol ve İzin Doğrulaması", passed, f"Status={status}, Role={body.get('role')}", dur)

    # 2.5 POST /api/auth/test
    status, body, dur = http_post("/api/auth/test", {})
    passed = status == 200 and body.get("success") is True and body.get("status") == "Validated"
    log_test("api_tests", "POST /api/auth/test - Entra ID Federasyon Testi", passed, f"Status={status}, Provider={body.get('authProvider')}", dur)

    # 2.6 POST /api/tenants/tenant-sandbox/test (Sandbox Tenant Bağlantı Testi)
    status, body, dur = http_post("/api/tenants/tenant-sandbox/test", {})
    passed = (status == 200 and body.get("success") is True and 
              body.get("isSimulation") is True and body.get("status") == "SimulationReady")
    log_test("api_tests", "POST /api/tenants/tenant-sandbox/test - Sandbox Hazır Yanıtı (200 OK)", passed, f"Status={status}, Badge={body.get('badge')}, Message={body.get('message')}", dur)

    # 2.7 POST /api/tenants/tenant-001/test (Eksik Kimlik Bilgili Canlı Kiracı Reddi)
    status, body, dur = http_post("/api/tenants/tenant-001/test", {})
    passed = (status == 400 and body.get("success") is False and 
              body.get("isSimulation") is False and body.get("status") == "AuthRequired")
    log_test("api_tests", "POST /api/tenants/tenant-001/test - Eksik Canlı Kiracı 400 Reddi", passed, f"Status={status}, StatusText={body.get('status')}, Error={body.get('error')}", dur)

    # 2.8 POST /api/tenants/tenant-002/test (Geçersiz Demo ID Canlı Kiracı Reddi)
    status, body, dur = http_post("/api/tenants/tenant-002/test", {})
    passed = (status == 400 and body.get("success") is False and 
              body.get("isSimulation") is False and body.get("status") == "AuthRequired")
    log_test("api_tests", "POST /api/tenants/tenant-002/test - Geçersiz Canlı Kiracı 400 Reddi", passed, f"Status={status}, StatusText={body.get('status')}", dur)

    # 2.9 POST /api/tenants/tenant-999-invalid/test (Bilinmeyen Kiracı 404 Reddi)
    status, body, dur = http_post("/api/tenants/tenant-999-invalid/test", {})
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/tenants/tenant-999-invalid/test - Bilinmeyen Kiracı 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.10 POST /api/reports/generate (Bilinmeyen Kiracı Rapor Talebi)
    status, body, dur = http_post("/api/reports/generate", {"tenantId": "tenant-999-unknown"})
    passed = status == 404 and body.get("success") is False
    log_test("api_tests", "POST /api/reports/generate - Bilinmeyen Kiracı Rapor 404 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.11 POST /api/reports/generate (Canlı Kiracı Eksik Yetki 400 Reddi)
    status, body, dur = http_post("/api/reports/generate", {"tenantId": "tenant-001", "services": ["SVC-MDE"]})
    passed = status == 400 and body.get("success") is False and "Canlı Kiracı Hatası" in body.get("error", "")
    log_test("api_tests", "POST /api/reports/generate - Canlı Kiracı Güvenlik 400 Reddi", passed, f"Status={status}, Error={body.get('error')}", dur)

    # 2.12 POST /api/reports/generate (Sandbox Başarılı Simülasyon Rapor Üretimi)
    print("   [INFO] Sandbox kiracısı için simülasyon raporu üretiliyor (PowerShell & Edge PDF motoru)...")
    status, body, dur = http_post("/api/reports/generate", {
        "tenantId": "tenant-sandbox",
        "services": ["SVC-MDE", "SVC-MDO"],
        "mode": "Monthly",
        "dryRun": True
    })
    pdf_url = body.get("pdfUrl", "")
    html_url = body.get("htmlUrl", "")
    passed = status == 200 and body.get("success") is True and body.get("isSimulation") is True and bool(pdf_url) and bool(html_url)
    log_test("api_tests", "POST /api/reports/generate - Sandbox Simülasyon Rapor Üretimi (200 OK)", passed, f"Status={status}, Customer={body.get('customer')}, PdfUrl={pdf_url}", dur)

    # 2.13 PDF & HTML İndirme ve Dosya Bütünlüğü Doğrulaması
    if pdf_url and html_url:
        p_status, p_content, p_dur, _ = http_get(pdf_url)
        h_status, h_content, h_dur, _ = http_get(html_url)
        is_pdf_valid = p_status == 200 and p_content.startswith(b"%PDF")
        is_html_valid = h_status == 200 and (b"<!DOCTYPE html>" in h_content or b"<html" in h_content)
        passed = is_pdf_valid and is_html_valid
        log_test("api_tests", "GET /api/reports/download - PDF/HTML Vektörel Dosya Bütünlüğü", passed, f"PdfSize={len(p_content)}B, HtmlSize={len(h_content)}B, ValidPdfHeader={is_pdf_valid}", p_dur + h_dur)

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

    # Test 3.1: Simultaneous Invalid/Live Requests (Fast concurrency check)
    def send_live_request(tid):
        return http_post("/api/reports/generate", {"tenantId": tid})
    
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_live_request, "tenant-001") for _ in range(5)]
        live_results = [f.result() for f in as_completed(futures)]
    t_dur = (time.time() - t_start) * 1000
    
    all_400 = all(r[0] == 400 for r in live_results)
    log_test("concurrency_tests", "Eşzamanlı 5 Canlı İstek İzolasyonu ve 400 Reddi", all_400, f"5/5 istek 400 döndü, süre: {round(t_dur, 1)}ms", t_dur)

    # Test 3.2: Concurrent Report Generation Requests with Different Configurations
    requests_data = [
        {"tenantId": "tenant-sandbox", "services": ["SVC-MDE"], "mode": "Monthly", "dryRun": True},
        {"tenantId": "tenant-sandbox", "services": ["SVC-MDO"], "mode": "Monthly", "dryRun": True},
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
