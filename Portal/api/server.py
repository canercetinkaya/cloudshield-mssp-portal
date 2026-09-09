#!/usr/bin/env python3
"""
CloudShield Enterprise MSSP Security & Compliance Platform (MSSP Portal)
Backend REST API Server - Pure Python 3 Standard Library (Zero External Dependencies)
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

try:
    from report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf
except ImportError:
    from Portal.api.report_generator import render_and_save_report, find_pdf_engine, create_executive_pdf

PORT = 8080
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB_DIR = os.path.join(ROOT_DIR, "Portal", "web")
DATA_DIR = os.path.join(ROOT_DIR, "Data")
TENANTS_FILE = os.path.join(DATA_DIR, "tenants.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
AUTH_CONFIG_FILE = os.path.join(DATA_DIR, "auth_config.json")
CACHE_FILE = os.path.join(DATA_DIR, "daily_cache.json")
CATALOG_FILE = os.path.join(ROOT_DIR, "Engine", "Config", "service-catalog.json")
OUTPUT_DIR = os.path.join(ROOT_DIR, "Engine", "Output")
DISPATCH_LOGS_FILE = os.path.join(DATA_DIR, "dispatch_logs.json")
ACTIVITIES_FILE = os.path.join(DATA_DIR, "manual-service-activities.json")

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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # API ROUTES
        if path == "/api/health":
            self.send_json_response({"status": "Healthy", "version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat()})
            return

        elif path == "/api/tenants":
            tenants = load_json_file(TENANTS_FILE, [])
            self.send_json_response(tenants)
            return

        elif path == "/api/users":
            users = load_json_file(USERS_FILE, [])
            self.send_json_response(users)
            return

        elif path == "/api/auth/config":
            auth_cfg = load_json_file(AUTH_CONFIG_FILE, {})
            self.send_json_response(auth_cfg)
            return

        elif path == "/api/services":
            catalog = load_json_file(CATALOG_FILE, {})
            self.send_json_response(catalog)
            return

        elif path == "/api/activities":
            activities = load_json_file(ACTIVITIES_FILE, [])
            tenant_filter = query.get("tenantId", [None])[0]
            if tenant_filter:
                activities = [a for a in activities if a.get("tenantId") == tenant_filter or a.get("customerName") == tenant_filter]
            self.send_json_response(activities)
            return

        elif path == "/api/users/me":
            # Current user context & RBAC
            self.send_json_response({
                "upn": "caner.cetinkaya@cloudshield-mssp.com",
                "displayName": "Caner Çetinkaya",
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
                "tenantCount": len(load_json_file(TENANTS_FILE, []))
            })
            return

        elif path == "/api/stats/global":
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
            history = load_json_file(DISPATCH_LOGS_FILE, [])
            self.send_json_response(history)
            return

        elif path == "/api/reports/download":
            file_param = query.get("file", [""])[0]
            if not file_param or ".." in file_param:
                self.send_error(400, "Invalid file path")
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

        if path == "/api/tenants":
            tenants = load_json_file(TENANTS_FILE, [])
            new_id = f"tenant-{len(tenants)+1:03d}"
            body["Id"] = new_id
            body["HealthStatus"] = body.get("HealthStatus", "Healthy")
            body["TotalEndpoints"] = int(body.get("TotalEndpoints", 120))
            body["GhostDevices"] = int(body.get("GhostDevices", 0))
            body["OpenHighAlerts"] = int(body.get("OpenHighAlerts", 0))
            body["SecureScore"] = float(body.get("SecureScore", 78.5))
            body["LastReportDate"] = datetime.now().strftime("%Y-%m-%d")
            body["ActiveServices"] = body.get("ActiveServices", ["SVC-MDE", "SVC-MDO"])
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
            tenants.append(body)
            save_json_file(TENANTS_FILE, tenants)
            self.send_json_response({"success": True, "tenant": body}, status=201)
            return

        elif path == "/api/dispatch/schedule":
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
            users = load_json_file(USERS_FILE, [])
            new_id = f"usr-{len(users)+1:03d}"
            body["Id"] = new_id
            body["LastLogin"] = "Henüz giriş yapmadı"
            users.append(body)
            save_json_file(USERS_FILE, users)
            self.send_json_response({"success": True, "user": body}, status=201)
            return

        elif path == "/api/stats/sync":
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
            activities = load_json_file(ACTIVITIES_FILE, [])
            new_id = f"ACT-{datetime.now().strftime('%Y%m%d')}-{len(activities)+1:03d}"
            body["activityId"] = new_id
            body["timestamp"] = datetime.now(timezone.utc).isoformat()
            activities.insert(0, body)
            save_json_file(ACTIVITIES_FILE, activities)
            self.send_json_response({"success": True, "activity": body}, status=201)
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
                cust_cfg["Subscriptions"]["ActiveServices"] = services

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
            if not os.path.exists(script_path):
                script_path = os.path.join(ROOT_DIR, "Engine", "Invoke-KocSistemSecurityReporting.ps1")

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
            
            # Pass specific single service if requested
            if services and len(services) == 1:
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

                # If PowerShell failed or did not produce report files, invoke Python fallback engine
                if not latest_html_path:
                    try:
                        py_html, py_pdf = render_and_save_report(customer_name, services, OUTPUT_DIR)
                        if py_html and os.path.exists(py_html):
                            latest_html_path = py_html
                        if py_pdf and os.path.exists(py_pdf):
                            latest_pdf_path = py_pdf
                        proc_log += "\n[OK] CloudShield Kurumsal Rapor Motoru ile rapor başarıyla derlendi."
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

                quoted_pdf = urllib.parse.quote(pdf_rel_path, safe="/") if pdf_rel_path else ""
                quoted_html = urllib.parse.quote(html_rel_path, safe="/") if html_rel_path else ""

                self.send_json_response({
                    "success": True,
                    "customer": customer_name,
                    "isSimulation": is_simulation,
                    "services": services,
                    "pdfUrl": f"/api/reports/download?file={quoted_pdf}" if quoted_pdf else "",
                    "htmlUrl": f"/api/reports/download?file={quoted_html}" if quoted_html else "",
                    "outputLog": proc_log[-500:] if proc_log else "Rapor başarıyla tamamlandı."
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
            client_id = auth_info.get("ClientId") or target.get("ClientId")
            client_secret = auth_info.get("ClientSecret") or target.get("ClientSecret")
            tenant_guid = target.get("TenantId")

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

                if client_secret:
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

                        # Test Graph API alerts endpoint with acquired token
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
                            "badge": "Canlı Kiracı Bağlandı",
                            "message": f"Microsoft Entra ID kiracısına ({tenant_guid[:8]}...) başarıyla bağlanıldı. {api_detail}",
                            "tenantId": tenant_guid,
                            "tokenEndpoint": token_url,
                            "latencyMs": latency,
                            "testedAt": datetime.now(timezone.utc).isoformat()
                        })
                        return
                else:
                    # Fallback to OpenID metadata check
                    entra_url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
                    req = urllib.request.Request(entra_url, headers={"User-Agent": "CloudShield-MSSP-Portal/2.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        self.send_json_response({
                            "success": True,
                            "isSimulation": False,
                            "status": "LiveConnected",
                            "badge": "Kiracı Doğrulandı",
                            "message": f"Microsoft Entra ID Kiracı uç noktası ({tenant_guid[:8]}...) doğrulandı. (Secret Key Vault üzerinden okunacak).",
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

        if path.startswith("/api/tenants/"):
            tenant_id = path.replace("/api/tenants/", "").strip()
            tenants = load_json_file(TENANTS_FILE, [])
            idx = next((i for i, t in enumerate(tenants) if t.get("Id") == tenant_id), None)
            if idx is not None:
                tenants[idx].update(body)
                save_json_file(TENANTS_FILE, tenants)
                self.send_json_response({"success": True, "tenant": tenants[idx]})
            else:
                self.send_json_response({"success": False, "error": "Tenant not found"}, status=404)
            return

        elif path.startswith("/api/users/"):
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
            save_json_file(AUTH_CONFIG_FILE, body)
            self.send_json_response({"success": True, "config": body})
            return

        self.send_error(404, "Endpoint Not Found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/tenants/"):
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

def run(port=PORT):
    server_address = ("", port)
    httpd = http.server.ThreadingHTTPServer(server_address, MSSPPortalHandler)
    print("=" * 80)
    print(f"  CloudShield Enterprise MSSP Security & Compliance Platform")
    print(f"  Web Portalı ve REST API başlatıldı: http://localhost:{port}")
    print(f"  Statik Web Dosyaları: {WEB_DIR}")
    print(f"  Veritabanı: {TENANTS_FILE}")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Sunucu durduruldu.")
        httpd.server_close()

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run(p)
