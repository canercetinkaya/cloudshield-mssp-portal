# CloudShield MSSP Platform Relational RBAC Database Manager
# Pure Python Standard Library (sqlite3, hashlib, secrets, os, json, datetime)

import os
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timezone, timedelta

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(ROOT_DIR, "Data", "cloudshield_rbac.db")
MIGRATIONS_DIR = os.path.join(ROOT_DIR, "database", "migrations")

def get_db(db_path=None):
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return key.hex(), salt

def verify_password(password, expected_hash, salt):
    if not salt or not expected_hash:
        return False
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    import hmac
    return hmac.compare_digest(key.hex(), expected_hash)

def init_db(db_path=None):
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)
    conn.commit()

    cur.execute("SELECT filename FROM _migrations")
    applied = {row["filename"] for row in cur.fetchall()}

    if os.path.exists(MIGRATIONS_DIR):
        migration_files = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")])
        for mfile in migration_files:
            if mfile not in applied:
                print(f"[MIGRATION] Applying {mfile}...")
                with open(os.path.join(MIGRATIONS_DIR, mfile), "r", encoding="utf-8") as mf:
                    sql_script = mf.read()
                cur.executescript(sql_script)
                cur.execute(
                    "INSERT INTO _migrations (filename, applied_at) VALUES (?, ?)",
                    (mfile, datetime.now(timezone.utc).isoformat())
                )
                conn.commit()
                print(f"[MIGRATION] Successfully applied {mfile}")

    seed_default_data(conn)
    conn.close()
    print("[DB] Database initialization and seed complete.")

def seed_default_data(conn):
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # 1. Organization
    cur.execute("SELECT id FROM organizations WHERE id = ?", ("org-kocsistem",))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO organizations (id, name, domain, created_at) VALUES (?, ?, ?, ?)",
            ("org-kocsistem", "KoçSistem MSSP Platform", "kocsistem.com.tr", now)
        )

    # 2. Permissions
    permissions_data = [
        ("reports:view", "Raporları Görüntüle", "reports", "Rapor özetlerini ve durumlarını listeleme"),
        ("reports:generate", "Rapor Üret", "reports", "Yeni güvenlik ve uyum raporu üretme tetikleme"),
        ("reports:download", "Rapor İndir", "reports", "HTML ve PDF rapor dosyalarını indirme"),
        ("reports:review", "Rapor İncele", "reports", "Rapor kalite ve veri bulgularını inceleme"),
        ("reports:approve", "Rapor Onayla", "reports", "Müşteriye sunulacak raporu onaylama"),
        ("customers:view", "Müşterileri Görüntüle", "customers", "Müşteri tenant listesi ve sağlık durumu"),
        ("customers:manage", "Müşterileri Yönet", "customers", "Müşteri ekleme, düzenleme ve silme"),
        ("services:view", "Servisleri Görüntüle", "services", "12 servis kataloğu ve telemetri kaynakları"),
        ("services:manage", "Servisleri Yönet", "services", "Servis tanımları ve eklenti yapılandırmaları"),
        ("matrix:view", "Servis Matrisini Görüntüle", "matrix", "Müşteri-Servis abonelik durumu matrisi"),
        ("matrix:manage", "Servis Matrisini Yönet", "matrix", "Servis onboarding, askıya alma ve seviye belirleme"),
        ("teams:view", "Ekipleri Görüntüle", "teams", "Operasyonel ekipler ve üyeleri"),
        ("teams:manage", "Ekipleri Yönet", "teams", "Ekip oluşturma ve üye atamaları"),
        ("roles:view", "Rol Kataloğunu Görüntüle", "roles", "Platform ve müşteri rolleri listesi"),
        ("roles:manage", "Rolleri Yönet", "roles", "Rol oluşturma ve izin atamaları"),
        ("assignments:view", "Erişim Atamalarını Görüntüle", "assignments", "Kullanıcı ve ekip erişim atamaları"),
        ("assignments:manage", "Erişim Atamalarını Yönet", "assignments", "Yeni erişim atama veya iptal etme"),
        ("approvals:request", "Süreli (JIT) Erişim Talep Et", "approvals", "Zaman kısıtlı ve onay zorunlu süreli (JIT) erişim talebi (Entra PIM Sıfır Sürekli Yetki prensibi)"),
        ("approvals:decide", "Süreli (JIT) Erişim Taleplerini Onayla/Reddet", "approvals", "Bekleyen süreli yetki taleplerini SoD gözeterek yanıtlama"),
        ("audit:view", "Yetkilendirme Denetim Kütüğünü Gör", "audit", "Allow/Deny kararları ve güvenlik denetim izi"),
        ("simulator:run", "Erişim Simülatörünü Çalıştır", "simulator", "Kullanıcı-Müşteri-Servis karar zinciri simülasyonu")
    ]

    for p_code, p_name, p_dom, p_desc in permissions_data:
        p_id = f"perm-{p_code.replace(':', '-')}"
        cur.execute("SELECT id FROM permissions WHERE code = ?", (p_code,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO permissions (id, code, name, domain, description) VALUES (?, ?, ?, ?, ?)",
                (p_id, p_code, p_name, p_dom, p_desc)
            )

    # 3. Roles
    roles_data = [
        ("role-platform-admin", "PlatformAdmin", "Platform Yöneticisi", "Tüm sistem, müşteri ve servislerde tam yetki", 1, 1),
        ("role-security-engineer", "SecurityEngineer", "Kıdemli Güvenlik Mühendisi (EDR/XDR)", "Defender ve XDR operasyonları, rapor üretimi ve indirme", 0, 1),
        ("role-compliance-specialist", "ComplianceSpecialist", "Purview & Uyum Uzmanı", "DLP, sınıflandırma, iç tehdit operasyonları ve raporlama", 0, 1),
        ("role-customer-ciso", "CustomerCISO", "Müşteri CISO & Yönetici", "Müşteriye özel güvenlik panosu, rapor inceleme ve onaylama", 0, 1),
        ("role-auditor", "Auditor", "Bağımsız Denetçi", "Tüm denetim kütükleri, atamalar ve raporları salt-okunur inceleme", 0, 1),
        ("role-service-operator", "ServiceOperator", "Operasyonel Teknisyen", "Temel telemetri izleme ve salt-okunur pano görünümü", 0, 1)
    ]

    for r_id, r_name, r_disp, r_desc, is_plat, is_sys in roles_data:
        cur.execute("SELECT id FROM roles WHERE name = ?", (r_name,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO roles (id, name, display_name, description, is_platform_role, is_system, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (r_id, r_name, r_disp, r_desc, is_plat, is_sys, now)
            )

    # Map Role Permissions
    cur.execute("SELECT id, code FROM permissions")
    perm_map = {row["code"]: row["id"] for row in cur.fetchall()}

    role_perm_assignments = {
        "PlatformAdmin": list(perm_map.keys()),
        "SecurityEngineer": [
            "reports:view", "reports:generate", "reports:download", "reports:review",
            "customers:view", "services:view", "matrix:view", "teams:view", "approvals:request", "simulator:run"
        ],
        "ComplianceSpecialist": [
            "reports:view", "reports:generate", "reports:download", "reports:review",
            "customers:view", "services:view", "matrix:view", "teams:view", "approvals:request", "simulator:run"
        ],
        "CustomerCISO": [
            "reports:view", "reports:download", "reports:review", "reports:approve",
            "customers:view", "services:view", "matrix:view"
        ],
        "Auditor": [
            "reports:view", "reports:download", "audit:view", "customers:view",
            "services:view", "roles:view", "assignments:view", "teams:view", "matrix:view"
        ],
        "ServiceOperator": [
            "reports:view", "customers:view", "services:view", "matrix:view"
        ]
    }

    for r_name, p_codes in role_perm_assignments.items():
        cur.execute("SELECT id FROM roles WHERE name = ?", (r_name,))
        r_row = cur.fetchone()
        if r_row:
            r_id = r_row["id"]
            for p_code in p_codes:
                p_id = perm_map.get(p_code)
                if p_id:
                    rp_id = f"{r_id}_{p_id}"
                    cur.execute("SELECT id FROM role_permissions WHERE role_id = ? AND permission_id = ?", (r_id, p_id))
                    if not cur.fetchone():
                        cur.execute(
                            "INSERT INTO role_permissions (id, role_id, permission_id) VALUES (?, ?, ?)",
                            (rp_id, r_id, p_id)
                        )

    # 4. Services (Load from service-catalog.json if available)
    catalog_path = os.path.join(ROOT_DIR, "Engine", "Config", "service-catalog.json")
    services_list = []
    if os.path.exists(catalog_path):
        try:
            with open(catalog_path, "r", encoding="utf-8") as cf:
                cat_data = json.load(cf)
                for scode, sinfo in cat_data.get("services", {}).items():
                    services_list.append((
                        f"svc-{scode.lower().replace('svc-', '')}",
                        scode,
                        sinfo.get("displayNameTr", scode),
                        sinfo.get("displayNameEn", scode),
                        sinfo.get("category", "Security"),
                        sinfo.get("productFamily", "Microsoft Security"),
                        sinfo.get("pluginFolder", "")
                    ))
        except Exception as e:
            print(f"[WARN] Catalog load error: {e}")

    if not services_list:
        services_list = [
            ("svc-mde", "SVC-MDE", "Yönetilen Uç Nokta Güvenliği (EDR)", "Managed Endpoint Security", "Endpoint", "Microsoft Defender for Endpoint", "DefenderEndpoint"),
            ("svc-mdo", "SVC-MDO", "Yönetilen E-posta & İşbirliği Güvenliği", "Managed Email Security", "Email", "Microsoft Defender for Office 365", "DefenderOffice"),
            ("svc-mdi", "SVC-MDI", "Yönetilen Kimlik Tehdit Algılama (ITDR)", "Managed Identity Security", "Identity", "Microsoft Defender for Identity", "DefenderIdentity"),
            ("svc-mdca", "SVC-MDCA", "Bulut Uygulama Güvenliği (CASB)", "Cloud App Security", "Cloud", "Microsoft Defender for Cloud Apps", "DefenderCloudApps"),
            ("svc-xdr", "SVC-XDR", "Bütünleşik Tehdit Yönetimi (XDR)", "Integrated XDR Management", "SecOps", "Microsoft Defender XDR", "DefenderXdr"),
            ("svc-intune", "SVC-INTUNE", "Cihaz Uyum & Konfigürasyon Yönetimi", "Device Compliance", "Endpoint", "Microsoft Intune", "IntuneCompliance"),
            ("svc-entra-pim", "SVC-ENTRA-PIM", "Ayrıcalıklı Kimlik Yönetimi (PIM)", "Privileged Identity Management", "Identity", "Microsoft Entra ID", "EntraGovernance"),
            ("svc-prv-dlp", "SVC-PRV-DLP", "Veri Kaybı Önleme (Purview DLP)", "Data Loss Prevention", "Purview", "Microsoft Purview", "PurviewDlp"),
            ("svc-prv-class", "SVC-PRV-CLASS", "Veri Sınıflandırma & Etiketleme", "Data Classification", "Purview", "Microsoft Purview", "PurviewClassification"),
            ("svc-prv-gov", "SVC-PRV-GOV", "Veri Yaşam Döngüsü & Arşivleme", "Data Lifecycle Management", "Purview", "Microsoft Purview", "PurviewGovernance"),
            ("svc-prv-risk", "SVC-PRV-RISK", "İç Tehdit & Uyarlanabilir Koruma", "Insider Risk Management", "Purview", "Microsoft Purview", "PurviewRiskCompliance"),
            ("svc-ai-security", "SVC-AI-SECURITY", "Yapay Zeka Güvenliği & Copilot", "AI Security & Governance", "AI", "Microsoft Purview AI Hub", "PurviewAiSecurity")
        ]

    for sid, scode, str_name, sen_name, scat, sprod, sdir in services_list:
        cur.execute("SELECT id FROM services WHERE code = ?", (scode,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO services (id, code, name_tr, name_en, category, product_family, plugin_folder, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (sid, scode, str_name, sen_name, scat, sprod, sdir)
            )

    # 5. Teams
    teams_data = [
        ("team-edr", "org-kocsistem", "Core-MSSP EDR & XDR Mühendisliği", "Defender Endpoint, Office ve XDR operasyonları ekibi"),
        ("team-compliance", "org-kocsistem", "Veri Güvenliği & Purview Uyum", "DLP, Hassas Veri Sınıflandırma ve İç Tehdit ekibi"),
        ("team-ciso-board", "org-kocsistem", "Müşteri Yönetici Gözetimi (CISO/Board)", "Müşteri CISO ve yönetim kurulu inceleme delegasyonu")
    ]
    for tid, torg, tname, tdesc in teams_data:
        cur.execute("SELECT id FROM teams WHERE id = ?", (tid,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO teams (id, organization_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
                (tid, torg, tname, tdesc, now)
            )

    # 6. Customers (Import from Data/tenants.json)
    tenants_path = os.path.join(ROOT_DIR, "Data", "tenants.json")
    if os.path.exists(tenants_path):
        try:
            with open(tenants_path, "r", encoding="utf-8") as tf:
                tenants_data = json.load(tf)
                for t in tenants_data:
                    cid = t.get("Id", f"cust-{secrets.token_hex(4)}")
                    t_guid = t.get("TenantId", cid)
                    c_name = t.get("Name", "Unknown Customer")
                    c_email = t.get("ContactEmail", "security-lead@cloudshield-mssp.com")
                    c_mode = t.get("ReportMode", "Consolidated")
                    c_pkg = t.get("SelectedPackage", "PKG-10")
                    c_conn = t.get("ConnectionStatus", "LiveConnected")
                    c_hlth = t.get("HealthStatus", "Healthy")
                    c_score = float(t.get("SecureScore", 0.0))

                    cur.execute("SELECT id FROM customers WHERE id = ? OR tenant_id = ?", (cid, t_guid))
                    if not cur.fetchone():
                        cur.execute(
                            """INSERT INTO customers (id, tenant_id, name, contact_email, report_mode, selected_package,
                                                    connection_status, health_status, secure_score, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (cid, t_guid, c_name, c_email, c_mode, c_pkg, c_conn, c_hlth, c_score, now)
                        )

                    active_svcs = t.get("ActiveServices", [])
                    for asvc in active_svcs:
                        cur.execute("SELECT id FROM services WHERE code = ?", (asvc,))
                        srow = cur.fetchone()
                        if srow:
                            cs_id = f"{cid}_{srow['id']}"
                            cur.execute("SELECT id FROM customer_services WHERE customer_id = ? AND service_id = ?", (cid, srow["id"]))
                            if not cur.fetchone():
                                cur.execute(
                                    """INSERT INTO customer_services (id, customer_id, service_id, service_level, status, onboarded_at, updated_at)
                                       VALUES (?, ?, ?, 'Managed', 'Onboarded', ?, ?)""",
                                    (cs_id, cid, srow["id"], now, now)
                                )
        except Exception as e:
            print(f"[WARN] Tenant import error: {e}")

    cur.execute("SELECT id FROM customers WHERE id = ?", ("tenant-002",))
    if not cur.fetchone():
        cur.execute(
            """INSERT INTO customers (id, tenant_id, name, contact_email, report_mode, selected_package,
                                    connection_status, health_status, secure_score, created_at)
               VALUES (?, ?, ?, ?, 'Consolidated', 'PKG-10', 'LiveConnected', 'Healthy', 43.0, ?)""",
            ("tenant-002", "c9c0ee10-6398-473c-9681-d2fffaa55531", "Emre-TestTenant",
             "security-lead@cloudshield-mssp.com", now)
        )

    # 7. Users
    admin_hash, admin_salt = hash_password("CloudShield2026!*")
    cur.execute("SELECT id FROM users WHERE upn = ?", ("admin@cloudshield-mssp.com",))
    if not cur.fetchone():
        cur.execute(
            """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 'Local', ?)""",
            ("usr-admin", "org-kocsistem", "admin@cloudshield-mssp.com", "Platform Administrator",
             "admin@cloudshield-mssp.com", "Siber Güvenlik Çözüm Mimarlığı", admin_hash, admin_salt, now)
        )
        cur.execute(
            """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope,
                                              service_scope, valid_from, is_temporary, is_active, created_by, created_at)
               VALUES (?, 'User', ?, 'role-platform-admin', 'ALL', 'ALL', ?, 0, 1, 'system', ?)""",
            ("asgn-admin", "usr-admin", now, now)
        )

    # Pilot mode JIT temporary access elevation for tenant-002
    cur.execute("SELECT id FROM access_assignments WHERE id = 'asgn-jit-pilot-admin'")
    if not cur.fetchone():
        jit_to = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        cur.execute(
            """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                              service_scope, service_id, valid_from, valid_to, is_temporary, is_active, approval_id, created_by, created_at)
               VALUES ('asgn-jit-pilot-admin', 'User', 'usr-admin', 'role-security-engineer', 'Specific', 'tenant-002',
                       'ALL', NULL, ?, ?, 1, 1, 'appr-pilot-init', 'system', ?)""",
            (now, jit_to, now)
        )

    # Import from Data/users.json
    users_path = os.path.join(ROOT_DIR, "Data", "users.json")
    if os.path.exists(users_path):
        try:
            with open(users_path, "r", encoding="utf-8") as uf:
                raw_users = json.load(uf)
                for u in raw_users:
                    uid = u.get("Id", f"usr-{secrets.token_hex(3)}")
                    upn = u.get("Upn", f"{uid}@cloudshield-mssp.com")
                    dname = u.get("DisplayName", upn)
                    dept = u.get("Department", "MSSP")
                    role_str = u.get("Role", "ServiceOperator")
                    assigned_tenants = u.get("AssignedTenants", ["ALL"])

                    cur.execute("SELECT id FROM users WHERE id = ? OR upn = ?", (uid, upn))
                    u_existing = cur.fetchone()
                    if not u_existing:
                        u_hash, u_salt = hash_password("SecurePass2026!*")
                        cur.execute(
                            """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                                password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'Local', ?)""",
                            (uid, "org-kocsistem", upn, dname, upn, dept, u_hash, u_salt, now)
                        )

                        role_id = "role-service-operator"
                        svc_scope = "ALL"
                        svc_id = None
                        if role_str == "PlatformAdmin":
                            role_id = "role-platform-admin"
                        elif role_str == "EdrEngineer":
                            role_id = "role-security-engineer"
                            svc_scope = "Specific"
                            svc_id = "svc-mde"
                        elif role_str == "ComplianceSpecialist":
                            role_id = "role-compliance-specialist"
                            svc_scope = "Specific"
                            svc_id = "svc-prv-dlp"
                        elif role_str == "XdrEngineer":
                            role_id = "role-security-engineer"
                            svc_scope = "Specific"
                            svc_id = "svc-xdr"
                        elif role_str == "CustomerCISO":
                            role_id = "role-customer-ciso"

                        if "ALL" in assigned_tenants:
                            asgn_id = f"asgn-{uid}-all"
                            cur.execute(
                                """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                                                  service_scope, service_id, valid_from, is_temporary, is_active, created_by, created_at)
                                   VALUES (?, 'User', ?, ?, 'ALL', NULL, ?, ?, ?, 0, 1, 'system', ?)""",
                                (asgn_id, uid, role_id, svc_scope, svc_id, now, now)
                            )
                        else:
                            for tid in assigned_tenants:
                                asgn_id = f"asgn-{uid}-{tid}"
                                cur.execute(
                                    """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                                                      service_scope, service_id, valid_from, is_temporary, is_active, created_by, created_at)
                                       VALUES (?, 'User', ?, ?, 'Specific', ?, ?, ?, ?, 0, 1, 'system', ?)""",
                                    (asgn_id, uid, role_id, tid, svc_scope, svc_id, now, now)
                                )

                        if role_str in ("EdrEngineer", "XdrEngineer"):
                            cur.execute("INSERT OR IGNORE INTO team_memberships (id, team_id, user_id, role_in_team, joined_at) VALUES (?, ?, ?, ?, ?)",
                                        (f"tm-{uid}-edr", "team-edr", uid, "Engineer", now))
                        elif role_str == "ComplianceSpecialist":
                            cur.execute("INSERT OR IGNORE INTO team_memberships (id, team_id, user_id, role_in_team, joined_at) VALUES (?, ?, ?, ?, ?)",
                                        (f"tm-{uid}-prv", "team-compliance", uid, "Specialist", now))
                        elif role_str == "CustomerCISO":
                            cur.execute("INSERT OR IGNORE INTO team_memberships (id, team_id, user_id, role_in_team, joined_at) VALUES (?, ?, ?, ?, ?)",
                                        (f"tm-{uid}-ciso", "team-ciso-board", uid, "Executive", now))
        except Exception as e:
            print(f"[WARN] User import error: {e}")

    conn.commit()

if __name__ == "__main__":
    init_db()
