# CloudShield MSSP Platform Relational RBAC Database Manager
# Pure Python Standard Library (sqlite3, hashlib, secrets, os, json, datetime)

import os
import pathlib
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timezone, timedelta

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(ROOT_DIR, "Data", "cloudshield_rbac.db")
MIGRATIONS_DIR = os.path.join(ROOT_DIR, "database", "migrations")

def verify_replica_safety():
    """
    Controlled Pilot Guard:
    Refuse to run in multi-replica mode while SQLite is used on shared storage.
    Prevents silent database page corruption caused by concurrent CIFS writes.
    """
    for env_var in ("MAX_REPLICAS", "CONTAINER_APP_MAX_REPLICAS", "REPLICA_COUNT"):
        val = os.environ.get(env_var)
        if val:
            try:
                if int(val) > 1:
                    raise RuntimeError(
                        f"FATAL CONFIGURATION ERROR: Multi-replica deployment ({env_var}={val}) "
                        "is prohibited when using SQLite over shared storage. "
                        "Set MAX_REPLICAS=1 or migrate to Azure Database for PostgreSQL before scaling horizontally."
                    )
            except ValueError:
                pass
    return True

def verify_database_integrity(db_path=None):
    """Run PRAGMA integrity_check on the database and return (is_healthy, message)."""
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA integrity_check;")
        rows = cur.fetchall()
        result = [r[0] for r in rows]
        is_ok = len(result) == 1 and result[0] == "ok"
        return is_ok, result
    finally:
        conn.close()

def backup_database(destination_path, source_db_path=None):
    """
    Perform a safe online backup of the SQLite database using the SQLite backup API.
    Guarantees consistent, uncorrupted backup snapshots even during active connections.
    """
    src_conn = get_db(source_db_path)
    os.makedirs(os.path.dirname(os.path.abspath(destination_path)), exist_ok=True)
    dst_conn = sqlite3.connect(destination_path)
    try:
        src_conn.backup(dst_conn)
        return True, destination_path
    finally:
        dst_conn.close()
        src_conn.close()

def get_db(db_path=None):
    verify_replica_safety()
    path = db_path or os.environ.get("DB_PATH") or DB_PATH
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    # Remove unsafe nolock=1 assumptions (Finding 6 / Phase 2.E).
    # Standard SQLite connection with WAL mode and busy_timeout provides safe concurrency.
    # nolock is strictly an opt-in fallback via USE_SQLITE_NOLOCK=1 for specialized read-only network shares.
    use_nolock = os.environ.get("USE_SQLITE_NOLOCK", "false").lower() == "true"
    conn = None
    if use_nolock:
        try:
            uri = pathlib.Path(os.path.abspath(path)).as_uri() + "?nolock=1"
            conn = sqlite3.connect(uri, uri=True, timeout=30.0)
        except Exception as ex:
            print(f"[WARN] Failed to open SQLite URI at {path} ({ex}). Trying standard path...")
            conn = sqlite3.connect(path, timeout=30.0)
    else:
        conn = sqlite3.connect(path, timeout=30.0)

    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass
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
                try:
                    cur.executescript(sql_script)
                    cur.execute(
                        "INSERT INTO _migrations (filename, applied_at) VALUES (?, ?)",
                        (mfile, datetime.now(timezone.utc).isoformat())
                    )
                    conn.commit()
                    print(f"[MIGRATION] Successfully applied {mfile}")
                except Exception as mex:
                    print(f"[MIGRATION ERROR] Failed to apply {mfile}: {mex}")

    seed_default_data(conn)
    conn.close()
    print("[DB] Database initialization and seed complete.")

def seed_default_data(conn):
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # 1. Organization
    cur.execute("SELECT id FROM organizations WHERE id = ?", ("org-cloudshield",))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO organizations (id, name, domain, created_at) VALUES (?, ?, ?, ?)",
            ("org-cloudshield", "CloudShield MSSP Platform", "cloudshield-mssp.com", now)
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
        ("role-customer-viewer", "CustomerViewer", "Müşteri Gözlemcisi", "Müşteriye özel salt-okunur rapor ve pano erişimi", 0, 1),
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
        "CustomerViewer": [
            "reports:view", "reports:download", "customers:view"
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
        ("team-edr", "org-cloudshield", "Core-MSSP EDR & XDR Mühendisliği", "Defender Endpoint, Office ve XDR operasyonları ekibi"),
        ("team-compliance", "org-cloudshield", "Veri Güvenliği & Purview Uyum", "DLP, Hassas Veri Sınıflandırma ve İç Tehdit ekibi"),
        ("team-ciso-board", "org-cloudshield", "Müşteri Yönetici Gözetimi (CISO/Board)", "Müşteri CISO ve yönetim kurulu inceleme delegasyonu")
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
    # W8 (Stage 1 Containment): Bootstrap admin is seeded WITHOUT a hard-coded password.
    # No usable password hash is set; credential establishment must go through the governed
    # flow (env PORTAL_ADMIN_PASSWORD / Data/auth.local.json generated by get_admin_credentials(),
    # or Entra ID OIDC in Entra-enforced deployments). Hashing algorithm unchanged.
    cur.execute("SELECT id FROM users WHERE upn = ?", ("admin@cloudshield-mssp.com",))
    if not cur.fetchone():
        cur.execute(
            """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 'Local', ?)""",
            ("usr-admin", "org-cloudshield", "admin@cloudshield-mssp.com", "Platform Administrator",
             "admin@cloudshield-mssp.com", "Siber Güvenlik Çözüm Mimarlığı", None, None, now)
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

    cur.execute("SELECT id FROM access_assignments WHERE id = 'asgn-jit-pilot-caner'")
    if not cur.fetchone():
        jit_to = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        cur.execute(
            """INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                              service_scope, service_id, valid_from, valid_to, is_temporary, is_active, approval_id, created_by, created_at)
               VALUES ('asgn-jit-pilot-caner', 'User', 'usr-001', 'role-security-engineer', 'Specific', 'tenant-002',
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
                    user_email = u.get("Email", upn)
                    if u_existing:
                        if u.get("Email"):
                            cur.execute("UPDATE users SET email = ? WHERE id = ?", (user_email, uid))
                    else:
                        # W8 (Stage 1 Containment): Imported users are seeded passwordless by default.
                        # No hard-coded literal password hash is written. A local password may only be
                        # set through an out-of-band governed provisioning process (non-pilot/dev).
                        cur.execute(
                            """INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                                password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'Local', ?)""",
                            (uid, "org-cloudshield", upn, dname, user_email, dept, None, None, now)
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
                        elif role_str == "CustomerViewer":
                            role_id = "role-customer-viewer"

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
                        elif role_str in ("CustomerCISO", "CustomerViewer"):
                            cur.execute("INSERT OR IGNORE INTO team_memberships (id, team_id, user_id, role_in_team, joined_at) VALUES (?, ?, ?, ?, ?)",
                                        (f"tm-{uid}-ciso", "team-ciso-board", uid, "Executive", now))
        except Exception as e:
            print(f"[WARN] User import error: {e}")

    # 7. Seed Historical Monthly Metrics for tenant-002 (12-month trajectory)
    seed_historical_metrics_data(cur, now)

    # 8. Seed Credential Health for tenant-002
    seed_credential_health_data(cur, now)

    conn.commit()

def seed_historical_metrics_data(cur, now):
    try:
        cur.execute("SELECT COUNT(*) as cnt FROM tenant_historical_metrics WHERE tenant_id = 'tenant-002'")
        row = cur.fetchone()
        if row and row["cnt"] > 0:
            return

        sample_history = [
            ("2026-05", "CONSOLIDATED", 36.2, 142, 5, 28, 86, 4, 78.5, 12.0, 48000.0),
            ("2026-06", "CONSOLIDATED", 38.0, 165, 4, 22, 94, 3, 82.0, 14.5, 58000.0),
            ("2026-07", "CONSOLIDATED", 40.5, 198, 3, 17, 112, 2, 86.4, 16.0, 64000.0),
            ("2026-08", "CONSOLIDATED", 43.0, 215, 2, 12, 128, 2, 89.2, 18.5, 74000.0),
            ("2026-09", "CONSOLIDATED", 45.2, 230, 1, 8, 145, 1, 91.8, 21.0, 84000.0),
            ("2026-10", "CONSOLIDATED", 47.0, 248, 0, 5, 160, 1, 94.0, 22.5, 90000.0),
            ("2026-08", "SVC-MDE", 43.0, 88, 2, 0, 0, 0, 89.2, 8.5, 34000.0),
            ("2026-09", "SVC-MDE", 45.2, 94, 1, 0, 0, 0, 91.8, 9.0, 36000.0),
            ("2026-10", "SVC-MDE", 47.0, 102, 0, 0, 0, 0, 94.0, 10.0, 40000.0),
            ("2026-08", "SVC-MDO", 43.0, 128, 0, 0, 128, 0, 0.0, 6.0, 24000.0),
            ("2026-09", "SVC-MDO", 45.2, 145, 0, 0, 145, 0, 0.0, 7.0, 28000.0),
            ("2026-10", "SVC-MDO", 47.0, 160, 0, 0, 160, 0, 0.0, 7.5, 30000.0),
            ("2026-08", "SVC-PURVIEW", 43.0, 12, 0, 12, 0, 0, 0.0, 4.0, 16000.0),
            ("2026-09", "SVC-PURVIEW", 45.2, 8, 0, 8, 0, 0, 0.0, 5.0, 20000.0),
            ("2026-10", "SVC-PURVIEW", 47.0, 5, 0, 5, 0, 0, 0.0, 5.0, 20000.0),
            ("2026-08", "SVC-INTUNE", 43.0, 0, 0, 0, 0, 0, 89.2, 4.0, 16000.0),
            ("2026-09", "SVC-INTUNE", 45.2, 0, 0, 0, 0, 0, 91.8, 4.5, 18000.0),
            ("2026-10", "SVC-INTUNE", 47.0, 0, 0, 0, 0, 0, 94.0, 5.0, 20000.0)
        ]
        for period, svc, score, thr, crit, dlp, phish, pim, dev_pct, hrs, cost in sample_history:
            cur.execute("""
                INSERT OR REPLACE INTO tenant_historical_metrics 
                (tenant_id, period, service_code, secure_score, threats_blocked, critical_incidents,
                 dlp_violations, phishing_blocked, pim_activations, device_compliance_pct, hours_saved,
                 cost_avoidance_usd, recorded_at, raw_summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "tenant-002", period, svc, score, thr, crit, dlp, phish, pim, dev_pct, hrs, cost, now,
                json.dumps({"period": period, "score": score, "source": "historical_seed"})
            ))
    except Exception as e:
        print(f"[WARN] Error seeding historical metrics: {e}")

def seed_credential_health_data(cur, now):
    try:
        cur.execute("SELECT tenant_id FROM tenant_credential_health WHERE tenant_id = 'tenant-002'")
        if not cur.fetchone():
            cur.execute("""
                INSERT OR REPLACE INTO tenant_credential_health
                (tenant_id, auth_type, secret_expiry_date, cert_expiry_date, last_preflight_check,
                 last_preflight_status, days_until_expiry, health_status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "tenant-002",
                "ClientSecret",
                "2027-04-15T00:00:00Z",
                "2027-09-30T00:00:00Z",
                now,
                "Passed (12/12 Services Authorized)",
                194,
                "Healthy",
                now
            ))
    except Exception as e:
        print(f"[WARN] Error seeding credential health: {e}")

def record_tenant_trend(tenant_id, period, service_code, metrics, raw_json=None, db_path=None):
    """Inserts or updates a monthly metric snapshot for a tenant."""
    conn = get_db(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    try:
        raw_str = json.dumps(raw_json) if raw_json is not None else None
        cur.execute("""
            INSERT OR REPLACE INTO tenant_historical_metrics
            (tenant_id, period, service_code, secure_score, threats_blocked, critical_incidents,
             dlp_violations, phishing_blocked, pim_activations, device_compliance_pct, hours_saved,
             cost_avoidance_usd, recorded_at, raw_summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tenant_id,
            period,
            service_code,
            float(metrics.get("secure_score", 0.0)),
            int(metrics.get("threats_blocked", 0)),
            int(metrics.get("critical_incidents", 0)),
            int(metrics.get("dlp_violations", 0)),
            int(metrics.get("phishing_blocked", 0)),
            int(metrics.get("pim_activations", 0)),
            float(metrics.get("device_compliance_pct", 0.0)),
            float(metrics.get("hours_saved", 0.0)),
            float(metrics.get("cost_avoidance_usd", 0.0)),
            now,
            raw_str
        ))
        conn.commit()
    finally:
        conn.close()

def get_tenant_trends(tenant_id, service_code=None, limit_months=12, db_path=None):
    """Retrieves time-series historical metrics for a tenant ordered chronologically."""
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        if service_code:
            cur.execute("""
                SELECT * FROM tenant_historical_metrics
                WHERE tenant_id = ? AND service_code = ?
                ORDER BY period ASC
                LIMIT ?
            """, (tenant_id, service_code, limit_months))
        else:
            cur.execute("""
                SELECT * FROM tenant_historical_metrics
                WHERE tenant_id = ?
                ORDER BY period ASC
                LIMIT ?
            """, (tenant_id, limit_months))
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def update_tenant_credential_health(tenant_id, auth_type="ClientSecret", secret_expiry=None,
                                    cert_expiry=None, preflight_status="Healthy",
                                    days_left=None, health_status="Healthy", db_path=None):
    """Updates credential expiration health and preflight verification status."""
    conn = get_db(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    try:
        cur.execute("""
            INSERT OR REPLACE INTO tenant_credential_health
            (tenant_id, auth_type, secret_expiry_date, cert_expiry_date, last_preflight_check,
             last_preflight_status, days_until_expiry, health_status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tenant_id,
            auth_type,
            secret_expiry,
            cert_expiry,
            now,
            preflight_status,
            days_left,
            health_status,
            now
        ))
        conn.commit()
    finally:
        conn.close()

def get_tenant_credential_health(tenant_id, db_path=None):
    """Returns the credential expiration and preflight health for a tenant."""
    conn = get_db(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM tenant_credential_health WHERE tenant_id = ?", (tenant_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def sync_customer_to_db(tenant_dict, db_path=None):
    """
    Synchronizes tenant onboarding data from dictionary (tenants.json structure)
    into SQLite relational tables:
    - customers
    - customer_services
    - tenant_credential_health
    - tenant_historical_metrics (seeds baseline snapshot if none exists)
    """
    conn = get_db(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cid = tenant_dict.get("Id") or f"tenant-{secrets.token_hex(3)}"
    t_guid = tenant_dict.get("TenantId", cid)
    c_name = tenant_dict.get("Name", "Unknown Customer")
    c_email = tenant_dict.get("ContactEmail", "security-lead@cloudshield-mssp.com")
    c_mode = tenant_dict.get("ReportMode", "Consolidated")
    c_pkg = tenant_dict.get("SelectedPackage", "PKG-10")
    c_conn = tenant_dict.get("ConnectionStatus", "LiveConnected")
    c_hlth = tenant_dict.get("HealthStatus", "Healthy")
    c_score = float(tenant_dict.get("SecureScore", 45.0))

    try:
        # 1. Upsert into customers
        cur.execute("SELECT id FROM customers WHERE id = ? OR tenant_id = ?", (cid, t_guid))
        crow = cur.fetchone()
        if crow:
            actual_id = crow["id"]
            cur.execute("""
                UPDATE customers SET
                    tenant_id = ?,
                    name = ?,
                    contact_email = ?,
                    report_mode = ?,
                    selected_package = ?,
                    connection_status = ?,
                    health_status = ?,
                    secure_score = ?
                WHERE id = ?
            """, (t_guid, c_name, c_email, c_mode, c_pkg, c_conn, c_hlth, c_score, actual_id))
            cid = actual_id
        else:
            cur.execute("""
                INSERT INTO customers (id, tenant_id, name, contact_email, report_mode, selected_package,
                                       connection_status, health_status, secure_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cid, t_guid, c_name, c_email, c_mode, c_pkg, c_conn, c_hlth, c_score, now))

        # 2. Sync customer_services
        active_svcs = tenant_dict.get("ActiveServices", [])
        sla_tier = tenant_dict.get("ServiceSlaTier", "Gold")
        for asvc in active_svcs:
            cur.execute("SELECT id FROM services WHERE code = ?", (asvc,))
            srow = cur.fetchone()
            if srow:
                svc_id = srow["id"]
                cs_id = f"{cid}_{svc_id}"
                cur.execute("SELECT id FROM customer_services WHERE customer_id = ? AND service_id = ?", (cid, svc_id))
                cs_row = cur.fetchone()
                if cs_row:
                    cur.execute("""
                        UPDATE customer_services SET
                            service_level = ?,
                            status = 'Onboarded',
                            updated_at = ?
                        WHERE id = ?
                    """, (sla_tier, now, cs_row["id"]))
                else:
                    cur.execute("""
                        INSERT INTO customer_services (id, customer_id, service_id, service_level, status, onboarded_at, updated_at)
                        VALUES (?, ?, ?, ?, 'Onboarded', ?, ?)
                    """, (cs_id, cid, svc_id, sla_tier, now, now))

        # 3. Upsert tenant_credential_health
        auth_data = tenant_dict.get("Auth", {}) if isinstance(tenant_dict.get("Auth"), dict) else {}
        auth_method = tenant_dict.get("AuthMethod") or auth_data.get("Method", "Certificate")
        secret_exp = auth_data.get("SecretExpiryDate") or tenant_dict.get("SecretExpiryDate")
        cert_exp = auth_data.get("CertExpiryDate") or tenant_dict.get("CertExpiryDate")

        days_left = None
        target_exp = cert_exp or secret_exp
        if target_exp:
            try:
                exp_clean = str(target_exp).replace("Z", "+00:00")
                if "T" not in exp_clean and len(exp_clean) == 10:
                    exp_clean += "T00:00:00+00:00"
                exp_dt = datetime.fromisoformat(exp_clean)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                days_left = max(0, (exp_dt - datetime.now(timezone.utc)).days)
            except Exception:
                pass

        health_badge = "Healthy"
        if days_left is not None:
            if days_left <= 15:
                health_badge = "Critical"
            elif days_left <= 30:
                health_badge = "Warning"

        cur.execute("""
            INSERT OR REPLACE INTO tenant_credential_health
            (tenant_id, auth_type, secret_expiry_date, cert_expiry_date, last_preflight_check,
             last_preflight_status, days_until_expiry, health_status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cid,
            auth_method,
            secret_exp,
            cert_exp,
            now,
            "Onboarding Preflight Verified",
            days_left,
            health_badge,
            now
        ))

        # 4. Seed baseline monthly snapshot in tenant_historical_metrics if none exists
        period_now = datetime.now(timezone.utc).strftime("%Y-%m")
        cur.execute("SELECT COUNT(*) as cnt FROM tenant_historical_metrics WHERE tenant_id = ?", (cid,))
        cnt_row = cur.fetchone()
        if not cnt_row or cnt_row["cnt"] == 0:
            cur.execute("""
                INSERT OR REPLACE INTO tenant_historical_metrics
                (tenant_id, period, service_code, secure_score, threats_blocked, critical_incidents,
                 dlp_violations, phishing_blocked, pim_activations, device_compliance_pct, hours_saved,
                 cost_avoidance_usd, recorded_at, raw_summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cid, period_now, "CONSOLIDATED", c_score, 0, 0, 0, 0, 0, 100.0, 0.0, 0.0, now,
                json.dumps({"period": period_now, "score": c_score, "source": "onboarding_baseline"})
            ))

        conn.commit()
        return True
    except Exception as ex:
        print(f"[DB ERROR] sync_customer_to_db failed for {cid}: {ex}")
        conn.rollback()
        return False
    finally:
        conn.close()

def create_customer_portal_user(customer_id, display_name, email, role="CustomerCISO", password=None, db_path=None):
    """
    Provisions a customer-scoped self-service portal user (CustomerCISO or CustomerViewer)
    and binds access assignment directly to the customer_id.
    """
    conn = get_db(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    clean_email = email.strip().lower()
    uid = f"usr-{secrets.token_hex(4)}"

    role_id = "role-customer-ciso" if role == "CustomerCISO" else "role-customer-viewer"

    try:
        # Check if user already exists
        cur.execute("SELECT id FROM users WHERE LOWER(upn) = ? OR LOWER(email) = ?", (clean_email, clean_email))
        existing = cur.fetchone()
        if existing:
            user_id = existing["id"]
        else:
            user_id = uid
            pwd_hash = None
            pwd_salt = None
            if password:
                pwd_hash, pwd_salt = hash_password(password)
            cur.execute("""
                INSERT INTO users (id, organization_id, upn, display_name, email, department,
                                   password_hash, password_salt, is_active, is_mfa_enabled, auth_provider, created_at)
                VALUES (?, 'org-cloudshield', ?, ?, ?, 'Müşteri Bilgi Güvenliği', ?, ?, 1, 0, 'Local', ?)
            """, (user_id, clean_email, display_name, clean_email, pwd_hash, pwd_salt, now))

        # Assign role to this customer
        asgn_id = f"asgn-{user_id}-{customer_id}"
        cur.execute("""
            INSERT OR REPLACE INTO access_assignments
            (id, subject_type, subject_id, role_id, customer_scope, customer_id,
             service_scope, service_id, valid_from, is_temporary, is_active, created_by, created_at)
            VALUES (?, 'User', ?, ?, 'Specific', ?, 'ALL', NULL, ?, 0, 1, 'system_onboarding', ?)
        """, (asgn_id, user_id, role_id, customer_id, now, now))

        # Membership in team-ciso-board
        cur.execute("""
            INSERT OR IGNORE INTO team_memberships (id, team_id, user_id, role_in_team, joined_at)
            VALUES (?, 'team-ciso-board', ?, 'Executive', ?)
        """, (f"tm-{user_id}-ciso", user_id, now))

        conn.commit()
        return {"userId": user_id, "email": clean_email, "role": role, "customerId": customer_id}
    except Exception as ex:
        print(f"[DB ERROR] create_customer_portal_user failed: {ex}")
        conn.rollback()
        return None
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
