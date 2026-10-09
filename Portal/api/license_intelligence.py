# CloudShield License Intelligence & Security Value Realization Engine
# Analyzes Entitlement -> Assignment -> Service Plan -> Configuration -> Telemetry across 15 workloads
# Strictly enforces persona auditing, duplicate detection, add-on prerequisites, and Zero Fake Financial ROI.

import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("CloudShield.LicenseIntelligence")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CATALOG_PATH = os.path.join(ROOT_DIR, "config", "catalog", "license-catalog.json")

def load_license_catalog():
    """Loads the official Microsoft license catalog."""
    if os.path.exists(CATALOG_PATH):
        try:
            with open(CATALOG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as ex:
            logger.error(f"Failed to read license catalog: {ex}")
    return {"skus": {}, "rules": {}}

# Pre-defined SKU Part Numbers for quick reference
SKU_M365_E5 = "SPE_E5"
SKU_M365_E3 = "SPE_E3"
SKU_E5_SEC = "SPE_E5_SEC"
SKU_E5_COMP = "SPE_E5_COMP"
SKU_M365_BUS_PREM = "SPB"
SKU_M365_BUS_STD = "SMB_BUSINESS_STD"
SKU_M365_BUS_BASIC = "SMB_BUSINESS_BASIC"
SKU_O365_E3 = "ENTERPRISEPACK"
SKU_O365_E5 = "ENTERPRISEPREMIUM"
SKU_EMS_E3 = "EMS"
SKU_EMS_E5 = "EMSPREMIUM"
SKU_M365_F1 = "DESKLESSPACK"
SKU_M365_F3 = "DESKLESSCOMMUNICATION"
SKU_COPILOT = "COPILOT_M365"

# 14 Canonical Realization Statuses
STATUS_FULL_VALUE = "Tam Değer Gerçekleştirildi"
STATUS_LICENSED_ACTIVE_TELEMETRY = "Lisanslı ve Aktif, Telemetri Doğrulandı"
STATUS_LICENSED_POLICY_WAITING = "Lisanslı, İlke Aktif, Telemetri Bekleniyor"
STATUS_LICENSE_CONFIG_MISSING = "Lisans Var, İlke veya Konfigürasyon Eksik"
STATUS_LICENSE_PLAN_DISABLED = "Lisans Var, Service Plan Devre Dışı"
STATUS_LICENSE_UNASSIGNED = "Lisans Var, Kullanıcıya Atanmamış"
STATUS_ASSIGNED_IDLE = "Atanmış Lisans Boşta"
STATUS_DUPLICATE_ENTITLEMENT = "Mükerrer veya Çakışan Lisans Hakkı"
STATUS_MISSING_PREREQUISITE = "Eksik Ön Koşul Lisansı"
STATUS_UNCOVERED_PROTECTION_GAP = "Kapsam Dışı Kullanıcı Koruması"
STATUS_LICENSE_SHORTAGE_CAP = "Lisans Yetersizliği / Aşımı"
STATUS_AZURE_CONSUMPTION_VERIFIED = "Azure Tüketim Modeli Doğrulandı"
STATUS_PENDING_LIVE_VALIDATION = "Canlı Doğrulama Bekliyor"
STATUS_SYNTHETIC_TEST_ONLY = "Yalnızca Test / Simülasyon Verisi"

CANONICAL_STATUSES = [
    STATUS_FULL_VALUE,
    STATUS_LICENSED_ACTIVE_TELEMETRY,
    STATUS_LICENSED_POLICY_WAITING,
    STATUS_LICENSE_CONFIG_MISSING,
    STATUS_LICENSE_PLAN_DISABLED,
    STATUS_LICENSE_UNASSIGNED,
    STATUS_ASSIGNED_IDLE,
    STATUS_DUPLICATE_ENTITLEMENT,
    STATUS_MISSING_PREREQUISITE,
    STATUS_UNCOVERED_PROTECTION_GAP,
    STATUS_LICENSE_SHORTAGE_CAP,
    STATUS_AZURE_CONSUMPTION_VERIFIED,
    STATUS_PENDING_LIVE_VALIDATION,
    STATUS_SYNTHETIC_TEST_ONLY
]

# 15 Supported Workloads
WORKLOADS_DEF = [
    {"code": "MDE", "name": "Microsoft Defender for Endpoint", "category": "Endpoint", "is_azure_resource": False},
    {"code": "MDO", "name": "Microsoft Defender for Office 365", "category": "Email & Collab", "is_azure_resource": False},
    {"code": "MDI", "name": "Microsoft Defender for Identity", "category": "Identity", "is_azure_resource": False},
    {"code": "MDCA", "name": "Microsoft Defender for Cloud Apps", "category": "Cloud App Security", "is_azure_resource": False},
    {"code": "MDC", "name": "Microsoft Defender for Cloud", "category": "Cloud Security", "is_azure_resource": True},
    {"code": "INTUNE", "name": "Microsoft Intune", "category": "Endpoint & MDM", "is_azure_resource": False},
    {"code": "PURVIEW_MIP", "name": "Microsoft Purview Information Protection", "category": "Data Security", "is_azure_resource": False},
    {"code": "PURVIEW_SIT", "name": "Microsoft Purview Sensitive Information Types", "category": "Data Security", "is_azure_resource": False},
    {"code": "PURVIEW_DLP", "name": "Microsoft Purview Data Loss Prevention", "category": "Data Security", "is_azure_resource": False},
    {"code": "PURVIEW_IRM", "name": "Microsoft Purview Insider Risk Management", "category": "Risk Management", "is_azure_resource": False},
    {"code": "PURVIEW_COMM", "name": "Microsoft Purview Communication Compliance", "category": "Compliance", "is_azure_resource": False},
    {"code": "PURVIEW_DLM", "name": "Microsoft Purview Data Lifecycle Management", "category": "Compliance", "is_azure_resource": False},
    {"code": "PURVIEW_RECORDS", "name": "Microsoft Purview Records Management", "category": "Compliance", "is_azure_resource": False},
    {"code": "PURVIEW_DSPM", "name": "Microsoft Purview Data Security Posture Management", "category": "Data Security", "is_azure_resource": False},
    {"code": "PURVIEW_DSPM_AI", "name": "Microsoft Purview DSPM for AI", "category": "AI Security", "is_azure_resource": False}
]

def _norm_text(s):
    if not s:
        return ""
    return str(s).replace("İ", "i").replace("I", "ı").lower()

def classify_user_persona(user_dict, admin_roles=None):
    """
    Classifies a user into one of the canonical enterprise personas:
    - Executive (C-Level, Yönetim Kurulu)
    - Sec / IT Admin (Yönetici Rolleri)
    - Finance / Sensitive Data (Finans, Mali İşler)
    - HR / PII (İnsan Kaynakları)
    - Dev / DevOps (Yazılım, Sistem Mühendisi)
    - Frontline (Saha, Vardiyalı Operasyon)
    - Guest (Harici Konuk Kullanıcı)
    - Service Account (Etkileşimsiz Servis Hesabı)
    - Shared Mailbox (Paylaşılan Posta Kutusu)
    - Inactive User (Devre Dışı / Pasif Kullanıcı)
    - Standard Knowledge Worker (Standart Bilgi Çalışanı)
    """
    admin_roles = admin_roles or []
    upn = _norm_text(user_dict.get("userPrincipalName"))
    display_name = _norm_text(user_dict.get("displayName"))
    job_title = _norm_text(user_dict.get("jobTitle"))
    department = _norm_text(user_dict.get("department"))
    account_enabled = user_dict.get("accountEnabled", True)
    user_type = user_dict.get("userType", "Member")

    # Inactive check
    if not account_enabled:
        return "Inactive User"

    # Guest check
    if user_type == "Guest" or "#ext#" in upn:
        return "Guest"

    # Service Account check
    svc_markers = ["svc_", "service_", "app_", "daemon_", "system_", "backup_", "scanner_"]
    if any(m in upn for m in svc_markers) or "servis hesabı" in display_name:
        return "Service Account"

    # Shared Mailbox check
    shared_markers = ["shared_", "ortak_", "info@", "ik@", "finans@", "destek@", "support@", "sales@"]
    if any(m in upn for m in shared_markers) or "shared mailbox" in display_name:
        return "Shared Mailbox"

    # Sec / IT Admin check
    admin_role_keywords = ["global administrator", "security administrator", "intune administrator", "compliance administrator"]
    if any(r.lower() in admin_role_keywords for r in admin_roles):
        return "Sec / IT Admin"
    if any(k in job_title for k in ["admin", "yönetici", "system administrator", "security engineer", "it lead"]):
        return "Sec / IT Admin"

    # Executive check
    exec_keywords = ["ciso", "cio", "ceo", "cfo", "cto", "coo", "director", "direktör", "genel müdür", "başkan", "president", "vice president", "executive"]
    if any(k in job_title for k in exec_keywords) or any(k in department for k in ["yönetim kurulu", "executive board", "genel müdürlük"]):
        return "Executive"

    # Finance / Sensitive Data check
    finance_keywords = ["finans", "finance", "muhasebe", "accounting", "mali", "treasury", "bütçe", "audit", "denetim"]
    if any(k in job_title for k in finance_keywords) or any(k in department for k in finance_keywords):
        return "Finance / Sensitive Data"

    # HR / PII check
    hr_keywords = ["insan kaynakları", "human resources", "hr", "özlük", "bordro", "recruitment", "talent"]
    if any(k in job_title for k in hr_keywords) or any(k in department for k in hr_keywords):
        return "HR / PII"

    # Dev / DevOps check
    dev_keywords = ["software", "yazılım", "developer", "geliştirici", "devops", "engineer", "mühendis", "architect", "data science"]
    if any(k in job_title for k in dev_keywords) or any(k in department for k in dev_keywords):
        return "Dev / DevOps"

    # Frontline check
    frontline_keywords = ["saha", "frontline", "vardiya", "kasiyer", "depo", "operatör", "teknisyen", "mağaza", "store"]
    if any(k in job_title for k in frontline_keywords) or any(k in department for k in frontline_keywords):
        return "Frontline"

    return "Standard Knowledge Worker"

def analyze_user_license_entitlements(user_profile, catalog=None):
    """
    Analyzes a user's assigned licenses against catalog rules:
    - Inspects licenseAssignmentStates for group vs direct assignment, disabled plans, and assignment errors
    - Delineates SKU entitlement vs service plan enablement
    - Detects duplicate/overlapping SKUs
    - Detects add-on prerequisite violations
    - Detects licensed inactive accounts
    Returns (status_label, risk_indicators, recommendations) with calibrated advisory phrasing.
    """
    catalog = catalog or load_license_catalog()
    skus = user_profile.get("assigned_skus", [])
    plans = user_profile.get("assigned_plans", [])
    account_enabled = user_profile.get("account_enabled", True)
    persona = user_profile.get("persona_type", "Standard Knowledge Worker")
    upn = user_profile.get("user_principal_name", "")
    license_states = user_profile.get("license_assignment_states") or user_profile.get("licenseAssignmentStates") or []

    risk_indicators = []
    recommendations = []
    value_status = "Normal"

    # 1. Inactive user with licenses
    if not account_enabled and len(skus) > 0:
        value_status = STATUS_ASSIGNED_IDLE
        risk_indicators.append(f"Pasif kullanıcı hesabında {len(skus)} adet lisans atanmış duruyor (Atıl Lisans Riski).")
        recommendations.append("Pasif durumdaki hesaba atanmış lisansların geri kazanılarak (license reclaim) aktif kullanıcı havuzuna aktarılması veya bir sonraki sözleşme döneminde optimize edilmesi tavsiye edilir.")
        return value_status, risk_indicators, recommendations

    # 2. Duplicate / Overlapping Entitlement Check
    sku_parts = [s.get("sku_part_number") for s in skus if isinstance(s, dict)]

    # Rule: E5 supersedes E3
    if SKU_M365_E5 in sku_parts and SKU_M365_E3 in sku_parts:
        value_status = STATUS_DUPLICATE_ENTITLEMENT
        risk_indicators.append("Mükerrer Lisans: Microsoft 365 E5 ve Microsoft 365 E3 aynı kullanıcıya atanmış.")
        recommendations.append("M365 E5 paketi tüm E3 yeteneklerini kapsadığından, mükerrer atanan M365 E3 koltuğunun optimizasyon amacıyla incelenmesi ve boşa çıkarılması değerlendirilebilir.")

    # Rule: E5 already includes E5 Security
    if SKU_M365_E5 in sku_parts and SKU_E5_SEC in sku_parts:
        value_status = STATUS_DUPLICATE_ENTITLEMENT
        risk_indicators.append("Mükerrer Lisans: Microsoft 365 E5 paketi E5 Security yeteneklerini zaten içerir, bağımsız E5 Security add-on gereksizdir.")
        recommendations.append("M365 E5 paketi E5 Security yeteneklerini zaten barındırmaktadır; bağımsız SPE_E5_SEC eklentisinin boşa çıkarılarak lisans havuzuna iadesi değerlendirilmelidir.")

    # Rule: E5 already includes E5 Compliance
    if SKU_M365_E5 in sku_parts and SKU_E5_COMP in sku_parts:
        value_status = STATUS_DUPLICATE_ENTITLEMENT
        risk_indicators.append("Mükerrer Lisans: Microsoft 365 E5 paketi E5 Compliance yeteneklerini zaten içerir, bağımsız E5 Compliance add-on gereksizdir.")
        recommendations.append("M365 E5 paketi E5 Compliance yeteneklerini zaten barındırmaktadır; bağımsız SPE_E5_COMP eklentisinin boşa çıkarılarak lisans havuzuna iadesi değerlendirilmelidir.")

    # Rule: Business Premium supersedes Business Standard
    if SKU_M365_BUS_PREM in sku_parts and SKU_M365_BUS_STD in sku_parts:
        value_status = STATUS_DUPLICATE_ENTITLEMENT
        risk_indicators.append("Mükerrer Lisans: Business Premium ve Business Standard bir arada atanmış.")
        recommendations.append("Business Premium paketi Business Standard yeteneklerini kapsadığından, mükerrer Business Standard lisansının optimizasyon amacıyla boşa çıkarılması tavsiye edilir.")

    # Rule: O365 E3 + M365 E3 overlap
    if SKU_O365_E3 in sku_parts and SKU_M365_E3 in sku_parts:
        value_status = STATUS_DUPLICATE_ENTITLEMENT
        risk_indicators.append("Mükerrer Lisans: Office 365 E3 ve Microsoft 365 E3 üst üste atanmış.")
        recommendations.append("M365 E3 kurumsal paketi O365 E3 yeteneklerini içerdiğinden, örtüşen Office 365 E3 atamasının gözden geçirilerek optimize edilmesi önerilir.")

    # 3. Add-on Prerequisite Validation (only if not already flagged as duplicate E5 superset)
    # Rule: E5 Security requires M365 E3 or (O365 E3 + EMS E3) or Business Premium
    if SKU_E5_SEC in sku_parts and SKU_M365_E5 not in sku_parts:
        has_qualifying_base = (
            SKU_M365_E3 in sku_parts or
            (SKU_O365_E3 in sku_parts and SKU_EMS_E3 in sku_parts) or
            SKU_M365_BUS_PREM in sku_parts
        )
        if not has_qualifying_base:
            value_status = STATUS_MISSING_PREREQUISITE
            risk_indicators.append("Ön Koşul Hatası: Microsoft 365 E5 Security add-on'u için geçerli bir temel lisans (M365 E3 / Business Premium) atanmamış.")
            recommendations.append("Kullanıcıya uygun temel plan tanımlanması veya eklentinin temel lisansı olan bir kullanıcıya aktarılması önerilir.")

    # Rule: E5 Compliance requires M365 E3 or (O365 E3 + EMS E3)
    if SKU_E5_COMP in sku_parts and SKU_M365_E5 not in sku_parts:
        has_qualifying_base = (
            SKU_M365_E3 in sku_parts or
            (SKU_O365_E3 in sku_parts and SKU_EMS_E3 in sku_parts)
        )
        if not has_qualifying_base:
            value_status = STATUS_MISSING_PREREQUISITE
            risk_indicators.append("Ön Koşul Hatası: Microsoft 365 E5 Compliance add-on'u için temel M365 E3 lisansı eksik.")
            recommendations.append("Kullanıcıya geçerli temel M365 E3 lisansının tanımlanması veya eklenti atamasının düzeltilmesi tavsiye edilir.")

    # Rule: Copilot requires qualifying base
    if SKU_COPILOT in sku_parts:
        qualifying = [SKU_M365_E5, SKU_M365_E3, SKU_M365_BUS_PREM, SKU_M365_BUS_STD, SKU_O365_E3, SKU_O365_E5]
        if not any(q in sku_parts for q in qualifying):
            value_status = STATUS_MISSING_PREREQUISITE
            risk_indicators.append("Ön Koşul Hatası: Microsoft 365 Copilot için yetkili temel üretkenlik lisansı bulunamadı.")
            recommendations.append("Copilot kullanıcı deneyiminin sağlanabilmesi için desteklenen temel üretkenlik lisansının tanımlanması tavsiye edilir.")

    # 4. Service Account with Interactive User License
    if persona == "Service Account" and any(s in [SKU_M365_E5, SKU_M365_E3, SKU_M365_BUS_PREM] for s in sku_parts):
        risk_indicators.append("Optimizasyon Fırsatı: Etkileşimsiz Servis Hesabına tam kurumsal kullanıcı lisansı atanmış.")
        recommendations.append("Servis hesabı için Entra Workload Identity veya lisanssız hizmet hesabı modeline geçiş yapılarak koltuğun boşa çıkarılması değerlendirilebilir.")

    # 5. Persona Alignment Recommendations (Calibrated Advisory)
    if persona == "Executive" and not any(s in [SKU_M365_E5, SKU_E5_SEC, SKU_M365_BUS_PREM] for s in sku_parts):
        risk_indicators.append("Güvenlik Riski: Üst düzey yönetici (Executive) hesabında gelişmiş XDR ve Defender Plan 2 koruması eksik.")
        recommendations.append("Yönetici profili için gelişmiş kimlik koruması ve XDR duruşunun (M365 E5 veya E5 Security) güçlendirilmesi tavsiye edilir.")

    if persona in ["Finance / Sensitive Data", "HR / PII"] and not any(s in [SKU_M365_E5, SKU_E5_COMP] for s in sku_parts):
        risk_indicators.append(f"Uyum Riski: {persona} kullanıcısında otomatik etiketleme, EDM ve gelişmiş Purview DLP kapsamı eksik.")
        recommendations.append(f"Hassas veri işleyen bu rol için Purview gelişmiş uyum (E5 Compliance) kapsamının değerlendirilmesi tavsiye edilir.")

    # 6. licenseAssignmentStates Detailed Inspection (Group vs Direct, Disabled Plans, Provisioning Errors)
    if license_states:
        has_group = any(bool(ls.get("assignedByGroup")) for ls in license_states if isinstance(ls, dict))
        is_direct = any(not ls.get("assignedByGroup") for ls in license_states if isinstance(ls, dict))
        if is_direct and not has_group:
            recommendations.append("Doğrudan Lisans Ataması Tespiti: Yönetim sürdürülebilirliği açısından Entra ID Dinamik Grup Tabanlı Lisanslama (GBL) modeli değerlendirilebilir.")

        # Check explicit disabled plans in licenseAssignmentStates
        explicit_disabled = []
        for ls in license_states:
            if isinstance(ls, dict):
                for dp in ls.get("disabledPlans", []):
                    explicit_disabled.append(dp)
        if explicit_disabled:
            risk_indicators.append(f"Servis Planı Ayrımı: Kullanıcıya atanmış SKU içinde {len(explicit_disabled)} servis planı devre dışı bırakılmış.")
            recommendations.append("Devre dışı bırakılan servis planlarının operasyonel ihtiyaca uygunluğu ve güvenlik kapsamına etkisi teyit edilmelidir.")

        # Check assignment state errors
        for ls in license_states:
            if isinstance(ls, dict):
                err = ls.get("error")
                if err and err != "None":
                    risk_indicators.append(f"Lisans Sağlama Hatası Tespiti: {err}")
                    recommendations.append(f"Entra ID lisans sağlama hatasının ({err}) giderilmesi için dizin ataması incelenmelidir.")

    if not risk_indicators:
        value_status = "Tam Değer Gerçekleştirildi"

    return value_status, risk_indicators, recommendations

def reconcile_workload_5_layers(workload_code, tenant_licenses, user_profiles, telemetry_data=None):
    """
    Executes the 5-Layer Reconciliation for a specific workload:
    Layer 1: Entitlement (Purchased seats)
    Layer 2: Assignment (Assigned seats)
    Layer 3: Service Plan Active (Plan enabled in tenant)
    Layer 4: Configuration & Policy Coverage (Policies target users/devices)
    Layer 5: Evidence & Telemetry (Active events, alerts, device count, mailboxes)
    Returns dictionary with counts, canonical status, and gap explanation.
    """
    telemetry_data = telemetry_data or {}
    w_info = next((w for w in WORKLOADS_DEF if w["code"] == workload_code), None)
    if not w_info:
        return None

    # Handle Azure Resource Based workloads (Defender for Servers, Containers, Storage, SQL, CSPM)
    if w_info.get("is_azure_resource"):
        azure_data = telemetry_data.get("azure_resources", {})
        active_resources = azure_data.get("protected_resources_count", 0)
        has_subscription = azure_data.get("subscription_active", False)

        if has_subscription and active_resources > 0:
            return {
                "workload_code": workload_code,
                "workload_name": w_info["name"],
                "category": w_info["category"],
                "is_azure_resource": True,
                "entitlement_count": active_resources,
                "assignment_count": active_resources,
                "service_plan_active_count": active_resources,
                "configuration_active_count": active_resources,
                "telemetry_active_count": active_resources,
                "realization_status": STATUS_AZURE_CONSUMPTION_VERIFIED,
                "gap_description": "Azure abonelik tüketim modeli üzerinden doğrulanmış koruma (Kullanıcı lisansı gerektirmez; sunucu, konteyner ve depolama kaynakları korunmaktadır)."
            }
        else:
            return {
                "workload_code": workload_code,
                "workload_name": w_info["name"],
                "category": w_info["category"],
                "is_azure_resource": True,
                "entitlement_count": 0,
                "assignment_count": 0,
                "service_plan_active_count": 0,
                "configuration_active_count": 0,
                "telemetry_active_count": 0,
                "realization_status": STATUS_LICENSE_CONFIG_MISSING,
                "gap_description": "Defender for Cloud koruması için Azure aboneliği veya plan konfigürasyonu tespit edilmedi."
            }

    # User SKU Based Workload
    # 1. Entitlement
    entitlement_count = 0
    workload_service_plans = get_service_plans_for_workload(workload_code)
    for lic in tenant_licenses:
        # Check if license covers workload
        sku_part = lic.get("sku_part_number", "")
        if sku_covers_workload(sku_part, workload_code):
            entitlement_count += int(lic.get("prepaid_units", 0))

    # 2. Assignment
    assignment_count = 0
    for u in user_profiles:
        u_skus = [s.get("sku_part_number") for s in u.get("assigned_skus", []) if isinstance(s, dict)]
        if any(sku_covers_workload(sp, workload_code) for sp in u_skus):
            assignment_count += 1

    # 3. Service Plan Active (Service Plan Distinction vs SKU Assignment)
    service_plan_active_count = 0
    for u in user_profiles:
        u_skus = [s.get("sku_part_number") for s in u.get("assigned_skus", []) if isinstance(s, dict)]
        if any(sku_covers_workload(sp, workload_code) for sp in u_skus):
            # Check if any required plan is disabled in assigned_plans or licenseAssignmentStates.disabledPlans
            plans = u.get("assigned_plans", [])
            license_states = u.get("license_assignment_states") or u.get("licenseAssignmentStates") or []

            # Extract disabled plan IDs from licenseAssignmentStates
            explicit_disabled_guids = []
            for ls in license_states:
                if isinstance(ls, dict):
                    explicit_disabled_guids.extend(ls.get("disabledPlans", []))

            has_active_plan = True
            matched_plans = [p for p in plans if p.get("servicePlanName") in workload_service_plans]
            if matched_plans:
                for p in matched_plans:
                    p_id = p.get("servicePlanId")
                    if p.get("provisioningStatus") not in ["Success", "Active"] or (p_id and p_id in explicit_disabled_guids):
                        has_active_plan = False
                        break
            elif explicit_disabled_guids:
                has_active_plan = False

            if has_active_plan:
                service_plan_active_count += 1

    # 4. Configuration & Policy Coverage
    # Check policies from telemetry_data
    policy_coverage = telemetry_data.get("policy_coverage", {}).get(workload_code, {})
    config_count = policy_coverage.get("targeted_users_count", min(service_plan_active_count, assignment_count))
    policy_active = policy_coverage.get("policy_active", True)

    # 5. Evidence & Telemetry
    telemetry_stats = telemetry_data.get("telemetry_stats", {}).get(workload_code, {})
    telemetry_count = telemetry_stats.get("evidence_count", 0)
    telemetry_verified = telemetry_stats.get("verified", False)

    # Determine Canonical Realization Status
    if entitlement_count == 0:
        realization_status = STATUS_LICENSE_CONFIG_MISSING
        gap = "Bu iş yükünü kapsayan aktif Microsoft lisansı satın alınmamış."
    elif assignment_count == 0:
        realization_status = STATUS_LICENSE_UNASSIGNED
        gap = f"{entitlement_count} adet lisans satın alınmış fakat kullanıcılara atanmamış."
    elif service_plan_active_count < assignment_count:
        realization_status = STATUS_LICENSE_PLAN_DISABLED
        gap = f"{assignment_count - service_plan_active_count} kullanıcıda ilgili servis planı devre dışı bırakılmış veya sağlama hatasında."
    elif not policy_active or config_count == 0:
        realization_status = STATUS_LICENSE_CONFIG_MISSING
        gap = "Lisans atanmış ancak iş yükünü aktifleştiren ilke (Policy) yapılandırılmamış veya hedef kullanıcılar seçilmemiş."
    elif not telemetry_verified:
        realization_status = STATUS_LICENSED_POLICY_WAITING
        gap = "Lisans ve ilkeler aktif; iş yükünden henüz operasyonel telemetri veya olay sinyali bekleniyor."
    else:
        realization_status = STATUS_FULL_VALUE
        gap = "Lisans hakkı, kullanıcı ataması, servis planı, ilke kapsamı ve canlı telemetri kanıtı uçtan uca doğrulanmıştır."

    return {
        "workload_code": workload_code,
        "workload_name": w_info["name"],
        "category": w_info["category"],
        "is_azure_resource": False,
        "entitlement_count": entitlement_count,
        "assignment_count": assignment_count,
        "service_plan_active_count": service_plan_active_count,
        "configuration_active_count": config_count,
        "telemetry_active_count": telemetry_count,
        "realization_status": realization_status,
        "gap_description": gap
    }

def sku_covers_workload(sku_part, workload_code):
    """Determines whether a given SKU part number provides entitlement for a workload."""
    sku_part = (sku_part or "").upper()
    coverage_map = {
        "MDE": [SKU_M365_E5, SKU_M365_E3, SKU_E5_SEC, SKU_M365_BUS_PREM],
        "MDO": [SKU_M365_E5, SKU_M365_E3, SKU_E5_SEC, SKU_M365_BUS_PREM, SKU_O365_E5],
        "MDI": [SKU_M365_E5, SKU_E5_SEC],
        "MDCA": [SKU_M365_E5, SKU_E5_SEC, SKU_M365_BUS_PREM],
        "INTUNE": [SKU_M365_E5, SKU_M365_E3, SKU_M365_BUS_PREM, SKU_EMS_E3, SKU_EMS_E5, SKU_M365_F1, SKU_M365_F3],
        "PURVIEW_MIP": [SKU_M365_E5, SKU_M365_E3, SKU_E5_COMP, SKU_M365_BUS_PREM, SKU_EMS_E3, SKU_EMS_E5],
        "PURVIEW_SIT": [SKU_M365_E5, SKU_M365_E3, SKU_E5_COMP, SKU_M365_BUS_PREM],
        "PURVIEW_DLP": [SKU_M365_E5, SKU_M365_E3, SKU_E5_COMP, SKU_M365_BUS_PREM, SKU_O365_E3, SKU_O365_E5],
        "PURVIEW_IRM": [SKU_M365_E5, SKU_E5_COMP],
        "PURVIEW_COMM": [SKU_M365_E5, SKU_E5_COMP],
        "PURVIEW_DLM": [SKU_M365_E5, SKU_M365_E3, SKU_E5_COMP, SKU_O365_E3, SKU_O365_E5],
        "PURVIEW_RECORDS": [SKU_M365_E5, SKU_E5_COMP],
        "PURVIEW_DSPM": [SKU_M365_E5, SKU_E5_COMP],
        "PURVIEW_DSPM_AI": [SKU_M365_E5, SKU_E5_COMP]
    }
    allowed = coverage_map.get(workload_code, [])
    return sku_part in allowed

def get_service_plans_for_workload(workload_code):
    """Returns canonical service plan names associated with a workload."""
    plans = {
        "MDE": ["WINDEFATP", "MDESIGNAL"],
        "MDO": ["ATP_ENTERPRISE", "SAFEDOCS"],
        "MDI": ["THREAT_DEFENDER"],
        "MDCA": ["ADALLOM_S_STANDALONE", "ADALLOM_S_DISCOVERY"],
        "INTUNE": ["INTUNE_A", "INTUNE_O365"],
        "PURVIEW_MIP": ["RMS_S_ENTERPRISE", "MIPC"],
        "PURVIEW_SIT": ["EQUIVIO_ANALYTICS", "MIPC"],
        "PURVIEW_DLP": ["MIPC", "EXCHANGE_S_ENTERPRISE"],
        "PURVIEW_IRM": ["MIPC", "EQUIVIO_ANALYTICS"],
        "PURVIEW_COMM": ["EXCHANGE_S_ENTERPRISE", "EQUIVIO_ANALYTICS"],
        "PURVIEW_DLM": ["EXCHANGE_S_ENTERPRISE", "SHAREPOINTENTERPRISE"],
        "PURVIEW_RECORDS": ["EQUIVIO_ANALYTICS", "SHAREPOINTENTERPRISE"],
        "PURVIEW_DSPM": ["MIPC"],
        "PURVIEW_DSPM_AI": ["MIPC"]
    }
    return plans.get(workload_code, [])

def check_smb_user_cap(tenant_licenses):
    """
    Checks if the organization exceeds the hard 300-user limit on SMB Business SKUs.
    Returns (exceeded, total_smb_units, message)
    """
    smb_skus = [SKU_M365_BUS_PREM, SKU_M365_BUS_STD, SKU_M365_BUS_BASIC]
    total_smb = 0
    for lic in tenant_licenses:
        if lic.get("sku_part_number") in smb_skus:
            total_smb += int(lic.get("consumed_units", 0))

    if total_smb > 300:
        return True, total_smb, f"KOBİ Lisans Tavanı Aşıldı: Tenant genelinde toplam {total_smb} KOBİ lisansı tüketilmektedir (Maksimum sınır: 300). Enterprise (M365 E3/E5) planlarına geçiş gereklidir."
    return False, total_smb, f"KOBİ Lisans Sınırı Normal: {total_smb}/300 kullanıcı."

def compute_overall_value_index(reconciliations, user_summaries):
    """
    Computes holistic Value Realization Score (0-100%) based strictly on:
    - Workloads with Full Value or Verified Telemetry
    - Absence of duplicate entitlements
    - Absence of licensed inactive users
    - Zero fake financial ROI: strictly posture & optimization metric.
    """
    if not reconciliations:
        return 0.0

    workload_points = 0
    max_workload_points = len(reconciliations) * 10

    for r in reconciliations:
        st = r.get("realization_status")
        if st in [STATUS_FULL_VALUE, STATUS_AZURE_CONSUMPTION_VERIFIED]:
            workload_points += 10
        elif st == STATUS_LICENSED_ACTIVE_TELEMETRY:
            workload_points += 8
        elif st == STATUS_LICENSED_POLICY_WAITING:
            workload_points += 6
        elif st in [STATUS_LICENSE_CONFIG_MISSING, STATUS_LICENSE_PLAN_DISABLED]:
            workload_points += 3
        else:
            workload_points += 0

    base_score = (workload_points / max_workload_points) * 100.0 if max_workload_points > 0 else 0.0

    # Penalties for hygiene issues
    penalty = 0.0
    duplicates = user_summaries.get("duplicate_count", 0)
    inactive_licensed = user_summaries.get("inactive_licensed_count", 0)
    missing_prereqs = user_summaries.get("missing_prereq_count", 0)

    if duplicates > 0:
        penalty += min(15.0, duplicates * 3.0)
    if inactive_licensed > 0:
        penalty += min(15.0, inactive_licensed * 2.0)
    if missing_prereqs > 0:
        penalty += min(10.0, missing_prereqs * 4.0)

    final_index = max(0.0, min(100.0, base_score - penalty))
    return round(final_index, 1)

def compare_license_snapshots(prev_snapshot, curr_snapshot):
    """
    Compares two monthly license intelligence snapshots to generate a diff:
    - Delta in total licenses, consumed, idle
    - Delta in overall value realization index
    - Resolved duplicate and inactive licenses
    - Workload status improvements
    """
    prev_payload = prev_snapshot.get("payload", {}) if prev_snapshot else {}
    curr_payload = curr_snapshot.get("payload", {}) if curr_snapshot else {}

    prev_summary = prev_payload.get("summary", {})
    curr_summary = curr_payload.get("summary", {})

    prev_val = prev_summary.get("overall_value_index", 0.0)
    curr_val = curr_summary.get("overall_value_index", 0.0)

    delta_total_lic = curr_summary.get("total_licenses", 0) - prev_summary.get("total_licenses", 0)
    delta_consumed = curr_summary.get("assigned_licenses", 0) - prev_summary.get("assigned_licenses", 0)
    delta_idle = curr_summary.get("idle_licenses", 0) - prev_summary.get("idle_licenses", 0)
    delta_value_index = round(curr_val - prev_val, 1)

    delta_duplicates = curr_summary.get("duplicate_entitlement_users", 0) - prev_summary.get("duplicate_entitlement_users", 0)
    delta_inactive = curr_summary.get("inactive_licensed_users", 0) - prev_summary.get("inactive_licensed_users", 0)

    # Workload diffs
    prev_workloads = {w.get("workload_code"): w.get("realization_status") for w in prev_payload.get("reconciliations", [])}
    curr_workloads = {w.get("workload_code"): w.get("realization_status") for w in curr_payload.get("reconciliations", [])}

    improved_workloads = []
    regressed_workloads = []

    for code, curr_st in curr_workloads.items():
        prev_st = prev_workloads.get(code)
        if prev_st and prev_st != curr_st:
            if curr_st in [STATUS_FULL_VALUE, STATUS_LICENSED_ACTIVE_TELEMETRY]:
                improved_workloads.append({"code": code, "from": prev_st, "to": curr_st})
            else:
                regressed_workloads.append({"code": code, "from": prev_st, "to": curr_st})

    return {
        "previous_period": prev_snapshot.get("period", "N/A") if prev_snapshot else "N/A",
        "current_period": curr_snapshot.get("period", "N/A") if curr_snapshot else "N/A",
        "delta_total_licenses": delta_total_lic,
        "delta_assigned_licenses": delta_consumed,
        "delta_idle_licenses": delta_idle,
        "delta_value_index": delta_value_index,
        "delta_duplicate_users": delta_duplicates,
        "delta_inactive_licensed_users": delta_inactive,
        "improved_workloads": improved_workloads,
        "regressed_workloads": regressed_workloads,
        "assessment": (
            "Güvenlik yatırımı değer endeksinde artış sağlandı; atıl ve mükerrer lisanslar optimize edildi."
            if delta_value_index >= 0 else
            "Değer endeksinde düşüş veya yeni konfigürasyon boşluğu tespit edildi; iyileştirme adımları gereklidir."
        )
    }
