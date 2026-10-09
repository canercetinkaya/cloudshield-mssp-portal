# CloudShield License Intelligence & Security Value Realization Test Suite
# Tests Catalog, Personas, Duplicate Detection, Add-on Prerequisites, 5-Layer Reconciliation,
# SMB 300 Cap, Azure Resource Separation, Snapshot Diffs, and Database Integration.

import os
import json
import tempfile
import unittest
from datetime import datetime, timezone

from database.db import (
    init_db, get_db,
    save_license_inventory, get_license_inventory,
    save_user_license_profiles, get_user_license_profiles,
    save_license_value_summary, get_license_value_summary,
    save_workload_reconciliation, get_workload_reconciliation,
    save_license_snapshot, get_license_snapshot, list_license_snapshots
)

from Portal.api.license_intelligence import (
    load_license_catalog,
    classify_user_persona,
    analyze_user_license_entitlements,
    reconcile_workload_5_layers,
    check_smb_user_cap,
    compute_overall_value_index,
    compare_license_snapshots,
    WORKLOADS_DEF,
    SKU_M365_E5,
    SKU_M365_E3,
    SKU_E5_SEC,
    SKU_E5_COMP,
    SKU_M365_BUS_PREM,
    SKU_M365_BUS_STD,
    SKU_COPILOT,
    STATUS_FULL_VALUE,
    STATUS_DUPLICATE_ENTITLEMENT,
    STATUS_MISSING_PREREQUISITE,
    STATUS_ASSIGNED_IDLE,
    STATUS_AZURE_CONSUMPTION_VERIFIED
)

from Portal.api.license_collector import collect_tenant_license_intelligence
from Portal.api.license_report_generator import generate_license_health_report
from Portal.api.license_catalog_updater import check_remote_feed, get_feed_status

class TestLicenseIntelligence(unittest.TestCase):

    def setUp(self):
        self.catalog = load_license_catalog()
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_path = self.temp_db_file.name
        self.temp_db_file.close()
        os.environ["DB_PATH"] = self.temp_db_path
        init_db(self.temp_db_path)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    # 1. Catalog loading and specification
    def test_catalog_loading_and_version(self):
        self.assertIsNotNone(self.catalog)
        self.assertEqual(self.catalog.get("catalogVersion"), "1.0.0")
        sources = self.catalog.get("sources", [])
        self.assertEqual(len(sources), 2)
        urls = [s.get("url") for s in sources]
        self.assertTrue(any("Modern-Work-Plan-Comparison-Enterprise.pdf" in u for u in urls))
        self.assertTrue(any("Modern-Work-Plan-Comparison-SMB.pdf" in u for u in urls))

    # 2. SKU Part Number Mapping
    def test_sku_part_number_mapping(self):
        skus = self.catalog.get("skus", {})
        parts = [s.get("skuPartNumber") for s in skus.values()]
        for expected in ["SPE_E5", "SPE_E3", "SPB", "SMB_BUSINESS_STD", "SPE_E5_SEC", "SPE_E5_COMP", "COPILOT_M365"]:
            self.assertIn(expected, parts)

    # 3. Persona Classification - Executive
    def test_persona_classification_executive(self):
        user = {"userPrincipalName": "ceo@acme.com", "jobTitle": "Chief Executive Officer", "department": "Executive Board", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Executive")

    # 4. Persona Classification - Sec / IT Admin
    def test_persona_classification_sec_admin(self):
        user = {"userPrincipalName": "admin@acme.com", "jobTitle": "Lead Security Engineer", "department": "IT Security", "accountEnabled": True}
        persona = classify_user_persona(user, admin_roles=["Global Administrator"])
        self.assertEqual(persona, "Sec / IT Admin")

    # 5. Persona Classification - Finance / Sensitive Data
    def test_persona_classification_finance(self):
        user = {"userPrincipalName": "finance.lead@acme.com", "jobTitle": "Mali İşler Müdürü", "department": "Muhasebe", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Finance / Sensitive Data")

    # 6. Persona Classification - HR / PII
    def test_persona_classification_hr(self):
        user = {"userPrincipalName": "hr.lead@acme.com", "jobTitle": "İnsan Kaynakları Uzmanı", "department": "İnsan Kaynakları", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "HR / PII")

    # 7. Persona Classification - Dev / DevOps
    def test_persona_classification_dev(self):
        user = {"userPrincipalName": "dev@acme.com", "jobTitle": "Senior Software Engineer", "department": "Yazılım Geliştirme", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Dev / DevOps")

    # 8. Persona Classification - Frontline
    def test_persona_classification_frontline(self):
        user = {"userPrincipalName": "store@acme.com", "jobTitle": "Kasiyer / Saha Personeli", "department": "Mağaza", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Frontline")

    # 9. Persona Classification - Guest
    def test_persona_classification_guest(self):
        user = {"userPrincipalName": "external_vendor#ext#@acme.com", "userType": "Guest", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Guest")

    # 10. Persona Classification - Service Account
    def test_persona_classification_service_account(self):
        user = {"userPrincipalName": "svc_backup_agent@acme.com", "displayName": "Yedekleme Servis Hesabı", "accountEnabled": True}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Service Account")

    # 11. Persona Classification - Inactive User
    def test_persona_classification_inactive(self):
        user = {"userPrincipalName": "resigned@acme.com", "accountEnabled": False}
        persona = classify_user_persona(user)
        self.assertEqual(persona, "Inactive User")

    # 12. Duplicate Entitlement: E5 + E3
    def test_duplicate_entitlement_e5_e3(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_M365_E5}, {"sku_part_number": SKU_M365_E3}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_DUPLICATE_ENTITLEMENT)
        self.assertTrue(any("Microsoft 365 E5 ve Microsoft 365 E3" in r for r in risks))

    # 13. Duplicate Entitlement: E5 + Standalone E5 Security
    def test_duplicate_entitlement_e5_security_redundancy(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_M365_E5}, {"sku_part_number": SKU_E5_SEC}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_DUPLICATE_ENTITLEMENT)
        self.assertTrue(any("E5 Security yeteneklerini zaten içerir" in r for r in risks))

    # 14. Duplicate Entitlement: Business Premium + Business Standard
    def test_duplicate_entitlement_smb_prem_std(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_M365_BUS_PREM}, {"sku_part_number": SKU_M365_BUS_STD}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_DUPLICATE_ENTITLEMENT)
        self.assertTrue(any("Business Premium ve Business Standard" in r for r in risks))

    # 15. Add-on Prerequisite: E5 Security with valid Base (M365 E3)
    def test_addon_prerequisite_e5_security_valid(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_M365_E3}, {"sku_part_number": SKU_E5_SEC}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_FULL_VALUE)
        self.assertEqual(len(risks), 0)

    # 16. Add-on Prerequisite: E5 Security Missing Base
    def test_addon_prerequisite_e5_security_missing_base(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_E5_SEC}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_MISSING_PREREQUISITE)
        self.assertTrue(any("temel lisans" in r for r in risks))

    # 17. Add-on Prerequisite: E5 Compliance Missing Base
    def test_addon_prerequisite_e5_compliance_missing_base(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_E5_COMP}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_MISSING_PREREQUISITE)
        self.assertTrue(any("E5 Compliance add-on'u için temel M365 E3 lisansı eksik" in r for r in risks))

    # 18. Add-on Prerequisite: Copilot Missing Base
    def test_addon_prerequisite_copilot_missing_base(self):
        profile = {
            "user_principal_name": "user@acme.com",
            "account_enabled": True,
            "assigned_skus": [{"sku_part_number": SKU_COPILOT}],
            "persona_type": "Standard Knowledge Worker"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_MISSING_PREREQUISITE)
        self.assertTrue(any("Copilot için yetkili temel" in r for r in risks))

    # 19. Inactive User with Assigned License (Atıl Lisans Riski)
    def test_inactive_user_with_assigned_licenses(self):
        profile = {
            "user_principal_name": "resigned@acme.com",
            "account_enabled": False,
            "assigned_skus": [{"sku_part_number": SKU_M365_E5}],
            "persona_type": "Inactive User"
        }
        status, risks, recs = analyze_user_license_entitlements(profile, self.catalog)
        self.assertEqual(status, STATUS_ASSIGNED_IDLE)
        self.assertTrue(any("Atıl Lisans Riski" in r for r in risks))

    # 20. SMB 300 User Cap Exceeded
    def test_smb_300_user_cap_warning(self):
        inventory = [
            {"sku_part_number": SKU_M365_BUS_PREM, "consumed_units": 200},
            {"sku_part_number": SKU_M365_BUS_STD, "consumed_units": 150}
        ]
        exceeded, units, msg = check_smb_user_cap(inventory)
        self.assertTrue(exceeded)
        self.assertEqual(units, 350)
        self.assertIn("KOBİ Lisans Tavanı Aşıldı", msg)

    # 21. SMB 300 User Cap Normal
    def test_smb_300_user_cap_normal(self):
        inventory = [
            {"sku_part_number": SKU_M365_BUS_PREM, "consumed_units": 120},
            {"sku_part_number": SKU_M365_BUS_STD, "consumed_units": 80}
        ]
        exceeded, units, msg = check_smb_user_cap(inventory)
        self.assertFalse(exceeded)
        self.assertEqual(units, 200)
        self.assertIn("Normal", msg)

    # 22. Azure Resource Workloads Separation (Defender for Cloud)
    def test_azure_resource_workloads_separation(self):
        telemetry = {
            "azure_resources": {
                "subscription_active": True,
                "protected_resources_count": 65
            }
        }
        rec = reconcile_workload_5_layers("MDC", [], [], telemetry)
        self.assertEqual(rec["realization_status"], STATUS_AZURE_CONSUMPTION_VERIFIED)
        self.assertTrue(rec["is_azure_resource"])
        self.assertIn("Azure abonelik tüketim modeli", rec["gap_description"])

    # 23. 5-Layer Reconciliation for All 15 Workloads
    def test_5_layer_reconciliation_all_15_workloads(self):
        self.assertEqual(len(WORKLOADS_DEF), 15)
        inventory = [{"sku_part_number": SKU_M365_E5, "prepaid_units": 100, "consumed_units": 90}]
        users = [{
            "assigned_skus": [{"sku_part_number": SKU_M365_E5}],
            "assigned_plans": [{"servicePlanName": "WINDEFATP", "provisioningStatus": "Success"}]
        }]
        telemetry = {
            "azure_resources": {"subscription_active": True, "protected_resources_count": 20},
            "policy_coverage": {"MDE": {"targeted_users_count": 90, "policy_active": True}},
            "telemetry_stats": {"MDE": {"evidence_count": 15, "verified": True}}
        }
        for w in WORKLOADS_DEF:
            rec = reconcile_workload_5_layers(w["code"], inventory, users, telemetry)
            self.assertIsNotNone(rec)
            self.assertIn("realization_status", rec)
            self.assertIn("gap_description", rec)

    # 24. Snapshot Diffing and Delta
    def test_snapshot_diffing_and_delta(self):
        prev_snap = {
            "period": "2026-09",
            "payload": {
                "summary": {
                    "total_licenses": 200, "assigned_licenses": 160, "idle_licenses": 40,
                    "overall_value_index": 70.0, "duplicate_entitlement_users": 2, "inactive_licensed_users": 3
                },
                "reconciliations": [{"workload_code": "MDE", "realization_status": "Lisans Var, İlke veya Konfigürasyon Eksik"}]
            }
        }
        curr_snap = {
            "period": "2026-10",
            "payload": {
                "summary": {
                    "total_licenses": 200, "assigned_licenses": 175, "idle_licenses": 25,
                    "overall_value_index": 85.0, "duplicate_entitlement_users": 0, "inactive_licensed_users": 0
                },
                "reconciliations": [{"workload_code": "MDE", "realization_status": STATUS_FULL_VALUE}]
            }
        }
        diff = compare_license_snapshots(prev_snap, curr_snap)
        self.assertEqual(diff["delta_assigned_licenses"], 15)
        self.assertEqual(diff["delta_idle_licenses"], -15)
        self.assertEqual(diff["delta_value_index"], 15.0)
        self.assertEqual(diff["delta_duplicate_users"], -2)
        self.assertEqual(len(diff["improved_workloads"]), 1)

    # 25. Database Persistence and Retrieval
    def test_database_persistence_and_retrieval(self):
        tenant_id = "test-tenant-db"
        snapshot_date = "2026-10-09"
        items = [{
            "sku_id": "06e2b970-d779-4be0-9168-26d6e502024e",
            "sku_part_number": "SPE_E5",
            "display_name": "Microsoft 365 E5",
            "prepaid_units": 100,
            "consumed_units": 85,
            "suspended_units": 0,
            "warning_units": 0,
            "capability_status": "Enabled"
        }]
        save_license_inventory(tenant_id, snapshot_date, items, db_path=self.temp_db_path)
        fetched = get_license_inventory(tenant_id, snapshot_date, db_path=self.temp_db_path)
        self.assertEqual(len(fetched), 1)
        self.assertEqual(fetched[0]["sku_part_number"], "SPE_E5")
        self.assertEqual(fetched[0]["consumed_units"], 85)

    # 26. Remote PDF Feed Monitor Status
    def test_remote_feed_monitor(self):
        status = get_feed_status()
        self.assertIsNotNone(status)
        self.assertIn("sources", status)
        self.assertIn("enterprise_comparison", status["sources"])
        self.assertIn("smb_comparison", status["sources"])

    # 27. 20-Section Report Generation
    def test_report_generation_20_sections(self):
        res = collect_tenant_license_intelligence("test-tenant-rpt", period="2026-10", dry_run=True, db_path=self.temp_db_path)
        html = generate_license_health_report(res)
        self.assertIn("CloudShield Güvenlik Değer Gerçekleştirme Raporu", html)
        self.assertIn("DİKKAT: SENTETİK / TEST SİMÜLASYONU RAPORUDUR", html)
        # Check all 20 numbered sections
        for sec_num in range(1, 21):
            self.assertIn(f'<span class="section-num">{sec_num}</span>', html)

if __name__ == "__main__":
    unittest.main()
