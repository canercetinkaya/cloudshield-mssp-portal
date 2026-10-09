# -*- coding: utf-8 -*-
"""
CloudShield Data Accuracy & Reporting Quality Gates (tests/test_data_accuracy_gates.py)
Automated verification ensuring zero synthetic multipliers, strict missing data transparency,
central 23+ field KPI catalog completeness, and verified managed activities across all 12 workloads.
"""

import os
import re
import json
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE_DIR = os.path.join(BASE_DIR, "Engine")
PLUGINS_DIR = os.path.join(ENGINE_DIR, "Plugins")
PORTAL_API_DIR = os.path.join(BASE_DIR, "Portal", "api")

class TestDataAccuracyAndQualityGates(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from database.db import init_db
        init_db()

    def test_gate_01_no_synthetic_multipliers_in_plugins(self):
        """
        Verify that no PowerShell plugin contains forbidden synthetic multipliers
        such as multiplying alerts by 80, multiplying compliant devices by 0.85/0.75,
        adding arbitrary +6 or +5 to server counts.
        """
        forbidden_patterns = [
            (r"\$a\.Count\s*\*\s*80", "Alert count synthetic 80x traffic multiplier in MDO"),
            (r"\$uyumlu\s*\*\s*0\.85", "Compliant devices synthetic 85% multiplier in Intune"),
            (r"\$toplam\s*\*\s*0\.75", "Total devices synthetic 75% multiplier in Intune"),
            (r"\$ovr\s*\*\s*0\.60?", "DLP override synthetic 60% multiplier in PurviewDlp"),
            (r"ToplamDcSayisi\s*=\s*\$dcSayisi\s*\+\s*6", "Synthetic +6 domain controller adder in MDI"),
            (r"SaglikliDcSayisi\s*=\s*\$dcSayisi\s*\+\s*5", "Synthetic +5 healthy DC adder in MDI"),
        ]

        violations = []
        for root, _, files in os.walk(PLUGINS_DIR):
            for file in files:
                if file.endswith(".psm1"):
                    fpath = os.path.join(root, file)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for pattern, desc in forbidden_patterns:
                        if re.search(pattern, content):
                            violations.append(f"{file}: {desc}")

        self.assertEqual(violations, [], f"Found forbidden synthetic multipliers in plugins: {violations}")

    def test_gate_02_no_synthetic_multipliers_in_report_generator(self):
        """
        Verify that report_generator.py does not contain synthetic multipliers
        on compliant devices or fake '0 Tespit / Temiz' claims for unconfigured metrics.
        """
        generator_path = os.path.join(PORTAL_API_DIR, "report_generator.py")
        with open(generator_path, "r", encoding="utf-8") as f:
            content = f.read()

        forbidden_patterns = [
            (r"int\(compliant_devices\s*\*\s*0\.85\)", "Synthetic 85% Windows compliance multiplier in report_generator"),
            (r"int\(total_devices\s*\*\s*0\.75\)", "Synthetic 75% Windows total multiplier in report_generator"),
            (r"0\s*Tespit\s*/\s*Temiz", "Deceptive '0 Tespit / Temiz' claim for unconfigured Intune BitLocker/Firewall"),
        ]

        violations = []
        for pattern, desc in forbidden_patterns:
            if re.search(pattern, content):
                violations.append(f"report_generator.py: {desc}")

        self.assertEqual(violations, [], f"Found forbidden patterns in report_generator.py: {violations}")

    def test_gate_03_kpi_catalog_has_all_23_fields_and_12_workloads(self):
        """
        Verify that kpi-catalog.json has all central metadata fields for every entry,
        and covers all 12 workloads.
        """
        kpi_catalog_path = os.path.join(ENGINE_DIR, "Config", "kpi-catalog.json")
        self.assertTrue(os.path.exists(kpi_catalog_path), "kpi-catalog.json must exist")

        with open(kpi_catalog_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        kpis = data.get("kpis", {})
        self.assertGreaterEqual(len(kpis), 20, "Should have at least 20 central KPIs defined")

        required_fields = [
            "id", "serviceCode", "product", "nameTr", "nameEn", "businessMeaning",
            "technicalDefinition", "sourceApi", "endpoint", "kqlQuery",
            "requiredPermission", "licenseRequired", "formula", "numerator", "denominator",
            "unit", "reportingPeriod", "collectionFrequency", "dataFreshness",
            "completenessStatus", "trustLevel", "knownLimitations", "missingDataBehavior",
            "targetAudience", "supportedDecision", "drillDownSource"
        ]

        covered_workloads = set()
        for kpi_id, kpi in kpis.items():
            covered_workloads.add(kpi.get("serviceCode"))
            for field in required_fields:
                self.assertIn(field, kpi, f"KPI '{kpi_id}' missing required field: {field}")
                self.assertTrue(str(kpi[field]).strip(), f"KPI '{kpi_id}' has empty field: {field}")

        # Check coverage of all 12 major workloads
        expected_workloads = {
            "SVC-MDE", "SVC-MDO", "SVC-MDI", "SVC-MDCA", "SVC-MDC", "SVC-INTUNE",
            "SVC-PRV-DLP", "SVC-PRV-CLASS", "SVC-PRV-GOV",
            "SVC-PRV-RISK", "SVC-PRV-COMM", "SVC-AI-SECURITY"
        }
        for w in expected_workloads:
            self.assertIn(w, covered_workloads, f"Workload {w} must be represented in kpi-catalog.json")

    def test_gate_04_all_12_workloads_dispatchable_in_report_generator(self):
        """
        Verify that single-service HTML generation dispatches successfully for all
        primary workloads without throwing an unhandled exception.
        """
        import sys
        if PORTAL_API_DIR not in sys.path:
            sys.path.insert(0, PORTAL_API_DIR)

        from report_generator import generate_html_report

        workloads = [
            "SVC-MDE", "SVC-MDO", "SVC-MDI", "SVC-MDCA", "SVC-MDC", "SVC-INTUNE",
            "SVC-PURVIEW-DLP", "SVC-PURVIEW-LABEL", "SVC-PURVIEW-GOV",
            "SVC-PURVIEW-INSIDER", "SVC-PURVIEW-AI-DSPM", "SVC-CONSOLIDATED"
        ]

        live_data_sample = {
            "SVC-MDE": {"kpis": {"CihazGuvenlikSkoru": "82", "ToplamZafiyetSayisi": 14}},
            "SVC-MDO": {"kpis": {"KullaniciSayisi": 500, "EngellenenPhishing": 25}},
            "SVC-MDI": {"kpis": {"ToplamDcSayisi": 4, "SaglikliDcSayisi": 4, "ToplamKimlikTehdidi": 0}},
            "SVC-MDCA": {"kpis": {"ToplamBulutUygulamasi": 120, "OnayliUygulamalar": 45}},
            "SVC-MDC": {"kpis": {"GuvenlikPuani": 74.5, "ToplamOneri": 18}},
            "SVC-INTUNE": {"kpis": {"ToplamCihaz": 250, "UyumluCihaz": 240}},
            "SVC-PURVIEW-DLP": {"kpis": {"ToplamDlpOlayi": 5}},
        }

        for svc in workloads:
            try:
                html = generate_html_report(
                    customer_name="Test Kurum A.S.",
                    services=[svc],
                    period_tag="2026-08",
                    period_label="Ağustos 2026",
                    live_data=live_data_sample,
                    data_source_note="Test Telemetry",
                    language="tr",
                    tenant_id="tenant-test-01"
                )
                self.assertIsInstance(html, str)
                self.assertGreater(len(html), 500, f"HTML output for {svc} too short")
                self.assertIn("Test Kurum A.S.", html, f"HTML for {svc} missing customer name")
            except Exception as e:
                self.fail(f"Failed to generate HTML report for service {svc}: {e}")

    def test_gate_05_observed_technical_improvements_without_tickets_or_crs(self):
        """
        Verify telemetry-derived technical improvements model:
        Zero tickets, zero CRs, zero ServiceNow/Jira, and zero manual engineer hours.
        Reflects observable tenant changes and technical security outcomes.
        """
        from database import db
        from report_generator import render_observed_technical_improvements_section

        imp_payload = {
            "tenant_id": "tenant-accuracy-qa",
            "service_code": "SVC-PURVIEW-DLP",
            "period": "2026-08",
            "category": "Politika Optimizasyonu & Tuning",
            "component": "Microsoft Purview DLP",
            "title": "Finansal Veri DLP İlkesinde Regex Eşik Değeri Optimize Edildi",
            "description": "IBAN ve Kredi Kartı kuralları için yanlış pozitifleri önleyecek hassasiyet eşiği güncellendi.",
            "technical_impact": "Yanlış pozitif bildirimler %40 azaltıldı; iş akışı kesintisi engellendi.",
            "telemetry_source": "Purview AuditLog: DlpPolicyChange"
        }
        imp_id = db.record_observed_improvement(imp_payload)
        self.assertTrue(imp_id.startswith("IMP-"))

        imps = db.get_observed_improvements("tenant-accuracy-qa", period="2026-08")
        self.assertGreaterEqual(len(imps), 1)

        html = render_observed_technical_improvements_section(
            tenant_id="tenant-accuracy-qa",
            service_code="SVC-PURVIEW-DLP",
            period_tag="2026-08",
            language="tr"
        )
        self.assertIn("Bu Ay Gerçekleştirilen İyileştirmeler", html)
        self.assertIn("Finansal Veri DLP İlkesinde Regex Eşik Değeri Optimize Edildi", html)
        self.assertIn("Purview AuditLog: DlpPolicyChange", html)
        self.assertIn("Yanlış pozitif bildirimler %40 azaltıldı", html)

        # Strict Absence of Tickets, CRs, ServiceNow, Jira, and Manual Hours
        self.assertNotIn("CR-", html)
        self.assertNotIn("Change Request", html)
        self.assertNotIn("Ticket", html)
        self.assertNotIn("ServiceNow", html)
        self.assertNotIn("Jira", html)

    def test_gate_06_unconfigured_telemetry_renders_transparent_missing_reason(self):
        """
        Verify that missing telemetry is rendered transparently with required permissions,
        licenses, and reasons rather than claiming fake compliant states.
        """
        from report_generator import render_missing_telemetry_catalog_section

        # Empty live data simulates unconfigured / missing permissions
        html = render_missing_telemetry_catalog_section(
            services=["SVC-MDE", "SVC-MDO", "SVC-INTUNE"],
            live_data={},
            language="tr"
        )
        self.assertIn("Telemetri Eksiklikleri", html)
        self.assertIn("Gerekli Lisans", html)

if __name__ == "__main__":
    unittest.main()
