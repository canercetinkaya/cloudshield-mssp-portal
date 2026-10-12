# -*- coding: utf-8 -*-
"""
CloudShield Collector to Report Reconciliation Test Suite
(tests/test_collector_to_report_reconciliation.py)

Performs 1-to-1 reconciliation between raw collector outputs (RawData / KPIs)
and rendered HTML/PDF reports across all 12 supported Microsoft workloads.
Ensures zero synthetic alteration, explicit audit verification status, and
strict test/simulation labeling.
"""

import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PORTAL_API_DIR = os.path.join(BASE_DIR, "Portal", "api")
if PORTAL_API_DIR not in sys.path:
    sys.path.insert(0, PORTAL_API_DIR)

from report_generator import generate_html_report, classify_workload_status, get_test_data_notice_banner

class TestCollectorToReportReconciliation(unittest.TestCase):
    """
    Automated 1-to-1 reconciliation across all 12 workloads.
    """

    def setUp(self):
        self.customer = "Anadolu Finans Grubu A.S."
        self.period_tag = "2026-08"
        self.period_label = "Ağustos 2026"

    def test_reconciliation_01_mde(self):
        """MDE: Raw devices, sensor health, and incidents reconcile exactly into HTML."""
        raw_kpis = {
            "TotalDevices": 843,
            "ActiveDevices": 820,
            "GhostDevices": 23,
            "ToplamAlarm": 31,
            "AcikOlaylar": 4,
            "OtonomAksiyonSayisi": 18,
            "ManuelAksiyonSayisi": 5
        }
        live_data = {
            "SVC-MDE": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-MDE"], self.period_tag, self.period_label, live_data)
        
        # 1-to-1 value assertions
        self.assertIn("843", html, "Raw TotalDevices must match in HTML")
        self.assertIn("820", html, "Raw ActiveDevices must match in HTML")
        self.assertIn("23", html, "Raw GhostDevices must match in HTML")
        self.assertIn("18", html, "Raw OtonomAksiyonSayisi must match in HTML")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)
        self.assertIn("Kodlandı, Canlı Doğrulama Bekliyor", html)

    def test_reconciliation_02_mdo(self):
        """MDO: Inbound mail, phishing, malware, ZAP reconcile exactly into HTML."""
        raw_kpis = {
            "TotalInbound": 194200,
            "PhishBlocked": 3410,
            "MalwareBlocked": 890,
            "ZapActions": 62,
            "SafeLinksBlocked": 412,
            "ManuelAnalistEforu": 8
        }
        live_data = {
            "SVC-MDO": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-MDO"], self.period_tag, self.period_label, live_data)
        self.assertIn("194.200", html, "Formatted TotalInbound must appear in HTML")
        self.assertIn("62", html, "Raw ZapActions must appear in HTML")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_03_mdi(self):
        """MDI: DCs, identity threats, and NTLM counts reconcile exactly into HTML."""
        raw_kpis = {
            "ToplamDcSayisi": 7,
            "SaglikliDcSayisi": 7,
            "ToplamKimlikTehdidi": 3,
            "NtlmV1CihazSayisi": 12,
            "ManuelAnalistEforu": 3
        }
        live_data = {
            "SVC-MDI": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-MDI"], self.period_tag, self.period_label, live_data)
        self.assertIn("7 / 7", html, "Healthy / Total DC count must match exactly")
        self.assertIn("3", html, "Identity threats must match exactly")
        self.assertIn("12", html, "NTLMv1 devices must match exactly")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_04_mdca(self):
        """MDCA: Cloud apps, high risk apps, and OAuth counts reconcile exactly into HTML."""
        raw_kpis = {
            "ToplamKesfedilenUygulama": 420,
            "YuksekRiskliUygulama": 54,
            "EngellenenOnaysizApp": 19,
            "OnayliKurumsalApp": 88,
            "YuksekYetkiliOAuth": 14,
            "SupheliOAuthApp": 2
        }
        live_data = {
            "SVC-MDCA": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-MDCA"], self.period_tag, self.period_label, live_data)
        self.assertIn("420", html, "Discovered apps must match exactly")
        self.assertIn("54", html, "High risk apps must match exactly")
        self.assertIn("19", html, "Blocked unsanctioned apps must match exactly")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_05_mdc(self):
        """MDC: Secure score, recommendations, exposed VMs reconcile exactly into HTML."""
        raw_kpis = {
            "BulutGuvenlikSkoru": 73.8,
            "KritikOneriler": 11,
            "AcikKaynakSayisi": 6,
            "IyilestirilenOneri": 4
        }
        live_data = {
            "SVC-MDC": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-MDC"], self.period_tag, self.period_label, live_data)
        self.assertIn("73.8", html, "Cloud Secure Score must match exactly")
        self.assertIn("11", html, "Critical recommendations must match exactly")
        self.assertIn("6", html, "Exposed VMs must match exactly")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_06_intune(self):
        """Intune: Devices, compliance, BitLocker encryption reconcile exactly into HTML."""
        raw_kpis = {
            "ToplamCihaz": 1250,
            "UyumluCihaz": 1205,
            "UyumsuzCihaz": 45,
            "SifreliCihaz": 1190,
            "WindowsSayisi": 850,
            "IosSayisi": 250,
            "AndroidSayisi": 150
        }
        live_data = {
            "SVC-INTUNE": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-INTUNE"], self.period_tag, self.period_label, live_data)
        self.assertIn("1250", html, "Total devices must match exactly")
        self.assertIn("1205", html, "Compliant devices must match exactly")
        self.assertIn("45", html, "Non-compliant devices must match exactly")
        self.assertIn("850", html, "Windows devices must match exactly")
        self.assertIn("250", html, "iOS devices must match exactly")
        self.assertIn("150", html, "Android devices must match exactly")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_07_purview_dlp(self):
        """Purview DLP: Policy matches, blocked transfers, overrides reconcile exactly into HTML."""
        raw_kpis = {
            "TotalMatches": 1420,
            "BlockedEvents": 1315,
            "UserOverrides": 105,
            "EndpointEvents": 85,
            "ManuelAnalistEforu": 12
        }
        live_data = {
            "SVC-PURVIEW": {
                "availabilityState": "SupportedAppOnly",
                "isLiveVerified": False,
                "collectedAtUtc": "2026-08-31T23:59:59Z",
                "kpis": raw_kpis
            }
        }
        html = generate_html_report(self.customer, ["SVC-PURVIEW"], self.period_tag, self.period_label, live_data)
        self.assertIn("1.420", html, "Formatted TotalMatches must match exactly")
        self.assertIn("1.315", html, "Formatted BlockedEvents must match exactly")
        self.assertIn("105", html, "UserOverrides must match exactly")
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)

    def test_reconciliation_08_to_12_consolidated_coverage(self):
        """
        Consolidated report reconciliation covering Information Protection,
        Data Governance, Insider Risk, Communication Compliance, and DSPM for AI.
        """
        live_data = {
            "SVC-PRV-CLASS": {"availabilityState": "SupportedAppOnly", "kpis": {"BlockedEvents": 0, "ApprovedAnalystActions": 4}},
            "SVC-PRV-GOV": {"availabilityState": "SupportedAppOnly", "kpis": {"BlockedEvents": 0, "ApprovedAnalystActions": 2}},
            "SVC-PRV-RISK": {"availabilityState": "SupportedAppOnly", "kpis": {"BlockedEvents": 3, "ApprovedAnalystActions": 3}},
            "SVC-PRV-COMM": {"availabilityState": "SupportedAppOnly", "kpis": {"BlockedEvents": 2, "ApprovedAnalystActions": 1}},
            "SVC-AI-SECURITY": {"availabilityState": "SupportedAppOnly", "kpis": {"BlockedEvents": 14, "ApprovedAnalystActions": 5}},
        }
        svcs = ["SVC-PRV-CLASS", "SVC-PRV-GOV", "SVC-PRV-RISK", "SVC-PRV-COMM", "SVC-AI-SECURITY"]
        html = generate_html_report(self.customer, svcs, self.period_tag, self.period_label, live_data)
        
        self.assertIn("Purview Bilgi Koruması", html)
        self.assertIn("Purview Veri Yaşam Döngüsü", html)
        self.assertIn("Purview İç Risk", html)
        self.assertIn("Purview DSPM for AI", html)
        self.assertIn("DOĞRULAMA STATÜSÜ: TEST / SİMÜLASYON VERİSİ", html)
        self.assertIn("Kodlandı, Canlı Doğrulama Bekliyor", html)

    def test_status_classification_rule_conformance(self):
        """
        Verify that classify_workload_status accurately outputs the 5 mandatory statuses.
        """
        st1, _, _ = classify_workload_status("Verified", is_verified=True)
        self.assertEqual(st1, "Canlı Tenant Üzerinde Doğrulandı")

        st2, _, _ = classify_workload_status("SupportedAppOnly", is_verified=False)
        self.assertEqual(st2, "Kodlandı, Canlı Doğrulama Bekliyor")

        st3, _, _ = classify_workload_status("PartialData", is_verified=False)
        self.assertEqual(st3, "Kısmi Veri Toplanıyor")

        st4, _, _ = classify_workload_status("PermissionMissing", is_verified=False)
        self.assertEqual(st4, "API veya İzin Engelli")

        st5, _, _ = classify_workload_status("DryRunMock", is_verified=False)
        self.assertEqual(st5, "Yalnızca Test/DryRun")

if __name__ == "__main__":
    unittest.main()
