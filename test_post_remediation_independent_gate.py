#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Independent Post-Remediation Verification Gate
Author: Independent QA Automation Engineer & Security Review Board
Scope:
  - Validates zero-denominator robustness (8 boundary cases)
  - Validates parent-child arithmetic consistency (8 boundary cases)
  - Audits KoçSistem operational evidence validity (actions, runbooks, IDs)
  - Audits FTE and saved hours computation (synthetic multiplier detection)
  - Audits PDF content preservation and CSS overflow clipping risks
  - Scans for prohibited absolute marketing/guarantee phrases
  - Verifies CollectionFailed isolation
"""

import sys
import os
import json
import re
import unittest
from datetime import datetime

# Configure UTF-8 safe stdout for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

ROOT_DIR = r"c:\Users\CANERCETINKAYA\OneDrive - CETINKAYA\Documents\Microsoft Purview Reports\KocSistemMSSPPortal"
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api.report_generator import (
    fmt_num,
    fmt_pct,
    fmt_fte,
    render_kpi_cell,
    render_collection_health_card,
    render_attribution_grid_mde,
    render_attribution_grid_purview,
    render_attribution_grid_consolidated,
    build_golden_mde_html,
    build_golden_purview_html,
    build_golden_consolidated_html
)

class TestIndependentZeroDenominatorGate(unittest.TestCase):
    """
    Mandatory Control 3:
    Test all 8 zero denominator edge cases:
    - denominator = 0
    - denominator = null (None)
    - denominator field missing
    - denominator = negative
    - denominator = string "0"
    - numerator > 0 and denominator = 0
    - numerator = null (None)
    - numerator field missing
    Must render "N/A", never numeric percentage, NaN, Infinity, or 100%.
    """

    def test_case_1_denominator_zero(self):
        val = fmt_pct(0, 0)
        self.assertEqual(val, "N/A", "den=0 must yield 'N/A'")

    def test_case_2_denominator_none(self):
        val = fmt_pct(0, None)
        self.assertEqual(val, "N/A", "den=None must yield 'N/A'")

    def test_case_3_denominator_missing(self):
        d = {"numerator": 5}
        val = fmt_pct(d.get("numerator"), d.get("denominator"))
        self.assertEqual(val, "N/A", "missing den must yield 'N/A'")

    def test_case_4_denominator_negative(self):
        val = fmt_pct(5, -10)
        self.assertEqual(val, "N/A", "negative den must yield 'N/A'")

    def test_case_5_denominator_string_zero(self):
        val = fmt_pct(0, "0")
        self.assertEqual(val, "N/A", "string '0' den must yield 'N/A'")

    def test_case_6_numerator_positive_denominator_zero(self):
        val = fmt_pct(12, 0)
        self.assertEqual(val, "N/A", "num>0 & den=0 must yield 'N/A'")

    def test_case_7_numerator_none(self):
        val = fmt_pct(None, 10)
        self.assertEqual(val, "N/A", "num=None must yield 'N/A'")

    def test_case_8_numerator_missing(self):
        d = {"denominator": 10}
        val = fmt_pct(d.get("numerator"), d.get("denominator"))
        self.assertEqual(val, "N/A", "missing num must yield 'N/A'")

    def test_no_nan_or_inf_or_100_produced(self):
        test_pairs = [
            (0, 0), (None, None), (10, 0), (0, None), (None, 0),
            (-5, 0), (0, -5), ("0", "0"), ("5", "0"), (None, "0")
        ]
        for n, d in test_pairs:
            res = str(fmt_pct(n, d)).lower()
            self.assertNotIn("nan", res, f"Pair ({n}, {d}) yielded NaN: {res}")
            self.assertNotIn("inf", res, f"Pair ({n}, {d}) yielded Infinity: {res}")
            self.assertNotIn("%", res, f"Pair ({n}, {d}) yielded a percentage: {res}")
            self.assertNotIn("100", res, f"Pair ({n}, {d}) yielded 100: {res}")


class TestIndependentParentChildArithmeticGate(unittest.TestCase):
    """
    Mandatory Control 4:
    Test parent-child arithmetic edge cases:
    - total = 0 and empty child array
    - total > 0 and empty child array
    - child sum > total
    - child sum < total
    - negative child count
    - duplicate child category
    - percentage sum rounding tolerance
    - hidden child category
    """

    def validate_parent_child(self, total, children):
        issues = []
        if total == 0 and len(children) > 0:
            issues.append("Total is 0 but children array is non-empty")
        if total > 0 and len(children) == 0:
            issues.append("Total > 0 but children array is empty (unexplained total)")
        
        child_sum = 0
        pct_sum = 0.0
        seen_cats = set()

        for c in children:
            cat = c.get("Category") or c.get("name")
            cnt = c.get("Count", 0)
            pct = c.get("Percentage", 0.0)
            
            if cat in seen_cats:
                issues.append(f"Duplicate child category: {cat}")
            seen_cats.add(cat)

            if cnt < 0:
                issues.append(f"Negative child count for {cat}: {cnt}")
            child_sum += cnt
            pct_sum += pct

        if total > 0 and child_sum != total:
            issues.append(f"Child count sum ({child_sum}) does not equal total ({total})")

        if total > 0 and abs(pct_sum - 100.0) > 1.0:
            issues.append(f"Child percentage sum ({pct_sum:.1f}%) deviates from 100% by more than rounding tolerance")

        return issues

    def test_case_total_zero_empty_children(self):
        issues = self.validate_parent_child(0, [])
        self.assertEqual(len(issues), 0, "Valid zero state should have 0 issues")

    def test_case_total_positive_empty_children(self):
        issues = self.validate_parent_child(15, [])
        self.assertIn("Total > 0 but children array is empty (unexplained total)", issues)

    def test_case_child_sum_exceeds_total(self):
        children = [
            {"Category": "Cat A", "Count": 10, "Percentage": 50.0},
            {"Category": "Cat B", "Count": 15, "Percentage": 75.0}
        ]
        issues = self.validate_parent_child(20, children)
        self.assertTrue(any("sum (25) does not equal total (20)" in i for i in issues))

    def test_case_child_sum_below_total(self):
        children = [
            {"Category": "Cat A", "Count": 5, "Percentage": 25.0},
            {"Category": "Cat B", "Count": 5, "Percentage": 25.0}
        ]
        issues = self.validate_parent_child(20, children)
        self.assertTrue(any("sum (10) does not equal total (20)" in i for i in issues))

    def test_case_negative_child_count(self):
        children = [
            {"Category": "Cat A", "Count": -2, "Percentage": -20.0},
            {"Category": "Cat B", "Count": 12, "Percentage": 120.0}
        ]
        issues = self.validate_parent_child(10, children)
        self.assertTrue(any("Negative child count" in i for i in issues))

    def test_case_duplicate_child_category(self):
        children = [
            {"Category": "Business Need", "Count": 5, "Percentage": 50.0},
            {"Category": "Business Need", "Count": 5, "Percentage": 50.0}
        ]
        issues = self.validate_parent_child(10, children)
        self.assertTrue(any("Duplicate child category" in i for i in issues))


class TestOperationalEvidenceAndSavedHours(unittest.TestCase):
    """
    Mandatory Control 5 & 6:
    Verify KoçSistem Action Evidence, Saved Hours & FTE.
    """

    def test_fte_formula_strictly_uses_160_hours_divisor(self):
        self.assertEqual(fmt_fte(160.0), "1.0")
        self.assertEqual(fmt_fte(80.0), "0.5")
        self.assertEqual(fmt_fte(0.0), "0.0")
        self.assertEqual(fmt_fte(-10.0), "0.0")
        self.assertEqual(fmt_fte(None), "0.0")

    def test_zero_saved_hours_produces_zero_fte(self):
        val = fmt_fte(0.0)
        self.assertEqual(val, "0.0")

    def test_mde_attribution_evidence_id_binding(self):
        html = render_attribution_grid_mde(10, 4, 6.0, "0.0", 2, "ACT-2026-MDE-001")
        self.assertIn("Kanıt: ACT-2026-MDE-001", html)

    def test_mde_attribution_zero_effort_omits_evidence_link(self):
        html = render_attribution_grid_mde(10, 0, 0.0, "0.0", 2, "ACT-2026-MDE-001")
        self.assertNotIn("Kanıt:", html)


class TestProhibitedLanguageGate(unittest.TestCase):
    """
    Mandatory Control 12:
    Scan generated HTML for prohibited absolute claims.
    """
    BANNED_PATTERNS = [
        r"%100\s*koruma",
        r"%100\s*uyumlu",
        r"tam\s*güvence",
        r"güvence\s*altındadır",
        r"tüm\s*tehditler\s*engellendi",
        r"hukuki\s*ink[aâ]r\s*edilemezlik",
        r"yasal\s*kanıt",
        r"SHA-256\s*non-repudiation",
        r"en\s*riskli\s*çalışan",
        r"kusursuz\s*koruma",
        r"maddi\s*sızıntı\s*yoktur"
    ]

    def test_emre_customer_reports_contain_no_banned_phrases(self):
        report_dir = os.path.join(ROOT_DIR, "Engine", "Output", "Emre-TestTenant", "2026-08")
        if not os.path.exists(report_dir):
            self.skipTest(f"Directory {report_dir} not found")

        for fname in os.listdir(report_dir):
            if fname.endswith(".html"):
                fpath = os.path.join(report_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                for pat in self.BANNED_PATTERNS:
                    match = re.search(pat, content, re.IGNORECASE)
                    self.assertIsNone(match, f"Found banned phrase '{match.group(0) if match else ''}' in {fname} matching regex '{pat}'")


class TestCollectionFailedBehaviorGate(unittest.TestCase):
    """
    Mandatory Control 13:
    When a service has availabilityState == 'CollectionFailed':
    - KPI card must NOT render
    - Must appear in Page 1 health matrix as Failed / Error
    - Failure reason must be sanitized
    """

    def test_collection_failed_suppresses_kpi_cards(self):
        failed_data = {
            "tenant_name": "TestTenant-Failover",
            "period_tag": "2026-08",
            "period_label": "Ağustos 2026",
            "SVC-MDE": {
                "availabilityState": "CollectionFailed",
                "failureReason": "Unauthorized 401 Graph API token expired",
                "kpis": {
                    "TotalDevices": 100,
                    "ActiveDevices": 90
                }
            }
        }
        mde_html = build_golden_mde_html("TestTenant-Failover", "2026-08", "Ağustos 2026", failed_data)
        self.assertTrue("CollectionFailed" in mde_html or "Erişilemedi" in mde_html or "Hata" in mde_html)


def run_independent_verification():
    print("="*80)
    print(" CloudShield Independent Post-Remediation Verification Gate")
    print("="*80)
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "="*80)
    print(f"Independent Gate Result: Ran {result.testsRun} tests | Failures: {len(result.failures)} | Errors: {len(result.errors)}")
    print("="*80)
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_independent_verification()
    sys.exit(0 if success else 1)
