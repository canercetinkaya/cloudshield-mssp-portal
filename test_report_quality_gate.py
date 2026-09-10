#!/usr/bin/env python3
"""
CloudShield MSSP Platform - Automated Report Quality Gate Harness
Authoritative Specification: docs/agents/tasks/cloudshield-agent-knowledge-base-report-quality-task.md

Evaluates generated report artifacts against the 8-dimension quality scoring rubric:
1. Data Integrity (15%)
2. Privacy & Governance (15%)
3. Technical Accuracy (10%)
4. Service Value Evidence (15%)
5. Executive Clarity (15%)
6. Visual Quality (10%)
7. Actionability (10%)
8. Language Quality (10%)

Enforces 14 Automated Semantic Failure Conditions:
1. Zero denominator with a numeric percentage
2. Zero total with nonzero child categories
3. Sum of child counts not equal to total
4. Percentage distribution with a zero total
5. FTE greater than zero when approved effort basis is absent
6. KoçSistem action without evidence
7. Service KPI rendered when collection failed
8. Empty table rendered
9. Unloaded service omitted from executive completeness
10. Absolute compliance claim
11. Non-repudiation claim based only on SHA-256 and JSONL
12. Recommendation without owner
13. Report without a decision section
14. Static positive badge on unknown or failed data
"""

import sys
import os
import json
import re

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api.report_generator import (
    build_golden_mde_html,
    build_golden_purview_html,
    build_golden_consolidated_html
)

def check_semantic_rules(html_content, live_data=None, requested_services=None):
    findings = []
    
    if requested_services is None:
        requested_services = ["SVC-MDE"]

    # Rule 1: Zero denominator with a numeric percentage
    zero_den_patterns = [
        r"0\s+adedi.*?\(%[0-9.]+\s+koruma",
        r"0\s+Cihaz.*?%[0-9.]+\s+Uyum",
        r"0\s+Olay.*?%100",
        r"Koruma Oran[ıi]:\s*<b>%[0-9.]+"
    ]
    for pat in zero_den_patterns:
        if re.search(pat, html_content, re.IGNORECASE):
            if "0 Olay" in html_content or "0 Cihaz" in html_content or "0 adedi" in html_content:
                findings.append(f"FAIL [Rule 1]: Zero denominator produced numeric percentage matching '{pat}'")

    # Rule 2: Zero total with nonzero child categories
    if "0 Kural Aşımı" in html_content:
        override_rows = re.findall(r"<tr><td><b>[^<]+</b></td><td class=[\"']num[\"']>([1-9][0-9]*)</td>", html_content)
        if override_rows:
            findings.append(f"FAIL [Rule 2]: Zero total overrides but nonzero child category counts found: {override_rows}")

    # Rule 3: Sum of child counts not equal to total
    if live_data:
        for svc in ["SVC-PURVIEW", "SVC-PRV-DLP"]:
            prv_kpis = live_data.get(svc, {}).get("kpis", {})
            ovr_total = int(prv_kpis.get("OverrideEvents") or prv_kpis.get("UserOverrides") or 0)
            breakdown = prv_kpis.get("UserOverrideBreakdown") or []
            if breakdown and ovr_total > 0:
                child_sum = sum(int(b.get("Count", 0)) for b in breakdown)
                if child_sum != ovr_total:
                    findings.append(f"FAIL [Rule 3]: Override breakdown child sum ({child_sum}) != total ({ovr_total})")

    # Rule 4: Percentage distribution with a zero total
    if "0 Kural Aşımı" in html_content and "%100" in html_content:
        if "Kural Aşımı Nedeni" in html_content:
            findings.append("FAIL [Rule 4]: Rendered percentage distribution table for zero total overrides")

    # Rule 5: FTE greater than zero when approved effort basis is absent
    fte_matches = re.findall(r"~?([1-9][0-9]*\.?[0-9]*)\s*FTE", html_content)
    if fte_matches:
        for fte_val in fte_matches:
            if float(fte_val) > 0.0:
                if "0.0 sa" in html_content or "+0 Saat" in html_content or "0 Uzman Eforu" in html_content or "0 Uzman Müdahalesi" in html_content:
                    findings.append(f"FAIL [Rule 5]: FTE ({fte_val}) > 0 rendered while approved effort/hours is zero")

    # Rule 6: KoçSistem action without evidence
    if "Uzman Müdahalesi" in html_content or "Uzman Eforu" in html_content:
        nonzero_actions = re.search(r"([1-9][0-9]*)\s*(?:Uzman Eforu|Uzman Müdahalesi|doğrudan analist müdahalesi)", html_content)
        if nonzero_actions:
            if "Kanıt:" not in html_content and "RB-" not in html_content and "INC-" not in html_content:
                findings.append(f"FAIL [Rule 6]: KoçSistem action ({nonzero_actions.group(0)}) rendered without approved operational evidence ID")

    # Rule 7: Service KPI rendered when collection failed
    if live_data:
        for svc, s_data in live_data.items():
            if isinstance(s_data, dict) and s_data.get("availabilityState") == "CollectionFailed":
                if f'data-kpi-id="KPI-{svc}' in html_content:
                    findings.append(f"FAIL [Rule 7]: Service KPI card rendered for service '{svc}' whose collection state is CollectionFailed")

    # Rule 8: Empty table rendered
    empty_tables = re.findall(r"<table[^>]*>\s*(?:<tr>\s*(?:<th>[^<]*</th>\s*)+</tr>\s*)?</table>", html_content, re.IGNORECASE)
    if empty_tables:
        findings.append(f"FAIL [Rule 8]: Empty <table> tag with no data rows rendered ({len(empty_tables)} found)")

    # Rule 9: Unloaded service omitted from executive completeness
    if "Veri Toplama ve Servis Sağlık Durumu" not in html_content and "Collection Health" not in html_content:
        findings.append("FAIL [Rule 9]: Executive completeness / Collection Health section missing from Page 1")
    else:
        for svc in requested_services:
            if svc not in html_content:
                findings.append(f"FAIL [Rule 9]: Requested service '{svc}' omitted from executive completeness table")

    # Rule 10: Absolute compliance claim
    prohibited_abs = [
        r"%100\s*uyumlu",
        r"tam\s*uyumlu",
        r"100%\s*compliance",
        r"kusursuz",
        r"%100\s*Koruma",
        r"%100\.0\s*koruma\s*orani",
        r"%100\s*bağışıklık",
        r"%100\s*otonom\s*durdurulması\s*sağlandı",
        r"Uyum\s*Güvencesi",
        r"Resmi\s*Guvence\s*Beyani",
        r"Maddi\s*Sızıntı\s*Yoktur",
        r"Sıfır\s*İhlal\s*Güvencesi",
        r"Zero\s*Incident\s*Verified\s*Security"
    ]
    for pat in prohibited_abs:
        match = re.search(pat, html_content, re.IGNORECASE)
        if match:
            findings.append(f"FAIL [Rule 10]: Prohibited absolute claim found: '{match.group(0)}'")

    # Rule 11: Non-repudiation claim based only on SHA-256 and JSONL
    if "SHA-256" in html_content:
        if "inkar edilemezlik" in html_content and "tek başına" not in html_content:
            findings.append("FAIL [Rule 11]: Unqualified legal non-repudiation claim based on SHA-256 checksum")

    # Rule 12: Recommendation without owner
    rec_matches = re.findall(r"<tr>\s*<td><b>DEC-[^<]+-REC-[^<]+</b></td>\s*<td>([^<]+)</td>\s*<td>([^<]*)</td>", html_content)
    for rec in rec_matches:
        rec_title, rec_owner = rec[0].strip(), rec[1].strip()
        if not rec_owner or rec_owner == "" or rec_owner == "N/A":
            findings.append(f"FAIL [Rule 12]: Recommendation '{rec_title}' has no assigned owner (Sorumlu)")

    # Rule 13: Report without a decision section
    quadrants = ["Approved Decisions", "Pending Decisions", "Deferred Decisions", "Recommended Decisions"]
    for q in quadrants:
        if q not in html_content:
            findings.append(f"FAIL [Rule 13]: Decision framework quadrant '{q}' missing from report")

    # Rule 14: Static positive badge on unknown or failed data
    bad_badges = re.findall(r"<span class=[\"'](?:pill p-ok|badge positive)[\"']>\s*(?:N/A|0|Veri Toplanamadı|CollectionFailed|Hata|Kritik)\s*</span>", html_content, re.IGNORECASE)
    if bad_badges:
        findings.append(f"FAIL [Rule 14]: Static positive badge assigned to failed/zero/unknown value: {bad_badges}")

    return findings

def evaluate_report_quality(html_content, report_type="MDE", live_data=None, requested_services=None):
    semantic_failures = check_semantic_rules(html_content, live_data, requested_services)
    
    scores = {}
    details = []

    # 1. Data Integrity (15%)
    score_di = 10.0
    for f in semantic_failures:
        if any(r in f for r in ["Rule 1", "Rule 2", "Rule 3", "Rule 4"]):
            score_di -= 2.5
            details.append(f)
    for mock in ["385.000 USD", "840 TCKN", "42 Wacatac"]:
        if mock in html_content:
            score_di -= 3.0
            details.append(f"Data Integrity: Hallucinated mock found: '{mock}'")
    scores["Data Integrity"] = max(0.0, score_di)

    # 2. Privacy & Governance (15%)
    score_pg = 10.0
    for f in semantic_failures:
        if "Rule 11" in f:
            score_pg -= 3.0
            details.append(f)
    unmasked = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html_content)
    raw_emails = [e for e in unmasked if "***" not in e and not any(d in e for d in ["example.com", "w3.org", "domain.com", "kocsistem.com.tr", "cloudshield-mssp.com"])]
    if raw_emails:
        score_pg -= 4.0
        details.append(f"Privacy: Raw unmasked email: {raw_emails[:2]}")
    if "SHA-256" not in html_content:
        score_pg -= 2.0
        details.append("Privacy: Missing cryptographic SHA-256 integrity notice")
    scores["Privacy & Governance"] = max(0.0, score_pg)

    # 3. Technical Accuracy (10%)
    score_ta = 10.0
    for f in semantic_failures:
        if any(r in f for r in ["Rule 1", "Rule 10"]):
            score_ta -= 3.0
            details.append(f)
    scores["Technical Accuracy"] = max(0.0, score_ta)

    # 4. Service Value Evidence (15%)
    score_sve = 10.0
    for f in semantic_failures:
        if any(r in f for r in ["Rule 5", "Rule 6"]):
            score_sve -= 3.0
            details.append(f)
    required_pillars = ["Microsoft Teknolojisi", "KoçSistem Yönetilen", "Müşteri Eylem", "Ortak Başarı"]
    for p in required_pillars:
        if p not in html_content:
            score_sve -= 2.5
            details.append(f"Service Value: Missing attribution pillar matching '{p}'")
    scores["Service Value Evidence"] = max(0.0, score_sve)

    # 5. Executive Clarity (15%)
    score_ec = 10.0
    for f in semantic_failures:
        if any(r in f for r in ["Rule 9", "Rule 14"]):
            score_ec -= 2.0
            details.append(f)
    required_questions = ["1. Ne Oldu?", "2. Neden Önemli?", "3. Microsoft", "4. KoçSistem", "5. Ortamda Hangi", "6. Liderlikten Hangi"]
    for q in required_questions:
        if q not in html_content:
            score_ec -= 1.5
            details.append(f"Executive Clarity: Missing answer for question '{q}'")
    if "ciso-badge" not in html_content:
        score_ec -= 1.5
        details.append("Executive Clarity: Missing 30-second CISO posture badge")
    scores["Executive Clarity"] = max(0.0, score_ec)

    # 6. Visual Quality (10%)
    score_vq = 10.0
    for f in semantic_failures:
        if "Rule 8" in f:
            score_vq -= 3.0
            details.append(f)
    if "@page" not in html_content or "wrap" not in html_content:
        score_vq -= 3.0
        details.append("Visual Quality: Missing A4 vector print CSS directives")
    scores["Visual Quality"] = max(0.0, score_vq)

    # 7. Actionability (10%)
    score_act = 10.0
    for f in semantic_failures:
        if any(r in f for r in ["Rule 12", "Rule 13"]):
            score_act -= 3.0
            details.append(f)
    scores["Actionability"] = max(0.0, score_act)

    # 8. Language Quality (10%)
    score_lq = 10.0
    for f in semantic_failures:
        if "Rule 10" in f:
            score_lq -= 2.0
    if "Uyar?" in html_content or "B?t?nl?k" in html_content or "M??teri" in html_content:
        score_lq -= 4.0
        details.append("Language Quality: Corrupted ASCII question marks found in Turkish strings")
    scores["Language Quality"] = max(0.0, score_lq)

    weights = {
        "Data Integrity": 0.15,
        "Privacy & Governance": 0.15,
        "Technical Accuracy": 0.10,
        "Service Value Evidence": 0.15,
        "Executive Clarity": 0.15,
        "Visual Quality": 0.10,
        "Actionability": 0.10,
        "Language Quality": 0.10
    }
    composite = sum(scores[dim] * weights[dim] for dim in weights)
    
    passed = len(semantic_failures) == 0 and composite >= 8.5 and all(s >= 7.0 for s in scores.values())
    return {
        "composite": round(composite, 2),
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "semantic_failures": semantic_failures,
        "details": details,
        "passed": passed
    }

def run_all_gates():
    print("==================================================")
    print("  CloudShield MSSP Semantic Report Quality Gate   ")
    print("==================================================\n")

    active_fix_path = os.path.join(ROOT_DIR, "tests", "fixtures", "fixture_active_enterprise.json")
    with open(active_fix_path, "r", encoding="utf-8") as f:
        active_data = json.load(f)

    # Test 1: MDE Executive Report
    print("--- 1. Evaluating SVC-MDE Executive Report ---")
    mde_html = build_golden_mde_html(
        customer_name=active_data["tenant_name"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    mde_res = evaluate_report_quality(mde_html, "MDE", live_data=active_data, requested_services=["SVC-MDE"])
    print(f"MDE Composite: {mde_res['composite']} / 10.0 (Passed: {mde_res['passed']})")
    for dim, sc in mde_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if mde_res["semantic_failures"]:
        print("  Semantic Failures:")
        for sf in mde_res["semantic_failures"]:
            print(f"    * {sf}")
    print()

    # Test 2: Purview DLP Executive Report
    print("--- 2. Evaluating SVC-PURVIEW Executive Report ---")
    prv_html = build_golden_purview_html(
        customer_name=active_data["tenant_name"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    prv_res = evaluate_report_quality(prv_html, "Purview", live_data=active_data, requested_services=["SVC-PURVIEW"])
    print(f"Purview Composite: {prv_res['composite']} / 10.0 (Passed: {prv_res['passed']})")
    for dim, sc in prv_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if prv_res["semantic_failures"]:
        print("  Semantic Failures:")
        for sf in prv_res["semantic_failures"]:
            print(f"    * {sf}")
    print()

    # Test 3: Consolidated M365 E5 Report
    print("--- 3. Evaluating M365 E5 Consolidated Report ---")
    cons_html = build_golden_consolidated_html(
        customer_name=active_data["tenant_name"],
        services=["SVC-MDE", "SVC-PURVIEW"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    cons_res = evaluate_report_quality(cons_html, "Consolidated", live_data=active_data, requested_services=["SVC-MDE", "SVC-PURVIEW"])
    print(f"Consolidated Composite: {cons_res['composite']} / 10.0 (Passed: {cons_res['passed']})")
    for dim, sc in cons_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if cons_res["semantic_failures"]:
        print("  Semantic Failures:")
        for sf in cons_res["semantic_failures"]:
            print(f"    * {sf}")
    print()

    # Test 4: Live Customer Emre-TestTenant Report Artifact Audit
    print("--- 4. Evaluating Actual Customer Report: Rapor_Emre-TestTenant_2026-08.html ---")
    cust_report_path = os.path.join(ROOT_DIR, "Engine", "Output", "Emre-TestTenant", "2026-08", "Rapor_Emre-TestTenant_2026-08.html")
    cust_data_path = os.path.join(ROOT_DIR, "Engine", "Output", "Emre-TestTenant", "2026-08", "data.json")
    cust_data = {}
    if os.path.exists(cust_data_path):
        try:
            with open(cust_data_path, "r", encoding="utf-8-sig") as f:
                cust_data = json.load(f)
        except Exception:
            pass

    if os.path.exists(cust_report_path):
        with open(cust_report_path, "r", encoding="utf-8") as f:
            cust_html = f.read()
        cust_res = evaluate_report_quality(cust_html, "CustomerReport", live_data=cust_data, requested_services=["SVC-MDE"])
        print(f"Customer Report Composite: {cust_res['composite']} / 10.0 (Passed: {cust_res['passed']})")
        for dim, sc in cust_res["scores"].items():
            print(f"  - {dim}: {sc:.1f} / 10.0")
        if cust_res["semantic_failures"]:
            print("  Semantic Failures:")
            for sf in cust_res["semantic_failures"]:
                print(f"    * {sf}")
    else:
        print(f"  [WARN] {cust_report_path} not found.")
        cust_res = {"passed": False, "composite": 0.0}
    print()

    overall_passed = mde_res["passed"] and prv_res["passed"] and cons_res["passed"] and cust_res.get("passed", True)
    print("==================================================")
    if overall_passed:
        print("  RESULT: ALL QUALITY GATES PASSED! (>= 8.5 / 10.0, Zero Semantic Violations) ")
    else:
        print("  RESULT: QUALITY GATE FAILED — SEMANTIC DEFECTS PRESENT ")
    print("==================================================")
    return overall_passed, {"MDE": mde_res, "Purview": prv_res, "Consolidated": cons_res, "Customer": cust_res}

if __name__ == "__main__":
    passed, results = run_all_gates()
    sys.exit(0 if passed else 1)
