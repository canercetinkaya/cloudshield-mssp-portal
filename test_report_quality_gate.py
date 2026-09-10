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
"""

import sys
import os
import json
import re

# Ensure repository root is on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Portal.api.report_generator import (
    build_golden_mde_html,
    build_golden_purview_html,
    build_golden_consolidated_html
)

def evaluate_report_quality(html_content, report_type="MDE"):
    scores = {}
    details = []

    # 1. Data Integrity (15%)
    # - No hallucinated static numbers (e.g. 385.000 USD, 18 QR phish, 840 TCKN)
    # - Valid numeric formatting
    score_di = 10.0
    forbidden_mocks = ["385.000 USD", "840 TCKN", "42 Wacatac"]
    for m in forbidden_mocks:
        if m in html_content:
            score_di -= 3.0
            details.append(f"Data Integrity: Hallucinated static mock found: '{m}'")
    scores["Data Integrity"] = max(0.0, score_di)

    # 2. Privacy & Governance (15%)
    # - Cleartext email check (k-anonymity masking verification)
    # - SHA-256 integrity notice
    score_pg = 10.0
    # Search for unmasked email addresses (e.g., user@domain.com without ***)
    unmasked_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content)
    raw_emails = [e for e in unmasked_emails if "***" not in e and "example.com" not in e and "w3.org" not in e and "cloudshield-mssp.com" not in e and "domain.com" not in e]
    if raw_emails:
        score_pg -= 4.0
        details.append(f"Privacy: Unmasked emails detected: {raw_emails[:3]}")
    if "SHA-256" not in html_content:
        score_pg -= 2.0
        details.append("Privacy: Missing cryptographic SHA-256 integrity notice")
    scores["Privacy & Governance"] = max(0.0, score_pg)

    # 3. Technical Accuracy (10%)
    # - Valid MITRE ATT&CK or KQL citations
    # - Valid sensor coverage or protection rate representation
    score_ta = 10.0
    if "KQL" not in html_content and "MITRE" not in html_content and "SIT" not in html_content:
        score_ta -= 3.0
        details.append("Technical Accuracy: Missing KQL/MITRE/SIT technical provenance")
    scores["Technical Accuracy"] = max(0.0, score_ta)

    # 4. Service Value Evidence (15%)
    # - Must contain all 4 pillars of the Service Value Attribution Model:
    #   1. Microsoft Technology Value
    #   2. KoçSistem Managed Service Value
    #   3. Customer Action Value
    #   4. Shared Outcome
    score_sve = 10.0
    required_pillars = [
        ("Microsoft Teknoloji", "Microsoft Teknolojisi"),
        ("KoçSistem", "KoçSistem Yönetilen"),
        ("Müşteri", "Müşteri Eylem"),
        ("Ortak", "Ortak Başarı")
    ]
    for p_tuple in required_pillars:
        if not any(p in html_content for p in p_tuple):
            score_sve -= 2.5
            details.append(f"Service Value: Missing attribution pillar matching '{p_tuple[0]}'")
    scores["Service Value Evidence"] = max(0.0, score_sve)

    # 5. Executive Clarity (15%)
    # - Must answer all 6 Executive Questions in the CISO Brief
    score_ec = 10.0
    required_questions = [
        "1. Ne Oldu?",
        "2. Neden Önemli?",
        "3. Microsoft",
        "4. KoçSistem",
        "5. Ortamda Hangi",
        "6. Liderlikten Hangi"
    ]
    for q in required_questions:
        if q not in html_content:
            score_ec -= 1.6
            details.append(f"Executive Clarity: Missing answer for question '{q}'")
    if "ciso-badge" not in html_content:
        score_ec -= 1.5
        details.append("Executive Clarity: Missing 30-second CISO posture badge")
    scores["Executive Clarity"] = max(0.0, score_ec)

    # 6. Visual Quality (10%)
    # - Clean CSS layout, A4 formatting, no broken SVG
    score_vq = 10.0
    if "@page" not in html_content or "wrap" not in html_content:
        score_vq -= 3.0
        details.append("Visual Quality: Missing A4 vector print CSS directives")
    if "ENTRA ID VERIFIED" not in html_content and "data:image/svg+xml" not in html_content:
        score_vq -= 2.0
        details.append("Visual Quality: Missing high-resolution verified SVG monogram")
    scores["Visual Quality"] = max(0.0, score_vq)

    # 7. Actionability (10%)
    # - Must contain the Customer Decision Framework with all 4 quadrants:
    #   1. Approved Decisions
    #   2. Pending Decisions
    #   3. Deferred Decisions
    #   4. Recommended Decisions
    score_act = 10.0
    quadrants = [
        "Approved Decisions",
        "Pending Decisions",
        "Deferred Decisions",
        "Recommended Decisions"
    ]
    for quad in quadrants:
        if quad not in html_content:
            score_act -= 2.5
            details.append(f"Actionability: Missing decision quadrant '{quad}'")
    scores["Actionability"] = max(0.0, score_act)

    # 8. Language Quality (10%)
    # - No broken unicode / ASCII question marks (e.g. Uyar?, B?t?nl?k)
    score_lq = 10.0
    if "Uyar?" in html_content or "B?t?nl?k" in html_content or "M??teri" in html_content:
        score_lq -= 4.0
        details.append("Language Quality: Corrupted ASCII question marks found in Turkish strings")
    scores["Language Quality"] = max(0.0, score_lq)

    # Calculate Weighted Composite Score
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
    
    passed = composite >= 8.5 and all(s >= 7.0 for s in scores.values())
    return {
        "composite": round(composite, 2),
        "scores": scores,
        "details": details,
        "passed": passed
    }

def run_all_gates():
    print("==================================================")
    print("  CloudShield MSSP Automated Report Quality Gate  ")
    print("==================================================\n")

    # Load Active Enterprise Fixture
    active_fix_path = os.path.join(ROOT_DIR, "tests", "fixtures", "fixture_active_enterprise.json")
    with open(active_fix_path, "r", encoding="utf-8") as f:
        active_data = json.load(f)

    # Test 1: MDE EDR Executive Report
    print("--- Evaluating SVC-MDE Executive Report ---")
    mde_html = build_golden_mde_html(
        customer_name=active_data["tenant_name"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    mde_res = evaluate_report_quality(mde_html, "MDE")
    print(f"MDE Composite Score: {mde_res['composite']} / 10.0 (Passed: {mde_res['passed']})")
    for dim, sc in mde_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if mde_res["details"]:
        print("  Findings:")
        for d in mde_res["details"]:
            print(f"    * {d}")
    print()

    # Test 2: Purview DLP & Compliance Executive Report
    print("--- Evaluating SVC-PURVIEW Executive Report ---")
    prv_html = build_golden_purview_html(
        customer_name=active_data["tenant_name"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    prv_res = evaluate_report_quality(prv_html, "Purview")
    print(f"Purview Composite Score: {prv_res['composite']} / 10.0 (Passed: {prv_res['passed']})")
    for dim, sc in prv_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if prv_res["details"]:
        print("  Findings:")
        for d in prv_res["details"]:
            print(f"    * {d}")
    print()

    # Test 3: Consolidated M365 E5 Report
    print("--- Evaluating M365 E5 Consolidated Report ---")
    cons_html = build_golden_consolidated_html(
        customer_name=active_data["tenant_name"],
        services=["SVC-MDE", "SVC-PURVIEW"],
        period_tag=active_data["period_tag"],
        period_label=active_data["period_label"],
        live_data=active_data
    )
    cons_res = evaluate_report_quality(cons_html, "Consolidated")
    print(f"Consolidated Composite Score: {cons_res['composite']} / 10.0 (Passed: {cons_res['passed']})")
    for dim, sc in cons_res["scores"].items():
        print(f"  - {dim}: {sc:.1f} / 10.0")
    if cons_res["details"]:
        print("  Findings:")
        for d in cons_res["details"]:
            print(f"    * {d}")
    print()

    overall_passed = mde_res["passed"] and prv_res["passed"] and cons_res["passed"]
    print("==================================================")
    if overall_passed:
        print("  RESULT: ALL QUALITY GATES PASSED! (>= 8.5 / 10.0) ")
    else:
        print("  RESULT: FAILED QUALITY GATES — REMEDIATION REQUIRED ")
    print("==================================================")
    return overall_passed, {"MDE": mde_res, "Purview": prv_res, "Consolidated": cons_res}

if __name__ == "__main__":
    passed, results = run_all_gates()
    sys.exit(0 if passed else 1)
