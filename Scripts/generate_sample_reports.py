#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield Security Reporting & Managed Services Visibility Platform
Sample Report Generator for Documentation Showcase (docs/samples)
Generates audit-grade HTML and PDF sample reports with explicit synthetic data watermarks.
"""

import os
import sys
import shutil

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PORTAL_API_DIR = os.path.join(ROOT_DIR, "Portal", "api")
if PORTAL_API_DIR not in sys.path:
    sys.path.insert(0, PORTAL_API_DIR)

from report_generator import generate_html_report, find_pdf_engine, create_executive_pdf

SAMPLES_DIR = os.path.join(ROOT_DIR, "docs", "samples")
os.makedirs(SAMPLES_DIR, exist_ok=True)

SAMPLE_CUSTOMER = "Demo Kurum A.S. (Ornek Musteri)"
PERIOD_TAG = "2026-08"
PERIOD_LABEL = "Agustos 2026 Donemi"
SAMPLE_BANNER = (
    '<div style="background:#fee2e2; border:2px dashed #ef4444; color:#991b1b; padding:10px 16px; '
    'font-size:12px; font-weight:700; text-align:center; border-radius:6px; margin:12px 0 16px 0;">'
    '&#9888;&#65039; ORNEK / SENTETIK VERI: Bu rapor yalnizca urun kabiliyetlerini gostermek amaciyla '
    'olusturulmustur. Gercek musteri veya canli tenant verisi icermez.</div>'
)

def convert_html_to_pdf(html_path, pdf_path):
    engine = find_pdf_engine()
    if engine:
        try:
            import subprocess
            html_uri = ("file:///" if sys.platform == "win32" else "file://") + os.path.abspath(html_path).replace("\\", "/")
            cmd = [
                engine,
                "--headless=new",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                html_uri
            ]
            subprocess.run(cmd, timeout=30, capture_output=True)
            if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) == 0:
                cmd[1] = "--headless"
                subprocess.run(cmd, timeout=30, capture_output=True)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                return pdf_path
        except Exception as ex:
            print(f"[WARN] Headless PDF creation failed: {ex}")
    return None

def build_samples():
    workloads = [
        ("sample_consolidated_report", ["SVC-MDE", "SVC-MDO", "SVC-INTUNE", "SVC-PURVIEW-DLP"], "Konsolide Guvenlik ve Uyum Raporu"),
        ("sample_mde_report", ["SVC-MDE"], "Microsoft Defender for Endpoint (EDR) Raporu"),
        ("sample_mdo_report", ["SVC-MDO"], "Microsoft Defender for Office 365 Raporu"),
        ("sample_intune_report", ["SVC-INTUNE"], "Microsoft Intune Cihaz Uyum & Hijyen Raporu"),
        ("sample_purview_dlp_report", ["SVC-PURVIEW-DLP"], "Microsoft Purview DLP Raporu"),
    ]

    print(f"[INFO] Generating sample reports in: {SAMPLES_DIR}")
    for fname, services, label in workloads:
        html_file = os.path.join(SAMPLES_DIR, f"{fname}.html")
        pdf_file = os.path.join(SAMPLES_DIR, f"{fname}.pdf")
        
        html_out = generate_html_report(
            customer_name=SAMPLE_CUSTOMER,
            services=services,
            period_tag=PERIOD_TAG,
            period_label=PERIOD_LABEL,
            live_data={},
            data_source_note="Gosterim Telemetrisi (Ornek Veri)",
            language="tr",
            tenant_id="tenant-demo"
        )
        
        # Inject the mandatory synthetic banner right after the first header if not present
        if "ORNEK / SENTETIK VERI" not in html_out:
            html_out = html_out.replace("</header>", f"</header>\n{SAMPLE_BANNER}", 1)

        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"[OK] Created HTML: {fname}.html ({len(html_out)} bytes)")

        # Attempt PDF creation
        pdf_res = convert_html_to_pdf(html_file, pdf_file)
        if pdf_res and os.path.exists(pdf_file):
            print(f"[OK] Created PDF:  {fname}.pdf ({os.path.getsize(pdf_file)} bytes)")
        else:
            try:
                create_executive_pdf(SAMPLE_CUSTOMER, services, pdf_file, PERIOD_LABEL)
                if os.path.exists(pdf_file):
                    print(f"[OK] Created PDF via fallback: {fname}.pdf ({os.path.getsize(pdf_file)} bytes)")
            except Exception as e:
                print(f"[INFO] PDF fallback skipped: {e}")

if __name__ == "__main__":
    build_samples()
