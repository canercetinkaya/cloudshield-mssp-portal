#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Historical Trends & Multilingual i18n Test Suite
===========================================================================
Validates:
1. Migration 002 schema integrity (tenant_historical_metrics & tenant_credential_health).
2. Time-series historical trend insertion and retrieval (record_tenant_trend, get_tenant_trends).
3. Credential lifecycle health tracking (update_tenant_credential_health, get_tenant_credential_health).
4. CustomerViewer role tenant isolation wall (cross-tenant 403 prevention).
5. Multilingual report generation (Turkish TR and English EN) in HTML and Page 2 trend integration.
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

_CUR_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.dirname(_CUR_DIR) if os.path.basename(_CUR_DIR) == "tests" else _CUR_DIR
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.helpers.stage1a_fixtures import isolated_database
from database.db import (
    get_db,
    record_tenant_trend,
    get_tenant_trends,
    update_tenant_credential_health,
    get_tenant_credential_health,
    hash_password
)
from Portal.api.rbac_engine import evaluate_access
from Portal.api.report_generator import (
    render_historical_trends_section,
    build_golden_consolidated_html,
    build_golden_mde_html
)


class TestHistoricalTrendsDatabase(unittest.TestCase):
    """Validates Migration 002 database schema and helper functions."""

    def test_migration_002_tables_exist(self):
        with isolated_database() as iso:
            conn = get_db(iso.db_path)
            try:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cur.fetchall()]
            finally:
                conn.close()

            self.assertIn("tenant_historical_metrics", tables)
            self.assertIn("tenant_credential_health", tables)

    def test_record_and_get_tenant_trends(self):
        with isolated_database() as iso:
            tid = "cust-iso-001"
            # Record 3 periods
            for i, period in enumerate(["2026-07", "2026-08", "2026-09"]):
                record_tenant_trend(
                    tenant_id=tid,
                    period=period,
                    service_code="CONSOLIDATED",
                    metrics={
                        "secure_score": 75.0 + (i * 5),
                        "threats_blocked": 100 + (i * 20),
                        "critical_incidents": 0,
                        "dlp_violations": 10 - i,
                        "phishing_blocked": 30 + i,
                        "hours_saved": 50.0 + (i * 10),
                        "cost_avoidance_usd": 10000.0
                    },
                    db_path=iso.db_path
                )

            # Retrieve trends (ordered chronologically ASC)
            trends = get_tenant_trends(tid, limit_months=12, db_path=iso.db_path)
            self.assertEqual(len(trends), 3)
            self.assertEqual(trends[0]["period"], "2026-07")
            self.assertEqual(trends[-1]["period"], "2026-09")
            self.assertEqual(trends[-1]["secure_score"], 85.0)
            self.assertEqual(trends[-1]["threats_blocked"], 140)

    def test_credential_health_tracking(self):
        with isolated_database() as iso:
            tid = "cust-iso-002"
            future_expiry = (datetime.now(timezone.utc) + timedelta(days=120)).isoformat()
            
            update_tenant_credential_health(
                tenant_id=tid,
                auth_type="ClientSecret",
                secret_expiry=future_expiry,
                cert_expiry=None,
                preflight_status="Healthy",
                days_left=120,
                health_status="Healthy",
                db_path=iso.db_path
            )

            rec = get_tenant_credential_health(tid, db_path=iso.db_path)
            self.assertIsNotNone(rec)
            self.assertEqual(rec["tenant_id"], tid)
            self.assertEqual(rec["health_status"], "Healthy")
            self.assertEqual(rec["auth_type"], "ClientSecret")
            self.assertEqual(rec["days_until_expiry"], 120)


class TestCustomerViewerTenantIsolation(unittest.TestCase):
    """Verifies that CustomerViewer users are strictly wall-isolated to their assigned tenant."""

    def test_customer_viewer_cross_tenant_denial(self):
        with isolated_database() as iso:
            conn = get_db(iso.db_path)
            viewer_id = "user-viewer-alpha"
            try:
                cur = conn.cursor()
                _, hashed_pw = hash_password("Secret123!")
                cur.execute("""
                    INSERT INTO users (id, upn, email, display_name, password_hash, is_active, created_at, organization_id)
                    VALUES (?, ?, ?, ?, ?, 1, ?, 'org-cloudshield')
                """, (viewer_id, "viewer@testtenant.com", "viewer@testtenant.com", "Tenant Viewer", hashed_pw, datetime.now(timezone.utc).isoformat()))

                now_str = datetime.now(timezone.utc).isoformat()
                cur.execute("""
                    INSERT INTO access_assignments (
                        id, subject_type, subject_id, role_id, customer_scope, customer_id,
                        service_scope, valid_from, is_active, created_by, created_at
                    ) VALUES (?, 'User', ?, 'role-customer-viewer', 'Specific', 'tenant-002', 'ALL', ?, 1, 'system', ?)
                """, ("assign-viewer-1", viewer_id, now_str, now_str))
                conn.commit()
            finally:
                conn.close()

            user_obj = {
                "id": viewer_id,
                "upn": "viewer@testtenant.com",
                "role": "CustomerViewer",
                "customerId": "tenant-002",
                "assignedTenants": ["tenant-002"]
            }

            # 1. Allowed: accessing reports on own tenant (tenant-002)
            allowed_own, reason_own = evaluate_access(
                user_obj,
                "reports:view",
                customer_id="tenant-002",
                resource="/api/tenants/tenant-002/reports"
            )
            self.assertTrue(allowed_own, f"CustomerViewer should access own tenant: {reason_own}")

            # 2. Denied (403): attempting to access reports of another tenant (cust-001)
            allowed_cross, reason_cross = evaluate_access(
                user_obj,
                "reports:view",
                customer_id="cust-001",
                resource="/api/tenants/cust-001/reports"
            )
            self.assertFalse(allowed_cross, "CustomerViewer must NOT access other tenant reports")
            self.assertIn("Müşteri Kapsam Hatası", reason_cross)

            # 3. Denied (403): CustomerViewer cannot manage tenants
            allowed_mgmt, _ = evaluate_access(
                user_obj,
                "customers:manage",
                customer_id="tenant-002",
                resource="/api/tenants/tenant-002"
            )
            self.assertFalse(allowed_mgmt, "CustomerViewer cannot have customers:manage permission")


class TestMultilingualReporting(unittest.TestCase):
    """Verifies Turkish (TR) and English (EN) report rendering and trend embedding."""

    def test_historical_trends_section_bilingual(self):
        with isolated_database() as iso:
            tid = "tenant-002"
            record_tenant_trend(
                tenant_id=tid,
                period="2026-09",
                service_code="CONSOLIDATED",
                metrics={"secure_score": 86.0, "threats_blocked": 142, "critical_incidents": 0, "dlp_violations": 12, "hours_saved": 88.5},
                db_path=iso.db_path
            )

            # Turkish Section
            html_tr = render_historical_trends_section(tid, language="tr", db_path=iso.db_path)
            self.assertIn("Tarihsel Güvenlik ve Uyum Gelişim Eğrisi", html_tr)
            self.assertIn("Secure Score", html_tr)
            self.assertIn("Bloke Tehdit", html_tr)
            self.assertIn("2026-09", html_tr)

            # English Section
            html_en = render_historical_trends_section(tid, language="en", db_path=iso.db_path)
            self.assertIn("Historical Security &amp; Compliance Trajectory", html_en)
            self.assertIn("Threats Blocked", html_en)
            self.assertIn("Critical Incidents", html_en)
            self.assertIn("Hours Saved", html_en)
            self.assertIn("2026-09", html_en)

    def test_consolidated_report_bilingual(self):
        # 1. Turkish Output
        html_tr = build_golden_consolidated_html("Test Kurumu A.Ş.", ["SVC-MDE", "SVC-PURVIEW"], language="tr")
        self.assertIn('<html lang="tr">', html_tr)
        self.assertIn("Aylık Birleşik Güvenlik ve Uyum Raporu", html_tr)
        self.assertIn("CloudShield MSSP Golden Standard", html_tr)
        self.assertIn("Sayfa 1 / 3", html_tr)

        # 2. English Output
        html_en = build_golden_consolidated_html("Test Enterprise Inc.", ["SVC-MDE", "SVC-PURVIEW"], language="en")
        self.assertIn('<html lang="en">', html_en)
        self.assertIn("Monthly Consolidated Security &amp; Compliance Report", html_en)
        self.assertIn("Historical Security &amp; Compliance Trajectory", html_en)
        self.assertIn("Threats Blocked", html_en)
        self.assertIn("Critical Incidents", html_en)
        self.assertIn("Page 1 / 3", html_en)
        self.assertIn("Disclaimer &amp; Legal Notice", html_en)

    def test_mde_report_bilingual(self):
        # 1. Turkish Output
        html_tr = build_golden_mde_html("Test Kurumu A.Ş.", language="tr")
        self.assertIn('<html lang="tr">', html_tr)
        self.assertIn("Aylık EDR Güvenlik Raporu", html_tr)

        # 2. English Output
        html_en = build_golden_mde_html("Test Enterprise Inc.", language="en")
        self.assertIn('<html lang="en">', html_en)
        self.assertIn("Monthly EDR Security Report", html_en)


if __name__ == "__main__":
    unittest.main()
