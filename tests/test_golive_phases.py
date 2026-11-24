#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go-Live Hardening Verification Suite (Phases 1, 2, and 3):
- Phase 1: Fail-closed JWT, random session secret, literal password rejection
- Phase 2: Unified SQLite /api/users sync, honest /api/dispatch/send, live license guard,
           zero-synthetic-multiplier cockpit & persistent CISO decision approvals
- Phase 3: Async report job queue (202 + polling), static /tailwind.min.css & strict CSP
"""

import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from tests.helpers.stage1a_fixtures import IsolatedServer, ROOT_DIR


class TestGoLivePhases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="cs_golive_test_")
        tmp_root = cls._tmp.name
        cls.data_dir = os.path.join(tmp_root, "Data")
        cls.out_dir = os.path.join(tmp_root, "Output")
        os.makedirs(cls.data_dir, exist_ok=True)
        os.makedirs(cls.out_dir, exist_ok=True)
        src_data = os.path.join(ROOT_DIR, "Data")
        for fn in ("tenants.json", "users.json", "dispatch_logs.json", "auth_config.json", "version.json"):
            sp = os.path.join(src_data, fn)
            if os.path.exists(sp):
                shutil.copy2(sp, os.path.join(cls.data_dir, fn))

        cls._prev_data = os.environ.get("CLOUDSHIELD_DATA_DIR")
        cls._prev_out = os.environ.get("CLOUDSHIELD_OUTPUT_DIR")
        os.environ["CLOUDSHIELD_DATA_DIR"] = cls.data_dir
        os.environ["CLOUDSHIELD_OUTPUT_DIR"] = cls.out_dir

        cls.srv = IsolatedServer(tmp_root)
        cls.srv.__enter__()
        cls.base_url = cls.srv.base_url
        cls.admin_token = cls.srv.create_session("usr-001")

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)
        if cls._prev_data is None:
            os.environ.pop("CLOUDSHIELD_DATA_DIR", None)
        else:
            os.environ["CLOUDSHIELD_DATA_DIR"] = cls._prev_data
        if cls._prev_out is None:
            os.environ.pop("CLOUDSHIELD_OUTPUT_DIR", None)
        else:
            os.environ["CLOUDSHIELD_OUTPUT_DIR"] = cls._prev_out
        cls._tmp.cleanup()

    def _req(self, method, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=35) as resp:
                raw = resp.read()
                ct = resp.headers.get("Content-Type", "")
                parsed = json.loads(raw.decode("utf-8")) if "application/json" in ct else raw.decode("utf-8", errors="ignore")
                return resp.status, parsed, dict(resp.headers)
        except urllib.error.HTTPError as he:
            raw = he.read()
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                parsed = raw.decode("utf-8", errors="ignore")
            return he.code, parsed, dict(he.headers)

    def test_01_pyjwt_fail_closed_when_missing(self):
        from Portal.api import server as srv_mod
        with patch.object(srv_mod, "jwt", None):
            with self.assertRaises(ValueError) as ctx:
                srv_mod.verify_entra_id_token("a.b.c", "tid", "cid")
            self.assertIn("fail-closed", str(ctx.exception).lower())

    def test_02_unified_users_crud_syncs_with_sqlite(self):
        test_upn = "golive.engineer@cloudshield-mssp.com"
        st, created, _ = self._req(
            "POST",
            "/api/users",
            {
                "DisplayName": "GoLive Security Engineer",
                "Upn": test_upn,
                "Email": test_upn,
                "Role": "SecurityEngineer",
                "Department": "MSSP Operations",
                "AssignedTenants": ["tenant-002"],
            },
            token=self.admin_token,
        )
        self.assertEqual(st, 201)
        uid = created["user"]["Id"]

        st_get, users_list, _ = self._req("GET", "/api/users", token=self.admin_token)
        self.assertEqual(st_get, 200)
        self.assertTrue(any(u.get("Id") == uid and u.get("Upn") == test_upn for u in users_list))

        conn = sqlite3.connect(self.srv.db_path)
        cur = conn.cursor()
        cur.execute("SELECT id, upn FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], test_upn)

        st_del, _, _ = self._req("DELETE", f"/api/users/{uid}", token=self.admin_token)
        self.assertEqual(st_del, 200)
        conn2 = sqlite3.connect(self.srv.db_path)
        cur2 = conn2.cursor()
        cur2.execute("SELECT id FROM users WHERE id = ?", (uid,))
        self.assertIsNone(cur2.fetchone())
        conn2.close()

    def test_03_cockpit_and_persistent_decision_approval(self):
        st, body, _ = self._req("GET", "/api/tenants/tenant-002/cockpit", token=self.admin_token)
        self.assertEqual(st, 200)
        self.assertTrue(body.get("success"))
        self.assertIn("decisions", body)

        st_app, app_body, _ = self._req(
            "POST",
            "/api/tenants/tenant-002/decisions/approve",
            {"decisionId": "DEC-M365-PEND-01"},
            token=self.admin_token,
        )
        self.assertEqual(st_app, 200)
        self.assertEqual(app_body["decision"]["status"], "Approved")

        st2, body2, _ = self._req("GET", "/api/tenants/tenant-002/cockpit", token=self.admin_token)
        self.assertEqual(st2, 200)
        dec = next(d for d in body2["decisions"] if d["id"] == "DEC-M365-PEND-01")
        self.assertEqual(dec["status"], "Approved")

    def test_04_honest_dispatch_and_live_license_guard(self):
        st, disp, _ = self._req(
            "POST",
            "/api/dispatch/send",
            {"tenantId": "tenant-002", "attachPdf": False, "attachHtml": True},
            token=self.admin_token,
        )
        self.assertEqual(st, 200)
        self.assertIn(disp["dispatch"]["status"], ("ArchivedOnly", "Simulated"))
        self.assertIsNotNone(disp["dispatch"]["htmlAttached"])

        st_lic, lic_body, _ = self._req(
            "POST",
            "/api/licenses/collect",
            {"tenantId": "tenant-002", "dryRun": False},
            token=self.admin_token,
        )
        self.assertEqual(st_lic, 422)
        self.assertFalse(lic_body.get("success"))

    def test_05_async_report_job_queue_and_compiled_tailwind(self):
        st_css, css_body, hdrs = self._req("GET", "/tailwind.min.css")
        self.assertEqual(st_css, 200)
        self.assertGreater(len(css_body), 10000)
        csp = hdrs.get("Content-Security-Policy", "")
        self.assertNotIn("cdn.tailwindcss.com", csp)

        st_job, job_init, _ = self._req(
            "POST",
            "/api/reports/generate",
            {"tenantId": "tenant-002", "services": ["SVC-MDE"], "mode": "Monthly", "dryRun": True, "async": True},
            token=self.admin_token,
        )
        self.assertEqual(st_job, 202)
        job_id = job_init["jobId"]

        final_job = None
        for _ in range(40):
            time.sleep(0.5)
            st_p, poll_b, _ = self._req("GET", f"/api/reports/jobs/{job_id}", token=self.admin_token)
            self.assertEqual(st_p, 200)
            if poll_b["job"]["status"] in ("Completed", "Failed"):
                final_job = poll_b["job"]
                break

        self.assertIsNotNone(final_job, "Async report job did not finish within timeout")
        self.assertEqual(final_job["status"], "Completed")
        self.assertTrue(final_job.get("htmlUrl") or final_job.get("pdfUrl"))


if __name__ == "__main__":
    unittest.main()
