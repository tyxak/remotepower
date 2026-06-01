"""
Regression tests for the mitigate / batch-tracker RBAC fixes and the CSV
formula-injection hardening.

Pure stdlib ``unittest`` (no pytest) so it runs identically under
``python -m unittest discover`` — which is what ``make dist`` uses to test the
staged release tree — and under pytest.

Covers:
  * handle_mitigate_investigate / handle_mitigate_fix — a read-only viewer and an
    out-of-scope custom (operator) role both get 403; an in-scope operator is NOT
    blocked by RBAC.
  * handle_exec_batch_status — a scoped caller never sees per-device entries for
    out-of-scope devices.
  * handle_batch_jobs_list — a scoped caller's job counts are recomputed over
    in-scope targets only, and jobs with zero in-scope targets are omitted.
  * _csv_safe — leading =, +, -, @, tab, CR are neutralized with a leading single
    quote; benign values are untouched.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# api.py creates DATA_DIR at import time; point it at a throwaway tmp dir so the
# import doesn't try to mkdir the production path (/var/lib/remotepower).
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

NOW = int(time.time())


class _Base(unittest.TestCase):
    """Point api.py's flat-file paths at a fresh tmp dir and stub the auth/IO
    helpers so a chosen identity is 'logged in'. Originals are restored in
    tearDown so the patches never leak into other test modules."""

    _FILES = ("DEVICES_FILE", "ROLES_FILE", "CMDS_FILE", "CMD_OUTPUT_FILE",
              "BATCH_JOBS_FILE", "SCRIPTS_FILE", "HISTORY_FILE",
              "AUDIT_LOG_FILE", "WEBHOOKS_FILE")
    _FUNCS = ("get_token_from_request", "verify_token", "get_json_body",
              "respond", "audit_log", "log_command")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a, None) for a in self._FILES}
        for a in self._FILES:
            setattr(api, a, self.tmp / (a.lower().replace("_file", "") + ".json"))
        self._saved_fns = {f: getattr(api, f) for f in self._FUNCS}
        # respond() raises HTTPError in production; pin it (other test modules
        # patch it globally, sometimes without restoring) so call() can capture.
        api.respond = lambda status, body=None: (_ for _ in ()).throw(api.HTTPError(status, body))
        api.get_json_body = lambda: {}
        api.audit_log = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        for f, v in self._saved_fns.items():
            setattr(api, f, v)
        api._LOAD_CACHE.clear()

    # ── seed / caller helpers ───────────────────────────────────────────────
    def seed_devices(self, devs):
        api.save(api.DEVICES_FILE, devs); api._LOAD_CACHE.clear()

    def seed_roles(self, roles):
        api.save(api.ROLES_FILE, {"roles": roles}); api._LOAD_CACHE.clear()

    def seed_jobs(self, jobs):
        api.save(api.BATCH_JOBS_FILE, {"jobs": jobs}); api._LOAD_CACHE.clear()

    def set_caller(self, user, role):
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda tok: (user, role)

    def set_body(self, payload):
        api.get_json_body = lambda: dict(payload)

    def call(self, handler, *args):
        try:
            handler(*args)
        except api.HTTPError as e:
            return ("http", e.status, e.body)
        return ("ok", None, None)


_OP_ROLE = [{"name": "op", "permissions": ["exec"],
             "scope": {"type": "groups", "values": ["prod"]}}]


class TestMitigateRbac(_Base):
    def test_investigate_viewer_blocked(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"}})
        self.set_caller("v", "viewer")
        self.set_body({"kind": "service_down", "target": "nginx"})
        kind, status, _ = self.call(api.handle_mitigate_investigate, "dev1")
        self.assertEqual((kind, status), ("http", 403))

    def test_fix_viewer_blocked(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"}})
        self.set_caller("v", "viewer")
        self.set_body({"kind": "service_down", "target": "nginx",
                       "command": "systemctl restart nginx", "confirmation": "RUN"})
        kind, status, _ = self.call(api.handle_mitigate_fix, "dev1")
        self.assertEqual((kind, status), ("http", 403))

    def test_investigate_out_of_scope_blocked(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"}})
        self.seed_roles(_OP_ROLE)
        self.set_caller("o", "op")
        self.set_body({"kind": "service_down", "target": "nginx"})
        kind, status, _ = self.call(api.handle_mitigate_investigate, "dev2")
        self.assertEqual((kind, status), ("http", 403))

    def test_fix_out_of_scope_blocked(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"}})
        self.seed_roles(_OP_ROLE)
        self.set_caller("o", "op")
        self.set_body({"kind": "service_down", "target": "nginx",
                       "command": "systemctl restart nginx", "confirmation": "RUN"})
        kind, status, _ = self.call(api.handle_mitigate_fix, "dev2")
        self.assertEqual((kind, status), ("http", 403))

    def test_investigate_in_scope_operator_not_rbac_blocked(self):
        """An in-scope operator with 'exec' must NOT be 403'd by RBAC (the call
        may still 400 if there's no playbook, but never 403)."""
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"}})
        self.seed_roles(_OP_ROLE)
        self.set_caller("o", "op")
        self.set_body({"kind": "service_down", "target": "nginx"})
        kind, status, _ = self.call(api.handle_mitigate_investigate, "dev1")
        self.assertFalse(kind == "http" and status == 403)


class TestBatchScope(_Base):
    def _mixed_job(self):
        return {"job1": {
            "kind": "install", "label": "install nginx", "created": NOW,
            "actor": "admin", "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}}}}

    def test_status_hides_out_of_scope_devices(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"}})
        self.seed_roles(_OP_ROLE)
        self.seed_jobs(self._mixed_job())
        self.set_caller("o", "op")
        kind, status, data = self.call(api.handle_exec_batch_status, "job1")
        self.assertEqual((kind, status), ("http", 200))
        self.assertEqual(set(data["per_device"].keys()), {"dev1"})

    def test_status_admin_sees_all(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"}})
        self.seed_jobs(self._mixed_job())
        self.set_caller("a", "admin")
        kind, status, data = self.call(api.handle_exec_batch_status, "job1")
        self.assertEqual((kind, status), ("http", 200))
        self.assertEqual(set(data["per_device"].keys()), {"dev1", "dev2"})

    def test_jobs_list_scopes_counts_and_omits(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"},
                           "dev3": {"name": "n3", "group": "dev"}})
        self.seed_roles(_OP_ROLE)
        self.seed_jobs({
            "jobA": {"kind": "install", "label": "install nginx", "created": NOW,
                     "actor": "admin", "match_cmd": "exec:apt-get install -y nginx",
                     "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}}},
            "jobB": {"kind": "install", "label": "install secret-pkg", "created": NOW - 10,
                     "actor": "admin", "match_cmd": "exec:apt-get install -y secret-pkg",
                     "per_device": {"dev2": {"queued": True}, "dev3": {"queued": True}}},
        })
        self.set_caller("o", "op")
        kind, status, data = self.call(api.handle_batch_jobs_list)
        self.assertEqual((kind, status), ("http", 200))
        jobs = {j["id"]: j for j in data["jobs"]}
        self.assertEqual(set(jobs.keys()), {"jobA"})        # jobB has no in-scope target
        self.assertEqual(jobs["jobA"]["total"], 1)          # only dev1 counted
        self.assertTrue(all("secret-pkg" not in j["label"] for j in data["jobs"]))

    def test_jobs_list_admin_unchanged(self):
        self.seed_devices({"dev1": {"name": "n1", "group": "prod"},
                           "dev2": {"name": "n2", "group": "dev"}})
        self.seed_jobs(self._mixed_job_named("jobA"))
        self.set_caller("a", "admin")
        kind, status, data = self.call(api.handle_batch_jobs_list)
        self.assertEqual((kind, status), ("http", 200))
        jobs = {j["id"]: j for j in data["jobs"]}
        self.assertEqual(jobs["jobA"]["total"], 2)

    def _mixed_job_named(self, jid):
        return {jid: {
            "kind": "install", "label": "install nginx", "created": NOW,
            "actor": "admin", "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}}}}


class TestCsvSafe(unittest.TestCase):
    def test_quotes_dangerous_leading_chars(self):
        for raw in ("=cmd()", "+1+1", "-2+3", "@SUM(A1)", "\tfoo", "\rbar"):
            with self.subTest(raw=raw):
                self.assertEqual(api._csv_safe(raw), "'" + raw)

    def test_leaves_benign_untouched(self):
        for raw in ("nginx", "web-01", "prod", "Ubuntu 22.04", ""):
            with self.subTest(raw=raw):
                self.assertEqual(api._csv_safe(raw), raw)

    def test_passes_non_strings(self):
        self.assertEqual(api._csv_safe(5), 5)
        self.assertIsNone(api._csv_safe(None))


if __name__ == "__main__":
    unittest.main()
