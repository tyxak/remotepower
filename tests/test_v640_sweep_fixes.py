"""v6.4.0 promise-vs-behavior sweep — fixes for text that lied about the code.

1. "Open alerts are never purged": the MAX_ALERTS count cap trimmed purely by
   insertion order, silently deleting the oldest STILL-OPEN alerts past 5000.
   _trim_alerts now evicts oldest RESOLVED entries first.
2. "Token is consumed atomically — same one can't enroll twice": the enroll
   consume was a lock-free load→check→delete→save (TOCTOU) — two concurrent
   enrolls could both pass. Now consumed under _LockedUpdate.
3. image_updates_enabled / image_scan_interval were read-only dead switches
   (code honored them, nothing could set them) — now writable + UI-exposed.
4. The runbook Delete half (client fn + server route) had no button; the
   runbook modal now carries one.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-swp-"))
_spec = importlib.util.spec_from_file_location("api_v640_swp", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestAlertCapKeepsOpenAlerts(unittest.TestCase):
    def test_resolved_evicted_first(self):
        open_alerts = [{"id": f"o{i}", "event": "x"} for i in range(10)]
        resolved = [{"id": f"r{i}", "event": "x", "resolved_at": 1}
                    for i in range(api.MAX_ALERTS)]
        alerts = open_alerts + resolved   # 5010 total, oldest are OPEN
        api._trim_alerts(alerts)
        self.assertEqual(len(alerts), api.MAX_ALERTS)
        ids = {a["id"] for a in alerts}
        for i in range(10):
            self.assertIn(f"o{i}", ids,
                          "an OPEN alert was evicted while resolved ones remained")
        # the oldest RESOLVED entries were the ones dropped
        self.assertNotIn("r0", ids)

    def test_all_open_pathology_still_bounds_the_store(self):
        alerts = [{"id": f"o{i}", "event": "x"}
                  for i in range(api.MAX_ALERTS + 7)]
        api._trim_alerts(alerts)
        self.assertEqual(len(alerts), api.MAX_ALERTS)
        self.assertNotIn("o0", {a["id"] for a in alerts})   # oldest open go last

    def test_no_bare_slice_cap_remains(self):
        src = (_CGI / "api.py").read_text()
        self.assertNotIn("del alerts[:-MAX_ALERTS]", src)
        self.assertNotIn("del arr[:-MAX_ALERTS]", src)


class TestEnrollTokenConsumeIsLocked(unittest.TestCase):
    def test_consume_happens_under_the_store_lock(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("Invalid enrollment token format")
        block = src[i:i + 1500]
        self.assertIn("_LockedUpdate(ENROLL_TOKENS_FILE)", block,
                      "enroll-token consume must be atomic (docs promise "
                      "'consumed atomically — same one can't enroll twice')")
        self.assertNotIn("tokens = load(ENROLL_TOKENS_FILE)", block,
                         "lock-free load→check→delete→save is the TOCTOU shape")


class TestImageSwitchesAreWritable(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("CONFIG_FILE", "USERS_FILE", "ROLES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "t"
        api.verify_token = lambda t: ("t", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def _save(self, body):
        api.get_json_obj = lambda: body
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return api.load(api.CONFIG_FILE) or {}

    def test_both_keys_persist_and_clamp(self):
        cfg = self._save({"image_updates_enabled": False,
                          "image_scan_interval": 6 * 3600})
        self.assertIs(cfg.get("image_updates_enabled"), False)
        self.assertEqual(cfg.get("image_scan_interval"), 6 * 3600)
        cfg = self._save({"image_scan_interval": 10})     # below floor
        self.assertEqual(cfg.get("image_scan_interval"), 3600)

    def test_ui_exposes_both(self):
        html = (ROOT / "server" / "html" / "index.html").read_text()
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        for needle in ('id="cfg-image-updates-enabled"',
                       'id="cfg-image-scan-hours"'):
            self.assertIn(needle, html, needle)
        self.assertIn("payload.image_updates_enabled", js)
        self.assertIn("payload.image_scan_interval", js)


class TestRunbookDeleteIsReachable(unittest.TestCase):
    def test_modal_carries_the_delete_button(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn('data-action="runbookModalDelete"', js)
        self.assertIn("async function runbookModalDelete", js)
        self.assertIn("aiDeleteRunbook(_runbookCurrentDevice.id)", js)
        aijs = (ROOT / "server" / "html" / "static" / "js" / "app-ai.js").read_text()
        self.assertIn("runbook-modal-delete", aijs,
                      "the delete button must be revealed alongside Regenerate")


if __name__ == "__main__":
    unittest.main()
