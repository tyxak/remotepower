#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, finding W2-F2): Provisioning works on a fresh install.

Provisioning became a standard module in 6.0.0 and its opt-in toggle was removed. The handlers still asked `_provisioning_enabled()`,
which read the old `show_provisioning` key, and a fresh install has no such key. So `GET /api/provisioning/blueprints` answered
`enabled: false` and every write answered 403 "Provisioning is disabled", while the page, the home payload and the docs all said it
was available and nothing in the interface could turn it on.

What this holds: a configuration with no key at all, and one with the key stored as off (an install that saved the old toggle), both
get a working list and a working create; the blueprint is there afterwards; the key is ignored in both directions; the integrations
answer reports what is true; and no empty state in the page points at a setting that does not exist.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-prov-"))

_spec = importlib.util.spec_from_file_location("api_v750_prov", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-prov-d-"))
        self._saved = {n: getattr(api, n) for n in ("CONFIG_FILE", "PROVISION_FILE")}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)   # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        api.save(api.PROVISION_FILE, {"blueprints": []})
        for name, value in (("verify_token", lambda token=None, *a, **k: ("alice", "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("audit_log", lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def config(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def call(self, fn, method="GET", body=None):
        with mock.patch.object(api, "method", lambda: method), \
                mock.patch.object(api, "get_json_obj", lambda: dict(body or {})), \
                mock.patch.object(api, "_read_valid", lambda model, *a, **k: dict(body or {})):
            try:
                fn()
            except api.HTTPError as e:
                return e.status, e.body
        self.fail("answered nothing")


class TestAFreshInstall(_Base):

    def work(self):
        status, body = self.call(api.handle_blueprints_list)
        self.assertEqual((status, body.get("enabled")), (200, True), body)
        status, body = self.call(api.handle_blueprint_create, "POST",
                                 {"name": "web", "kind": "cloud-init", "content": "#cloud-config\nhostname: ${host}\n"})
        self.assertIn(status, (200, 201), body)
        status, body = self.call(api.handle_blueprints_list)
        self.assertEqual([b["name"] for b in body["blueprints"]], ["web"], "what was created is there afterwards")

    def test_with_no_key_at_all(self):
        self.config()
        self.assertNotIn("show_provisioning", api.load(api.CONFIG_FILE))
        self.work()

    def test_with_the_old_toggle_stored_as_off(self):
        """An install that saved the 5.x toggle off has no toggle left to turn it back on: the stored value is ignored."""
        self.config(show_provisioning=False)
        self.work()

    def test_with_the_old_toggle_stored_as_on(self):
        self.config(show_provisioning=True)
        self.work()

    def test_the_switch_is_one_function_and_it_says_yes(self):
        for cfg in ({}, {"show_provisioning": False}, {"show_provisioning": True}):
            self.config(**cfg)
            self.assertIs(api._provisioning_enabled(), True, cfg)

    def test_render_and_delete_are_not_refused_either(self):
        self.config()
        status, body = self.call(api.handle_blueprint_create, "POST", {"name": "w", "kind": "cloud-init", "content": "hello ${x}"})
        self.assertIn(status, (200, 201), body)
        bid = body.get("id") or (body.get("blueprint") or {}).get("id")
        self.assertTrue(bid, body)
        status, body = self.call(lambda: api.handle_blueprint_render(bid), "POST", {"values": {"x": "world"}})
        self.assertEqual(status, 200, body)
        status, body = self.call(lambda: api.handle_blueprint_delete(bid), "DELETE")
        self.assertEqual(status, 200, body)

    def test_the_integrations_answer_does_not_report_a_flag_that_decides_nothing_as_off(self):
        self.config()
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        with mock.patch.object(api, "method", lambda: "GET"):
            try:
                api.handle_integrations_list()
            except api.HTTPError as e:
                self.assertEqual(e.status, 200, e.body)
                self.assertIs(e.body.get("show_provisioning"), True)
                return
        self.fail("answered nothing")


class TestThePageDoesNotPointAtAMissingSetting(unittest.TestCase):

    def test_no_empty_state_tells_you_to_enable_it_under_settings(self):
        js = (_JS / "app-provisioning.js").read_text()
        self.assertNotIn("Provisioning is disabled", js)
        self.assertNotIn("Enable it under Settings", js)


if __name__ == "__main__":
    unittest.main()
