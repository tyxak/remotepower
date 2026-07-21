"""v6.3.1 — detection-chain self-test.

"Silence isn't clearance." Verifies the alert detection→routing→delivery chain
is intact fleet-wide and surfaces the silent gaps that only live in the
operator's LIVE config (no build-time test can catch them): an alert kind muted
on every actionable channel, sandbox mode left on, a webhook-only kind with no
destination, a recover event that can never close its alert.
"""
import importlib.util
import os
import sys
import tempfile
import unittest

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-dselftest-"))

_SPEC = importlib.util.spec_from_file_location(
    "api", os.path.join(os.path.dirname(__file__), "..", "server", "cgi-bin", "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestBaselineClean(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})

    def test_default_config_has_no_silent_gaps(self):
        rep = api._detection_selftest()
        self.assertEqual(rep["summary"]["silent"], 0)
        self.assertFalse(any(i["level"] == "critical" for i in rep["issues"]))
        self.assertGreater(rep["summary"]["total_kinds"], 20)

    def test_intentionally_quiet_kinds_not_flagged(self):
        # agentlifecycle / new_port ship deliberately quiet — classified
        # silent_by_default, NOT a critical gap.
        rep = api._detection_selftest()
        byd = {k["kind"] for k in rep["kinds"] if k["status"] == "silent_by_default"}
        self.assertIn("agentlifecycle", byd)
        for k in rep["kinds"]:
            if k["kind"] in ("agentlifecycle", "new_port"):
                self.assertNotEqual(k["status"], "silent")


class TestSilentGapDetection(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})

    def test_silencing_a_loud_kind_is_critical(self):
        routing = api._channel_routing()
        routing["offline"] = {"alerts": False, "needs_attention": False,
                              "webhook": False, "recent_activity": True}
        api.save(api.CONFIG_FILE, {"channel_routing": routing})
        rep = api._detection_selftest()
        off = next(k for k in rep["kinds"] if k["kind"] == "offline")
        self.assertEqual(off["status"], "silent")
        self.assertFalse(off["reachable"])
        self.assertTrue(any(i["kind"] == "offline" and i["level"] == "critical"
                            for i in rep["issues"]))

    def test_sandbox_mode_is_flagged_critical_first(self):
        api.save(api.CONFIG_FILE, {"notifications_test_mode": True})
        rep = api._detection_selftest()
        self.assertTrue(rep["delivery"]["sandbox_mode"])
        self.assertEqual(rep["issues"][0]["level"], "critical")
        self.assertIn("test_mode", rep["issues"][0]["message"])

    def test_no_external_destination_noted(self):
        api.save(api.CONFIG_FILE, {})
        rep = api._detection_selftest()
        self.assertFalse(rep["delivery"]["external_configured"])
        self.assertTrue(any("no external destination" in i["message"]
                            for i in rep["issues"]))

    def test_external_configured_detected(self):
        api.save(api.CONFIG_FILE, {"webhook_urls": [{"url": "https://hooks.example/x"}]})
        rep = api._detection_selftest()
        self.assertTrue(rep["delivery"]["external_configured"])

    def test_external_helper(self):
        self.assertTrue(api._external_delivery_configured(
            {"smtp_enabled": True, "smtp_recipients": "a@b.c"}))
        self.assertTrue(api._external_delivery_configured({"webpush_enabled": True}))
        self.assertFalse(api._external_delivery_configured({}))
        self.assertFalse(api._external_delivery_configured(
            {"smtp_enabled": True}))   # enabled but no recipient/from


class TestHandlerAndWiring(unittest.TestCase):
    def test_handler_admin_gated(self):
        # stub identity/transport to drive the handler
        captured = {}

        def fake_respond(status, data):
            captured["status"] = status
            captured["data"] = data
            raise api.HTTPError(status, data)

        orig = (api.require_admin_auth, api.respond, api.method)
        try:
            api.require_admin_auth = lambda *a, **k: "admin"
            api.respond = fake_respond
            api.method = lambda: "GET"
            try:
                api.handle_detection_selftest()
            except (SystemExit, api.HTTPError):
                pass
            self.assertEqual(captured["status"], 200)
            self.assertIn("kinds", captured["data"])
            self.assertIn("summary", captured["data"])
        finally:
            api.require_admin_auth, api.respond, api.method = orig

    def test_module_bound(self):
        self.assertTrue(callable(api.handle_detection_selftest))
        self.assertTrue(callable(api._detection_selftest))


if __name__ == "__main__":
    unittest.main()
