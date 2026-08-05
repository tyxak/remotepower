"""v6.4.2 — an operator can threshold a connector's own metrics.

All 44 connectors return a `metrics` dict that is stored, charted and shown in
the drawer — and could never raise an alert. The only integration events came
from the connector AUTHOR's hardcoded ok/warn/crit status, with no operator-
tunable per-metric threshold equivalent to the device-side
`custom_metric_thresholds`.

So a Pi-hole whose gravity list silently emptied went from `blocked_pct` 23% to
0% with its own status still OK, and RemotePower displayed the number and said
nothing. Same shape for TrueNAS `alerts_warn` climbing, SABnzbd queue growth,
Immich storage, Uptime Kuma monitors-down. The only recourse was to write a
`connectors.d/` plugin re-implementing the connector, or stand up a parallel
`custom_probe` duplicating the same HTTP call.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-integthr642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestThresholdFiring(unittest.TestCase):
    def setUp(self):
        self._fire = api.fire_webhook
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api.save(api.CONFIG_FILE, {"integrations": [{
            "id": "pi", "type": "pihole", "label": "Pi-hole", "enabled": True,
            "metric_thresholds": [
                {"metric": "blocked_pct", "op": "lt", "value": 5,
                 "severity": "high"},
                {"metric": "queries_today", "op": "gt", "value": 1000000,
                 "severity": "low"}]}]})
        api.save(api.INTEG_STATE_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.fire_webhook = self._fire

    def poll(self, metrics, status="ok"):
        self.fired.clear()
        api._LOAD_CACHE.clear()
        api._persist_integration_results([{
            "id": "pi", "label": "Pi-hole", "type": "pihole", "status": status,
            "detail": "", "checked": int(time.time()), "metrics": metrics}])
        return [(e, p.get("metric")) for e, p in self.fired]

    def test_a_healthy_metric_is_silent(self):
        self.assertEqual(self.poll({"blocked_pct": 23.0}), [])

    def test_a_breach_fires_while_the_connector_says_ok(self):
        """The whole finding: Pi-hole's own status stays OK when its gravity
        list empties, so the connector-status events can never catch it."""
        self.assertEqual(self.poll({"blocked_pct": 0.0}),
                         [("integration_metric_alert", "blocked_pct")])

    def test_it_is_edge_triggered(self):
        self.poll({"blocked_pct": 0.0})
        self.assertEqual(self.poll({"blocked_pct": 0.0}), [],
                         "re-fires every poll — muted within a day")

    def test_it_recovers(self):
        self.poll({"blocked_pct": 0.0})
        self.assertEqual(self.poll({"blocked_pct": 22.0}),
                         [("integration_metric_recovered", "blocked_pct")])

    def test_the_flap_flag_actually_persists(self):
        """The flags are keyed `<instance>::<metric>`, and the save-time purge
        filtered on `k in configured` — which stripped every composite key, so
        the flag never persisted, a parked breach re-fired on EVERY poll, and
        the recovery never fired at all. Found by driving it."""
        self.poll({"blocked_pct": 0.0})
        flags = (api.load(api.CONFIG_FILE) or {}).get("integration_notified") or {}
        self.assertIn("pi::blocked_pct", flags)

    def test_two_thresholds_on_one_integration_are_independent(self):
        got = self.poll({"blocked_pct": 0.0, "queries_today": 2000000})
        self.assertEqual(len(got), 2)
        self.poll({"blocked_pct": 22.0, "queries_today": 2000000})
        flags = (api.load(api.CONFIG_FILE) or {}).get("integration_notified") or {}
        self.assertFalse(flags.get("pi::blocked_pct"))
        self.assertTrue(flags.get("pi::queries_today"),
                        "recovering one metric cleared the other")

    def test_a_non_numeric_value_is_not_a_breach(self):
        """A connector that reports a string for a thresholded metric must not
        be read as crossing the bound."""
        self.assertEqual(self.poll({"blocked_pct": "n/a"}), [])

    def test_a_missing_metric_is_not_a_breach(self):
        self.assertEqual(self.poll({"other": 1}), [])

    def test_the_severity_comes_from_the_threshold(self):
        self.poll({"blocked_pct": 0.0})
        self.assertEqual(self.fired[0][1]["severity"], "high")

    def test_the_alert_reaches_the_inbox(self):
        """severity=None in the registry means _alert_severity must derive it
        from the payload — without a branch there the event webhooks and never
        lands in the inbox, which is the recurring silent gap."""
        self.assertEqual(
            api._alert_severity("integration_metric_alert",
                                {"severity": "high"}), "high")
        self.assertEqual(
            api._alert_severity("integration_metric_alert", {}), "medium")


class TestComparisons(unittest.TestCase):
    def test_every_operator(self):
        cases = [("gt", 5, 3, True), ("gt", 2, 3, False),
                 ("lt", 2, 3, True), ("lt", 5, 3, False),
                 ("gte", 3, 3, True), ("lte", 3, 3, True),
                 ("eq", 3, 3, True), ("ne", 4, 3, True)]
        for op, v, b, want in cases:
            with self.subTest(op=op, value=v, bound=b):
                self.assertIs(api._integ_threshold_breached(op, v, b), want)

    def test_an_unknown_operator_never_breaches(self):
        self.assertFalse(api._integ_threshold_breached("~=", 5, 3))


class TestSaveValidation(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(api, k, None) for k in
                       ("require_admin_auth", "get_json_body", "audit_log",
                        "method", "_env")}
        api.require_admin_auth = lambda *a, **k: "admin"
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"
        api._env = lambda k, d="": d
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                setattr(api, k, v)

    def _save(self, thresholds):
        api.get_json_body = lambda: {"integrations": [{
            "id": "pi", "type": "pihole", "label": "Pi-hole",
            "enabled": True, "metric_thresholds": thresholds}]}
        try:
            api.handle_integrations_save()
            return None
        except api.HTTPError as e:
            return e.status, e.body

    def test_a_valid_threshold_saves(self):
        self._save([{"metric": "blocked_pct", "op": "lt", "value": 5}])
        inst = (api.load(api.CONFIG_FILE) or {}).get("integrations")[0]
        self.assertEqual(inst["metric_thresholds"],
                         [{"metric": "blocked_pct", "op": "lt", "value": 5.0,
                           "severity": "medium"}])

    def test_a_bad_operator_is_a_400_not_a_silent_drop(self):
        """A silently-skipped threshold is one the operator believes is armed —
        the exact failure shape this release has been removing."""
        r = self._save([{"metric": "x", "op": "~=", "value": 1}])
        self.assertEqual(r[0], 400)
        self.assertIn("~=", r[1]["error"])

    def test_a_non_numeric_bound_is_a_400(self):
        r = self._save([{"metric": "x", "op": "gt", "value": "lots"}])
        self.assertEqual(r[0], 400)

    def test_a_nameless_threshold_is_dropped_quietly(self):
        """An empty row is an unfilled form field, not a mistake worth a 400."""
        self._save([{"metric": "", "op": "gt", "value": 1},
                    {"metric": "ok", "op": "gt", "value": 1}])
        inst = (api.load(api.CONFIG_FILE) or {}).get("integrations")[0]
        self.assertEqual(len(inst["metric_thresholds"]), 1)

    def test_it_is_additive(self):
        api.get_json_body = lambda: {"integrations": [{
            "id": "pi", "type": "pihole", "label": "Pi-hole", "enabled": True}]}
        try:
            api.handle_integrations_save()
        except api.HTTPError:
            pass
        inst = (api.load(api.CONFIG_FILE) or {}).get("integrations")[0]
        self.assertNotIn("metric_thresholds", inst)


class TestRegistryWiring(unittest.TestCase):
    def test_both_events_are_registered(self):
        for ev in ("integration_metric_alert", "integration_metric_recovered"):
            with self.subTest(ev=ev):
                self.assertIn(ev, api.EVENT_REGISTRY)
                self.assertEqual(api.EVENT_KIND_MAP.get(ev), "integration")

    def test_the_recover_resolves_it(self):
        self.assertEqual(
            api._ALERT_RECOVER.get("integration_metric_recovered"),
            "integration_metric_alert")

    def test_the_recover_matches_per_metric(self):
        """integration_metric_alert is edge-triggered PER THRESHOLD, so one
        integration can hold several open rows. Matching on integration_id
        alone would clear a still-breaching sibling, which then never re-fires
        because its flap flag stays set."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("elif event == 'integration_metric_recovered':"):]
        fn = fn[:fn.index("elif event ==", 10)]
        self.assertIn("sub_match['metric']", fn)
        self.assertIn("sub_match['integration_id']", fn)

    def test_the_discriminators_are_identity_fields(self):
        """The other half of the v6.4.0 rule — without these in
        _ALERT_IDENTITY_FIELDS two thresholds on one integration coalesce into
        ONE row and the per-metric sub_match has nothing to discriminate."""
        self.assertIn("metric", api._ALERT_IDENTITY_FIELDS)
        self.assertIn("integration_id", api._ALERT_IDENTITY_FIELDS)

    def test_the_message_builder_has_a_branch(self):
        import notify
        msg = notify._webhook_message("integration_metric_alert", {
            "label": "Pi-hole", "metric": "blocked_pct", "value": 0.0,
            "op": "lt", "threshold": 5})
        self.assertIn("blocked_pct", msg)
        self.assertNotIn("unknown", msg.lower())

    def test_the_frontend_registries_have_them(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        for ev in ("integration_metric_alert", "integration_metric_recovered"):
            with self.subTest(ev=ev):
                self.assertIn(f"'{ev}'", js)
                self.assertIn(f"case '{ev}':", js)


if __name__ == "__main__":
    unittest.main()


class TestTheEditor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "server" / "html" / "static" / "js"
                  / "app.js").read_text()

    def test_the_field_exists_and_is_read_back(self):
        self.assertIn("data-ithresh", self.js)
        self.assertIn("_parseIntegThresholds", self.js)
        self.assertIn("it.metric_thresholds = parsed", self.js,
                      "the field renders and never reaches the save payload")

    def test_an_empty_field_clears_rather_than_sending_an_empty_list(self):
        body = self.js[self.js.index("function _readIntegrationCards"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("delete it.metric_thresholds", body)

    def test_the_metric_hint_uses_a_field_that_exists(self):
        """`last_metrics` is attached by handle_integrations_list. An invented
        cache name would be an undefined global — silent in JS, and dead in a
        branch nobody exercises."""
        self.assertIn("it.last_metrics", self.js)
        self.assertNotIn("_integLatest", self.js)
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe['last_metrics']", src,
                      "the client reads a field the server does not send")

    def test_the_parser_tolerates_a_half_typed_line(self):
        """Parsed on READ, not on every keystroke — a three-token minimum means
        a half-typed line is skipped rather than becoming a validation error
        mid-edit."""
        body = self.js[self.js.index("function _parseIntegThresholds"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("parts.length < 3", body)
