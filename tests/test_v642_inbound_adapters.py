"""v6.4.2 — Alertmanager and Authentik stop being 400'd by a receiver that names them.

`POST /api/webhook/in/<token>` hard-required a top-level `title` and read
RemotePower's own `{severity, title, body, device, links}` shape. There was no
per-source adapter, no `status: firing|resolved` handling, and no dedup — the
handler appended straight to ALERTS_FILE rather than coalescing.

features.md and the token-create UI both name Grafana / Alertmanager /
Authentik / n8n as senders. Alertmanager's payload
(`{status, commonLabels, alerts:[…]}`) and Authentik's
(`{body, severity, user_email}`) have no `title` field, so both were rejected
with a bare 400 "title required" on every notification — and their payloads are
fixed, so there is nothing the operator can change at the sending end.

Grafana does send a title, so it worked. Then its 4-hourly re-notify created a
brand-new alert row every cycle, and its `status: resolved` did nothing, so the
inbox filled with duplicates to be closed by hand.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-inbadapt-"))

_spec = importlib.util.spec_from_file_location("api_inbadapt", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_AM = {
    "status": "firing",
    "groupKey": '{}:{alertname="HighCPU"}',
    "commonLabels": {"alertname": "HighCPU", "severity": "warning",
                     "instance": "web1:9100"},
    "commonAnnotations": {"summary": "CPU above 90%",
                          "description": "node_cpu > 0.9 for 10m"},
    "alerts": [{"status": "firing", "labels": {}, "annotations": {},
                "generatorURL": "http://prom/graph?g0.expr=x"}],
}
_AUTHENTIK = {"body": "A user logged in from a new device\nIP 10.0.0.9",
              "severity": "warning", "user_email": "a@b.c"}
_GRAFANA = {"ruleName": "Disk", "state": "alerting", "title": "Disk almost full",
            "message": "85% used", "ruleUrl": "http://g/d/1"}


class TestDetection(unittest.TestCase):
    def test_alertmanager(self):
        self.assertEqual(api._inbound_detect_format(_AM), "alertmanager")

    def test_grafana_legacy(self):
        self.assertEqual(api._inbound_detect_format(_GRAFANA), "grafana")

    def test_authentik(self):
        self.assertEqual(api._inbound_detect_format(_AUTHENTIK), "authentik")

    def test_the_native_shape_is_still_generic(self):
        self.assertEqual(
            api._inbound_detect_format({"title": "x", "severity": "high"}),
            "generic")

    def test_a_body_WITH_a_title_is_generic_not_authentik(self):
        """Authentik is identified by having a body and NO title. Someone
        sending both means the native shape."""
        self.assertEqual(
            api._inbound_detect_format({"title": "x", "body": "y"}), "generic")

    def test_junk_does_not_raise(self):
        for bad in (None, [], "string", 7):
            with self.subTest(body=bad):
                self.assertEqual(api._inbound_detect_format(bad), "generic")


class TestAlertmanager(unittest.TestCase):
    def setUp(self):
        self.n, self.resolved = api._inbound_normalize(_AM, "auto")

    def test_it_gets_a_title_at_all(self):
        """This is the whole finding: the payload has no `title` field, so
        every notification 400'd."""
        self.assertEqual(self.n["title"], "CPU above 90%")

    def test_it_falls_back_to_the_alert_name(self):
        am = {"status": "firing", "commonLabels": {"alertname": "DiskFull"},
              "alerts": []}
        self.assertEqual(api._inbound_normalize(am, "auto")[0]["title"], "DiskFull")

    def test_warning_maps_to_medium_not_high(self):
        """Prometheus `warning` is the level every disk-80% rule fires at.
        Mapping it to high would page the operator for the whole fleet."""
        self.assertEqual(self.n["severity"], "medium")

    def test_critical_stays_critical(self):
        am = {"status": "firing", "commonLabels": {"severity": "critical"},
              "alerts": []}
        self.assertEqual(api._inbound_normalize(am, "auto")[0]["severity"],
                         "critical")

    def test_an_unknown_severity_label_defaults_to_medium(self):
        am = {"status": "firing", "commonLabels": {"severity": "spicy"},
              "alerts": []}
        self.assertEqual(api._inbound_normalize(am, "auto")[0]["severity"],
                         "medium")

    def test_the_port_is_stripped_from_instance(self):
        """`instance` is host:port; the port is not part of a hostname, and
        device matching is by name."""
        self.assertEqual(self.n["device"], "web1")

    def test_the_group_key_is_the_dedup_key(self):
        """groupKey identifies the alert GROUP across firing and resolving
        notifications — exactly what dedup and resolve both need."""
        self.assertEqual(self.n["dedup"], '{}:{alertname="HighCPU"}')

    def test_a_missing_group_key_still_dedups(self):
        am = {"status": "firing", "commonLabels": {"alertname": "HighCPU"},
              "alerts": []}
        self.assertEqual(api._inbound_normalize(am, "auto")[0]["dedup"],
                         "alertname=HighCPU")

    def test_the_generator_url_becomes_a_link(self):
        self.assertEqual(self.n["links"][0]["url"],
                         "http://prom/graph?g0.expr=x")

    def test_a_multi_alert_group_says_so(self):
        am = dict(_AM, alerts=[{"labels": {}}, {"labels": {}}, {"labels": {}}])
        self.assertIn("+2 more", api._inbound_normalize(am, "auto")[0]["title"])

    def test_resolved_is_recognised(self):
        self.assertFalse(self.resolved)
        self.assertTrue(api._inbound_normalize(dict(_AM, status="resolved"),
                                               "auto")[1])


class TestAuthentik(unittest.TestCase):
    def test_the_first_line_becomes_the_title(self):
        """Authentik's body is prose. Truncating at the first line beats an
        empty title, which is what the hard `title` requirement produced."""
        n, resolved = api._inbound_normalize(_AUTHENTIK, "auto")
        self.assertEqual(n["title"], "A user logged in from a new device")
        self.assertIn("10.0.0.9", n["body"])
        self.assertFalse(resolved)

    def test_an_empty_body_still_gets_a_title(self):
        n, _ = api._inbound_normalize({"body": "   ", "severity": "info"},
                                      "authentik")
        self.assertEqual(n["title"], "Authentik notification")


class TestGrafanaLegacy(unittest.TestCase):
    def test_alerting_is_high(self):
        n, resolved = api._inbound_normalize(_GRAFANA, "auto")
        self.assertEqual(n["severity"], "high")
        self.assertFalse(resolved)

    def test_ok_resolves(self):
        self.assertTrue(api._inbound_normalize(dict(_GRAFANA, state="ok"),
                                               "auto")[1])

    def test_no_data_does_NOT_resolve(self):
        """A rule that stopped receiving data is not a rule that cleared —
        treating it as one silently closes a real alert."""
        self.assertFalse(api._inbound_normalize(dict(_GRAFANA, state="no_data"),
                                                "auto")[1])

    def test_it_dedups_on_the_rule(self):
        """Grafana re-notifies every 4h; without this each cycle is a new row."""
        self.assertEqual(api._inbound_normalize(_GRAFANA, "auto")[0]["dedup"],
                         "grafana=Disk")


class TestGenericIsUnchanged(unittest.TestCase):
    def test_the_native_shape_passes_through(self):
        body = {"title": "Something", "severity": "high", "body": "detail",
                "device": "web1", "links": [{"url": "http://x", "label": "l"}]}
        n, resolved = api._inbound_normalize(body, "generic")
        for k in ("title", "severity", "body", "device", "links"):
            with self.subTest(field=k):
                self.assertEqual(n[k], body[k])
        self.assertFalse(resolved)

    def test_it_gains_a_dedup_key_from_the_title(self):
        """Existing senders get coalescing without changing anything."""
        n, _ = api._inbound_normalize({"title": "Disk full"}, "generic")
        self.assertEqual(n["dedup"], "Disk full")

    def test_an_explicit_dedup_key_wins(self):
        n, _ = api._inbound_normalize({"title": "x", "dedup_key": "k"}, "generic")
        self.assertEqual(n["dedup"], "k")

    def test_status_resolved_is_honoured(self):
        """Grafana unified and n8n both set it."""
        self.assertTrue(api._inbound_normalize({"title": "x", "status": "resolved"},
                                               "generic")[1])


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("ALERTS_FILE", "INBOUND_WEBHOOKS_FILE", "DEVICES_FILE",
                     "FLEET_EVENTS_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "audit_log",
                       "_log_inbound", "_record_fleet_event")}
        api.audit_log = lambda *a, **k: None
        api._log_inbound = lambda *a, **k: None
        api._record_fleet_event = lambda *a, **k: None
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.DEVICES_FILE, {"d1": {"name": "web1"}})
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": [
            {"id": "t1", "label": "am", "token": "rpwi_am", "enabled": True,
             "kind": "alert", "source_format": "auto"}]})
        for f in (api.DEVICES_FILE, api.INBOUND_WEBHOOKS_FILE, api.ALERTS_FILE):
            api._invalidate_load_cache(f)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def post(self, body, token="rpwi_am"):
        api.get_json_body = lambda: body
        for f in (api.ALERTS_FILE, api.INBOUND_WEBHOOKS_FILE):
            api._invalidate_load_cache(f)
        try:
            api.handle_inbound_webhook(token)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def alerts(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        return (api.load(api.ALERTS_FILE) or {}).get("alerts", [])


class TestEndToEnd(_Base):
    def test_an_alertmanager_notification_no_longer_400s(self):
        r = self.post(_AM)
        self.assertEqual(self.cap["s"], 200, self.cap.get("b"))
        self.assertTrue(r["ok"])
        a = self.alerts()[0]
        self.assertEqual(a["title"], "CPU above 90%")
        self.assertEqual(a["severity"], "medium")

    def test_an_authentik_notification_no_longer_400s(self):
        self.post(_AUTHENTIK)
        self.assertEqual(self.cap["s"], 200, self.cap.get("b"))
        self.assertEqual(self.alerts()[0]["title"],
                         "A user logged in from a new device")

    def test_it_attaches_to_the_device_the_labels_name(self):
        self.post(_AM)
        self.assertEqual(self.alerts()[0]["device_name"], "web1")

    def test_a_repeat_firing_coalesces_instead_of_stacking(self):
        """Grafana's default re-notify is 4-hourly: one unresolved rule made
        six new rows a day, all needing to be closed by hand."""
        self.post(_AM)
        self.post(_AM)
        self.post(_AM)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["repeats"], 3)

    def test_the_coalesced_row_keeps_when_it_first_fired(self):
        """Otherwise a long-running problem looks like it started minutes ago,
        every time it re-notifies."""
        self.post(_AM)
        first = self.alerts()[0]["ts"]
        self.post(_AM)
        self.assertEqual(self.alerts()[0]["payload"]["first_seen"], first)

    def test_two_different_alerts_stay_apart(self):
        self.post(_AM)
        other = dict(_AM, groupKey='{}:{alertname="DiskFull"}',
                     commonLabels={"alertname": "DiskFull"},
                     commonAnnotations={"summary": "Disk full"})
        self.post(other)
        self.assertEqual(len(self.alerts()), 2)

    def test_a_resolve_closes_it(self):
        self.post(_AM)
        r = self.post(dict(_AM, status="resolved"))
        self.assertEqual(r["resolved"], 1)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["resolved_at"])

    def test_a_resolve_opens_nothing(self):
        """Grafana's resolve did nothing before; opening a NEW row for it would
        be worse than ignoring it."""
        r = self.post(dict(_AM, status="resolved"))
        self.assertEqual(r["resolved"], 0)
        self.assertEqual(self.alerts(), [])

    def test_a_resolve_does_not_touch_another_tokens_alerts(self):
        self.post(_AM)
        with api._LockedUpdate(api.INBOUND_WEBHOOKS_FILE) as st:
            st["tokens"].append({"id": "t2", "label": "other",
                                 "token": "rpwi_other", "enabled": True,
                                 "kind": "alert", "source_format": "auto"})
        self.post(dict(_AM, status="resolved"), token="rpwi_other")
        self.assertFalse(self.alerts()[0]["resolved_at"])

    def test_a_resolve_does_not_reopen_a_resolved_alert(self):
        self.post(_AM)
        self.post(dict(_AM, status="resolved"))
        r = self.post(dict(_AM, status="resolved"))
        self.assertEqual(r["resolved"], 0)

    def test_a_firing_after_a_resolve_opens_a_fresh_row(self):
        """The problem came back — that is a new incident, not the old one."""
        self.post(_AM)
        self.post(dict(_AM, status="resolved"))
        self.post(_AM)
        rows = self.alerts()
        self.assertEqual(len(rows), 2)
        self.assertEqual(len([a for a in rows if not a.get("resolved_at")]), 1)

    def test_a_pinned_format_overrides_detection(self):
        with api._LockedUpdate(api.INBOUND_WEBHOOKS_FILE) as st:
            st["tokens"][0]["source_format"] = "generic"
        # Read as generic, the Alertmanager body has no title → still a 400,
        # which is the honest outcome of pinning the wrong shape.
        self.post(_AM)
        self.assertEqual(self.cap["s"], 400)

    def test_the_400_now_points_at_the_fix(self):
        with api._LockedUpdate(api.INBOUND_WEBHOOKS_FILE) as st:
            st["tokens"][0]["source_format"] = "generic"
        self.post({"severity": "high"})
        self.assertIn("source format", self.cap["b"]["error"])

    def test_a_token_with_no_format_field_still_works(self):
        """Tokens created before this shipped carry no source_format."""
        with api._LockedUpdate(api.INBOUND_WEBHOOKS_FILE) as st:
            st["tokens"][0].pop("source_format", None)
        self.post(_AM)
        self.assertEqual(self.cap["s"], 200, self.cap.get("b"))

    def test_a_garbage_format_falls_back_to_auto_rather_than_500ing(self):
        with api._LockedUpdate(api.INBOUND_WEBHOOKS_FILE) as st:
            st["tokens"][0]["source_format"] = "nonsense"
        self.post(_AM)
        self.assertEqual(self.cap["s"], 200, self.cap.get("b"))


class TestTokenCreation(unittest.TestCase):
    def test_the_format_is_validated(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_inbound_webhooks_create")
        self.assertIn("source_format", body)
        self.assertIn("_INBOUND_FORMATS", body)

    def test_the_model_accepts_it(self):
        """A field the pydantic model does not know is still passed through
        (_read_valid returns the raw dict), but declaring it keeps the model
        1:1 with the handler, which is the documented contract."""
        import request_models
        self.assertIn("source_format",
                      request_models.InboundWebhooksCreateRequest.model_fields)

    def test_the_ui_offers_every_supported_format(self):
        html = (ROOT / "server" / "html" / "index.html")
        if not html.exists():
            self.skipTest("excluded from this tree")
        s = html.read_text()
        i = s.index('id="inbound-wh-format"')
        seg = s[i:i + 900]
        for f in api._INBOUND_FORMATS:
            with self.subTest(fmt=f):
                self.assertIn(f'value="{f}"', seg)

    def test_the_ui_sends_it(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js")
        if not js.exists():
            self.skipTest("excluded from this tree")
        body = js.read_text()
        b = body[body.index("async function createInboundWebhook("):]
        b = b[:b.index("\n}\n")]
        self.assertIn("source_format", b)

    def test_the_picker_hides_for_non_alert_tokens(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js")
        if not js.exists():
            self.skipTest("excluded from this tree")
        body = js.read_text()
        b = body[body.index("function updateInboundWebhookKindHint("):]
        b = b[:b.index("\n}\n")]
        self.assertIn("inbound-wh-format-row", b)


if __name__ == "__main__":
    unittest.main()
