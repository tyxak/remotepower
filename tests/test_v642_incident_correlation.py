"""v6.4.2 — the inbox says which alerts are collateral, and can declare an incident.

Two findings, both about an answer the server already had and threw away:

  1. Dependency suppression stops at webhook delivery. `fire_webhook` calls
     `_upstream_down()`, gets back the name of the offline upstream, suppresses
     the notification and returns — but `_record_alert` has ALREADY run, so the
     downstream alert is in the inbox with nothing marking it as collateral.
     `_annotate_alert_correlation` then folds symptoms strictly within one
     device_id. So a rack switch losing power gave the operator 21 host groups,
     each with its own `device_offline` flagged "root cause" FOR THAT HOST, and
     no sign that 20 of them were consequences. The server computed exactly
     that, in order to stay quiet, and then discarded it.

  2. The incident object spans an alert cluster — auto-promotion writes
     `alert_ids` / `device_ids` and stamps `incident_id` back onto every member
     alert — and the inbox never rendered it. An on-call operator working 14
     alerts had no sign an incident existed; it was three clicks into Settings →
     Integrations, a pane nobody opens during an outage. And there was no way to
     declare one from the alerts in front of them.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-inccorr642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestCollateralIsMarked(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        n = self.now
        self._saved = {k: getattr(api, k) for k in
                       ("_send_webhook_to_url", "_log_webhook")}
        api._send_webhook_to_url = lambda *a, **k: None
        api._log_webhook = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {
            "sw01": {"name": "rack-switch", "last_seen": n - 99999},
            "h1": {"name": "web-01", "last_seen": n, "depends_on": ["sw01"]},
            "h2": {"name": "web-02", "last_seen": n, "depends_on": ["sw01"]},
            "lone": {"name": "unrelated", "last_seen": n},
        })
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _fire(self, dev, name, event="device_offline"):
        api.fire_webhook(event, {"device_id": dev, "name": name})

    def _rows(self):
        return (api.load(api.ALERTS_FILE) or {}).get("alerts") or []

    def test_a_downstream_alert_records_its_upstream(self):
        self._fire("h1", "web-01")
        row = self._rows()[-1]
        self.assertEqual((row.get("payload") or {}).get("upstream_down"),
                         "rack-switch",
                         "the alert is in the inbox with nothing saying it is "
                         "collateral — the server computed the upstream to "
                         "suppress the webhook and then dropped it")

    def test_an_unrelated_host_is_not_marked(self):
        self._fire("lone", "unrelated")
        row = self._rows()[-1]
        self.assertIsNone((row.get("payload") or {}).get("upstream_down"))

    def test_the_callers_payload_is_not_mutated(self):
        """Several call sites reuse their payload for the webhook body and for a
        later event; stamping through it would leak into both."""
        p = {"device_id": "h1", "name": "web-01"}
        api.fire_webhook("device_offline", p)
        self.assertEqual(p, {"device_id": "h1", "name": "web-01"})

    def test_a_recover_event_is_never_marked(self):
        """A device coming back must always clear — marking a recover as
        collateral would be meaningless and could confuse auto-resolve."""
        self._fire("h1", "web-01", event="device_online")
        rows = [r for r in self._rows() if r.get("event") == "device_online"]
        for r in rows:
            self.assertIsNone((r.get("payload") or {}).get("upstream_down"))

    def test_the_annotator_surfaces_it(self):
        self._fire("h1", "web-01")
        self._fire("h2", "web-02")
        self._fire("lone", "unrelated")
        rows = api._annotate_alert_correlation(self._rows())
        by = {r["device_id"]: r for r in rows}
        self.assertEqual(by["h1"].get("_collateral_of"), "rack-switch")
        self.assertEqual(by["h2"].get("_collateral_of"), "rack-switch")
        self.assertIsNone(by["lone"].get("_collateral_of"))

    def test_it_does_not_replace_the_per_host_root_cause(self):
        """A downstream host's device_offline is genuinely the root cause ON
        THAT HOST and also collateral from the upstream. Both are true; dropping
        either loses information."""
        self._fire("h1", "web-01")
        rows = api._annotate_alert_correlation(self._rows())
        r = rows[-1]
        self.assertTrue(r.get("_root_cause"))
        self.assertEqual(r.get("_collateral_of"), "rack-switch")

    def test_a_resolved_alert_is_not_annotated(self):
        self._fire("h1", "web-01")
        rows = self._rows()
        rows[-1]["resolved_at"] = self.now
        api._annotate_alert_correlation(rows)
        self.assertIsNone(rows[-1].get("_collateral_of"))

    def test_the_key_survives_the_record_alert_whitelist(self):
        """`_record_alert` stores only whitelisted payload keys — the recurring
        silent-drop class. Without `upstream_down` in it the stamp would exist
        at fire time and be gone by the time anything read it."""
        self.assertIn("'upstream_down'", (_CGI / "api.py").read_text())
        self._fire("h1", "web-01")
        self.assertIn("upstream_down", self._rows()[-1].get("payload") or {})

    def test_the_upstream_is_looked_up_once(self):
        """It used to be computed only in the suppression block. Computing it
        twice per fired event on a fleet-sized DEVICES_FILE is a real cost on
        the hottest write path."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def fire_webhook("):]
        fn = fn[:fn.index("\ndef ")]
        self.assertEqual(fn.count("_upstream_down("), 1,
                         "the upstream lookup runs more than once per event")


class TestDeclareIncidentFromAlerts(unittest.TestCase):
    def setUp(self):
        n = int(time.time())
        self._saved = {k: getattr(api, k, None) for k in
                       ("require_admin_auth", "method",
                        "_notify_incident_subscribers", "audit_log",
                        "_filter_alerts_for_caller", "get_json_body")}
        api.require_admin_auth = lambda *a, **k: "jakob"
        api.method = lambda: "POST"
        api._notify_incident_subscribers = lambda *a, **k: None
        api.audit_log = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {"h1": {"name": "web-01", "last_seen": n}})
        api.save(api.INCIDENTS_FILE, {"incidents": []})
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "event": "service_down", "device_id": "h1",
             "device_name": "web-01", "ts": n, "severity": "high"},
            {"id": "a2", "event": "disk_full", "device_id": "h1",
             "device_name": "web-01", "ts": n, "severity": "high"},
            {"id": "a3", "event": "x", "device_id": "other",
             "device_name": "other", "ts": n, "severity": "low"},
        ], "alert_seq": 3})

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                setattr(api, k, v)

    def _post(self, **body):
        api.get_json_body = lambda: dict(
            {"title": "Web outage", "impact": "major",
             "status": "investigating", "body": "x"}, **body)
        try:
            api.handle_incidents()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return e.body

    def _inc(self):
        return ((api.load(api.INCIDENTS_FILE) or {}).get("incidents") or [])[-1]

    def _alerts(self):
        return {a["id"]: a
                for a in (api.load(api.ALERTS_FILE) or {}).get("alerts") or []}

    def test_the_incident_records_which_alerts_it_covers(self):
        api._filter_alerts_for_caller = lambda rows: rows
        self._post(alert_ids=["a1", "a2"])
        inc = self._inc()
        self.assertEqual(inc.get("alert_ids"), ["a1", "a2"])
        self.assertEqual(inc.get("device_ids"), ["h1"])

    def test_each_member_alert_is_stamped_back(self):
        """One-way linkage would leave the inbox with no sign the incident
        exists, which is the finding restated."""
        api._filter_alerts_for_caller = lambda rows: rows
        r = self._post(alert_ids=["a1", "a2"])
        al = self._alerts()
        self.assertEqual(al["a1"]["incident_id"], r["id"])
        self.assertEqual(al["a2"]["incident_id"], r["id"])
        self.assertIsNone(al["a3"].get("incident_id"))

    def test_an_alert_the_caller_cannot_see_is_dropped(self):
        """Otherwise this becomes a way to claim, and enumerate, another
        tenant's alert ids."""
        api._filter_alerts_for_caller = lambda rows: [
            r for r in rows if r.get("device_id") != "other"]
        self._post(alert_ids=["a1", "a3"])
        self.assertEqual(self._inc().get("alert_ids"), ["a1"])
        self.assertIsNone(self._alerts()["a3"].get("incident_id"))

    def test_an_unknown_id_is_ignored_not_500(self):
        api._filter_alerts_for_caller = lambda rows: rows
        self._post(alert_ids=["a1", "does-not-exist"])
        self.assertEqual(self._inc().get("alert_ids"), ["a1"])

    def test_a_plain_incident_still_works(self):
        """The status-page form posts no alert_ids — this must stay additive."""
        api._filter_alerts_for_caller = lambda rows: rows
        r = self._post()
        self.assertTrue(r["ok"])
        self.assertNotIn("alert_ids", self._inc())

    def test_a_non_list_alert_ids_does_not_break_it(self):
        api._filter_alerts_for_caller = lambda rows: rows
        r = self._post(alert_ids="a1")
        self.assertTrue(r["ok"])
        self.assertNotIn("alert_ids", self._inc())

    def test_the_model_accepts_the_field(self):
        import request_models
        ok, err = request_models.validate(
            request_models.IncidentsRequest,
            {"title": "x", "alert_ids": ["a1"]})
        self.assertTrue(ok, err)
        ok, _ = request_models.validate(request_models.IncidentsRequest, {})
        self.assertTrue(ok, "the model became required-field")

    def test_the_two_locks_are_not_nested(self):
        """INCIDENTS_FILE then ALERTS_FILE, sequentially — a nested
        _LockedUpdate is an OperationalError on the SQL backends, and the
        auto-promoter alongside this takes the same care."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def handle_incidents("):]
        fn = fn[:fn.index("\ndef ")]
        i = fn.index("_LockedUpdate(INCIDENTS_FILE)")
        j = fn.index("_LockedUpdate(ALERTS_FILE)")
        self.assertLess(i, j)
        between = fn[i:j]
        self.assertIn("\n    if _link_ids:", between,
                      "the ALERTS lock must be at function indent, i.e. AFTER "
                      "the INCIDENTS block closed")


class TestClientHalf(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app-alerts.js").read_text()
        self.css = (ROOT / "server" / "html" / "static" / "css"
                    / "styles.css").read_text()

    def test_the_row_renders_its_incident(self):
        self.assertIn("a.incident_id", self.js,
                      "the stamp exists on the alert and is rendered nowhere")
        self.assertIn("${incBadge}", self.js,
                      "the badge is built and never placed in the row")

    def test_the_group_header_names_the_upstream(self):
        self.assertIn("_collateral_of", self.js)
        self.assertIn("is down", self.js,
                      "'collateral' without the name leaves the operator "
                      "hunting for which upstream")

    def test_a_single_alert_host_still_shows_it(self):
        """One downstream host with one device_offline is the commonest shape,
        and it has no group header to hang the note on."""
        body = self.js[self.js.index("if (g.items.length === 1)"):]
        body = body[:body.index("\n    const items =")]
        self.assertIn("_collateral_of", body)

    def test_declare_incident_exists_and_confirms(self):
        self.assertIn('data-action="declareIncident"', self.js)
        body = self.js[self.js.index("async function declareIncident"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("uiConfirm", body,
                      "declaring an incident notifies public status "
                      "subscribers — not a one-mis-click action")
        self.assertLess(body.index("uiConfirm"), body.index("api('POST'"))

    def test_it_sends_the_alert_ids(self):
        body = self.js[self.js.index("async function declareIncident"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("alert_ids: ids", body)

    def test_it_is_not_offered_when_one_already_exists(self):
        self.assertIn("if (!a.incident_id) {", self.js)

    def test_the_collateral_badge_is_styled(self):
        self.assertIn(".alert-rc-badge.rc-collateral", self.css,
                      "an unstyled badge renders as bare text next to two "
                      "styled siblings")

    def test_no_inline_handlers_or_styles(self):
        body = self.js[self.js.index("async function declareIncident"):]
        body = body[:body.index("\n}\n")]
        self.assertNotRegex(body, r"\son\w+=")
        self.assertNotRegex(body, r'\sstyle="')


if __name__ == "__main__":
    unittest.main()


class TestMalformedWebhookLogDoesNotKillTheScrape(unittest.TestCase):
    """Found by a neighbouring test poisoning the shared store, which is the
    only reason it was ever seen.

    `generate_metrics` did `for entry in ctx['webhook_log']: entry.get(...)`.
    Iterating a STRING yields characters, so one corrupt or hand-edited
    webhook_log.json raised AttributeError out of the exporter and 500'd the
    ENTIRE /api/metrics scrape — every gauge Prometheus reads, gone, because of
    one unrelated store. The bare-list shape is not even exotic: it is what old
    deployments have on disk, and what the `_log_email` bug wrote.
    """

    def setUp(self):
        sys.path.insert(0, str(_CGI))
        import prometheus_export
        self.pe = prometheus_export
        api.save(api.DEVICES_FILE,
                 {"promdev1": {"name": "x", "last_seen": int(time.time())}})

    def _scrape(self, log):
        api.save(api.WEBHOOK_LOG_FILE, log)
        api._LOAD_CACHE.clear()
        return self.pe.generate_metrics(api._build_metrics_ctx())

    def test_a_string_store_does_not_raise(self):
        out = self._scrape("not a log at all")
        self.assertIn("remotepower_devices_total", out,
                      "the scrape died on an unrelated malformed store")

    def test_a_bare_list_of_records_still_counts(self):
        """The legacy shape — it must be READ, not merely survived."""
        out = self._scrape([{"ts": 1, "event": "e", "status": "error"}])
        self.assertIn('remotepower_webhook_deliveries_total{status="error"} 1',
                      out)

    def test_a_non_record_entry_is_skipped_not_fatal(self):
        out = self._scrape({"entries": ["junk", {"status": 200}]})
        self.assertIn('remotepower_webhook_deliveries_total{status="ok"} 1', out)

    def test_an_email_success_counts_as_ok(self):
        """A webhook row's status is the HTTP code ('200'); an email row's is
        the literal 'ok'. Only the first was counted, so every successful email
        landed in "other" and the ok gauge under-reported."""
        out = self._scrape({"entries": [{"status": "ok"}, {"status": 200}]})
        self.assertIn('remotepower_webhook_deliveries_total{status="ok"} 2', out)
