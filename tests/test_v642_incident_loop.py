"""v6.4.2 — the incident loop can be pointed at the incident.

Three findings on the detect→triage→act→learn path:

  1. The Timeline is the one screen built for incident reconstruction and it
     could not be pointed at the incident. It accepted `limit`/`kinds`/`device`/
     `severity` and nothing else; the client always asked for the newest 300
     rows, which on a busy host may not even reach the 03:41 the alert is about.
     No alert row linked to it. docs/timeline.md meanwhile sold the page as 'the
     "what happened around 03:40" view' and listed a time-range filter that did
     not exist.

  2. The Timeline merged fleet events, commands and CVE state but never the
     audit log, so the operator-side changes that are not events — config saves,
     maintenance windows, rule and threshold edits, mitigations — were invisible
     during a reconstruction. "What changed right before this broke" was the one
     question it could not answer.

  3. Monitoring → Tuning ranked noise purely on raw event count. 340
     `nic_errors` that all auto-resolved in 90 seconds and were never
     acknowledged got the top slot and a Mute button; 12 `backup_stale` that a
     human resolved by hand after six hours each got the same Mute button. The
     data that tells them apart was computed one endpoint away and aggregated
     only per host.

The audit merge is a privilege boundary, not a convenience — `handle_audit_log`
is `require_admin_or_auditor_auth`, so merging unconditionally would have made
the Timeline a way around that gate. That is driven from both sides.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-incloop642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_HTML = ROOT / "server" / "html"
_JS = _HTML / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)

T = 1700000000


class _TimelineBase(unittest.TestCase):
    def setUp(self):
        self._saved = {n: getattr(api, n) for n in
                       ("require_auth", "_caller_scope", "_tenant_gate",
                        "_caller_role", "_env")}
        api.require_auth = lambda *a, **k: "jakob"
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api.save(api.DEVICES_FILE,
                 {"h1": {"name": "web-01", "last_seen": T},
                  "h2": {"name": "db-01", "last_seen": T}})
        api.save(api.FLEET_EVENTS_FILE, {"events": [
            {"ts": T, "event": "service_down",
             "payload": {"device_id": "h1", "unit": "nginx"}},
            {"ts": T - 86400, "event": "service_down",
             "payload": {"device_id": "h1", "unit": "nginx"}},
        ]})
        api.save(api.CMD_OUTPUT_FILE,
                 {"h1": [{"ts": T - 420, "cmd": "apt-get -y upgrade", "rc": 0}]})
        api.save(api.AUDIT_LOG_FILE, {"entries": [
            {"ts": T - 840, "actor": "jakob", "action": "config_changed",
             "detail": "keys: cpu_warn_pct"},
            {"ts": T - 600, "actor": "jakob", "action": "mitigate_fix",
             "detail": "device=h1 kind=service_down"},
            {"ts": T - 500, "actor": "jakob", "action": "mitigate_fix",
             "detail": "device=h2 kind=x"},
            {"ts": T - 100, "actor": "jakob", "action": "login_success",
             "detail": "noise"},
        ]})
        api.save(api.CVE_FINDINGS_FILE, {})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def tl(self, qs="", role="admin", dev="h1"):
        api._env = lambda k, d="": qs if k == "QUERY_STRING" else d
        api._caller_role = lambda: role
        try:
            api.handle_device_timeline(dev)
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return e.body

    def fleet(self, qs="", role="admin"):
        api._env = lambda k, d="": qs if k == "QUERY_STRING" else d
        api._caller_role = lambda: role
        try:
            api.handle_fleet_timeline()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return e.body


class TestTimelineCanBePointedAtAMoment(_TimelineBase):
    def test_around_narrows_to_the_window(self):
        wide = self.tl("")
        near = self.tl(f"around={T}&window=900")
        self.assertLess(len(near["items"]), len(wide["items"]),
                        "the window did not narrow anything")
        self.assertTrue(all(abs(i["ts"] - T) <= 900 for i in near["items"]),
                        "a row outside the window survived")

    def test_the_day_old_event_drops_out(self):
        near = self.tl(f"around={T}&window=900")
        self.assertEqual(
            sum(1 for i in near["items"] if i["ts"] == T - 86400), 0)

    def test_explicit_since_until(self):
        b = self.tl(f"since={T - 1000}&until={T - 300}")
        self.assertTrue(b["items"])
        self.assertTrue(all(T - 1000 <= i["ts"] <= T - 300 for i in b["items"]))

    def test_the_resolved_window_is_echoed_back(self):
        """The client shows the window it actually got; guessing it from the
        request would drift the moment the server clamps anything."""
        b = self.tl(f"around={T}&window=900")
        self.assertEqual(b["since"], T - 900)
        self.assertEqual(b["until"], T + 900)

    def test_milliseconds_are_coerced(self):
        """The client has a Date in hand; sending Date.now() instead of /1000 is
        the obvious mistake, and it would silently return an empty window."""
        ms = self.tl(f"around={T * 1000}&window=900")
        secs = self.tl(f"around={T}&window=900")
        self.assertEqual(len(ms["items"]), len(secs["items"]))

    def test_the_window_is_clamped(self):
        b = self.tl(f"around={T}&window=99999999")
        self.assertLessEqual(b["until"] - b["around"] if "around" in b
                             else b["until"] - T, 30 * 86400)

    def test_a_garbage_window_falls_back_rather_than_500ing(self):
        b = self.tl(f"around={T}&window=abc")
        self.assertEqual(b["since"], T - 1800)

    def test_no_window_is_still_newest_first(self):
        b = self.tl("")
        self.assertIsNone(b["since"])
        ts = [i["ts"] for i in b["items"]]
        self.assertEqual(ts, sorted(ts, reverse=True))

    def test_the_kind_chips_stay_stable_across_windows(self):
        """The filter chips are built from the UNwindowed set on purpose — a
        chip vanishing as you narrow the window would make the filter feel
        broken."""
        wide = set(self.tl("")["kinds"])
        near = set(self.tl(f"around={T}&window=900")["kinds"])
        self.assertEqual(wide, near)

    def test_the_fleet_endpoint_takes_the_window_too(self):
        b = self.fleet(f"around={T}&window=900")
        self.assertEqual(b["since"], T - 900)
        self.assertTrue(all(abs(i["ts"] - T) <= 900 for i in b["items"]))


class TestTimelineMergesOperatorChanges(_TimelineBase):
    def test_an_admin_sees_audit_rows(self):
        kinds = {i["kind"] for i in self.tl("")["items"]}
        self.assertIn("audit", kinds,
                      "config saves and mitigations are still invisible during "
                      "an incident reconstruction")

    def test_an_auditor_sees_them(self):
        kinds = {i["kind"] for i in self.tl("", role="auditor")["items"]}
        self.assertIn("audit", kinds)

    def test_a_viewer_does_not(self):
        """`handle_audit_log` is require_admin_or_auditor_auth. Merging
        unconditionally would make the Timeline a way around that gate."""
        kinds = {i["kind"] for i in self.tl("", role="viewer")["items"]}
        self.assertNotIn("audit", kinds,
                         "the timeline leaks the audit log to a viewer")

    def test_read_shaped_audit_noise_is_excluded(self):
        """The audit log is mostly logins and reads. Folding all of it in would
        bury the events."""
        details = [i["detail"] for i in self.tl("")["items"]
                   if i["kind"] == "audit"]
        self.assertFalse(any("noise" in d for d in details),
                         "login_success rows reached the incident timeline")

    def test_another_devices_audit_row_does_not_appear(self):
        """`device=h2` in the detail must not show on h1's timeline — that would
        be a cross-device leak wearing an incident-reconstruction hat."""
        details = [i["detail"] for i in self.tl("")["items"]
                   if i["kind"] == "audit"]
        self.assertFalse(any("device=h2" in d for d in details))

    def test_fleet_level_audit_rows_carry_no_invented_device(self):
        """A global config save belongs to no host. Attributing it to one would
        be worse than leaving it unattributed."""
        rows = [i for i in self.tl("")["items"]
                if i["kind"] == "audit" and "cpu_warn_pct" in i["detail"]]
        self.assertTrue(rows)
        self.assertIsNone(rows[0]["device_id"])

    def test_the_row_names_the_actor(self):
        rows = [i for i in self.tl("")["items"] if i["kind"] == "audit"]
        self.assertTrue(all("jakob" in r["title"] for r in rows),
                        "an audit row that does not say WHO is half a record")

    def test_the_etag_separates_roles(self):
        """Two callers with different audit visibility must never share a 304."""
        api._caller_role = lambda: "admin"
        a = api._timeline_etag_source("h1", 100, (), None, None,
                                      api._caller_can_read_audit())
        api._caller_role = lambda: "viewer"
        v = api._timeline_etag_source("h1", 100, (), None, None,
                                      api._caller_can_read_audit())
        self.assertNotEqual(a, v)

    def test_the_etag_busts_on_a_config_save(self):
        """Without AUDIT_LOG_FILE in the source, a config save would not bust the
        ETag and the timeline would keep serving a 304 that omits the very
        change being looked for."""
        before = api._timeline_etag_source("h1")
        api.save(api.AUDIT_LOG_FILE, {"entries": [
            {"ts": T, "actor": "x", "action": "config_changed", "detail": "y"}]})
        api._invalidate_load_cache(api.AUDIT_LOG_FILE)
        self.assertNotEqual(before, api._timeline_etag_source("h1"))


class TestTuningActionability(unittest.TestCase):
    """340 loud-and-harmless vs 12 quiet-and-real."""

    def setUp(self):
        self.now = int(time.time())
        n = self.now
        self._saved = {k: getattr(api, k) for k in
                       ("require_auth", "_caller_scope", "_tenant_gate", "_env")}
        api.require_auth = lambda *a, **k: "jakob"
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api._env = lambda k, d="": d
        api.save(api.DEVICES_FILE, {"h1": {"name": "web-01", "last_seen": n}})
        evs = [{"ts": n - i * 60, "event": "nic_errors",
                "payload": {"device_id": "h1", "iface": "eth0"}}
               for i in range(340)]
        evs += [{"ts": n - i * 3600, "event": "backup_stale",
                 "payload": {"device_id": "h1", "path": "/srv"}}
                for i in range(12)]
        api.save(api.FLEET_EVENTS_FILE, {"events": evs})
        alerts = [{"id": f"n{i}", "event": "nic_errors", "device_id": "h1",
                   "device_name": "web-01", "ts": n - i * 60,
                   "first_seen": n - i * 60, "resolved_at": n - i * 60 + 60,
                   "resolved_by": "auto"} for i in range(30)]
        alerts += [{"id": f"b{i}", "event": "backup_stale", "device_id": "h1",
                    "device_name": "web-01", "ts": n - i * 3600,
                    "first_seen": n - i * 3600,
                    "resolved_at": n - i * 3600 + 21600, "resolved_by": "jakob",
                    "acknowledged_at": n - i * 3600 + 300,
                    "acknowledged_by": "jakob"} for i in range(12)]
        api.save(api.ALERTS_FILE, {"alerts": alerts, "alert_seq": len(alerts)})

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _sources(self):
        try:
            api.handle_alert_tuning()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return {s["event"]: s for s in e.body["sources"]}

    def test_the_loud_event_is_reported_as_auto_and_unacked(self):
        s = self._sources()["nic_errors"]
        self.assertEqual(s["count"], 340)
        self.assertEqual(s["auto_pct"], 100)
        self.assertEqual(s["acked_pct"], 0)
        self.assertLess(s["mttr_mean"], 900)

    def test_the_quiet_event_is_reported_as_human_work(self):
        s = self._sources()["backup_stale"]
        self.assertEqual(s["count"], 12)
        self.assertEqual(s["auto_pct"], 0)
        self.assertEqual(s["acked_pct"], 100)
        self.assertGreater(s["mttr_mean"], 3600)

    def test_the_denominator_is_resolutions_not_firings(self):
        """340 firings with 30 resolved rows must not read as 100% of 340."""
        s = self._sources()["nic_errors"]
        self.assertEqual(s["resolved"], 30)

    def test_an_event_with_no_resolutions_reports_no_data(self):
        """Silently defaulting to 0% auto would read as 'people act on this' —
        an assertion about data that does not exist."""
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})
        s = self._sources()["nic_errors"]
        self.assertNotIn("auto_pct", s,
                         "reported a percentage with nothing behind it")

    def test_per_event_stats_exist_on_the_resolution_endpoint(self):
        store = api.load(api.ALERTS_FILE) or {}
        res = api._alert_resolution_stats(store.get("alerts") or [], 30)
        self.assertIn("events", res,
                      "the per-event aggregation only ever grouped per host")
        by = {e["event"]: e for e in res["events"]}
        self.assertEqual(by["nic_errors"]["auto"], 30)
        self.assertEqual(by["backup_stale"]["manual"], 12)

    def test_a_broken_alerts_store_does_not_break_the_page(self):
        """The join is an enrichment. Tuning must still rank by count if the
        alerts store is unreadable."""
        api.save(api.ALERTS_FILE, "garbage")
        self.addCleanup(api.save, api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})
        s = self._sources()
        self.assertEqual(s["nic_errors"]["count"], 340)


class TestClientHalf(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app.js").read_text()
        self.alerts_js = (_JS / "app-alerts.js").read_text()
        self.tuning_js = (_JS / "app-tuning.js").read_text()
        self.html = (_HTML / "index.html").read_text()

    def test_an_alert_row_links_to_the_timeline(self):
        self.assertIn('data-action="alertTimeline"', self.alerts_js,
                      "no alert links to the one screen built for incident "
                      "reconstruction")
        self.assertRegex(self.alerts_js, r"\bfunction alertTimeline\s*\(")

    def test_the_deep_link_sends_seconds(self):
        body = self.alerts_js[self.alerts_js.index("function alertTimeline"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("first_seen", body,
                      "centring on `ts` would move as the alert re-fires — "
                      "first_seen is when it actually broke")
        self.assertNotIn("Date.now()", body)

    def test_the_timeline_page_has_the_controls(self):
        for el in ("timeline-around", "timeline-window",
                   "timeline-clear-window"):
            with self.subTest(el=el):
                self.assertIn(f'id="{el}"', self.html)

    def test_the_loader_sends_around_and_window(self):
        body = self.js[self.js.index("async function loadTimeline"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("around=", body)
        self.assertIn("window=", body)

    def test_the_window_is_escapable(self):
        self.assertRegex(self.js, r"\bfunction clearTimelineWindow\s*\(")
        self.assertIn('data-action="clearTimelineWindow"', self.html)

    def test_local_time_is_not_shifted_to_utc(self):
        """datetime-local is LOCAL. `new Date(ts).toISOString().slice(0,16)`
        silently hands the input a UTC wall-clock, so an operator in UTC+2 lands
        two hours away from the incident."""
        body = self.js[self.js.index("function _toLocalInput"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("getTimezoneOffset", body)

    def test_the_summary_reports_the_windowed_count(self):
        """`total` is pre-window; showing it alone claims 300 events for a
        15-minute slice that holds four."""
        body = self.js[self.js.index("async function loadTimeline"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("inside the window", body)

    def test_tuning_renders_a_verdict(self):
        self.assertRegex(self.tuning_js, r"\bfunction _tuningVerdict\s*\(")
        self.assertIn("_tuningVerdict(r)", self.tuning_js)

    def test_the_verdict_says_no_data_rather_than_guessing(self):
        body = self.tuning_js[self.tuning_js.index("function _tuningVerdict"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("no resolution data", body)

    def test_no_inline_handlers_or_styles(self):
        body = self.tuning_js[self.tuning_js.index("function _tuningVerdict"):]
        body = body[:body.index("\n}\n")]
        self.assertNotRegex(body, r"\son\w+=")
        self.assertNotRegex(body, r'\sstyle="')


class TestDocsMatchTheCode(unittest.TestCase):
    """The doc sold a time-range filter that did not exist and called the page
    'the "what happened around 03:40" view' — precisely the query the API could
    not express."""

    def setUp(self):
        p = ROOT / "docs" / "timeline.md"
        if not p.exists():
            self.skipTest("excluded from this tree")
        self.doc = p.read_text()

    def test_the_documented_parameters_are_parsed(self):
        for param in ("since", "until", "around", "window"):
            with self.subTest(param=param):
                self.assertIn(f"`{param}`", self.doc)
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def _timeline_window("):]
        fn = fn[:fn.index("\ndef ")]
        for param in ("since", "until", "around", "window"):
            with self.subTest(parsed=param):
                self.assertIn(f"'{param}'", fn)

    def test_the_audit_gate_is_documented(self):
        self.assertIn("admins and auditors only", self.doc.lower())


if __name__ == "__main__":
    unittest.main()
