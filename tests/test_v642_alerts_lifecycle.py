"""v6.4.2 — alert lifecycle: first_seen, inbox paging/filtering, control-plane
security events, and the last-login / session-inventory access-review surface.

Every test here DRIVES the real handler or the real _record_alert path. A
source-text assertion would have passed for all four of these bugs: the alert
row genuinely carried a `ts`, the list handler genuinely sliced a list, the
event registry genuinely had 183 entries, and the user record genuinely
persisted — what was wrong was what those values MEANT.
"""

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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-life-"))
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")

_spec = importlib.util.spec_from_file_location("api_v642_life", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def call(fn, *args, **kwargs):
    """Run a handler and capture its response. respond() raises HTTPError, so a
    plain call never returns — catching the exception is the only way to read
    the status and body without stubbing respond() (which would then leak into
    every later test in the process)."""
    try:
        fn(*args, **kwargs)
    except api.HTTPError as e:
        return e.status, e.body
    return None, None


class _AlertBase(unittest.TestCase):
    """Isolate ALERTS_FILE per test and let every event through the gates."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-"))
        self._saved = {n: getattr(api, n) for n in
                       ("ALERTS_FILE", "FLEET_EVENTS_FILE", "_module_on",
                        "_channel_allowed", "device_get", "_alert_muted")}
        api.ALERTS_FILE = self.d / "alerts.json"
        api.FLEET_EVENTS_FILE = self.d / "fleet_events.json"
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.save(api.FLEET_EVENTS_FILE, {"events": []})
        api._module_on = lambda n: True
        api._channel_allowed = lambda e, c, routing=None: True
        api.device_get = lambda i: {"monitored": True}
        api._alert_muted = lambda e, p: False
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def alerts(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.ALERTS_FILE) or {}).get("alerts", [])


class TestAlertFirstSeen(_AlertBase):
    """The escalation bug: a coalescing alert reset its own age on every fire."""

    def test_new_alert_stamps_first_seen_equal_to_ts(self):
        api._record_alert("service_down", {"device_id": "h1", "unit": "nginx"})
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["first_seen"], rows[0]["ts"])
        self.assertGreater(rows[0]["first_seen"], 0)

    def test_coalescing_advances_ts_but_preserves_first_seen(self):
        api._record_alert("service_down", {"device_id": "h1", "unit": "nginx"})
        original = self.alerts()[0]["first_seen"]
        # Re-fire the SAME condition 30 minutes later, the way an edge-triggered
        # check does on every heartbeat.
        later = original + 1800
        _real_time = time.time
        time.time = lambda: float(later)
        try:
            api._record_alert("service_down", {"device_id": "h1", "unit": "nginx"})
        finally:
            time.time = _real_time
        rows = self.alerts()
        self.assertEqual(len(rows), 1, "the repeat firing must coalesce, not append")
        self.assertEqual(rows[0]["count"], 2)
        self.assertEqual(rows[0]["ts"], later, "ts tracks the LAST occurrence")
        self.assertEqual(rows[0]["last_seen"], later)
        self.assertEqual(rows[0]["first_seen"], original,
                         "first_seen must survive coalescing — this is the whole bug")
        self.assertEqual(api._alert_first_seen(rows[0]), original)

    def test_age_from_first_seen_grows_while_age_from_ts_does_not(self):
        """The concrete failure: 90 minutes of continuous breakage looks 0
        minutes old if you measure from `ts`."""
        api._record_alert("nic_errors", {"device_id": "h1", "iface": "eth0"})
        start = self.alerts()[0]["first_seen"]
        _real_time = time.time
        try:
            for minute in (30, 60, 90):
                time.time = lambda m=minute: float(start + m * 60)
                api._record_alert("nic_errors", {"device_id": "h1", "iface": "eth0"})
        finally:
            time.time = _real_time
        row = self.alerts()[0]
        now = start + 90 * 60
        self.assertEqual((now - row["ts"]) / 60.0, 0.0,
                         "sanity: measuring from ts really does report a zero age")
        self.assertEqual((now - api._alert_first_seen(row)) / 60.0, 90.0)

    def test_legacy_row_without_first_seen_adopts_its_ts(self):
        """An alert already open when the server upgrades has no first_seen —
        its stored ts IS its first observation and must be adopted, not lost."""
        old = int(time.time()) - 7200
        api.save(api.ALERTS_FILE, {"alerts": [{
            "id": "a-legacy", "alertid": "alertid_000001", "ts": old,
            "event": "service_down", "severity": "high", "title": "Service Down",
            "device_id": "h1", "device_name": "h1",
            "payload": {"device_id": "h1", "unit": "nginx"},
            "source": "internal", "acknowledged_by": None, "acknowledged_at": None,
            "resolved_by": None, "resolved_at": None,
        }]})
        api._LOAD_CACHE.clear()
        api._record_alert("service_down", {"device_id": "h1", "unit": "nginx"})
        rows = self.alerts()
        self.assertEqual(len(rows), 1, "must coalesce onto the legacy row")
        self.assertEqual(rows[0]["first_seen"], old)
        self.assertGreater(rows[0]["ts"], old)

    def test_alert_first_seen_fallbacks(self):
        self.assertEqual(api._alert_first_seen({"first_seen": 5, "ts": 9}), 5)
        self.assertEqual(api._alert_first_seen({"ts": 9}), 9)
        self.assertEqual(api._alert_first_seen({}), 0)
        self.assertEqual(api._alert_first_seen(None), 0)
        self.assertEqual(api._alert_first_seen({"first_seen": "junk", "ts": 9}), 0)


class TestResolutionStatsMeasureFromFirstSeen(_AlertBase):
    """MTTA/MTTR were measured from the last occurrence, so the noisier an
    incident was the better its numbers looked."""

    def setUp(self):
        super().setUp()
        self._auth = {n: getattr(api, n) for n in
                      ("require_auth", "_filter_alerts_for_caller")}
        api.require_auth = lambda *a, **k: "alice"
        api._filter_alerts_for_caller = lambda rows: list(rows)
        os.environ["QUERY_STRING"] = "days=30"

    def tearDown(self):
        for n, v in self._auth.items():
            setattr(api, n, v)
        os.environ.pop("QUERY_STRING", None)
        super().tearDown()

    def test_mttr_and_mtta_use_first_seen(self):
        now = int(time.time())
        api.save(api.ALERTS_FILE, {"alerts": [{
            "id": "a-1", "alertid": "alertid_000001",
            "first_seen": now - 3600,      # broke an hour ago
            "ts": now - 60,                # last re-fire a minute ago
            "event": "service_down", "severity": "high", "title": "Service Down",
            "device_id": "h1", "device_name": "h1", "payload": {},
            "acknowledged_by": "alice", "acknowledged_at": now - 1800,
            "resolved_by": "alice", "resolved_at": now,
        }]})
        api._LOAD_CACHE.clear()
        status, body = call(api.handle_alert_resolution_stats)
        self.assertEqual(status, 200)
        self.assertEqual(body["mttr_mean"], 3600,
                         "MTTR must run from when it broke, not from the last re-fire")
        self.assertEqual(body["mtta_mean"], 1800)
        self.assertEqual(body["timeline"][0]["first_seen"], now - 3600)

    def test_legacy_row_without_first_seen_still_scores(self):
        now = int(time.time())
        api.save(api.ALERTS_FILE, {"alerts": [{
            "id": "a-2", "alertid": "alertid_000002", "ts": now - 600,
            "event": "service_down", "severity": "high", "title": "Service Down",
            "device_id": "h1", "device_name": "h1", "payload": {},
            "acknowledged_by": None, "acknowledged_at": 0,
            "resolved_by": "bob", "resolved_at": now,
        }]})
        api._LOAD_CACHE.clear()
        status, body = call(api.handle_alert_resolution_stats)
        self.assertEqual(status, 200)
        self.assertEqual(body["mttr_mean"], 600, "old rows must not become 0-second MTTRs")


# The escalation half of the first_seen fix lives in oncall_handlers.py
# (_escalation_tick reads a.get('ts')), which this agent does not own. The test
# below is the real driving test; it activates automatically once that one line
# reads _alert_first_seen. Until then it skips with an explicit reason rather
# than pretending to cover behaviour that isn't there.
_ONCALL_SRC = (_CGI / "oncall_handlers.py").read_text() if (_CGI / "oncall_handlers.py").exists() else ""
_ESC_USES_FIRST_SEEN = "_alert_first_seen" in _ONCALL_SRC


class TestEscalationAgesFromFirstSeen(_AlertBase):

    @unittest.skipUnless(
        _ESC_USES_FIRST_SEEN,
        "blocked on the oncall_handlers.py half: _escalation_tick still ages "
        "alerts off a.get('ts'), which _record_alert rewrites on every re-fire")
    def test_repeatedly_refiring_alert_still_escalates(self):
        saved_cfg = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        sends = []
        saved_send = api._send_webhook_to_url
        api._send_webhook_to_url = lambda *a, **k: sends.append(a)
        try:
            api.save(api.CONFIG_FILE, {"escalation": {
                "enabled": True, "severities": ["high", "critical"],
                "tiers": [{"after_minutes": 15}]}})
            api._LOAD_CACHE.clear()
            api._record_alert("nic_errors", {"device_id": "h1", "iface": "eth0"})
            start = self.alerts()[0]["first_seen"]
            _real_time = time.time
            try:
                for minute in (5, 10, 16, 20):
                    time.time = lambda m=minute: float(start + m * 60)
                    api._record_alert("nic_errors", {"device_id": "h1", "iface": "eth0"})
            finally:
                time.time = _real_time
            api._LOAD_CACHE.clear()
            api._escalation_tick(now=start + 20 * 60)
            self.assertTrue(sends, "an alert open for 20m past a 15m tier must escalate")
            self.assertEqual(self.alerts()[0].get("escalated_tiers"), [0])
        finally:
            api._send_webhook_to_url = saved_send
            api.CONFIG_FILE = saved_cfg
            api._LOAD_CACHE.clear()


class TestAlertsListPagingAndFiltering(_AlertBase):
    """GET /api/alerts could only ever return the newest `limit` rows."""

    def setUp(self):
        super().setUp()
        self._auth = {n: getattr(api, n) for n in
                      ("verify_token", "get_token_from_request")}
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "tok"
        rows, base = [], int(time.time()) - 1000
        for i in range(25):
            rows.append({
                "id": f"a-{i}", "alertid": f"alertid_{i:06d}",
                "ts": base + i, "first_seen": base + i,
                "event": "service_down" if i % 2 else "disk_low",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "title": f"Alert number {i}",
                "device_id": "h1" if i < 10 else "h2",
                "device_name": "web01" if i < 10 else "db02",
                "payload": {}, "source": "internal",
                "acknowledged_by": None, "acknowledged_at": None,
                "resolved_by": None, "resolved_at": None,
            })
        api.save(api.ALERTS_FILE, {"alerts": rows})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._auth.items():
            setattr(api, n, v)
        os.environ.pop("QUERY_STRING", None)
        super().tearDown()

    def get(self, qs=""):
        os.environ["QUERY_STRING"] = qs
        api._LOAD_CACHE.clear()
        status, body = call(api.handle_alerts_list)
        self.assertEqual(status, 200, body)
        return body

    def test_envelope_carries_total_offset_and_limit(self):
        b = self.get("status=open&limit=10")
        self.assertEqual(b["total"], 25)
        self.assertEqual(b["offset"], 0)
        self.assertEqual(b["limit"], 10)
        self.assertEqual(len(b["alerts"]), 10)

    def test_offset_reaches_rows_the_first_page_cannot(self):
        first = self.get("status=open&limit=10")
        second = self.get("status=open&limit=10&offset=10")
        third = self.get("status=open&limit=10&offset=20")
        self.assertEqual(len(second["alerts"]), 10)
        self.assertEqual(len(third["alerts"]), 5, "the tail page must be short, not empty")
        ids = [a["id"] for a in first["alerts"] + second["alerts"] + third["alerts"]]
        self.assertEqual(len(set(ids)), 25, "paging must not repeat or drop rows")
        self.assertEqual(second["total"], 25, "total is the filtered count, not the page size")

    def test_offset_is_clamped_and_survives_garbage(self):
        self.assertEqual(self.get("offset=-5")["offset"], 0)
        self.assertEqual(self.get("offset=abc")["offset"], 0)
        self.assertEqual(self.get("offset=999")["alerts"], [])

    def test_device_id_filter(self):
        b = self.get("device_id=h2")
        self.assertEqual(b["total"], 15)
        self.assertTrue(all(a["device_id"] == "h2" for a in b["alerts"]))

    def test_severity_filter_single_and_comma_list(self):
        one = self.get("severity=critical")
        self.assertTrue(one["total"] > 0)
        self.assertTrue(all(a["severity"] == "critical" for a in one["alerts"]))
        two = self.get("severity=critical,high")
        self.assertEqual(two["total"], one["total"] + self.get("severity=high")["total"])
        self.assertEqual(self.get("severity=bogus")["total"], 25,
                         "an unknown severity must not silently empty the inbox")

    def test_q_matches_device_name_event_and_title(self):
        self.assertEqual(self.get("q=web01")["total"], 10)
        self.assertEqual(self.get("q=DISK_LOW")["total"],
                         self.get("q=disk_low")["total"])
        self.assertGreater(self.get("q=disk_low")["total"], 0)
        self.assertEqual(self.get("q=Alert number 7")["total"], 1)
        self.assertEqual(self.get("q=nothing-matches-this")["total"], 0)

    def test_filters_combine_and_total_reflects_the_filtered_set(self):
        b = self.get("device_id=h1&severity=high&limit=2")
        self.assertLessEqual(len(b["alerts"]), 2)
        self.assertTrue(all(a["device_id"] == "h1" and a["severity"] == "high"
                            for a in b["alerts"]))
        self.assertEqual(b["total"],
                         len([a for a in self.get("device_id=h1&limit=1000")["alerts"]
                              if a["severity"] == "high"]))

    def test_defaults_are_unchanged_for_an_existing_caller(self):
        b = self.get("")
        self.assertEqual(b["limit"], 200)
        self.assertEqual(b["offset"], 0)
        self.assertIn("summary", b)
        self.assertIn("ack_comment_enabled", b)

    def test_filtering_runs_after_the_visibility_filter(self):
        """`total` must never count a row the caller cannot see."""
        saved = api._filter_alerts_for_caller
        api._filter_alerts_for_caller = lambda rows: [a for a in rows
                                                      if a.get("device_id") == "h1"]
        try:
            b = self.get("status=open&limit=1000")
            self.assertEqual(b["total"], 10)
            self.assertTrue(all(a["device_id"] == "h1" for a in b["alerts"]))
        finally:
            api._filter_alerts_for_caller = saved


class TestControlPlaneSecurityEvent(_AlertBase):
    """Nothing fired when somebody became an admin OF REMOTEPOWER."""

    EV = "control_plane_security_change"

    def test_registry_entry_follows_the_point_event_rules(self):
        spec = api.EVENT_REGISTRY[self.EV]
        self.assertIn(spec["kind"], {k for k, _l, _g in api.CHANNEL_KIND_DEFS})
        self.assertEqual(spec["severity"], "high")
        self.assertEqual(spec["lifecycle"], "point")
        self.assertTrue(spec.get("label"))
        self.assertTrue(spec.get("title"))
        self.assertIn(self.EV, {e[0] for e in api.WEBHOOK_EVENTS})
        self.assertNotIn(self.EV, api._ALERT_RECOVER.values(),
                         "a privilege change is an event, not a state — no recover")
        for _ev, spec2 in api.EVENT_REGISTRY.items():
            self.assertNotIn(self.EV, spec2.get("resolves") or ())

    def test_fire_records_an_alert_with_the_payload_intact(self):
        api._fire_control_plane_change("admin_user_created", "root", "mallory")
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        p = rows[0]["payload"]
        self.assertEqual(rows[0]["event"], self.EV)
        self.assertEqual(rows[0]["severity"], "high")
        # These four only survive because they are in the _record_alert
        # whitelist — an un-whitelisted key is dropped silently.
        self.assertEqual(p["change"], "admin_user_created")
        self.assertEqual(p["actor"], "root")
        self.assertEqual(p["target_user"], "mallory")
        self.assertIn("admin account", p["detail"])

    def test_fire_records_a_fleet_event_with_the_payload_intact(self):
        api._fire_control_plane_change("audit_log_cleared", "root")
        api._LOAD_CACHE.clear()
        evs = [e for e in (api.load(api.FLEET_EVENTS_FILE) or {}).get("events", [])
               if e.get("event") == self.EV]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["payload"]["change"], "audit_log_cleared")
        self.assertEqual(evs[0]["payload"]["actor"], "root")

    def test_unknown_change_key_fires_nothing(self):
        api._fire_control_plane_change("not_a_real_change", "root")
        self.assertEqual(self.alerts(), [])

    def test_two_changes_do_not_coalesce_into_one_row(self):
        api._fire_control_plane_change("admin_user_created", "root", "a")
        api._fire_control_plane_change("admin_user_created", "root", "b")
        self.assertEqual(len(self.alerts()), 2,
                         "two separate privilege grants are two events")


class TestControlPlaneFireSites(_AlertBase):
    """Drive the real handlers — a helper nobody calls is not a feature."""

    EV = "control_plane_security_change"

    def setUp(self):
        super().setUp()
        self.d2 = Path(tempfile.mkdtemp(prefix="rp-v642-cp-"))
        self._saved2 = {n: getattr(api, n) for n in
                        ("USERS_FILE", "APIKEYS_FILE", "CONFIG_FILE",
                         "require_admin_auth", "require_step_up",
                         "get_json_body", "audit_log", "_config_ro")}
        api.USERS_FILE = self.d2 / "users.json"
        api.APIKEYS_FILE = self.d2 / "apikeys.json"
        api.CONFIG_FILE = self.d2 / "config.json"
        api.save(api.USERS_FILE, {"root": {"role": "admin", "password_hash": "x"}})
        api.save(api.APIKEYS_FILE, {})
        api.save(api.CONFIG_FILE, {})
        api.require_admin_auth = lambda *a, **k: "root"
        api.require_step_up = lambda *a, **k: None
        api.audit_log = lambda *a, **k: None
        api._config_ro = lambda: {}
        self.body = {}
        api.get_json_body = lambda: self.body
        os.environ["REQUEST_METHOD"] = "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved2.items():
            setattr(api, n, v)
        os.environ["REQUEST_METHOD"] = "GET"
        super().tearDown()

    def fired(self):
        return [a for a in self.alerts() if a["event"] == self.EV]

    def test_creating_an_admin_user_fires_it(self):
        self.body = {"username": "mallory", "password": "Correct-Horse-9!x",
                     "role": "admin"}
        status, body = call(api.handle_user_create)
        self.assertEqual(status, 201, body)
        rows = self.fired()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["change"], "admin_user_created")
        self.assertEqual(rows[0]["payload"]["target_user"], "mallory")

    def test_creating_a_viewer_does_not_fire_it(self):
        self.body = {"username": "reader", "password": "Correct-Horse-9!x",
                     "role": "viewer"}
        status, body = call(api.handle_user_create)
        self.assertEqual(status, 201, body)
        self.assertEqual(self.fired(), [], "a read-only account is not a privilege grant")

    def test_promoting_an_existing_user_to_admin_fires_it(self):
        api.save(api.USERS_FILE, {"root": {"role": "admin", "password_hash": "x"},
                                  "reader": {"role": "viewer", "password_hash": "x"}})
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "PATCH"
        self.body = {"role": "admin"}
        status, body = call(api.handle_user_update, "reader")
        self.assertEqual(status, 200, body)
        rows = self.fired()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["change"], "user_promoted_to_admin")
        self.assertEqual(rows[0]["payload"]["target_user"], "reader")

    def test_demoting_an_admin_does_not_fire_it(self):
        api.save(api.USERS_FILE, {"root": {"role": "admin", "password_hash": "x"},
                                  "other": {"role": "admin", "password_hash": "x"}})
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "PATCH"
        self.body = {"role": "viewer"}
        status, body = call(api.handle_user_update, "other")
        self.assertEqual(status, 200, body)
        self.assertEqual(self.fired(), [])

    def test_minting_an_admin_api_key_fires_it(self):
        self.body = {"name": "ci-bot", "role": "admin", "user": "ci"}
        status, body = call(api.handle_apikeys_create)
        self.assertEqual(status, 201, body)
        rows = self.fired()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["change"], "admin_apikey_created")

    def test_minting_a_viewer_api_key_does_not_fire_it(self):
        self.body = {"name": "dash", "role": "viewer", "user": "ci"}
        status, body = call(api.handle_apikeys_create)
        self.assertEqual(status, 201, body)
        self.assertEqual(self.fired(), [])

    def _save_config(self, before, body):
        api.save(api.CONFIG_FILE, before)
        api._LOAD_CACHE.clear()
        self.body = body
        status, resp = call(api.handle_config_save)
        self.assertEqual(status, 200, resp)

    def test_disabling_mfa_enforcement_fires_it(self):
        self._save_config({"mfa_required_roles": ["admin"]},
                          {"mfa_required_roles": []})
        rows = self.fired()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["change"], "mfa_enforcement_disabled")

    def test_enabling_mfa_enforcement_does_not_fire_it(self):
        self._save_config({"mfa_required_roles": []},
                          {"mfa_required_roles": ["admin"]})
        self.assertEqual(self.fired(), [], "turning a control ON is not a security event")

    def test_disabling_change_approval_fires_it(self):
        self._save_config({"change_approval_enabled": True},
                          {"change_approval_enabled": False})
        rows = self.fired()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["change"], "change_approval_disabled")

    def test_an_unrelated_settings_save_fires_nothing(self):
        self._save_config({"change_approval_enabled": True,
                           "mfa_required_roles": ["admin"]},
                          {"incident_device_threshold": 5})
        self.assertEqual(self.fired(), [])


class TestResolveNoteRoundTrip(_AlertBase):
    """Item 3 was reported as already-implemented; prove it end to end rather
    than taking the code's word for it."""

    def setUp(self):
        super().setUp()
        self._saved3 = {n: getattr(api, n) for n in
                        ("_check_alert_mutation_perm", "_alert_mutable_by_caller",
                         "get_json_body", "audit_log", "require_auth",
                         "_filter_alerts_for_caller")}
        api._check_alert_mutation_perm = lambda *a, **k: "alice"
        api._alert_mutable_by_caller = lambda a: True
        api._filter_alerts_for_caller = lambda rows: list(rows)
        api.require_auth = lambda *a, **k: "alice"
        api.audit_log = lambda *a, **k: None
        self.body = {}
        api.get_json_body = lambda: self.body
        os.environ["REQUEST_METHOD"] = "POST"

    def tearDown(self):
        for n, v in self._saved3.items():
            setattr(api, n, v)
        os.environ["REQUEST_METHOD"] = "GET"
        os.environ.pop("QUERY_STRING", None)
        super().tearDown()

    def test_note_is_stored_and_surfaces_in_resolution_stats(self):
        api._record_alert("service_down", {"device_id": "h1", "unit": "nginx"})
        aid = self.alerts()[0]["id"]
        self.body = {"note": "restarted nginx; bad config from the 14:02 deploy"}
        status, body = call(api.handle_alert_resolve, aid)
        self.assertEqual(status, 200, body)
        api._LOAD_CACHE.clear()
        self.assertEqual(self.alerts()[0]["resolve_note"], self.body["note"])
        os.environ["REQUEST_METHOD"] = "GET"
        os.environ["QUERY_STRING"] = "days=30"
        status, stats = call(api.handle_alert_resolution_stats)
        self.assertEqual(status, 200)
        self.assertEqual(stats["timeline"][0]["note"], self.body["note"])


class TestLastLoginAndSessionInventory(unittest.TestCase):
    """Access review (SOC 2 CC6.2/CC6.3): who has an account nobody uses, and
    who is logged in right now."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-sess-"))
        self._saved = {n: getattr(api, n) for n in
                       ("USERS_FILE", "TOKENS_FILE", "CONFIG_FILE", "TENANTS_FILE",
                        "require_admin_auth", "require_auth", "audit_log",
                        "verify_token", "get_token_from_request")}
        api.USERS_FILE = self.d / "users.json"
        api.TOKENS_FILE = self.d / "tokens.json"
        api.CONFIG_FILE = self.d / "config.json"
        api.TENANTS_FILE = self.d / "tenants.json"
        api.save(api.CONFIG_FILE, {})
        api.save(api.TENANTS_FILE, {})
        api.save(api.TOKENS_FILE, {})
        api.save(api.USERS_FILE, {
            "alice": {"role": "admin", "password_hash": "x", "created": 1},
            "bob": {"role": "viewer", "password_hash": "x", "created": 2},
        })
        api.require_admin_auth = lambda *a, **k: "alice"
        api.require_auth = lambda *a, **k: "alice"
        api.audit_log = lambda *a, **k: None
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "tok-alice"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def test_route_is_registered(self):
        routes = api._build_exact_routes()
        self.assertIs(routes[("GET", "/api/sessions")], api.handle_sessions_list)

    def test_stamp_last_login_writes_the_user_record(self):
        api._stamp_last_login("alice")
        api._LOAD_CACHE.clear()
        self.assertGreater(api.load(api.USERS_FILE)["alice"]["last_login"], 0)

    def test_stamp_last_login_is_a_noop_for_an_unknown_user(self):
        api._stamp_last_login("nobody")
        api._LOAD_CACHE.clear()
        self.assertNotIn("nobody", api.load(api.USERS_FILE))

    def test_mint_session_stamps_last_login(self):
        """Every SSO path (SAML/OIDC/passkey) mints through here."""
        api._stamp = None
        token = api._mint_session("bob")
        self.assertTrue(token)
        api._LOAD_CACHE.clear()
        self.assertGreater(api.load(api.USERS_FILE)["bob"]["last_login"], 0)

    def test_users_list_exposes_last_login(self):
        api._stamp_last_login("alice")
        api._LOAD_CACHE.clear()
        status, rows = call(api.handle_users_list)
        self.assertEqual(status, 200)
        by = {r["username"]: r for r in rows}
        self.assertGreater(by["alice"]["last_login"], 0)
        self.assertEqual(by["bob"]["last_login"], 0, "never-logged-in reads as 0")

    def _seed_sessions(self):
        now = int(time.time())
        api.save(api.TOKENS_FILE, {
            api._token_hash("tok-alice"): {"user": "alice", "created": now - 60,
                                           "ttl": 3600, "ip": "10.0.0.1",
                                           "ua": "Firefox", "last_seen": now},
            api._token_hash("tok-bob"): {"user": "bob", "created": now - 120,
                                         "ttl": 3600, "ip": "10.0.0.2",
                                         "ua": "curl", "last_seen": now - 90,
                                         "oidc": True},
            api._token_hash("tok-stale"): {"user": "bob", "created": now - 99999,
                                           "ttl": 3600, "ip": "10.0.0.3",
                                           "ua": "old", "last_seen": now - 99999},
        })
        api._LOAD_CACHE.clear()
        return now

    def test_sessions_list_returns_live_sessions_and_hides_expired(self):
        self._seed_sessions()
        status, body = call(api.handle_sessions_list)
        self.assertEqual(status, 200, body)
        users = sorted(s["user"] for s in body["sessions"])
        self.assertEqual(users, ["alice", "bob"],
                         "the expired session must be filtered out")
        self.assertEqual(body["count"], 2)
        rows = {s["user"]: s for s in body["sessions"]}
        self.assertTrue(rows["alice"]["current"], "the caller's own session is flagged")
        self.assertFalse(rows["bob"]["current"])
        self.assertEqual(rows["bob"]["source"], "oidc")
        self.assertEqual(rows["alice"]["role"], "admin")
        self.assertEqual(rows["bob"]["role"], "viewer")
        self.assertEqual(rows["alice"]["ip"], "10.0.0.1")

    def test_sessions_list_never_returns_a_raw_token(self):
        self._seed_sessions()
        _status, body = call(api.handle_sessions_list)
        blob = repr(body)
        for raw in ("tok-alice", "tok-bob", "tok-stale"):
            self.assertNotIn(raw, blob)
        for s in body["sessions"]:
            self.assertEqual(len(s["id"]), 16)

    def test_sessions_list_rejects_a_non_get(self):
        os.environ["REQUEST_METHOD"] = "DELETE"
        try:
            status, _ = call(api.handle_sessions_list)
            self.assertEqual(status, 405)
        finally:
            os.environ["REQUEST_METHOD"] = "GET"

    def test_sessions_list_is_admin_gated(self):
        """Stub only verify_token — stubbing require_admin_auth would pass a
        handler with no gate at all."""
        api.require_admin_auth = self._saved["require_admin_auth"]
        api.require_auth = self._saved["require_auth"]   # require_admin_auth delegates to it
        api.verify_token = lambda t: ("bob", "viewer")
        self._seed_sessions()
        status, _ = call(api.handle_sessions_list)
        self.assertIn(status, (401, 403))

    def test_sessions_list_respects_tenancy(self):
        """A user-keyed store, so the gate follows the ACCOUNT's tenant."""
        api.save(api.TENANTS_FILE, {"t2": {"name": "T2", "status": "active"}})
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.USERS_FILE, {
            "alice": {"role": "admin", "password_hash": "x", "tenant_id": "t2"},
            "bob": {"role": "viewer", "password_hash": "x"},   # default tenant
        })
        self._seed_sessions()
        # alice is an admin in t2 → NOT a superadmin → gate == 't2'.
        self.assertEqual(api._tenant_gate(), "t2")
        status, body = call(api.handle_sessions_list)
        self.assertEqual(status, 200, body)
        self.assertEqual([s["user"] for s in body["sessions"]], ["alice"],
                         "bob lives in another tenant and must be invisible")

    def test_superadmin_sees_every_tenant(self):
        api.save(api.TENANTS_FILE, {"t2": {"name": "T2", "status": "active"}})
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.USERS_FILE, {
            "alice": {"role": "admin", "password_hash": "x"},   # default tenant
            "bob": {"role": "viewer", "password_hash": "x", "tenant_id": "t2"},
        })
        self._seed_sessions()
        self.assertIsNone(api._tenant_gate())
        _status, body = call(api.handle_sessions_list)
        self.assertEqual(sorted(s["user"] for s in body["sessions"]), ["alice", "bob"])


if __name__ == "__main__":
    unittest.main()
