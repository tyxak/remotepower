#!/usr/bin/env python3
"""v7.4.3, issue #51: the HTTP monitor's expected status, and an alert that outlives an edit.

(1) "Apps that require a login (Sonarr, Radarr, Lidarr, Readarr, Prowlarr) answer 401 at their
root, so I set expect_status 401. The monitor stays down." urllib raises HTTPError for a 3xx it
does not follow, a 4xx and a 5xx, and that branch decided with `code < 400` first. The expected
status could only turn a pass into a failure there, never the other way, so an expected 4xx or
5xx could not pass.

(2) "I changed five failing monitors' targets (added /ping); they went green, but their open
alerts never closed." monitor_up looked for the open monitor_down by label AND target. The
target in the alert is the one the monitor had when it went down, so an edited target never
matched. Every other piece of per-monitor state (history, the down flag, the failure streak) is
keyed by label, so the label is the monitor's identity and the recovery matches on it alone.

The first half drives the real probe against a local server. The second half goes through the
real persister, the real webhook recorder and the real alert ledger, and edits the monitor with
the real config save: a hand-built alert row would skip the one thing under test, which fields
the recovery matches.
"""
import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v743-mon-"))
_spec = importlib.util.spec_from_file_location("api_v743_mon", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Origin(http.server.BaseHTTPRequestHandler):
    """A small origin: path -> (status, headers, body, delay seconds)."""
    ROUTES = {
        "/ok": (200, {"Content-Type": "application/json"}, b'{"status": "ok"}', 0),
        "/moved": (301, {"Location": "/ok"}, b"", 0),
        "/login": (401, {"Content-Type": "application/json"}, b'{"error": "Unauthorized"}', 0),
        "/slow-login": (401, {"Content-Type": "application/json"}, b'{"error": "Unauthorized"}', 0.3),
        "/forbidden": (403, {}, b"no", 0),
        "/missing": (404, {}, b"gone", 0),
        "/broken": (500, {}, b"oops", 0),
        "/cf": (403, {"cf-mitigated": "challenge"}, b"", 0),
        "/cf-server": (403, {}, b"", 0),
    }

    def version_string(self):
        # BaseHTTPRequestHandler stamps its own Server header, so a route cannot add a second one.
        return "cloudflare" if self.path == "/cf-server" else super().version_string()

    def _answer(self, with_body):
        status, headers, body, delay = self.ROUTES.get(self.path, (404, {}, b"", 0))
        if delay:
            time.sleep(delay)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self):
        self._answer(True)

    def do_HEAD(self):
        self._answer(False)

    def log_message(self, *a):
        pass


def _serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class _Base(unittest.TestCase):
    def setUp(self):
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONFIG_FILE, {}),
                         (api.MON_HIST_FILE, {}), (api.MAINT_FILE, {"windows": []}),
                         (api.MAINT_SUPPRESS_LOG, {"entries": []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def set_config(self, **kw):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update(kw)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()


class TestAnExpectedStatusDecidesAlone(_Base):

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def probe(self, path, **monitor):
        self.set_config(allow_internal_monitors=True)
        return api._run_one_monitor_check("http", self.base + path, "t", dict(monitor))

    def test_without_an_expected_status_nothing_changes(self):
        """The control: the rule an install without the field has always had."""
        for path, ok in (("/ok", True), ("/moved", True), ("/login", False),
                         ("/forbidden", False), ("/missing", False), ("/broken", False)):
            with self.subTest(path=path):
                r = self.probe(path)
                self.assertIs(r["ok"], ok, r)

    def test_an_expected_4xx_or_5xx_passes_when_that_is_what_comes_back(self):
        for path, code in (("/login", 401), ("/forbidden", 403), ("/missing", 404),
                           ("/broken", 500), ("/moved", 301), ("/ok", 200)):
            with self.subTest(path=path, expect=code):
                r = self.probe(path, expect_status=code)
                self.assertTrue(r["ok"], r)
                self.assertTrue(r["detail"].startswith(f"{code} · "), r["detail"])

    def test_any_other_status_fails_and_says_what_was_expected(self):
        for path, got, want in (("/ok", 200, 401), ("/login", 401, 200), ("/login", 401, 403),
                                ("/broken", 500, 503), ("/missing", 404, 200)):
            with self.subTest(path=path, expect=want):
                r = self.probe(path, expect_status=want)
                self.assertFalse(r["ok"], r)
                self.assertEqual(r["detail"], f"{got} (expected {want})")

    def test_the_body_checks_apply_to_the_answer_that_was_expected(self):
        """A check that is configured and never evaluated would read green for nothing."""
        r = self.probe("/login", expect_status=401, body_match={"mode": "contains", "value": "Unauthorized"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, body_match={"mode": "contains", "value": "Welcome"})
        self.assertFalse(r["ok"], r)
        self.assertIn("not found", r["detail"])
        r = self.probe("/login", expect_status=401, body_match={"mode": "not_contains", "value": "Unauthorized"})
        self.assertFalse(r["ok"], r)
        r = self.probe("/login", expect_status=401, body_match={"mode": "regex", "value": "Unauth[a-z]+"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "error", "value": "Unauthorized"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "error", "value": "Other"})
        self.assertFalse(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "missing"})
        self.assertFalse(r["ok"], r)

    def test_the_latency_limit_applies_to_the_answer_that_was_expected(self):
        r = self.probe("/slow-login", expect_status=401, max_latency_ms=60)
        self.assertFalse(r["ok"], r)
        self.assertIn("SLA", r["detail"])
        r = self.probe("/slow-login", expect_status=401, max_latency_ms=20000)
        self.assertTrue(r["ok"], r)

    def test_a_wrong_status_is_reported_before_a_body_that_does_not_match(self):
        """The status is the first question; a body that cannot be right is a second one."""
        r = self.probe("/ok", expect_status=401, body_match={"mode": "contains", "value": "Welcome"})
        self.assertEqual(r["detail"], "200 (expected 401)")

    def test_who_refused_is_still_named(self):
        """7.0.3: a bare 403 read as a host that was down. That naming survives."""
        for path, words in (("/cf", "refused by the edge"), ("/cf-server", "refused by Cloudflare")):
            for monitor in ({}, {"expect_status": 200}):
                with self.subTest(path=path, monitor=monitor):
                    r = self.probe(path, **monitor)
                    self.assertFalse(r["ok"], r)
                    self.assertIn(words, r["detail"])

    def test_a_flow_step_already_behaves_this_way(self):
        """The multi-step monitor never had the bug; this keeps the two in agreement."""
        self.set_config(allow_internal_monitors=True)
        ok, detail = api._run_http_flow({"steps": [{"method": "GET", "url": self.base + "/login",
                                                    "expect_status": 401}]})
        self.assertTrue(ok, detail)

    def test_the_save_accepts_a_4xx_and_a_5xx(self):
        for code in (401, 403, 404, 500, 503):
            with self.subTest(code=code):
                mons = _save_monitors(self, [{"type": "http", "label": "app", "target": "https://app.example/",
                                              "expect_status": code}])
                self.assertEqual(mons[0]["expect_status"], code)


def _save_monitors(case, monitors, extra=None):
    """The real config save, with only the sign-in stubbed (verify_token), as for any gate test."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
             "audit_log", "respond", "require_admin_auth")
    saved = {n: getattr(api, n) for n in names}
    body = {"monitors": monitors}
    body.update(extra or {})
    box = {}
    api.require_admin_auth = lambda: "alice"
    api.verify_token = lambda t: ("alice", "admin")
    api.get_token_from_request = lambda: "t"
    api.method = lambda: "POST"
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    case.assertEqual(box.get("status"), 200, box)
    api._LOAD_CACHE.clear()
    return (api.load(api.CONFIG_FILE) or {}).get("monitors") or []


class TestEditingATargetDoesNotStrandTheAlert(_Base):

    def setUp(self):
        super().setUp()
        self.events = []
        self._real_fire = api.fire_webhook

        def spy(event, payload):
            self.events.append((event, dict(payload)))
            return self._real_fire(event, payload)
        api.fire_webhook = spy

    def tearDown(self):
        api.fire_webhook = self._real_fire
        super().tearDown()

    def result(self, label, target, ok, mtype="http"):
        return {"label": label, "type": mtype, "target": target, "ok": ok,
                "detail": "200" if ok else "401", "checked": int(time.time())}

    def sweep(self, *results):
        api._LOAD_CACHE.clear()
        api._persist_monitor_results(list(results))
        api._LOAD_CACHE.clear()

    def alerts(self, event="monitor_down"):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == event]

    def open_labels(self):
        return sorted((a.get("payload") or {}).get("label") for a in self.alerts() if not a.get("resolved_at"))

    def monitor(self, label, target):
        return {"type": "http", "label": label, "target": target}

    def test_a_target_edited_while_the_monitor_is_down_still_closes_on_recovery(self):
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", old)])
        self.sweep(self.result("Sonarr", old, False))
        self.assertEqual(self.open_labels(), ["Sonarr"])
        self.assertEqual((self.alerts()[0]["payload"] or {}).get("target"), old)

        _save_monitors(self, [self.monitor("Sonarr", new)])
        self.assertEqual(self.open_labels(), ["Sonarr"], "an edit alone does not claim the host is up")

        self.sweep(self.result("Sonarr", new, True))
        self.assertEqual(self.open_labels(), [], "the monitor is up under its new target")
        self.assertEqual([e for e, _ in self.events], ["monitor_down", "monitor_up"])
        self.assertEqual(self.alerts()[0].get("resolved_by"), "auto")

    def test_a_monitor_that_is_still_down_after_the_edit_keeps_one_alert(self):
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", old)])
        self.sweep(self.result("Sonarr", old, False))
        _save_monitors(self, [self.monitor("Sonarr", new)])
        self.sweep(self.result("Sonarr", new, False))
        self.sweep(self.result("Sonarr", new, False))
        self.assertEqual([e for e, _ in self.events], ["monitor_down"], "the down flag survives an edit")
        self.assertEqual(self.open_labels(), ["Sonarr"])

    def test_a_recovery_closes_only_the_monitor_it_names(self):
        a, b = "http://10.0.0.5:8989/", "http://10.0.0.5:7878/"
        self.set_config(monitors=[self.monitor("Sonarr", a), self.monitor("Radarr", b)])
        self.sweep(self.result("Sonarr", a, False), self.result("Radarr", b, False))
        self.assertEqual(self.open_labels(), ["Radarr", "Sonarr"])
        self.sweep(self.result("Sonarr", a + "ping", True), self.result("Radarr", b, False))
        self.assertEqual(self.open_labels(), ["Radarr"])

    def test_the_hosts_of_a_group_monitor_close_one_at_a_time(self):
        sep = api._MON_FANOUT_SEP
        self.set_config(monitors=[{"type": "tcp", "label": "web", "target": "web", "target_kind": "tag",
                                   "port": 443}])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"),
                   self.result("web" + sep + "h2", "10.0.0.2:443", False, "tcp"))
        self.assertEqual(len(self.open_labels()), 2)
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", True, "tcp"),
                   self.result("web" + sep + "h2", "10.0.0.2:443", False, "tcp"))
        self.assertEqual(self.open_labels(), ["web" + sep + "h2"])

    def test_an_alert_the_old_code_left_behind_closes_when_the_monitor_next_recovers(self):
        """Alerts that were stranded on 7.4.2 hold the old target; the next recovery clears them too."""
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", new)],
                        monitor_notified={"Sonarr": True}, monitor_fail_streak={"Sonarr": 1})
        api.fire_webhook("monitor_down", {"label": "Sonarr", "type": "http", "target": old, "detail": "401"})
        self.assertEqual(self.open_labels(), ["Sonarr"])
        self.sweep(self.result("Sonarr", new, True))
        self.assertEqual(self.open_labels(), [])

    def test_deleting_a_monitor_that_is_down_closes_its_alert(self):
        a, b = "http://10.0.0.5:8989/", "http://10.0.0.5:7878/"
        self.set_config(monitors=[self.monitor("Sonarr", a), self.monitor("Radarr", b)])
        self.sweep(self.result("Sonarr", a, False), self.result("Radarr", b, False))
        _save_monitors(self, [self.monitor("Radarr", b)])
        self.assertEqual(self.open_labels(), ["Radarr"], "nothing watches Sonarr any more")

    def test_renaming_a_monitor_that_is_down_closes_the_old_alert_and_the_new_name_alerts_afresh(self):
        a = "http://10.0.0.5:8989/"
        self.set_config(monitors=[self.monitor("Sonarr", a)])
        self.sweep(self.result("Sonarr", a, False))
        _save_monitors(self, [self.monitor("Sonarr (LAN)", a)])
        self.assertEqual(self.open_labels(), [])
        self.sweep(self.result("Sonarr (LAN)", a, False))
        self.assertEqual(self.open_labels(), ["Sonarr (LAN)"])

    def test_deleting_the_hosts_of_a_group_monitor_closes_their_alerts(self):
        sep = api._MON_FANOUT_SEP
        self.set_config(monitors=[{"type": "tcp", "label": "web", "target": "web", "target_kind": "tag",
                                   "port": 443}])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"))
        _save_monitors(self, [])
        self.assertEqual(self.open_labels(), [])

    def test_a_group_monitor_that_is_kept_keeps_the_alerts_of_its_hosts(self):
        """The hosts of a tag monitor are keyed 'label · host', and the monitor itself is still there."""
        sep = api._MON_FANOUT_SEP
        mon = {"type": "tcp", "label": "web", "target": "web", "target_kind": "tag", "port": 443}
        self.set_config(monitors=[mon])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"))
        _save_monitors(self, [mon, self.monitor("Radarr", "http://10.0.0.5:7878/")])
        self.assertEqual(self.open_labels(), ["web" + sep + "h1"])

    def test_a_save_that_does_not_touch_the_monitors_leaves_the_alerts_alone(self):
        a = "http://10.0.0.5:8989/"
        self.set_config(monitors=[self.monitor("Sonarr", a)])
        self.sweep(self.result("Sonarr", a, False))
        saved = {n: getattr(api, n) for n in ("verify_token", "get_token_from_request", "method",
                                              "get_json_body", "get_json_obj", "audit_log", "respond",
                                              "require_admin_auth")}
        api.require_admin_auth = lambda: "alice"
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"monitor_interval": 120}
        api.get_json_obj = api.get_json_body
        api.audit_log = lambda *a, **k: None
        box = {}

        def _resp(status, data=None):
            box["status"] = status
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_config_save()
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(box.get("status"), 200, box)
        self.assertEqual(self.open_labels(), ["Sonarr"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
