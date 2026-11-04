#!/usr/bin/env python3
"""v7.5.0 (docs cross-check): four ways a maintenance window did less, or more, than it said.

* **Browser push ignored the situation.** `fire_webhook` sent the push before it asked about a maintenance window, quiet hours, an
  unmonitored host and an upstream that is down, so a window that held the webhook and the e-mail still paged every subscribed browser
  (and a host marked unmonitored did too). Push now obeys those holds and keeps its own switch and its severity floor.
* **Editing a window in the dialog switched it off the public status page.** The validator returned `public` and `public_title` (off,
  empty) whether or not the request named them, and the dialog never sends them.
* **An auto-patch policy for one tag or site silenced the whole fleet.** It became a `global` window; windows have taken a tag and a
  site since 7.0.2 and match a host the way the policy does.
* **The active-scan refusal named the wrong menu.** The page is under Scheduling.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-mw-"))

from apisrc import api_source  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v750_mw", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class _Base(unittest.TestCase):
    FILES = ("CONFIG_FILE", "DEVICES_FILE", "MAINT_FILE", "CALENDAR_FILE")

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-mw-d-"))
        self._saved = {n: getattr(api, n) for n in self.FILES}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)   # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "web01", "tags": ["web"], "site": "oslo", "group": "prod"},
            "d2": {"name": "db01", "tags": ["db"], "site": "bergen", "group": "prod"},
        })
        api.save(api.MAINT_FILE, {"windows": []})
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def config(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def windows(self, *ws):
        api.save(api.MAINT_FILE, {"windows": list(ws)})
        api._LOAD_CACHE.clear()


class TestBrowserPushObeysTheSituation(_Base):

    def setUp(self):
        super().setUp()
        self.pushed, self.webhooks, self.mails = [], [], []
        sinks = {
            "_record_fleet_event": lambda *a, **k: None, "_record_alert": lambda *a, **k: None,
            "_auto_resolve_alerts": lambda *a, **k: None, "_forward_siem": lambda *a, **k: None,
            "_run_automation_rules": lambda *a, **k: None, "_record_after_hours": lambda *a, **k: None,
            "_deliver_user_notifications": lambda *a, **k: None, "log_suppression": lambda *a, **k: None,
            "_log_webhook": lambda *a, **k: None,
            "_maybe_webpush": lambda event, payload: self.pushed.append(event),
            "_send_webhook_to_url": lambda *a, **k: self.webhooks.append(a[0]),
            "_send_event_email": lambda *a, **k: self.mails.append(a[0]),
            "is_webhook_event_enabled": lambda event: True,
            "_channel_allowed": lambda *a, **k: True,
            "_alert_muted": lambda *a, **k: False,
        }
        for name, value in sinks.items():
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def fire(self, event="device_offline", device="d1"):
        self.pushed.clear()
        self.webhooks.clear()
        api.fire_webhook(event, {"device_id": device, "name": "x"})
        return list(self.pushed), list(self.webhooks)

    def test_a_normal_event_reaches_both(self):
        """Control: nothing holds it, so the push and the webhook both go."""
        self.assertEqual(self.fire(), (["device_offline"], ["device_offline"]))

    def test_a_maintenance_window_holds_the_push_as_it_holds_the_webhook(self):
        now = int(time.time())
        self.windows({"id": "w1", "scope": "global", "target": "", "start": _iso(now - 60), "end": _iso(now + 3600),
                      "reason": "patching", "events": [], "suppress": "notifications"})
        self.assertEqual(self.fire(), ([], []))

    def test_a_window_for_another_host_holds_nothing(self):
        now = int(time.time())
        self.windows({"id": "w1", "scope": "device", "target": "d2", "start": _iso(now - 60), "end": _iso(now + 3600),
                      "reason": "patching db01", "events": []})
        self.assertEqual(self.fire(device="d1"), (["device_offline"], ["device_offline"]))
        self.assertEqual(self.fire(device="d2"), ([], []))

    def test_a_window_that_has_closed_holds_nothing(self):
        now = int(time.time())
        self.windows({"id": "w1", "scope": "global", "target": "", "start": _iso(now - 7200), "end": _iso(now - 3600), "reason": "old"})
        self.assertEqual(self.fire(), (["device_offline"], ["device_offline"]))

    def test_an_unmonitored_host_pages_nobody(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "monitored": False}})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.fire(), ([], []))

    def test_a_down_upstream_holds_the_push_with_the_webhook(self):
        with mock.patch.object(api, "_upstream_down", lambda *a, **k: "core-switch"):
            self.assertEqual(self.fire(), ([], []))

    def test_quiet_hours_hold_a_high_alert_and_let_a_critical_one_through(self):
        self.config(quiet_hours={"enabled": True, "start": "00:00", "end": "23:59", "min_severity": "critical"})
        high = next(e for e, (sev, _) in api._ALERT_RULES.items() if sev == "high")
        self.assertEqual(api._ALERT_RULES["device_offline"][0], "critical", "control: the other event is a critical alert")
        self.assertEqual(self.fire(high), ([], []), "a high alert is held by quiet hours, push included")
        self.assertEqual(self.fire("device_offline"), (["device_offline"], ["device_offline"]),
                         "a critical alert bypasses quiet hours")

    def test_a_muted_event_is_still_not_pushed(self):
        with mock.patch.object(api, "_alert_muted", lambda *a, **k: True):
            self.assertEqual(self.fire(), ([], []))

    def test_the_held_reason_names_the_hold(self):
        self.assertEqual(api._push_held_reason("device_offline", {"device_id": "d1"}, {"reason": "x"}, None), "maintenance")
        self.assertEqual(api._push_held_reason("device_offline", {"device_id": "d1"}, None, "core-switch"), "upstream down")
        self.assertEqual(api._push_held_reason("device_offline", {"device_id": "d1"}, None, None), "")


class TestThePushChannelKeepsItsOwnRules(_Base):
    """The holds above are added in front of `_maybe_webpush`; its own switch and severity floor are still the ones that decide."""

    def setUp(self):
        super().setUp()
        self.sent = []
        p = mock.patch.object(api, "_webpush_send_all", lambda *a, **k: self.sent.append(a[0]))
        p.start()
        self.addCleanup(p.stop)

    def test_off_by_default_and_high_or_critical_only(self):
        api._maybe_webpush("device_offline", {"device_id": "d1", "name": "web01"})
        self.assertEqual(self.sent, [], "push is off until it is enabled")
        self.config(webpush_enabled=True)
        api._maybe_webpush("device_offline", {"device_id": "d1", "name": "web01"})
        self.assertEqual(len(self.sent), 1)
        low = next(e for e, (sev, _) in api._ALERT_RULES.items() if sev in ("low", "medium"))
        api._maybe_webpush(low, {"device_id": "d1", "name": "web01"})
        self.assertEqual(len(self.sent), 1, "a low or medium alert is not pushed")


class TestAWindowEditedInTheDialog(_Base):

    def setUp(self):
        super().setUp()
        for name, value in (("verify_token", lambda token=None, *a, **k: ("alice", "admin")),
                            ("get_token_from_request", lambda: "t"), ("audit_log", lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def call(self, fn, method, body, *args):
        with mock.patch.object(api, "method", lambda: method), mock.patch.object(api, "get_json_body", lambda: dict(body)), \
                mock.patch.object(api, "get_json_obj", lambda: dict(body)):
            try:
                fn(*args)
            except api.HTTPError as e:
                return e.status, e.body
        self.fail("answered nothing")

    def stored(self, wid):
        api._LOAD_CACHE.clear()
        return next(w for w in api.load(api.MAINT_FILE)["windows"] if w["id"] == wid)

    DIALOG = {"reason": "kernel update", "scope": "global", "target": "", "events": [], "gate_exec": False,
              "suppress": "notifications", "cron": "0 3 * * 6", "duration": 3600}

    def create(self, **extra):
        status, body = self.call(api.handle_maintenance_add, "POST", dict(self.DIALOG, **extra))
        self.assertEqual(status, 200, body)
        return body["window"]["id"] if "window" in body else body.get("id")

    def test_a_window_created_without_the_flags_has_them_off(self):
        wid = self.create()
        w = self.stored(wid)
        self.assertEqual((w["public"], w["public_title"]), (False, ""))

    def test_the_dialog_does_not_send_the_flags_and_an_edit_keeps_them(self):
        wid = self.create(public=True, public_title="Planned maintenance")
        self.assertEqual((self.stored(wid)["public"], self.stored(wid)["public_title"]), (True, "Planned maintenance"))
        status, body = self.call(api.handle_maintenance_update, "PUT", dict(self.DIALOG, reason="kernel update, later"), wid)
        self.assertEqual(status, 200, body)
        w = self.stored(wid)
        self.assertEqual(w["reason"], "kernel update, later", "control: the edit did apply")
        self.assertEqual((w["public"], w["public_title"]), (True, "Planned maintenance"))

    def test_an_edit_that_names_the_flags_changes_them(self):
        wid = self.create(public=True, public_title="Planned maintenance")
        self.call(api.handle_maintenance_update, "PUT", dict(self.DIALOG, public=False), wid)
        w = self.stored(wid)
        self.assertEqual((w["public"], w["public_title"]), (False, "Planned maintenance"))
        self.call(api.handle_maintenance_update, "PUT", dict(self.DIALOG, public=True, public_title="New title"), wid)
        self.assertEqual((self.stored(wid)["public"], self.stored(wid)["public_title"]), (True, "New title"))


class TestAutoPatchWindows(_Base):

    def policy(self, target):
        return {"id": "p1", "name": "saturday", "enabled": True, "cron": "* * * * *", "target": target, "reboot": False, "tenant_gate": None}

    def sync(self, target):
        api._autopatch_sync(self.policy(target))
        api._LOAD_CACHE.clear()
        (w,) = [w for w in api.load(api.MAINT_FILE)["windows"] if w.get("autopatch_id") == "p1"]
        return w

    def test_each_target_maps_to_a_window_of_its_own_scope(self):
        for target, scope, value in (({"type": "device", "value": "d1"}, "device", "d1"), ({"type": "group", "value": "prod"}, "group", "prod"),
                                     ({"type": "tag", "value": "web"}, "tag", "web"), ({"type": "site", "value": "oslo"}, "site", "oslo"),
                                     ({"type": "all"}, "global", "")):
            with self.subTest(target=target):
                w = self.sync(target)
                self.assertEqual((w["scope"], w["target"]), (scope, value))

    def test_a_tag_policy_silences_the_hosts_with_that_tag_and_no_others(self):
        self.sync({"type": "tag", "value": "web"})
        self.assertIsNotNone(api.in_maintenance("device_offline", {"device_id": "d1"}), "web01 carries the tag")
        self.assertIsNone(api.in_maintenance("device_offline", {"device_id": "d2"}), "db01 does not: its alerts still go out")

    def test_a_site_policy_silences_that_site_and_no_other(self):
        self.sync({"type": "site", "value": "bergen"})
        self.assertIsNone(api.in_maintenance("device_offline", {"device_id": "d1"}))
        self.assertIsNotNone(api.in_maintenance("device_offline", {"device_id": "d2"}))

    def test_an_all_policy_is_still_fleet_wide(self):
        self.sync({"type": "all"})
        self.assertIsNotNone(api.in_maintenance("device_offline", {"device_id": "d1"}))
        self.assertIsNotNone(api.in_maintenance("device_offline", {"device_id": "d2"}))

    def test_a_policy_without_a_value_does_not_become_a_window_that_matches_nothing(self):
        w = self.sync({"type": "tag", "value": ""})
        self.assertEqual(w["scope"], "global")


class TestTheMenuInTheScanMessage(unittest.TestCase):

    def test_the_server_message_and_every_translation_name_scheduling(self):
        src = api_source()
        self.assertIn("open one (Scheduling → '", src)
        self.assertNotIn("open one (Monitoring → '", src)
        i18n = (_JS / "i18n.js").read_text()
        line = next(ln for ln in i18n.splitlines() if "active scan needs an active maintenance window" in ln)
        self.assertIn("(Scheduling → Maintenance)", line)
        for lang_menu in ("调度", "शेड्यूलिंग", "Programación", "الجدولة", "Zeitplanung", "Planification"):
            self.assertIn(lang_menu, line)
        for old in ("监控 → 维护", "निगरानी → रखरखाव", "Monitorización → Mantenimiento", "المراقبة ← الصيانة", "Überwachung → Wartung",
                    "Surveillance → Maintenance"):
            self.assertNotIn(old, line)


if __name__ == "__main__":
    unittest.main()
