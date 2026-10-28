#!/usr/bin/env python3
"""v7.4.3, issue #48: a maintenance window can raise no alerts at all, not only hold the notifications.

"My nightly backup stops and restarts 17 containers on one host inside a 32-minute window; each raises a
'container stopped' alert that sits on the dashboard until its container returns, and all 17 land in the
alert history every night. The work is planned and expected, so these aren't problems, but they look like
problems to anyone who opens the dashboard during the backup, and they bury real alerts in the history."

A window now has a second setting, `suppress`: `notifications` (what every window has always done: the
event is held back from webhooks, e-mail and push, and listed in the suppression log) or `alerts`, which
also keeps the event out of the Alerts inbox and out of Needs attention and the stopped-containers count.
An alert that was open before the window starts stays open, and a recovery that arrives inside the window
still closes it.

Everything here goes through the real heartbeat, the real webhook recorder and the real alert ledger. A
hand-built alert row would skip the one thing under test: whether the window is asked before the row is
written.
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, api, ctr  # noqa: E402
import attention_isolation  # noqa: E402


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def window(suppress=None, events=None, scope="device", target=DEV, start=-60, end=3600, wid="mw_t1"):
    """A one-shot window; start and end are seconds from now."""
    now = int(time.time())
    w = {"id": wid, "reason": "nightly backup", "scope": scope, "target": target,
         "start": iso(now + start), "end": iso(now + end), "duration": 0, "cron": "", "events": events or []}
    if suppress is not None:
        w["suppress"] = suppress
    return w


def put(*windows):
    api.save(api.MAINT_FILE, {"windows": list(windows)})
    api._LOAD_CACHE.clear()


class _Window(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.FLEET_EVENTS_FILE, {"events": []})
        api._LOAD_CACHE.clear()

    def inbox(self, event="container_stopped"):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == event]

    def open_names(self, event="container_stopped"):
        return sorted((a.get("payload") or {}).get("container") for a in self.inbox(event)
                      if not a.get("resolved_at"))

    def held(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.MAINT_SUPPRESS_LOG) or {}).get("entries", [])

    def activity(self):
        api._LOAD_CACHE.clear()
        store = api.load(api.FLEET_EVENTS_FILE) or {}
        rows = store.get("events", store) if isinstance(store, dict) else store
        return [r.get("event") for r in rows if isinstance(r, dict)]

    def stop_all(self, names):
        self.beat([ctr(n) for n in names])
        self.beat([])                                # a backup that docker-stops everything


class TestWhatTheWindowHolds(_Window):

    NAMES = [f"app{i}" for i in range(17)]

    def test_a_window_without_the_setting_holds_the_notification_and_keeps_the_alert(self):
        """The control: every window that exists today behaves as it did."""
        put(window())
        self.stop_all(self.NAMES)
        self.assertEqual(len(self.open_names()), 17)
        self.assertEqual(len([h for h in self.held() if h["event"] == "container_stopped"]), 17)

    def test_notifications_only_is_the_same_as_no_setting(self):
        put(window(suppress="notifications"))
        self.stop_all(self.NAMES[:3])
        self.assertEqual(len(self.open_names()), 3)

    def test_the_reporters_backup_raises_no_alert_and_leaves_a_record(self):
        put(window(suppress="alerts"))
        self.stop_all(self.NAMES)
        self.assertEqual(self.inbox(), [], "no alert row at all, open or resolved")
        held = [h for h in self.held() if h["event"] == "container_stopped"]
        self.assertEqual(len(held), 17, "every held event is in the suppression log")
        self.assertTrue(all(h["window_id"] == "mw_t1" for h in held))
        self.beat([ctr(n) for n in self.NAMES])      # the containers are back
        self.assertEqual(self.inbox(), [])
        self.assertEqual(len([h for h in self.held() if h["event"] == "container_recovered"]), 17)

    def test_the_record_of_what_happened_is_kept(self):
        """The activity feed is the log of what happened on the fleet. A window never edited it, and
        the suppression log is where "held" is told apart from "did not happen"."""
        put(window(suppress="alerts"))
        self.stop_all(self.NAMES[:2])
        self.assertEqual(self.activity().count("container_stopped"), 2)

    def test_a_window_that_has_not_started_or_has_ended_holds_nothing(self):
        for start, end in ((600, 3600), (-7200, -60)):
            with self.subTest(start=start):
                api.save(api.ALERTS_FILE, {"alerts": []})
                put(window(suppress="alerts", start=start, end=end))
                self.stop_all(["web"])
                self.assertEqual(self.open_names(), ["web"])
                self.beat([ctr("web")])

    def test_another_host_is_not_covered(self):
        put(window(suppress="alerts", target="some-other-host"))
        self.stop_all(["web"])
        self.assertEqual(self.open_names(), ["web"])

    def test_a_fleet_wide_window_covers_the_host(self):
        put(window(suppress="alerts", scope="global", target=""))
        self.stop_all(["web"])
        self.assertEqual(self.inbox(), [])

    def test_only_the_listed_events_are_held(self):
        put(window(suppress="alerts", events=["container_recovered"]))
        self.stop_all(["web"])
        self.assertEqual(self.open_names(), ["web"], "container_stopped is not in the window's list")

    def test_an_event_the_window_does_not_cover_still_raises_its_alert(self):
        """The window covers the events a window can cover; a disk that fills up during the backup is not one
        of the ones it was asked to hold."""
        put(window(suppress="alerts", events=["container_stopped", "container_recovered"]))
        api.fire_webhook("metric_critical", {"device_id": DEV, "name": "serverbox", "metric": "disk",
                                             "target": "/", "value": 97})
        self.assertEqual(len(self.inbox("metric_critical")), 1)

    def test_when_two_windows_overlap_the_stronger_one_decides(self):
        for order in ((0, 1), (1, 0)):
            with self.subTest(order=order):
                api.save(api.ALERTS_FILE, {"alerts": []})
                both = [window(wid="mw_a"), window(suppress="alerts", wid="mw_b")]
                put(*[both[i] for i in order])
                self.stop_all(["web"])
                self.assertEqual(self.inbox(), [])
                self.beat([ctr("web")])


class TestWhatWasAlreadyOpen(_Window):

    def test_an_alert_open_before_the_window_stays_open(self):
        self.stop_all(["web"])
        self.assertEqual(self.open_names(), ["web"])
        put(window(suppress="alerts"))
        self.beat([])                                # still gone, the window has begun
        self.assertEqual(self.open_names(), ["web"], "starting a window does not close what is open")
        self.assertEqual(len(self.inbox()), 1, "and does not add a second row for it")

    def test_a_recovery_inside_the_window_still_closes_it(self):
        self.stop_all(["web"])
        put(window(suppress="alerts"))
        self.beat([ctr("web")])
        self.assertEqual(self.open_names(), [])
        self.assertIsNotNone(self.inbox()[0].get("resolved_at"))

    def test_an_alert_raised_after_the_window_is_a_normal_alert(self):
        put(window(suppress="alerts", start=-3600, end=-60))
        self.stop_all(["web"])
        self.assertEqual(self.open_names(), ["web"])


class TestNeedsAttentionAndTheDashboard(_Window):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix="rp-v743-maint-")
        self._saved = attention_isolation.isolate(api, self._tmp)
        api.save(api.DEVICES_FILE, {DEV: {
            "name": "serverbox", "group": "g", "monitored": True, "tags": [], "enrolled": int(time.time()) - 99999,
            "last_seen": int(time.time()), "sysinfo": {}}})
        api.save(api.CONFIG_FILE, {})
        api.save(api.MAINT_FILE, {"windows": []})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        attention_isolation.restore(api, self._saved)
        super().tearDown()

    def stopped(self):
        api.save(api.CONTAINERS_FILE, {DEV: {"ts": int(time.time()), "items": [
            ctr("web"), ctr("db", status="Exited (1) 2 hours ago"), ctr("job", status="Exited (0) 1 hour ago")]}})
        api._LOAD_CACHE.clear()

    def digest_kinds(self):
        api._LOAD_CACHE.clear()
        return sorted(i.get("kind") for i in api._compute_attention())

    def widget(self):
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        return api._dashboard_extra_widgets(devs, api.load(api.CONFIG_FILE), int(time.time()),
                                            want={"containers"})["containers"]["stopped"]

    def test_the_digest_and_the_widget_show_a_stopped_container_without_a_window(self):
        self.stopped()
        self.assertIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 2)

    def test_a_notifications_window_changes_neither(self):
        self.stopped()
        put(window(suppress="notifications"))
        self.assertIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 2)

    def test_a_window_that_raises_no_alerts_empties_both(self):
        self.stopped()
        put(window(suppress="alerts"))
        self.assertNotIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 0)

    def test_they_come_back_when_the_window_ends(self):
        self.stopped()
        put(window(suppress="alerts"))
        self.assertNotIn("container", self.digest_kinds())
        put(window(suppress="alerts", start=-7200, end=-60))
        self.assertIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 2)

    def test_a_window_for_other_events_leaves_them(self):
        self.stopped()
        put(window(suppress="alerts", events=["device_offline"]))
        self.assertIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 2)

    def test_another_hosts_window_leaves_them(self):
        self.stopped()
        put(window(suppress="alerts", target="some-other-host"))
        self.assertIn("container", self.digest_kinds())
        self.assertEqual(self.widget(), 2)

    def test_an_offline_host_is_held_by_the_same_rule(self):
        api.save(api.DEVICES_FILE, {})                # the store refuses a last_seen that goes backwards
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {DEV: {
            "name": "serverbox", "group": "g", "monitored": True, "tags": [], "enrolled": int(time.time()) - 99999,
            "last_seen": int(time.time()) - 86400, "sysinfo": {}}})
        put(window(suppress="notifications"))
        self.assertIn("offline", self.digest_kinds())
        put(window(suppress="alerts"))
        self.assertNotIn("offline", self.digest_kinds())

    def test_the_digest_cache_follows_a_window_that_is_added(self):
        """The digest is cached for ten seconds and keyed on what an operator changes; a window is one."""
        self.stopped()
        api._attention_payload(use_cache=False)
        self.assertGreater(api._attention_payload(use_cache=True)["total"], 0)
        before = api._attention_payload(use_cache=True)["total"]
        put(window(suppress="alerts"))
        self.assertLess(api._attention_payload(use_cache=True)["total"], before)


def _call(handler, body, *path):
    """A handler through its real sign-in, with only verify_token stubbed."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
             "audit_log", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.verify_token = lambda t: ("alice", "admin")
    api.get_token_from_request = lambda: "t"
    api.method = lambda: "PUT" if path else "POST"
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(*path)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class TestTheWindowForm(_Window):

    BODY = {"reason": "nightly backup", "scope": "device", "target": DEV,
            "start": iso(int(time.time()) + 300), "end": iso(int(time.time()) + 3900), "events": []}

    def create(self, **extra):
        box = _call(api.handle_maintenance_add, dict(self.BODY, **extra))
        self.assertEqual(box.get("status"), 200, box)
        return box["body"]["window"]

    def test_a_new_window_defaults_to_holding_notifications(self):
        self.assertEqual(self.create()["suppress"], "notifications")

    def test_the_choice_is_stored_and_listed(self):
        w = self.create(suppress="alerts")
        self.assertEqual(w["suppress"], "alerts")
        stored = (api.load(api.MAINT_FILE) or {})["windows"]
        self.assertEqual([x["suppress"] for x in stored], ["alerts"])
        box = _call(api.handle_maintenance_list, {})
        self.assertEqual([x["suppress"] for x in box["body"]["windows"]], ["alerts"])

    def test_only_the_word_alerts_asks_for_it(self):
        for given in ("ALERTS", " alerts "):
            self.assertEqual(self.create(suppress=given)["suppress"], "alerts", given)
        for given in ("all", "none", "", None, True, 1, ["alerts"], {"a": 1}):
            with self.subTest(given=given):
                self.assertEqual(self.create(suppress=given)["suppress"], "notifications")

    def test_the_window_an_auto_patch_policy_writes_says_what_it_holds(self):
        """The mirror is "a complete window, the same shape the add handler writes"."""
        api.save(api.MAINT_FILE, {"windows": []})
        api._autopatch_sync({"id": "p1", "name": "Sunday", "enabled": True, "cron": "0 3 * * 0",
                             "target": {"type": "all"}})
        api._LOAD_CACHE.clear()
        wins = [w for w in (api.load(api.MAINT_FILE) or {}).get("windows", []) if w.get("autopatch_id") == "p1"]
        self.assertEqual(len(wins), 1, wins)
        self.assertEqual(wins[0].get("suppress"), "notifications")

    def test_an_edit_can_switch_it_both_ways(self):
        w = self.create(suppress="alerts")
        box = _call(api.handle_maintenance_update, dict(self.BODY, suppress="notifications"), w["id"])
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(box["body"]["window"]["suppress"], "notifications")
        box = _call(api.handle_maintenance_update, dict(self.BODY, suppress="alerts"), w["id"])
        self.assertEqual(box["body"]["window"]["suppress"], "alerts")

    def test_an_edit_that_does_not_mention_it_means_notifications(self):
        """The form always sends it; an API client that never heard of it is asking for what it always got."""
        w = self.create(suppress="alerts")
        box = _call(api.handle_maintenance_update, dict(self.BODY), w["id"])
        self.assertEqual(box["body"]["window"]["suppress"], "notifications")


if __name__ == "__main__":
    unittest.main()
