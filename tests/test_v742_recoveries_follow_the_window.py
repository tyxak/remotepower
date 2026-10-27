#!/usr/bin/env python3
"""v7.4.2: a recovery notice rides its alert into a maintenance window.

A window holds the notice for an event in SUPPRESSIBLE_EVENTS. The convention in that tuple was
already "hold the pair": device_offline and device_online, monitor_down and monitor_up,
service_down and service_up, failed_unit and failed_unit_cleared, timer_failed and
timer_failed_cleared, integration_down and integration_recovered. Nine more recoveries were missing
from it, so a window held "metric_warning" and then delivered "metric_recovered", a page that the
operator inside the window never had a reason to expect. 7.4.2 found it when container_recovered
started to fire for containers the agent had reported as gone, fixed that one with its own change,
and closes the other eight (EIGHT below) with the rule this file holds.

The population here is derived, not listed: every event in EVENT_REGISTRY whose `resolves` names a
suppressible event. A new recover event that resolves one has to be suppressible too, or this fails
and names it.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v742-win-"))
_spec = importlib.util.spec_from_file_location("api_v742_win", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# Recover events that resolve a suppressible event and are NOT suppressible, with the reason. Empty:
# there is no recovery that should be delivered inside a window its alert was held in.
EXCEPTIONS = {}

EIGHT = ("patch_ok", "cve_cleared", "service_recover", "container_restarting_cleared",
         "containers_current", "metric_recovered", "reboot_cleared", "backup_recovered")


def population():
    s = set(api.SUPPRESSIBLE_EVENTS)
    return {ev: tuple(meta.get("resolves") or ())
            for ev, meta in api.EVENT_REGISTRY.items()
            if any(r in s for r in (meta.get("resolves") or ()))}


class TestTheRule(unittest.TestCase):

    def test_the_population_was_found(self):
        """The control: a derivation that finds nothing would pass the rule below for free."""
        pop = population()
        self.assertGreaterEqual(len(pop), 15, sorted(pop))
        for known in ("device_online", "monitor_up", "failed_unit_cleared", "integration_recovered",
                      "container_recovered"):
            self.assertIn(known, pop)

    def test_every_recovery_of_a_suppressible_event_is_suppressible(self):
        missing = sorted(ev for ev in population()
                         if ev not in api.SUPPRESSIBLE_EVENTS and ev not in EXCEPTIONS)
        self.assertEqual(missing, [], "these recover a suppressible event and are delivered inside the window "
                                      "that held its alert: add them to SUPPRESSIBLE_EVENTS (and to test_v180)")

    def test_the_rule_would_catch_a_recover_event_added_later(self):
        """The control: register a recovery of a suppressible event that is not suppressible and the
        derivation must list it. A rule that cannot fail is not holding anything."""
        api.EVENT_REGISTRY["zz_probe_recovered"] = {"label": "probe", "kind": "service",
                                                    "resolves": ("service_down",)}
        try:
            missing = sorted(ev for ev in population()
                             if ev not in api.SUPPRESSIBLE_EVENTS and ev not in EXCEPTIONS)
        finally:
            del api.EVENT_REGISTRY["zz_probe_recovered"]
        self.assertEqual(missing, ["zz_probe_recovered"])

    def test_the_exception_list_has_no_dead_entries(self):
        for ev in EXCEPTIONS:
            self.assertIn(ev, population(), ev)
            self.assertNotIn(ev, api.SUPPRESSIBLE_EVENTS, ev)

    def test_the_eight_that_were_missing_are_in(self):
        for ev in EIGHT:
            self.assertIn(ev, api.SUPPRESSIBLE_EVENTS, ev)
            self.assertIn(ev, api.EVENT_REGISTRY, ev)

    def test_the_set_has_no_duplicates_and_only_known_events(self):
        s = list(api.SUPPRESSIBLE_EVENTS)
        self.assertEqual(len(s), len(set(s)), "an event is listed twice")
        # Every entry is a real event or a deliberate external alias; a typo would hold nothing.
        for ev in s:
            self.assertIn(ev, api.EVENT_REGISTRY, f"{ev} is suppressible but not an event")


class TestThroughTheRealGate(unittest.TestCase):
    """The rule above is about a tuple. This drives in_maintenance, the function fire_webhook asks."""

    DEV = "w1"

    def setUp(self):
        import time
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "w1", "monitored": True,
                                               "last_seen": now, "group": ""}})
        api.save(api.MAINT_FILE, {"windows": [{
            "id": "mw1", "scope": "device", "target": self.DEV, "reason": "patching",
            "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 600)),
            "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600))}]})
        api._LOAD_CACHE.clear()

    def test_each_of_the_eight_is_held_for_a_host_in_a_window(self):
        for ev in EIGHT:
            with self.subTest(event=ev):
                held = api.in_maintenance(ev, {"device_id": self.DEV})
                self.assertIsNotNone(held, f"{ev} is delivered inside the window")
                self.assertEqual(held["window_id"], "mw1")

    def test_a_host_outside_the_window_still_gets_them(self):
        api.save(api.DEVICES_FILE, {"other": {"id": "other", "name": "o", "monitored": True, "group": ""}})
        api._LOAD_CACHE.clear()
        for ev in EIGHT:
            self.assertIsNone(api.in_maintenance(ev, {"device_id": "other"}), ev)

    def test_a_window_that_lists_events_holds_only_those(self):
        """The per-window allow-list is untouched by this: a window that names metric_warning holds
        metric_warning and nothing it did not name."""
        import time
        now = int(time.time())
        api.save(api.MAINT_FILE, {"windows": [{
            "id": "mw2", "scope": "device", "target": self.DEV, "events": ["metric_warning"],
            "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 600)),
            "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600))}]})
        api._LOAD_CACHE.clear()
        self.assertIsNotNone(api.in_maintenance("metric_warning", {"device_id": self.DEV}))
        self.assertIsNone(api.in_maintenance("metric_recovered", {"device_id": self.DEV}))

    def test_a_window_can_now_name_a_recovery_in_its_list(self):
        """handle_maintenance_add drops events that are not suppressible; the eight survive it."""
        listed = [e for e in EIGHT if e in api.SUPPRESSIBLE_EVENTS]
        self.assertEqual(listed, list(EIGHT))


if __name__ == "__main__":
    unittest.main()
