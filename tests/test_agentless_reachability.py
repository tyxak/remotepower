#!/usr/bin/env python3
"""v3.3.4: agentless ICMP reachability + offline/online alerts.

Agentless devices have no heartbeat. They now default to an ICMP ping
check (run_agentless_reachability_if_due) that flips `reachable` and fires
device_offline / device_online on the edge, with a 2-fail debounce; a
'manual' mode keeps the operator-set manual_status for ping-blocked hosts.
_ping_host is mocked so these tests never touch the network.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_reach", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _seed_agentless(dev_id="nas", reachability="icmp", monitored=True, **extra):
    devs = api.load(api.DEVICES_FILE)
    devs[dev_id] = {"name": dev_id, "agentless": True, "ip": "10.0.0.9",
                    "reachability": reachability, "monitored": monitored, **extra}
    api.save(api.DEVICES_FILE, devs)


def _reset_sweep_marker():
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg["last_agentless_ping"] = 0
    api.save(api.CONFIG_FILE, cfg)


def _events():
    """Recorded fleet events (device_offline / device_online)."""
    ev = api.load(api.FLEET_EVENTS_FILE) if hasattr(api, "FLEET_EVENTS_FILE") else None
    return ev or []


class TestAgentlessOnlineHelper(unittest.TestCase):
    def test_manual_mode_uses_manual_status(self):
        self.assertTrue(api._agentless_online({"reachability": "manual", "manual_status": True}))
        self.assertFalse(api._agentless_online({"reachability": "manual", "manual_status": False}))

    def test_icmp_mode_uses_reachable(self):
        self.assertTrue(api._agentless_online({"reachability": "icmp", "reachable": True}))
        self.assertFalse(api._agentless_online({"reachability": "icmp", "reachable": False}))

    def test_defaults_up(self):
        # absent fields -> icmp, reachable defaults True (no flash of down)
        self.assertTrue(api._agentless_online({}))


class TestReachabilitySweep(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api.save(f, {})
        _seed_agentless("nas", reachability="icmp", monitored=True)
        _reset_sweep_marker()

    def _sweep(self, up):
        _reset_sweep_marker()
        with patch.object(api, "_ping_host", return_value=up), \
             patch.object(api, "fire_webhook") as fw, \
             patch.object(api, "_record_uptime"):
            api.run_agentless_reachability_if_due()
        return fw

    def test_success_marks_reachable_no_alert(self):
        fw = self._sweep(up=True)
        self.assertTrue(api.load(api.DEVICES_FILE)["nas"]["reachable"])
        fw.assert_not_called()

    def test_two_fails_marks_down_and_fires_offline(self):
        self._sweep(up=False)            # 1st fail — debounce, still up
        self.assertNotEqual(api.load(api.DEVICES_FILE)["nas"].get("reachable"), False)
        fw = self._sweep(up=False)       # 2nd fail — now down + alert
        self.assertFalse(api.load(api.DEVICES_FILE)["nas"]["reachable"])
        fw.assert_called_once()
        self.assertEqual(fw.call_args[0][0], "device_offline")

    def test_recovery_fires_online(self):
        self._sweep(up=False)
        self._sweep(up=False)            # down
        fw = self._sweep(up=True)        # back up
        fw.assert_called_once()
        self.assertEqual(fw.call_args[0][0], "device_online")
        self.assertTrue(api.load(api.DEVICES_FILE)["nas"]["reachable"])

    def test_manual_device_is_not_pinged(self):
        _seed_agentless("manualbox", reachability="manual", manual_status=False)
        called = {"n": 0}

        def spy(*a, **k):
            called["n"] += 1
            return True
        _reset_sweep_marker()
        with patch.object(api, "_ping_host", side_effect=spy), \
             patch.object(api, "fire_webhook"), patch.object(api, "_record_uptime"):
            api.run_agentless_reachability_if_due()
        # only the icmp 'nas' is pinged, never the manual box
        self.assertEqual(called["n"], 1)

    def test_unmonitored_down_stays_silent(self):
        _seed_agentless("nas", reachability="icmp", monitored=False)
        self._sweep(up=False)
        fw = self._sweep(up=False)
        self.assertFalse(api.load(api.DEVICES_FILE)["nas"]["reachable"])
        fw.assert_not_called()           # status updated, no alert


if __name__ == "__main__":
    unittest.main()
