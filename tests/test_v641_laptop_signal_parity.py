#!/usr/bin/env python3
"""v6.4.1 guardrail: chassis / battery / uptime_seconds reach the server from
the Windows and macOS agents too.

These three sysinfo fields were Linux-agent-only, so three features were dead
on exactly the hosts they were designed for:

  * `chassis`        → laptop offline-grace (`laptop_offline_grace_hours`), so
                       a closed lid pages like a dead server — on the Windows
                       and Mac laptops that make up most laptop fleets.
  * `battery`        → the `battery_health_low` edge alert, the drawer card and
                       the hardware RAG source.
  * `uptime_seconds` → the fleet uptime leaderboard, whose JS filter is
                       `typeof d.sysinfo.uptime_seconds === 'number'`, silently
                       excluding every non-Linux host.

The important half of this test is the SERVER half: a collector that emits a
shape `safe_si` drops is the dead-signal class wearing a different coat, so we
drive the real `handle_heartbeat` and assert the values land on the device
record — not that the agent merely produced something.

Runs under both backends via `make test-both`.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import api  # noqa: E402


def _load_agent(fname, modname):
    spec = importlib.util.spec_from_file_location(modname, _ROOT / "client" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mac = _load_agent("remotepower-agent-mac.py", "rp_mac_laptop")
win = _load_agent("remotepower-agent-win.py", "rp_win_laptop")


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestCollectorsExistAndDegrade(unittest.TestCase):
    """Both agents must expose all three collectors, and each must degrade to
    an empty/zero value off-platform rather than raising — these run inside a
    try/except in the heartbeat, so an exception would be swallowed and the
    field would silently never appear (the exact failure mode being fixed)."""

    def test_all_three_exist_on_both_agents(self):
        for name, agent in (("mac", mac), ("win", win)):
            for fn in ("get_chassis", "get_battery", "get_uptime_seconds"):
                self.assertTrue(callable(getattr(agent, fn, None)),
                                f"{name} agent is missing {fn}()")

    def test_degrade_off_platform_without_raising(self):
        for name, agent in (("mac", mac), ("win", win)):
            self.assertIsInstance(agent.get_chassis(), str, name)
            self.assertIsInstance(agent.get_battery(), list, name)
            self.assertIsInstance(agent.get_uptime_seconds(), int, name)

    def test_chassis_vocabulary_matches_the_linux_agent(self):
        # The server keys laptop-grace off specific words; a Mac reporting
        # "MacBookPro18,3" instead of "laptop" would silently never match.
        linux = _load_agent("remotepower-agent.py", "rp_linux_laptop")
        import inspect
        allowed = set()
        for src in (inspect.getsource(linux.get_chassis),
                    inspect.getsource(win.get_chassis)):
            for word in ("laptop", "notebook", "portable", "desktop", "server",
                         "tablet", "convertible", "detachable", "all-in-one",
                         "mini-pc"):
                if f"'{word}'" in src:
                    allowed.add(word)
        self.assertIn("laptop", allowed)
        mac_src = inspect.getsource(mac.get_chassis)
        for word in ("laptop", "desktop", "server"):
            self.assertIn(f"'{word}'", mac_src,
                          "mac chassis must use the shared vocabulary")


class TestServerKeepsTheFields(unittest.TestCase):
    """The half that actually matters: safe_si must persist all three."""

    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"
        self.dev_id = "laptop-host"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {"name": self.dev_id, "hostname": self.dev_id,
                          "os": "macOS 15.2", "token": "devtoken",
                          "last_seen": int(time.time()),
                          "enrolled": int(time.time()), "tags": [],
                          "group": "", "sysinfo": {}, "agentless": False}})

    def _beat(self, sysinfo):
        api.get_json_obj = lambda: {
            "device_id": self.dev_id, "token": "devtoken", "sysinfo": sysinfo}

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
        return (api.load(api.DEVICES_FILE)[self.dev_id].get("sysinfo") or {})

    def test_all_three_survive_safe_si(self):
        si = self._beat({
            "os": "macOS 15.2",
            "uptime_seconds": 864000,
            "chassis": "laptop",
            "battery": [{"name": "InternalBattery", "percent": 74,
                         "status": "Discharging", "cycles": 312,
                         "health_pct": 88}],
        })
        self.assertEqual(si.get("uptime_seconds"), 864000,
                         "safe_si dropped uptime_seconds — the uptime "
                         "leaderboard would still exclude this host")
        self.assertEqual(si.get("chassis"), "laptop",
                         "safe_si dropped chassis — laptop offline-grace "
                         "would still never apply")
        bat = si.get("battery") or []
        self.assertTrue(bat, "safe_si dropped battery")
        self.assertEqual(bat[0].get("health_pct"), 88,
                         "battery health_pct is what the low-health alert "
                         "and the hardware RAG line read")

    def test_battery_health_is_what_the_alert_threshold_reads(self):
        # Cross-check the field name against the server's own threshold read,
        # so a rename on either side fails here instead of going quiet.
        import inspect
        src = inspect.getsource(api)
        self.assertIn("health_pct", src,
                      "the server no longer reads health_pct — the agents' "
                      "battery record shape needs updating with it")


if __name__ == "__main__":
    unittest.main(verbosity=2)
