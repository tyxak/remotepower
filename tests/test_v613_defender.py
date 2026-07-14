"""v6.2.0 — Windows Defender AV posture (competitive-gap item #7).

RemotePower alerted on ClamAV/rkhunter but a Windows box with real-time
protection switched off was invisible. Defender now rides the SAME server
pipeline (_ingest_av → av_status.json → attention items → av_infected /
av_warning / av_clean) as a distinct `defender` tool key — deliberately NOT
masquerading as 'clamav', which would mislead every webhook consumer.

The genuinely new signal is `realtime_enabled: False` — "AV installed but
switched off". It has no ClamAV equivalent (those are on-demand scanners), so
it gets its own event, and it is a CONDITION not an EVENT: it fires on first
contact (a host that enrols already unprotected is exactly what you want to
hear about) and auto-resolves when protection returns.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-def-"))
_spec = importlib.util.spec_from_file_location("api_v613_def", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# The Windows agent is not importable as a module (no .py-importable name on
# non-Windows and it self-executes), so load it the way the other agent tests do.
_WIN = _ROOT / "client" / "remotepower-agent-win.py"
_wspec = importlib.util.spec_from_file_location("rp_agent_win", _WIN)
winagent = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(winagent)


class TestDefenderParser(unittest.TestCase):
    """The parser is pure, so it is testable without Windows."""

    def test_parses_a_healthy_host(self):
        t = winagent._parse_defender("True|2|1720000000|1719000000|0\n")
        self.assertEqual(t["realtime_enabled"], True)
        self.assertEqual(t["db_age_days"], 2)
        self.assertEqual(t["infected"], 0)
        self.assertEqual(t["last_scan_ts"], 1720000000)  # newest of quick/full

    def test_parses_protection_off(self):
        t = winagent._parse_defender("False|0|0|0|0")
        self.assertIs(t["realtime_enabled"], False)

    def test_threat_count_maps_to_infected(self):
        t = winagent._parse_defender("True|1|0|0|3")
        self.assertEqual(t["infected"], 3)

    def test_unparseable_realtime_omits_the_key_rather_than_guessing(self):
        """A wrong False pages the operator for nothing; a wrong True hides an
        unprotected host. When PowerShell returns junk, report neither."""
        t = winagent._parse_defender("|1|0|0|0")
        self.assertNotIn("realtime_enabled", t)

    def test_garbage_returns_none(self):
        self.assertIsNone(winagent._parse_defender(""))
        self.assertIsNone(winagent._parse_defender("nonsense"))


class TestDefenderIngest(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-def-1"
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        api._entity_write_one(api.AV_FILE, self.dev, {})

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def _ingest(self, av):
        api._ingest_av(self.dev, av, time.time(), "win-host")

    def _events(self):
        return [e for e, _ in self.fired]

    def test_defender_is_persisted_as_its_own_tool(self):
        self._ingest({"defender": {"installed": True, "realtime_enabled": True,
                                   "db_age_days": 1, "infected": 0}})
        rec = api._entity_read_one(api.AV_FILE, self.dev, None) or {}
        self.assertIn("defender", rec)
        self.assertNotIn("clamav", rec, "must not masquerade as another engine")
        self.assertIs(rec["defender"]["realtime_enabled"], True)

    def test_realtime_off_fires_on_first_contact(self):
        """A CONDITION, not an event: a host enrolling with protection already
        off is precisely the host the operator needs to hear about."""
        self._ingest({"defender": {"installed": True, "realtime_enabled": False}})
        evs = [p for e, p in self.fired if e == "av_realtime_off"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["tool"], "defender")

    def test_realtime_off_does_not_re_fire_every_heartbeat(self):
        self._ingest({"defender": {"installed": True, "realtime_enabled": False}})
        self.fired.clear()
        self._ingest({"defender": {"installed": True, "realtime_enabled": False}})
        self.assertNotIn("av_realtime_off", self._events())

    def test_realtime_back_on_auto_resolves(self):
        self._ingest({"defender": {"installed": True, "realtime_enabled": False}})
        self.fired.clear()
        self._ingest({"defender": {"installed": True, "realtime_enabled": True}})
        self.assertIn("av_realtime_on", self._events())

    def test_clamav_host_never_reports_protection_off(self):
        """The tri-state matters: ClamAV has no real-time concept, so an ABSENT
        realtime_enabled must not be read as False. `not None` would have
        reported every Linux host in the fleet as unprotected."""
        self._ingest({"clamav": {"installed": True, "infected": 0, "db_age_days": 1}})
        self.assertNotIn("av_realtime_off", self._events())

    def test_defender_infection_rides_the_existing_av_infected_event(self):
        self._ingest({"defender": {"installed": True, "realtime_enabled": True, "infected": 0}})
        self.fired.clear()
        self._ingest({"defender": {"installed": True, "realtime_enabled": True, "infected": 2}})
        evs = [p for e, p in self.fired if e == "av_infected"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["tool"], "defender")
        self.assertEqual(evs[0]["infected"], 2)

    def test_defender_clean_again_auto_resolves(self):
        self._ingest({"defender": {"installed": True, "infected": 2}})
        self.fired.clear()
        self._ingest({"defender": {"installed": True, "infected": 0}})
        self.assertIn("av_clean", self._events())


class TestWiring(unittest.TestCase):
    def test_events_registered(self):
        off = api.EVENT_REGISTRY["av_realtime_off"]
        self.assertEqual(off["kind"], "av_posture")
        self.assertEqual(off["severity"], "high")
        on = api.EVENT_REGISTRY["av_realtime_on"]
        self.assertIn("av_realtime_off", on["resolves"])

    def test_tool_key_is_whitelisted_on_stored_alerts(self):
        """Without this, the inbox can't say WHICH engine found the malware."""
        src = (_CGI / "api.py").read_text()
        start = src.index("def _record_alert(")
        self.assertIn("'tool'", src[start:start + 6000])

    def test_windows_agent_sends_av_top_level(self):
        """`av` is ingested by _ingest_av, which is NOT part of the safe_si
        sysinfo whitelist — putting it in sysinfo would silently drop it."""
        src = _WIN.read_text()
        self.assertIn("payload['av'] = av", src)
        self.assertNotIn("sysinfo['av']", src)

    def test_agent_extensionless_untouched(self):
        """The .py/extensionless sync rule applies to the LINUX agent only; this
        test documents that the Windows agent has no extensionless twin."""
        self.assertFalse((_ROOT / "client" / "remotepower-agent-win").exists())


if __name__ == "__main__":
    unittest.main()
