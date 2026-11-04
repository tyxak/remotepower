#!/usr/bin/env python3
"""Defender switched off reaches the risk score and the compliance AV control.

`posture_signals.av_verdict` tested `av_rec[tool].get("realtime") is False`. Nothing writes that
key: the Windows agent's parser writes `realtime_enabled` and `_ingest_av` keeps it. So a Windows
host with Defender's real-time protection off scored nothing in the risk score and passed the
compliance AV control (PCI 5.2.1, HIPAA 164.308(a)(5)(ii)(B)), while the alert, the Checks row and
the AI index all saw it. Three test fixtures carried the wrong key, which is why the tests passed.

The record here is built the way the product builds it: the agent's own parser reads the PowerShell
line, the real ingest stores it, and the three readers are asked about what was stored.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-def-"))

import compliance  # noqa: E402
import posture_signals as ps  # noqa: E402

_wspec = importlib.util.spec_from_file_location("rp_agent_win_v750_def", ROOT / "client" / "remotepower-agent-win.py")
winagent = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(winagent)


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-def-api-")
    spec = importlib.util.spec_from_file_location("api_v750_def", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestFromThePowerShellLineToTheVerdict(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        api._entity_write_one(api.AV_FILE, "w_off", {})
        api._entity_write_one(api.AV_FILE, "w_on", {})
        real = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None
        try:
            for dev, line in (("w_off", "False|2|1720000000|1719000000|0"), ("w_on", "True|2|1720000000|1719000000|0")):
                api._ingest_av(dev, {"defender": winagent._parse_defender(line)}, time.time(), dev)
        finally:
            api.fire_webhook = real
        api._LOAD_CACHE.clear()
        cls.off = api._entity_read_one(api.AV_FILE, "w_off", None)
        cls.on = api._entity_read_one(api.AV_FILE, "w_on", None)

    def test_the_premise_the_store_holds_realtime_enabled_and_nothing_else_by_that_name(self):
        self.assertIs(self.off["defender"]["realtime_enabled"], False)
        self.assertNotIn("realtime", self.off["defender"])

    def test_the_verdict_sees_it(self):
        self.assertTrue(ps.av_verdict(self.off, self.api._AV_TOOLS)["realtime_off"])
        self.assertFalse(ps.av_verdict(self.on, self.api._AV_TOOLS)["realtime_off"])

    def test_the_risk_score_counts_it_at_half_the_weight(self):
        api = self.api
        dev = {"name": "w_off", "last_seen": int(time.time()), "monitored": True, "sysinfo": {}}
        r = api._device_risk("w_off", dev, {}, {}, {}, int(time.time()), 180, av_rec=self.off)
        f = [x for x in r["factors"] if x["kind"] == "av_bad"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["points"], max(1, api._RISK_WEIGHTS["av_bad"] // 2))
        self.assertIn("real-time", f[0]["detail"])
        r2 = api._device_risk("w_on", dev, {}, {}, {}, int(time.time()), 180, av_rec=self.on)
        self.assertEqual([x for x in r2["factors"] if x["kind"] == "av_bad"], [])

    def test_the_compliance_facts_and_the_control_fail_it(self):
        api = self.api
        api.save(api.DEVICES_FILE, {
            "w_off": {"name": "win-off", "monitored": True, "sysinfo": {"cpu_percent": 1}},
            "w_on": {"name": "win-on", "monitored": True, "sysinfo": {"cpu_percent": 1}}})
        api._LOAD_CACHE.clear()
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual(facts["av_bad"], ["win-off"])
        self.assertEqual(facts["av_data_devices"], 2)
        status, evidence = compliance._av_control(facts)
        self.assertEqual(status, compliance.FAIL)
        self.assertIn("win-off", evidence)

    def test_a_tool_with_no_realtime_concept_is_not_off(self):
        """clamav and rkhunter report no real-time flag; absent is not disabled."""
        self.assertFalse(ps.av_verdict({"clamav": {"infected": 0}}, self.api._AV_TOOLS)["realtime_off"])

    def test_the_old_key_no_longer_counts(self):
        """Nothing writes `realtime`, so a record that has it must not be read as an answer."""
        self.assertFalse(ps.av_verdict({"defender": {"realtime": False}}, self.api._AV_TOOLS)["realtime_off"])


if __name__ == "__main__":
    unittest.main()
