"""v6.3.0: chassis-aware offline grace — a closed laptop lid is not a down server.

The agent reports its DMI chassis class (`sysinfo.chassis`); when the operator
sets `laptop_offline_grace_hours` (Settings → Alert parameters → Reachability,
default 0 = behaviour unchanged), laptop-class hosts get that many extra hours
of silence before becoming offline candidates. Drives the REAL save handler
and the REAL threshold function.
"""

import unittest
from pathlib import Path

from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

AGENT = (ROOT / "client/remotepower-agent.py").read_text()


class TestSavePersists(_SaveBase):
    def test_key_persists_and_blank_clears(self):
        cfg = self._save({"laptop_offline_grace_hours": "24"})
        self.assertEqual(cfg.get("laptop_offline_grace_hours"), 24,
                         "save-whitelist silent-drop gotcha")
        cfg = self._save({"laptop_offline_grace_hours": ""})
        self.assertNotIn("laptop_offline_grace_hours", cfg)

    def test_out_of_range_rejected(self):
        self._save({"laptop_offline_grace_hours": "200"})   # > 168h max
        self.assertEqual(self.cap.get("s"), 400)


class TestThresholdBehaviour(unittest.TestCase):
    """_offline_thresholds honours the grace ONLY for laptop-class chassis."""

    def setUp(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.pop("laptop_offline_grace_hours", None)
        api.save(api.CONFIG_FILE, cfg)

    def _thr(self, chassis):
        dev = {"poll_interval": 60, "sysinfo": ({"chassis": chassis} if chassis else {})}
        after, _deb = api._offline_thresholds(dev, ttl=300)
        return after

    def test_default_zero_changes_nothing(self):
        self.assertEqual(self._thr("laptop"), self._thr("server"))

    def test_grace_applies_to_laptop_class_only(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["laptop_offline_grace_hours"] = 24
        api.save(api.CONFIG_FILE, cfg)
        base_server = self._thr("server")
        self.assertEqual(self._thr("desktop"), base_server)
        self.assertEqual(self._thr(None), base_server)
        for ch in ("laptop", "notebook", "portable", "tablet", "convertible", "detachable"):
            self.assertEqual(self._thr(ch), base_server + 24 * 3600, ch)

    def test_grace_capped_at_168h(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["laptop_offline_grace_hours"] = 10000   # hand-edited config
        api.save(api.CONFIG_FILE, cfg)
        self.assertEqual(self._thr("laptop"), self._thr("server") + 168 * 3600)


class TestChassisPlumbing(unittest.TestCase):
    def test_agent_collects_and_stores_chassis(self):
        self.assertIn("def get_chassis", AGENT)
        self.assertIn("/sys/class/dmi/id/chassis_type", AGENT)
        self.assertIn("sysinfo['chassis'] = ch", AGENT)   # scope guarded by AST test

    def test_safe_si_whitelists_chassis(self):
        self.assertIn("safe_si['chassis']", (_CGI / "api.py").read_text())

    def test_ui_spots_wired(self):
        html = (ROOT / "server/html/index.html").read_text()
        self.assertIn('id="ap-laptop-grace"', html)
        appjs = (ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("'laptop_offline_grace_hours', 0]", appjs)
        self.assertIn("['Chassis', si.chassis || null]", appjs)   # drawer pill
        self.assertIn("'Chassis':", (ROOT / "server/html/static/js/i18n.js").read_text())


if __name__ == "__main__":
    unittest.main()
