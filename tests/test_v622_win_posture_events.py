"""v6.2.2 — Windows endpoint-posture events (data-binding gap fill).

The Windows agent reported BitLocker / firewall / Windows-Update-service /
Defender-signature-age posture and the Checks page got rows, but nothing
FIRED — a host that silently stopped patching or lost disk encryption was
invisible to every fleet view. These wire the four device-level CONDITION
events (fire on entering the bad state incl. first contact; auto-resolve when
it clears). Driven through the real _ingest_posture_v3110.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-win-"))
_spec = importlib.util.spec_from_file_location("api_v622_win", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestWinPostureEvents(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-win-1"
        self.fired = []
        self._real = api.fire_webhook
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))
        try:
            api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        except Exception:
            pass

    def tearDown(self):
        api.fire_webhook = self._real

    def _ingest(self, wp):
        api._ingest_posture_v3110(self.dev, "winhost", {"mounts": [], "win_posture": wp})

    def _events(self):
        return [e for e, _ in self.fired]

    _GOOD = {"bitlocker": [{"status": "on"}], "firewall": [{"name": "Domain", "enabled": True}],
             "wu_service": "Running", "defender_sig_age_days": 1}

    def test_first_contact_bad_fires(self):
        """A host that enrols already-unprotected is exactly the one to hear about."""
        self._ingest({"bitlocker": [{"status": "off"}]})
        self.assertIn("win_bitlocker_off", self._events())

    def test_each_condition_fires_and_recovers(self):
        cases = [
            ({"bitlocker": [{"status": "off"}]}, "win_bitlocker_off", "win_bitlocker_on",
             {"bitlocker": [{"status": "on"}]}),
            ({"firewall": [{"name": "Public", "enabled": False}]}, "win_firewall_off",
             "win_firewall_on", {"firewall": [{"name": "Public", "enabled": True}]}),
            ({"wu_service": "Stopped"}, "win_update_stopped", "win_update_running",
             {"wu_service": "Running"}),
            ({"defender_sig_age_days": 10}, "win_defender_stale", "win_defender_current",
             {"defender_sig_age_days": 0}),
        ]
        for bad, fire_ev, rec_ev, good in cases:
            with self.subTest(fire_ev):
                api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
                self.fired.clear()
                self._ingest(bad)
                self.assertIn(fire_ev, self._events(), fire_ev)
                self.fired.clear()
                self._ingest(good)
                self.assertIn(rec_ev, self._events(), rec_ev)

    def test_steady_bad_does_not_refire(self):
        self._ingest({"wu_service": "Stopped"})
        self.fired.clear()
        self._ingest({"wu_service": "Stopped"})
        self.assertNotIn("win_update_stopped", self._events())

    def test_defender_warning_band_does_not_fire(self):
        """The event fires at the >=7d critical band, not the 3-6d warning band
        (the Checks row shows warning; the alert is reserved for stale)."""
        self._ingest({"defender_sig_age_days": 4})
        self.assertNotIn("win_defender_stale", self._events())

    def test_conditions_are_independent(self):
        self._ingest({"bitlocker": [{"status": "off"}], "wu_service": "Running"})
        self.fired.clear()
        # WU stops; bitlocker still off (no refire); no recovery for bitlocker.
        self._ingest({"bitlocker": [{"status": "off"}], "wu_service": "Stopped"})
        evs = self._events()
        self.assertIn("win_update_stopped", evs)
        self.assertNotIn("win_bitlocker_off", evs)
        self.assertNotIn("win_bitlocker_on", evs)


class TestWiring(unittest.TestCase):
    def test_registry_pairs(self):
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        for fire, rec in (("win_bitlocker_off", "win_bitlocker_on"),
                          ("win_firewall_off", "win_firewall_on"),
                          ("win_update_stopped", "win_update_running"),
                          ("win_defender_stale", "win_defender_current")):
            self.assertIn(api.EVENT_REGISTRY[fire]["kind"], kinds)
            self.assertIn(fire, api.EVENT_REGISTRY[rec]["resolves"])

    def test_win_posture_in_gate(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("_ingest_posture_v3110(dev_id, saved_dev.get('name'")
        self.assertIn("'win_posture'", src[max(0, i - 900):i])

    def test_frontend_both_spots(self):
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("'win_update_stopped'", js)
        self.assertIn("case 'win_update_stopped':", js)


if __name__ == "__main__":
    unittest.main()
