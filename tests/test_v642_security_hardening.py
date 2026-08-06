"""v6.4.2: opt-in Security hardening — advisory checks + alerts.

The SSH-daemon-hardening, auto-updates-off and stale-password checks flag
DELIBERATE configuration choices, so they are OFF by default (like protect
baselines) and only render + alert when the operator enables Security hardening
(Settings → Security). A BLANK password and an inactive host firewall are real
exposure and stay always-on. When enabled, each check also raises an
edge-triggered alert that auto-resolves when fixed.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-harden-"))

_spec = importlib.util.spec_from_file_location("api_harden", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_cspec = importlib.util.spec_from_file_location("checks_harden", _CGI / "checks.py")
checks = importlib.util.module_from_spec(_cspec)
_cspec.loader.exec_module(checks)


class TestGating(unittest.TestCase):
    """The check ROWS are hidden unless hardening is enabled — except blank
    passwords (always critical)."""

    def _rows(self, sysinfo, hw, hardening):
        dev = {"name": "h", "last_seen": 1, "monitored": True, "sysinfo": sysinfo}
        return {r["key"]: r for r in
                checks._host_checks("d", dev, hw, now=1, security_hardening=hardening)}

    def test_advisory_checks_hidden_when_off(self):
        r = self._rows({"ssh_config": {"permit_root_login": "yes"},
                        "autoupdate": {"enabled": False}}, {}, False)
        self.assertNotIn("linux_ssh_hardening", r)
        self.assertNotIn("linux_auto_update", r)

    def test_advisory_checks_shown_when_on(self):
        r = self._rows({"ssh_config": {"permit_root_login": "yes"},
                        "autoupdate": {"enabled": False}}, {}, True)
        self.assertEqual(r["linux_ssh_hardening"]["status"], "warning")
        self.assertEqual(r["linux_auto_update"]["status"], "warning")

    def test_blank_password_is_always_critical(self):
        hw = {"accounts": [{"user": "x", "flags": ["empty_password"]}]}
        for hardening in (False, True):
            r = self._rows({}, hw, hardening)
            self.assertEqual(r["account_passwords"]["status"], "critical")

    def test_stale_password_row_only_when_on(self):
        hw = {"accounts": [{"user": "postgres", "flags": ["stale_password"]}]}
        self.assertNotIn("account_passwords", self._rows({}, hw, False))
        self.assertEqual(self._rows({}, hw, True)["account_passwords"]["status"],
                         "warning")


class _FireBase(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("POSTURE_STATE_FILE", "HARDWARE_FILE", "CONFIG_FILE"):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / pathlib.Path(getattr(api, a)).name)
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append(ev)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        api.fire_webhook = self._fw
        for a, v in self._files.items():
            setattr(api, a, v)

    def _set_hardening(self, on):
        api.save(api.CONFIG_FILE, {"security_hardening_checks": bool(on)})
        api._invalidate_load_cache(api.CONFIG_FILE)


class TestSshAutoupdateAlerts(_FireBase):
    def _ingest(self, si):
        self.fired = []
        api._ingest_posture_v3110("d1", "host1", si)
        return list(self.fired)

    def test_nothing_fires_when_disabled(self):
        self._set_hardening(False)
        self.assertEqual(self._ingest({"ssh_config": {"permit_root_login": "yes"},
                                       "autoupdate": {"enabled": False}}), [])

    def test_fires_when_enabled_and_recovers(self):
        self._set_hardening(True)
        fired = self._ingest({"ssh_config": {"permit_root_login": "yes"},
                              "autoupdate": {"enabled": False}})
        self.assertIn("ssh_hardening_weak", fired)
        self.assertIn("autoupdate_disabled", fired)
        # fix the config → recover events
        fired2 = self._ingest({"ssh_config": {"permit_root_login": "no",
                                              "password_authentication": "no",
                                              "permit_empty_passwords": "no"},
                              "autoupdate": {"enabled": True}})
        self.assertIn("ssh_hardening_ok", fired2)
        self.assertIn("autoupdate_enabled", fired2)

    def test_does_not_refire_on_a_steady_state(self):
        self._set_hardening(True)
        si = {"ssh_config": {"permit_root_login": "yes"}}
        self.assertIn("ssh_hardening_weak", self._ingest(si))
        self.assertNotIn("ssh_hardening_weak", self._ingest(si))  # edge-triggered


class TestStalePasswordAlert(_FireBase):
    def _ingest(self, accounts):
        self.fired = []
        api._ingest_hardware("d1", "host1", {"accounts": accounts}, 1000)
        return list(self.fired)

    def test_nothing_when_disabled(self):
        self._set_hardening(False)
        self.assertNotIn("password_stale",
                         self._ingest([{"user": "postgres", "uid": 999,
                                        "flags": ["stale_password"]}]))

    def test_fires_and_recovers_when_enabled(self):
        self._set_hardening(True)
        f = self._ingest([{"user": "postgres", "uid": 999,
                           "flags": ["stale_password"]}])
        self.assertIn("password_stale", f)
        f2 = self._ingest([{"user": "postgres", "uid": 999, "flags": []}])
        self.assertIn("password_stale_cleared", f2)


class TestConfigAndRegistry(unittest.TestCase):
    def test_default_is_off(self):
        """The get handler setdefaults the flag to False, so a fresh install
        never sees the advisories until the operator opts in."""
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe.setdefault('security_hardening_checks', False)", src)

    def test_events_registered_with_recovers(self):
        for fire, rec in (("ssh_hardening_weak", "ssh_hardening_ok"),
                          ("autoupdate_disabled", "autoupdate_enabled"),
                          ("password_stale", "password_stale_cleared")):
            self.assertIn(fire, api.EVENT_REGISTRY)
            self.assertIn(rec, api.EVENT_REGISTRY)
            # _ALERT_RECOVER maps the RECOVER event → the fire event it resolves.
            self.assertEqual(api._ALERT_RECOVER.get(rec), fire)

    def test_hardening_alert_events_constant_matches(self):
        self.assertEqual(set(api._HARDENING_ALERT_EVENTS),
                         {"ssh_hardening_weak", "autoupdate_disabled", "password_stale"})


if __name__ == "__main__":
    unittest.main()
