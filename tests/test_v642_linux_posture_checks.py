"""v6.4.2 (data-binding): Linux host-security posture reaches the Checks engine.

Host firewall, sshd hardening and the auto-update mechanism were collected on
every heartbeat and drove ONLY the risk score and the advisory list — never a
Checks-page row, never alertable — while the Windows/macOS equivalents were
already check rows. These tests drive the real _host_checks and assert the
three new Linux rows, mirroring the tri-state / hardening logic the agent and
advisory.py use.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-linpost-"))

_spec = importlib.util.spec_from_file_location("checks_linpost", _CGI / "checks.py")
checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checks)


def _rows(sysinfo):
    dev = {"name": "h", "last_seen": 1, "monitored": True, "sysinfo": sysinfo}
    out = checks._host_checks("d1", dev, now=1)
    return {r["key"]: r for r in out}


class TestLinuxFirewallCheck(unittest.TestCase):
    def test_no_active_ruleset_warns(self):
        r = _rows({"firewall": {"active": False, "backends": [
            {"name": "nftables", "active": False}]}})
        self.assertIn("linux_firewall", r)
        self.assertEqual(r["linux_firewall"]["status"], "warning")

    def test_active_is_ok_and_names_the_backend(self):
        r = _rows({"firewall": {"active": True, "backends": [
            {"name": "nftables", "active": True}]}})
        self.assertEqual(r["linux_firewall"]["status"], "ok")
        self.assertIn("nftables", r["linux_firewall"]["output"])

    def test_unknown_is_not_flagged(self):
        """active=None means the probe couldn't read the ruleset — flagging it
        as off would invent a failing bill of health (advisory.py's rule)."""
        r = _rows({"firewall": {"active": None, "backends": []}})
        self.assertNotIn("linux_firewall", r)

    def test_absent_on_a_windows_host(self):
        r = _rows({"win_posture": {"firewall": [{"name": "Domain", "enabled": True}]}})
        self.assertNotIn("linux_firewall", r)


class TestLinuxSshHardeningCheck(unittest.TestCase):
    def test_empty_passwords_is_critical(self):
        r = _rows({"ssh_config": {"permit_empty_passwords": "yes",
                                  "permit_root_login": "no",
                                  "password_authentication": "no"}})
        self.assertEqual(r["linux_ssh_hardening"]["status"], "critical")
        self.assertIn("empty passwords", r["linux_ssh_hardening"]["output"])

    def test_root_login_yes_warns(self):
        r = _rows({"ssh_config": {"permit_root_login": "yes",
                                  "password_authentication": "no",
                                  "permit_empty_passwords": "no"}})
        self.assertEqual(r["linux_ssh_hardening"]["status"], "warning")

    def test_key_only_root_is_ok(self):
        """prohibit-password / without-password = key-based root, the hardened
        state — must NOT warn."""
        r = _rows({"ssh_config": {"permit_root_login": "prohibit-password",
                                  "password_authentication": "no",
                                  "permit_empty_passwords": "no"}})
        self.assertEqual(r["linux_ssh_hardening"]["status"], "ok")

    def test_absent_when_sshd_not_installed(self):
        r = _rows({"ssh_config": {}})
        self.assertNotIn("linux_ssh_hardening", r)


class TestLinuxAutoUpdateCheck(unittest.TestCase):
    def test_disabled_warns(self):
        r = _rows({"autoupdate": {"enabled": False, "mechanism": ""}})
        self.assertEqual(r["linux_auto_update"]["status"], "warning")

    def test_enabled_is_ok_and_names_the_mechanism(self):
        r = _rows({"autoupdate": {"enabled": True, "mechanism": "unattended-upgrades"}})
        self.assertEqual(r["linux_auto_update"]["status"], "ok")
        self.assertIn("unattended-upgrades", r["linux_auto_update"]["output"])


class TestThePrizeIsNowAlertable(unittest.TestCase):
    """The whole point: a root-login-permitted, password-auth-enabled sshd now
    produces a non-ok CHECK row that the Checks page and any check-derived
    alerting can act on — where before it only nudged a risk number."""

    def test_a_wide_open_sshd_is_no_longer_silent(self):
        r = _rows({"ssh_config": {"permit_root_login": "yes",
                                  "password_authentication": "yes",
                                  "permit_empty_passwords": "yes"}})
        self.assertEqual(r["linux_ssh_hardening"]["status"], "critical")
        self.assertNotEqual(r["linux_ssh_hardening"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
