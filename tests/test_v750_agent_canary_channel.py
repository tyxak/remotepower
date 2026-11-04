#!/usr/bin/env python3
"""7.5.0 agent review: the canary channel on macOS and Windows, and the places a decoy may not live.

A canary list is a setting that rides every heartbeat answer, and planting one writes a root-owned (SYSTEM-owned) file with content
the server chose. 7.4.9 made the Linux agent refuse the channel when `require-signed-commands` is set (the flag an operator sets to
say the server's word is not enough). The macOS and Windows agents still planted: they asked audit mode and nothing else.

That matters most on macOS, because the location rule (mirrored from the server, and held equal across the copies by
tests/test_v702_canary_paths.py) knew Linux and Windows persistence places and not the macOS ones. `/Library/LaunchDaemons/x.plist`,
`/Library/LaunchAgents`, `~/Library/LaunchAgents`, `/etc/periodic`, `/etc/paths.d`, `/Library/StartupItems` were all accepted, so a
server that could not run a signed command could still leave a root program that launchd starts at the next boot. The Linux list
also lacked the drop-in directories of sshd (`AuthorizedKeysCommand`), logrotate (`postrotate`), rsyslog, fail2ban, snmpd and
others. The extra rules sit beside the mirrored ones, so the three copies of those stay equal.

RP_TEST_AGENT, RP_TEST_WIN_AGENT and RP_TEST_MAC_AGENT point the tests at another copy (a `git show HEAD:` of the old file shows them fail).
"""
import importlib.machinery
import importlib.util
import logging
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
LINUX = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")
WIN = Path(os.environ.get("RP_TEST_WIN_AGENT") or ROOT / "client" / "remotepower-agent-win.py")
MAC = Path(os.environ.get("RP_TEST_MAC_AGENT") or ROOT / "client" / "remotepower-agent-mac.py")


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


# Places that run what they find, as root, with nothing a decoy needs from them.
MAC_PERSISTENCE = (
    "/Library/LaunchDaemons/com.evil.agent.plist", "/Library/LaunchAgents/com.evil.plist", "/Users/bob/Library/LaunchAgents/x.plist",
    "/Library/StartupItems/Evil/Evil", "/etc/periodic/daily/999.evil", "/private/etc/periodic/daily/999.evil", "/etc/paths.d/evil",
    "/Library/PrivilegedHelperTools/com.evil.helper", "/Library/Preferences/com.apple.loginwindow.plist", "/System/Library/x",
    "/Users/bob/Documents/launch.plist",
)
LINUX_DROPINS = (
    "/etc/ssh/sshd_config.d/00-evil.conf", "/etc/logrotate.d/evil", "/etc/rsyslog.d/evil.conf", "/etc/fail2ban/action.d/evil.conf",
    "/etc/modprobe.d/evil.conf", "/etc/tmpfiles.d/evil.conf", "/etc/snmp/snmpd.conf.d/evil", "/etc/supervisor/conf.d/evil.conf",
    "/etc/kernel/postinst.d/zz-evil", "/etc/default/evil", "/usr/lib/evil/helper", "/lib/evil", "/var/spool/evil",
)
WINDOWS_PLACES = (
    "C:\\Windows\\Temp\\evil.txt", "C:\\Program Files\\App\\evil.txt", "C:\\ProgramData\\Microsoft\\Windows\\evil.txt",
    "C:\\Users\\Default\\evil.txt",
)
FINE = (
    "/home/bob/.aws/credentials", "/root/.aws/credentials", "/root/.ssh/id_rsa.bak", "/var/backups/db-passwords.txt", "/srv/www/.env.bak",
    "/opt/app/secret.key", "/Users/bob/.aws/credentials", "/Users/bob/Documents/passwords.txt", "C:\\Users\\bob\\.aws\\credentials",
    "D:\\Backups\\keys.txt", "/mnt/data/finance-export.csv", "/etc/ssl/private/server-backup.key",
)


class TestSignedCommandsRefuseTheCanaryChannel(unittest.TestCase):
    def agents(self):
        yield "windows", load(WIN, "agent_v750_canary_win"), "_require_signed_commands_win"
        yield "macos", load(MAC, "agent_v750_canary_mac"), "_require_signed_commands_mac"

    def plant(self, mod, requirement, flag_on, path):
        mod._canary_planted.clear()
        mod._canary_failed.clear()
        if hasattr(mod, "_REFUSED_UNSIGNED"):
            mod._REFUSED_UNSIGNED.clear()
        with mock.patch.object(mod, "_audit_mode", lambda: False), mock.patch.object(mod, requirement, lambda: flag_on):
            mod._plant_canaries([{"path": path, "content": "decoy\n"}])

    def test_with_the_flag_nothing_is_planted_and_the_reason_is_recorded(self):
        for label, mod, requirement in self.agents():
            with self.subTest(agent=label), tempfile.TemporaryDirectory(prefix="rp-v750-can-") as td:
                path = str(Path(td) / "decoy.txt")
                self.plant(mod, requirement, True, path)
                self.assertFalse(Path(path).exists(), "a host that asks for signed commands planted a file the server chose")
                self.assertEqual(mod._canary_failed.get(path), "refused (require-signed-commands)")

    def test_control_without_the_flag_the_decoy_is_planted(self):
        for label, mod, requirement in self.agents():
            with self.subTest(agent=label), tempfile.TemporaryDirectory(prefix="rp-v750-can-") as td:
                path = str(Path(td) / "decoy.txt")
                self.plant(mod, requirement, False, path)
                self.assertEqual(Path(path).read_text(), "decoy\n")
                self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)

    def test_the_refusal_is_logged_once(self):
        for label, mod, requirement in self.agents():
            with self.subTest(agent=label), mock.patch.object(mod.log, "error") as err, tempfile.TemporaryDirectory(prefix="rp-v750-can-") as td:
                mod._REFUSED_UNSIGNED.clear()
                with mock.patch.object(mod, "_audit_mode", lambda: False), mock.patch.object(mod, requirement, lambda: True):
                    for i in range(4):
                        mod._plant_canaries([{"path": str(Path(td) / f"d{i}.txt")}])
                self.assertEqual(err.call_count, 1)


class TestWherePlantingIsRefused(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.win = load(WIN, "agent_v750_loc_win")
        cls.mac = load(MAC, "agent_v750_loc_mac")
        cls.lin = load(LINUX, "agent_v750_loc_lin")

    def test_macos_and_windows_refuse_the_places_the_system_runs_what_it_finds(self):
        for label, mod in (("windows", self.win), ("macos", self.mac)):
            for path in MAC_PERSISTENCE + WINDOWS_PLACES:
                with self.subTest(agent=label, path=path):
                    self.assertFalse(mod._canary_path_ok(path), f"{path} is accepted as a place for a decoy")

    def test_macos_and_windows_still_accept_the_places_decoys_are_for(self):
        for label, mod in (("windows", self.win), ("macos", self.mac)):
            for path in FINE:
                with self.subTest(agent=label, path=path):
                    self.assertTrue(mod._canary_path_ok(path), f"{path} is refused")

    def test_linux_refuses_the_dropin_directories_and_the_macos_ones(self):
        with mock.patch.object(self.lin, "_audit_mode", lambda: False), \
                mock.patch.object(self.lin, "_require_signed_commands", lambda: False):
            # the rule reads the path as written, so the files are named in the configuration and never created
            self.lin._canary_planted.clear()
            self.lin._canary_failed.clear()
            self.lin._plant_canaries([{"path": p} for p in LINUX_DROPINS + MAC_PERSISTENCE[:2]])
            for path in LINUX_DROPINS + MAC_PERSISTENCE[:2]:
                with self.subTest(path=path):
                    self.assertIn(path, self.lin._canary_failed, f"{path} was neither planted nor refused")
                    self.assertTrue(self.lin._canary_failed[path].startswith("a decoy cannot live in"), self.lin._canary_failed[path])
                    self.assertNotIn(path, self.lin._canary_planted)

    def test_linux_still_plants_where_decoys_belong(self):
        with tempfile.TemporaryDirectory(prefix="rp-v750-lin-") as td, mock.patch.object(self.lin, "_audit_mode", lambda: False), \
                mock.patch.object(self.lin, "_require_signed_commands", lambda: False):
            self.lin._canary_planted.clear()
            self.lin._canary_failed.clear()
            home = Path(td) / "home" / "bob" / ".aws"
            home.mkdir(parents=True)
            self.lin._plant_canaries([{"path": str(home / "credentials")}])
            self.assertTrue((home / "credentials").exists())
            self.assertEqual(self.lin._canary_failed, {})

    def test_the_populations_are_not_empty(self):
        self.assertGreater(len(MAC_PERSISTENCE) + len(WINDOWS_PLACES), 12)
        self.assertGreater(len(LINUX_DROPINS), 10)
        self.assertGreater(len(FINE), 8)


if __name__ == "__main__":
    unittest.main()
