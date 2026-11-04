#!/usr/bin/env python3
"""The server refuses at save time what the agents refuse at plant time.

7.5.0 gave the three agents more places to refuse a decoy: the macOS persistence places (a
plist in /Library/LaunchDaemons is run by launchd as root at the next boot), the drop-in
directories Linux programs read and run (sshd's AuthorizedKeysCommand, logrotate's
postrotate, rsyslog, fail2ban, snmpd, modprobe, tmpfiles, supervisor, kernel hooks) and the
library trees. The agents refuse silently. Without the same rule on the server, the save
dialog says nothing and an operator is told a decoy is armed when the agent threw it away.

The population is read from the agents' own source, not listed here, so a place added to
one of them without the server fails this.
"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import sanitize  # noqa: E402

AGENTS = {
    "linux": ("client/remotepower-agent.py", "_plant_canaries"),
    "macos": ("client/remotepower-agent-mac.py", "_canary_path_ok"),
    "windows": ("client/remotepower-agent-win.py", "_canary_path_ok"),
}
# The macOS and Windows agents refuse these whole trees. A decoy under /usr/local is fine on Linux, so the
# server does not repeat them (the agent of a Mac or a Windows host refuses it anyway).
BROAD_ON_PURPOSE = {"/usr/", "/bin/", "/sbin/"}


def _strings(path, func):
    tree = ast.parse((ROOT / path).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func:
            return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    raise AssertionError(f"{func} not found in {path}")


def _places(agent):
    path, func = AGENTS[agent]
    strs = _strings(path, func)
    dirs = sorted({s for s in strs if len(s) >= 5 and s.startswith("/") and (s.endswith("/") or s in ("/etc/pam.conf", "/etc/anacrontab", "/etc/crontab", "/etc/sudoers"))})
    return dirs, sorted({s for s in strs if s.startswith(".") and 3 <= len(s) <= 12})


class TestTheAgentsListsAreFound(unittest.TestCase):
    """Controls: an empty population would pass every test below."""

    def test_each_agent_has_a_substantial_list(self):
        for agent in AGENTS:
            dirs, _suf = _places(agent)
            self.assertGreater(len(dirs), 8, agent)

    def test_the_known_cases_are_in_them(self):
        self.assertIn("/etc/ssh/", _places("linux")[0])
        self.assertIn("/library/launchdaemons/", _places("macos")[0])
        self.assertIn("/library/launchdaemons/", _places("windows")[0])
        self.assertIn(".plist", _places("macos")[1])


class TestTheServerRefusesWhatTheAgentsRefuse(unittest.TestCase):

    def test_every_directory_an_agent_refuses_is_refused_here_too(self):
        missing = []
        for agent in AGENTS:
            for d in _places(agent)[0]:
                if d in BROAD_ON_PURPOSE:
                    continue
                sample = d + ("decoy.txt" if d.endswith("/") else "")
                ok, _why = sanitize.canary_path_safe(sample)
                if ok:
                    missing.append((agent, d))
        self.assertEqual(missing, [], "agents refuse places the server accepts: %s" % missing)

    def test_every_file_type_the_macos_agent_refuses_is_refused_here_too(self):
        for suf in _places("macos")[1]:
            ok, _why = sanitize.canary_path_safe("/opt/decoys/thing" + suf)
            self.assertFalse(ok, suf)

    def test_the_reason_names_the_place(self):
        ok, why = sanitize.canary_path_safe("/Library/LaunchDaemons/com.evil.agent.plist")
        self.assertFalse(ok)
        self.assertIn("launchdaemons", why)
        ok, why = sanitize.canary_path_safe("/opt/decoys/x.plist")
        self.assertIn(".plist", why)

    def test_the_cases_from_the_finding(self):
        for p in ("/Library/LaunchDaemons/x.plist", "/Library/LaunchAgents/com.evil.plist", "/etc/periodic/daily/999.evil",
                  "/etc/paths.d/evil", "/Library/StartupItems/Evil/Evil", "/etc/ssh/sshd_config.d/00-evil.conf",
                  "/etc/logrotate.d/evil", "/etc/rsyslog.d/evil.conf", "/etc/fail2ban/action.d/evil.conf",
                  "/etc/modprobe.d/evil.conf", "/etc/tmpfiles.d/evil.conf", "/etc/snmp/snmpd.conf", "/etc/supervisor/conf.d/evil.conf"):
            self.assertFalse(sanitize.canary_path_safe(p)[0], p)


class TestWhatStaysLegal(unittest.TestCase):
    """A server that refused every path would pass the tests above."""

    def test_the_usual_decoys_are_still_allowed(self):
        for p in ("/home/u/.aws/credentials", "/root/.ssh/id_rsa", "/srv/decoy/passwords.txt", "/opt/app/secret.key",
                  "/usr/local/share/decoy.txt", "/var/backups/db-password.txt", "C:\\Users\\Public\\Documents\\keys.txt",
                  "/Users/me/Documents/passwords.docx"):
            self.assertTrue(sanitize.canary_path_safe(p)[0], p)

    def test_the_mirrored_constants_are_untouched(self):
        """The three tuples the agents mirror stay as they were, so the five copies the drift test compares are equal."""
        self.assertIn("/etc/cron.d/", sanitize.CANARY_DENY_DIRS)
        self.assertNotIn("/library/launchdaemons/", sanitize.CANARY_DENY_DIRS)
        self.assertNotIn(".plist", sanitize.CANARY_DENY_SUFFIXES)


if __name__ == "__main__":
    unittest.main()
