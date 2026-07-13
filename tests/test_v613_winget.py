"""v6.1.3 — Windows/macOS patch execution actually works now (gap item #6).

THE BUG (shipped since v6.0.0): `handle_upgrade_device` computed
`queued_str = f'exec:{_UPGRADE_CMD}'` ONCE, outside the device loop, with no OS
branch anywhere. _UPGRADE_CMD is a **bash** script. Commands are delivered to
agents verbatim — so a Windows host received a shell script, which its agent
handed to PowerShell.

Meanwhile BOTH the Windows and macOS agents have implemented the bare `upgrade` /
`upgrade:<name>` command since v6.0.0 — and the server never emitted it. The
shipped "Windows / macOS patch execution" feature was dead end to end: fully
wired on the agent, never triggered by the server. Exactly the class documented
in CLAUDE.md ("a feature that can never fire").

Same bug in the auto-patch and scheduled-job paths.

PLUS a security bug the fix surfaced: `_command_kind` did not know about
`upgrade`, so a bare `upgrade` classified as 'other' — which is NOT in
_APPROVAL_GATED_KINDS. Routing Windows hosts onto the bare command would have
silently bypassed the four-eyes gate for auto-patch.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-wg-"))
_spec = importlib.util.spec_from_file_location("api_v613_wg", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_WIN = _ROOT / "client" / "remotepower-agent-win.py"
_wspec = importlib.util.spec_from_file_location("rp_agent_win_wg", _WIN)
winagent = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(winagent)


class TestOsFamilyDetection(unittest.TestCase):
    def test_detects_windows(self):
        self.assertEqual(api._device_os_family({"os": "Windows 11 (Build 22631)"}), "windows")

    def test_detects_macos(self):
        self.assertEqual(api._device_os_family({"os": "macOS 14.5 (23F79)"}), "darwin")

    def test_defaults_to_linux(self):
        """Linux is the overwhelmingly common case AND the one the bash command
        fits — an unknown OS must not be handed a PowerShell-only command."""
        self.assertEqual(api._device_os_family({"os": "Ubuntu 22.04"}), "linux")
        self.assertEqual(api._device_os_family({"os": ""}), "linux")
        self.assertEqual(api._device_os_family({}), "linux")
        self.assertEqual(api._device_os_family(None), "linux")


class TestUpgradeCommandIsOsAware(unittest.TestCase):
    def test_linux_gets_the_bash_script(self):
        cmd = api._upgrade_command_for({"os": "Debian 12"})
        self.assertTrue(cmd.startswith("exec:"))
        self.assertIn("apt-get", cmd)

    def test_windows_gets_the_bare_upgrade_command(self):
        """THE FIX. This is the command the Windows agent has always understood
        and never once received."""
        self.assertEqual(api._upgrade_command_for({"os": "Windows 11"}), "upgrade")

    def test_macos_gets_the_bare_upgrade_command(self):
        self.assertEqual(api._upgrade_command_for({"os": "macOS 14.5"}), "upgrade")

    def test_windows_never_receives_bash(self):
        """The regression guard: no shell script may reach a Windows host."""
        cmd = api._upgrade_command_for({"os": "Windows Server 2022"})
        self.assertNotIn("apt-get", cmd)
        self.assertNotIn("exec:", cmd)

    def test_per_package_form(self):
        self.assertEqual(
            api._upgrade_command_for({"os": "Windows 11"}, "Some Update"),
            "upgrade:Some Update")


class TestApprovalGateStillApplies(unittest.TestCase):
    """The security half. Routing Windows onto a BARE command changed which
    _command_kind it maps to — and 'other' is not gated."""

    def test_bare_upgrade_is_classified_as_upgrade_not_other(self):
        self.assertEqual(api._command_kind("upgrade"), "upgrade")
        self.assertEqual(api._command_kind("upgrade:Google.Chrome"), "upgrade")

    def test_winget_is_classified_as_upgrade(self):
        self.assertEqual(api._command_kind("winget:Google.Chrome"), "upgrade")

    def test_upgrade_is_in_the_default_gated_set(self):
        """Otherwise the four-eyes approval gate would not fire for a Windows
        auto-patch run."""
        self.assertIn("upgrade", api._APPROVAL_GATED_KINDS)

    def test_linux_exec_command_kind_unchanged(self):
        self.assertEqual(api._command_kind("exec:set -e; apt-get upgrade"), "exec")


class TestWingetDetection(unittest.TestCase):
    def test_parses_the_upgrade_table(self):
        out = (
            "Name                 Id                    Version    Available  Source\n"
            "-------------------------------------------------------------------------\n"
            "Google Chrome        Google.Chrome         120.0.1    121.0.2    winget\n"
            "7-Zip                7zip.7zip             23.01      24.05      winget\n"
            "2 upgrades available.\n"
        )
        count, names = winagent._parse_winget(out)
        self.assertEqual(count, 2)
        self.assertEqual(names, ["Google.Chrome", "7zip.7zip"])

    def test_app_names_with_spaces_do_not_break_the_parse(self):
        """A naive whitespace split breaks on 'Google Chrome' — key off the
        header's Id column offset instead."""
        out = (
            "Name                      Id              Version  Available  Source\n"
            "----------------------------------------------------------------\n"
            "Microsoft Visual C++ 2015 Microsoft.VC    14.0     14.1       winget\n"
        )
        _c, names = winagent._parse_winget(out)
        self.assertEqual(names, ["Microsoft.VC"])

    def test_no_updates_yields_nothing(self):
        self.assertEqual(winagent._parse_winget(""), (0, []))
        self.assertEqual(winagent._parse_winget("No installed package found."), (0, []))

    def test_server_whitelist_accepts_winget(self):
        """The sanitizer's third_party tuple is a WHITELIST — winget missing from
        it means the agent could report updates forever and nothing downstream
        would ever see them."""
        src = (_CGI / "api.py").read_text()
        i = src.index("for mgr in ('flatpak'")
        self.assertIn("'winget'", src[i:i + 120])


class TestWingetRemediation(unittest.TestCase):
    def test_upgrade_all(self):
        argv = winagent.command_argv("winget:")
        self.assertEqual(argv[:2], ["winget", "upgrade"])
        self.assertIn("--all", argv)

    def test_upgrade_one_package_is_exact(self):
        argv = winagent.command_argv("winget:Google.Chrome")
        self.assertIn("--id", argv)
        self.assertIn("Google.Chrome", argv)
        self.assertIn("--exact", argv, "must not fuzzy-match a package id")

    def test_injection_is_refused_not_escaped(self):
        """argv is passed directly (no shell), and the id is charset-validated —
        so there is nothing to inject into. Refuse rather than sanitize."""
        for bad in ("winget:; rm -rf /", "winget:a b", "winget:$(whoami)",
                    "winget:../../etc/passwd", "winget:a|b"):
            self.assertIsNone(winagent.command_argv(bad), bad)

    def test_never_shells_out(self):
        argv = winagent.command_argv("winget:Google.Chrome")
        self.assertNotIn("powershell", argv)
        self.assertNotIn("cmd", argv)


if __name__ == "__main__":
    unittest.main()
