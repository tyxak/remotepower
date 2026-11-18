#!/usr/bin/env python3
"""The Windows Update search: Defender definition updates are not pending updates, and the search is a state of its own.

Two things were wrong with what a Windows host reported about its updates.

  * The Defender definition updates ("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602") are offered several times a
    day. They were counted as pending updates, so every Windows host showed one or two of them at all times, over the patch alert threshold,
    in the patch SLA and in the risk score.
  * A search that failed sent nothing. The stored report was replaced by the next one, so the count was gone, and nothing on the host said
    when the last search ran or that it had failed.

The agent could not run on Windows here. What it reads is replaced by the real thing's shape (a `winreg` that behaves as the real module does,
the output of the search script and of its failure path, run for real under PowerShell where there is one) and the agent's own functions run
on it. The payload that reaches the server is the one `collect_sysinfo()` builds, sent through the real heartbeat handler.

The last class is the list of readers of the pending count: every function of the server that names the count is found by syntax tree, and
the ones that matter are driven with a host that has three pending updates and two definition updates.
"""
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="rp-wusearch-")
os.environ.setdefault("RP_DATA_DIR", _TMP)

_HERE = Path(__file__).resolve().parent
_CGI = _HERE.parent / "server" / "cgi-bin"
for _p in (str(_CGI), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import win_host_support as S  # noqa: E402
import windows_host as wh  # noqa: E402

import api  # noqa: E402
import checks  # noqa: E402

agent = S.load_agent("rp_wusearch_agent")

_PWSH = shutil.which("pwsh") or next((p for p in ("/home/jaove/.local/bin/pwsh",) if os.path.exists(p)), None)


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


# What Windows Update offers, as the search script prints it (one title per line, CRLF as PowerShell writes it on Windows).
PENDING = [
    "2024-05 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5037771)",
    "2024-04 .NET 8.0.4 Security Update for x64 Client (KB5036620)",
    "Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24040.4)",
]
DEFINITIONS = [
    "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.411.1035.0)",
    "Definition Update for Windows Defender Antivirus - KB2267602 (Definition 1.243.123.0)",
]
# They are not definition updates, though each looks like one in a word.
LOOKALIKES = [
    "Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24040.4)",
    "Definition Update for Microsoft Office 2016 (KB4011123) 64-Bit Edition",
    "Security Update for Microsoft Defender for Endpoint (KB5034441)",
    "Windows Malicious Software Removal Tool x64 - v5.125 (KB890830)",
    "2024-05 Security Update for Windows Defender Application Guard",
    "",
]
# More definition updates, one for each way the rule matches (the older names, the case, the KB number alone).
ALSO_DEFINITIONS = [
    "Security Intelligence Update for Windows Defender Antivirus - KB2267602 (Version 1.273.1234.0)",
    "Definition Update for Windows Defender - KB915597 (Definition 1.171.123.0)",
    "SECURITY INTELLIGENCE UPDATE FOR MICROSOFT DEFENDER ANTIVIRUS",
    "definition update for windows defender antivirus",
    "Some vendor driver - KB2267602",
    "Definition Update for Microsoft Antivirus - KB1234567",
]
EVERY_TITLE = PENDING + DEFINITIONS + LOOKALIKES + ALSO_DEFINITIONS + ["Definition Update for Forefront Client Security (KB1234567)"]


def crlf(lines):
    return "".join(f"{ln}\r\n" for ln in lines)


class CompletedRun:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def fake_run(rc=0, out="", err="", raises=None):
    """A stand-in for subprocess.run: the one call the search makes."""
    calls = []

    def run(argv, *args, **kwargs):
        calls.append((argv, kwargs))
        if raises is not None:
            raise raises
        return CompletedRun(rc, out, err)

    run.calls = calls
    return run


def search(run, winget=None):
    """The agent's real search, on a host that is Windows as far as the agent can tell."""
    with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", run), \
            mock.patch.object(agent, "get_winget_updates", lambda: winget or {}):
        agent._wu_search_state = None
        pkgs = agent.windows_update_pending()
        return pkgs, agent._wu_search_state


class TestWhichUpdatesAreDefinitionUpdates(unittest.TestCase):
    def test_the_agent_and_the_server_agree_on_every_title(self):
        for title in EVERY_TITLE:
            with self.subTest(title=title):
                self.assertEqual(agent._is_definition_update(title), wh.is_definition_update(title))

    def test_the_definition_updates_are_found(self):
        for title in DEFINITIONS + ALSO_DEFINITIONS:
            with self.subTest(title=title):
                self.assertTrue(agent._is_definition_update(title))
                self.assertTrue(wh.is_definition_update(title))

    def test_nothing_else_is(self):
        for title in PENDING + LOOKALIKES + ["Definition Update for Forefront Client Security (KB1234567)"]:
            with self.subTest(title=title):
                self.assertFalse(agent._is_definition_update(title))
                self.assertFalse(wh.is_definition_update(title))

    def test_the_table_has_both_kinds(self):
        """A control: a table with only one kind would let a rule that says yes to everything, or no to everything, pass."""
        hits = [t for t in EVERY_TITLE if agent._is_definition_update(t)]
        self.assertGreaterEqual(len(hits), 6)
        self.assertGreaterEqual(len(EVERY_TITLE) - len(hits), 8)

    def test_a_title_that_is_not_text_is_not_one(self):
        for value in (None, 0, [], {}, b"Security Intelligence Update", ["Security Intelligence Update"]):
            with self.subTest(value=value):
                self.assertFalse(wh.is_definition_update(value))
        self.assertFalse(agent._is_definition_update(None))


class TestTheSearchTheAgentRuns(unittest.TestCase):
    def test_a_search_that_worked_leaves_the_definition_updates_out_of_the_count(self):
        pkgs, state = search(fake_run(0, crlf(PENDING + DEFINITIONS)))
        self.assertEqual(pkgs["manager"], "windows-update")
        self.assertEqual(pkgs["upgradable"], 3)
        self.assertEqual(pkgs["upgradable_names"], PENDING)
        self.assertEqual(pkgs["definition_updates"], 2)
        self.assertTrue(state["ok"])
        self.assertEqual(state["error_class"], "")

    def test_a_host_with_only_definition_updates_has_nothing_pending(self):
        pkgs, _ = search(fake_run(0, crlf(DEFINITIONS)))
        self.assertEqual((pkgs["upgradable"], pkgs["upgradable_names"], pkgs["definition_updates"]), (0, [], 2))

    def test_a_host_with_nothing_offered_says_so(self):
        pkgs, state = search(fake_run(0, ""))
        self.assertEqual((pkgs["upgradable"], pkgs["definition_updates"]), (0, 0))
        self.assertTrue(state["ok"])

    def test_the_winget_updates_still_ride_along(self):
        pkgs, _ = search(fake_run(0, crlf(PENDING)), winget={"count": 1, "names": ["7zip.7zip"]})
        self.assertEqual(pkgs["third_party"], {"winget": {"count": 1, "names": ["7zip.7zip"]}})

    def test_the_state_is_four_fields_and_a_clock_the_agent_just_read(self):
        before = int(time.time())
        _, state = search(fake_run(0, crlf(PENDING)))
        self.assertEqual(sorted(state), ["at", "error_class", "ok", "source"])
        self.assertTrue(before <= state["at"] <= int(time.time()))
        self.assertIs(state["ok"], True)

    def test_a_search_that_failed_sends_no_count_and_says_why(self):
        for out, expect in (
            ("RP_WU_ERROR:8024402C:NotSpecified\r\n", "network"),
            ("RP_WU_ERROR:80070005:NotSpecified\r\n", "access"),
            ("RP_WU_ERROR:80070422:NotSpecified\r\n", "service"),
            ("RP_WU_ERROR:800705B4:OperationTimeout\r\n", "timeout"),
            ("RP_WU_ERROR:80131501:InvalidArgument\r\n", "unknown"),
        ):
            with self.subTest(out=out):
                pkgs, state = search(fake_run(3, out))
                self.assertIsNone(pkgs)
                self.assertIs(state["ok"], False)
                self.assertEqual(state["error_class"], expect)

    def test_a_search_that_ran_out_of_time(self):
        pkgs, state = search(fake_run(raises=subprocess.TimeoutExpired("powershell", 120)))
        self.assertIsNone(pkgs)
        self.assertEqual((state["ok"], state["error_class"]), (False, "timeout"))

    def test_a_search_that_could_not_start(self):
        for exc in (FileNotFoundError("powershell"), PermissionError("blocked"), OSError(5, "denied")):
            with self.subTest(exc=type(exc).__name__):
                pkgs, state = search(fake_run(raises=exc))
                self.assertIsNone(pkgs)
                self.assertEqual((state["ok"], state["error_class"]), (False, "unknown"))

    def test_a_failure_with_no_marker_is_unknown(self):
        for rc, out, err in ((1, "", "The term 'New-Object' is not recognized"), (-1, "", ""), (3, "garbage", "")):
            with self.subTest(rc=rc):
                _, state = search(fake_run(rc, out, err))
                self.assertEqual(state["error_class"], "unknown")

    def test_the_text_of_an_error_is_never_sent(self):
        """The error text is in the language of the host and can name paths and accounts; only a word of the fixed set leaves."""
        hostile = ("RP_WU_ERROR:8024402C:NotSpecified\r\nC:\\Users\\jdoe\\secret.txt Access is denied for CORP\\jdoe\r\n")
        _, state = search(fake_run(3, hostile, "Der Zugriff auf C:\\Users\\jdoe wurde verweigert"))
        self.assertIn(state["error_class"], wh.SEARCH_CLASSES)
        self.assertNotIn("jdoe", repr(state))
        for text in ("RP_WU_ERROR:8024402C:Some text with spaces\r\n", "RP_WU_ERROR:ZZZZZZZZ:NotSpecified\r\n",
                     "RP_WU_ERROR:8024402C\r\n", "xx RP_WU_ERROR:8024402C:NotSpecified"):
            with self.subTest(text=text):
                self.assertEqual(agent._wu_error_class(text), "unknown")

    def test_the_search_script_asks_with_a_timeout_and_runs_powershell_by_absolute_path_or_its_fallback(self):
        run = fake_run(0, "")
        search(run)
        argv, kwargs = run.calls[0]
        self.assertEqual(kwargs["timeout"], 120)
        self.assertEqual(argv[-2:], ["-Command", agent._WU_PS])

    def test_every_hresult_in_the_table_is_in_one_class_and_the_classes_are_the_servers(self):
        self.assertTrue(set(agent._WU_HRESULT_CLASS.values()) <= set(wh.SEARCH_CLASSES))
        self.assertTrue(set(agent._WU_CATEGORY_CLASS.values()) <= set(wh.SEARCH_CLASSES))
        self.assertGreaterEqual(len(agent._WU_HRESULT_CLASS), 15)

    def test_the_marker_is_not_a_title(self):
        self.assertEqual(agent._parse_wu_titles("RP_WU_ERROR:8024402C:NotSpecified\nA title\n"), ["A title"])


class TestWhereTheSearchAsks(unittest.TestCase):
    POLICY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    def source(self, tree):
        fake = S.FakeWinreg(tree)
        with mock.patch.dict(sys.modules, {"winreg": fake}):
            result = agent._wu_source()
        self.assertEqual(fake.reached_for, [], "the agent reached for a winreg name that is not a read")
        self.assertFalse(fake.wrote, "a key was opened with a right that writes")
        self.assertEqual(fake.leaked, [], "a key was left open")
        return result

    def test_a_host_pointed_at_a_wsus_server(self):
        tree = {self.POLICY: {"WUServer": ("http://wsus.corp.example:8530", S.SZ)},
                self.POLICY + r"\AU": {"UseWUServer": (1, S.DWORD)}}
        self.assertEqual(self.source(tree), "wsus")

    def test_a_server_that_the_policy_does_not_use_is_not_wsus(self):
        tree = {self.POLICY: {"WUServer": ("http://wsus.corp.example:8530", S.SZ)},
                self.POLICY + r"\AU": {"UseWUServer": (0, S.DWORD)}}
        self.assertEqual(self.source(tree), "windows-update-agent")

    def test_the_switch_with_no_server_is_not_wsus(self):
        self.assertEqual(self.source({self.POLICY + r"\AU": {"UseWUServer": (1, S.DWORD)}}), "windows-update-agent")
        self.assertEqual(self.source({self.POLICY: {"WUServer": ("", S.SZ)}, self.POLICY + r"\AU": {"UseWUServer": (1, S.DWORD)}}),
                         "windows-update-agent")

    def test_a_host_with_no_policy_asks_microsoft(self):
        self.assertEqual(self.source({r"SOFTWARE\Microsoft\Windows\CurrentVersion": {}}), "windows-update-agent")
        self.assertEqual(self.source({self.POLICY: {"WUServer": ("http://wsus", S.SZ)}}), "windows-update-agent")

    def test_off_windows_there_is_no_registry_and_the_answer_is_the_default(self):
        with mock.patch.dict(sys.modules, {"winreg": None}):
            self.assertEqual(agent._wu_source(), "windows-update-agent")

    def test_the_state_carries_the_source(self):
        tree = {self.POLICY: {"WUServer": ("http://wsus.corp.example:8530", S.SZ)},
                self.POLICY + r"\AU": {"UseWUServer": (1, S.DWORD)}}
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg(tree)}):
            _, state = search(fake_run(0, crlf(PENDING)))
        self.assertEqual(state["source"], "wsus")


class TestWhatCollectSysinfoSends(unittest.TestCase):
    def collect(self, run):
        """The sysinfo the agent builds, with the search the real one."""
        def real_search():
            with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", run), \
                    mock.patch.object(agent, "get_winget_updates", lambda: {}):
                return orig()
        orig = agent.windows_update_pending
        with mock.patch.object(agent, "windows_update_pending", real_search):
            return agent.collect_sysinfo()

    def test_a_good_search_sends_the_count_and_the_state(self):
        info = self.collect(fake_run(0, crlf(PENDING + DEFINITIONS)))
        self.assertEqual(info["packages"]["upgradable"], 3)
        self.assertEqual(info["packages"]["definition_updates"], 2)
        self.assertTrue(info["wu_search"]["ok"])

    def test_a_failed_search_sends_the_state_and_no_count(self):
        info = self.collect(fake_run(3, "RP_WU_ERROR:80070005:NotSpecified\r\n"))
        self.assertNotIn("packages", info)
        self.assertEqual((info["wu_search"]["ok"], info["wu_search"]["error_class"]), (False, "access"))

    def test_an_old_outcome_is_never_sent_again(self):
        """A search that did not run (off Windows, or a stand-in for it) must not send what an earlier one left."""
        agent._wu_search_state = {"at": 1, "ok": False, "source": "wsus", "error_class": "timeout"}
        with mock.patch.object(agent, "windows_update_pending", lambda: None):
            info = agent.collect_sysinfo()
        self.assertNotIn("wu_search", info)

    def test_off_windows_nothing_is_sent_about_a_search(self):
        info = agent.collect_sysinfo()
        self.assertNotIn("wu_search", info)
        self.assertNotIn("packages", info)

    def test_the_payload_is_json(self):
        import json
        info = self.collect(fake_run(0, crlf(PENDING + DEFINITIONS)))
        json.dumps(info)


@unittest.skipUnless(_PWSH, "PowerShell is not available here")
class TestTheSearchScriptUnderPowerShell(unittest.TestCase):
    def test_the_script_parses(self):
        script = ("$e=$null;$t=$null;$null=[System.Management.Automation.Language.Parser]::ParseInput("
                  "$env:RP_PS_TEXT,[ref]$t,[ref]$e);if($e.Count){'ERR:'+$e[0].Message}else{'OK'}")
        out = subprocess.run([_PWSH, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, RP_PS_TEXT=agent._WU_PS))
        self.assertEqual(out.stdout.strip(), "OK")

    def test_the_failure_path_prints_the_marker_and_exits_with_three(self):
        """On Linux there is no Windows Update COM class, so the script fails for real: this runs its catch branch."""
        out = subprocess.run([_PWSH, "-NoProfile", "-NonInteractive", "-Command", agent._WU_PS], capture_output=True, text=True,
                             timeout=60)
        self.assertEqual(out.returncode, 3)
        self.assertRegex(out.stdout.strip().splitlines()[-1], r"^RP_WU_ERROR:[0-9A-F]{8}:[A-Za-z]+$")
        self.assertIn(agent._wu_error_class(out.stdout), wh.SEARCH_CLASSES)

    def test_a_wrapped_com_error_is_read_from_the_innermost_exception(self):
        """A COM call fails as a MethodInvocationException around a COMException; the script has to report the inner HRESULT."""
        body = agent._WU_PS.split("try{", 1)[1].split("}catch{", 1)[1].rsplit("}", 1)[0]
        signed = 0x80072EE7 - (1 << 32)          # ERROR_INTERNET_NAME_NOT_RESOLVED, as the Int32 that .NET holds
        probe = ("$ErrorActionPreference='Stop';try{ throw ([System.Management.Automation.MethodInvocationException]::new('outer', "
                 f"([System.Runtime.InteropServices.COMException]::new('inner', {signed})))) }}catch{{" + body + "}")
        out = subprocess.run([_PWSH, "-NoProfile", "-NonInteractive", "-Command", probe], capture_output=True, text=True,
                             timeout=60)
        self.assertEqual(out.returncode, 3)
        self.assertTrue(out.stdout.startswith("RP_WU_ERROR:80072EE7:"), out.stdout)
        self.assertEqual(agent._wu_error_class(out.stdout), "network")


# ── the server ───────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheServerReadsTheState(unittest.TestCase):
    NOW = 1_800_000_000

    def state(self, raw, prev=None):
        return wh.clean_search_state(raw, self.NOW, prev)

    def test_a_good_state(self):
        s = self.state({"at": self.NOW - 30, "ok": True, "source": "wsus", "error_class": ""})
        self.assertEqual(s, {"at": self.NOW - 30, "ok": True, "source": "wsus", "error_class": "", "ok_at": self.NOW - 30, "fail_since": 0})

    def test_a_failed_state_with_nothing_before_it(self):
        s = self.state({"at": self.NOW - 30, "ok": False, "source": "windows-update-agent", "error_class": "access"})
        self.assertEqual((s["ok"], s["error_class"], s["ok_at"], s["fail_since"]), (False, "access", 0, self.NOW - 30))

    def test_a_failure_keeps_the_time_of_the_last_search_that_worked(self):
        prev = {"wu_search": {"at": self.NOW - 700, "ok": True, "ok_at": self.NOW - 700, "fail_since": 0}}
        s = self.state({"at": self.NOW, "ok": False, "error_class": "timeout"}, prev)
        self.assertEqual((s["ok_at"], s["fail_since"]), (self.NOW - 700, self.NOW))

    def test_a_second_failure_keeps_where_the_failures_began_and_the_time_of_the_last_success(self):
        prev = {"wu_search": {"at": self.NOW - 700, "ok": False, "ok_at": self.NOW - 90000, "fail_since": self.NOW - 3000}}
        s = self.state({"at": self.NOW, "ok": False, "error_class": "timeout"}, prev)
        self.assertEqual((s["ok_at"], s["fail_since"]), (self.NOW - 90000, self.NOW - 3000))

    def test_a_host_from_before_the_state_existed_gives_the_time_of_its_last_report(self):
        s = self.state({"at": self.NOW, "ok": False, "error_class": "service"}, {"pkg_scan_ts": self.NOW - 5000, "packages": {}})
        self.assertEqual(s["ok_at"], self.NOW - 5000)

    def test_a_success_ends_the_failures(self):
        prev = {"wu_search": {"at": self.NOW - 700, "ok": False, "ok_at": 5, "fail_since": self.NOW - 9000}}
        s = self.state({"at": self.NOW, "ok": True}, prev)
        self.assertEqual((s["ok_at"], s["fail_since"]), (self.NOW, 0))

    def test_a_word_outside_the_fixed_sets_is_unknown(self):
        s = self.state({"at": self.NOW, "ok": False, "source": "rm -rf /", "error_class": "Access is denied: C:\\Users\\jdoe"})
        self.assertEqual((s["source"], s["error_class"]), ("unknown", "unknown"))
        s = self.state({"at": self.NOW, "ok": False})
        self.assertEqual(s["error_class"], "unknown")
        s = self.state({"at": self.NOW, "ok": True, "error_class": "access", "source": ["wsus"]})
        self.assertEqual((s["error_class"], s["source"]), ("", "unknown"))

    def test_an_ok_that_is_not_true_or_false_is_not_a_state(self):
        for ok in (None, 1, 0, "true", "ok", [], {}):
            with self.subTest(ok=ok):
                self.assertIsNone(self.state({"at": self.NOW, "ok": ok}))
        for raw in (None, "x", 5, [], [{"ok": True}], ()):
            with self.subTest(raw=raw):
                self.assertIsNone(self.state(raw))

    def test_the_time_of_a_clock_that_is_wrong_is_not_believed(self):
        for at in (self.NOW + 3600, self.NOW + 10**12, self.NOW - 3600, 0, -5, 1.5, True, "now", None, [1], 10**30):
            with self.subTest(at=at):
                self.assertEqual(self.state({"at": at, "ok": True})["at"], self.NOW)
        for at in (self.NOW - 800, self.NOW - 1, self.NOW + 30):
            self.assertEqual(self.state({"at": at, "ok": True})["at"], at)

    def test_a_stored_state_that_is_hostile_does_not_break_the_next_one(self):
        for prev in ({"wu_search": "x"}, {"wu_search": {"ok_at": "a", "fail_since": [], "ok": False}}, {"wu_search": None}, "x", [], None,
                     {"pkg_scan_ts": "x", "wu_search": {"ok": True, "at": True}}):
            with self.subTest(prev=prev):
                s = self.state({"at": self.NOW, "ok": False, "error_class": "timeout"}, prev)
                self.assertEqual((s["ok_at"], s["fail_since"]), (0, self.NOW))


class TestTheServerLeavesDefinitionUpdatesOut(unittest.TestCase):
    def settle(self, pkg, raw=None):
        pkg = dict(pkg)
        wh.settle_update_packages(pkg, pkg if raw is None else raw)
        return pkg

    def test_an_older_agent_that_counted_them(self):
        got = self.settle({"manager": "windows-update", "upgradable": 5, "upgradable_names": PENDING + DEFINITIONS})
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["definition_updates"]), (3, PENDING, 2))

    def test_a_current_agent_is_not_counted_twice(self):
        got = self.settle({"manager": "windows-update", "upgradable": 3, "upgradable_names": PENDING},
                          {"definition_updates": 2})
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["definition_updates"]), (3, PENDING, 2))

    def test_both_at_once(self):
        got = self.settle({"manager": "windows-update", "upgradable": 4, "upgradable_names": PENDING + DEFINITIONS[:1]},
                          {"definition_updates": 2})
        self.assertEqual((got["upgradable"], got["definition_updates"]), (3, 3))

    def test_the_count_does_not_go_below_zero(self):
        got = self.settle({"manager": "windows-update", "upgradable": 0, "upgradable_names": DEFINITIONS})
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["definition_updates"]), (0, [], 2))

    def test_a_count_that_is_unknown_stays_unknown(self):
        got = self.settle({"manager": "windows-update", "upgradable": None, "upgradable_names": PENDING + DEFINITIONS})
        self.assertIsNone(got["upgradable"])

    def test_another_manager_is_left_alone(self):
        pkg = {"manager": "apt", "upgradable": 5, "upgradable_names": PENDING + DEFINITIONS}
        self.assertEqual(self.settle(pkg), pkg)

    def test_the_reported_number_is_bounded(self):
        for value in (-1, 10**9, True, "2", 2.5, None, [2]):
            with self.subTest(value=value):
                got = self.settle({"manager": "windows-update", "upgradable": 1}, {"definition_updates": value})
                self.assertEqual(got["definition_updates"], 0)

    def test_the_number_of_definition_updates_stays_below_the_bound_with_the_names_added(self):
        """A report can carry the largest count and 300 names of definition updates (the most the sanitizer keeps)."""
        names = [DEFINITIONS[0]] * 300
        got = self.settle({"manager": "windows-update", "upgradable": 300, "upgradable_names": names}, {"definition_updates": wh.MAX_COUNT})
        self.assertEqual(got["definition_updates"], wh.MAX_COUNT)
        self.assertEqual(got["upgradable"], 0)

    def test_the_names_are_text_or_they_are_left_to_the_sanitizer(self):
        got = self.settle({"manager": "windows-update", "upgradable": 2, "upgradable_names": [PENDING[0], None, 5]})
        self.assertEqual(got["upgradable"], 2)

    def test_keep_last_count_copies_only_what_the_new_report_lacks(self):
        prev = {"packages": {"upgradable": 3, "upgradable_names": ["a"]}, "pkg_scan_ts": 100, "cpu": 1}
        si = {"cpu": 2}
        self.assertTrue(wh.keep_last_count(si, prev))
        self.assertEqual(si, {"cpu": 2, "packages": {"upgradable": 3, "upgradable_names": ["a"]}, "pkg_scan_ts": 100})
        si["packages"]["upgradable"] = 9
        self.assertEqual(prev["packages"]["upgradable"], 3, "the copy shares the stored record")
        fresh = {"packages": {"upgradable": 1}}
        self.assertTrue(wh.keep_last_count(fresh, prev))
        self.assertEqual(fresh["packages"], {"upgradable": 1})
        self.assertFalse(wh.keep_last_count({}, None))
        self.assertFalse(wh.keep_last_count({}, "x"))


class TestTheRowOnTheChecksPage(unittest.TestCase):
    NOW = 1_800_000_000
    DAY = 86400

    def row(self, state, **kw):
        si = {"packages": {"manager": "windows-update", "upgradable": 0}}
        if state is not None:
            si["wu_search"] = state
        dev = {"sysinfo": si, "last_seen": self.NOW}
        rows = {r["key"]: r for r in checks._host_checks("w1", dev, now=self.NOW, **kw)}
        return rows.get("win_update_search")

    def failed(self, days, since=None, cls="access"):
        ok_at = self.NOW - int(days * self.DAY)
        return {"at": self.NOW - 600, "ok": False, "source": "windows-update-agent", "error_class": cls, "ok_at": ok_at,
                "fail_since": since or 0}

    def test_a_search_that_worked_is_ok(self):
        row = self.row({"at": self.NOW - 720, "ok": True, "source": "wsus", "error_class": "", "ok_at": self.NOW - 720, "fail_since": 0})
        self.assertEqual((row["status"], row["name"], row["group"]), ("ok", "Windows Update search", "patch"))
        self.assertEqual(row["output"], "last search 12 minutes ago, ok")

    def test_a_failure_of_a_day_is_not_a_finding_yet(self):
        row = self.row(self.failed(1))
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["output"], "last search failed (access) 10 minutes ago; the count is from "
                         + time.strftime("%Y-%m-%d", time.gmtime(self.NOW - self.DAY)))

    def test_amber_from_three_days_and_red_from_fourteen(self):
        cases = ((3 * self.DAY - 1, "ok"), (3 * self.DAY, "warning"), (14 * self.DAY - 1, "warning"), (14 * self.DAY, "critical"),
                 (60 * self.DAY, "critical"))
        for seconds, expect in cases:
            with self.subTest(seconds=seconds):
                state = self.failed(0)
                state["ok_at"] = self.NOW - seconds
                self.assertEqual(self.row(state)["status"], expect)

    def test_the_text_of_a_late_failure_says_how_long(self):
        row = self.row(self.failed(5))
        self.assertTrue(row["output"].startswith("no successful search for 5 days; last search failed (access)"), row["output"])

    def test_a_host_that_has_never_had_a_search_that_worked_counts_from_its_first_failure(self):
        state = {"at": self.NOW - 600, "ok": False, "source": "unknown", "error_class": "service", "ok_at": 0,
                 "fail_since": self.NOW - 4 * self.DAY}
        row = self.row(state)
        self.assertEqual(row["status"], "warning")
        self.assertIn("no search has worked yet", row["output"])
        state["fail_since"] = self.NOW - 20 * self.DAY
        self.assertEqual(self.row(state)["status"], "critical")

    def test_a_good_state_that_nothing_has_followed_goes_stale(self):
        row = self.row({"at": self.NOW - 5 * self.DAY, "ok": True, "source": "wsus", "error_class": "", "ok_at": self.NOW - 5 * self.DAY})
        self.assertEqual(row["status"], "warning")
        self.assertIn("nothing newer has been reported", row["output"])

    def test_a_host_that_sent_no_state_has_no_row(self):
        for state in (None, "x", [], {}, {"ok": "yes"}, {"at": self.NOW}):
            with self.subTest(state=state):
                self.assertIsNone(self.row(state))

    def test_a_row_the_operator_switched_off_is_still_there_and_is_not_enabled(self):
        row = self.row(self.failed(20), disabled=["win_update_search"])
        self.assertEqual((row["status"], row["enabled"]), ("critical", False))
        self.assertTrue(self.row(self.failed(20))["enabled"])

    def test_the_output_is_the_one_line_the_page_prints(self):
        for days in (0, 1, 3, 14, 400):
            self.assertLessEqual(len(self.row(self.failed(days))["output"]), 200)

    def test_hostile_stored_values_do_not_break_the_row(self):
        for state in ({"ok": True, "at": "x", "ok_at": [], "fail_since": {}}, {"ok": False, "at": -1, "error_class": {"a": 1}},
                      {"ok": False, "at": 10**30, "ok_at": 10**30, "fail_since": 10**30}):
            with self.subTest(state=state):
                self.assertIn(self.row(state)["status"], ("ok", "warning", "critical"))


# ── the whole way: the agent's payload through the real heartbeat ────────────────────────────────────────────────────────
class _Host(unittest.TestCase):
    DEV = "win-search-host-1"
    TOKEN = "token-win-search-host-1"

    def setUp(self):
        api.save(api.DEVICES_FILE, {self.DEV: {
            "name": "WIN-SEARCH-1", "hostname": "WIN-SEARCH-1", "os": "Windows 11 (Build 22631)", "token": self.TOKEN,
            "last_seen": int(time.time()), "enrolled": int(time.time()), "tags": [], "group": "", "sysinfo": {}, "agentless": False}})
        api._LOAD_CACHE.clear()

    def stored(self):
        api._LOAD_CACHE.clear()
        return api.load(api.DEVICES_FILE)[self.DEV].get("sysinfo") or {}

    def send(self, run):
        """What the agent sends after this search, through the real handler."""
        def real_search():
            with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", run), \
                    mock.patch.object(agent, "get_winget_updates", lambda: {}):
                return orig()
        orig = agent.windows_update_pending
        with mock.patch.object(agent, "windows_update_pending", real_search):
            info = agent.collect_sysinfo()
        status, body = S.beat(api, self.DEV, self.TOKEN, info)
        self.assertEqual(status, 200, body)
        return info

    def send_raw(self, sysinfo):
        status, body = S.beat(api, self.DEV, self.TOKEN, sysinfo)
        self.assertEqual(status, 200, body)


class TestTheHeartbeat(_Host):
    def test_a_search_that_worked_is_stored_without_the_definition_updates(self):
        self.send(fake_run(0, crlf(PENDING + DEFINITIONS)))
        si = self.stored()
        self.assertEqual(si["packages"]["upgradable"], 3)
        self.assertEqual(si["packages"]["upgradable_names"], PENDING)
        self.assertEqual(si["packages"]["definition_updates"], 2)
        self.assertTrue(si["wu_search"]["ok"])
        self.assertEqual(si["wu_search"]["ok_at"], si["wu_search"]["at"])
        self.assertIn("pkg_scan_ts", si)

    def test_a_failed_search_keeps_the_count_and_does_not_refresh_it(self):
        self.send(fake_run(0, crlf(PENDING + DEFINITIONS)))
        first = self.stored()
        time.sleep(1.1)
        self.send(fake_run(3, "RP_WU_ERROR:80070005:NotSpecified\r\n"))
        second = self.stored()
        self.assertEqual(second["packages"], first["packages"])
        self.assertEqual(second["pkg_scan_ts"], first["pkg_scan_ts"], "a failed search refreshed the time the count was taken")
        ws = second["wu_search"]
        self.assertFalse(ws["ok"])
        self.assertEqual(ws["error_class"], "access")
        self.assertEqual(ws["ok_at"], first["wu_search"]["at"])
        self.assertGreater(ws["at"], first["wu_search"]["at"])

    def test_a_failure_that_goes_on_keeps_the_count_and_where_it_began(self):
        self.send(fake_run(0, crlf(PENDING)))
        self.send(fake_run(3, "RP_WU_ERROR:80070422:NotSpecified\r\n"))
        began = self.stored()["wu_search"]["fail_since"]
        self.send(fake_run(3, "RP_WU_ERROR:80070422:NotSpecified\r\n"))
        si = self.stored()
        self.assertEqual(si["wu_search"]["fail_since"], began)
        self.assertEqual(si["packages"]["upgradable"], 3)

    def test_a_search_that_works_again_replaces_the_count(self):
        self.send(fake_run(0, crlf(PENDING)))
        self.send(fake_run(3, "RP_WU_ERROR:80070005:NotSpecified\r\n"))
        self.send(fake_run(0, crlf(PENDING[:1])))
        si = self.stored()
        self.assertEqual(si["packages"]["upgradable"], 1)
        self.assertTrue(si["wu_search"]["ok"])
        self.assertEqual(si["wu_search"]["fail_since"], 0)

    def test_a_host_whose_first_search_failed_has_no_count_and_says_so(self):
        self.send(fake_run(3, "RP_WU_ERROR:8024402C:NotSpecified\r\n"))
        si = self.stored()
        self.assertNotIn("packages", si)
        self.assertEqual((si["wu_search"]["ok"], si["wu_search"]["error_class"], si["wu_search"]["ok_at"]), (False, "network", 0))

    def test_an_agent_from_before_the_state_existed_is_read_the_way_the_new_one_is(self):
        """The count of an old agent holds the definition updates in its names; the server leaves them out."""
        self.send_raw({"hostname": "WIN-SEARCH-1", "packages": {
            "manager": "windows-update", "upgradable": 5, "upgradable_names": PENDING + DEFINITIONS}})
        si = self.stored()
        self.assertEqual((si["packages"]["upgradable"], si["packages"]["definition_updates"]), (3, 2))
        self.assertEqual(si["packages"]["upgradable_names"], PENDING)
        self.assertNotIn("wu_search", si)

    def test_an_agent_that_failed_after_an_upgrade_names_the_date_of_the_old_count(self):
        self.send_raw({"hostname": "WIN-SEARCH-1", "packages": {"manager": "windows-update", "upgradable": 2, "upgradable_names": PENDING[:2]}})
        scanned = self.stored()["pkg_scan_ts"]
        self.send_raw({"hostname": "WIN-SEARCH-1", "wu_search": {"at": int(time.time()), "ok": False, "error_class": "timeout"}})
        si = self.stored()
        self.assertEqual(si["wu_search"]["ok_at"], scanned)
        self.assertEqual(si["packages"]["upgradable"], 2)

    def test_a_state_a_host_makes_up_is_cleaned(self):
        self.send_raw({"hostname": "WIN-SEARCH-1", "wu_search": {
            "at": 10**15, "ok": False, "source": "<script>alert(1)</script>", "error_class": "Access is denied C:\\Users\\jdoe",
            "ok_at": 1, "fail_since": 1, "extra": "x" * 10000}})
        ws = self.stored()["wu_search"]
        self.assertEqual(sorted(ws), ["at", "error_class", "fail_since", "ok", "ok_at", "source"])
        self.assertEqual((ws["source"], ws["error_class"]), ("unknown", "unknown"))
        self.assertLess(abs(ws["at"] - time.time()), 30)
        self.assertEqual(ws["ok_at"], 0, "an agent set the time of the last good search")

    def test_a_state_of_the_wrong_kind_is_dropped_and_the_beat_is_taken(self):
        for raw in ("x", 5, [1], {"ok": "yes"}, {"at": 5}, None):
            with self.subTest(raw=raw):
                self.send_raw({"hostname": "WIN-SEARCH-1", "wu_search": raw})
                self.assertNotIn("wu_search", self.stored())

    def test_the_definition_count_a_host_reports_is_bounded(self):
        self.send_raw({"hostname": "WIN-SEARCH-1", "packages": {
            "manager": "windows-update", "upgradable": 1, "upgradable_names": ["x"], "definition_updates": 10**12}})
        self.assertEqual(self.stored()["packages"]["definition_updates"], 0)

    def test_a_linux_report_is_untouched(self):
        self.send_raw({"hostname": "linux-1", "packages": {"manager": "apt", "upgradable": 4, "upgradable_names": DEFINITIONS + ["a", "b"]}})
        pkg = self.stored()["packages"]
        self.assertEqual((pkg["upgradable"], pkg["upgradable_names"]), (4, DEFINITIONS + ["a", "b"]))
        self.assertNotIn("definition_updates", pkg)

    def test_only_a_failed_search_keeps_the_count(self):
        """The stored report is replaced by each beat, so a count is kept on a beat that says its search failed and on no other. A beat that
        sends no count and no state (an agent from before the state existed, a host whose package manager vanished), a search that worked and
        sent no count, and a state that is not one all leave no count and no time behind, as they did before the state existed."""
        now = int(time.time())
        counted = {"hostname": "WIN-SEARCH-1", "packages": {"manager": "windows-update", "upgradable": 3, "upgradable_names": PENDING}}
        for label, sysinfo in (
            ("no count and no state", {"hostname": "WIN-SEARCH-1"}),
            ("a search that worked and sent no count", {"hostname": "WIN-SEARCH-1", "wu_search": {"at": now, "ok": True}}),
            ("a state whose ok is not true or false", {"hostname": "WIN-SEARCH-1", "wu_search": {"at": now, "ok": "no"}}),
            ("a state that is not a map", {"hostname": "WIN-SEARCH-1", "wu_search": "failed"}),
        ):
            with self.subTest(beat=label):
                self.send_raw(counted)
                seeded = self.stored()
                self.assertEqual((seeded["packages"]["upgradable"], "pkg_scan_ts" in seeded), (3, True), "control: the host has a count")
                self.send_raw(sysinfo)
                si = self.stored()
                self.assertNotIn("packages", si, "the count of an earlier report was kept by a beat that did not say its search failed")
                self.assertNotIn("pkg_scan_ts", si, "the time of an earlier count was kept by a beat that did not say its search failed")
        self.send_raw(counted)
        self.send_raw({"hostname": "WIN-SEARCH-1", "wu_search": {"at": now, "ok": False, "error_class": "service"}})
        kept = self.stored()
        self.assertEqual((kept["packages"]["upgradable"], "pkg_scan_ts" in kept), (3, True), "control: a failed search does keep it")

    def test_a_search_that_worked_and_found_nothing_is_a_count_of_zero_and_not_a_kept_one(self):
        self.send_raw({"hostname": "WIN-SEARCH-1", "packages": {"manager": "windows-update", "upgradable": 3, "upgradable_names": PENDING}})
        self.send_raw({"hostname": "WIN-SEARCH-1", "wu_search": {"at": int(time.time()), "ok": True},
                       "packages": {"manager": "windows-update", "upgradable": 0, "upgradable_names": []}})
        self.assertEqual(self.stored()["packages"]["upgradable"], 0)

    def test_the_checks_page_shows_the_row_and_the_mute_applies(self):
        self.send(fake_run(3, "RP_WU_ERROR:80070005:NotSpecified\r\n"))
        status, body = S.call(api, api.handle_device_checks, self.DEV)
        self.assertEqual(status, 200)
        row = next(r for r in body["checks"] if r["key"] == "win_update_search")
        self.assertEqual((row["status"], row["enabled"]), ("ok", True))
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["host_checks_disabled"] = {self.DEV: ["win_update_search"]}
        api.save(api.CONFIG_FILE, cfg)
        try:
            api._LOAD_CACHE.clear()
            status, body = S.call(api, api.handle_device_checks, self.DEV)
            row = next(r for r in body["checks"] if r["key"] == "win_update_search")
            self.assertFalse(row["enabled"])
        finally:
            cfg.pop("host_checks_disabled", None)
            api.save(api.CONFIG_FILE, cfg)

    def test_the_patch_report_and_the_drawer_read_the_state(self):
        self.send(fake_run(0, crlf(PENDING + DEFINITIONS)))
        status, body = S.call(api, api.handle_patch_report_device, self.DEV)
        self.assertEqual(status, 200)
        self.assertEqual((body["upgradable"], body["definition_updates"], body["wu_search"]["ok"]), (3, 2, True))
        status, body = S.call(api, api.handle_sysinfo, self.DEV)
        self.assertEqual(body["sysinfo"]["wu_search"]["ok"], True)
        self.assertEqual(body["sysinfo"]["packages"]["definition_updates"], 2)


# ── every reader of the pending count ────────────────────────────────────────────────────────────────────────────────────
#
# The count is stored once (sysinfo.packages.upgradable) and every reader takes it from there, so a reader needs no change when the stored
# count leaves the definition updates out. This is the list of the functions that name it, found by syntax tree in every server module. It is
# a ratchet in both directions: a reader that is not on it fails the build (look at what it reads, then add it), and a name on it that no
# longer reads the count fails too.
READERS = {
    "advisory.py:_os_findings", "api.py:_alert_title", "api.py:_autoheal_recheck", "api.py:_build_posture_digest",
    "api.py:_build_runbook_snapshot", "api.py:_compliance_facts", "api.py:_compute_attention", "api.py:_device_risk",
    "api.py:_eval_patch_sla", "api.py:_maybe_sample_metrics", "api.py:_offline_sweep_has_work", "api.py:_patches",
    "api.py:_qe_device_posture", "api.py:_rag_fleet_rollups", "api.py:_record_alert", "api.py:_record_fleet_event",
    "api.py:_upgrade_verify_status", "api.py:check_offline_webhooks", "api.py:handle_ai_anomaly", "api.py:handle_digest",
    "api.py:handle_fleet_query", "api.py:handle_heartbeat", "api.py:handle_home", "api.py:handle_patch_catalog",
    "api.py:handle_patch_report", "api.py:handle_patch_report_csv", "api.py:handle_patch_report_device",
    "api.py:handle_patch_report_xml", "api.py:handle_upgrade_device", "api.py:run_patch_sla_if_due", "checks.py:_host_checks",
    "mcp_http.py:tool_get_patches", "notify.py:<module>", "notify.py:_webhook_message", "prometheus_export.py:generate_metrics",
    "provisioning_handlers.py:_rollout_dispatch_ring", "rag_index.py:build_live_state_corpus",
    "reports_handlers.py:_build_fleet_report",
}


# The module that takes the definition updates out of the count on the way in names the key too; it writes the count and reads none.
NOT_A_READER = {"windows_host.py"}


def readers_of_the_pending_count():
    found = set()
    for path in sorted(_CGI.glob("*.py")):
        if path.name in NOT_A_READER:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        spans = [(n.lineno, n.end_lineno, n.name) for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and n.value == "upgradable":
                inside = [(a, name) for a, b, name in spans if a <= n.lineno <= b]
                found.add(f"{path.name}:{max(inside)[1] if inside else '<module>'}")
    return found


class TestEveryReaderOfThePendingCount(_Host):
    def setUp(self):
        super().setUp()
        self.send(fake_run(0, crlf(PENDING + DEFINITIONS)))      # 3 pending updates and 2 definition updates
        self.dev = api.load(api.DEVICES_FILE)[self.DEV]
        self.assertEqual(self.dev["sysinfo"]["packages"]["upgradable"], 3)

    def test_the_list_of_readers_is_the_one_in_the_source(self):
        found = readers_of_the_pending_count()
        self.assertGreater(len(found), 30, "the scan found almost nothing")
        self.assertEqual(sorted(found - READERS), [], "a function reads the pending count and is not on the list: see what it reads")
        self.assertEqual(sorted(READERS - found), [], "a function on the list no longer reads the pending count")

    def test_the_checks_row(self):
        rows = {r["key"]: r for r in checks._host_checks(self.DEV, self.dev, now=int(time.time()))}
        self.assertEqual(rows["patches"]["output"], "3 updates")

    def test_the_risk_score(self):
        risk = api._device_risk(self.DEV, self.dev, {}, {}, {}, int(time.time()), 180)
        factor = next(f for f in risk["factors"] if f["kind"] == "pending_updates")
        self.assertEqual(factor["detail"], "3 pending updates")

    def test_the_advisory(self):
        import advisory
        findings = advisory.build({self.DEV: self.dev})["findings"]
        patches = next(f for f in findings if f["id"].endswith("os.patches") or "os.patches" in str(f.get("id")))
        self.assertTrue(patches["title"].startswith("3 pending package updates"), patches["title"])

    def test_the_data_explorer(self):
        self.assertEqual(api._qe_device_posture(self.dev["sysinfo"])["pending_updates"], 3)

    def test_the_fleet_query(self):
        for gt, expect in ((2, [self.DEV]), (3, [])):
            with self.subTest(pending_gt=gt):
                status, body = S.call(api, api.handle_fleet_query, query=f"pending_gt={gt}")
                self.assertEqual(status, 200)
                rows = body["devices"] if isinstance(body, dict) else body
                self.assertEqual([r.get("id") or r.get("device_id") for r in rows], expect)

    def test_the_patch_sla_and_its_aging(self):
        """The SLA stamps when a host first had a pending update and clears the stamp when it has none. A host with only
        definition updates has none, so it is never stamped and never in breach."""
        only_defs = {"name": "defs-only", "sysinfo": {"packages": {"manager": "windows-update", "upgradable": 0, "definition_updates": 2}}}
        age = {}
        rows, _ = api._eval_patch_sla({self.DEV: self.dev, "defs": only_defs}, {"patch_sla": [{"match_type": "all", "all_days": 7}]},
                                      age, int(time.time()))
        self.assertEqual({r["device_id"]: r["upgradable"] for r in rows}, {self.DEV: 3, "defs": 0})
        self.assertIn("all_first", age[self.DEV])
        self.assertNotIn("all_first", age["defs"])

    def test_the_hosts_list(self):
        status, body = S.call(api, api.handle_devices_list)
        row = next(r for r in body if r["id"] == self.DEV)
        self.assertEqual(row["sysinfo"]["packages"]["upgradable"], 3)

    def test_the_fleet_patch_report(self):
        status, body = S.call(api, api.handle_patch_report)
        row = next(r for r in body["devices"] if r["device_id"] == self.DEV)
        self.assertEqual(row["upgradable"], 3)
        self.assertEqual(body["summary"]["total_pending_patches"], 3)

    def test_the_metrics_export(self):
        import prometheus_export
        text = prometheus_export.generate_metrics({
            "server_version": "x", "now": int(time.time()), "online_ttl": 180, "devices": {self.DEV: self.dev}, "monitors": [],
            "monitor_state": {}, "schedule": [], "pending_cmds": {}})
        line = next(ln for ln in text.splitlines() if ln.startswith("remotepower_device_upgradable_packages{"))
        self.assertTrue(line.rstrip().endswith(" 3"), line)

    def test_what_the_ai_is_told(self):
        import rag_index
        chunks = rag_index.build_live_state_corpus([dict(self.dev, id=self.DEV)], now=int(time.time()))
        text = "\n".join(str(c) for c in chunks)
        self.assertIn("pending package updates: 3", text)
        self.assertNotIn("pending package updates: 5", text)

    def test_the_patch_alert_threshold_does_not_count_them(self):
        """The Needs Attention pile-up turns from info to warning at a count the operator sets. At four, three pending updates are
        info; had the two definition updates been counted, five would have been a warning. At three it is the warning."""
        cfg = api.load(api.CONFIG_FILE) or {}
        try:
            for threshold, severity in ((4, "info"), (3, "warning")):
                with self.subTest(patch_na_warn_count=threshold):
                    cfg["patch_na_warn_count"] = threshold
                    api.save(api.CONFIG_FILE, cfg)
                    api._LOAD_CACHE.clear()
                    items = [i for i in api._compute_attention() if i.get("device_id") == self.DEV and i.get("kind") == "patches"]
                    self.assertEqual([(i["severity"], i["summary"]) for i in items], [(severity, "3 pending package updates")])
        finally:
            cfg.pop("patch_na_warn_count", None)
            api.save(api.CONFIG_FILE, cfg)


if __name__ == "__main__":
    unittest.main()
