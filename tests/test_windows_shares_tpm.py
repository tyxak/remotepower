#!/usr/bin/env python3
"""The file shares a Windows host exports, and its TPM.

Two slow probes of the Windows agent, each its own PowerShell, sent with the system information:

  * Get-SmbShare as JSON. A share that ends in $ is administrative (ADMIN$, C$, IPC$ and any hidden one): the agent counts those and does not list
    them. At most 100 shares are listed, and `count` says how many there are.
  * Get-Tpm and Win32_Tpm: whether a TPM is present, ready and enabled, and which specification it follows.

A probe that fails, or that the host cannot answer, sends nothing, and what is not sent is not read as "none": a TPM that was never reported is not a
host without one. The probes share a time budget. The server whitelists the fields (`safe_si`), the drawer shows them, and the Data Explorer and the Fleet
Query can ask for shares_count, tpm_present and tpm_ready. There is no alert for either.

The agent could not run on Windows here. The PowerShell texts are parsed by a real pwsh and run for real with the two cmdlets that Linux has not
replaced by functions that answer in the shape the real ones do; the answers go through the agent's own parsers and the real heartbeat handler.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="rp-shares-tpm-")
os.environ.setdefault("RP_DATA_DIR", _TMP)

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_CGI = _ROOT / "server" / "cgi-bin"
for _p in (str(_CGI), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import win_host_support as S  # noqa: E402
import windows_host as wh  # noqa: E402

import api  # noqa: E402
import checks  # noqa: E402

agent = S.load_agent("rp_shares_tpm_agent")
_PWSH = shutil.which("pwsh") or next((p for p in ("/home/jaove/.local/bin/pwsh",) if os.path.exists(p)), None)


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


# What Get-SmbShare answers on a file server, through the select of the agent's script: ConvertTo-Json -InputObject on an array.
FILE_SERVER = json.dumps([
    {"name": "ADMIN$", "path": "C:\\Windows", "description": "Remote Admin", "encrypted": False},
    {"name": "C$", "path": "C:\\", "description": "Default share", "encrypted": False},
    {"name": "Data", "path": "D:\\Data", "description": "Team data", "encrypted": True},
    {"name": "IPC$", "path": "", "description": "Remote IPC", "encrypted": False},
    {"name": "Public", "path": "C:\\Public", "description": "", "encrypted": False},
    {"name": "Backup$", "path": "E:\\Backup", "description": "hidden by the operator", "encrypted": False},
], separators=(",", ":"))
WORKSTATION = json.dumps([
    {"name": "ADMIN$", "path": "C:\\Windows", "description": "Remote Admin", "encrypted": False},
    {"name": "C$", "path": "C:\\", "description": "Default share", "encrypted": False},
    {"name": "IPC$", "path": "", "description": "Remote IPC", "encrypted": False},
])
TPM_20 = json.dumps({"present": True, "ready": True, "enabled": True, "spec": "2.0, 0, 1.59"})


def shares(n, prefix="Share"):
    return json.dumps([{"name": f"{prefix}{i:04d}", "path": f"D:\\{prefix}{i}", "description": "", "encrypted": False} for i in range(n)])


class TestWhatTheAgentMakesOfTheShares(unittest.TestCase):
    def test_a_file_server(self):
        got = agent._parse_smb_shares(FILE_SERVER)
        self.assertEqual(got["count"], 2)
        self.assertEqual(got["admin_count"], 4)
        self.assertEqual([r["name"] for r in got["items"]], ["Data", "Public"])
        self.assertEqual(got["items"][0], {"name": "Data", "path": "D:\\Data", "description": "Team data", "encrypted": True})
        self.assertEqual(got["items"][1]["encrypted"], False)

    def test_a_workstation_has_only_administrative_shares_and_says_so(self):
        self.assertEqual(agent._parse_smb_shares(WORKSTATION), {"count": 0, "admin_count": 3, "items": []})

    def test_an_administrative_share_is_counted_and_never_listed(self):
        got = agent._parse_smb_shares(FILE_SERVER)
        self.assertEqual([r for r in got["items"] if r["name"].endswith("$")], [])
        self.assertNotIn("Backup$", json.dumps(got))

    def test_one_share_that_is_an_object_and_not_a_list(self):
        got = agent._parse_smb_shares(json.dumps({"name": "Only", "path": "C:\\Only", "description": "d", "encrypted": False}))
        self.assertEqual((got["count"], got["admin_count"], [r["name"] for r in got["items"]]), (1, 0, ["Only"]))

    def test_the_list_is_cut_at_a_hundred_and_the_count_says_how_many(self):
        got = agent._parse_smb_shares(shares(250))
        self.assertEqual((got["count"], len(got["items"])), (250, 100))
        self.assertEqual([r["name"] for r in got["items"]][:2], ["Share0000", "Share0001"])

    def test_the_hundred_are_the_same_whatever_order_the_host_lists_them_in(self):
        rows = json.loads(shares(150))
        forward = agent._parse_smb_shares(json.dumps(rows))
        backward = agent._parse_smb_shares(json.dumps(rows[::-1]))
        self.assertEqual(forward, backward)

    def test_it_is_sorted_by_name_without_regard_to_case(self):
        rows = [{"name": n, "path": "", "description": "", "encrypted": False} for n in ("beta", "Alpha", "alpha2", "Zed", "gamma")]
        self.assertEqual([r["name"] for r in agent._parse_smb_shares(json.dumps(rows))["items"]], ["Alpha", "alpha2", "beta", "gamma", "Zed"])

    def test_text_is_capped(self):
        row = {"name": "n" * 500, "path": "p" * 500, "description": "d" * 500, "encrypted": True}
        item = agent._parse_smb_shares(json.dumps([row]))["items"][0]
        self.assertEqual((len(item["name"]), len(item["path"]), len(item["description"])), (80, 260, 200))

    def test_encrypted_is_kept_only_when_it_is_true_or_false(self):
        rows = [{"name": f"s{i}", "path": "", "description": "", "encrypted": v} for i, v in enumerate((True, False, "True", 1, None))]
        got = agent._parse_smb_shares(json.dumps(rows))["items"]
        self.assertEqual([r.get("encrypted", "absent") for r in got], [True, False, "absent", "absent", "absent"])

    def test_rows_that_are_not_shares_are_left_out(self):
        rows = [5, None, "x", [1], {"path": "no name"}, {"name": ""}, {"name": "   "}, {"name": "Real", "path": "C:\\Real"}]
        got = agent._parse_smb_shares(json.dumps(rows))
        self.assertEqual((got["count"], [r["name"] for r in got["items"]]), (1, ["Real"]))

    def test_an_answer_that_is_not_one(self):
        for out in (None, "", "   ", "null", "[]", "{}", "[1,2]", '"text"', "5", "not json", "[{", "\ufeff[", "[]" + " " * 10,
                    json.dumps([{"name": ""}])):
            with self.subTest(out=out):
                self.assertIsNone(agent._parse_smb_shares(out))

    def test_an_answer_that_is_too_large_is_not_read(self):
        big = shares(30000)
        self.assertGreater(len(big), agent.MAX_PROBE_OUTPUT)
        self.assertIsNone(agent._parse_smb_shares(big))

    def test_only_the_first_rows_of_an_answer_are_looked_at(self):
        rows = [{"name": f"S{i:05d}", "path": "", "description": "", "encrypted": False} for i in range(agent.MAX_SHARES_READ + 700)]
        text = json.dumps(rows, separators=(",", ":"))
        self.assertLessEqual(len(text), agent.MAX_PROBE_OUTPUT)
        got = agent._parse_smb_shares(text)
        self.assertEqual(got["count"], agent.MAX_SHARES_READ)


class TestWhatTheAgentMakesOfTheTpm(unittest.TestCase):
    def test_a_ready_tpm_of_the_second_specification(self):
        self.assertEqual(agent._parse_tpm(TPM_20), {"present": True, "ready": True, "enabled": True, "spec": "2.0"})

    def test_the_specification_is_the_version_at_the_front(self):
        for spec, expect in (("2.0, 0, 1.59", "2.0"), ("1.2, 2, 3", "1.2"), ("  2.0", "2.0"), ("2", "2"), ("2.0", "2.0")):
            self.assertEqual(agent._parse_tpm(json.dumps({"spec": spec})), {"spec": expect}, spec)
        for spec in ("", "x", "version 2.0", None, 5, [2.0], "99999.0"):
            self.assertIsNone(agent._parse_tpm(json.dumps({"spec": spec})), spec)

    def test_no_tpm_is_an_answer(self):
        got = agent._parse_tpm(json.dumps({"present": False, "ready": False, "enabled": False}))
        self.assertEqual(got, {"present": False, "ready": False, "enabled": False})

    def test_a_flag_the_host_could_not_answer_is_left_out_and_is_not_false(self):
        self.assertEqual(agent._parse_tpm(json.dumps({"spec": "2.0"})), {"spec": "2.0"})
        self.assertEqual(agent._parse_tpm(json.dumps({"present": True})), {"present": True})

    def test_a_flag_that_is_not_true_or_false_is_dropped(self):
        got = agent._parse_tpm(json.dumps({"present": "True", "ready": 1, "enabled": None, "spec": "2.0"}))
        self.assertEqual(got, {"spec": "2.0"})

    def test_an_answer_that_is_not_one(self):
        for out in (None, "", "null", "{}", "[]", "[true]", "5", "text", "{", "[{\"present\": true}]"):
            with self.subTest(out=out):
                self.assertIsNone(agent._parse_tpm(out))


class TestThePowerShell(unittest.TestCase):
    """The scripts are parsed, and run for real under PowerShell with the cmdlets that Linux does not have replaced by functions that
    answer in the shape the real ones do."""

    MOCK_SHARES = r"""
function Get-SmbShare {
  [pscustomobject]@{Name='ADMIN$'; Path='C:\Windows'; Description='Remote Admin'; EncryptData=$false; Special=$true; ShareType='FileSystemDirectory'}
  [pscustomobject]@{Name='Data'; Path='D:\Data'; Description='Team data'; EncryptData=$true; Special=$false; ShareType='FileSystemDirectory'}
  [pscustomobject]@{Name='Public'; Path='C:\Public'; Description=$null; EncryptData=$null; Special=$false; ShareType='FileSystemDirectory'}
}
"""
    MOCK_ONE_SHARE = r"""
function Get-SmbShare {
  [pscustomobject]@{Name='Only'; Path='C:\Only'; Description='one'; EncryptData=$false; Special=$false; ShareType='FileSystemDirectory'}
}
"""
    MOCK_NO_SHARES = "function Get-SmbShare { }\n"
    MOCK_FAILING_SHARES = "function Get-SmbShare { throw 'The Server service is not running' }\n"

    def run_ps(self, text, timeout=60):
        return subprocess.run([_PWSH, "-NoProfile", "-NonInteractive", "-Command", text], capture_output=True, text=True, timeout=timeout)

    def setUp(self):
        if not _PWSH:
            self.skipTest("PowerShell is not available here")

    def test_both_scripts_parse(self):
        script = ("$e=$null;$t=$null;$null=[System.Management.Automation.Language.Parser]::ParseInput("
                  "$env:RP_PS_TEXT,[ref]$t,[ref]$e);if($e.Count){'ERR:'+$e[0].Message}else{'OK'}")
        for name, text in (("_SHARES_PS", agent._SHARES_PS), ("_TPM_PS", agent._TPM_PS)):
            with self.subTest(script=name):
                out = subprocess.run([_PWSH, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60,
                                     env=dict(os.environ, RP_PS_TEXT=text))
                self.assertEqual(out.stdout.strip(), "OK")

    def test_the_shares_script_answers_what_the_parser_reads(self):
        out = self.run_ps(self.MOCK_SHARES + agent._SHARES_PS)
        self.assertEqual(out.returncode, 0, out.stderr)
        got = agent._parse_smb_shares(out.stdout)
        self.assertEqual((got["count"], got["admin_count"]), (2, 1))
        by_name = {r["name"]: r for r in got["items"]}
        self.assertEqual(by_name["Data"], {"name": "Data", "path": "D:\\Data", "description": "Team data", "encrypted": True})
        # a share with no description and no answer for EncryptData: [string]$null is "" and [bool]$null is false
        self.assertEqual(by_name["Public"]["description"], "")
        self.assertIs(by_name["Public"]["encrypted"], False)

    def test_one_share_is_still_a_list(self):
        out = self.run_ps(self.MOCK_ONE_SHARE + agent._SHARES_PS)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(out.stdout.strip().startswith("["), out.stdout)
        self.assertEqual(agent._parse_smb_shares(out.stdout)["count"], 1)

    def test_a_host_with_no_shares_at_all_is_no_answer(self):
        out = self.run_ps(self.MOCK_NO_SHARES + agent._SHARES_PS)
        self.assertIsNone(agent._parse_smb_shares(out.stdout))

    def test_a_cmdlet_that_fails_makes_the_script_fail(self):
        out = self.run_ps(self.MOCK_FAILING_SHARES + agent._SHARES_PS)
        self.assertNotEqual(out.returncode, 0)

    def test_the_tpm_script_with_both_answers(self):
        mock = (r"function Get-Tpm { [pscustomobject]@{TpmPresent=$true; TpmReady=$false; TpmEnabled=$true} }" "\n"
                r"function Get-CimInstance { param($Namespace, $ClassName) [pscustomobject]@{SpecVersion='2.0, 0, 1.59'} }" "\n")
        out = self.run_ps(mock + agent._TPM_PS)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(agent._parse_tpm(out.stdout), {"present": True, "ready": False, "enabled": True, "spec": "2.0"})

    def test_the_tpm_script_reads_the_right_namespace_and_class(self):
        mock = (r"function Get-Tpm { }" "\n"
                r"function Get-CimInstance { param($Namespace, $ClassName) "
                r"if ($Namespace -eq 'root\cimv2\Security\MicrosoftTpm' -and $ClassName -eq 'Win32_Tpm') { [pscustomobject]@{SpecVersion='1.2, 2, 3'} } }" "\n")
        out = self.run_ps(mock + agent._TPM_PS)
        self.assertEqual(agent._parse_tpm(out.stdout), {"spec": "1.2"})

    def test_a_host_without_the_tpm_cmdlet_leaves_the_flags_out_and_they_are_not_false(self):
        mock = r"function Get-CimInstance { param($Namespace, $ClassName) [pscustomobject]@{SpecVersion='2.0, 0, 1.38'} }" "\n"
        out = self.run_ps(mock + agent._TPM_PS)
        self.assertEqual(agent._parse_tpm(out.stdout), {"spec": "2.0"})

    def test_a_host_that_answers_neither_sends_nothing(self):
        out = self.run_ps(agent._TPM_PS)        # Linux has neither Get-Tpm nor Get-CimInstance
        self.assertIsNone(agent._parse_tpm(out.stdout))

    def test_a_host_with_no_tpm_says_so(self):
        mock = r"function Get-Tpm { [pscustomobject]@{TpmPresent=$false; TpmReady=$false; TpmEnabled=$false} }" "\n"
        out = self.run_ps(mock + agent._TPM_PS)
        self.assertEqual(agent._parse_tpm(out.stdout), {"present": False, "ready": False, "enabled": False})


class _FakeRun:
    """subprocess.run for the two probes: the answer by the script it is asked to run, the time each takes, and a record of the calls."""

    def __init__(self, answers, takes=None, raises=None, rc=0):
        self.answers, self.takes, self.raises, self.rc = answers, takes or {}, raises or {}, rc
        self.calls = []
        self.clock = [1000.0]

    def monotonic(self):
        return self.clock[0]

    def __call__(self, argv, *args, **kwargs):
        script = argv[-1]
        key = "shares" if script == agent._SHARES_PS else "tpm" if script == agent._TPM_PS else "other"
        self.calls.append((key, kwargs.get("timeout")))
        self.clock[0] += self.takes.get(key, 1.0)
        if key in self.raises:
            raise self.raises[key]

        class R:
            returncode = self.rc
            stdout = self.answers.get(key, "")
            stderr = ""
        return R


def probes(fake, budget=None):
    with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", fake), \
            mock.patch.object(agent.time, "monotonic", fake.monotonic):
        return agent.collect_slow_probes() if budget is None else agent.collect_slow_probes(budget)


class TestTheProbesAndTheirBudget(unittest.TestCase):
    def test_both_answers_are_sent(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        got = probes(fake)
        self.assertEqual(got["shares"]["count"], 2)
        self.assertEqual(got["tpm"]["spec"], "2.0")
        self.assertEqual([c[0] for c in fake.calls], ["shares", "tpm"], "one PowerShell for each")

    def test_a_probe_with_no_answer_leaves_its_key_out(self):
        got = probes(_FakeRun({"shares": "", "tpm": TPM_20}))
        self.assertEqual(sorted(got), ["tpm"])
        got = probes(_FakeRun({"shares": FILE_SERVER, "tpm": "{}"}))
        self.assertEqual(sorted(got), ["shares"])

    def test_a_probe_that_fails_sends_nothing_and_the_other_still_runs(self):
        got = probes(_FakeRun({"shares": FILE_SERVER, "tpm": TPM_20}, rc=1))
        self.assertEqual(got, {})
        got = probes(_FakeRun({"tpm": TPM_20}, raises={"shares": OSError("blocked")}))
        self.assertEqual(sorted(got), ["tpm"])
        got = probes(_FakeRun({"shares": FILE_SERVER}, raises={"tpm": subprocess.TimeoutExpired("powershell", 20)}))
        self.assertEqual(sorted(got), ["shares"])

    def test_a_probe_that_raises_does_not_end_the_others(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        with mock.patch.object(agent, "get_smb_shares", mock.Mock(side_effect=RuntimeError("boom"))):
            got = probes(fake)
        self.assertEqual(sorted(got), ["tpm"])
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        with mock.patch.object(agent, "get_tpm", mock.Mock(side_effect=RuntimeError("boom"))):
            got = probes(fake)
        self.assertEqual(sorted(got), ["shares"])

    def test_each_probe_is_given_a_timeout_that_is_at_most_twenty_seconds(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        probes(fake)
        self.assertEqual([c[1] for c in fake.calls], [20, 20])

    def test_the_second_probe_gets_what_is_left_of_the_budget(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20}, takes={"shares": 25.0})
        probes(fake)
        self.assertEqual([c[1] for c in fake.calls], [20, 15])

    def test_a_probe_that_would_get_less_than_three_seconds_is_not_started(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20}, takes={"shares": 38.5})
        got = probes(fake)
        self.assertEqual([c[0] for c in fake.calls], ["shares"])
        self.assertEqual(sorted(got), ["shares"])

    def test_the_budget_is_forty_seconds(self):
        self.assertEqual((agent.SLOW_PROBE_BUDGET_S, agent.SLOW_PROBE_EACH_S), (40, 20))
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        probes(fake, budget=0)
        self.assertEqual(fake.calls, [])

    def test_off_windows_nothing_runs(self):
        fake = _FakeRun({"shares": FILE_SERVER, "tpm": TPM_20})
        with mock.patch.object(agent.subprocess, "run", fake):
            self.assertEqual(agent.collect_slow_probes(), {})
        self.assertEqual(fake.calls, [])

    def test_the_sysinfo_carries_the_keys_that_were_answered(self):
        with mock.patch.object(agent, "collect_slow_probes", lambda: {"shares": {"count": 1, "admin_count": 0, "items": []}}):
            info = agent.collect_sysinfo()
        self.assertIn("shares", info)
        self.assertNotIn("tpm", info)
        with mock.patch.object(agent, "collect_slow_probes", lambda: (_ for _ in ()).throw(RuntimeError("boom"))):
            self.assertNotIn("shares", agent.collect_sysinfo())

    def test_the_sysinfo_of_a_host_that_answers_neither_has_neither(self):
        info = agent.collect_sysinfo()
        self.assertNotIn("shares", info)
        self.assertNotIn("tpm", info)


# ── the server ───────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheServerCleansTheShares(unittest.TestCase):
    def test_what_the_agent_sends_survives(self):
        sent = agent._parse_smb_shares(FILE_SERVER)
        self.assertEqual(wh.clean_shares(sent), sent)

    def test_an_administrative_name_that_a_host_lists_is_not_listed(self):
        got = wh.clean_shares({"count": 3, "admin_count": 1, "items": [
            {"name": "C$", "path": "C:\\"}, {"name": "Real", "path": "D:\\Real"}, {"name": "Hidden$", "path": ""}]})
        self.assertEqual([r["name"] for r in got["items"]], ["Real"])

    def test_the_list_is_cut_at_a_hundred(self):
        items = [{"name": f"s{i}", "path": "", "description": ""} for i in range(300)]
        got = wh.clean_shares({"count": 300, "admin_count": 3, "items": items})
        self.assertEqual((len(got["items"]), got["count"]), (100, 300))

    def test_the_count_is_never_below_what_is_listed_and_is_bounded(self):
        items = [{"name": f"s{i}"} for i in range(5)]
        self.assertEqual(wh.clean_shares({"count": 1, "items": items})["count"], 5)
        self.assertEqual(wh.clean_shares({"count": 10**12, "items": items})["count"], 5)
        self.assertEqual(wh.clean_shares({"count": -3, "items": items})["count"], 5)
        self.assertEqual(wh.clean_shares({"count": True, "items": []})["count"], 0)
        self.assertEqual(wh.clean_shares({"count": "7", "items": []})["count"], 0)
        self.assertEqual(wh.clean_shares({"count": 100000, "items": []})["count"], 100000)

    def test_the_administrative_count_is_bounded_too(self):
        for v, expect in ((4, 4), (-1, 0), (10**12, 0), (True, 0), ("3", 0), (None, 0), (100000, 100000)):
            self.assertEqual(wh.clean_shares({"count": 0, "admin_count": v, "items": []})["admin_count"], expect, v)

    def test_a_name_is_listed_once_whatever_its_case(self):
        got = wh.clean_shares({"items": [{"name": "Data"}, {"name": "DATA"}, {"name": "data", "path": "x"}]})
        self.assertEqual([r["name"] for r in got["items"]], ["Data"])

    def test_text_is_capped_and_cleaned(self):
        got = wh.clean_shares({"items": [{"name": "n" * 500, "path": "p\x00" + "q" * 500, "description": "d\r\nx\x1b[31m" + "e" * 500, "encrypted": True}]})
        item = got["items"][0]
        self.assertEqual((len(item["name"]), len(item["path"]), len(item["description"])), (80, 260, 200))
        self.assertNotRegex(json.dumps(item).replace("\\u0000", "NUL").replace("\\r", "CR").replace("\\n", "LF"), r"NUL|CR|LF|\\u001b")
        self.assertIs(item["encrypted"], True)

    def test_encrypted_is_kept_only_as_a_bool(self):
        got = wh.clean_shares({"items": [{"name": "a", "encrypted": "yes"}, {"name": "b", "encrypted": 1}, {"name": "c", "encrypted": False}]})
        self.assertEqual([r.get("encrypted", "absent") for r in got["items"]], ["absent", "absent", False])

    def test_rows_and_reports_of_the_wrong_kind(self):
        got = wh.clean_shares({"items": [5, None, "x", [], {"name": 5}, {"name": ""}, {"path": "no name"}, {"name": "Ok"}]})
        self.assertEqual([r["name"] for r in got["items"]], ["Ok"])
        self.assertEqual(wh.clean_shares({"items": "not a list", "count": 2})["items"], [])
        for raw in (None, "x", 5, [], [{"name": "a"}], {}, {"other": 1}):
            with self.subTest(raw=raw):
                self.assertIsNone(wh.clean_shares(raw))

    def test_the_number_of_shares_of_a_host(self):
        self.assertEqual(wh.shares_count({"shares": {"count": 3, "items": []}}), 3)
        self.assertEqual(wh.shares_count({"shares": {"count": 0}}), 0)
        for si in ({}, None, {"shares": None}, {"shares": {}}, {"shares": {"count": "3"}}, {"shares": {"count": True}}, {"shares": []}, "x"):
            self.assertIsNone(wh.shares_count(si), si)


class TestTheServerCleansTheTpm(unittest.TestCase):
    def test_what_the_agent_sends_survives(self):
        sent = agent._parse_tpm(TPM_20)
        self.assertEqual(wh.clean_tpm(sent), sent)

    def test_a_flag_is_kept_only_as_a_bool_and_the_specification_only_as_a_version(self):
        self.assertEqual(wh.clean_tpm({"present": "yes", "ready": 1, "enabled": None, "spec": "2.0 <b>"}), None)
        self.assertEqual(wh.clean_tpm({"present": False, "spec": "1.2"}), {"present": False, "spec": "1.2"})
        for spec in ("2.0.1", "x", "2.0, 0", "", None, 2.0, "<script>"):
            self.assertNotIn("spec", wh.clean_tpm({"present": True, "spec": spec}), spec)

    def test_a_report_that_is_not_one(self):
        for raw in (None, "x", 5, [], [{"present": True}], {}, {"other": True}):
            with self.subTest(raw=raw):
                self.assertIsNone(wh.clean_tpm(raw))

    def test_the_flags_are_tri_state(self):
        si = {"tpm": {"present": True, "ready": False}}
        self.assertEqual((wh.tpm_flag(si, "present"), wh.tpm_flag(si, "ready")), (True, False))
        self.assertIsNone(wh.tpm_flag({"tpm": {"present": True}}, "ready"))
        for si in ({}, None, {"tpm": None}, {"tpm": {}}, {"tpm": {"present": "True"}}, {"tpm": []}, "x"):
            self.assertIsNone(wh.tpm_flag(si, "present"), si)


# ── the whole way ────────────────────────────────────────────────────────────────────────────────────────────────────────
class _Fleet(unittest.TestCase):
    TOKEN = "token-shares-tpm"

    def setUp(self):
        now = int(time.time())

        def host(name, os_text):
            return {"name": name, "hostname": name, "os": os_text, "token": self.TOKEN, "last_seen": now, "enrolled": now, "tags": [],
                    "group": "", "sysinfo": {}, "agentless": False}

        api.save(api.DEVICES_FILE, {k: host(k + "-host", os_t) for k, os_t in (
            ("srv", "Windows 2022Server"), ("wks", "Windows 11"), ("old", "Windows 10"), ("quiet", "Windows 11"), ("lin", "Ubuntu 24.04"),
            ("half", "Windows 11"))})
        api._LOAD_CACHE.clear()
        self.beat("srv", {"shares": FILE_SERVER, "tpm": TPM_20})
        self.beat("wks", {"shares": WORKSTATION, "tpm": json.dumps({"present": True, "ready": False, "enabled": True, "spec": "2.0"})})
        self.beat("old", {"shares": WORKSTATION, "tpm": json.dumps({"present": False, "ready": False, "enabled": False})})
        self.beat("quiet", {})              # a Windows host whose probes could not answer
        self.beat("half", {"tpm": json.dumps({"present": True})})   # one whose TPM probe answered only that a TPM is there
        self.assertEqual(S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "cpu": "x"})[0], 200)

    def beat(self, dev, answers):
        """What the agent builds for a host whose probes answer `answers`, through the real handler."""
        fake = _FakeRun(answers)
        with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", fake):
            slow = agent.collect_slow_probes()
        info = agent.collect_sysinfo()
        info.update(slow)
        status, body = S.beat(api, dev, self.TOKEN, info)
        self.assertEqual(status, 200, body)

    def stored(self, dev):
        api._LOAD_CACHE.clear()
        return api.load(api.DEVICES_FILE)[dev].get("sysinfo") or {}


class TestTheHeartbeat(_Fleet):
    def test_the_shares_and_the_tpm_are_stored(self):
        si = self.stored("srv")
        self.assertEqual((si["shares"]["count"], si["shares"]["admin_count"]), (2, 4))
        self.assertEqual([r["name"] for r in si["shares"]["items"]], ["Data", "Public"])
        self.assertEqual(si["tpm"], {"present": True, "ready": True, "enabled": True, "spec": "2.0"})

    def test_a_host_whose_probes_could_not_answer_has_neither_and_is_not_read_as_having_none(self):
        si = self.stored("quiet")
        self.assertNotIn("shares", si)
        self.assertNotIn("tpm", si)

    def test_a_workstation_has_no_shares_of_its_own_and_three_administrative_ones(self):
        self.assertEqual(self.stored("wks")["shares"], {"count": 0, "admin_count": 3, "items": []})

    def test_what_a_host_makes_up_is_cleaned(self):
        S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "shares": {
            "count": 10**15, "admin_count": -4, "items": [{"name": "<img src=x onerror=alert(1)>", "path": "p" * 5000, "description": {"a": 1}, "x": 1}] * 400},
            "tpm": {"present": "True", "ready": False, "spec": "2.0; rm -rf /", "extra": "x" * 10000}})
        si = self.stored("lin")
        self.assertEqual(len(si["shares"]["items"]), 1, "the same name listed 400 times is one share")
        self.assertEqual((si["shares"]["admin_count"], si["shares"]["count"]), (0, 1))
        self.assertEqual(len(si["shares"]["items"][0]["path"]), 260)
        self.assertEqual(si["shares"]["items"][0]["description"], "")
        self.assertEqual(si["tpm"], {"ready": False})

    def test_a_report_of_the_wrong_kind_is_dropped_and_the_beat_is_taken(self):
        for raw in ("x", 5, [1], {}, None, {"count": "x", "items": "y"}):
            with self.subTest(raw=raw):
                self.assertEqual(S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "shares": raw, "tpm": raw})[0], 200)
                si = self.stored("lin")
                self.assertNotIn("tpm", si)
                if raw in ("x", 5, [1], {}, None):
                    self.assertNotIn("shares", si)

    def test_the_next_beat_replaces_them(self):
        self.beat("srv", {"shares": WORKSTATION, "tpm": json.dumps({"present": False})})
        si = self.stored("srv")
        self.assertEqual(si["shares"]["count"], 0)
        self.assertEqual(si["tpm"], {"present": False})
        self.beat("srv", {})
        self.assertNotIn("shares", self.stored("srv"))

    def test_the_hosts_list_leaves_the_shares_out_and_keeps_the_tpm(self):
        status, body = S.call(api, api.handle_devices_list)
        row = next(r for r in body if r["id"] == "srv")
        self.assertNotIn("shares", row["sysinfo"])
        self.assertEqual(row["sysinfo"]["tpm"]["spec"], "2.0")

    def test_the_drawer_reads_the_shares_from_the_hosts_own_sysinfo(self):
        status, body = S.call(api, api.handle_sysinfo, "srv")
        self.assertEqual(status, 200)
        self.assertEqual([r["name"] for r in body["sysinfo"]["shares"]["items"]], ["Data", "Public"])

    def test_a_read_only_user_reads_them_as_an_administrator_does(self):
        status, body = S.call(api, api.handle_sysinfo, "srv", role="viewer")
        self.assertEqual((status, body["sysinfo"]["shares"]["count"]), (200, 2))

    def test_a_tenant_administrator_of_another_tenant_gets_no_host_of_this_one(self):
        with mock.patch.object(api, "_tenant_gate", lambda: "other-tenant"):
            status, body = S.call(api, api.handle_devices_list)
        self.assertEqual(body, [])

    def test_there_is_no_alert_and_no_check_for_either(self):
        for name in api.EVENT_REGISTRY:
            self.assertNotRegex(name, r"share|tpm", name)
        dev = api.load(api.DEVICES_FILE)["old"]          # a host that reported no TPM
        rows = checks._host_checks("old", dev, now=int(time.time()))
        self.assertEqual([r["key"] for r in rows if re.search(r"share|tpm", r["key"])], [])


class TestTheQueries(_Fleet):
    def explorer(self):
        def handler():
            api.respond(200, api._qe_devices_rows())
        status, body = S.call(api, handler)
        self.assertEqual(status, 200)
        return {r["device_id"]: r for r in body}

    def test_the_data_explorer_fields(self):
        rows = self.explorer()
        self.assertEqual((rows["srv"]["shares_count"], rows["srv"]["tpm_present"], rows["srv"]["tpm_ready"]), (2, True, True))
        self.assertEqual((rows["wks"]["shares_count"], rows["wks"]["tpm_present"], rows["wks"]["tpm_ready"]), (0, True, False))
        self.assertEqual((rows["old"]["tpm_present"], rows["old"]["tpm_ready"]), (False, False))
        for name in ("shares_count", "tpm_present", "tpm_ready"):
            self.assertIn(name, api._QE_DEVICE_FIELDS)
            self.assertIsNone(rows["quiet"][name], f"{name}: a host that never said is not a host with none")
            self.assertIsNone(rows["lin"][name], name)

    def test_a_query_on_them(self):
        import query_engine
        rows = list(self.explorer().values())
        for pred, expect in (
            ({"field": "tpm_present", "op": "eq", "value": False}, ["old"]),
            ({"field": "tpm_ready", "op": "eq", "value": False}, ["old", "wks"]),     # half is not in it: it never said
            ({"field": "shares_count", "op": "gt", "value": 0}, ["srv"]),
            ({"and": [{"field": "tpm_present", "op": "eq", "value": True}, {"field": "tpm_ready", "op": "eq", "value": False}]}, ["wks"]),
            ({"not": {"field": "tpm_present", "op": "exists"}}, ["lin", "quiet"]),
            ({"field": "tpm_present", "op": "eq", "value": True}, ["half", "srv", "wks"]),
        ):
            with self.subTest(pred=pred):
                query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
                self.assertEqual(sorted(r["device_id"] for r in query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)), expect)

    def fleet(self, **params):
        status, body = S.call(api, api.handle_fleet_query, query="&".join(f"{k}={v}" for k, v in params.items()))
        self.assertEqual(status, 200)
        rows = body["devices"] if isinstance(body, dict) else body
        return sorted(r.get("id") or r.get("device_id") for r in rows)

    def test_the_fleet_query_asks_for_hosts_with_shares(self):
        self.assertEqual(self.fleet(shares_gt=0), ["srv"])
        self.assertEqual(self.fleet(shares_gt=1), ["srv"])
        self.assertEqual(self.fleet(shares_gt=2), [])
        self.assertEqual(self.fleet(shares_gt=-1), ["old", "srv", "wks"], "a host that reported none is matched by 'more than -1', one that never said is not")

    def test_the_fleet_query_asks_for_a_missing_tpm(self):
        self.assertEqual(self.fleet(tpm="missing"), ["old"])

    def test_the_fleet_query_asks_for_a_tpm_that_is_not_ready(self):
        self.assertEqual(self.fleet(tpm="notready"), ["wks"])

    def test_the_fleet_query_asks_for_a_tpm_that_is_there(self):
        self.assertEqual(self.fleet(tpm="present"), ["half", "srv", "wks"], "present is what the host said, and half said only that")

    def test_the_fleet_query_asks_for_a_tpm_that_is_ready(self):
        self.assertEqual(self.fleet(tpm="ready"), ["srv"], "wks says not ready, half never said, old has no TPM")

    def test_a_tpm_that_is_there_and_whose_readiness_was_not_answered_is_not_called_not_ready(self):
        self.assertNotIn("half", self.fleet(tpm="notready"))
        self.assertNotIn("half", self.fleet(tpm="missing"))

    def test_a_host_that_never_reported_is_matched_by_none(self):
        for params in ({"tpm": "missing"}, {"tpm": "notready"}, {"tpm": "present"}, {"tpm": "ready"}, {"shares_gt": 0}):
            self.assertNotIn("quiet", self.fleet(**params))
            self.assertNotIn("lin", self.fleet(**params))

    def test_a_criterion_it_does_not_know_filters_nothing(self):
        self.assertEqual(len(self.fleet(tpm="whatever")), 6)
        self.assertEqual(len(self.fleet(tpm="")), 6)
        self.assertEqual(len(self.fleet(shares_gt="x")), 6)

    def test_the_two_can_be_asked_together(self):
        self.assertEqual(self.fleet(tpm="notready", shares_gt=-1), ["wks"])
        self.assertEqual(self.fleet(tpm="present", shares_gt=0), ["srv"])
        self.assertEqual(self.fleet(tpm="ready", shares_gt=2), [])

    def test_the_saved_query_keeps_them_and_the_page_has_the_controls(self):
        for param in ("shares_gt", "tpm"):
            self.assertIn(param, api._FQ_PARAMS)
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        block = re.search(r"const _FQ_FIELDS = \{(.*?)\n\};", js, re.S).group(1)
        fields = dict(re.findall(r"(\w+):\s*'(fq-[\w-]+)'", block))
        self.assertEqual((fields.get("shares_gt"), fields.get("tpm")), ("fq-shares", "fq-tpm"))
        html = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
        for ident in ("fq-shares", "fq-tpm"):
            self.assertEqual(html.count(f'id="{ident}"'), 1)
        self.assertIn('<option value="missing">no TPM</option><option value="present">TPM present</option><option value="ready">TPM ready</option>'
                      '<option value="notready">not ready</option>', html)


# ── who may see them ─────────────────────────────────────────────────────────────────────────────────────────────────────
class TestWhoMaySeeThem(unittest.TestCase):
    """The shares and the TPM are read through routes that already scope their callers, and nothing here adds a route. With isolation on, a tenant
    administrator and a read-only user of one tenant must get the data of that tenant's hosts through the drawer's route, the roster, the Data
    Explorer and the Fleet Query, and none of another tenant's; the platform operator gets every tenant's."""

    STORES = ("CONFIG_FILE", "USERS_FILE", "TENANTS_FILE", "DEVICES_FILE")

    def setUp(self):
        self._saved = {n: api.load(getattr(api, n)) for n in self.STORES}
        now = int(time.time())

        def win(tenant, shares, tpm):
            slow = {"shares": shares, "tpm": tpm}
            fake = _FakeRun(slow)
            with mock.patch.object(agent.sys, "platform", "win32"), mock.patch.object(agent.subprocess, "run", fake):
                got = agent.collect_slow_probes()
            return {"name": f"win-{tenant}", "hostname": f"win-{tenant}", "os": "Windows 11", "token": "t", "last_seen": now, "enrolled": now,
                    "tags": [], "group": "", "agentless": False, "tenant": tenant,
                    "sysinfo": {"shares": wh.clean_shares(got["shares"]), "tpm": wh.clean_tpm(got["tpm"])}}

        api.save(api.TENANTS_FILE, {"default": {"name": "Default", "status": "active", "builtin": True},
                                    "tenantB": {"name": "B", "status": "active"}, "tenantC": {"name": "C", "status": "active"}})
        api.save(api.USERS_FILE, {"platform": {"role": "admin", "tenant_id": "default"},
                                  "badmin": {"role": "admin", "tenant_id": "tenantB"},
                                  "bview": {"role": "viewer", "tenant_id": "tenantB"},
                                  "dview": {"role": "viewer", "tenant_id": "default"}})
        api.save(api.DEVICES_FILE, {"winB": win("tenantB", FILE_SERVER, TPM_20),
                                    "winC": win("tenantC", FILE_SERVER, json.dumps({"present": False}))})
        cfg = dict(self._saved["CONFIG_FILE"] or {}, tenancy_enforced=True)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            api.save(getattr(api, n), v)
        api._LOAD_CACHE.clear()

    def explorer_ids(self, user, role):
        def handler():
            api.respond(200, api._qe_devices_rows())
        status, body = S.call(api, handler, user=user, role=role)
        self.assertEqual(status, 200)
        return sorted(r["device_id"] for r in body)

    def fleet_ids(self, user, role, **params):
        status, body = S.call(api, api.handle_fleet_query, user=user, role=role, query="&".join(f"{k}={v}" for k, v in params.items()))
        self.assertEqual(status, 200)
        rows = body["devices"] if isinstance(body, dict) else body
        return sorted(r.get("id") or r.get("device_id") for r in rows)

    def gate(self, path, user, role):
        """main()'s check that a request for /api/devices/<id>/... may reach the host: (status, body) of the refusal, or (None, None) when it let
        the request through."""
        saved = {n: getattr(api, n) for n in ("verify_token", "respond")}
        box = {}

        def respond(status, data=None):
            box["answer"] = (status, data)
            raise api.HTTPError(status, data)

        api.verify_token = lambda token=None: (user, role)
        api.respond = respond
        api._RCTX.environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "HTTP_X_TOKEN": "t"}
        try:
            try:
                api._enforce_device_scope()
            except api.HTTPError:
                pass
        finally:
            api._RCTX.environ = None
            for n, v in saved.items():
                setattr(api, n, v)
        return box.get("answer", (None, None))

    def test_control_the_platform_operator_sees_both_tenants_with_the_new_fields(self):
        self.assertEqual(self.explorer_ids("platform", "admin"), ["winB", "winC"])
        self.assertEqual(self.fleet_ids("platform", "admin", shares_gt=0), ["winB", "winC"])
        self.assertEqual(self.fleet_ids("platform", "admin", tpm="missing"), ["winC"])

    def test_a_tenant_administrator_gets_the_hosts_of_their_own_tenant_only(self):
        self.assertEqual(self.explorer_ids("badmin", "admin"), ["winB"])
        self.assertEqual(self.fleet_ids("badmin", "admin", shares_gt=0), ["winB"])
        self.assertEqual(self.fleet_ids("badmin", "admin", tpm="present"), ["winB"])
        self.assertEqual(self.fleet_ids("badmin", "admin", tpm="missing"), [], "winC has no TPM, and it is not theirs")
        status, rows = S.call(api, api.handle_devices_list, user="badmin", role="admin")
        self.assertEqual([r["id"] for r in rows], ["winB"])
        self.assertNotIn("shares", rows[0]["sysinfo"])

    def test_a_read_only_user_gets_the_hosts_of_their_tenant_only(self):
        self.assertEqual(self.explorer_ids("bview", "viewer"), ["winB"])
        self.assertEqual(self.fleet_ids("bview", "viewer", shares_gt=0), ["winB"])
        self.assertEqual(self.fleet_ids("bview", "viewer", tpm="missing"), [])
        status, body = S.call(api, api.handle_sysinfo, "winB", user="bview", role="viewer")
        self.assertEqual((status, body["sysinfo"]["shares"]["count"], body["sysinfo"]["tpm"]["spec"]), (200, 2, "2.0"))

    def test_a_user_of_the_default_tenant_is_not_the_platform_operator(self):
        self.assertEqual(self.explorer_ids("dview", "viewer"), [])
        self.assertEqual(self.fleet_ids("dview", "viewer", shares_gt=-1), [])

    def test_the_drawers_route_refuses_another_tenants_host_before_it_reaches_the_handler(self):
        for user, role in (("badmin", "admin"), ("bview", "viewer")):
            with self.subTest(user=user):
                status, body = self.gate("/api/devices/winC/sysinfo", user, role)
                self.assertEqual(status, 403)
                self.assertIn("another tenant", body["error"])
                self.assertEqual(self.gate("/api/devices/winB/sysinfo", user, role), (None, None))
        self.assertEqual(self.gate("/api/devices/winC/sysinfo", "platform", "admin"), (None, None))


# ── a store with a wrong value in each of the fields of this territory ──────────────────────────────────────────────────
class TestAStoreThatHoldsTheWrongKindOfValue(unittest.TestCase):
    """devices.json can be edited by hand or restored from a backup, so a field of this territory may hold any kind of value. The shape
    registry repairs what it lists (store_shapes.py) and the readers take the rest: no page that reads a host answers 500."""

    HOSTILE = {
        "wu_search": [
            "x", 5, [], {"at": "1700000000", "ok": True, "ok_at": [], "fail_since": {}}, {"ok": False, "at": 10**30, "ok_at": 10**30},
            {"ok": "yes"}, {"at": None, "ok": False, "error_class": ["x"]}],
        "win_build": ["x", 5, [], {"build": 22631, "ubr": "3593"}, {"build": "22631", "ubr": [1], "product": {"a": 1}}, {"ubr": 10**30}],
        "shares": ["x", 5, [], {"count": "3", "admin_count": "x", "items": "not a list"}, {"items": [5, None, {"name": 5}, {"path": "x"}]},
                   {"count": 10**30, "items": [{"name": "ok", "path": 5, "description": [1], "encrypted": "yes"}]}],
        "tpm": ["x", 5, [], {"present": "True", "ready": 1}, {"spec": [2.0]}, {"present": True, "spec": 2.0}],
        "packages": ["x", [], {"manager": "windows-update", "upgradable": 3, "definition_updates": "2"},
                     {"manager": "windows-update", "upgradable": 3, "upgradable_names": "not a list", "definition_updates": [2]}],
    }

    def hosts(self):
        now = int(time.time())
        hosts = {}
        for field, values in self.HOSTILE.items():
            for i, value in enumerate(values):
                hid = f"hostile-{field}-{i}"
                hosts[hid] = {"name": hid, "hostname": hid, "os": "Windows 11", "token": "t", "last_seen": now, "enrolled": now, "tags": [],
                              "group": "", "agentless": False, "sysinfo": {field: value}}
        return hosts

    def setUp(self):
        api.save(api.DEVICES_FILE, self.hosts())
        api._LOAD_CACHE.clear()

    def test_the_pages_that_read_a_host_answer_for_every_one(self):
        for hid in self.hosts():
            for name, handler, args in (("sysinfo", api.handle_sysinfo, (hid,)), ("checks", api.handle_device_checks, (hid,)),
                                        ("patch report", api.handle_patch_report_device, (hid,))):
                with self.subTest(host=hid, page=name):
                    status, _body = S.call(api, handler, *args)
                    self.assertEqual(status, 200)

    def test_the_lists_and_the_queries_answer(self):
        def explorer():
            api.respond(200, api._qe_devices_rows())

        for name, handler, kw in (("hosts list", api.handle_devices_list, {}), ("data explorer", explorer, {}),
                                  ("fleet query", api.handle_fleet_query, {"query": "shares_gt=0&tpm=missing&win_build=x&pending_gt=0"}),
                                  ("fleet query 2", api.handle_fleet_query, {"query": "tpm=notready"}), ("patch report", api.handle_patch_report, {})):
            with self.subTest(page=name):
                status, _body = S.call(api, handler, **kw)
                self.assertEqual(status, 200)

    def test_the_registry_repairs_the_fields_it_lists(self):
        import store_shapes
        fixed = store_shapes.normalize("devices.json", {"h": {"name": "h", "sysinfo": {
            "wu_search": {"at": "1700000000", "ok": True}, "shares": {"count": "3", "items": "x"}, "tpm": "x"}}})["h"]["sysinfo"]
        self.assertEqual(fixed["wu_search"]["at"], 1700000000)
        self.assertEqual((fixed["shares"]["count"], fixed["shares"]["items"]), (3, []))
        self.assertEqual(fixed["tpm"], {})
        # a row of the list that is not a share is left out, so the drawer never meets a null where it reads a name
        fixed = store_shapes.normalize("devices.json", {"h": {"name": "h", "sysinfo": {
            "shares": {"count": 1, "items": [5, None, {"path": "x"}, {"name": "ok", "path": "p"}]}}}})["h"]["sysinfo"]
        self.assertEqual(fixed["shares"]["items"], [{"name": "ok", "path": "p"}])


if __name__ == "__main__":
    unittest.main()
