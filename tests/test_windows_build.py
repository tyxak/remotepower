#!/usr/bin/env python3
"""The build of a Windows host: number, revision, display version, edition and product, and what the server makes of them.

The agent read the system with platform.win32_ver(), which says "10" for Windows 11 on some Pythons and knows nothing of the revision (the number
after the build that changes with every cumulative update). It now reads HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, read only, and sends
{build, ubr, display_version, edition, product} with the system information. The server shows "Windows 11 Pro 23H2 (build 22631.3593)" in the host
drawer and in the Hosts list, and the Data Explorer and the Fleet Query can ask for it.

The family of a client system comes from its build number (22000 and up is Windows 11), because ProductName still says "Windows 10" on many builds of
Windows 11. A server keeps the name of its product, because a server and a client share build numbers: Windows Server 2025 and Windows 11 24H2 are both
26100.

The agent could not run on Windows here. The registry is replaced by a stand-in that behaves as the real module does, with the values a real host
writes under that key, and the agent's own functions run on it; what it builds goes through the real heartbeat handler.

No check of the server reads the version of Windows (the end-of-life table holds Linux distributions only), so none was changed: a test says so.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="rp-winbuild-")
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

agent = S.load_agent("rp_winbuild_agent")


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


# What real hosts write under the key. The label is what the server is expected to print for each.
HOSTS = {
    "w11-23h2-pro": (S.nt_values(), "Windows 11 Pro 23H2 (build 22631.3593)"),
    "w10-22h2-pro": (S.nt_values(CurrentBuildNumber=("19045", S.SZ), CurrentBuild=("19045", S.SZ), UBR=(4291, S.DWORD),
                                 DisplayVersion=("22H2", S.SZ), ProductName=("Windows 10 Pro", S.SZ)),
                     "Windows 10 Pro 22H2 (build 19045.4291)"),
    # before 20H2 there is no DisplayVersion, and ReleaseId is the version
    "w10-1909-enterprise": (S.nt_values(CurrentBuildNumber=("18363", S.SZ), CurrentBuild=("18363", S.SZ), UBR=(2274, S.DWORD),
                                        DisplayVersion=None, ReleaseId=("1909", S.SZ), ProductName=("Windows 10 Enterprise", S.SZ),
                                        EditionID=("Enterprise", S.SZ)),
                            "Windows 10 Enterprise 1909 (build 18363.2274)"),
    # Windows 11 Home, whose ProductName still says Windows 10
    "w11-24h2-home": (S.nt_values(CurrentBuildNumber=("26100", S.SZ), CurrentBuild=("26100", S.SZ), UBR=(2605, S.DWORD),
                                  DisplayVersion=("24H2", S.SZ), ProductName=("Windows 10 Home", S.SZ), EditionID=("Core", S.SZ)),
                      "Windows 11 Home 24H2 (build 26100.2605)"),
    "server-2022": (S.nt_values(CurrentBuildNumber=("20348", S.SZ), CurrentBuild=("20348", S.SZ), UBR=(2402, S.DWORD),
                                DisplayVersion=("21H2", S.SZ), ProductName=("Windows Server 2022 Datacenter", S.SZ),
                                EditionID=("ServerDatacenter", S.SZ), InstallationType=("Server", S.SZ)),
                    "Windows Server 2022 Datacenter 21H2 (build 20348.2402)"),
    # the same build number as Windows 11 24H2: a server is not a Windows 11
    "server-2025": (S.nt_values(CurrentBuildNumber=("26100", S.SZ), CurrentBuild=("26100", S.SZ), UBR=(2605, S.DWORD),
                                DisplayVersion=("24H2", S.SZ), ProductName=("Windows Server 2025 Standard", S.SZ),
                                EditionID=("ServerStandard", S.SZ), InstallationType=("Server", S.SZ)),
                    "Windows Server 2025 Standard 24H2 (build 26100.2605)"),
    "server-2016": (S.nt_values(CurrentBuildNumber=("14393", S.SZ), CurrentBuild=("14393", S.SZ), UBR=(7159, S.DWORD),
                                DisplayVersion=None, ReleaseId=("1607", S.SZ), ProductName=("Windows Server 2016 Standard", S.SZ),
                                EditionID=("ServerStandard", S.SZ)),
                    "Windows Server 2016 Standard 1607 (build 14393.7159)"),
    "w81-pro": (S.nt_values(CurrentBuildNumber=("9600", S.SZ), CurrentBuild=("9600", S.SZ), UBR=(20778, S.DWORD), DisplayVersion=None,
                            ReleaseId=None, ProductName=("Windows 8.1 Pro", S.SZ), EditionID=("Professional", S.SZ)),
                "Windows 8.1 Pro (build 9600.20778)"),
    "w7-professional": (S.nt_values(CurrentBuildNumber=("7601", S.SZ), CurrentBuild=("7601", S.SZ), UBR=None, DisplayVersion=None,
                                    ReleaseId=None, ProductName=("Windows 7 Professional", S.SZ), EditionID=("Professional", S.SZ)),
                        "Windows 7 Professional (build 7601)"),
}


def read_build(values, **fake_kw):
    """What the agent's own function makes of a registry that holds `values`."""
    fake = S.FakeWinreg({S.NT_KEY: values})
    with mock.patch.dict(sys.modules, {"winreg": fake}):
        got = agent.get_win_build()
    assert fake.reached_for == [], f"the agent reached for {fake.reached_for}"
    assert not fake.wrote, "a key was opened with a right that writes"
    assert fake.leaked == [], f"a key was left open: {fake.leaked}"
    return got


class TestTheAgentReadsTheRegistry(unittest.TestCase):
    def test_a_windows_11_host(self):
        self.assertEqual(read_build(S.nt_values()), {
            "build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "Professional", "product": "Windows 10 Pro"})

    def test_the_revision_is_a_whole_number_and_the_rest_are_text(self):
        got = read_build(S.nt_values())
        self.assertIs(type(got["ubr"]), int)
        for key in ("build", "display_version", "edition", "product"):
            self.assertIsInstance(got[key], str)

    def test_a_build_from_before_20h2_gives_the_release_id(self):
        got = read_build(HOSTS["w10-1909-enterprise"][0])
        self.assertEqual(got["display_version"], "1909")

    def test_display_version_wins_over_the_release_id(self):
        self.assertEqual(read_build(S.nt_values())["display_version"], "23H2")      # ReleaseId is "2009" in the same key

    def test_a_missing_revision_or_version_is_left_out(self):
        got = read_build(HOSTS["w7-professional"][0])
        self.assertEqual(got, {"build": "7601", "edition": "Professional", "product": "Windows 7 Professional"})

    def test_current_build_stands_in_for_the_build_number(self):
        got = read_build(S.nt_values(CurrentBuildNumber=None))
        self.assertEqual(got["build"], "22631")

    def test_no_build_is_nothing_to_say(self):
        for values in (S.nt_values(CurrentBuildNumber=None, CurrentBuild=None), S.nt_values(CurrentBuildNumber=("", S.SZ), CurrentBuild=None),
                       S.nt_values(CurrentBuildNumber=("x22631", S.SZ), CurrentBuild=None),
                       S.nt_values(CurrentBuildNumber=(22631, S.DWORD), CurrentBuild=None), {}):
            with self.subTest(values=values):
                self.assertEqual(read_build(values), {})

    def test_text_is_capped_and_a_revision_that_is_not_a_number_is_dropped(self):
        got = read_build(S.nt_values(ProductName=("P" * 500, S.SZ), EditionID=("E" * 500, S.SZ), DisplayVersion=("V" * 500, S.SZ),
                                     CurrentBuildNumber=("9" * 50, S.SZ)))
        self.assertEqual((len(got["product"]), len(got["edition"]), len(got["display_version"]), len(got["build"])), (80, 40, 16, 8))
        for ubr in (-1, 10**7, True, b"\x01\x02", "abc", None):
            with self.subTest(ubr=ubr):
                self.assertNotIn("ubr", read_build(S.nt_values(UBR=None if ubr is None else (ubr, S.DWORD))))
        self.assertEqual(read_build(S.nt_values(UBR=("3593", S.SZ)))["ubr"], 3593)

    def test_a_value_that_is_not_text_is_left_out(self):
        got = read_build(S.nt_values(ProductName=(b"\x00\x01", 3), EditionID=(5, S.DWORD)))
        self.assertNotIn("product", got)
        self.assertNotIn("edition", got)

    def test_the_key_is_read_in_the_64_bit_view_and_nothing_is_written(self):
        fake = S.FakeWinreg({S.NT_KEY: S.nt_values()})
        with mock.patch.dict(sys.modules, {"winreg": fake}):
            agent.get_win_build()
        self.assertTrue(all(a & fake.KEY_WOW64_64KEY for a in fake.access), fake.access)
        self.assertFalse(fake.wrote)
        self.assertEqual([r for r in fake.reads if r[1] == "UBR"], [(S.NT_KEY.lower(), "UBR")])

    def test_a_key_that_is_not_there_or_a_host_with_no_registry_says_nothing(self):
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg({r"SOFTWARE\Other": {}})}):
            self.assertEqual(agent.get_win_build(), {})
        with mock.patch.dict(sys.modules, {"winreg": None}):
            self.assertEqual(agent.get_win_build(), {})

    def test_the_sysinfo_carries_it(self):
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg({S.NT_KEY: S.nt_values()})}):
            info = agent.collect_sysinfo()
        self.assertEqual(info["win_build"]["build"], "22631")
        json.dumps(info)

    def test_off_windows_it_carries_nothing(self):
        self.assertNotIn("win_build", agent.collect_sysinfo())


class TestTheFamilyTheAgentNames(unittest.TestCase):
    def os_info(self, release, version):
        with mock.patch("platform.win32_ver", return_value=(release, version, "", "Multiprocessor Free")):
            return agent.get_os_info()

    def test_windows_11_is_named_from_its_build_number(self):
        self.assertEqual(self.os_info("10", "10.0.22631"), "Windows 11 (Build 22631)")
        self.assertEqual(self.os_info("10", "10.0.26100"), "Windows 11 (Build 26100)")

    def test_the_boundary_is_22000(self):
        self.assertEqual(self.os_info("10", "10.0.21999"), "Windows 10 (Build 21999)")
        self.assertEqual(self.os_info("10", "10.0.22000"), "Windows 11 (Build 22000)")

    def test_windows_10_stays_windows_10(self):
        self.assertEqual(self.os_info("10", "10.0.19045"), "Windows 10 (Build 19045)")

    def test_a_python_that_already_says_11_is_not_changed(self):
        self.assertEqual(self.os_info("11", "10.0.22631"), "Windows 11 (Build 22631)")

    def test_a_server_is_not_renamed(self):
        self.assertEqual(self.os_info("2022Server", "10.0.20348"), "Windows 2022Server (Build 20348)")
        self.assertEqual(self.os_info("2016Server", "10.0.26100"), "Windows 2016Server (Build 26100)")

    def test_a_version_that_is_not_a_number_is_left_as_it_is(self):
        self.assertEqual(self.os_info("10", "10.0.abc"), "Windows 10 (Build abc)")


class TestTheServerCleansIt(unittest.TestCase):
    def test_what_the_agent_sends_survives(self):
        got = read_build(S.nt_values())
        self.assertEqual(wh.clean_win_build(got), got)

    def test_a_field_that_is_not_what_it_should_be_is_left_out(self):
        got = wh.clean_win_build({"build": "22631", "ubr": "3593", "display_version": "<b>23H2</b>", "edition": ["x"], "product": 5})
        self.assertEqual(got, {"build": "22631"})

    def test_the_build_is_digits(self):
        for build in ("", "12", "1234567", "2263a", "22631.3593", "22 631", None, 22631, ["22631"]):
            with self.subTest(build=build):
                self.assertNotIn("build", wh.clean_win_build({"build": build, "ubr": 1}) or {})

    def test_the_build_is_trimmed_before_it_is_read(self):
        self.assertEqual(wh.clean_win_build({"build": " 22631\n"}), {"build": "22631"})

    def test_the_revision_is_a_whole_number_inside_a_bound(self):
        for ubr, ok in ((0, True), (3593, True), (999999, True), (1000000, False), (-1, False), (True, False), (1.5, False), ("3", False)):
            with self.subTest(ubr=ubr):
                got = wh.clean_win_build({"build": "22631", "ubr": ubr})
                self.assertEqual("ubr" in got, ok)

    def test_text_is_capped_and_stripped_of_control_characters(self):
        got = wh.clean_win_build({"build": "22631", "product": "Windows\x00 10\r\nPro" + "x" * 200, "edition": "Pro\x1b[31m"})
        self.assertEqual(len(got["product"]), 80)
        self.assertNotRegex(got["product"] + got["edition"], r"[\x00-\x1f\x7f]")

    def test_the_display_version_is_a_short_word(self):
        for dv, ok in (("23H2", True), ("1909", True), ("22H2", True), ("Dev", True), ("<script>", False), ("", False), ("-x", False)):
            with self.subTest(dv=dv):
                self.assertEqual("display_version" in wh.clean_win_build({"build": "22631", "display_version": dv}), ok)
        self.assertEqual(wh.clean_win_build({"build": "22631", "display_version": "a" * 40})["display_version"], "a" * 16)

    def test_nothing_left_is_none(self):
        for raw in (None, [], "x", {}, {"ubr": "x"}, {"product": ""}, 5):
            with self.subTest(raw=raw):
                self.assertIsNone(wh.clean_win_build(raw))


class TestTheLabel(unittest.TestCase):
    def test_the_label_of_each_real_host(self):
        for name, (values, expect) in HOSTS.items():
            with self.subTest(host=name):
                built = wh.clean_win_build(read_build(values))
                self.assertEqual(wh.os_label(built), expect)

    def test_the_example_of_the_brief(self):
        self.assertEqual(wh.os_label({"build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "Professional",
                                      "product": "Windows 10 Pro"}), "Windows 11 Pro 23H2 (build 22631.3593)")

    def test_windows_11_is_not_called_windows_10_because_the_product_name_says_so(self):
        label = wh.os_label({"build": "22631", "product": "Windows 10 Pro"})
        self.assertTrue(label.startswith("Windows 11 Pro"), label)
        self.assertNotIn("Windows 10", label)

    def test_the_boundary_is_22000(self):
        self.assertEqual(wh.win_family({"build": "21999", "product": "Windows 10 Pro"}), "Windows 10")
        self.assertEqual(wh.win_family({"build": "22000", "product": "Windows 10 Pro"}), "Windows 11")
        self.assertEqual(wh.win_family({"build": "10240", "product": "Windows 10 Pro"}), "Windows 10")
        self.assertEqual(wh.win_family({"build": "9600", "product": "Windows 8.1 Pro"}), "Windows 8.1")

    def test_a_server_with_the_build_of_windows_11_is_a_server(self):
        self.assertEqual(wh.win_family({"build": "26100", "product": "Windows Server 2025 Standard", "edition": "ServerStandard"}),
                         "Windows Server 2025 Standard")
        self.assertEqual(wh.win_family({"build": "26100", "edition": "ServerDatacenter"}), "")
        self.assertNotIn("Windows 11", wh.os_label({"build": "26100", "product": "Windows Server 2025 Standard"}))

    def test_the_edition_comes_from_edition_id_when_there_is_no_product_name(self):
        for edition, expect in (("Professional", "Pro"), ("Core", "Home"), ("CoreSingleLanguage", "Home Single Language"),
                                ("Enterprise", "Enterprise"), ("Education", "Education"), ("Unheard", "Unheard")):
            with self.subTest(edition=edition):
                label = wh.os_label({"build": "22631", "edition": edition, "display_version": "23H2", "ubr": 1})
                self.assertEqual(label, f"Windows 11 {expect} 23H2 (build 22631.1)")

    def test_what_is_missing_is_left_out_of_the_label(self):
        self.assertEqual(wh.os_label({"build": "22631"}), "Windows 11 (build 22631)")
        self.assertEqual(wh.os_label({"build": "22631", "ubr": 0}), "Windows 11 (build 22631.0)")
        self.assertEqual(wh.os_label({"build": "22631", "display_version": "23H2"}), "Windows 11 23H2 (build 22631)")

    def test_no_build_no_label(self):
        for raw in (None, {}, {"product": "Windows 10 Pro"}, "x", [], {"build": ""}):
            self.assertEqual(wh.os_label(raw), "", raw)

    def test_a_build_below_the_table_names_its_family_from_the_product(self):
        self.assertEqual(wh.os_label({"build": "6002", "product": "Windows Vista (TM) Business"}),
                         "Windows Vista (TM) Business (build 6002)")

    def test_a_product_name_the_table_does_not_know_names_itself(self):
        self.assertEqual(wh.os_label({"build": "7601", "product": "Windows Embedded Standard 7", "ubr": 5}),
                         "Windows Embedded Standard 7 (build 7601.5)")

    def test_the_data_explorer_fields(self):
        self.assertEqual(wh.build_fields({"win_build": {"build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "Professional",
                                                        "product": "Windows 10 Pro"}}),
                         {"win_build": "22631", "win_ubr": 3593, "win_display_version": "23H2", "win_edition": "Professional",
                          "win_product": "Windows 10 Pro", "win_family": "Windows 11"})
        for si in ({}, None, {"win_build": None}, {"win_build": "x"}, {"win_build": {}}):
            self.assertEqual(set(wh.build_fields(si).values()), {None}, si)


# ── the whole way ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class _Fleet(unittest.TestCase):
    TOKEN = "token-winbuild"

    def setUp(self):
        now = int(time.time())

        def host(name, os_text, **extra):
            return dict({"name": name, "hostname": name, "os": os_text, "token": self.TOKEN, "last_seen": now, "enrolled": now, "tags": [],
                         "group": "", "sysinfo": {}, "agentless": False}, **extra)

        api.save(api.DEVICES_FILE, {
            "w11": host("w11-host", "Windows 10 (Build 22631)"),
            "w10": host("w10-host", "Windows 10 (Build 19045)"),
            "srv": host("srv-host", "Windows 2025Server (Build 26100)"),
            "lin": host("lin-host", "Ubuntu 24.04"),
            "other": host("other-host", "Windows 11 (Build 22631)", tenant="t2"),
        })
        api._LOAD_CACHE.clear()
        for dev, (values, _label) in (("w11", HOSTS["w11-23h2-pro"]), ("w10", HOSTS["w10-22h2-pro"]), ("srv", HOSTS["server-2025"]),
                                      ("other", HOSTS["w11-23h2-pro"])):
            self.beat(dev, values)
        self.assertEqual(S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "cpu": "x"})[0], 200)

    def beat(self, dev, values):
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg({S.NT_KEY: values})}):
            info = agent.collect_sysinfo()
        status, body = S.beat(api, dev, self.TOKEN, info)
        self.assertEqual(status, 200, body)

    def stored(self, dev):
        api._LOAD_CACHE.clear()
        return api.load(api.DEVICES_FILE)[dev].get("sysinfo") or {}


class TestTheHeartbeat(_Fleet):
    def test_the_build_is_stored(self):
        self.assertEqual(self.stored("w11")["win_build"], {
            "build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "Professional", "product": "Windows 10 Pro"})

    def test_a_linux_host_has_none(self):
        self.assertNotIn("win_build", self.stored("lin"))

    def test_a_build_a_host_makes_up_is_cleaned(self):
        S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "win_build": {
            "build": "22631", "ubr": 3593, "product": "<img src=x onerror=alert(1)>" + "x" * 500, "edition": "E\x00", "extra": "x" * 10000}})
        wb = self.stored("lin")["win_build"]
        self.assertEqual(sorted(wb), ["build", "edition", "product", "ubr"])
        self.assertEqual(len(wb["product"]), 80)
        self.assertNotIn("\x00", wb["edition"])

    def test_a_build_of_the_wrong_kind_is_dropped_and_the_beat_is_taken(self):
        for raw in ("x", 5, [1], {"build": "x"}, None):
            with self.subTest(raw=raw):
                self.assertEqual(S.beat(api, "lin", self.TOKEN, {"hostname": "lin-host", "win_build": raw})[0], 200)
                self.assertNotIn("win_build", self.stored("lin"))

    def test_the_build_is_replaced_by_the_next_beat(self):
        self.beat("w11", HOSTS["w11-24h2-home"][0])
        self.assertEqual(self.stored("w11")["win_build"]["ubr"], 2605)


class TestTheHostsList(_Fleet):
    def rows(self, role="admin"):
        status, body = S.call(api, api.handle_devices_list, role=role)
        self.assertEqual(status, 200)
        return {r["id"]: r for r in body}

    def test_a_windows_host_that_reported_its_build_has_the_label(self):
        rows = self.rows()
        self.assertEqual(rows["w11"]["os_detail"], "Windows 11 Pro 23H2 (build 22631.3593)")
        self.assertEqual(rows["w10"]["os_detail"], "Windows 10 Pro 22H2 (build 19045.4291)")
        self.assertEqual(rows["srv"]["os_detail"], "Windows Server 2025 Standard 24H2 (build 26100.2605)")

    def test_the_text_the_agent_sends_stays_where_it_was(self):
        self.assertEqual(self.rows()["w11"]["os"], "Windows 10 (Build 22631)")

    def test_a_host_that_did_not_report_a_build_has_no_label(self):
        self.assertNotIn("os_detail", self.rows()["lin"])

    def test_a_read_only_user_reads_it_the_same(self):
        self.assertEqual(self.rows("viewer")["w11"]["os_detail"], "Windows 11 Pro 23H2 (build 22631.3593)")

    def test_a_tenant_administrator_reads_the_hosts_of_the_tenant_and_no_other(self):
        with mock.patch.object(api, "_tenant_gate", lambda: "t2"):
            rows = self.rows()
        self.assertEqual(sorted(rows), ["other"])
        self.assertEqual(rows["other"]["os_detail"], "Windows 11 Pro 23H2 (build 22631.3593)")
        with mock.patch.object(api, "_tenant_gate", lambda: "t1"):
            self.assertEqual(self.rows(), {})

    def test_the_slim_list_does_not_compute_it(self):
        status, body = S.call(api, api.handle_devices_list, query="slim=1")
        self.assertTrue(all("os_detail" not in r for r in body))


class TestTheQueries(_Fleet):
    def explorer_rows(self):
        out = {}

        def handler():
            api.respond(200, api._qe_devices_rows())

        status, body = S.call(api, handler)
        self.assertEqual(status, 200)
        for r in body:
            out[r["device_id"]] = r
        return out

    def test_the_data_explorer_has_the_six_fields(self):
        rows = self.explorer_rows()
        w11 = rows["w11"]
        self.assertEqual((w11["win_build"], w11["win_ubr"], w11["win_display_version"], w11["win_edition"], w11["win_product"], w11["win_family"]),
                         ("22631", 3593, "23H2", "Professional", "Windows 10 Pro", "Windows 11"))
        self.assertEqual(rows["srv"]["win_family"], "Windows Server 2025 Standard")
        self.assertEqual(rows["w10"]["win_family"], "Windows 10")
        for name in ("win_build", "win_ubr", "win_display_version", "win_edition", "win_product", "win_family"):
            self.assertIn(name, api._QE_DEVICE_FIELDS)
            self.assertIsNone(rows["lin"][name], name)

    def test_the_question_which_hosts_are_still_on_windows_10_is_answered_by_the_build_not_the_product_name(self):
        rows = self.explorer_rows()
        by_product = sorted(d for d, r in rows.items() if (r["win_product"] or "").startswith("Windows 10"))
        by_family = sorted(d for d, r in rows.items() if r["win_family"] == "Windows 10")
        self.assertEqual(by_product, ["other", "w10", "w11"], "the product name of a Windows 11 host says Windows 10")
        self.assertEqual(by_family, ["w10"])

    def test_the_data_explorer_runs_a_query_on_them(self):
        import query_engine
        rows = list(self.explorer_rows().values())
        pred = {"and": [{"field": "win_family", "op": "eq", "value": "Windows 11"}, {"field": "win_ubr", "op": "lt", "value": 4000}]}
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        got = [r["device_id"] for r in query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)]
        self.assertEqual(sorted(got), ["other", "w11"])

    def fleet(self, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        status, body = S.call(api, api.handle_fleet_query, query=query)
        self.assertEqual(status, 200)
        rows = body["devices"] if isinstance(body, dict) else body
        return sorted(r.get("id") or r.get("device_id") for r in rows)

    def test_the_fleet_query_matches_a_part_of_the_label(self):
        for text, expect in (("23H2", ["other", "w11"]), ("22631", ["other", "w11"]), ("22631.3593", ["other", "w11"]),
                             ("windows 11", ["other", "w11"]), ("Windows 10", ["w10"]), ("pro", ["other", "w10", "w11"]),
                             ("server 2025", ["srv"]), ("24H2", ["srv"]), ("nothing like this", [])):
            with self.subTest(text=text):
                self.assertEqual(self.fleet(win_build=text), expect)

    def test_the_fleet_query_ignores_the_criterion_when_it_is_empty(self):
        self.assertEqual(self.fleet(win_build=""), ["lin", "other", "srv", "w10", "w11"])

    def test_a_host_that_never_reported_a_build_is_not_matched(self):
        self.assertNotIn("lin", self.fleet(win_build="a"))

    def test_the_saved_query_keeps_the_criterion_and_the_page_has_the_control(self):
        self.assertIn("win_build", api._FQ_PARAMS)
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        block = re.search(r"const _FQ_FIELDS = \{(.*?)\n\};", js, re.S).group(1)
        fields = dict(re.findall(r"(\w+):\s*'(fq-[\w-]+)'", block))
        self.assertEqual(fields.get("win_build"), "fq-winbuild")
        html = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('id="fq-winbuild"'), 1)


class TestNoCheckReadsTheVersionOfWindows(unittest.TestCase):
    def test_the_end_of_life_table_holds_linux_distributions_only(self):
        """The brief asked for the build to be used where a check reads the version of Windows, and for nothing to be added if none does."""
        self.assertFalse([d for d in api._OS_EOL if "win" in d.lower()])
        self.assertEqual(api._device_os_eol({"os": "Windows 11 (Build 22631)"}, {}), None)
        self.assertEqual(api._device_os_eol({"os": "Windows 10 (Build 19045)"}, {}), None)

    def test_no_check_names_the_build(self):
        src = (_CGI / "checks.py").read_text(encoding="utf-8")
        self.assertNotIn("win_build", src)


if __name__ == "__main__":
    unittest.main()
