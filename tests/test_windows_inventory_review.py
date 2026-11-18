#!/usr/bin/env python3
"""What the review of the Windows host items found (the update search, the build, the shares and the TPM), closed at the cause.

Each class below is one finding of that review. Every guard in it was watched failing against the old code: the mutations that were
applied one at a time (with the anchor checked first, and a green control before) are listed in the commit that added the class.

  * A host read on its own by a SQL backend skipped the shape registry that every other read of the store goes through.
  * A stored build that is text of digits `int()` refuses ("²²²") took the whole Hosts list down: the readers of a stored build now take it
    through the cleaner that ingest uses, and the digits are ASCII digits wherever a build or a version is read.
  * Windows 10 and 11 Enterprise multi-session has an EditionID that starts with "Server" and is a client system: the agent reads
    InstallationType and the server decides "server" from it.
  * A Windows Update search that failed leaves the count the host had. Two readers took that count for the count now: the check of a queued
    upgrade said "didn't take" about a count older than the upgrade, and the patch reports said "fully patched" about a zero of 40 days ago.
  * The four signals the Windows items persist (build, shares, TPM, search state) were in no chunk of the corpus that fleet knowledge is built
    from, which tests/test_v643_rag_signal_coverage.py reads as a forgotten signal.
  * (a later commit adds the time cell.)

The Windows agent cannot run here; its parsing is driven through the stand-ins of win_host_support.py.
"""
import ast
import io
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="rp-winreview-")
os.environ.setdefault("RP_DATA_DIR", _TMP)

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_CGI = _ROOT / "server" / "cgi-bin"
for _p in (str(_CGI), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import rag_index  # noqa: E402
import win_host_support as S  # noqa: E402
import windows_host as wh  # noqa: E402

import api  # noqa: E402
import storage  # noqa: E402
import store_shapes  # noqa: E402

agent = S.load_agent("rp_winreview_agent")


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


# ── a host read on its own ───────────────────────────────────────────────────────────────────────────────────────────────
class _OnSqlite(unittest.TestCase):
    """Runs against the SQLite backend whatever backend the gate runs: the marker of a scratch directory selects it, the way
    test_storage_backend.py does, and the environment variable that would override the marker is put back afterwards."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-winreview-sql-"))
        storage.close_connection()
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        self._files = {}
        for attr in ("DEVICES_FILE", "STORAGE_MARKER_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.dir / Path(getattr(api, attr)).name)
        storage.write_marker(self.dir, "sqlite")
        self._env_backend = os.environ.pop("RP_STORAGE_BACKEND", None)
        self.assertEqual(api._storage_backend(), "sqlite", "control: this class runs the SQL path, not the JSON one")

    def tearDown(self):
        for attr, value in self._files.items():
            setattr(api, attr, value)
        if self._env_backend is not None:
            os.environ["RP_STORAGE_BACKEND"] = self._env_backend
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        storage.close_connection()
        shutil.rmtree(self.dir, ignore_errors=True)

    def host(self, **over):
        now = int(time.time())
        return dict({"name": "h1", "hostname": "h1", "os": "Windows 11", "token": "t", "last_seen": now, "enrolled": now, "tags": [],
                     "group": "", "agentless": False, "sysinfo": {"uptime": "1d"}}, **over)

    def raw_row(self, dev_id, doc):
        """A row written the way a hand edit or a restore from a mixed-up backup would leave it: straight into the table."""
        import json
        conn = storage._connect(self.dir)
        conn.execute("INSERT OR REPLACE INTO devices(id, doc, last_seen) VALUES(?,?,?)", (dev_id, json.dumps(doc), 1))
        conn.commit()
        api._LOAD_CACHE.clear()


class TestAHostReadOnItsOwnIsRepairedLikeTheWholeStore(_OnSqlite):
    """The whole store is repaired where it is read (api._load_uncached, and the locked read of the SQL backends). A host read on its own
    (device_get, and the transaction of _DeviceUpdate) was not: a text where `sysinfo.packages` is a map answered 500 on the Checks page of
    the host on SQLite and PostgreSQL, and 200 on JSON."""

    HOSTILE = {
        "packages as text": {"sysinfo": {"packages": "x", "uptime": "1d"}},
        "the search as a list": {"sysinfo": {"wu_search": [1, 2], "uptime": "1d"}},
        "tags as text and a stamp as text": {"tags": "oops", "last_seen": "17", "sysinfo": {"uptime": "1d"}},
        "the name as a list": {"name": ["x"], "sysinfo": {"uptime": "1d"}},
    }

    def test_every_way_to_read_one_host_gives_the_row_the_whole_store_gives(self):
        for label, over in self.HOSTILE.items():
            with self.subTest(row=label):
                api.save(api.DEVICES_FILE, {"h1": self.host(**over)})
                api._LOAD_CACHE.clear()
                whole = api.load(api.DEVICES_FILE)["h1"]
                api._LOAD_CACHE.clear()
                single = api.device_get("h1")
                self.assertEqual(single, whole, "the single-row read left a field as it was stored")
                api._LOAD_CACHE.clear()
                with api._DeviceUpdate("h1") as devices:
                    in_transaction = devices["h1"]
                self.assertEqual(in_transaction, whole, "the transaction of one host yielded the stored row")

    def test_the_repair_is_real_and_not_a_comparison_of_two_unrepaired_rows(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        stored = storage.device_get(api.DEVICES_FILE, "h1")
        self.assertEqual(stored["sysinfo"]["packages"], "x", "control: the stored row really holds the text")
        self.assertEqual(api.device_get("h1")["sysinfo"]["packages"], {})

    def test_the_checks_page_of_the_host_answers(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        status, body = S.call(api, api.handle_device_checks, "h1")
        self.assertEqual(status, 200, body)

    def test_the_transaction_stores_the_repaired_row_when_it_ends_cleanly(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(tags="oops", sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        with api._DeviceUpdate("h1") as devices:
            devices["h1"]["group"] = "edited"
        stored = storage.device_get(api.DEVICES_FILE, "h1")
        self.assertEqual((stored["tags"], stored["sysinfo"]["packages"], stored["group"]), ([], {}, "edited"))

    def test_a_row_the_registry_leaves_out_is_a_host_that_is_not_there(self):
        self.raw_row("h2", "not a map")
        self.assertIsNone(api.device_get("h2"))
        self.assertEqual(api.device_get("h2", {"fallback": 1}), {"fallback": 1})
        with api._DeviceUpdate("h2") as devices:
            self.assertEqual(devices, {}, "the transaction yielded a row that is not a map")
        self.assertEqual(storage.device_get(api.DEVICES_FILE, "h2"), "not a map", "nothing was written for a row the registry left out")

    def test_a_host_that_is_not_stored_is_still_the_default(self):
        self.assertIsNone(api.device_get("nobody"))
        self.assertEqual(api.device_get("nobody", {"d": 1}), {"d": 1})
        with api._DeviceUpdate("nobody") as devices:
            self.assertEqual(devices, {})

    def test_a_clean_row_comes_back_unchanged(self):
        row = self.host(tags=["a", "b"], sysinfo={"uptime": "1d", "packages": {"manager": "apt", "upgradable": 2}})
        api.save(api.DEVICES_FILE, {"h1": row})
        api._LOAD_CACHE.clear()
        self.assertEqual(api.device_get("h1"), api.load(api.DEVICES_FILE)["h1"])
        self.assertEqual(api.device_get("h1")["sysinfo"]["packages"], {"manager": "apt", "upgradable": 2})


class TestTheRepairIsTheSameOnJson(unittest.TestCase):
    """The page walk of test_windows_shares_tpm.py runs on whichever backend the gate runs. This is the JSON side of the same property, so
    a plain `make test` holds both directions."""

    def test_the_json_backend_gives_the_same_repaired_row(self):
        saved_cache = api._BACKEND_CACHE
        saved_env = os.environ.pop("RP_STORAGE_BACKEND", None)
        saved_file = api.DEVICES_FILE
        scratch = Path(tempfile.mkdtemp(prefix="rp-winreview-json-"))
        try:
            api._BACKEND_CACHE = "json"
            api.DEVICES_FILE = scratch / "devices.json"
            api._LOAD_CACHE.clear()
            self.assertIsNone(api._dbmod(), "control: this is the JSON path")
            now = int(time.time())
            api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "os": "Windows 11", "token": "t", "last_seen": now, "tags": "oops",
                                               "sysinfo": {"packages": "x"}}})
            api._LOAD_CACHE.clear()
            row = api.device_get("h1")
            self.assertEqual((row["tags"], row["sysinfo"]["packages"]), ([], {}))
        finally:
            api._BACKEND_CACHE = saved_cache
            if saved_env is not None:
                os.environ["RP_STORAGE_BACKEND"] = saved_env
            api.DEVICES_FILE = saved_file
            api._LOAD_CACHE.clear()
            shutil.rmtree(scratch, ignore_errors=True)


# ── a stored build that is not a build ────────────────────────────────────────────────────────────────────────────────────
def host_row(name, win_build=None, **over):
    now = int(time.time())
    row = {"name": name, "hostname": name, "os": "Windows 11", "token": "t", "last_seen": now, "enrolled": now, "tags": [], "group": "",
           "agentless": False, "sysinfo": {"uptime": "1d"}}
    if win_build is not None:
        row["sysinfo"]["win_build"] = win_build
    row.update(over)
    return row


# Each of these is a build string `str.isdigit()` accepts or a stored value of another kind. "²²²" is the one that took the Hosts list down:
# isdigit() is true for it and int() refuses it.
HOSTILE_BUILDS = ["²²²", "①②③", "٢٢٦٣١", "２２６３１", "2263²", "9" * 1000, "22 631", "", "x22631", "-22631", None, 22631, [], {}, True]


class TestAStoredBuildThatIsNotANumber(unittest.TestCase):
    def test_the_readers_do_not_raise_on_any_of_them(self):
        for build in HOSTILE_BUILDS:
            record = {"build": build, "product": "Windows 10 Pro", "ubr": 5, "display_version": "23H2"}
            with self.subTest(build=build):
                label, family = wh.os_label(record), wh.win_family(record)
                fields = wh.build_fields({"win_build": record})
                if isinstance(build, int) and not isinstance(build, bool):
                    continue    # a number stored where text goes: the registry reads it as its text (a test below)
                self.assertEqual(label, "", "a build that is not 3 to 6 ASCII digits is no build, so there is no label")
                self.assertIsNone(fields["win_build"])
                self.assertEqual(family, "Windows 10", "the family then comes from the product name, as for a host that sent no build")

    def test_a_control_character_at_the_end_is_trimmed_the_way_ingest_trims_it(self):
        self.assertEqual(wh.os_label({"build": "22631\x00", "product": "Windows 10 Pro"}), wh.os_label({"build": "22631", "product": "Windows 10 Pro"}))

    def test_the_control_a_real_build_still_reads(self):
        record = {"build": "22631", "product": "Windows 10 Pro", "ubr": 3593, "display_version": "23H2", "edition": "Professional"}
        self.assertEqual(wh.os_label(record), "Windows 11 Pro 23H2 (build 22631.3593)")
        self.assertEqual(wh.win_family(record), "Windows 11")

    def test_the_second_layer_alone_does_not_raise_either(self):
        """`_family` checks the build itself before it calls int(), so a caller that skipped the cleaner would still not raise."""
        for build in ("²²²", "①②③", "٢٢٦٣١", "9" * 1000):
            with self.subTest(build=build):
                self.assertEqual(wh._family({"build": build, "product": "Windows 10 Pro"}), "Windows 10")

    def test_a_stored_text_is_capped_and_a_stored_revision_is_a_number(self):
        label = wh.os_label({"build": "22631", "product": "P" * 5000, "edition": "E" * 5000, "display_version": "<img src=x onerror=alert(1)>",
                             "ubr": True})
        self.assertLess(len(label), 200)
        self.assertNotIn("<img", label)
        self.assertNotIn("True", label)
        self.assertNotIn(".True", label)
        self.assertEqual(wh.os_label({"build": "22631", "ubr": 10**9}), "Windows 11 (build 22631)")
        self.assertEqual(wh.build_fields({"win_build": {"build": "22631", "ubr": True}})["win_ubr"], None)

    def test_the_digits_of_other_scripts_are_no_build_at_ingest_either(self):
        for build in ("٢٢٦٣١", "２２６３１", "²²²", "२२६३१"):
            with self.subTest(build=build):
                self.assertIsNone(wh.clean_win_build({"build": build}))
        self.assertEqual(wh.clean_win_build({"build": "22631"}), {"build": "22631"})

    def test_the_tpm_specification_is_ascii_digits_too(self):
        self.assertEqual(wh.clean_tpm({"present": True, "spec": "٢.٠"}), {"present": True})
        self.assertEqual(wh.clean_tpm({"present": True, "spec": "2.0"}), {"present": True, "spec": "2.0"})

    def test_the_registry_reads_a_number_stored_as_text_and_the_other_way_round(self):
        doc = {"h": {"name": "h", "sysinfo": {"win_build": {"build": 22631, "ubr": "3593", "product": 5, "display_version": 23}}}}
        fixed = store_shapes.normalize("devices.json", doc)["h"]["sysinfo"]["win_build"]
        self.assertEqual(fixed, {"build": "22631", "ubr": 3593, "product": "5", "display_version": "23"})
        for wrong in ("x", 5, [1], None):
            doc = {"h": {"name": "h", "sysinfo": {"win_build": wrong}}}
            self.assertEqual(store_shapes.normalize("devices.json", doc)["h"]["sysinfo"]["win_build"], {}, wrong)

    def test_the_pages_that_read_a_stored_build_answer_for_every_hostile_one(self):
        hosts = {"good": host_row("good", {"build": "22631", "ubr": 1})}
        for i, build in enumerate(HOSTILE_BUILDS):
            hosts[f"hostile{i}"] = host_row(f"hostile{i}", {"build": build, "product": "Windows 10 Pro", "ubr": True, "installation_type": ["x"]})
        hosts["plain"] = host_row("plain")
        api.save(api.DEVICES_FILE, hosts)
        api._LOAD_CACHE.clear()

        def explorer():
            api.respond(200, api._qe_devices_rows())

        for name, handler, kw in (("hosts list", api.handle_devices_list, {}), ("data explorer", explorer, {}),
                                  ("fleet query", api.handle_fleet_query, {"query": "win_build=windows"})):
            with self.subTest(page=name):
                status, body = S.call(api, handler, **kw)
                self.assertEqual(status, 200, body)
        status, rows = S.call(api, api.handle_devices_list)
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(by_id["good"]["os_detail"], "Windows 11 (build 22631.1)")
        self.assertIn("plain", by_id, "a host with no build is still in the list")
        self.assertEqual(len(rows), len(hosts), "the Hosts list lost a row")


class TestTheAgentReadsDigitsAsAsciiDigits(unittest.TestCase):
    def test_a_registry_number_of_superscripts_is_not_a_number(self):
        for text in ("²", "²²²", "①", "٣٥٩٣"):
            with self.subTest(text=text):
                fake = S.FakeWinreg({S.NT_KEY: {"UBR": (text, S.SZ)}})
                with mock.patch.dict(sys.modules, {"winreg": fake}):
                    handle = fake.OpenKey(fake.HKEY_LOCAL_MACHINE, S.NT_KEY)
                    self.assertIsNone(agent._reg_number(fake, handle, "UBR"))
        fake = S.FakeWinreg({S.NT_KEY: {"UBR": (" 3593 ", S.SZ)}})
        self.assertEqual(agent._reg_number(fake, fake.OpenKey(fake.HKEY_LOCAL_MACHINE, S.NT_KEY), "UBR"), 3593)

    def test_a_build_number_of_superscripts_says_nothing(self):
        for build in ("²²²", "①②③"):
            with self.subTest(build=build):
                fake = S.FakeWinreg({S.NT_KEY: S.nt_values(CurrentBuildNumber=(build, S.SZ), CurrentBuild=None)})
                with mock.patch.dict(sys.modules, {"winreg": fake}):
                    self.assertEqual(agent.get_win_build(), {})

    def test_the_family_the_agent_names_from_a_build_that_is_not_digits(self):
        with mock.patch("platform.win32_ver", return_value=("10", "10.0.²²²", "", "Multiprocessor Free")):
            self.assertEqual(agent.get_os_info(), "Windows 10 (Build ²²²)", "int() raised and the fallback text was sent instead")
        with mock.patch("platform.win32_ver", return_value=("10", "10.0.22631", "", "Multiprocessor Free")):
            self.assertEqual(agent.get_os_info(), "Windows 11 (Build 22631)")


# ── a client edition whose EditionID says Server ──────────────────────────────────────────────────────────────────────────
MULTI_SESSION = dict(EditionID=("ServerRdsh", S.SZ), ProductName=("Windows 10 Enterprise", S.SZ))


def read_build(values):
    fake = S.FakeWinreg({S.NT_KEY: values})
    with mock.patch.dict(sys.modules, {"winreg": fake}):
        return agent.get_win_build()


class TestAMultiSessionClientIsNotAServer(unittest.TestCase):
    """Windows 10 and 11 Enterprise multi-session (what Azure Virtual Desktop runs) is a client system: its InstallationType is "Client", its
    EditionID is "ServerRdsh" and its ProductName says "Windows 10" on every build. The edition id alone made it a server, which skipped the rule
    the build number exists for and left "Windows 10" on a host that runs Windows 11."""

    def test_the_agent_sends_the_installation_type(self):
        got = read_build(S.nt_values(**MULTI_SESSION))
        self.assertEqual((got["installation_type"], got["edition"]), ("Client", "ServerRdsh"))

    def test_the_host_reads_as_the_windows_11_it_is(self):
        built = wh.clean_win_build(read_build(S.nt_values(**MULTI_SESSION)))
        self.assertEqual(wh.os_label(built), "Windows 11 Enterprise 23H2 (build 22631.3593)")
        self.assertEqual(wh.win_family(built), "Windows 11")
        self.assertEqual(wh.build_fields({"win_build": built})["win_family"], "Windows 11")

    def test_the_same_host_from_an_agent_that_does_not_send_the_installation_type(self):
        old = {"build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "ServerRdsh", "product": "Windows 10 Enterprise"}
        self.assertEqual(wh.os_label(old), "Windows 11 Enterprise 23H2 (build 22631.3593)")
        self.assertEqual(wh.win_family(old), "Windows 11")

    def test_a_real_server_is_still_a_server_with_or_without_the_installation_type(self):
        for record in ({"build": "20348", "product": "Windows Server 2022 Datacenter", "edition": "ServerDatacenter", "installation_type": "Server"},
                       {"build": "20348", "product": "Windows Server 2022 Datacenter", "edition": "ServerDatacenter"},
                       {"build": "26100", "edition": "ServerStandard"},
                       {"build": "20348", "product": "Windows Server 2022 Standard", "installation_type": "Server Core"}):
            with self.subTest(record=record):
                self.assertNotIn("Windows 11", wh.os_label(record))
                self.assertNotIn("Windows 10", wh.os_label(record))
        self.assertEqual(wh.win_family({"build": "26100", "product": "Windows Server 2025 Standard", "installation_type": "Server"}),
                         "Windows Server 2025 Standard")

    def test_a_server_whose_name_has_no_server_in_it_is_one_by_its_installation_type(self):
        record = {"build": "25398", "product": "Azure Stack HCI", "display_version": "23H2", "ubr": 1, "installation_type": "Server Core"}
        self.assertEqual(wh.win_family(record), "Azure Stack HCI")
        self.assertEqual(wh.os_label(record), "Azure Stack HCI 23H2 (build 25398.1)")

    def test_the_installation_type_decides_when_the_host_sent_one(self):
        self.assertEqual(wh.win_family({"build": "26100", "product": "Windows Server 2025 Standard", "installation_type": "Client"}), "Windows 11")
        self.assertEqual(wh.win_family({"build": "22631", "product": "Windows 10 Pro", "edition": "ServerStandard", "installation_type": "Client"}),
                         "Windows 11")

    def test_the_words_of_the_installation_type_are_a_fixed_set(self):
        for sent, kept in (("Client", "Client"), ("client", "Client"), (" SERVER ", "Server"), ("Server Core", "Server Core"),
                           ("Nano Server", "Nano Server"), ("Embedded", "Embedded")):
            with self.subTest(sent=sent):
                self.assertEqual(wh.clean_win_build({"build": "22631", "installation_type": sent})["installation_type"], kept)
        for sent in ("<script>alert(1)</script>", "Servers", "Client\x00x", "x" * 500, "", None, 5, ["Client"], {"a": 1}):
            with self.subTest(sent=sent):
                self.assertNotIn("installation_type", wh.clean_win_build({"build": "22631", "installation_type": sent}))

    def test_the_whole_way_through_the_heartbeat_and_the_data_explorer(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {"avd": host_row("avd-host", token="tok-avd")})
        api._LOAD_CACHE.clear()
        info = None
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg({S.NT_KEY: S.nt_values(**MULTI_SESSION)})}):
            info = agent.collect_sysinfo()
        status, body = S.beat(api, "avd", "tok-avd", info)
        self.assertEqual(status, 200, body)
        api._LOAD_CACHE.clear()
        si = api.load(api.DEVICES_FILE)["avd"]["sysinfo"]
        self.assertEqual(si["win_build"]["installation_type"], "Client")
        status, rows = S.call(api, api.handle_devices_list)
        self.assertEqual(next(r for r in rows if r["id"] == "avd")["os_detail"], "Windows 11 Enterprise 23H2 (build 22631.3593)")
        self.assertEqual(api._qe_device_posture(si)["win_family"], "Windows 11")
        self.assertGreater(now, 0)


# ── the count a failed search leaves ──────────────────────────────────────────────────────────────────────────────────────
# Every time below is counted from a clock read when the test runs, never when the module is imported: a gate imports every module first and
# runs them minutes later, and a host whose last_seen is that old is offline.
DAY = 86400


def win_host(name, now, count, taken, state, pkg_scan_ts=None, last_seen=None, **extra):
    """A Windows host with `count` pending updates that were taken at `taken` and the search state `state` ("worked", "failed", a state of its
    own, or None for a host that sent none). pkg_scan_ts is `taken` unless it is given, and False leaves it out."""
    si = {"uptime": "1d", "packages": {"manager": "windows-update", "upgradable": count, "upgradable_names": ["KB%d" % i for i in range(count)]}}
    if pkg_scan_ts is not False:
        si["pkg_scan_ts"] = taken if pkg_scan_ts is None else pkg_scan_ts
    if state == "worked":
        si["wu_search"] = {"at": now - 600, "ok": True, "source": "windows-update-agent", "error_class": "", "ok_at": now - 600, "fail_since": 0}
    elif state == "failed":
        si["wu_search"] = {"at": now - 600, "ok": False, "source": "windows-update-agent", "error_class": "service", "ok_at": taken,
                           "fail_since": now - 3600}
    elif isinstance(state, dict):
        si["wu_search"] = state
    row = host_row(name, last_seen=now if last_seen is None else last_seen, sysinfo=si)
    row.update(extra)
    return row


def store(hosts):
    """The hosts as they are built: save() keeps last_seen from going back, and a host that is offline has to be able to be saved as one."""
    api.save(api.DEVICES_FILE, hosts, clamp_last_seen=False)
    api._LOAD_CACHE.clear()


def stored(dev_id):
    api._LOAD_CACHE.clear()
    return api.load(api.DEVICES_FILE)[dev_id]


class TestTheCheckOfAQueuedUpgradeAgainstAKeptCount(unittest.TestCase):
    """_upgrade_verify_status compares the count snapshotted when an upgrade was queued with the latest count. A host whose last search failed
    carries the count it had, so a count taken before the upgrade was read as "the upgrade did not take". It waits for a count that was taken
    after the upgrade, the way it waits for a host that has sent none."""

    def setUp(self):
        self.now = int(time.time())

    def status(self, count, taken_ago, state, queued_ago=5400, before=3, **kw):
        now = self.now
        row = win_host("w", now, count, now - taken_ago, state, upgrade_queued_at=now - queued_ago, upgrade_pending_before=before, **kw)
        store({"w": row})
        return api._upgrade_verify_status(stored("w"), now)

    def test_a_kept_count_that_is_older_than_the_upgrade_proves_nothing(self):
        self.assertIsNone(self.status(3, 7200, "failed"), "an online host, an hour after the queue: gives up quietly as a host with no count does")
        self.assertEqual(self.status(3, 7200, "failed", queued_ago=1800), "pending")
        self.assertEqual(self.status(3, 7200, "failed", last_seen=self.now - 86400), "pending", "an offline host waits")

    def test_the_controls_a_count_that_was_taken_after_the_upgrade_still_decides(self):
        self.assertEqual(self.status(3, 600, "worked"), "stalled", "a search that worked after the upgrade and found the same count")
        self.assertEqual(self.status(1, 600, "worked"), "ok")
        self.assertEqual(self.status(1, 1800, "failed"), "ok", "the count after the upgrade was taken, and the search failed later")
        self.assertEqual(self.status(3, 1800, "failed"), "stalled", "a count taken after the upgrade, unchanged, with a later failure")

    def test_a_host_that_sent_no_state_is_read_as_it_always_was(self):
        self.assertEqual(self.status(3, 600, None), "stalled")
        self.assertEqual(self.status(3, 7200, None), "stalled", "a Linux host's count is never read as a kept one, whatever its age")
        self.assertEqual(self.status(3, 0, None, pkg_scan_ts=False), "stalled", "no time at all")
        self.assertEqual(self.status(1, 7200, None), "ok")

    def test_a_search_that_failed_and_has_no_time_for_its_count_is_a_count_that_predates(self):
        row = win_host("w", self.now, 3, 0, "failed", pkg_scan_ts=False, upgrade_queued_at=self.now - 5400, upgrade_pending_before=3)
        store({"w": row})
        self.assertIsNone(api._upgrade_verify_status(stored("w"), self.now))

    def test_the_whole_way_through_the_heartbeat(self):
        """The case of the review: a count of 3, an upgrade queued 90 minutes ago, and a beat that says the search failed."""
        now = self.now
        host = win_host("w", now, 3, now - 7200, None, upgrade_queued_at=now - 5400, upgrade_pending_before=3, token="tok-w")   # no state yet
        store({"w": host})
        status, body = S.beat(api, "w", "tok-w", {"hostname": "w", "wu_search": {"at": int(time.time()), "ok": False, "error_class": "service"}})
        self.assertEqual(status, 200, body)
        row = stored("w")
        self.assertEqual(row["sysinfo"]["packages"]["upgradable"], 3, "control: the count was kept")
        self.assertIsNone(api._upgrade_verify_status(row, now))


def export_text(handler):
    """What an export handler (CSV or XML) writes to the web server: it prints headers and a blank line and then the file, and exits."""
    saved = api.verify_token
    api.verify_token = lambda token: ("alice", "admin")
    api._RCTX.environ = {"REQUEST_METHOD": "GET", "QUERY_STRING": "", "HTTP_X_TOKEN": "t"}
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    try:
        with mock.patch.object(sys, "stdout", out):
            try:
                handler()
            except SystemExit:
                pass
    finally:
        api.verify_token = saved
        api._RCTX.environ = None
        api._LOAD_CACHE.clear()
    out.flush()
    return raw.getvalue().decode("utf-8").split("\n\n", 1)[1]


class TestThePatchReportsAgainstAKeptCount(unittest.TestCase):
    """Four functions turn the count into "no data", "fully patched" or "patches available". A host whose search has failed for three days or more
    is "no data" in all four, with the count it had and its date in the two JSON reports; a failed search for less is still the count it had."""

    def setUp(self):
        n = self.now = int(time.time())
        # name -> (the host, the status all four answer)
        self.hosts = {
            "worked0": (win_host("worked0", n, 0, n - 600, "worked"), "fully_patched"),
            "failed_a_day0": (win_host("failed_a_day0", n, 0, n - DAY, "failed"), "fully_patched"),
            "just_under0": (win_host("just_under0", n, 0, n - (3 * DAY - 3600), "failed"), "fully_patched"),
            "just_over0": (win_host("just_over0", n, 0, n - (3 * DAY + 3600), "failed"), "no_data"),
            "stale0": (win_host("stale0", n, 0, n - 40 * DAY, "failed"), "no_data"),
            "stale5": (win_host("stale5", n, 5, n - 20 * DAY, "failed"), "no_data"),
            "failed_a_day5": (win_host("failed_a_day5", n, 5, n - DAY, "failed"), "patches_available"),
            "never_counted": (win_host("never_counted", n, 0, 0, "failed", pkg_scan_ts=False), "no_data"),
            "time_from_the_scan": (win_host("time_from_the_scan", n, 0, 0, "failed", pkg_scan_ts=n - 40 * DAY), "no_data"),
            "recent_scan_no_ok_at": (win_host("recent_scan_no_ok_at", n, 0, 0, "failed", pkg_scan_ts=n - 600), "fully_patched"),
            "delta_beats0": (win_host("delta_beats0", n, 0, n - 600, "worked", pkg_scan_ts=n - 40 * DAY), "fully_patched"),
            "worked_but_old_ok_at": (win_host("worked_but_old_ok_at", n, 0, 0, {"at": n - 60, "ok": True, "ok_at": n - 40 * DAY}), "fully_patched"),
            "linux0": (win_host("linux0", n, 0, n - 40 * DAY, None), "fully_patched"),
            "no_state3": (win_host("no_state3", n, 3, n - 40 * DAY, None), "patches_available"),
        }
        self.want = {k: v[1] for k, v in self.hosts.items()}
        store({k: v[0] for k, v in self.hosts.items()})

    def test_the_fleet_report(self):
        status, body = S.call(api, api.handle_patch_report)
        self.assertEqual(status, 200)
        rows = {r["device_id"]: r for r in body["devices"]}
        self.assertEqual({k: r["patch_status"] for k, r in rows.items()}, self.want)
        count = lambda s: sum(1 for v in self.want.values() if v == s)  # noqa: E731
        patched, with_patches = count("fully_patched"), count("patches_available")
        self.assertEqual((body["summary"]["devices_fully_patched"], body["summary"]["devices_with_patches"], body["summary"]["devices_no_data"]),
                         (patched, with_patches, count("no_data")))
        self.assertEqual(body["summary"]["patch_percentage"], round(patched / (patched + with_patches) * 100, 1))
        self.assertEqual(body["summary"]["total_pending_patches"], 5 + 3)

    def test_the_count_and_its_date_stay_in_the_report(self):
        n = self.now
        status, body = S.call(api, api.handle_patch_report)
        rows = {r["device_id"]: r for r in body["devices"]}
        self.assertEqual((rows["stale0"]["upgradable"], rows["stale0"]["stale_count"]), (None, {"upgradable": 0, "taken_at": n - 40 * DAY}))
        self.assertEqual(rows["stale5"]["stale_count"], {"upgradable": 5, "taken_at": n - 20 * DAY})
        self.assertEqual(rows["never_counted"]["stale_count"], {"upgradable": 0, "taken_at": 0})
        for name in ("worked0", "failed_a_day0", "just_under0", "linux0", "no_state3", "delta_beats0"):
            self.assertIsNone(rows[name]["stale_count"], name)
        self.assertEqual((rows["failed_a_day5"]["upgradable"], rows["no_state3"]["upgradable"]), (5, 3))

    def test_the_report_of_one_host(self):
        for name, want in self.want.items():
            with self.subTest(host=name):
                status, body = S.call(api, api.handle_patch_report_device, name)
                self.assertEqual(status, 200)
                self.assertEqual(body["patch_status"], want)
                self.assertEqual(body["stale_count"] is not None, want == "no_data", "the record of the count is there for the hosts that are no data")
        status, body = S.call(api, api.handle_patch_report_device, "stale0")
        self.assertEqual((body["upgradable"], body["stale_count"], body["wu_search"]["ok"]),
                         (None, {"upgradable": 0, "taken_at": self.now - 40 * DAY}, False))

    def test_the_csv_export(self):
        import csv
        rows = list(csv.reader(io.StringIO(export_text(api.handle_patch_report_csv))))
        head, body = rows[0], {r[0]: r for r in rows[1:]}
        status_col, count_col = head.index("Patch Status"), head.index("Pending Updates")
        self.assertEqual({k: r[status_col] for k, r in body.items()}, self.want)
        self.assertEqual((body["stale0"][count_col], body["failed_a_day5"][count_col]), ("N/A", "5"))

    def test_the_xml_export(self):
        from xml.etree import ElementTree as ET
        root = ET.fromstring(export_text(api.handle_patch_report_xml).split("?>", 1)[1])
        got = {d.find("Name").text: d.find("PatchStatus").text for d in root.iter("Device")}
        self.assertEqual(got, self.want)
        self.assertEqual(root.find("Summary/NoData").text, str(sum(1 for v in self.want.values() if v == "no_data")))


class TestTheHelpersOfTheKeptCount(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())

    def test_a_count_that_is_not_a_kept_one_comes_back_as_it_is(self):
        for si in (None, "x", {}, {"wu_search": None}, {"wu_search": "x"}, {"wu_search": {"ok": True, "ok_at": 1}}, {"wu_search": {"ok": "no"}}):
            with self.subTest(si=si):
                self.assertEqual(wh.readable_count(si, 3, self.now), (3, None))
                self.assertIsNone(wh.kept_count_time(si))
                self.assertFalse(wh.count_predates(si, self.now))

    def test_what_is_not_a_count_is_never_a_stale_one(self):
        failed = {"wu_search": {"ok": False, "ok_at": 1}}
        for count in (None, True, False, 1.5, "3", [3]):
            with self.subTest(count=count):
                self.assertEqual(wh.readable_count(failed, count, self.now), (count, None))

    def test_the_time_of_a_kept_count(self):
        self.assertEqual(wh.kept_count_time({"wu_search": {"ok": False, "ok_at": 100}, "pkg_scan_ts": 50}), 100)
        self.assertEqual(wh.kept_count_time({"wu_search": {"ok": False, "ok_at": 0}, "pkg_scan_ts": 50}), 50)
        self.assertEqual(wh.kept_count_time({"wu_search": {"ok": False}}), 0)
        for hostile in ("100", [100], 10**30, -5, True, None):
            self.assertEqual(wh.kept_count_time({"wu_search": {"ok": False, "ok_at": hostile}, "pkg_scan_ts": hostile}), 0, hostile)

    def test_the_limit_is_a_whole_number_of_days_and_the_day_it_is_reached_is_stale(self):
        now = self.now
        failed = {"wu_search": {"ok": False, "ok_at": now - 2 * DAY}}
        self.assertEqual(wh.readable_count(failed, 7, now, days=3), (7, None))
        self.assertEqual(wh.readable_count(failed, 7, now, days=2), (None, {"upgradable": 7, "taken_at": now - 2 * DAY}), "at exactly the limit")
        self.assertEqual(wh.readable_count(failed, 7, now - 1, days=2), (7, None), "one second short of it")
        self.assertEqual(wh.SEARCH_WARN_DAYS, 3, "the limit of the reports is the one at which the Checks row turns amber")


class TestEveryClassifierOfTheCountReadsItsAge(unittest.TestCase):
    """Enumerated from the code, not from a list of names: every function of the server that turns the count into "fully patched" asks
    `readable_count` first, and the check of a queued upgrade asks `count_predates`. A fifth classifier, or one of these without the call,
    fails here."""

    def functions(self):
        out = {}
        for path in sorted(_CGI.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[f"{path.name}:{node.name}"] = node
        return out

    @staticmethod
    def calls(node):
        names = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                f = n.func
                names.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
        return names

    @staticmethod
    def strings(node):
        return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}

    def test_the_four_patch_reports(self):
        funcs = self.functions()
        classifiers = {k for k, node in funcs.items() if "fully_patched" in self.strings(node)}
        self.assertEqual(sorted(classifiers), ["api.py:handle_patch_report", "api.py:handle_patch_report_csv", "api.py:handle_patch_report_device",
                                               "api.py:handle_patch_report_xml"], "a function that says 'fully patched' is new: read its count's age")
        for k in sorted(classifiers):
            with self.subTest(function=k):
                self.assertIn("readable_count", self.calls(funcs[k]))

    def test_the_check_of_a_queued_upgrade(self):
        node = self.functions()["api.py:_upgrade_verify_status"]
        self.assertIn("count_predates", self.calls(node))


# ── what fleet knowledge is told ──────────────────────────────────────────────────────────────────────────────────────────
class TestTheCorpusKnowsTheWindowsSignals(unittest.TestCase):
    """build_live_state_corpus is where an operator's question about the fleet meets what the product knows. Each of these drives the real
    builder with a host that has the signal, and with the shapes a stored host can hold instead."""

    def docs(self, **si):
        host = {"id": "w1", "name": "WIN-ONE", "os": "Windows 11 (Build 22631)", "last_seen": int(time.time()), "monitored": True, "sysinfo": si}
        return {d["id"]: d["text"] for d in rag_index.build_live_state_corpus([host], now=int(time.time()))}

    def text(self, **si):
        return "\n".join(self.docs(**si).values())

    def test_the_positive_control_the_builder_emits_the_chunks(self):
        docs = self.docs(uptime="1d", win_build={"build": "22631"})
        self.assertIn("live/w1#summary", docs)

    def test_the_build_is_in_the_summary_chunk(self):
        docs = self.docs(win_build={"build": "22631", "ubr": 3593, "display_version": "23H2", "edition": "Professional", "product": "Windows 10 Pro"})
        self.assertIn("windows build: Windows 11 Pro 23H2 (build 22631.3593)", docs["live/w1#summary"])
        self.assertNotIn("windows build", self.text(uptime="1d"))

    def test_the_tpm_is_in_the_posture_chunk_and_a_flag_that_was_not_reported_is_not_false(self):
        for tpm, line in (({"present": True, "ready": True, "enabled": True, "spec": "2.0"}, "TPM: present, ready, specification 2.0"),
                          ({"present": True, "ready": False}, "TPM: present, NOT ready"),
                          ({"present": True, "enabled": False}, "TPM: present, disabled"),
                          ({"present": True}, "TPM: present"),
                          ({"present": False}, "TPM: none")):
            with self.subTest(tpm=tpm):
                self.assertIn(line, self.docs(tpm=tpm)["live/w1#posture"])
        for tpm in ({"ready": True}, {"spec": "2.0"}, {}, "x", [1], 5, None):
            with self.subTest(tpm=tpm):
                self.assertNotIn("TPM", self.text(tpm=tpm), "a TPM that was never reported is not 'none'")

    def test_the_shares_are_counted_and_never_named(self):
        shares = {"count": 2, "admin_count": 3, "items": [{"name": "Finance", "path": "C:\\Secrets\\Finance", "description": "payroll", "encrypted": True},
                                                          {"name": "Public", "path": "D:\\Public", "description": ""}]}
        text = self.text(shares=shares)
        self.assertIn("file shares exported by the host: 2", self.docs(shares=shares)["live/w1#posture"])
        for word in ("Finance", "Secrets", "payroll", "Public"):
            self.assertNotIn(word, text, "a share name, path or description reached the corpus")
        self.assertIn("file shares exported by the host: 0", self.text(shares={"count": 0, "admin_count": 3, "items": []}))
        for shares in ("x", [1], 5, {}, {"items": "x"}):
            self.assertNotIn("file shares", self.text(shares=shares), shares)

    def test_the_search_is_in_the_patch_chunk(self):
        n = int(time.time())
        patches = lambda state, **more: self.docs(packages={"manager": "windows-update", "upgradable": 0}, wu_search=state, **more)["live/w1#patches"]  # noqa: E731
        self.assertIn("Windows Update search: working", patches({"at": n, "ok": True, "ok_at": n}))
        failing = patches({"at": n, "ok": False, "error_class": "access", "ok_at": 1731400000})
        self.assertIn("Windows Update search: FAILING (access); the pending-update count is from 2024-11-12", failing)
        self.assertIn("no search has worked yet", patches({"at": n, "ok": False, "error_class": "service", "ok_at": 0}))
        self.assertIn("FAILING (unknown)", patches({"at": n, "ok": False, "error_class": "<script>alert(1)</script>", "ok_at": 5}))
        self.assertNotIn("<script>", patches({"at": n, "ok": False, "error_class": "<script>alert(1)</script>", "ok_at": 5}))
        self.assertNotIn("Windows Update search", self.text(packages={"manager": "apt", "upgradable": 2}))
        for state in ("x", 5, [1], {"ok": "yes"}, {"at": 5}, None):
            self.assertNotIn("Windows Update search", self.text(packages={"manager": "apt", "upgradable": 2}, wu_search=state), state)

    def test_a_failing_host_does_not_change_its_chunk_from_one_day_to_the_next(self):
        """A date, not "N days ago": the corpus is rebuilt when a source changes, and a chunk that said "3 days ago" would be a new chunk (and,
        with an embedding provider, a new vector) every day the search stays broken."""
        host = {"id": "w1", "name": "WIN-ONE", "os": "Windows 11", "last_seen": 1731500000, "monitored": True, "sysinfo": {
            "packages": {"manager": "windows-update", "upgradable": 2},
            "wu_search": {"at": 1731500000, "ok": False, "error_class": "service", "ok_at": 1731400000}}}
        a = {d["id"]: d["text"] for d in rag_index.build_live_state_corpus([host], now=1731500000)}
        b = {d["id"]: d["text"] for d in rag_index.build_live_state_corpus([host], now=1731500000 + 2 * 86400)}
        self.assertEqual(a["live/w1#patches"], b["live/w1#patches"])

    def test_the_header_of_the_posture_chunk_names_what_it_holds(self):
        text = self.docs(tpm={"present": True})["live/w1#posture"]
        self.assertIn("TPM, file shares", text.splitlines()[0])

    def test_no_stored_shape_stops_the_builder(self):
        for si in ({"win_build": "x", "tpm": [1], "shares": "x", "wu_search": 5}, {"win_build": {"build": "²²²"}, "tpm": {"present": "yes"}},
                   {"win_build": [1], "tpm": 5, "shares": [1], "wu_search": {"ok": False, "ok_at": "x", "error_class": ["x"]}, "packages": "x"}):
            with self.subTest(si=si):
                self.assertGreater(len(self.docs(**si)), 0)


if __name__ == "__main__":
    unittest.main()
