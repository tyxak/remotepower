#!/usr/bin/env python3
"""What the review of the Windows host items found (the update search, the build, the shares and the TPM), closed at the cause.

Each class below is one finding of that review. Every guard in it was watched failing against the old code: the mutations that were
applied one at a time (with the anchor checked first, and a green control before) are listed in the commit that added the class.

  * A host read on its own by a SQL backend skipped the shape registry that every other read of the store goes through.
  * A stored build that is text of digits `int()` refuses ("²²²") took the whole Hosts list down: the readers of a stored build now take it
    through the cleaner that ingest uses, and the digits are ASCII digits wherever a build or a version is read.
  * Windows 10 and 11 Enterprise multi-session has an EditionID that starts with "Server" and is a client system: the agent reads
    InstallationType and the server decides "server" from it.
  * (later commits add the count a failed search leaves, the corpus and the time cell.)

The Windows agent cannot run here; its parsing is driven through the stand-ins of win_host_support.py.
"""
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


if __name__ == "__main__":
    unittest.main()
