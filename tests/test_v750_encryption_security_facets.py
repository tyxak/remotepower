#!/usr/bin/env python3
"""v7.5.0 (data binding): disk encryption and security updates are fleet questions.

The Data Explorer has answered "is the disk encrypted" since 7.0.0 but never "how
many security updates are waiting", and the Fleet Query page answered neither: it
had the pending count and the firewall, SSH and automatic-update facets. The two
questions that start most exposure reviews ("which hosts have an unencrypted
disk", "which hosts have security updates waiting") had no facet on the page an
operator opens for them.

Driven through the real handle_fleet_query and the real Data Explorer loader.
The Windows and macOS rows are built by each agent's own parser: a fixture is the
consumer's idea of the producer, and 7.3.0 shipped a release in which
posture_flags read the Windows lists as booleans.
"""

import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-facets-"))

_spec = importlib.util.spec_from_file_location("api_v750_facets", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import query_engine  # noqa: E402


def _load_agent(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "client" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_WIN = _load_agent("rp_win_agent_v750_facets", "remotepower-agent-win.py")
_MAC = _load_agent("rp_mac_agent_v750_facets", "remotepower-agent-mac.py")

_PROFILES_ON = [{"name": "Domain", "enabled": True},
                {"name": "Private", "enabled": True},
                {"name": "Public", "enabled": True}]


def _win_posture(**over):
    """What the Windows agent's parser produces from the PowerShell JSON."""
    raw = {"firewall": _PROFILES_ON,
           "bitlocker": [{"mount": "C:", "status": "On"}],
           "defender_realtime": True, "defender_sig_age_days": 1,
           "wu_service": "Running", "wu_start": "Manual"}
    raw.update(over)
    return _WIN._parse_win_posture(json.dumps(raw))


def _mac_posture(filevault):
    return _MAC._parse_mac_posture(filevault, "Firewall is enabled. (State = 1)",
                                   "assessments enabled",
                                   "System Integrity Protection status: enabled.", "1")


def _host(name, **sysinfo):
    return {"name": name, "last_seen": 1, "monitored": True, "sysinfo": sysinfo}


def _pk(upgradable, security):
    return {"manager": "apt", "upgradable": upgradable, "security_updates": security}


def _fleet():
    return {
        # Linux: reported off, reported on, never reported either.
        "lin_off": _host("lin_off", disk_encryption={"encrypted": False},
                         packages=_pk(9, 4)),
        "lin_on": _host("lin_on", disk_encryption={"encrypted": True},
                        packages=_pk(2, 0)),
        "lin_silent": _host("lin_silent"),
        # Windows through the agent's parser: BitLocker off, on, unreadable.
        "win_off": _host("win_off", win_posture=_win_posture(
            bitlocker=[{"mount": "C:", "status": "Off"}])),
        "win_on": _host("win_on", win_posture=_win_posture()),
        "win_unknown": _host("win_unknown", win_posture=_win_posture(
            bitlocker=[{"mount": "C:", "status": "Unknown"}])),
        # macOS through the agent's parser.
        "mac_off": _host("mac_off", mac_posture=_mac_posture("FileVault is Off.")),
        "mac_on": _host("mac_on", mac_posture=_mac_posture("FileVault is On.")),
        # Security updates only.
        "sec_many": _host("sec_many", packages=_pk(30, 12)),
        # A count of the wrong kind is no count.
        "sec_bool": _host("sec_bool", packages=_pk(1, True)),
        "sec_text": _host("sec_text", packages=_pk(1, "7")),
    }


class _FleetBase(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._df = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        api.save(api.DEVICES_FILE, _fleet())
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "require_auth", "_env", "_scope_filter_devices",
                       "method")}
        api.require_auth = lambda **k: "admin"
        api._scope_filter_devices = lambda d: d
        api.method = lambda: "GET"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.DEVICES_FILE = self._df

    def _rows(self, qs):
        self.cap.clear()
        api._env = lambda k, dv="": (qs if k == "QUERY_STRING" else dv)
        try:
            api.handle_fleet_query()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get("s"), 200, self.cap)
        return (self.cap.get("b") or {}).get("devices") or []

    def _ids(self, qs):
        return {r["name"] for r in self._rows(qs)}


class TestEncryptionOffFacet(_FleetBase):

    def test_the_population_is_not_empty(self):
        """Control: the unfiltered query sees every host planted above, so an
        empty answer below cannot be a fixture that never loaded."""
        self.assertEqual(len(self._ids("")), len(_fleet()))

    def test_matches_the_hosts_that_reported_their_disks_off_on_all_three_platforms(self):
        self.assertEqual(self._ids("encryption_off=1"),
                         {"lin_off", "win_off", "mac_off"})

    def test_a_host_that_never_reported_is_not_a_finding(self):
        ids = self._ids("encryption_off=1")
        self.assertNotIn("lin_silent", ids)
        self.assertNotIn("win_unknown", ids)    # an unreadable volume says nothing
        for ok in ("lin_on", "win_on", "mac_on"):
            self.assertNotIn(ok, ids)

    def test_true_is_accepted_like_1(self):
        self.assertEqual(self._ids("encryption_off=true"),
                         self._ids("encryption_off=1"))

    def test_empty_or_zero_does_not_filter(self):
        self.assertEqual(len(self._ids("encryption_off=")), len(_fleet()))
        self.assertEqual(len(self._ids("encryption_off=0")), len(_fleet()))


class TestSecurityUpdatesFacet(_FleetBase):

    def test_matches_above_the_threshold(self):
        self.assertEqual(self._ids("security_gt=0"), {"lin_off", "sec_many"})
        self.assertEqual(self._ids("security_gt=4"), {"sec_many"})
        self.assertEqual(self._ids("security_gt=12"), set())

    def test_a_host_with_nothing_waiting_is_not_matched_at_zero(self):
        self.assertNotIn("lin_on", self._ids("security_gt=0"))

    def test_a_host_without_a_count_never_matches(self):
        """None is "no package scan reported", not zero and not many. Even a
        threshold below zero must leave the silent hosts out."""
        for qs in ("security_gt=0", "security_gt=-1"):
            ids = self._ids(qs)
            for silent in ("lin_silent", "win_off", "mac_off"):
                self.assertNotIn(silent, ids, qs)
        self.assertIn("lin_on", self._ids("security_gt=-1"))

    def test_a_count_of_the_wrong_kind_is_no_count(self):
        ids = self._ids("security_gt=0")
        self.assertNotIn("sec_bool", ids)
        self.assertNotIn("sec_text", ids)

    def test_a_garbage_threshold_is_ignored_like_every_other_number(self):
        self.assertEqual(len(self._ids("security_gt=abc")), len(_fleet()))

    def test_the_two_facets_combine_with_and(self):
        self.assertEqual(self._ids("encryption_off=1&security_gt=0"), {"lin_off"})

    def test_rows_carry_the_count(self):
        by_name = {r["name"]: r for r in self._rows("")}
        self.assertEqual(by_name["lin_off"]["security"], 4)
        self.assertEqual(by_name["sec_many"]["security"], 12)
        self.assertEqual(by_name["lin_on"]["security"], 0)
        self.assertIsNone(by_name["lin_silent"]["security"])
        self.assertIsNone(by_name["sec_bool"]["security"])


class TestExportCarriesTheColumn(_FleetBase):

    def test_csv_has_a_security_column_next_to_pending(self):
        data, ctype, _name = api._fleet_query_bytes(self._rows("security_gt=4"), "csv")
        lines = data.decode().splitlines()
        head = lines[0].split(",")
        self.assertEqual(ctype, "text/csv")
        self.assertEqual(head[head.index("Pending") + 1], "Security")
        row = lines[1].split(",")
        self.assertEqual(row[head.index("Security")], "12")

    def test_xml_has_a_security_element_when_known_and_none_when_not(self):
        data, ctype, _name = api._fleet_query_bytes(self._rows(""), "xml")
        text = data.decode()
        self.assertEqual(ctype, "application/xml")
        self.assertIn("<security>12</security>", text)
        # lin_silent has no count: the element is left out rather than written empty.
        silent = re.search(r"<Device id=\"lin_silent\">.*?</Device>", text, re.S)
        self.assertIsNotNone(silent)
        self.assertNotIn("<security>", silent.group(0))


class TestTheDataExplorerHasTheSameTwoFields(_FleetBase):

    def test_posture_projection_reads_both_counts(self):
        r = api._qe_device_posture({"packages": _pk(9, 4)})
        self.assertEqual(r["pending_updates"], 9)
        self.assertEqual(r["security_updates"], 4)

    def test_a_silent_host_is_none_not_zero(self):
        r = api._qe_device_posture({})
        self.assertIsNone(r["pending_updates"])
        self.assertIsNone(r["security_updates"])

    def test_a_count_of_the_wrong_kind_is_none(self):
        r = api._qe_device_posture({"packages": _pk("9", True)})
        self.assertIsNone(r["pending_updates"])
        self.assertIsNone(r["security_updates"])

    def test_both_names_are_queryable_fields(self):
        for f in ("pending_updates", "security_updates"):
            self.assertIn(f, api._QE_DEVICE_FIELDS)

    def test_a_real_query_over_the_loader_finds_the_exposed_hosts(self):
        """Security updates waiting AND the disk reported unencrypted, asked of
        the rows the Data Explorer builds from the stored fleet."""
        rows = api._qe_devices_rows()
        self.assertEqual(len(rows), len(_fleet()))
        pred = {"and": [
            {"field": "security_updates", "op": "gt", "value": 0},
            {"field": "disk_encrypted", "op": "eq", "value": False}]}
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        keep = query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)
        self.assertEqual({r["name"] for r in keep}, {"lin_off"})

    def test_exists_separates_the_hosts_that_never_scanned(self):
        rows = api._qe_devices_rows()
        pred = {"not": {"field": "security_updates", "op": "exists"}}
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        names = {r["name"] for r in query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)}
        self.assertIn("lin_silent", names)
        self.assertNotIn("sec_many", names)


class TestThePageSendsWhatTheServerReads(unittest.TestCase):
    """The facet on one side only is dropped without a sound: the saved-query
    whitelist cuts it, the form never sends it."""

    JS = (ROOT / "server/html/static/js/app.js").read_text()
    HTML = (ROOT / "server/html/index.html").read_text()

    def test_both_params_are_whitelisted_for_saved_queries(self):
        for p in ("encryption_off", "security_gt"):
            self.assertIn(p, api._FQ_PARAMS)

    def test_the_client_maps_both_params_to_a_form_control_that_exists(self):
        block = re.search(r"const _FQ_FIELDS = \{(.*?)\n\};", self.JS, re.S).group(1)
        fields = dict(re.findall(r"(\w+):\s*'(fq-[\w-]+)'", block))
        for param, ident in (("encryption_off", "fq-encoff"),
                             ("security_gt", "fq-security")):
            self.assertEqual(fields.get(param), ident)
            self.assertRegex(self.HTML, r'id="%s"' % re.escape(ident))

    def test_the_result_table_has_a_sortable_security_column(self):
        self.assertIn('data-col="security"', self.JS)
        self.assertIn("security: (d.security == null ? -1 : d.security)", self.JS)

    def test_the_print_page_shows_the_column_too(self):
        js = (ROOT / "server/html/static/js/fleet-query.js").read_text()
        self.assertIn("<th>Security</th>", js)
        self.assertIn("d.security", js)


if __name__ == "__main__":
    unittest.main()
