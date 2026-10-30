#!/usr/bin/env python3
"""7.4.6: hostile input to what the release added, through the real functions.

The release added five things that read or write something an outsider can influence: a request that asks a
host to report (any signed-in user may resolve an alert), a host's own heartbeat, the setting that keeps CVE
alerts quiet, the OSV record behind a CVE finding, and the stores the Thermal page, the risk score and the
suggested dependencies read. Each is held here with the input that would break it, and each test names the
failure it stops.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin  # noqa: E402,F401
from test_v746_cve_fix_status import _Alerts, finding  # noqa: E402
from test_v746_cve_fix_status import api as api_cve  # noqa: E402
from test_v746_drive_lines_thermal import HDD, NOW, _Fleet  # noqa: E402
from test_v746_drive_lines_thermal import api as api_fleet  # noqa: E402
from test_v746_resolve_refresh import _Resolve, alert  # noqa: E402
from test_v746_resolve_refresh import api as api_resolve  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "server/html/static/js/app.js"
CVE_JS = ROOT / "server/html/static/js/app-cve.js"


class TestWhoCanAskAHostToReport(_Resolve):

    def setUp(self):
        super().setUp()
        saved = {n: getattr(api_resolve, n) for n in ("_caller_scope", "_tenant_gate")}
        self.addCleanup(lambda: [setattr(api_resolve, n, v) for n, v in saved.items()])

    def forced_at(self):
        api_resolve._LOAD_CACHE.clear()
        return (api_resolve.load(api_resolve.DEVICES_FILE) or {})[DEV].get("sysinfo_forced_at")

    def test_a_viewer_may_resolve_by_default_and_cannot_make_a_host_report_more_than_once_in_the_cool_down(self):
        api_resolve.verify_token = lambda t: ("viewer1", "viewer")
        api_resolve.save(api_resolve.ALERTS_FILE, {"alerts": [alert("a1")]})
        api_resolve._LOAD_CACHE.clear()
        self.assertEqual(self.resolve("a1"), 200)
        first = self.forced_at()
        self.assertTrue(self.heartbeat().get("force_sysinfo"), "the first request is delivered")
        answers = []
        for _ in range(20):                                  # reopen, resolve, and let the host beat in between
            with api_resolve._LockedUpdate(api_resolve.ALERTS_FILE) as store:
                for a in store["alerts"]:
                    a.pop("resolved_at", None)
            api_resolve._LOAD_CACHE.clear()
            self.assertEqual(self.resolve("a1"), 200)
            answers.append(self.heartbeat().get("force_sysinfo"))
        self.assertEqual(self.forced_at(), first, "the host was asked again inside the cool-down")
        self.assertEqual(answers, [None] * 20, "a beat carried a request inside the cool-down")

    def test_where_the_install_keeps_alert_changes_to_administrators_a_viewer_asks_nothing(self):
        api_resolve.save(api_resolve.CONFIG_FILE, {"viewers_can_ack_alerts": False})
        api_resolve._LOAD_CACHE.clear()
        api_resolve.verify_token = lambda t: ("viewer1", "viewer")
        self.assertEqual(self.resolve("a1"), 403)
        self.assertEqual(self.requested(), [])

    def test_bulk_resolve_is_for_administrators_only(self):
        api_resolve.verify_token = lambda t: ("viewer1", "viewer")
        self.assertEqual(self.bulk(["a1", "a2"]), 403)
        self.assertEqual(self.requested(), [])

    def test_a_caller_scoped_to_one_group_cannot_ask_a_host_of_another(self):
        with api_resolve._LockedUpdate(api_resolve.DEVICES_FILE) as devs:
            devs[DEV]["group"] = "B"
            devs["d2"]["group"] = "A"
        api_resolve._LOAD_CACHE.clear()
        api_resolve._caller_scope = lambda: {"type": "groups", "values": ["A"]}
        api_resolve._alert_mutable_by_caller = self._saved["_alert_mutable_by_caller"]    # the real rule, not the stand-in
        self.assertEqual(self.resolve("a1"), 404)                                  # a host in group B
        self.assertEqual(self.requested(), [])
        self.assertEqual(self.resolve("a2"), 200)                                  # a host in group A
        self.assertEqual(self.requested(), ["d2"])

    def test_a_caller_of_one_tenant_cannot_ask_a_host_of_another(self):
        with api_resolve._LockedUpdate(api_resolve.DEVICES_FILE) as devs:
            devs[DEV]["tenant"] = "tenant-b"
            devs["d2"]["tenant"] = "tenant-a"
        api_resolve._LOAD_CACHE.clear()
        api_resolve._tenant_gate = lambda: "tenant-a"
        api_resolve._alert_mutable_by_caller = self._saved["_alert_mutable_by_caller"]
        self.assertEqual(self.resolve("a1"), 404)
        self.bulk(["a1", "a2"])
        self.assertEqual(self.requested(), ["d2"])



class TestAHostCannotAskForItself(_Resolve):

    def test_a_heartbeat_that_carries_the_request_does_not_leave_one(self):
        raw = json.dumps({"device_id": DEV, "token": "tok", "force_sysinfo": True, "sysinfo_forced_at": 1,
                          "sysinfo": {"force_sysinfo": True}}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        stubs = {n: getattr(api_resolve, n) for n in ("verify_token", "get_token_from_request", "method", "get_json_body")}
        for n in stubs:
            setattr(api_resolve, n, self._saved[n])
        api_resolve.sys.stdin = _Stdin(raw)
        api_resolve._LOAD_CACHE.clear()
        body = None
        try:
            api_resolve.handle_heartbeat()
        except _Captured as c:
            body = c.body
        finally:
            for n, v in stubs.items():
                setattr(api_resolve, n, v)
        self.assertNotIn("force_sysinfo", body)
        api_resolve._LOAD_CACHE.clear()
        stored = (api_resolve.load(api_resolve.DEVICES_FILE) or {})[DEV]
        self.assertNotIn("force_sysinfo", stored)
        self.assertNotEqual(stored.get("sysinfo_forced_at"), 1)


class TestTheOptionTakesOnlyTrueOrFalse(_Alerts):

    def save(self, value):
        api_cve.method = lambda: "POST"
        api_cve.get_json_body = lambda: {"cve_alert_fixable_only": value}
        self.call(api_cve.handle_config_save)
        api_cve._LOAD_CACHE.clear()
        return self.cap.get("s")

    def test_a_string_that_reads_like_false_does_not_turn_it_on(self):
        """bool("false") is True. A client that meant off must not silence alerts by accident."""
        for value in ("false", "0", "no", "off", "", "True", 1, 0, 2.5, None, [], [1], {}, {"a": 1}):
            self.option(False)
            self.assertEqual(self.save(value), 400, repr(value))
            self.assertIs(api_cve.get_cve_alert_fixable_only(), False, repr(value))
            self.option(True)
            self.assertEqual(self.save(value), 400, repr(value))
            self.assertIs(api_cve.get_cve_alert_fixable_only(), True, f"{value!r} turned it off")

    def test_the_refusal_is_a_sentence_the_dashboard_can_translate(self):
        self.save("false")
        self.assertEqual(self.cap["b"], {"error": "cve_alert_fixable_only must be true or false"})

    def test_a_real_true_or_false_still_works(self):
        self.assertEqual(self.save(True), 200)
        self.assertIs(api_cve.get_cve_alert_fixable_only(), True)
        self.assertEqual(self.save(False), 200)
        self.assertIs(api_cve.get_cve_alert_fixable_only(), False)

    def test_a_viewer_cannot_change_it(self):
        api_cve.require_auth = self._orig["require_auth"]
        api_cve.require_admin_auth = self._orig["require_admin_auth"]
        api_cve.verify_token = lambda t: ("viewer1", "viewer")
        self.option(False)
        self.assertEqual(self.save(True), 403)
        self.assertIs(api_cve.get_cve_alert_fixable_only(), False)


class TestTheCveRecordIsInput(_Alerts):
    """What OSV answers is a public feed's word. It reaches the page, so it is escaped there, and a
    stored finding of any shape does not fail the report."""

    HOSTILE = [
        finding("A", status={"x": 1}),
        finding("B", status=["newer_release"]),
        finding("C", status=7),
        finding("D", status="x" * 5000),
        finding("E", status="newer_release", fixed_elsewhere="not a map"),
        finding("F", status="newer_release", fixed_elsewhere={"Debian:13": {"v": 1}, "5": "x"}),
        finding("G", status="fixed", fixed="1" * 100000),
        "not a finding", None, 12, [],
    ]

    def setUp(self):
        super().setUp()
        api_cve.method = lambda: "GET"
        api_cve.save(api_cve.PACKAGES_FILE, {"d1": {"ecosystem": "Debian:12", "count": 1}})
        api_cve.save(api_cve.CVE_FINDINGS_FILE, {"d1": {"scanned_at": 5, "findings": self.HOSTILE}})
        api_cve._LOAD_CACHE.clear()

    def test_a_stored_finding_of_any_shape_does_not_fail_the_report(self):
        report = self.call(api_cve.handle_cve_findings)
        self.assertEqual(self.cap.get("s"), 200)
        self.assertEqual(sum(report["summary"]["fix"].values()), sum(1 for f in self.HOSTILE if isinstance(f, dict)))

    def test_a_stored_finding_of_any_shape_does_not_fail_the_host_view(self):
        try:
            self.call(lambda: api_cve.handle_cve_device("d1"))
        except TypeError:
            self.fail("the host view raised on a finding that is not a map")
        self.assertEqual(self.cap.get("s"), 200)

    def test_the_alert_path_reads_such_findings_without_raising(self):
        self.option(True)
        api_cve._detect_new_cve_and_fire_webhook("d1", {"d1": {"name": "web"}}, self.HOSTILE, self.HOSTILE)

    def run_page(self, finding_json):
        """_cveFixHtml and escHtml, the page's own functions, run under node on one finding."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        # escHtml is one line of regular expressions with quotes in them, which srcpin's scanner cannot bound
        esc = re.search(r"^function escHtml\(s\) \{.*\}$", APP_JS.read_text(), re.M)
        self.assertIsNotNone(esc, "escHtml moved: find it again")
        script = (esc.group(0) + "\n"
                  + srcpin.js_function(CVE_JS.read_text(), "_cveFixHtml") + "\n"
                  + "console.log(_cveFixHtml(JSON.parse(process.argv[1])));\n")
        done = subprocess.run([node, "-e", script, finding_json], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_markup_in_a_fixed_version_or_a_release_name_is_text_on_the_page(self):
        evil = '"><img src=x onerror=alert(1)><script>alert(2)</script>'
        for case in (
            {"fix_status": "fixed", "fixed_version": evil},
            {"fix_status": "newer_release", "fixed_elsewhere": {evil: evil}},
            {"fix_status": "newer_release", "fixed_elsewhere": {"Debian:13": evil, "Debian:14": evil}},
            {"fix_status": "none"},
            {"fixed_version": evil},
        ):
            html = self.run_page(json.dumps(case))
            self.assertNotIn("<img", html, case)
            self.assertNotIn("<script", html, case)
            self.assertNotIn('"><', html, case)

    def test_the_page_check_can_fail(self):
        """The control: the same hostile value in an unescaped template must show up."""
        html = self.run_page(json.dumps({"fix_status": "fixed", "fixed_version": "<b>"}))
        self.assertIn("&lt;b&gt;", html)


class TestTheThermalReadsHostileStores(_Fleet):

    def test_a_host_whose_lines_are_not_maps_still_gets_a_page_and_a_score(self):
        for junk in ("x", ["a"], 5, {"drivetemp_per_serial": "x"}, {"drivetemp_per_serial": ["a"]},
                     {"drivetemp_per_serial": {"SER-HDD": "x"}}, {"drivetemp_per_serial": {"SER-HDD": {"warn": "z", "crit": []}}},
                     {"drivetemp_warn_c": "hot", "drivetemp_hdd_crit_c": 10**400}):
            self.fleet({"h1": ([HDD], [], None)})
            devs = api_fleet.load(api_fleet.DEVICES_FILE)
            devs["h1"]["metric_thresholds"] = junk
            api_fleet.save(api_fleet.DEVICES_FILE, devs)
            api_fleet._LOAD_CACHE.clear()
            row = self.row()
            self.assertEqual((row["hot"], row["critical"]), (False, False), junk)
            self.assertEqual(self.risk(), [], junk)

    def test_a_drive_entry_that_is_not_a_map_or_has_no_serial_is_skipped_or_judged_by_the_fleet(self):
        hw = {"h1": {"ts": NOW, "smart": ["x", None, {"device": "/dev/sdz", "temperature_c": 80}, {"temperature_c": "hot"}],
                     "hardware": {"temps": []}}}
        self.fleet({"h1": ([], [], None)})
        api_fleet.save(api_fleet.HARDWARE_FILE, hw)
        api_fleet._LOAD_CACHE.clear()
        try:
            row = self.row()
        except AssertionError:
            self.fail("a drive that is not a map removed the host from the page")
        self.assertEqual((row["hot"], row["critical"]), (True, False))


class TestTheSuggestionsReadHostileStores(_Alerts):

    def test_a_row_that_is_not_a_whole_peer_does_not_fail_the_page(self):
        api_cve.verify_token = lambda t: ("jakob", "admin")
        api_cve.save(api_cve.DEVICES_FILE, {"a": {"name": "a", "ip": "10.0.0.1"}, "b": {"name": "b", "ip": "10.0.0.2"}})
        for rows in ([{"ip": "10.0.0.2", "port": "x", "count": 1}], ["junk", 5, None, []], [{"ip": "10.0.0.2", "port": 9, "count": "z"}],
                     [{"ip": "10.0.0.2", "port": None}], {"not": "a list"}, "text"):
            api_cve.save(api_cve.PEER_CONNS_FILE, {"a": {"ts": 1, "peers": rows}, "b": "not a map"})
            api_cve._LOAD_CACHE.clear()
            try:
                out = api_cve._dependency_suggestions()
            except Exception as e:
                self.fail(f"{rows!r}: {type(e).__name__}: {e}")
            self.assertIsInstance(out, list)

    def test_the_rows_that_are_whole_are_still_suggested(self):
        api_cve.verify_token = lambda t: ("jakob", "admin")
        api_cve.save(api_cve.DEVICES_FILE, {"a": {"name": "a", "ip": "10.0.0.1"}, "b": {"name": "b", "ip": "10.0.0.2"}})
        api_cve.save(api_cve.PEER_CONNS_FILE, {"a": {"ts": 1, "peers": ["junk", {"ip": "10.0.0.2", "port": 5432, "count": 2}]}})
        api_cve._LOAD_CACHE.clear()
        self.assertEqual([(s["device_id"], s["upstream_id"], s["ports"]) for s in api_cve._dependency_suggestions()],
                         [("a", "b", [5432])])


if __name__ == "__main__":
    unittest.main()
