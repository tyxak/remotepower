#!/usr/bin/env python3
"""7.4.9: a custom monitoring script can be read as a Nagios-style plugin: four states and performance data.

The scripts page said it out loud: "this is a binary signal, not MRPE's four-level severity". A plugin that reports a
warning (exit 1) was a failure, and a check_disk or an NRPE command, which print `TEXT | label=value;warn;crit`, could
not be used without a wrapper. A script now has a mode. In `nagios` mode the exit code is the state (0 ok, 1 warning,
2 critical, 3 or anything else unknown), the first line is the status text, and the performance data is kept beside it.
Every other script is read exactly as before.

Three layers, each driven for real: the pure reader (nagios_result), the heartbeat's ingest with the alert ledger, and the
pages' data (the Checks rows, the results endpoint, Needs attention).
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

import nagios_result as nr  # noqa: E402


class TestTheStates(unittest.TestCase):

    def test_plugin_mode_has_four_states(self):
        got = {rc: nr.state_for(rc, "nagios") for rc in (0, 1, 2, 3, 4, 127, -1, 255)}
        self.assertEqual(got, {0: "ok", 1: "warning", 2: "critical", 3: "unknown", 4: "unknown", 127: "unknown",
                               -1: "unknown", 255: "unknown"})

    def test_the_default_mode_has_two_and_failure_is_critical(self):
        self.assertEqual([nr.state_for(rc, "exit") for rc in (0, 1, 2, 3, -1)], ["ok", "critical", "critical", "critical", "critical"])

    def test_a_non_number_is_unknown_in_plugin_mode_and_a_failure_otherwise(self):
        for junk in (None, "0", 0.0, True, [], {}):
            self.assertEqual(nr.state_for(junk, "nagios"), "unknown", junk)
            self.assertEqual(nr.state_for(junk, "exit"), "critical", junk)

    def test_mode_text_from_a_client_is_cleaned(self):
        self.assertEqual(nr.clean_mode("nagios"), "nagios")
        self.assertEqual(nr.clean_mode("  NAGIOS "), "nagios")
        for other in ("", None, "exit", "plugin", 5, ["nagios"], "nagios; rm -rf /"):
            self.assertEqual(nr.clean_mode(other), "exit", other)


class TestThePerformanceData(unittest.TestCase):

    def test_the_example_of_the_convention(self):
        text, perf = nr.parse_output("DISK OK - free space: / 3326 MB (56%);| /=2643MB;5948;5958;0;5968")
        self.assertEqual(text, "DISK OK - free space: / 3326 MB (56%);")
        self.assertEqual(perf, [{"label": "/", "value": 2643.0, "uom": "MB", "warn": "5948", "crit": "5958",
                                 "min": 0.0, "max": 5968.0}])

    def test_several_items_a_unit_and_no_unit(self):
        _t, perf = nr.parse_output("OK | time=0.05s;0.5;1;0 size=1024B load=0.7 pct=33%;80;90")
        self.assertEqual([(p["label"], p["value"], p["uom"]) for p in perf],
                         [("time", 0.05, "s"), ("size", 1024.0, "B"), ("load", 0.7, ""), ("pct", 33.0, "%")])

    def test_a_label_with_spaces_is_quoted_and_a_doubled_quote_is_one(self):
        _t, perf = nr.parse_output("OK | 'free space'=12MB 'it''s'=1 plain=2")
        self.assertEqual([p["label"] for p in perf], ["free space", "it's", "plain"])

    def test_ranges_stay_as_the_plugin_wrote_them(self):
        _t, perf = nr.parse_output("OK | a=5;10:20;~:30 b=1;@3:4;")
        self.assertEqual((perf[0]["warn"], perf[0]["crit"]), ("10:20", "~:30"))
        self.assertEqual((perf[1]["warn"], perf[1]["crit"]), ("@3:4", ""))

    def test_unknown_negative_and_exponent_values(self):
        _t, perf = nr.parse_output("OK | u=U t=-4.5C e=1.5e3ms")
        self.assertIsNone(perf[0]["value"])
        self.assertEqual((perf[1]["value"], perf[1]["uom"]), (-4.5, "C"))
        self.assertEqual((perf[2]["value"], perf[2]["uom"]), (1500.0, "ms"))

    def test_what_cannot_be_read_is_left_out(self):
        _t, perf = nr.parse_output("OK | nolabel =3 =5 good=1 bad=abc inf=inf nan=nan big=1e999 huge=1e30 x=1;;;;")
        self.assertEqual([p["label"] for p in perf], ["good", "x"])

    def test_the_item_count_the_label_and_the_thresholds_are_cut(self):
        many = " ".join(f"m{i}={i}" for i in range(50))
        self.assertEqual(len(nr.parse_output("OK | " + many)[1]), nr.MAX_PERF_ENTRIES)
        _t, perf = nr.parse_output("OK | " + "L" * 500 + "=1;" + "9" * 500 + ";" + "8" * 500)
        self.assertEqual(len(perf[0]["label"]), nr.MAX_LABEL)
        self.assertEqual(len(perf[0]["warn"]), nr.MAX_THRESHOLD)
        self.assertEqual(len(perf[0]["crit"]), nr.MAX_THRESHOLD)

    def test_long_output_can_carry_more_performance_data(self):
        text, perf = nr.parse_output("WARN - 2 things | a=1\nline two\nline three | b=2 c=3\n")
        self.assertEqual(text, "WARN - 2 things")
        self.assertEqual([p["label"] for p in perf], ["a", "b", "c"])

    def test_no_bar_means_no_performance_data(self):
        self.assertEqual(nr.parse_output("everything is fine"), ("everything is fine", []))

    def test_leading_blank_lines_crlf_and_the_status_cap(self):
        text, perf = nr.parse_output("\r\n\r\nSTATUS here | x=1\r\n" + "z" * 100)
        self.assertEqual((text, perf[0]["label"]), ("STATUS here", "x"))
        self.assertEqual(len(nr.parse_output("x" * 5000)[0]), nr.MAX_TEXT)

    def test_hostile_input_never_raises(self):
        for text in (None, "", "|", "||||", "'", "'''", "=", "a=;;;;;;", "x=1;" * 1000, "\x00|\x00=\x00", "é=ü;ö;ß",
                     "'unterminated=1 b=2", ("a=1 " * 100000)[:200000], 5, [1], {"a": 1}):
            status, perf = nr.parse_output(text)
            self.assertIsInstance(status, str)
            self.assertLessEqual(len(perf), nr.MAX_PERF_ENTRIES)
        self.assertEqual(nr.parse_perfdata(None), [])
        self.assertEqual(nr.parse_perfdata(12), [])


DEV = "d1"


def result(rc, text="", ok=None):
    return {"ok": rc == 0 if ok is None else ok, "output": text, "rc": rc, "ran_at": int(time.time()), "duration_ms": 5}


class _Ingest(_Base):
    STORES = _Base.STORES + ("CUSTOM_SCRIPTS_FILE", "ALERTS_FILE", "FLEET_EVENTS_FILE", "ALERT_MUTES_FILE")

    def setUp(self):
        super().setUp()
        api.save(api.CUSTOM_SCRIPTS_FILE, {
            "sP": {"id": "sP", "name": "disk plugin", "body": "x", "assigned_devices": [DEV], "mode": "nagios"},
            "sB": {"id": "sB", "name": "plain check", "body": "x", "assigned_devices": [DEV]}})
        api.save(api.ALERTS_FILE, {"alerts": []})
        devs = api.load(api.DEVICES_FILE)
        devs[DEV] = {"name": "box", "tenant": "default", "token_hash": "x", "last_seen": int(time.time()), "monitored": True}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.fired = []
        self._real_fire = api.fire_webhook

        def spy(event, payload):
            self.fired.append((event, dict(payload)))
            return self._real_fire(event, payload)
        api.fire_webhook = spy

    def tearDown(self):
        api.fire_webhook = self._real_fire
        super().tearDown()

    def report(self, sid, rc, text=""):
        api._ingest_custom_script_results(DEV, "box", {sid: result(rc, text)})
        api._LOAD_CACHE.clear()

    def stored(self, sid):
        return api.load(api.DEVICES_FILE)[DEV]["custom_script_results"][sid]

    def events(self, name):
        return [p for e, p in self.fired if e == name]

    def open_alerts(self):
        api._LOAD_CACHE.clear()
        return [a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]


class TestTheIngestOfAPlugin(_Ingest):

    def test_the_first_result_alerts_nobody_and_is_stored_with_its_state_and_data(self):
        self.report("sP", 1, "DISK WARNING - 18% free | /=17988MB;19000;20000;0;22000")
        self.assertEqual(self.fired, [])
        r = self.stored("sP")
        self.assertEqual((r["state"], r["ok"], r["mode"], r["rc"]), ("warning", False, "nagios", 1))
        self.assertEqual(r["status_text"], "DISK WARNING - 18% free")
        self.assertEqual(r["perf"][0]["label"], "/")
        self.assertEqual(r["perf"][0]["value"], 17988.0)

    def test_ok_to_warning_to_critical_to_ok(self):
        self.report("sP", 0, "DISK OK | /=1MB")
        self.report("sP", 1, "DISK WARNING - 18% free | /=18000MB")
        warn = self.events("custom_script_fail")
        self.assertEqual(len(warn), 1)
        self.assertEqual((warn[0]["state"], warn[0]["output"], warn[0]["rc"]), ("warning", "DISK WARNING - 18% free", 1))
        rows = self.open_alerts()
        self.assertEqual((len(rows), rows[0]["severity"]), (1, "medium"))
        self.assertIn("warning on box: disk plugin", rows[0]["title"])
        self.assertEqual(rows[0]["payload"]["state"], "warning")

        self.report("sP", 2, "DISK CRITICAL - 3% free | /=21000MB")
        self.assertEqual(len(self.events("custom_script_fail")), 2)
        rows = self.open_alerts()
        self.assertEqual(len(rows), 1, "the second failing state joins the open alert")
        self.assertEqual(rows[0]["severity"], "high", "and raises it")
        self.assertEqual(rows[0]["payload"]["state"], "critical")

        self.report("sP", 0, "DISK OK | /=1MB")
        self.assertEqual(len(self.events("custom_script_recover")), 1)
        self.assertEqual(self.open_alerts(), [])
        self.assertEqual(self.stored("sP")["state"], "ok")

    def test_the_same_state_again_fires_nothing_new(self):
        self.report("sP", 0, "OK")
        self.report("sP", 2, "CRIT")
        self.report("sP", 2, "CRIT again")
        self.report("sP", 2, "CRIT still")
        self.assertEqual(len(self.events("custom_script_fail")), 1)

    def test_a_script_that_could_not_run_is_unknown_and_medium(self):
        self.report("sP", 0, "OK")
        api._ingest_custom_script_results(DEV, "box", {"sP": {"ok": False, "output": "EXEC ERROR: boom", "rc": -1,
                                                                 "ran_at": int(time.time()), "duration_ms": 1}})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.stored("sP")["state"], "unknown")
        fail = self.events("custom_script_fail")
        self.assertEqual(fail[0]["state"], "unknown")
        self.assertEqual(self.open_alerts()[0]["severity"], "medium")

    def test_changed_at_moves_when_the_state_moves_between_failing_states(self):
        self.report("sP", 1, "W")
        first = self.stored("sP")["changed_at"]
        # force the stored time back so a move is visible
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["custom_script_results"]["sP"]["changed_at"] = first - 1000
        self.report("sP", 1, "W")
        self.assertEqual(self.stored("sP")["changed_at"], first - 1000)
        self.report("sP", 2, "C")
        self.assertGreater(self.stored("sP")["changed_at"], first - 1000)

    def test_the_status_text_not_the_whole_output_is_what_the_alert_says(self):
        self.report("sP", 0, "OK")
        self.report("sP", 2, "CRITICAL - 3% free | /=1MB;2;3\nlong output line one\nline two")
        self.assertEqual(self.events("custom_script_fail")[0]["output"], "CRITICAL - 3% free")


class TestTheOtherScriptsAreReadAsBefore(_Ingest):

    def test_exit_one_is_a_failure_with_no_state_in_the_alert(self):
        self.report("sB", 0, "fine")
        self.report("sB", 1, "broken")
        fail = self.events("custom_script_fail")
        self.assertEqual(len(fail), 1)
        self.assertNotIn("state", fail[0])
        self.assertEqual(fail[0]["output"], "broken")
        rows = self.open_alerts()
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["title"], "Custom script failed on box: plain check")

    def test_the_stored_result_has_no_plugin_fields(self):
        self.report("sB", 3, "x | y=1")
        r = self.stored("sB")
        self.assertEqual((r["ok"], r["state"], r["rc"]), (False, "critical", 3))
        self.assertNotIn("perf", r)
        self.assertNotIn("status_text", r)
        self.assertNotIn("mode", r)

    def test_recovery_still_resolves_and_a_second_failure_does_not_stack(self):
        self.report("sB", 0)
        self.report("sB", 1)
        self.report("sB", 2)        # failing both times: same state to the two-state reading, no new alert
        self.assertEqual(len(self.events("custom_script_fail")), 1)
        self.report("sB", 0)
        self.assertEqual(self.open_alerts(), [])

    def test_a_result_stored_before_states_existed_still_recovers(self):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["custom_script_results"] = {"sB": {"ok": False, "output": "old", "rc": 1, "ran_at": 1}}
        self.report("sB", 0)
        self.assertEqual(len(self.events("custom_script_recover")), 1)

    def test_a_mode_that_the_definition_does_not_name_is_the_default(self):
        s = api.load(api.CUSTOM_SCRIPTS_FILE)
        s["sB"]["mode"] = "bogus; drop table"
        api.save(api.CUSTOM_SCRIPTS_FILE, s)
        api._LOAD_CACHE.clear()
        self.report("sB", 1, "x")
        self.assertNotIn("mode", self.stored("sB"))


class TestThePages(_Ingest):

    def test_the_checks_row_of_a_plugin_has_its_state_and_its_status_text(self):
        self.report("sP", 1, "DISK WARNING - 18% free | /=1MB\nsome long output")
        dev = api.load(api.DEVICES_FILE)[DEV]
        rows = {c["key"]: c for c in api._host_checks(DEV, dev, {}, [], int(time.time()), 180,
                                                      scripts=api.load(api.CUSTOM_SCRIPTS_FILE))}
        self.assertEqual(rows["script:sP"]["status"], "warning")
        self.assertEqual(rows["script:sP"]["output"], "DISK WARNING - 18% free")

    def test_the_checks_row_of_a_two_state_script_is_unchanged(self):
        self.report("sB", 1, "line1\nFAILED: disk")
        dev = api.load(api.DEVICES_FILE)[DEV]
        rows = {c["key"]: c for c in api._host_checks(DEV, dev, {}, [], int(time.time()), 180,
                                                      scripts=api.load(api.CUSTOM_SCRIPTS_FILE))}
        self.assertEqual(rows["script:sB"]["status"], "critical")
        self.assertEqual(rows["script:sB"]["output"], "FAILED: disk")

    def test_the_results_endpoint_carries_state_mode_and_data(self):
        self.report("sP", 2, "CRIT - bad | a=1;2;3 b=U")
        self.report("sB", 1, "bad")
        st, d = self.call(api.handle_custom_scripts_results, m="GET", who="platform")
        self.assertEqual(st, 200, d)
        by = {r["script_id"]: r for r in d["results"]}
        self.assertEqual((by["sP"]["state"], by["sP"]["mode"], by["sP"]["status_text"]), ("critical", "nagios", "CRIT - bad"))
        self.assertEqual([p["label"] for p in by["sP"]["perf"]], ["a", "b"])
        self.assertEqual((by["sB"]["state"], by["sB"]["mode"], by["sB"]["perf"]), ("critical", "exit", []))
        self.assertEqual({s["id"]: s["mode"] for s in d["scripts"]}, {"sP": "nagios", "sB": "exit"})

    def test_critical_sorts_before_unknown_before_warning_before_ok(self):
        for sid, rc in (("sP", 1),):
            self.report(sid, rc, "w")
        self.report("sB", 0, "fine")
        st, d = self.call(api.handle_custom_scripts_results, m="GET", who="platform")
        self.assertEqual([r["state"] for r in d["results"]], ["warning", "ok"])

    def test_needs_attention_says_which_failing_state_and_ranks_critical_higher(self):
        self.report("sP", 0, "OK")
        self.report("sP", 2, "CRIT")
        self.report("sB", 0, "fine")
        self.report("sB", 1, "bad")
        items = [i for i in api._compute_attention() if i.get("kind") == "custom_script_fail"]
        by = {i["severity"]: i["summary"] for i in items}
        self.assertEqual(sorted(by), ["critical", "warning"])
        self.assertIn("CRITICAL", by["critical"])
        self.assertIn("failed", by["warning"])

    def test_muting_the_alert_hides_the_critical_item_as_well(self):
        # the warning item was always muteable; the critical one a plugin can now raise needs its own _NA_MUTE_EVENTS row,
        # or muting the alert stops the message and leaves the item (and the host's health score) where it was
        self.report("sP", 2, "CRIT")
        shown = lambda: [i for i in api._compute_attention() if i.get("kind") == "custom_script_fail"]
        self.assertEqual([i["severity"] for i in shown()], ["critical"])
        api.save(api.ALERT_MUTES_FILE, {"mutes": [{"id": "m1", "device_id": DEV, "event": "custom_script_fail"}]})
        api._ALERT_MUTE_SET_CACHE["mtime"] = None
        self.assertEqual(shown(), [])

    def test_the_script_list_and_the_definition_carry_the_mode(self):
        st, d = self.call(api.handle_custom_scripts_list, m="GET", who="platform")
        self.assertEqual({s["id"]: s["mode"] for s in d["scripts"]}, {"sP": "nagios", "sB": "exit"})


class TestCreatingAndEditing(_Ingest):

    def test_a_script_is_created_in_plugin_mode_and_can_be_changed_back(self):
        st, d = self.call(api.handle_custom_script_create, body={"name": "n", "body": "echo hi", "mode": "nagios"}, who="platform")
        self.assertEqual(st, 201, d)
        self.assertEqual(d["mode"], "nagios")
        sid = d["id"]
        st, d = self.call(api.handle_custom_script_update, sid, body={"mode": "exit"}, m="PUT", who="platform")
        self.assertEqual((st, d["mode"]), (200, "exit"))
        st, d = self.call(api.handle_custom_script_update, sid, body={"mode": "nagios"}, m="PUT", who="platform")
        self.assertEqual(d["mode"], "nagios")

    def test_a_script_created_without_a_mode_is_pass_or_fail(self):
        st, d = self.call(api.handle_custom_script_create, body={"name": "n", "body": "echo hi"}, who="platform")
        self.assertEqual((st, d["mode"]), (201, "exit"))

    def test_an_update_without_a_mode_leaves_it_alone(self):
        st, d = self.call(api.handle_custom_script_update, "sP", body={"description": "d"}, m="PUT", who="platform")
        self.assertEqual((st, d["mode"]), (200, "nagios"))

    def test_junk_in_the_mode_field_is_the_default_not_an_error(self):
        for junk in (None, 5, ["nagios"], {"a": 1}, "NaGiOs\x00"):
            st, d = self.call(api.handle_custom_script_create, body={"name": "j", "body": "echo", "mode": junk}, who="platform")
            self.assertIn(st, (201, 400), junk)
            if st == 201:
                self.assertEqual(d["mode"], "exit", junk)
            api.save(api.CUSTOM_SCRIPTS_FILE, {k: v for k, v in api.load(api.CUSTOM_SCRIPTS_FILE).items() if k in ("sP", "sB")})


class TestThePrometheusFamilies(_Ingest):
    """The state of every script result and the performance values of a plugin reach /api/metrics."""

    def scrape(self, visible=None):
        import prometheus_export
        api._LOAD_CACHE.clear()
        return prometheus_export.generate_metrics(api._build_metrics_ctx(visible)).splitlines()

    def test_state_and_values_are_exported_with_the_script_id(self):
        self.report("sP", 1, "DISK WARNING | /=17988MB;19000;20000;0;22000 inodes=41%")
        self.report("sB", 2, "bad")
        lines = self.scrape()
        state = {ln.split("}")[0].split('script_id="')[1].split('"')[0]: ln.rsplit(" ", 1)[1]
                 for ln in lines if ln.startswith("remotepower_script_state{")}
        self.assertEqual(state, {"sP": "1", "sB": "2"})
        perf = [ln for ln in lines if ln.startswith("remotepower_script_perf_value{")]
        self.assertEqual(len(perf), 2)
        self.assertTrue(any('label="/"' in ln and 'unit="MB"' in ln and ln.endswith(" 17988.0") for ln in perf), perf)
        self.assertTrue(any('label="inodes"' in ln and 'unit="%"' in ln and ln.endswith(" 41.0") for ln in perf), perf)
        # the two-state script has a state and no values
        self.assertFalse(any('script_id="sB"' in ln for ln in perf))

    def test_a_label_printed_twice_is_two_series_not_one_dropped(self):
        self.report("sP", 0, "OK | a=1 a=2 a=3")
        perf = [ln for ln in self.scrape() if ln.startswith("remotepower_script_perf_value{")]
        self.assertEqual(sorted(ln.split('label="')[1].split('"')[0] for ln in perf), ["a", "a #2", "a #3"])

    def test_unknown_values_and_junk_never_reach_the_scrape(self):
        self.report("sP", 0, "OK | u=U good=5")
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["custom_script_results"]["sP"]["perf"] += [
                {"label": "nan", "value": "NaN"}, {"label": "inf", "value": "Infinity"},
                {"label": "text", "value": "abc"}, {"label": "huge", "value": 10 ** 400}, "not a dict", None,
                {"label": 5, "value": "7", "uom": ["x"]}]
        perf = [ln for ln in self.scrape() if ln.startswith("remotepower_script_perf_value{")]
        labels = sorted(ln.split('label="')[1].split('"')[0] for ln in perf)
        self.assertEqual(labels, ["5", "good"])
        for ln in perf:
            self.assertNotIn("nan", ln.rsplit(" ", 1)[1].lower())
            self.assertNotIn("inf", ln.rsplit(" ", 1)[1].lower())

    def test_a_result_with_a_junk_state_falls_back_to_ok_or_critical(self):
        self.report("sB", 1, "bad")
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["custom_script_results"]["sB"]["state"] = ["nope"]
        line = [ln for ln in self.scrape() if ln.startswith("remotepower_script_state{")][0]
        self.assertTrue(line.endswith(" 2"), line)

    def test_a_session_caller_sees_only_its_own_hosts(self):
        self.report("sP", 1, "W | x=1")
        devs = api.load(api.DEVICES_FILE)
        devs["devC"]["custom_script_results"] = {"sP": {"ok": False, "state": "critical", "rc": 2, "output": "",
                                                        "perf": [{"label": "secret", "value": 9.0, "uom": ""}]}}
        api.save(api.DEVICES_FILE, devs)
        out = "\n".join(self.scrape(visible={DEV}))
        self.assertIn(f'device="{DEV}"', out)
        self.assertNotIn("devC", out)
        self.assertNotIn("secret", out)
        # control: the machine scrape (everything visible) does carry it
        self.assertIn("secret", "\n".join(self.scrape()))

    def test_no_definitions_no_families(self):
        api.save(api.CUSTOM_SCRIPTS_FILE, {})
        self.assertFalse([ln for ln in self.scrape() if "remotepower_script_" in ln])


class TestTheWords(unittest.TestCase):

    def test_the_editor_and_the_page_know_the_modes(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "server", "html", "index.html"), encoding="utf-8") as f:
            html = f.read()
        with open(os.path.join(root, "server", "html", "static", "js", "app-hostconfig.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertTrue('id="cs-modal-mode"' in html and 'value="nagios"' in html)
        for token in ("_csStateBadge", "_csPerfHtml", "assigned_devices: assigned, mode }", "cs-modal-mode"):
            self.assertTrue(token in js, token)


if __name__ == "__main__":
    unittest.main()
