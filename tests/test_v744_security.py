#!/usr/bin/env python3
"""v7.4.4 security review: what it found, each driven for real and watched failing first, and the properties the
review checked and found to hold, so a later change cannot take them away without a test saying so.

Found
  1. PATCH /api/devices/<id>/metric-thresholds recorded nothing in the audit trail unless the body also changed
     the ignored sensors. A host's lines, now including its drive temperature lines, could be raised until they
     never fire (a critical line of 150 does not) and nothing said who did it or when. The fleet's save, the
     container lines, the disk names and the sensor ignores are all on the trail; this was the one that was not.

Held (checked, and pinned here)
  * Only an administrator can set a host's lines, and a host of another tenant is refused before the handler runs.
  * A host cannot make its own heartbeat fail, or the server keep more than a bounded amount, by what it reports
    about its drives; and a line break in a drive's name does not reach a mail header or a webhook header.
  * Stored lines that are not what the code writes (a hand-edited store) are read without an error.
"""
import copy
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, api  # noqa: E402
from test_v743_security import _Tenancy  # noqa: E402
from test_v744_drive_temp import _Drives, drv  # noqa: E402

import drive_temp as dt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _call_path(handler, path_arg, body, verb):
    """Run a handler that takes a host id, with the auth gates left real (the caller stubs verify_token only)."""
    names = ("get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: box.setdefault("audit", []).append((a, k))

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(path_arg)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class _Hosts(_Tenancy):
    """Two tenants, a platform operator (alice), an admin and a viewer of tenant A, and a host in each tenant."""

    def lines_as(self, user, host, body, verb="PATCH"):
        saved = api.verify_token
        role = api.load(api.USERS_FILE)[user]["role"]
        try:
            api.verify_token = lambda t: (user, role)
            return _call_path(api.handle_device_metric_thresholds, host, body, verb)
        finally:
            api.verify_token = saved

    def stored(self, host="hostA"):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(host, {}).get("metric_thresholds", {})

    def audit(self, box):
        return [(a[0], a[1], (a[2] if len(a) > 2 else k.get("detail", ""))) for a, k in box.get("audit", [])]


# ── 1. the trail ────────────────────────────────────────────────────────────────────────────────────

class TestAChangeToAHostsLinesIsOnTheTrail(_Hosts):

    def test_a_line_that_is_set_names_who_which_host_and_the_number(self):
        box = self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 48, "drivetemp_hdd_crit_c": 53})
        self.assertEqual(box["status"], 200, box)
        rows = self.audit(box)
        self.assertEqual(len(rows), 1, rows)
        actor, action, detail = rows[0]
        self.assertEqual((actor, action), ("alice", "device_metric_thresholds"))
        for needle in ("dev=hostA", "drivetemp_hdd_warn_c=48", "drivetemp_hdd_crit_c=53"):
            self.assertIn(needle, detail)

    def test_a_line_raised_until_it_never_fires_shows_its_number(self):
        """The reason the trail matters: a critical line of 150 silences a drive, and the number is the evidence."""
        box = self.lines_as("tadmin", "hostA", {"drivetemp_crit_c": 150})
        self.assertEqual(box["status"], 200, box)
        (actor, action, detail), = self.audit(box)
        self.assertEqual((actor, action), ("tadmin", "device_metric_thresholds"))
        self.assertIn("drivetemp_crit_c=150", detail)

    def test_a_drives_own_lines_are_counted_and_its_serial_is_not_written(self):
        box = self.lines_as("alice", "hostA", {"drivetemp_per_serial": {"WD-SECRET-1234": {"warn": 45, "crit": 150}}})
        self.assertEqual(box["status"], 200, box)
        (_a, action, detail), = self.audit(box)
        self.assertEqual(action, "device_metric_thresholds")
        self.assertIn("drivetemp_per_serial=1", detail)
        self.assertNotIn("WD-SECRET-1234", detail, "a count, not the identifiers")

    def test_taking_a_line_away_is_recorded_too(self):
        self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 48})
        box = self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": None})
        (_a, _action, detail), = self.audit(box)
        self.assertIn("cleared=drivetemp_hdd_warn_c", detail)

    def test_a_reset_is_recorded_with_how_many_lines_it_removed(self):
        self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 48, "diskio_warn_percent": 70})
        box = self.lines_as("alice", "hostA", {}, verb="DELETE")
        self.assertEqual(box["status"], 200, box)
        (actor, action, detail), = self.audit(box)
        self.assertEqual((actor, action), ("alice", "device_metric_thresholds"))
        self.assertIn("cleared=diskio_warn_percent,drivetemp_hdd_warn_c", detail)
        self.assertEqual(self.stored(), {})

    def test_the_other_thresholds_are_on_the_trail_as_well(self):
        """The gap was not specific to drives: nothing recorded a change to any of a host's lines."""
        box = self.lines_as("alice", "hostA", {"mem_warn_percent": 60, "mem_crit_percent": 99})
        (_a, action, detail), = self.audit(box)
        self.assertEqual(action, "device_metric_thresholds")
        self.assertIn("mem_crit_percent=99", detail)

    def test_a_refused_change_changes_nothing_and_leaves_no_entry(self):
        box = self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 999})
        self.assertEqual(box["status"], 400)
        self.assertEqual(self.audit(box), [])
        self.assertEqual(self.stored(), {})

    def test_a_save_that_changes_nothing_leaves_no_entry(self):
        self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 48})
        box = self.lines_as("alice", "hostA", {"drivetemp_hdd_warn_c": 48})
        self.assertEqual(box["status"], 200)
        self.assertEqual(self.audit(box), [])

    def test_the_ignored_sensors_are_still_on_the_trail_as_before(self):
        box = self.lines_as("alice", "hostA", {"sensor_ignores": ["board temp3"]})
        actions = [a for _actor, a, _d in self.audit(box)]
        self.assertIn("device_sensor_ignores", actions)

    def test_a_long_change_is_cut_not_dropped(self):
        """The helper alone, with more keys than any real save has: the entry keeps its start and its length."""
        after = {f"drivetemp_key_{i:03d}_c": 100 + i for i in range(60)}
        detail = api._threshold_change_detail({}, after)
        self.assertTrue(detail.startswith("set=drivetemp_key_000_c=100,"), detail[:60])
        self.assertLessEqual(len(detail), 480)
        self.assertGreater(len(detail), 400, "it is cut, not dropped")

    def test_the_helper_says_nothing_when_nothing_changed_and_copes_with_junk(self):
        self.assertEqual(api._threshold_change_detail({"a": 1}, {"a": 1}), "")
        for junk in (None, "x", 5, [], {"a": 1}):
            self.assertIsInstance(api._threshold_change_detail(junk, junk), str)
            self.assertIsInstance(api._threshold_change_detail(junk, {"b": 2.5}), str)
        self.assertEqual(api._threshold_change_detail({"x": True}, {"x": False}), "set=x=False", "a bool is not printed as 0")


# ── held: who may, and which tenant ─────────────────────────────────────────────────────────────────

class TestOnlyAnAdministratorSetsLinesAndATenantStaysInItsOwn(_Hosts):

    def test_a_viewer_of_the_tenant_is_refused(self):
        box = self.lines_as("tviewer", "hostA", {"drivetemp_hdd_warn_c": 40})
        self.assertIn(box["status"], (401, 403), box)
        self.assertEqual(self.stored(), {})
        self.assertEqual(self.audit(box), [])

    def test_a_tenant_admin_can_set_the_lines_of_a_host_of_the_tenant(self):
        box = self.lines_as("tadmin", "hostA", {"drivetemp_hdd_warn_c": 40})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.stored()["drivetemp_hdd_warn_c"], 40.0)

    def dispatcher_status(self, user, path):
        """What main()'s pre-dispatch device check answers for this caller and this path, before any handler runs."""
        saved = api.verify_token
        role = api.load(api.USERS_FILE)[user]["role"]
        api.verify_token = lambda t: (user, role)
        old = os.environ.get("PATH_INFO")
        os.environ["PATH_INFO"] = path
        box = {}

        def _resp(status, data=None):
            box["status"] = status
            raise api.HTTPError(status, data)
        real_respond, real_token = api.respond, api.get_token_from_request
        api.respond = _resp
        api.get_token_from_request = lambda: "t"
        try:
            try:
                api._enforce_device_scope()
            except api.HTTPError:
                pass
        finally:
            api.respond, api.get_token_from_request = real_respond, real_token
            api.verify_token = saved
            if old is None:
                os.environ.pop("PATH_INFO", None)
            else:
                os.environ["PATH_INFO"] = old
        return box.get("status")

    def test_the_dispatcher_refuses_a_host_of_another_tenant_before_the_handler_runs(self):
        """_enforce_device_scope covers every /api/devices/<id>/... route: the three 7.4.4 changed, for both
        a tenant administrator and a viewer, and it lets the same callers through to their own host."""
        for path in ("metric-thresholds", "hardware", "disk-names"):
            for user in ("tadmin", "tviewer"):
                with self.subTest(route=path, caller=user):
                    self.assertEqual(self.dispatcher_status(user, f"/api/devices/hostB/{path}"), 403)
                    self.assertIsNone(self.dispatcher_status(user, f"/api/devices/hostA/{path}"))


class TestADrivesRowsStayInTheirTenant(_Hosts):
    """A drive over its line is a row in Needs attention for its host. The digest keeps an item that carries no
    host id (a fleet-level one), so a drive item is only as private as the id it is stamped with."""

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True, "drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50})
        for f in (api.DISK_NAMES_FILE, api.FLEET_EVENTS_FILE, api.SMART_HIST_FILE):
            api.save(f, {"events": []} if f == api.FLEET_EVENTS_FILE else {})
        api.save(api.HARDWARE_FILE, {
            h: {"smart": [{"device": f"/dev/sd-{h}", "serial": f"SN-{h}", "model": "M", "health": "PASSED",
                           "temperature_c": 52, "media": "hdd"}],
                "ts": now, "_drive_temp": {f"SN-{h}": {"l": "critical", "m": 0}}} for h in ("hostA", "hostB")})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.HARDWARE_FILE, {}), (api.DISK_NAMES_FILE, {}), (api.SMART_HIST_FILE, {}),
                         (api.FLEET_EVENTS_FILE, {"events": []}), (api.CONFIG_FILE, {}), (api.DEVICES_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        super().tearDown()

    def rows(self, user):
        box = self.as_user(user, api.handle_attention, verb="GET")
        self.assertEqual(box["status"], 200, box)
        return [i["summary"] for i in box["body"]["items"] if i.get("kind") == "disk"]

    def test_the_platform_operator_sees_the_drives_of_both_tenants(self):
        rows = self.rows("alice")
        self.assertTrue(any("sd-hostA" in r for r in rows) and any("sd-hostB" in r for r in rows), rows)

    def test_a_tenant_sees_its_own_drive_and_not_the_other_tenants(self):
        for user in ("tadmin", "tviewer"):
            with self.subTest(caller=user):
                rows = self.rows(user)
                self.assertTrue(any("sd-hostA" in r for r in rows), rows)
                self.assertFalse(any("sd-hostB" in r for r in rows), rows)

    def test_the_hardware_answer_of_a_host_is_the_tenants_own(self):
        for user in ("tadmin", "tviewer"):
            box = self.as_user(user, lambda: api.handle_device_hardware("hostA"), verb="GET")
            self.assertEqual(box["status"], 200, box)
            self.assertEqual([d["serial"] for d in box["body"]["smart"]], ["SN-hostA"])
            lines = box["body"]["smart"][0]["lines"]
            self.assertEqual((lines["warn"], lines["crit"], lines["media"]), (45.0, 50.0, "hdd"))


# ── held: what a host can make the server do by what it reports ─────────────────────────────────────

class TestWhatAHostReportsAboutItsDrives(_Drives):

    HOSTILE = [10 ** 400, -10 ** 400, float("nan"), float("inf"), -float("inf"), 1e308, True, None, "x" * 3000,
               "\x00", "<img src=x onerror=1>", ["a"], {"a": 1}, "\r\nBcc: x@y.invalid", 255, -5, "45"]

    def test_no_value_in_any_field_makes_the_heartbeat_fail(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        for field in ("device", "serial", "model", "health", "temperature_c", "media", "wear_pct", "standby"):
            for value in self.HOSTILE:
                with self.subTest(field=field, value=repr(value)[:24]):
                    entry = drv("S1", 52)
                    entry[field] = value
                    self.heartbeat(smart=[entry, drv("S2", 30, device="/dev/sdb")])      # fails the test on anything but 200

    def test_a_smart_value_that_is_not_a_list_is_not_a_report(self):
        for junk in ("x", {"a": 1}, 5, None, [None, 1, "a", [], {}]):
            self.heartbeat(smart=junk)
        self.assertEqual(self.drive_events(), [])

    def test_what_the_server_keeps_for_a_host_is_bounded(self):
        """32 drives a report, a state entry for each that is over a line and for three reports after it leaves,
        so a host that invents new serials every report cannot grow the record."""
        self.lines(drivetemp_warn_c=1, drivetemp_crit_c=2)
        biggest = 0
        for i in range(12):
            drives = [drv(f"R{i}-{j}", 60, device=f"/dev/sd{j}") for j in range(80)]       # 80 offered, 32 kept
            self.report(*drives)
            biggest = max(biggest, len(self.record().get("_drive_temp") or {}))
        self.assertLessEqual(biggest, 3 * api.MAX_SMART_DISKS)
        self.assertLessEqual(len(self.record()["smart"]), api.MAX_SMART_DISKS)

    def test_a_line_break_in_a_drive_name_does_not_reach_a_mail_header(self):
        import notify
        import smtp_notifier
        sent = []

        class Relay:
            def __init__(self, *a, **k): pass
            def ehlo(self): pass
            def has_extn(self, n): return False
            def starttls(self, **k): pass
            def login(self, *a): pass
            def sendmail(self, frm, to, msg): sent.append(msg if isinstance(msg, str) else msg.decode("utf-8", "replace"))
            def send_message(self, msg, *a, **k): sent.append(msg.as_string())
            def quit(self): pass
            def close(self): pass
        real = smtp_notifier.smtplib.SMTP
        smtp_notifier.smtplib.SMTP = Relay
        try:
            payload = {"kind": "drivetemp", "target": "S2", "disk": "/dev/sdb\r\nBcc: evil@example.invalid\nX-Injected: 1",
                       "serial": "S2", "disk_name": "Pool\r\nSubject: x", "value": 52.0, "threshold": 50.0, "name": "nas01",
                       "level": "critical", "metric": "drivetemp"}
            message = notify._webhook_message("metric_critical", payload)
            subject, body = smtp_notifier.render_event_email("RemotePower", "metric_critical", payload, message)
            cfg = {"smtp_host": "mail.invalid", "smtp_port": 25, "smtp_tls": "plain", "smtp_from": "rp@example.invalid"}
            smtp_notifier.send_email(cfg, ["ops@example.invalid"], subject, body,
                                     html_body=smtp_notifier.brand_html(cfg, subject, body))
        finally:
            smtp_notifier.smtplib.SMTP = real
        head = sent[-1].split("\n\n", 1)[0]
        for line in head.split("\n"):
            self.assertFalse(line.lower().startswith(("bcc:", "x-injected:")), line)
        self.assertEqual(sum(1 for line in head.split("\n") if line.lower().startswith("subject:")), 1)

    def test_an_ascii_subject_with_a_line_break_is_flattened_not_refused_or_smuggled(self):
        """The alert's subject always holds a dash or a degree sign, so the email package encodes it whatever
        the notifier does. An ASCII subject is where only send_email's own flattening stands in the way: without
        it the package refuses the message (HeaderParseError) and the alert is never sent."""
        import smtp_notifier
        sent = []

        class Relay:
            def __init__(self, *a, **k): pass
            def ehlo(self): pass
            def has_extn(self, n): return False
            def starttls(self, **k): pass
            def login(self, *a): pass
            def sendmail(self, frm, to, msg): sent.append(msg if isinstance(msg, str) else msg.decode("utf-8", "replace"))
            def send_message(self, msg, *a, **k): sent.append(msg.as_string())
            def quit(self): pass
            def close(self): pass
        real = smtp_notifier.smtplib.SMTP
        smtp_notifier.smtplib.SMTP = Relay
        try:
            cfg = {"smtp_host": "mail.invalid", "smtp_port": 25, "smtp_tls": "plain", "smtp_from": "rp@example.invalid"}
            result = smtp_notifier.send_email(cfg, ["ops@example.invalid"], "Drive sdb\r\nBcc: evil@example.invalid", "body")
        finally:
            smtp_notifier.smtplib.SMTP = real
        self.assertEqual(result, {"ok": True})
        head = sent[-1].split("\n\n", 1)[0]
        for line in head.split("\n"):
            self.assertFalse(line.lower().startswith("bcc:"), line)
        self.assertRegex(head, r"Subject: Drive sdb +Bcc: evil@example\.invalid\n")

    def test_a_line_break_in_a_drive_name_does_not_reach_a_webhook_header(self):
        import notify
        title = "Drive /dev/sdb\r\nX-Injected: 1 CRITICAL on nas01: 52°C"
        message = "nas01: CRITICAL — drive /dev/sdb\r\nX-Injected: 1"
        _body, headers, _ctype = notify._build_ntfy_body("metric_critical", title, message, 2)
        for name, value in headers.items():
            self.assertNotIn("\n", value, name)
            self.assertNotIn("\r", value, name)
        generic = notify._build_generic_body("metric_critical", title, message, 2, {"device_id": "d1"})
        for name, value in generic[1].items():
            self.assertNotIn("\n", str(value), name)


class TestAStoreThatIsNotWhatTheCodeWritesIsStillRead(_Drives):

    JUNK = ({"drivetemp_per_serial": "x"}, {"drivetemp_per_serial": [1]}, {"drivetemp_per_serial": {"S1": "x"}},
            {"drivetemp_per_serial": {"S1": {"warn": [1], "crit": {"a": 1}}}}, {"drivetemp_hdd_warn_c": [1]},
            {"drivetemp_warn_c": "45"}, {"drivetemp_per_serial": {"S1": {"warn": 10 ** 400}}})

    # What no handler writes but a hand-edited store can hold: the whole value is not a dictionary.
    NOT_A_DICT = ("not a dict", 5, [1], 2.5, True)

    def test_the_heartbeat_the_hardware_answer_and_the_digest_survive_it(self):
        from test_v743_disk_io import _call
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        for junk in self.JUNK + self.NOT_A_DICT:
            with api._LockedUpdate(api.DEVICES_FILE) as devs:
                devs[DEV]["metric_thresholds"] = copy.deepcopy(junk)
            api._LOAD_CACHE.clear()
            with self.subTest(junk=json.dumps(junk, default=str)[:60]):
                self.heartbeat(smart=[drv("S1", 52)])
                box = _call(api.handle_device_hardware, {}, DEV, verb="GET")
                self.assertEqual(box["status"], 200, box)
                json.dumps(box["body"], allow_nan=False)
                self.assertIsInstance(api._compute_attention(), list)

    def test_the_pure_rules_take_the_same_junk(self):
        for host in self.JUNK + self.NOT_A_DICT:
            host = host if isinstance(host, dict) else {}
            self.assertEqual(len(dt.resolve("S1", "hdd", host.get("drivetemp_per_serial"), host, {})), 2)
            json.dumps(dt.view({"device": "/dev/sda", "serial": "S1"}, host.get("drivetemp_per_serial"), host, {}),
                       allow_nan=False)
        for whole in self.NOT_A_DICT:
            self.assertEqual(dt.resolve("S1", "hdd", whole, whole, whole), (None, None), repr(whole))


if __name__ == "__main__":
    unittest.main()
