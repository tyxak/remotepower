#!/usr/bin/env python3
"""v7.4.3, issue #47: a name for a drive, kept against its serial number.

"Disks are listed only by kernel name (/dev/sda, /dev/nvme0n1) plus model and serial. On a host with
eleven drives, several of the same model, 'sdd' means nothing at a glance, and the letters aren't
stable: the same physical drive can be sda in one tool and sdd in another, or move after a reboot or
a controller change. When a SMART alert fires, I have to look up which physical drive (which bay,
which pool member) the serial belongs to."

A host keeps a table of names, one per serial number. The Hardware tab shows the name where it showed
the letter, the fleet disk-health list shows it, and an alert that names a drive says
"Pool disk 2 (/dev/sdd, sn WD-1234)", so the letter and the serial stay next to the name.

Everything here goes through the real handler, the real hardware ingest and the real alert text. A
hand-built record would skip what the feature is for: that the name is found by the serial and not by
the letter.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v743-dn-"))
_spec = importlib.util.spec_from_file_location("api_v743_dn", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DEV = "d1"


def disk(device, serial, health="PASSED", **kw):
    d = {"device": device, "health": health, "model": "WDC WD40EFRX", "serial": serial}
    d.update(kw)
    return d


class _Base(unittest.TestCase):

    def setUp(self):
        for f, empty in ((api.HARDWARE_FILE, {}), (api.DISK_NAMES_FILE, {}), (api.ALERTS_FILE, {"alerts": []}),
                         (api.FLEET_EVENTS_FILE, {"events": []}), (api.CONFIG_FILE, {}),
                         (api.MAINT_FILE, {"windows": []}), (api.SMART_HIST_FILE, {}),
                         (api.ROLES_FILE, {"roles": []})):
            api.save(f, empty)
        api.save(api.DEVICES_FILE, {})
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {DEV: {
            "id": DEV, "name": "nas01", "hostname": "nas01", "token": "tok", "last_seen": int(time.time()),
            "enrolled": int(time.time()), "tags": [], "group": "", "sysinfo": {}, "monitored": True}})
        api._LOAD_CACHE.clear()
        self.fired = []
        self._real_fire = api.fire_webhook

        def spy(event, payload):
            self.fired.append((event, dict(payload)))
            return self._real_fire(event, payload)
        api.fire_webhook = spy

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def ingest(self, *disks):
        api._LOAD_CACHE.clear()
        api._ingest_hardware(DEV, "nas01", {"smart": list(disks)}, int(time.time()))
        api._LOAD_CACHE.clear()

    def names(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DISK_NAMES_FILE) or {}).get(DEV, {})

    def put(self, body, role="admin", dev_id=DEV, verb="PUT"):
        """The handler through its real sign-in and role gate, with only verify_token stubbed."""
        names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
                 "audit_log", "respond")
        saved = {n: getattr(api, n) for n in names}
        box = {}
        api.verify_token = lambda t: ("alice", role) if role else (None, None)
        api.get_token_from_request = lambda: "t" if role else ""
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
                api.handle_device_disk_names(dev_id)
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        api._LOAD_CACHE.clear()
        return box

    def hardware(self):
        """What the host drawer is given."""
        names = ("verify_token", "get_token_from_request", "method", "respond")
        saved = {n: getattr(api, n) for n in names}
        box = {}
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "t"
        api.method = lambda: "GET"

        def _resp(status, data=None):
            box["status"], box["body"] = status, data
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_device_hardware(DEV)
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(box.get("status"), 200, box)
        return box["body"]


class TestNamingADisk(_Base):

    def setUp(self):
        super().setUp()
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B"), disk("/dev/sdc", ""))

    def test_a_name_is_kept_against_the_serial(self):
        box = self.put({"names": {"S-A": "Pool disk 2"}})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.names(), {"S-A": "Pool disk 2"})
        self.assertEqual(box["body"]["names"], {"S-A": "Pool disk 2"})

    def test_a_blank_name_removes_it_and_an_empty_table_leaves_no_row(self):
        self.put({"names": {"S-A": "Pool disk 2", "S-B": "Backup SSD"}})
        self.put({"names": {"S-A": ""}})
        self.assertEqual(self.names(), {"S-B": "Backup SSD"})
        self.put({"names": {"S-B": "   "}})
        api._LOAD_CACHE.clear()
        self.assertNotIn(DEV, api.load(api.DISK_NAMES_FILE) or {})

    def test_naming_one_disk_does_not_forget_another(self):
        self.put({"names": {"S-A": "Pool disk 2"}})
        self.put({"names": {"S-B": "Backup SSD"}})
        self.assertEqual(self.names(), {"S-A": "Pool disk 2", "S-B": "Backup SSD"})

    def test_a_serial_the_host_does_not_report_is_not_stored(self):
        box = self.put({"names": {"S-A": "Pool disk 2", "S-NOPE": "Ghost"}})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.names(), {"S-A": "Pool disk 2"})
        self.assertEqual(box["body"]["ignored"], ["S-NOPE"])

    def test_a_disk_that_reports_no_serial_cannot_be_named(self):
        """Its letter is the one thing that moves, so a name keyed on it would be wrong after a reboot."""
        for key in ("", "/dev/sdc", "sdc"):
            with self.subTest(key=key):
                box = self.put({"names": {key: "Mystery"}})
                self.assertEqual(box["status"], 200, box)
                self.assertEqual(self.names(), {})

    def test_a_name_for_a_disk_that_was_pulled_can_still_be_changed_or_removed(self):
        self.put({"names": {"S-B": "Backup SSD"}})
        self.ingest(disk("/dev/sda", "S-A"))                    # S-B is no longer reported
        box = self.put({"names": {"S-B": "Retired"}})
        self.assertEqual(box["body"]["ignored"], [])
        self.assertEqual(self.names(), {"S-B": "Retired"})
        self.put({"names": {"S-B": ""}})
        self.assertEqual(self.names(), {})

    def test_the_name_is_cleaned(self):
        long = "x" * 200
        self.put({"names": {"S-A": "  Pool\tdisk\n2\x00  ", "S-B": long}})
        got = self.names()
        self.assertEqual(got["S-A"], "Pool disk 2")
        self.assertEqual(len(got["S-B"]), 64)

    def test_only_text_is_a_name(self):
        for value in (5, None, True, ["a"], {"a": 1}):
            with self.subTest(value=value):
                box = self.put({"names": {"S-A": value}})
                self.assertEqual(box["status"], 200, box)
                self.assertEqual(self.names(), {})

    def test_the_body_must_be_an_object_of_names(self):
        for body in ({}, {"names": ["S-A"]}, {"names": "S-A"}, {"names": None}, []):
            with self.subTest(body=body):
                self.assertEqual(self.put(body)["status"], 400)

    def test_a_host_keeps_at_most_128_names(self):
        full = {f"old-{i}": f"n{i}" for i in range(128)}
        api.save(api.DISK_NAMES_FILE, {DEV: full})
        api._LOAD_CACHE.clear()
        box = self.put({"names": {"S-A": "one too many"}})
        self.assertEqual(box["status"], 400, box)
        self.assertEqual(self.names(), full)

    def test_the_change_is_in_the_audit_log(self):
        box = self.put({"names": {"S-A": "Pool disk 2"}})
        self.assertTrue(box["audit"], "naming a disk is a change somebody made")
        text = json.dumps(box["audit"])
        self.assertIn(DEV, text)
        self.assertNotIn("Pool disk 2", text, "the audit trail names the host and the count, not the labels")


class TestWhoMayName(_Base):

    def setUp(self):
        super().setUp()
        self.ingest(disk("/dev/sda", "S-A"))

    def test_a_viewer_cannot(self):
        for role in ("viewer", "auditor", "finance", "mcp"):
            with self.subTest(role=role):
                self.assertEqual(self.put({"names": {"S-A": "x"}}, role=role)["status"], 403)
        self.assertEqual(self.names(), {})

    def test_a_signed_out_caller_is_refused(self):
        self.assertEqual(self.put({"names": {"S-A": "x"}}, role=None)["status"], 401)

    def test_an_operator_with_an_action_permission_can(self):
        api.save(api.ROLES_FILE, {"roles": [{"name": "ops", "permissions": ["exec"], "scope": {"type": "all"}}]})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.put({"names": {"S-A": "x"}}, role="ops")["status"], 200)

    def test_only_put(self):
        for verb in ("GET", "POST", "DELETE", "PATCH"):
            with self.subTest(verb=verb):
                self.assertEqual(self.put({"names": {"S-A": "x"}}, verb=verb)["status"], 405)

    def test_an_unknown_host_is_a_404(self):
        self.assertEqual(self.put({"names": {"S-A": "x"}}, dev_id="nope")["status"], 404)
        self.assertEqual(self.put({"names": {"S-A": "x"}}, dev_id="../x")["status"], 404)


class TestTheRoute(_Base):

    def test_the_route_resolves_to_the_handler(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("PUT", "/api/devices/nas01/disk-names")[0], "handle_device_disk_names")

    def test_a_delete_on_that_path_is_not_a_host_delete(self):
        from routing_harness import resolve_route
        self.assertNotEqual(resolve_route("DELETE", "/api/devices/nas01/disk-names")[0], "handle_device_delete")
        self.assertFalse(api._route_code_5("/api/devices/nas01/disk-names", "DELETE"))

    def test_the_pre_dispatch_gate_covers_the_path(self):
        real = (api.path_info, api._tenant_visible, api.respond)
        seen = {}

        def fake(status, data):
            seen["status"] = status
            raise SystemExit()
        api.path_info = lambda: f"/api/devices/{DEV}/disk-names"
        api._tenant_visible = lambda dev: False
        api.respond = fake
        try:
            with self.assertRaises(SystemExit):
                api._enforce_device_scope()
        finally:
            api.path_info, api._tenant_visible, api.respond = real
        self.assertEqual(seen["status"], 403)


class TestTheNameFollowsTheSerial(_Base):

    def test_the_hardware_tab_gets_the_name_where_it_has_the_disk(self):
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B"))
        self.put({"names": {"S-A": "Pool disk 2"}})
        rows = {d["device"]: d for d in self.hardware()["smart"]}
        self.assertEqual(rows["/dev/sda"]["name"], "Pool disk 2")
        self.assertNotIn("name", rows["/dev/sdb"])

    def test_the_name_is_not_written_into_the_hardware_record(self):
        self.ingest(disk("/dev/sda", "S-A"))
        self.put({"names": {"S-A": "Pool disk 2"}})
        self.hardware()
        stored = (api.load(api.HARDWARE_FILE) or {})[DEV]["smart"][0]
        self.assertNotIn("name", stored, "the table is the one place a name lives")

    def test_after_a_reboot_shuffles_the_letters_the_name_is_on_the_same_drive(self):
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B"))
        self.put({"names": {"S-A": "Pool disk 2", "S-B": "Backup SSD"}})
        self.ingest(disk("/dev/sda", "S-B"), disk("/dev/sdd", "S-A"))      # the controller enumerated them the other way
        rows = {d["device"]: d.get("name") for d in self.hardware()["smart"]}
        self.assertEqual(rows, {"/dev/sda": "Backup SSD", "/dev/sdd": "Pool disk 2"})

    def test_a_host_with_no_names_gets_the_same_answer_as_before(self):
        self.ingest(disk("/dev/sda", "S-A"))
        self.assertNotIn("name", self.hardware()["smart"][0])

    def test_another_hosts_names_are_not_used(self):
        api.save(api.DISK_NAMES_FILE, {"other-host": {"S-A": "Elsewhere"}})
        api._LOAD_CACHE.clear()
        self.ingest(disk("/dev/sda", "S-A"))
        self.assertNotIn("name", self.hardware()["smart"][0])

    def test_deleting_the_host_removes_its_names(self):
        self.ingest(disk("/dev/sda", "S-A"))
        self.put({"names": {"S-A": "Pool disk 2"}})
        self.assertTrue(api._purge_device(DEV))
        api._LOAD_CACHE.clear()
        self.assertNotIn(DEV, api.load(api.DISK_NAMES_FILE) or {})


class TestTheFleetList(_Base):

    def test_the_disk_health_list_names_the_disk(self):
        self.ingest(disk("/dev/sda", "S-A", health="FAILED"), disk("/dev/sdb", "S-B"))
        self.put({"names": {"S-A": "Pool disk 2"}})
        api._LOAD_CACHE.clear()
        rows = {r["disk"]: r for r in api._disk_health_view()}
        self.assertEqual(rows["/dev/sda"]["name"], "Pool disk 2")
        tracked = {r["disk"]: r for r in api._disk_tracked_view()}
        self.assertEqual(tracked["/dev/sda"]["name"], "Pool disk 2")
        self.assertEqual(tracked["/dev/sdb"]["name"], "")

    def test_the_list_keeps_the_letter_and_the_serial_next_to_the_name(self):
        self.ingest(disk("/dev/sda", "S-A", health="FAILED"))
        self.put({"names": {"S-A": "Pool disk 2"}})
        row = api._disk_health_view()[0]
        self.assertEqual((row["disk"], row["serial"], row["name"]), ("/dev/sda", "S-A", "Pool disk 2"))


class TestTheWordsOfAnAlert(_Base):

    def smart_failure(self):
        return [p for e, p in self.fired if e == "smart_failure"]

    def test_the_alert_for_a_failing_drive_says_which_one(self):
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B"))
        self.put({"names": {"S-B": "Backup SSD"}})
        self.fired.clear()
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B", health="FAILED"))
        p = self.smart_failure()[0]
        self.assertEqual(p["disks"], "Backup SSD (/dev/sdb, sn S-B)")
        self.assertEqual(api._alert_title("smart_failure", dict(p, name="nas01")),
                         "SMART failure on nas01: Backup SSD (/dev/sdb, sn S-B)")

    def test_a_drive_without_a_name_reads_as_it_always_did(self):
        self.ingest(disk("/dev/sda", "S-A"), disk("/dev/sdb", "S-B", health="FAILED"))
        self.assertEqual(self.smart_failure()[0]["disks"], "/dev/sdb")

    def test_the_inbox_row_carries_the_name(self):
        self.ingest(disk("/dev/sdb", "S-B"))
        self.put({"names": {"S-B": "Backup SSD"}})
        self.ingest(disk("/dev/sdb", "S-B", health="FAILED"))
        api._LOAD_CACHE.clear()
        rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == "smart_failure"]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0].get("title"), "SMART failure on nas01: Backup SSD (/dev/sdb, sn S-B)")

    def test_needs_attention_says_which_one(self):
        self.ingest(disk("/dev/sdb", "S-B", health="FAILED"))
        self.put({"names": {"S-B": "Backup SSD"}})
        import attention_isolation
        tmp = tempfile.mkdtemp(prefix="rp-v743-dn-na-")
        saved = attention_isolation.isolate(api, tmp)
        try:
            api.save(api.DEVICES_FILE, {DEV: {"name": "nas01", "group": "", "monitored": True, "tags": [],
                                              "enrolled": int(time.time()), "last_seen": int(time.time()), "sysinfo": {}}})
            api.save(api.HARDWARE_FILE, {DEV: {"smart": [dict(disk("/dev/sdb", "S-B", health="FAILED"), failed=True)]}})
            api.save(api.DISK_NAMES_FILE, {DEV: {"S-B": "Backup SSD"}})
            api._LOAD_CACHE.clear()
            lines = [i["summary"] for i in api._compute_attention() if i.get("kind") == "hardware"]
        finally:
            attention_isolation.restore(api, saved)
        self.assertEqual(lines, ["SMART failure on Backup SSD (/dev/sdb, sn S-B)"])

    def test_a_predicted_failure_carries_the_name(self):
        self.ingest(disk("/dev/sdb", "S-B", health="FAILED"))
        self.put({"names": {"S-B": "Backup SSD"}})
        # the at-risk row feeds the event; fire it as _maybe_check_disk_predictions does
        row = api._disk_health_view()[0]
        api.fire_webhook("disk_predict_fail", {"device_id": DEV, "name": row["device"], "disk": row["disk"],
                                               "disk_name": row["name"], "eta_days": 30, "reason": "x"})
        self.assertEqual(api._alert_title("disk_predict_fail", {"name": "nas01", "disk": "/dev/sdb",
                                                                 "disk_name": "Backup SSD", "eta_days": 30}),
                         "Disk predicted to fail on nas01: Backup SSD (/dev/sdb) (~30d to failure)")
        api._LOAD_CACHE.clear()
        rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == "disk_predict_fail"]
        self.assertEqual((rows[0].get("payload") or {}).get("disk_name"), "Backup SSD", "the inbox keeps it")
        events = [e for e in (api.load(api.FLEET_EVENTS_FILE) or {}).get("events", []) if e.get("event") == "disk_predict_fail"]
        self.assertEqual((events[0].get("payload") or {}).get("disk_name"), "Backup SSD", "and so does the feed")

    def test_the_prediction_is_fired_with_the_name(self):
        """The sweep that fires disk_predict_fail builds its payload from the at-risk row."""
        text = (_CGI / "api.py").read_text(encoding="utf-8")
        i = text.index("def _maybe_check_disk_predictions")
        block = text[i:text.index("\ndef ", i + 10)]
        self.assertIn("'disk_name'", block)

    def test_the_reliability_reason_names_the_drive(self):
        rec = {"smart": [dict(disk("/dev/sdb", "S-B", health="FAILED"), failed=True)]}
        api.save(api.DISK_NAMES_FILE, {DEV: {"S-B": "Backup SSD"}})
        api._LOAD_CACHE.clear()
        dev = (api.load(api.DEVICES_FILE) or {})[DEV]
        out = api._device_reliability(DEV, dev, rec, {}, [], {}, {}, {}, int(time.time()))
        details = [f["detail"] for f in out.get("factors", [])]
        self.assertTrue(any("Backup SSD (/dev/sdb, sn S-B)" in d for d in details), details)


class TestTheHelpers(_Base):

    def test_the_label_is_the_name_with_the_letter_and_serial_beside_it(self):
        d = disk("/dev/sdd", "WD-1234")
        self.assertEqual(api._disk_label({"WD-1234": "Pool disk 2"}, d), "Pool disk 2 (/dev/sdd, sn WD-1234)")
        self.assertEqual(api._disk_label({}, d), "/dev/sdd")
        self.assertEqual(api._disk_label({"WD-1234": ""}, d), "/dev/sdd")

    def test_a_disk_with_no_serial_is_never_named(self):
        self.assertEqual(api._disk_name_of({"": "x", "/dev/sdd": "y"}, disk("/dev/sdd", "")), "")

    def test_the_lookup_survives_a_damaged_store(self):
        for bad in ({DEV: "text"}, {DEV: ["a"]}, {DEV: None}, []):
            with self.subTest(bad=bad):
                api.save(api.DISK_NAMES_FILE, bad if isinstance(bad, dict) else {})
                api._LOAD_CACHE.clear()
                self.assertEqual(api._disk_names_for(DEV), {})


if __name__ == "__main__":
    unittest.main()
