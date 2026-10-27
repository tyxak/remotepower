#!/usr/bin/env python3
"""v7.4.2, issue #42: SNMP memory counts the cache as used.

"An OPNsense 26.7 firewall (FreeBSD 15.1) added as an agentless SNMP host reports memory at
94% and raises snmp_mem warning and critical alerts. The firewall's own top shows about 23%
in real use. The rest is cache, which FreeBSD counts as 'used' in hrStorage."

net-snmp puts the page cache and the buffers into the "Physical memory" row's used figure and
lists them again as their own rows ("Cached memory", "Memory buffers"). Three surfaces read
that row: the alert and the metric history, the devices-list cell, and the SNMP card. They
have to agree, so the sum is done once (snmp.memory_in_use) and all three use it.

The rows below are the reporter's, as snmp.poll_hr_storage returns them.
"""
import importlib.util
import io
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v742-snmp-"))
_spec = importlib.util.spec_from_file_location("api_v742_snmp", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import snmp as snmp_mod  # noqa: E402

MB = 1024 * 1024
DEV = "fw1"


def row(index, descr, size_mb, used_mb):
    size, used = size_mb * MB, used_mb * MB
    return {"index": index, "descr": descr, "size_bytes": size, "used_bytes": used,
            "used_pct": round(used * 100.0 / size, 1) if size else None}


def opnsense():
    """The reporter's firewall: 7,918 MB, 7,454 of it 'used', of which 3,919 MB is cache and
    502 MB buffers. Their `top` showed about 23% in real use."""
    return [row(1, "Physical memory", 7918, 7454),
            row(2, "Cached memory", 3919, 3919),
            row(3, "Memory buffers", 802, 502),
            row(4, "Swap space", 8192, 0),
            row(5, "/", 220000, 41000)]


class TestTheSum(unittest.TestCase):

    def test_the_reporters_firewall(self):
        m = snmp_mod.memory_in_use(opnsense())
        self.assertEqual(m["used_pct"], 38.3)
        self.assertEqual(m["used_bytes"], (7454 - 3919 - 502) * MB)
        self.assertEqual(m["size_bytes"], 7918 * MB)
        self.assertEqual(m["cache_bytes"], (3919 + 502) * MB)
        self.assertEqual(m["raw_used_pct"], 94.1, "the figure the device reports stays available")
        self.assertEqual(m["index"], 1)

    def test_a_host_with_no_cache_rows_is_read_as_it_always_was(self):
        for descr in ("Physical memory", "Physical Memory", "main memory", "Memory"):
            m = snmp_mod.memory_in_use([row(1, descr, 4096, 3000), row(2, "C:\\", 100000, 50000)])
            self.assertEqual(m["used_pct"], round(3000 * 100 / 4096, 1), descr)
            self.assertEqual(m["cache_bytes"], 0, descr)

    def test_only_cache_or_only_buffers(self):
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 900), row(2, "Cached memory", 500, 500)])
        self.assertEqual(m["used_pct"], 40.0)
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 900), row(3, "Memory buffers", 300, 200)])
        self.assertEqual(m["used_pct"], 70.0)

    def test_cache_and_buffers_are_taken_from_the_used_column(self):
        """The buffers row is 802 MB in size and 502 MB in use; the 502 is what holds data."""
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 900), row(3, "Memory buffers", 802, 502)])
        self.assertEqual(m["cache_bytes"], 502 * MB)

    def test_more_cache_than_used_means_used_never_held_it(self):
        """If cache plus buffers is bigger than the used figure, this host's 'used' cannot
        include them. Subtracting would invent a negative; the figure is left alone."""
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 300), row(2, "Cached memory", 800, 800)])
        self.assertEqual(m["used_pct"], 30.0)
        self.assertEqual(m["cache_bytes"], 0)

    def test_cache_equal_to_used_is_zero_in_use_not_a_refusal(self):
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 800), row(2, "Cached memory", 800, 800)])
        self.assertEqual(m["used_pct"], 0.0)

    def test_a_cache_row_with_no_used_figure_counts_as_nothing(self):
        cached = row(2, "Cached memory", 500, 500)
        cached["used_bytes"] = None
        cached["used_pct"] = None
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 900), cached])
        self.assertEqual(m["used_pct"], 90.0)

    def test_no_memory_row_is_none(self):
        self.assertIsNone(snmp_mod.memory_in_use([row(5, "/", 220000, 41000)]))
        self.assertIsNone(snmp_mod.memory_in_use([]))
        self.assertIsNone(snmp_mod.memory_in_use(None))

    def test_a_memory_row_without_a_size_gives_no_percentage(self):
        r = row(1, "Physical memory", 1000, 900)
        r["size_bytes"], r["used_pct"] = None, None
        m = snmp_mod.memory_in_use([r, row(2, "Cached memory", 500, 500)])
        self.assertIsNone(m["used_pct"])

    def test_the_rows_it_was_given_are_not_changed(self):
        rows = opnsense()
        before = json.dumps(rows, sort_keys=True)
        snmp_mod.memory_in_use(rows)
        self.assertEqual(json.dumps(rows, sort_keys=True), before)

    def test_the_first_memory_row_wins(self):
        m = snmp_mod.memory_in_use([row(1, "Physical memory", 1000, 500), row(9, "Memory", 2000, 1900)])
        self.assertEqual(m["index"], 1)


class _Base(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.CONFIG_FILE, api.SNMP_DATA_FILE):
            api.save(f, {})
        api.save(api.DEVICES_FILE, {DEV: {
            "id": DEV, "name": "opnsense", "hostname": "opnsense", "ip": "10.0.0.1",
            "agentless": True, "monitored": True, "last_seen": int(time.time()),
            "snmp": {"enabled": True, "version": "2c", "community": "public"}}})
        api._LOAD_CACHE.clear()
        self.events = []
        self._real = api.fire_webhook
        api.fire_webhook = lambda event, payload: self.events.append((event, dict(payload)))

    def tearDown(self):
        api.fire_webhook = self._real

    def poll(self, storage):
        entry = {"storage": storage, "last_ok": int(time.time())}
        api.process_snmp_metric_thresholds(DEV, api.load(api.DEVICES_FILE)[DEV], entry)
        api._LOAD_CACHE.clear()
        return entry

    def mem_events(self):
        return [(e, p.get("value")) for e, p in self.events
                if p.get("metric") == "snmp_mem" or p.get("kind") == "snmp_mem"]


class TestTheAlertAndTheMetric(_Base):

    def test_the_helper_the_alert_reads_gives_the_corrected_figure(self):
        self.assertEqual(api._snmp_memory_used_pct({"storage": opnsense()}), 38.3)

    def test_the_reporters_firewall_raises_nothing(self):
        self.poll(opnsense())
        self.assertEqual(self.mem_events(), [], "94% of which most is cache is not memory pressure")

    def test_a_host_that_really_is_short_of_memory_still_alerts(self):
        """The control: the correction must not make the alert blind."""
        rows = [row(1, "Physical memory", 7918, 7454), row(2, "Cached memory", 3919, 100),
                row(3, "Memory buffers", 802, 50)]          # 7,304 MB in use, 92%
        self.poll(rows)
        self.assertEqual([e for e, _ in self.mem_events()], ["metric_warning"])

    def test_a_host_with_no_cache_rows_alerts_as_before(self):
        self.poll([row(1, "Physical memory", 7918, 7454)])
        self.assertEqual([e for e, _ in self.mem_events()], ["metric_warning"])

    def test_the_metric_history_records_the_corrected_figure(self):
        recorded = []
        real = api._record_metrics
        api._record_metrics = lambda dev_id, m: recorded.append((dev_id, dict(m)))
        try:
            api._record_snmp_metrics(DEV, {"storage": opnsense()})
        finally:
            api._record_metrics = real
        self.assertEqual(recorded[0][1]["mem_percent"], 38.3)


class _Call(unittest.TestCase):
    """Run a handler through its real auth gate and capture the answer."""

    def run_handler(self, handler, *args):
        class Cap(SystemExit):
            pass
        out = {}

        def fake(status, data):
            out["status"], out["body"] = status, data
            raise Cap()
        real_respond, real_admin, real_auth = api.respond, api.require_admin_auth, api.require_auth
        api.respond = fake
        api.require_admin_auth = lambda *a, **k: "admin"
        api.require_auth = lambda *a, **k: None
        os.environ.update({"REQUEST_METHOD": "GET", "QUERY_STRING": "", "CONTENT_LENGTH": "0"})
        api.sys.stdin = type("S", (), {"buffer": io.BytesIO(b"")})()
        try:
            handler(*args)
        except Cap:
            pass
        finally:
            api.respond, api.require_admin_auth, api.require_auth = real_respond, real_admin, real_auth
        return out["status"], out["body"]


class TestTheDevicesList(_Base, _Call):
    """The cell on the Devices page was a second copy of the row selection."""

    def test_the_list_cell_agrees_with_the_alert(self):
        self.seed_snmp(opnsense())
        status, body = self.run_handler(api.handle_devices_list)
        self.assertEqual(status, 200)
        ss = next(d for d in body if d["id"] == DEV)["snmp_status"]
        self.assertEqual(ss["mem_pct"], api._snmp_memory_used_pct({"storage": opnsense()}))
        self.assertEqual(ss["mem_pct"], 38.3)
        self.assertEqual(ss["mem_total_kb"], 7918 * 1024)
        self.assertEqual(ss["mem_used_kb"], (7454 - 3919 - 502) * 1024)
        self.assertEqual(ss["mem_cache_kb"], (3919 + 502) * 1024)

    def test_a_host_without_cache_rows_has_no_cache_field_set(self):
        self.seed_snmp([row(1, "Physical memory", 4096, 3000)])
        status, body = self.run_handler(api.handle_devices_list)
        ss = next(d for d in body if d["id"] == DEV)["snmp_status"]
        self.assertEqual(ss["mem_pct"], round(3000 * 100 / 4096, 1))
        self.assertIsNone(ss["mem_cache_kb"])

    def seed_snmp(self, storage):
        api.save(api.SNMP_DATA_FILE, {DEV: {"storage": storage, "last_ok": int(time.time()),
                                            "processors": []}})
        api._LOAD_CACHE.clear()


class TestTheSnmpCard(_Base, _Call):
    """GET /api/devices/<id>/snmp/deep feeds the card on the host drawer."""

    def stub_polls(self, storage):
        self._saved = {n: getattr(snmp_mod, n) for n in (
            "poll_system", "poll_interfaces", "poll_host_resources", "poll_hr_storage",
            "poll_processors", "poll_ucd_snmp", "poll_synology")}
        snmp_mod.poll_system = lambda *a, **k: {"sysName": "opnsense"}
        snmp_mod.poll_interfaces = lambda *a, **k: []
        snmp_mod.poll_host_resources = lambda *a, **k: {}
        snmp_mod.poll_hr_storage = lambda *a, **k: storage
        snmp_mod.poll_processors = lambda *a, **k: []
        snmp_mod.poll_ucd_snmp = lambda *a, **k: {"memTotalReal": 7918 * 1024, "memAvailReal": 464 * 1024}
        snmp_mod.poll_synology = lambda *a, **k: {}

    def tearDown(self):
        for n, v in getattr(self, "_saved", {}).items():
            setattr(snmp_mod, n, v)
        super().tearDown()

    def test_the_card_gets_the_sum_beside_the_raw_rows(self):
        self.stub_polls(opnsense())
        status, body = self.run_handler(api.handle_device_snmp_deep, DEV)
        self.assertEqual(status, 200)
        self.assertEqual(body["memory"]["used_pct"], 38.3)
        self.assertEqual(body["memory"]["raw_used_pct"], 94.1)
        self.assertEqual(body["memory"]["cache_bytes"], (3919 + 502) * MB)
        self.assertEqual(body["storage"][0]["used_pct"], 94.1, "the raw rows are still the device's own")

    def test_a_host_with_no_memory_row_has_no_memory_block(self):
        self.stub_polls([row(5, "/", 220000, 41000)])
        status, body = self.run_handler(api.handle_device_snmp_deep, DEV)
        self.assertEqual(status, 200)
        self.assertNotIn("memory", body)


if __name__ == "__main__":
    unittest.main()
