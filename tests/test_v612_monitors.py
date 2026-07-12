"""v6.1.2 — monitor & alert-tuning improvements.

- **Pause/resume a monitor.** Monitors had no enabled flag, so the only way to
  stop one probing (a NAS you're rebuilding, a host away for a week) was to
  DELETE it — throwing away its history and meaning you retyped it afterwards.
- **Response-time percentiles.** Latency was embedded in the human-readable
  `detail` string for http/icmp only and never persisted as a number, so there
  was nothing to compute a p95 from. Every probe is now timed and the number is
  stored.
- **Clone + export.** The Nagios/Kuma/Zabbix importer has existed since v6.0.0
  with no way OUT, so moving monitors between your own instances was retyping.
- **Timed alert mutes.** Mutes were permanent-only; a mute you forget to lift is
  a signal you have silently stopped monitoring.
"""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-mon-"))
_spec = importlib.util.spec_from_file_location("api_v612_mon", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import importers  # noqa: E402  (needs the sys.path insert above)


class TestMonitorPause(unittest.TestCase):
    def test_paused_monitor_is_never_probed(self):
        mons = [
            {"label": "live", "type": "ping", "target": "127.0.0.1"},
            {"label": "off", "type": "ping", "target": "127.0.0.1", "paused": True},
        ]
        ran = [r["label"] for r in api._execute_monitor_checks(mons)]
        self.assertEqual(ran, ["live"])

    def test_paused_monitor_is_not_handed_to_a_satellite(self):
        # Otherwise the satellite keeps probing what the server agreed to stop.
        src = (_CGI / "api.py").read_text()
        i = src.index("def handle_satellite_monitor_work")
        block = src[i : src.index("\ndef ", i + 10)]
        self.assertIn("if m.get('paused'):", block)

    def test_pausing_a_down_monitor_clears_its_down_state(self):
        # A monitor that's DOWN when paused would otherwise stay flagged down
        # forever: no further probes means no recovery result, so monitor_up
        # never fires and the open alert never auto-resolves.
        src = (_CGI / "api.py").read_text()
        i = src.index("def handle_monitor_pause")
        block = src[i : src.index("\ndef ", i + 10)]
        self.assertIn("monitor_notified", block)
        self.assertIn("_auto_resolve_alerts('monitor_up'", block)

    def test_pause_route_is_registered(self):
        self.assertIn(("POST", "/api/monitors/pause"), api._build_exact_routes())


class TestMonitorLatencyPercentiles(unittest.TestCase):
    def test_percentile_is_nearest_rank(self):
        vals = list(range(1, 101))
        self.assertEqual(api._percentile(vals, 50), 50)
        self.assertEqual(api._percentile(vals, 95), 95)
        self.assertEqual(api._percentile(vals, 99), 99)

    def test_percentile_of_empty_is_none(self):
        self.assertIsNone(api._percentile([], 95))

    def test_single_sample(self):
        self.assertEqual(api._percentile([7], 99), 7)

    def test_failed_checks_are_excluded(self):
        # A timeout's elapsed time is the TIMEOUT VALUE, not the service's
        # response time — folding it in would make p99 track the timeout
        # constant instead of anything real.
        hist = [
            {"ok": True, "ms": 10},
            {"ok": True, "ms": 20},
            {"ok": False, "ms": 5000},   # timeout
            {"ok": True, "ms": 30},
        ]
        st = api._monitor_latency_stats(hist)
        self.assertEqual(st["samples"], 3)
        self.assertEqual(st["max"], 30)
        self.assertEqual(st["min"], 10)
        self.assertEqual(st["avg"], 20)

    def test_none_when_the_window_has_no_timed_samples(self):
        # Older history rows predate `ms`; don't invent numbers for them.
        self.assertIsNone(api._monitor_latency_stats([{"ok": True, "detail": "up"}]))

    def test_every_probe_result_carries_ms(self):
        res = api._execute_monitor_checks(
            [{"label": "x", "type": "ping", "target": "127.0.0.1"}]
        )
        self.assertTrue(res)
        self.assertIsInstance(res[0].get("ms"), int)

    def test_history_rows_persist_ms(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("def _persist_monitor_results")
        block = src[i : src.index("\ndef ", i + 10)]
        self.assertIn("_row['ms'] = int(r['ms'])", block)


class TestMonitorExportRoundTrips(unittest.TestCase):
    """Export must be importable — otherwise it's a dead end."""

    def setUp(self):
        api.require_auth = lambda *a, **k: "admin"
        api.save(
            api.CONFIG_FILE,
            {
                "monitors": [
                    {"label": "NAS", "type": "ping", "target": "192.168.1.10",
                     "target_kind": "host"},
                    {"label": "Web", "type": "http", "target": "https://example.com",
                     "expect_status": 200, "max_latency_ms": 800,
                     "body_match": {"mode": "contains", "value": "ok"}},
                    {"label": "Paused", "type": "tcp", "target": "10.0.0.9:22",
                     "paused": True},
                    {"label": "Sat", "type": "ping", "target": "10.9.9.9",
                     "via_satellite": "sat-1"},
                ]
            },
        )
        api._LOAD_CACHE.clear()

    def _export(self):
        cap = {}
        api.respond = lambda s, d: cap.update(status=s, body=d)
        api.handle_export_monitors()
        return cap["body"]

    def test_export_emits_the_native_format(self):
        doc = self._export()
        self.assertEqual(doc["format"], "remotepower")
        self.assertEqual(len(doc["monitors"]), 4)

    def test_via_satellite_is_stripped(self):
        # A satellite id is local to THIS install — meaningless (or wrong) on
        # the instance importing the file.
        doc = self._export()
        self.assertTrue(all("via_satellite" not in m for m in doc["monitors"]))

    def test_the_export_detects_and_parses_as_remotepower(self):
        text = json.dumps(self._export())
        self.assertEqual(importers.detect_format(text), "remotepower")
        back = importers.parse(text)
        self.assertEqual(len(back["monitors"]), 4)
        self.assertEqual(back["unmapped"], [])

    def test_rich_fields_survive_the_round_trip(self):
        back = importers.parse(json.dumps(self._export()))
        web = next(m for m in back["monitors"] if m["label"] == "Web")
        self.assertEqual(web["expect_status"], 200)
        self.assertEqual(web["max_latency_ms"], 800)
        self.assertEqual(web["body_match"], {"mode": "contains", "value": "ok"})
        paused = next(m for m in back["monitors"] if m["label"] == "Paused")
        self.assertTrue(paused["paused"])

    def test_export_route_is_registered(self):
        self.assertIn(("GET", "/api/export/monitors"), api._build_exact_routes())

    def test_a_garbage_entry_is_reported_not_silently_dropped(self):
        doc = {"format": "remotepower", "monitors": [
            {"label": "ok", "type": "ping", "target": "1.2.3.4"},
            {"label": "no target", "type": "ping"},
            "not-an-object",
        ]}
        out = importers.parse(json.dumps(doc))
        self.assertEqual(len(out["monitors"]), 1)
        self.assertEqual(len(out["unmapped"]), 2)


class TestTimedAlertMutes(unittest.TestCase):
    def setUp(self):
        api._ALERT_MUTE_SET_CACHE.update({"mtime": None, "checked": 0})

    def _seed(self, mutes):
        api.save(api.ALERT_MUTES_FILE, {"mutes": mutes})
        api._ALERT_MUTE_SET_CACHE.update({"mtime": None, "checked": 0})

    def test_a_live_timed_mute_silences(self):
        now = int(time.time())
        self._seed([{"id": "a", "device_id": "d1", "event": "log_alert",
                     "expires_at": now + 3600}])
        self.assertTrue(api._alert_muted("log_alert", {"device_id": "d1"}))

    def test_an_expired_mute_stops_silencing(self):
        now = int(time.time())
        self._seed([{"id": "b", "device_id": "d2", "event": "av_warning",
                     "expires_at": now - 10}])
        self.assertFalse(api._alert_muted("av_warning", {"device_id": "d2"}))

    def test_a_mute_with_no_expiry_is_permanent(self):
        self._seed([{"id": "c", "device_id": "d3", "event": "metric_warning"}])
        self.assertTrue(api._alert_muted("metric_warning", {"device_id": "d3"}))

    def test_expiry_also_lapses_the_needs_attention_suppression(self):
        # The v6.1.2 health fix routes NA items through the same mute set, so an
        # expired mute must let the item (and its health penalty) come back.
        now = int(time.time())
        self._seed([{"id": "d", "device_id": "d4", "event": "av_warning",
                     "expires_at": now - 5}])
        self.assertFalse(
            api._na_item_muted(
                {"kind": "av_posture", "severity": "warning", "device_id": "d4"}
            )
        )

    def test_mute_expired_helper(self):
        now = int(time.time())
        self.assertTrue(api._mute_expired({"expires_at": now - 1}, now))
        self.assertFalse(api._mute_expired({"expires_at": now + 1}, now))
        self.assertFalse(api._mute_expired({}, now))
        self.assertFalse(api._mute_expired({"expires_at": "junk"}, now))

    def test_the_cache_cannot_hold_an_expired_mute_indefinitely(self):
        # Nothing WRITES the store when a mute merely expires, so a cache keyed
        # on the store's mtime alone would keep silencing forever.
        src = (_CGI / "api.py").read_text()
        i = src.index("def _alert_mute_set")
        block = src[i : src.index("\ndef ", i + 10)]
        self.assertIn("checked", block)
        self.assertIn("_mute_expired", block)


class TestCloneUsesTheCorrectNewSentinel(unittest.TestCase):
    def test_clone_resets_the_edit_index_to_minus_one_not_null(self):
        # addMonitor() branches on `_monitorEditIdx >= 0`, and in JS
        # `null >= 0` is TRUE — null would take the EDIT branch and do
        # `monitors[null] = entry`, quietly corrupting the array.
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        i = js.index("function cloneMonitor")
        block = js[i : i + 700]
        self.assertIn("_monitorEditIdx = -1;", block)
        self.assertNotIn("_monitorEditIdx = null;", block)


if __name__ == "__main__":
    unittest.main()
