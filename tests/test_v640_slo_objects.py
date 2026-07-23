"""v6.4.0 — SLA/SLO objects for remote probes (monitors).

An SLA/SLO object is a named availability target (`slo_objects` in config:
id/name/target_pct/window_days/description). Monitors attach to objects via
``slo_ids`` (checkboxes in the monitor editor); ``GET /api/slo`` gains an
``objects`` list with per-object check-weighted availability + error budget
over each object's own window, and the same numbers export as Prometheus
gauges. Also guards the v6.4.0 bug fix that pausing a monitor made it VANISH
from ``GET /api/monitor`` (no display row → the v6.1.2 Resume button was
unreachable).

These tests drive the REAL handlers (handle_config_save / _compute_slo /
handle_monitor_run) — only identity/transport is stubbed.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-slo-"))
_spec = importlib.util.spec_from_file_location("api_v640_slo", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import prometheus_export  # noqa: E402


class _Base(unittest.TestCase):
    """Point the touched stores at a per-test tmp dir; stub identity only."""

    _FILES = ("CONFIG_FILE", "USERS_FILE", "ROLES_FILE", "MON_HIST_FILE",
              "SATELLITE_MON_FILE", "SATELLITES_FILE", "DEVICES_FILE")

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in self._FILES:
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "require_auth", "verify_token",
                       "audit_log", "fire_webhook", "respond", "method",
                       "get_json_obj")}
        api.require_admin_auth = lambda: "jakob"
        api.require_auth = lambda *a, **k: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            self.cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        api._LOAD_CACHE.clear()

    def _save(self, body):
        self.cap.clear()
        api.get_json_obj = lambda: body
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return api.load(api.CONFIG_FILE) or {}


class TestSloObjectConfigSave(_Base):
    def test_objects_validated_ids_minted_garbage_dropped(self):
        cfg = self._save({"slo_objects": [
            {"name": "Web", "target_pct": 99.9, "window_days": 30,
             "description": "public web"},
            {"name": "DNS", "target_pct": "99.5"},
            {"name": "", "target_pct": 99},     # no name -> dropped
            "garbage",                           # not a dict -> dropped
        ]})
        objs = cfg.get("slo_objects")
        self.assertEqual([o["name"] for o in objs], ["Web", "DNS"])
        for o in objs:
            self.assertTrue(o["id"].startswith("slo-"),
                            "ids must be non-numeric by construction (data-arg "
                            f"coercion gotcha): {o['id']}")
        self.assertEqual(objs[0]["window_days"], 30)
        self.assertEqual(objs[1]["target_pct"], 99.5)
        self.assertEqual(objs[1]["window_days"], 30)   # default

    def test_out_of_range_target_rejected(self):
        self._save({"slo_objects": [{"name": "bad", "target_pct": 150}]})
        self.assertEqual(self.cap.get("s"), 400)
        self._save({"slo_objects": [{"name": "bad", "target_pct": 0}]})
        self.assertEqual(self.cap.get("s"), 400)

    def test_window_clamped(self):
        cfg = self._save({"slo_objects": [
            {"name": "x", "target_pct": 99, "window_days": 4000}]})
        self.assertEqual(cfg["slo_objects"][0]["window_days"], 365)

    def test_existing_id_kept_and_duplicates_dropped(self):
        cfg = self._save({"slo_objects": [
            {"id": "slo-abc", "name": "A", "target_pct": 99},
            {"id": "slo-abc", "name": "B", "target_pct": 98}]})
        objs = cfg["slo_objects"]
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]["id"], "slo-abc")

    def test_monitor_slo_ids_survive_save_on_both_entry_shapes(self):
        cfg = self._save({"monitors": [
            {"label": "web", "type": "http", "target": "https://example.com/",
             "slo_ids": ["slo-a", "bad id $$$", "slo-a"]},
            {"label": "flow", "type": "http_flow",
             "steps": [{"url": "https://example.com/login"}],
             "slo_ids": ["slo-b"]},
        ]})
        mons = {m["label"]: m for m in cfg["monitors"]}
        # charset-cleaned + deduped; a cleaned-but-unknown id is harmless
        self.assertEqual(mons["web"]["slo_ids"], ["slo-a", "badid"])
        self.assertEqual(mons["flow"]["slo_ids"], ["slo-b"])

    def test_deleting_an_object_prunes_monitor_attachments(self):
        cfg = self._save({"slo_objects": [{"name": "Web", "target_pct": 99.9}]})
        sid = cfg["slo_objects"][0]["id"]
        self._save({"monitors": [
            {"label": "web", "type": "http", "target": "https://example.com/",
             "slo_ids": [sid]}]})
        cfg = self._save({"slo_objects": []})
        mon = cfg["monitors"][0]
        self.assertNotIn("slo_ids", mon,
                         "deleted object left a stale attachment behind")

    def test_config_get_exposes_slo_objects_default(self):
        self.cap.clear()
        try:
            api.handle_config_get()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap["s"], 200)
        self.assertEqual(self.cap["b"].get("slo_objects"), [])


class TestComputeSloObjects(_Base):
    def _seed(self, hist, slo_objects, monitors):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["slo_objects"] = slo_objects
        cfg["monitors"] = monitors
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.MON_HIST_FILE, hist)
        api._LOAD_CACHE.clear()

    def test_availability_budget_and_window(self):
        now = int(time.time())
        hist = {
            # 100 in-window checks, 1 failure -> 99.0% (< 99.9 target, breached)
            "web": ([{"ts": now - 40 * 86400, "ok": False}] +   # outside window
                    [{"ts": now - i * 3600, "ok": i != 5, "ms": 40}
                     for i in range(100)]),
            "dns": [{"ts": now - i * 3600, "ok": True} for i in range(50)],
        }
        self._seed(hist,
                   [{"id": "slo-web", "name": "Web", "target_pct": 99.9,
                     "window_days": 30},
                    {"id": "slo-dns", "name": "DNS", "target_pct": 99.0,
                     "window_days": 7}],
                   [{"label": "web", "type": "http", "target": "https://x/",
                     "slo_ids": ["slo-web"]},
                    {"label": "dns", "type": "dns", "target": "x.com",
                     "slo_ids": ["slo-dns"]}])
        objs = {o["name"]: o for o in api._compute_slo()["objects"]}
        web, dns = objs["Web"], objs["DNS"]
        self.assertEqual(web["checks"], 100)   # the 40-day-old row is excluded
        self.assertAlmostEqual(web["availability"], 99.0, places=2)
        self.assertFalse(web["meeting_slo"])
        self.assertGreater(web["burn_rate"], 1)
        self.assertTrue(dns["meeting_slo"])
        self.assertEqual(dns["budget_remaining_pct"], 100.0)
        # breached sorts before meeting
        names = [o["name"] for o in api._compute_slo()["objects"]]
        self.assertEqual(names, ["Web", "DNS"])

    def test_fanout_history_keys_count_toward_the_object(self):
        now = int(time.time())
        hist = {
            "lan · host1": [{"ts": now - 60, "ok": True}],
            "lan · host2": [{"ts": now - 60, "ok": False}],
            "lanother":    [{"ts": now - 60, "ok": False}],   # NOT a fan-out of 'lan'
        }
        self._seed(hist,
                   [{"id": "slo-lan", "name": "LAN", "target_pct": 99,
                     "window_days": 7}],
                   [{"label": "lan", "type": "ping", "target": "t",
                     "target_kind": "tag", "slo_ids": ["slo-lan"]}])
        obj = api._compute_slo()["objects"][0]
        self.assertEqual(obj["checks"], 2)
        self.assertAlmostEqual(obj["availability"], 50.0, places=1)

    def test_object_with_no_data_reports_none_not_breach(self):
        self._seed({}, [{"id": "slo-x", "name": "Empty", "target_pct": 99.9,
                         "window_days": 30}],
                   [{"label": "m", "type": "ping", "target": "1.2.3.4",
                     "slo_ids": ["slo-x"]}])
        obj = api._compute_slo()["objects"][0]
        self.assertIsNone(obj["availability"])
        self.assertIsNone(obj["meeting_slo"])
        self.assertEqual([m["label"] for m in obj["monitors"]], ["m"])

    def test_unknown_slo_id_is_ignored(self):
        self._seed({}, [{"id": "slo-x", "name": "X", "target_pct": 99}],
                   [{"label": "m", "type": "ping", "target": "1.2.3.4",
                     "slo_ids": ["slo-gone"]}])
        obj = api._compute_slo()["objects"][0]
        self.assertEqual(obj["monitors"], [])

    def test_prometheus_gauges_for_measured_objects(self):
        now = int(time.time())
        self._seed({"web": [{"ts": now - 60, "ok": True}]},
                   [{"id": "slo-web", "name": "Web SLO", "target_pct": 99.9,
                     "window_days": 30},
                    {"id": "slo-new", "name": "Fresh", "target_pct": 99.9,
                     "window_days": 30}],
                   [{"label": "web", "type": "http", "target": "https://x/",
                     "slo_ids": ["slo-web"]}])
        txt = prometheus_export.generate_metrics(api._build_metrics_ctx())
        self.assertIn('remotepower_slo_object_availability_percent{name="Web SLO"}', txt)
        self.assertIn('remotepower_slo_object_budget_remaining_percent{name="Web SLO"}', txt)
        # an object with no measured checks yet must NOT export a 0 (reads as
        # a hard breach on a freshly created object)
        self.assertNotIn('name="Fresh"', txt)


class TestPausedMonitorDisplayRow(_Base):
    """v6.4.0 bug fix: a paused monitor must still get a DISPLAY row from
    GET /api/monitor — before this it vanished from the Remote Checks table,
    making the v6.1.2 PAUSED badge and Resume button unreachable."""

    def setUp(self):
        super().setUp()
        self._exec = api._execute_monitor_checks
        self._persist = api._persist_monitor_results
        api._execute_monitor_checks = lambda monitors: []   # no real probes
        api._persist_monitor_results = lambda results: None

    def tearDown(self):
        api._execute_monitor_checks = self._exec
        api._persist_monitor_results = self._persist
        super().tearDown()

    def _run(self):
        self.cap.clear()
        try:
            api.handle_monitor_run()
        except api.HTTPError:
            pass
        return self.cap["b"]["monitors"]

    def test_paused_monitor_gets_a_display_row(self):
        api.save(api.CONFIG_FILE, {"monitors": [
            {"label": "Paused", "type": "tcp", "target": "10.0.0.9:22",
             "paused": True, "slo_ids": ["slo-x"]}]})
        api._LOAD_CACHE.clear()
        rows = self._run()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "Paused")
        self.assertTrue(rows[0]["paused"])

    def test_paused_satellite_monitor_gets_one_row_not_two(self):
        api.save(api.CONFIG_FILE, {"monitors": [
            {"label": "Sat", "type": "ping", "target": "10.9.9.9",
             "via_satellite": "sat-1", "paused": True}]})
        api._LOAD_CACHE.clear()
        rows = self._run()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["paused"])


class TestFrontendWiring(unittest.TestCase):
    """The SLO panel + monitor-editor checkboxes exist in the shipped UI."""

    def setUp(self):
        self.html = (ROOT / "server" / "html" / "index.html").read_text()
        self.js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()

    def test_panel_and_modal_shipped(self):
        for needle in ('id="mon-panel-slo"', 'id="slo-tbody"',
                       'id="slo-status-filter"', 'id="slo-edit-modal"',
                       'id="mon-slo-grp"', 'id="mon-slo-list"'):
            self.assertIn(needle, self.html, needle)

    def test_slo_modal_is_at_body_level_not_inside_container(self):
        # stacking-context trap: overlays inside .container render under the
        # sidebar (see CLAUDE.md) — new modals must sit with the others.
        app_end = self.html.index("<!-- /app -->")
        self.assertGreater(self.html.index('id="slo-edit-modal"'), app_end)

    def test_js_functions_shipped_and_wired(self):
        for needle in ("function loadSloObjects", "function _renderSloObjects",
                       "function openSloAdd", "function editSloObject",
                       "async function saveSloObject",
                       "async function removeSloObject",
                       "_collectMonitorSlos", "_fillMonitorSlos",
                       "'mon-panel-slo'"):
            self.assertIn(needle, self.js, needle)
        # page loader actually calls it
        self.assertIn("loadSloObjects();", self.js)

    def test_slo_table_headers_carry_data_col(self):
        i = self.html.index('id="slo-thead"')
        block = self.html[i:i + 700]
        for col in ("name", "target", "window", "probes", "availability",
                    "budget", "status"):
            self.assertIn(f'data-col="{col}"', block, col)


if __name__ == "__main__":
    unittest.main()
