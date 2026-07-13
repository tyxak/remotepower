"""v6.1.3 — host-wide disk-usage explorer (competitive-gap item #22).

"Disk 94% — of WHAT?" Disk-fill forecasting has always been able to say WHEN a
mount fills up (forecast.forecast_mounts, 6 months of daily samples); nothing
said what to delete. This closes that loop.

Design notes the tests pin:
  * du is shelled, not hand-rolled in Python — it solves hardlink double-counting,
    sparse files and bind mounts, which an os.walk + st_blocks summer gets subtly
    wrong. The server's own AI disk diagnostic already trusts the same idioms.
  * The cadence is a PERSISTED wall-clock timestamp, never `poll_count % N`.
    poll_count is process-local and resets on every agent restart, so a
    restart-churny host would never scan — the v6.1.2 trivy bug, exactly.
  * The ingest CARRIES FORWARD: the scan runs ~12-hourly, so the report is absent
    from ~99% of heartbeats. Without carry-forward the panel renders empty almost
    always (the same reason docker_df carries forward).
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-du-"))
_spec = importlib.util.spec_from_file_location("api_v613_du", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_AGENT = _ROOT / "client" / "remotepower-agent.py"
_aspec = importlib.util.spec_from_file_location("rp_agent_du", _AGENT)
agent = importlib.util.module_from_spec(_aspec)
_aspec.loader.exec_module(agent)


class TestDuParser(unittest.TestCase):
    """Pure — no filesystem needed."""

    def test_parses_and_sorts_biggest_first(self):
        out = "1024\t/var/log\n8192\t/var/lib\n512\t/var/tmp\n99999\t/var\n"
        rows = agent._parse_du(out, "/var")
        self.assertEqual([r["path"] for r in rows], ["/var/lib", "/var/log", "/var/tmp"])
        self.assertEqual(rows[0]["bytes"], 8192)

    def test_drops_the_root_total_line(self):
        """du prints the root's own total last — it is the SUM of the children,
        not a child. Including it would double every number in the panel."""
        rows = agent._parse_du("100\t/var/log\n999\t/var\n", "/var")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], "/var/log")

    def test_ignores_junk_lines(self):
        rows = agent._parse_du("du: cannot read: /var/x\n100\t/var/log\n", "/var")
        self.assertEqual([r["path"] for r in rows], ["/var/log"])

    def test_caps_at_top_n(self):
        out = "".join(f"{i}\t/var/d{i}\n" for i in range(1, 60))
        self.assertLessEqual(len(agent._parse_du(out, "/var")), agent._DU_TOP_N)


class TestDuCadenceIsRestartSafe(unittest.TestCase):
    def test_uses_a_persisted_timestamp_not_poll_count(self):
        """poll_count % N resets to 0 on every agent restart, so a host that
        restarts more often than the interval NEVER scans. This is the exact
        bug that made the trivy image scan dead on arrival (v6.1.2)."""
        src = _AGENT.read_text()
        self.assertIn("def _load_du_scan_ts", src)
        self.assertIn("def _save_du_scan_ts", src)
        # The call site must gate on the timestamp, not the modulo.
        i = src.index("_du_due =")
        window = src[i:i + 400]
        self.assertIn("last_du_scan_ts", window)
        self.assertNotIn("poll_count %", window)

    def test_collector_bounds_itself(self):
        """It runs unattended on someone's NAS: it must never cross a filesystem
        boundary (into /proc, an NFS mount, a 40TB media array) and must be
        time-bounded."""
        src = _AGENT.read_text()
        fn = src[src.index("def collect_disk_usage"):src.index("def _load_image_scan_ts")]
        self.assertIn("'-x'", fn, "must not cross filesystem boundaries")
        self.assertIn("--max-depth=1", fn)
        self.assertIn("timeout", fn)
        self.assertIn("host_path(", fn, "must resolve host paths in a container")


class TestDuIngest(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-du-1"
        api._entity_write_one(api.DISK_USAGE_FILE, self.dev, {})

    def _rec(self):
        return api._entity_read_one(api.DISK_USAGE_FILE, self.dev, None) or {}

    def test_ingest_persists_the_report(self):
        api._ingest_disk_usage(self.dev, {
            "/var": [{"path": "/var/lib/docker", "bytes": 80_000_000_000},
                     {"path": "/var/log", "bytes": 2_000_000_000}],
        }, time.time())
        rec = self._rec()
        self.assertIn("/var", rec["paths"])
        self.assertEqual(rec["paths"]["/var"][0]["bytes"], 80_000_000_000)
        self.assertTrue(rec["ts"])

    def test_absent_report_carries_the_previous_one_forward(self):
        """The scan runs ~12-hourly, so ~99% of heartbeats carry no report. If an
        empty beat wiped the record, the drawer panel would be blank almost always."""
        api._ingest_disk_usage(self.dev, {"/var": [{"path": "/var/log", "bytes": 5}]},
                               time.time())
        api._ingest_disk_usage(self.dev, {}, time.time())          # a normal beat
        self.assertIn("/var", self._rec().get("paths", {}))

    def test_garbage_is_dropped_not_stored(self):
        api._ingest_disk_usage(self.dev, {"/var": [{"path": "/x", "bytes": "huge"},
                                                   {"bogus": 1}]}, time.time())
        self.assertEqual(self._rec(), {})

    def test_entries_are_capped(self):
        big = [{"path": f"/var/d{i}", "bytes": i} for i in range(200)]
        api._ingest_disk_usage(self.dev, {"/var": big}, time.time())
        self.assertLessEqual(len(self._rec()["paths"]["/var"]), api._DU_MAX_ENTRIES)


class TestWiring(unittest.TestCase):
    def test_config_defaults_off(self):
        """It walks the filesystem — it must be opt-in."""
        safe = api._config_ro()
        self.assertFalse(safe.get("du_scan_enabled", False))

    def test_scan_endpoint_is_write_gated_not_just_authed(self):
        """A bare require_auth() admits the READ-ONLY roles (viewer/mcp/auditor/
        finance) — the recurring write-gate bug class. Queuing work on a host is
        a mutation and must gate on require_write_role."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def handle_disk_usage_scan"):
                 src.index("def handle_secrets_scan_now")]
        self.assertIn("require_write_role", fn)

    def test_routes_registered(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("'/disk-usage/scan'", src)
        self.assertIn("'/disk-usage'", src)

    def test_store_is_registered_with_the_storage_backend(self):
        """A DATA_DIR json that isn't declared to storage.py doesn't persist
        correctly under the SQLite/Postgres backends."""
        st = (_CGI / "storage.py").read_text()
        self.assertIn("'disk_usage.json'", st)

    def test_force_flag_is_actually_delivered_to_the_agent(self):
        """The 'feature that can never fire' class: the agent honours a flag the
        server never sets. Both halves must exist."""
        src = (_CGI / "api.py").read_text()
        self.assertIn("common_resp['force_du_scan'] = True", src)
        self.assertIn("dev['force_du_scan'] = True", src)
        self.assertIn("resp.get('force_du_scan')", _AGENT.read_text())

    def test_settings_ui_load_and_save_both_wired(self):
        """A toggle that loads but never saves (or vice versa) is the silent
        half-wiring the RAG-source whitelist bug taught us to check."""
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        html = (_ROOT / "server" / "html" / "index.html").read_text()
        self.assertIn('id="cfg-du-scan-enabled"', html)
        self.assertIn("payload.du_scan_enabled", js)       # save
        self.assertIn("_duEn.checked = !!data.du_scan_enabled", js)   # load

    def test_frontend_restringifies_the_device_id(self):
        """The data-action dispatcher coerces numeric-looking args to Number —
        a hex device id like '1e5' would silently become 100000."""
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        fn = js[js.index("async function duScan"):js.index("function _fmtBytes")]
        self.assertIn("String(devId)", fn)


if __name__ == "__main__":
    unittest.main()
