"""v5.0.0 follow-on features:
  - CMDB primary_interface + nat_ip (with a NAT IP shown as a child)
  - device decommissioning (greyed out + monitoring forced off)
  - the Network Metrics page (per-device throughput, scoped fleet/group/tag/site)
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_DATA = tempfile.mkdtemp(prefix="rp-v500f-")
os.environ["RP_DATA_DIR"] = _DATA
_spec = importlib.util.spec_from_file_location("api_v500f", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

API_SRC = (_CGI / "api.py").read_text()
HTML = (_ROOT / "server" / "html" / "index.html").read_text()
APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
APP_NET = (_ROOT / "server" / "html" / "static" / "js" / "app-network.js").read_text()
APP_CMDB = (_ROOT / "server" / "html" / "static" / "js" / "app-cmdb.js").read_text()


class _Stop(Exception):
    pass


def _capture_respond():
    """Patch api.respond to capture (status, body) and stop the handler."""
    box = {}

    def _cap(status, body=None):
        box["status"], box["body"] = status, body
        raise _Stop()

    api.respond = _cap
    return box


# ───────────────────────── CMDB primary interface + NAT IP ──────────────────────
class TestCmdbInterfaceNat(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "monitored": True}})
        api.save(api.CMDB_FILE, {})
        self._auth = api.require_auth
        self._scope = api._scope_block_device
        self._method = api.method
        self._body = api.get_json_body
        api.require_auth = lambda *a, **k: "tester"
        api._scope_block_device = lambda *a, **k: None
        api.method = lambda: "PUT"

    def tearDown(self):
        api.require_auth = self._auth
        api._scope_block_device = self._scope
        api.method = self._method
        api.get_json_body = self._body

    def test_record_default_has_fields(self):
        rec = api._cmdb_record_default()
        self.assertIn("primary_interface", rec)
        self.assertIn("nat_ip", rec)

    def test_valid_iface_and_nat_ip_saved(self):
        api.get_json_body = lambda: {"primary_interface": "ens18", "nat_ip": "203.0.113.10"}
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_cmdb_update("d1")
        self.assertEqual(box["status"], 200)
        rec = api._cmdb_load()["d1"]
        self.assertEqual(rec["primary_interface"], "ens18")
        self.assertEqual(rec["nat_ip"], "203.0.113.10")

    def test_bad_interface_rejected(self):
        api.get_json_body = lambda: {"primary_interface": "eth0; rm -rf /"}
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_cmdb_update("d1")
        self.assertEqual(box["status"], 400)

    def test_bad_nat_ip_rejected(self):
        api.get_json_body = lambda: {"nat_ip": "not-an-ip"}
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_cmdb_update("d1")
        self.assertEqual(box["status"], 400)

    def test_cmdb_list_exposes_fields(self):
        # source-level: the list/get endpoints surface the new fields
        self.assertIn("'primary_interface': rec_safe.get('primary_interface'", API_SRC)
        self.assertIn("'nat_ip':          rec_safe.get('nat_ip'", API_SRC)

    def test_frontend_wires_fields(self):
        self.assertIn('id="cmdb-asset-primary-interface"', HTML)
        self.assertIn('id="cmdb-asset-nat-ip"', HTML)
        self.assertIn("primary_interface:", APP_CMDB)
        self.assertIn("nat_ip:", APP_CMDB)
        self.assertIn("cmdb-nat-child", APP_CMDB)   # NAT shown as a child


# ───────────────────────────── decommissioning ─────────────────────────────────
class TestDecommission(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "monitored": True}})
        self._auth = api.require_admin_auth
        self._scope = api._scope_block_device
        self._method = api.method
        self._body = api.get_json_obj
        self._audit = api.audit_log
        api.require_admin_auth = lambda *a, **k: "admin"
        api._scope_block_device = lambda *a, **k: None
        api.method = lambda: "PATCH"
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        api.require_admin_auth = self._auth
        api._scope_block_device = self._scope
        api.method = self._method
        api.get_json_obj = self._body
        api.audit_log = self._audit

    def test_decommission_forces_unmonitored(self):
        api.get_json_obj = lambda: {"decommissioned": True}
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_device_decommission("d1")
        self.assertEqual(box["status"], 200)
        dev = api.load(api.DEVICES_FILE)["d1"]
        self.assertTrue(dev["decommissioned"])
        self.assertFalse(dev["monitored"])      # silenced

    def test_recommission_restores_monitoring(self):
        api.save(api.DEVICES_FILE,
                 {"d1": {"name": "web01", "monitored": False, "decommissioned": True}})
        api.get_json_obj = lambda: {"decommissioned": False}
        _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_device_decommission("d1")
        dev = api.load(api.DEVICES_FILE)["d1"]
        self.assertFalse(dev["decommissioned"])
        self.assertTrue(dev["monitored"])       # monitoring restored

    def test_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(
            resolve_route("PATCH", "/api/devices/d1/decommissioned")[0],
            "handle_device_decommission")

    def test_bulk_save_also_handles_it(self):
        self.assertIn("if 'decommissioned' in body:", API_SRC)

    def test_frontend_greys_out(self):
        self.assertIn("decommissioned", APP)            # device card class
        self.assertIn(".device-card.decommissioned", (
            _ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text())
        self.assertIn('id="cmdb-asset-decommissioned"', HTML)


# ─────────────────────────── network metrics page ──────────────────────────────
class TestNetworkMetrics(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "web01", "group": "web", "site": "cust-a",
                   "monitored": True,
                   "sysinfo": {"network_io": [
                       {"iface": "eth0", "rx_bps": 1000, "tx_bps": 500},
                       {"iface": "eth1", "rx_bps": 200, "tx_bps": 100}]}},
            "d2": {"name": "db01", "group": "db", "site": "cust-a",
                   "monitored": True,
                   "sysinfo": {"network_io": [
                       {"iface": "eth0", "rx_bps": 50, "tx_bps": 50}]}},
            "d3": {"name": "idle", "group": "web", "site": "cust-b",
                   "monitored": True, "sysinfo": {}},   # no io → not reporting
        })
        self._auth = api.require_auth
        self._scope = api._scope_filter_devices
        api.require_auth = lambda *a, **k: "tester"
        api._scope_filter_devices = lambda d, *a, **k: d

    def tearDown(self):
        api.require_auth = self._auth
        api._scope_filter_devices = self._scope

    def _call(self, by):
        os.environ["QUERY_STRING"] = "by=" + by
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_network_metrics()
        return box["body"]

    def test_fleet_totals(self):
        out = self._call("fleet")
        self.assertEqual(out["by"], "fleet")
        # 1000+200+50 rx, 500+100+50 tx
        self.assertEqual(out["totals"]["rx_bps"], 1250)
        self.assertEqual(out["totals"]["tx_bps"], 650)
        self.assertEqual(out["totals"]["devices"], 3)
        self.assertEqual(out["totals"]["reporting"], 2)   # idle has no io
        # top talker first (web01)
        self.assertEqual(out["devices"][0]["name"], "web01")

    def test_group_rollup(self):
        out = self._call("group")
        tiles = {t["key"]: t for t in out["tiles"]}
        self.assertEqual(tiles["web"]["rx_bps"], 1200)    # web01 only reports
        self.assertEqual(tiles["db"]["rx_bps"], 50)

    def test_site_rollup_is_customer(self):
        out = self._call("site")
        tiles = {t["key"]: t for t in out["tiles"]}
        self.assertEqual(tiles["cust-a"]["rx_bps"], 1250)
        self.assertIn("cust-b", tiles)

    def test_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/network-metrics")[0],
                         "handle_network_metrics")

    def test_frontend_page_and_renderer(self):
        self.assertIn('id="page-netmetrics"', HTML)
        self.assertIn('data-page="netmetrics"', HTML)
        self.assertIn("function loadNetMetrics(", APP_NET)
        self.assertIn("function netMetricsBy(", APP_NET)
        self.assertIn("scrollable-table-wrap audit-scroll", APP_NET)   # box-cap rule
        self.assertIn("wireSortOnly('netmetrics-thead'", APP_NET)       # sortable rule

    def test_nav_dispatch(self):
        self.assertIn("name === 'netmetrics'", APP)

    def test_i18n_nav_label(self):
        i18n = (_ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()
        self.assertIn("'Network metrics'", i18n)


if __name__ == "__main__":
    unittest.main()
