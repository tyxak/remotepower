"""v6.2.2 — NIC errors/drops event (data-binding gap fill).

The agent always reported per-interface error/drop counters and the Checks page
got a row, but nothing ever FIRED — so a NIC shedding packets (failing cable,
dirty SFP, dying switch port) could never page. This wires the edge-triggered,
per-interface nic_errors event with a per-iface auto-resolve. Driven through
the REAL _ingest_posture_v3110 / _record_alert / _auto_resolve_alerts path — a
hand-built alert dict would bypass the payload whitelist and false-green.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-nic-"))
_spec = importlib.util.spec_from_file_location("api_v622_nic", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestNicErrorEvent(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-nic-1"
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        try:
            api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        except Exception:
            pass

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def _ingest(self, nio):
        api._ingest_posture_v3110(self.dev, "host-n", {"mounts": [], "network_io": nio})

    def _events(self):
        return [e for e, _ in self.fired]

    def test_first_contact_baselines_silently(self):
        self._ingest([{"iface": "eth0", "err_delta": 5}])
        self.assertNotIn("nic_errors", self._events())

    def test_new_erroring_iface_fires_once(self):
        self._ingest([{"iface": "eth0", "err_delta": 0}])
        self.fired.clear()
        self._ingest([{"iface": "eth0", "err_delta": 12}])
        evs = [p for e, p in self.fired if e == "nic_errors"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["iface"], "eth0")
        self.assertIn("12", evs[0]["detail"])

    def test_steady_errors_do_not_refire(self):
        self._ingest([{"iface": "eth0", "err_delta": 0}])
        self._ingest([{"iface": "eth0", "err_delta": 4}])
        self.fired.clear()
        self._ingest([{"iface": "eth0", "err_delta": 4}])  # still erroring
        self.assertNotIn("nic_errors", self._events())

    def test_recovery_fires_cleared(self):
        self._ingest([{"iface": "eth0", "err_delta": 0}])
        self._ingest([{"iface": "eth0", "err_delta": 4}])
        self.fired.clear()
        self._ingest([{"iface": "eth0", "err_delta": 0}])  # stopped
        self.assertIn("nic_errors_cleared", self._events())

    def test_per_iface_independence(self):
        """eth1 erroring must not clear eth0's still-open state, and recovery on
        eth0 must not clear eth1."""
        self._ingest([{"iface": "eth0", "err_delta": 0}, {"iface": "eth1", "err_delta": 0}])
        self._ingest([{"iface": "eth0", "err_delta": 3}, {"iface": "eth1", "err_delta": 0}])
        self.fired.clear()
        # eth1 starts erroring; eth0 keeps erroring (no re-fire), no clear for eth0.
        self._ingest([{"iface": "eth0", "err_delta": 3}, {"iface": "eth1", "err_delta": 9}])
        evs = [(e, p.get("iface")) for e, p in self.fired]
        self.assertIn(("nic_errors", "eth1"), evs)
        self.assertNotIn(("nic_errors", "eth0"), evs)
        self.assertNotIn("nic_errors_cleared", self._events())


class TestAutoResolveRealPath(unittest.TestCase):
    def setUp(self):
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._invalidate_load_cache(api.ALERTS_FILE)

    def _open(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        store = api.load(api.ALERTS_FILE) or {}
        return [a for a in store.get("alerts", [])
                if a.get("event") == "nic_errors" and not a.get("resolved_at")]

    def test_cleared_resolves_only_its_own_iface(self):
        api._record_alert("nic_errors", {"device_id": "d1", "name": "h",
                                         "iface": "eth0", "detail": "x"})
        api._record_alert("nic_errors", {"device_id": "d1", "name": "h",
                                         "iface": "eth1", "detail": "y"})
        self.assertEqual(len(self._open()), 2)
        # Recover eth0 only — eth1 must stay open.
        api._auto_resolve_alerts("nic_errors_cleared",
                                 {"device_id": "d1", "name": "h", "iface": "eth0"})
        open_ifaces = {a["payload"].get("iface") for a in self._open()}
        self.assertEqual(open_ifaces, {"eth1"})


class TestWiring(unittest.TestCase):
    def test_registry_pair(self):
        ev = api.EVENT_REGISTRY["nic_errors"]
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn(ev["kind"], kinds)
        self.assertEqual(ev["severity"], "high")
        self.assertIn("nic_errors", api.EVENT_REGISTRY["nic_errors_cleared"]["resolves"])

    def test_network_io_in_posture_gate(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("_ingest_posture_v3110(dev_id, saved_dev.get('name'")
        gate = src[max(0, i - 900):i]
        self.assertIn("'network_io'", gate)

    def test_iface_whitelisted_in_record_alert(self):
        src = (_CGI / "api.py").read_text()
        # the sub_match key must be stored on the alert or resolve silently fails
        self.assertIn("'iface'", src)

    def test_frontend_both_spots(self):
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("'nic_errors'", js)
        self.assertIn("case 'nic_errors':", js)


if __name__ == "__main__":
    unittest.main()
