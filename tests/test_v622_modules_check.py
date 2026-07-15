"""v6.2.2 "Pu1seMatters" — forced kernel-module visibility check.

An agent execution context that cannot see /lib/modules/<running kernel>
builds module-less, unbootable initrds on the next package upgrade. The agent
reports `modules_visible` (omitted where no initramfs generator exists), the
server surfaces a FORCED Checks row plus a modules_hidden CONDITION alert
(fires on first contact, auto-resolves on recovery).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-mod-"))
_spec = importlib.util.spec_from_file_location("api_v622_mod", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import checks  # noqa: E402  (sys.path has cgi-bin)

_AGENT = _ROOT / "client" / "remotepower-agent.py"


class TestForcedCheckRow(unittest.TestCase):
    """checks.py is pure — drive it for real, no source greps."""

    def _rows(self, si, disabled=None):
        dev = {"sysinfo": si, "last_seen": 1000}
        return checks._host_checks("d1", dev, {}, disabled or [], 1000, 180)

    def _mod_row(self, si, disabled=None):
        rows = [r for r in self._rows(si, disabled) if r["key"] == "modules"]
        return rows[0] if rows else None

    def test_hidden_is_critical(self):
        row = self._mod_row({"modules_visible": False})
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "critical")
        self.assertIn("initramfs", row["output"])

    def test_visible_is_ok(self):
        row = self._mod_row({"modules_visible": True})
        self.assertEqual(row["status"], "ok")

    def test_absent_field_means_no_row(self):
        """Tri-state: the agent omits the field on hosts with no initramfs
        generator (WSL, minimal containers). No row — not a false critical."""
        self.assertIsNone(self._mod_row({"mounts": []}))

    def test_check_is_forced_ignores_disable_list(self):
        """THE point: this signal must not be muteable into invisibility.
        A disabled 'modules' key still yields an ENABLED row (and so still
        counts in _host_check_summary)."""
        row = self._mod_row({"modules_visible": False}, disabled=["modules"])
        self.assertIsNotNone(row)
        self.assertTrue(row["enabled"])
        summ = api._host_check_summary(
            self._rows({"modules_visible": False}, disabled=["modules"]))
        self.assertGreaterEqual(summ["counts"]["critical"], 1)

    def test_other_checks_remain_disableable(self):
        """The carve-out must not leak: 'reachability' still honours the list."""
        rows = self._rows({"modules_visible": True}, disabled=["reachability"])
        reach = [r for r in rows if r["key"] == "reachability"][0]
        self.assertFalse(reach["enabled"])


class TestConditionAlert(unittest.TestCase):
    """Drive _ingest_posture_v3110 for real; stub only fire_webhook."""

    def setUp(self):
        self.dev = "dev-mod-1"
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        try:
            api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        except Exception:
            pass

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def _ingest(self, mv):
        si = {"mounts": []}
        if mv is not None:
            si["modules_visible"] = mv
        api._ingest_posture_v3110(self.dev, "host-m", si)

    def _events(self):
        return [e for e, _ in self.fired]

    def test_condition_fires_on_first_contact(self):
        """Unlike the edge tripwires, a host that ENROLS with modules hidden
        is exactly the host about to brick — first sight must fire."""
        self._ingest(False)
        self.assertIn("modules_hidden", self._events())

    def test_steady_hidden_does_not_refire(self):
        self._ingest(False)
        self.fired.clear()
        self._ingest(False)
        self.assertNotIn("modules_hidden", self._events())

    def test_recovery_fires_restore_once(self):
        self._ingest(False)
        self.fired.clear()
        self._ingest(True)
        self.assertIn("modules_visible_restored", self._events())
        self.fired.clear()
        self._ingest(True)
        self.assertEqual(self._events(), [])

    def test_visible_from_the_start_is_silent(self):
        self._ingest(True)
        self.assertEqual(self._events(), [])

    def test_payload_detail_names_the_fix(self):
        self._ingest(False)
        p = [p for e, p in self.fired if e == "modules_hidden"][0]
        self.assertIn("ProtectKernelModules", p["detail"])


class TestAutoResolveRealPath(unittest.TestCase):
    """Recover matching through the REAL _record_alert/fire_webhook path — a
    hand-built alert dict bypasses the payload whitelist and false-greens."""

    def setUp(self):
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._invalidate_load_cache(api.ALERTS_FILE)

    def _open(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        store = api.load(api.ALERTS_FILE) or {}
        return [a for a in store.get("alerts", [])
                if a.get("event") == "modules_hidden"
                and not a.get("resolved_at")]

    def test_restore_resolves_the_open_alert(self):
        api._record_alert("modules_hidden",
                          {"device_id": "dev-ar-1", "name": "h", "detail": "x"})
        self.assertEqual(len(self._open()), 1, "firing must open exactly one alert")
        api._auto_resolve_alerts("modules_visible_restored",
                                 {"device_id": "dev-ar-1", "name": "h"})
        self.assertEqual(len(self._open()), 0)


class TestGateAndWiring(unittest.TestCase):
    def test_registry_pair(self):
        ev = api.EVENT_REGISTRY["modules_hidden"]
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn(ev["kind"], kinds)
        self.assertEqual(ev["severity"], "critical")
        rec = api.EVENT_REGISTRY["modules_visible_restored"]
        self.assertIn("modules_hidden", rec["resolves"])

    def test_posture_gate_presence_tests_the_field(self):
        """THE trap, one level deeper than the v6.2.0 usb note: the ingest gate
        is an any()-TRUTHY check, and the value that matters here is False —
        falsy. The gate must presence-test modules_visible explicitly."""
        src = (_CGI / "api.py").read_text()
        i = src.index("_ingest_posture_v3110(dev_id, saved_dev.get('name'")
        gate = src[max(0, i - 900):i]
        self.assertIn("_si.get('modules_visible') is not None", gate)

    def test_safe_si_whitelists_the_field(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe_si['modules_visible']", src)

    def test_agent_collector_shape(self):
        """The agent gates on an initramfs generator, skips WSL, and goes
        through host_path() so the containerized agent reads the HOST."""
        src = _AGENT.read_text()
        i = src.index("out['modules_visible']")
        fn = src[max(0, i - 900):i + 300]
        self.assertIn("update-initramfs", fn)
        self.assertIn("microsoft", fn)
        self.assertIn("host_path(", fn)

    def test_frontend_has_both_spots(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn("'modules_hidden'", js)
        self.assertIn("case 'modules_hidden':", js)


if __name__ == "__main__":
    unittest.main()
