"""v6.4.2 — switch ports get bandwidth history, a link-state alert and an error trend.

`snmp.poll_interfaces()` — a full IF-MIB ifTable walk with in/out octets,
errors and admin/oper status — existed and was reachable only through the
on-demand deep poll, which renders a one-shot table in the drawer. The
recurring 5-minute sweep skipped it, and said so in its own docstring: "ifTable
walking stays on the on-demand deep-poll — too heavy for the 5-minute sweep on
big switches."

So for a switch, router or firewall polled over SNMP there was no per-port
bandwidth history, no utilisation graph, no error trend, and no alert when a
port went down or saturated. The counters were read, shown once, and thrown
away. `nic_errors` only ever fires from agent sysinfo, so it covers
Linux/Windows/Mac hosts and never a switch port — an uplink at 98 % for a week,
or an access port bouncing every night, was invisible unless somebody opened
the deep-poll panel at the exact moment.

The cost decision was real, so this does not override it: the walk is OPT-IN
PER DEVICE. An operator turns it on for the core switch they care about, not
for all forty access switches.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-ifhist-"))

_spec = importlib.util.spec_from_file_location("api_ifhist", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_GIG = 1_000_000_000
_STEP = 300
_LINE_RATE_BYTES = 125_000_000 * _STEP     # bytes carried at exactly 1 Gb/s


def _row(**kw):
    r = {"index": 1, "descr": "gi1/0/12", "admin": "up", "oper": "up",
         "speed_bps": _GIG, "in_octets": 0, "out_octets": 0,
         "in_errors": 0, "out_errors": 0}
    r.update(kw)
    return r


class TestTheRateMaths(unittest.TestCase):
    def test_a_plain_delta(self):
        self.assertEqual(api._if_rate_bps(0, 125_000, 1), 1_000_000.0)

    def test_a_counter_wrap_is_recovered(self):
        """32-bit ifInOctets wraps at ~34 s on a saturated 1 Gb link, so this is
        not an edge case — it is Tuesday."""
        self.assertEqual(api._if_rate_bps(2**32 - 1000, 500, 10, _GIG), 1200.0)

    def test_an_impossible_rate_is_dropped(self):
        """A device reboot resets every counter and is indistinguishable from a
        wrap. The implied rate gives it away — and a fictional peak in a
        utilisation graph is worse than a gap, because a gap is visibly a gap."""
        self.assertIsNone(api._if_rate_bps(0, 10_000_000_000, 1, _GIG))

    def test_a_little_headroom_is_allowed(self):
        """Vendors report ifSpeed in round numbers and a sample interval is
        never exactly the wall-clock gap, so an exact-line-rate sample must not
        be thrown away."""
        self.assertIsNotNone(api._if_rate_bps(0, 125_000_000, 1, _GIG))

    def test_an_unknown_speed_cannot_sanity_check(self):
        self.assertIsNotNone(api._if_rate_bps(0, 10_000_000_000, 1))

    def test_a_zero_interval_is_not_a_division_by_zero(self):
        self.assertIsNone(api._if_rate_bps(0, 100, 0, _GIG))

    def test_junk_counters_do_not_raise(self):
        self.assertIsNone(api._if_rate_bps(None, "x", 10))

    def test_utilisation(self):
        self.assertEqual(api._if_util_pct(900_000_000, _GIG), 90.0)
        self.assertIsNone(api._if_util_pct(1000, 0))
        self.assertIsNone(api._if_util_pct(None, _GIG))

    def test_utilisation_is_capped_at_a_hundred(self):
        self.assertEqual(api._if_util_pct(2 * _GIG, _GIG), 100.0)

    def test_the_port_key_prefers_the_name_an_operator_recognises(self):
        """ifIndex alone is not stable across a reboot on some platforms, and
        an operator thinks in "gi1/0/12"."""
        self.assertEqual(api._if_key({"index": 7, "descr": "gi1/0/12"}), "gi1/0/12")
        self.assertEqual(api._if_key({"index": 7}), "if7")


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("SNMP_IF_HIST_FILE", "SNMP_IF_STATE_FILE", "DEVICES_FILE",
                     "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        self.now = int(time.time())
        self.cap = {}
        self.fired = []
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "_env", "require_auth",
                       "fire_webhook", "_device_snmp_target")}
        api.require_auth = lambda require_admin=False: "jakob"
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, p or {}))
        api._device_snmp_target = lambda dev: ("10.0.0.1", "public", 161)
        self._qs = ""
        _real_env = self._orig["_env"]
        api._env = lambda k, d="": (self._qs if k == "QUERY_STRING"
                                    else _real_env(k, d))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "GET"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def rec(self, rows, step):
        return api._record_if_samples("sw1", rows, self.now + step * _STEP)

    def hist(self, iface="gi1/0/12"):
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        return ((api.load(api.SNMP_IF_HIST_FILE) or {}).get("sw1") or {}).get(iface) or {}


class TestTheHistory(_Base):
    def test_the_first_sample_has_no_rate(self):
        """There is nothing to subtract from — reporting 0 would put a
        fictional idle period at the start of every port's graph."""
        self.rec([_row()], 0)
        self.assertIsNone(self.hist()["samples"][0]["in_bps"])

    def test_a_rate_appears_on_the_second(self):
        self.rec([_row()], 0)
        self.rec([_row(in_octets=int(_LINE_RATE_BYTES * 0.5))], 1)
        self.assertAlmostEqual(self.hist()["samples"][1]["in_bps"], _GIG * 0.5, delta=1e6)

    def test_utilisation_takes_the_busier_direction(self):
        """A port is saturated when EITHER direction is — averaging the two
        hides a full uplink."""
        self.rec([_row()], 0)
        self.rec([_row(in_octets=int(_LINE_RATE_BYTES * 0.9), out_octets=1000)], 1)
        self.assertGreaterEqual(self.hist()["samples"][1]["util"], 89)

    def test_the_ring_is_bounded(self):
        mod = api.snmp_device_handlers_mod
        real = mod._IF_HIST_SAMPLES
        try:
            mod._IF_HIST_SAMPLES = 3
            for i in range(6):
                self.rec([_row(in_octets=i * 1000)], i)
        finally:
            mod._IF_HIST_SAMPLES = real
        self.assertEqual(len(self.hist()["samples"]), 3)

    def test_the_port_count_is_bounded(self):
        mod = api.snmp_device_handlers_mod
        real = mod._IF_HIST_MAX_PORTS
        try:
            mod._IF_HIST_MAX_PORTS = 2
            self.rec([_row(index=i, descr=f"gi1/0/{i}") for i in range(5)], 0)
        finally:
            mod._IF_HIST_MAX_PORTS = real
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        self.assertEqual(len((api.load(api.SNMP_IF_HIST_FILE) or {})["sw1"]), 2)

    def test_ports_do_not_share_history(self):
        self.rec([_row(index=1, descr="gi1/0/1"), _row(index=2, descr="gi1/0/2")], 0)
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        self.assertEqual(sorted((api.load(api.SNMP_IF_HIST_FILE) or {})["sw1"]),
                         ["gi1/0/1", "gi1/0/2"])


class TestLinkStateAlerts(_Base):
    def test_a_port_going_down_fires_once(self):
        self.rec([_row()], 0)
        ev = self.rec([_row(oper="down")], 1)
        self.assertEqual([e for e, _ in ev], ["snmp_if_down"])
        self.assertEqual(self.rec([_row(oper="down")], 2), [])

    def test_it_carries_the_port_name(self):
        self.rec([_row()], 0)
        ev = self.rec([_row(oper="down")], 1)
        self.assertEqual(ev[0][1]["iface"], "gi1/0/12")

    def test_coming_back_up_resolves_it(self):
        self.rec([_row()], 0)
        self.rec([_row(oper="down")], 1)
        ev = self.rec([_row()], 2)
        self.assertEqual([e for e, _ in ev], ["snmp_if_up"])

    def test_an_administratively_shut_port_is_not_an_incident(self):
        """A port the operator disabled reads "down" forever. Alerting on it is
        alerting on the configuration."""
        self.assertEqual(self.rec([_row(admin="down", oper="down")], 0), [])

    def test_the_recover_event_resolves_the_firing_one(self):
        self.assertIn("snmp_if_down",
                      api.EVENT_REGISTRY["snmp_if_up"]["resolves"])

    def test_two_ports_on_one_switch_stay_separate(self):
        """`iface` is in _ALERT_IDENTITY_FIELDS, so two down ports are two
        rows — otherwise fixing one clears the alert for both."""
        self.assertIn("iface", api._ALERT_IDENTITY_FIELDS)


class TestSaturationAlerts(_Base):
    def _busy(self, step, frac=0.95):
        return _row(in_octets=int(_LINE_RATE_BYTES * frac * step))

    def test_one_busy_sample_is_not_an_alert(self):
        """A single spike is a backup job finishing, not a port that needs a
        bigger link."""
        self.rec([_row()], 0)
        self.assertEqual(self.rec([self._busy(1)], 1), [])

    def test_two_in_a_row_is(self):
        self.rec([_row()], 0)
        self.rec([self._busy(1)], 1)
        ev = self.rec([self._busy(2)], 2)
        self.assertEqual([e for e, _ in ev], ["snmp_if_saturated"])
        self.assertGreaterEqual(ev[0][1]["util"], 90)

    def test_it_fires_once_not_every_sweep(self):
        self.rec([_row()], 0)
        self.rec([self._busy(1)], 1)
        self.rec([self._busy(2)], 2)
        self.assertEqual(self.rec([self._busy(3)], 3), [])

    def test_going_quiet_relieves_it(self):
        self.rec([_row()], 0)
        self.rec([self._busy(1)], 1)
        self.rec([self._busy(2)], 2)
        ev = self.rec([_row(in_octets=int(_LINE_RATE_BYTES * 0.95 * 2) + 1000)], 3)
        self.assertEqual([e for e, _ in ev], ["snmp_if_relieved"])

    def test_a_port_that_goes_DOWN_does_not_report_itself_relieved(self):
        """It reads 0 % and would fire "utilisation back to normal" in the same
        breath as "port down" — technically true and useless."""
        self.rec([_row()], 0)
        self.rec([self._busy(1)], 1)
        self.rec([self._busy(2)], 2)
        ev = self.rec([_row(oper="down",
                            in_octets=int(_LINE_RATE_BYTES * 0.95 * 2))], 3)
        self.assertEqual([e for e, _ in ev], ["snmp_if_down"])

    def test_and_it_does_not_re_fire_saturation_when_it_comes_back(self):
        """The flag was cleared silently while the port was down."""
        self.rec([_row()], 0)
        self.rec([self._busy(1)], 1)
        self.rec([self._busy(2)], 2)
        self.rec([_row(oper="down", in_octets=int(_LINE_RATE_BYTES * 0.95 * 2))], 3)
        ev = self.rec([_row(in_octets=int(_LINE_RATE_BYTES * 0.95 * 2) + 1000)], 4)
        self.assertEqual([e for e, _ in ev], ["snmp_if_up"])


class TestTheSweep(_Base):
    def _dev(self, if_history=True):
        api.save(api.DEVICES_FILE, {"sw1": {
            "name": "core-sw", "snmp": {"enabled": True, "if_history": if_history}}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _walk(self, rows):
        import snmp
        self._real_walk = snmp.poll_interfaces
        snmp.poll_interfaces = lambda *a, **k: rows
        self.addCleanup(lambda: setattr(snmp, "poll_interfaces", self._real_walk))

    def test_it_skips_devices_that_did_not_opt_in(self):
        """The main sweep records that walking the ifTable every five minutes
        is too heavy for a big switch. This IS that walk, so it is a decision
        per device rather than a fleet-wide default."""
        self._dev(if_history=False)
        called = []
        import snmp
        real = snmp.poll_interfaces
        snmp.poll_interfaces = lambda *a, **k: called.append(1) or []
        try:
            api.run_snmp_if_history_if_due()
        finally:
            snmp.poll_interfaces = real
        self.assertEqual(called, [])

    def test_it_walks_an_opted_in_device(self):
        self._dev()
        self._walk([_row()])
        api.run_snmp_if_history_if_due()
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        self.assertIn("gi1/0/12", (api.load(api.SNMP_IF_HIST_FILE) or {})["sw1"])

    def test_it_respects_its_interval(self):
        self._dev()
        calls = []
        import snmp
        real = snmp.poll_interfaces
        snmp.poll_interfaces = lambda *a, **k: (calls.append(1), [_row()])[1]
        try:
            api.run_snmp_if_history_if_due()
            api.run_snmp_if_history_if_due()
        finally:
            snmp.poll_interfaces = real
        self.assertEqual(len(calls), 1)

    def test_a_quarantined_switch_is_skipped(self):
        api.save(api.DEVICES_FILE, {"sw1": {
            "name": "sw", "quarantined": True,
            "snmp": {"enabled": True, "if_history": True}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self._walk([_row()])
        api.run_snmp_if_history_if_due()
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        self.assertEqual(api.load(api.SNMP_IF_HIST_FILE) or {}, {})

    def test_the_event_carries_the_device_name(self):
        self._dev()
        self._walk([_row()])
        api.run_snmp_if_history_if_due()
        with api._LockedUpdate(api.SNMP_IF_STATE_FILE) as st:
            st["last_run"] = 0
        api._invalidate_load_cache(api.SNMP_IF_STATE_FILE)
        self._walk([_row(oper="down")])
        api.run_snmp_if_history_if_due()
        self.assertEqual(self.fired[0][1]["name"], "core-sw")

    def test_one_unreachable_switch_does_not_stop_the_others(self):
        api.save(api.DEVICES_FILE, {
            "sw1": {"name": "a", "snmp": {"enabled": True, "if_history": True}},
            "sw2": {"name": "b", "snmp": {"enabled": True, "if_history": True}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        import snmp
        real = snmp.poll_interfaces
        seen = []

        def _walk(host, community, **k):
            seen.append(host)
            if len(seen) == 1:
                raise RuntimeError("timeout")
            return [_row()]
        snmp.poll_interfaces = _walk
        try:
            api.run_snmp_if_history_if_due()
        finally:
            snmp.poll_interfaces = real
        self.assertEqual(len(seen), 2)

    def test_events_fire_outside_the_history_lock(self):
        """fire_webhook takes its own lock, and this one is held across a whole
        device's port set — the recurring lock-nesting bug."""
        from srcpin import py_function
        src = (_CGI / "snmp_device_handlers.py").read_text()
        body = py_function(src, "run_snmp_if_history_if_due")
        tail = body[body.index("for ev, payload in pending:"):]
        self.assertNotIn("_LockedUpdate", tail)


class TestTheEndpoint(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {"sw1": {
            "name": "core", "snmp": {"enabled": True, "if_history": True}}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def test_the_summary_lists_ports(self):
        self.rec([_row()], 0)
        self.rec([_row(in_octets=1_000_000)], 1)
        r = self.call(api.handle_device_snmp_interfaces, "sw1")
        self.assertEqual(len(r["ports"]), 1)
        self.assertEqual(r["ports"][0]["iface"], "gi1/0/12")
        self.assertTrue(r["enabled"])

    def test_the_summary_does_not_ship_every_sample(self):
        """288 samples per port across 128 ports is not a drawer payload."""
        self.rec([_row()], 0)
        r = self.call(api.handle_device_snmp_interfaces, "sw1")
        self.assertNotIn("samples_list", r["ports"][0])
        self.assertEqual(r["ports"][0]["samples"], 1)

    def test_one_port_returns_its_ring(self):
        self.rec([_row()], 0)
        self.rec([_row(in_octets=1_000_000)], 1)
        self._qs = "iface=gi1/0/12"
        r = self.call(api.handle_device_snmp_interfaces, "sw1")
        self.assertEqual(len(r["samples"]), 2)

    def test_an_unknown_port_404s(self):
        self._qs = "iface=nope"
        self.call(api.handle_device_snmp_interfaces, "sw1")
        self.assertEqual(self.cap["s"], 404)

    def test_an_unknown_device_404s(self):
        self.call(api.handle_device_snmp_interfaces, "nope")
        self.assertEqual(self.cap["s"], 404)

    def test_a_device_with_it_switched_off_says_so(self):
        api.save(api.DEVICES_FILE, {"sw1": {"name": "c", "snmp": {"enabled": True}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertFalse(self.call(api.handle_device_snmp_interfaces, "sw1")["enabled"])


class TestWiring(unittest.TestCase):
    def test_every_event_is_registered(self):
        for ev in ("snmp_if_down", "snmp_if_up", "snmp_if_saturated",
                   "snmp_if_relieved"):
            with self.subTest(event=ev):
                self.assertIn(ev, api.EVENT_REGISTRY)
                self.assertIn(ev, {e[0] for e in api.WEBHOOK_EVENTS})

    def test_the_sweep_is_in_both_cadence_registries(self):
        self.assertIn("_safe(run_snmp_if_history_if_due",
                      (_CGI / "api.py").read_text())
        self.assertIn("'run_snmp_if_history_if_due'",
                      (_CGI / "scheduler.py").read_text())

    def test_the_handler_lives_in_the_bound_module(self):
        """api.py is at the inline-handler ratchet ceiling."""
        self.assertEqual(api.handle_device_snmp_interfaces.__module__,
                         "snmp_device_handlers")

    def test_the_per_device_toggle_persists(self):
        from srcpin import py_function
        src = (_CGI / "snmp_device_handlers.py").read_text()
        self.assertIn("snmp_cfg['if_history']", py_function(src, "handle_device_snmp"))

    def test_the_model_knows_the_field(self):
        import request_models
        self.assertIn("if_history",
                      request_models.DeviceSnmpRequest.model_fields)

    def test_the_toggle_is_read_back(self):
        """A write-only setting reads as unchecked next time the drawer opens,
        so the operator turns it on twice and doubts it saved."""
        from srcpin import py_function
        src = (_CGI / "snmp_device_handlers.py").read_text()
        self.assertIn("'if_history':", py_function(src, "handle_device_snmp"))

    def test_the_ui_is_wired(self):
        js = ROOT / "server" / "html" / "static" / "js" / "app.js"
        if not js.exists():
            self.skipTest("excluded from this tree")
        s = js.read_text()
        self.assertIn('id="ds-snmp-if-history"', s)
        self.assertIn("if_history:", s)
        self.assertRegex(s, r"\basync function _drawerSnmpPorts\s*\(")
        self.assertIn("/snmp/interfaces", s)


if __name__ == "__main__":
    unittest.main()


class TestOnePortRecoveringDoesNotClearTheOthers(unittest.TestCase):
    """v6.4.2 (adversarial audit of the session diff): `snmp_if_up` and
    `snmp_if_relieved` shipped with no per-iface `sub_match` branch.

    `iface` was already in `_ALERT_IDENTITY_FIELDS` and in `_record_alert`'s
    payload whitelist — two of the three legs — so the alerts stayed as
    separate rows. But `_auto_resolve_alerts` matched on device id alone, so on
    a 48-port switch the FIRST port to come back up closed every other port's
    open alert. And the still-down ports never re-fire, because their edge
    already triggered: the operator is left with a switch that looks healthy
    and 47 dead ports.

    Driven through the real `_record_alert` → `_auto_resolve_alerts` path — a
    hand-built {'payload': …} dict bypasses the identity coalescing and gives a
    false green, which is the documented lesson from v4.9.0.
    """

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("ALERTS_FILE", "CONFIG_FILE", "DEVICES_FILE",
                     "ALERT_MUTES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        api.save(api.ALERTS_FILE, {"alerts": []})

    def tearDown(self):
        for a, v in self._files.items():
            setattr(api, a, v)

    def _open(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if not a.get("resolved_at")]

    def test_two_down_ports_are_two_rows(self):
        for iface in ("gi1/0/1", "gi1/0/2"):
            api._record_alert("snmp_if_down",
                              {"device_id": "sw1", "name": "core", "iface": iface})
        self.assertEqual(len(self._open()), 2)

    def test_one_coming_up_clears_only_its_own(self):
        for iface in ("gi1/0/1", "gi1/0/2"):
            api._record_alert("snmp_if_down",
                              {"device_id": "sw1", "name": "core", "iface": iface})
        api._auto_resolve_alerts("snmp_if_up",
                                 {"device_id": "sw1", "iface": "gi1/0/1"})
        left = self._open()
        self.assertEqual(len(left), 1)
        self.assertEqual(left[0]["payload"]["iface"], "gi1/0/2")

    def test_the_same_holds_for_saturation(self):
        for iface in ("gi1/0/1", "gi1/0/2"):
            api._record_alert("snmp_if_saturated",
                              {"device_id": "sw1", "name": "core", "iface": iface,
                               "util": 96})
        api._auto_resolve_alerts("snmp_if_relieved",
                                 {"device_id": "sw1", "iface": "gi1/0/1"})
        self.assertEqual([a["payload"]["iface"] for a in self._open()],
                         ["gi1/0/2"])

    def test_a_recovery_on_another_switch_touches_nothing(self):
        api._record_alert("snmp_if_down",
                          {"device_id": "sw1", "name": "a", "iface": "gi1/0/1"})
        api._auto_resolve_alerts("snmp_if_up",
                                 {"device_id": "sw2", "iface": "gi1/0/1"})
        self.assertEqual(len(self._open()), 1)

    def test_iface_is_stored_on_the_alert(self):
        """The identity field has to be on the ROW, or the sub_match has
        nothing to match against — the third leg of the documented trio."""
        api._record_alert("snmp_if_down",
                          {"device_id": "sw1", "name": "core", "iface": "gi1/0/9"})
        self.assertEqual(self._open()[0]["payload"].get("iface"), "gi1/0/9")
