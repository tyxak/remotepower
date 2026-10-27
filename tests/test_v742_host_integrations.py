#!/usr/bin/env python3
"""v7.4.2, issue #44: show the integrations bound to a host on that host's card.

"Some hosts can't run an agent or answer SNMP (a Hubitat hub, for example), so their real health
data comes from integrations: I have nine custom HTTP probes bound to my Hubitat host. Binding
routes their alerts through the host, but the values only appear on the Integrations page. Opening
the host's card shows nothing but reachability, so the host looks empty even though RemotePower
knows everything about it."

Three layers: what the poll keeps (the numbers, for an instance bound to a host), the answer
GET /api/devices/<id>/integrations gives (and what it must not give), and the route and scope
gate that put it behind the same rules as every other per-host read. The drawer section is drawn
by the real page in test_v742_host_integrations_e2e.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v742-hi-"))
_spec = importlib.util.spec_from_file_location("api_v742_hi", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

HUB = "hub1"
OTHER = "nas1"
URL = "http://hubitat.lan/apps/api/42?access_token=SUPERSECRETTOKEN"
SECRET = "bearer-secret-value"


def inst(i, label, device_id=HUB, **kw):
    d = {"id": f"i{i}", "type": "custom_probe", "label": label, "url": URL, "enabled": True,
         "verify_tls": True, "secret": SECRET, "username": "svc", "device_id": device_id,
         "probe_json_field": "freeMemory"}
    d.update(kw)
    return d


def result(i, label, status="ok", metrics=None, ts=None, detail=""):
    return {"id": f"i{i}", "label": label, "type": "custom_probe", "status": status,
            "detail": detail or f"HTTP 200, {label}", "metrics": metrics or {},
            "checked": ts or int(time.time())}


class _Base(unittest.TestCase):
    def setUp(self):
        for f, empty in ((api.CONFIG_FILE, {}), (api.INTEG_STATE_FILE, {}), (api.ALERTS_FILE, {"alerts": []})):
            api.save(f, empty)
        api.save(api.DEVICES_FILE, {
            HUB: {"id": HUB, "name": "hubitat", "ip": "10.0.0.9", "agentless": True,
                  "monitored": True, "last_seen": int(time.time())},
            OTHER: {"id": OTHER, "name": "nas", "ip": "10.0.0.10", "monitored": True,
                    "last_seen": int(time.time())}})
        api._LOAD_CACHE.clear()
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def configure(self, *insts, **extra):
        api.save(api.CONFIG_FILE, dict({"integrations": list(insts)}, **extra))
        api._LOAD_CACHE.clear()

    def poll(self, *results):
        api._persist_integration_results(list(results))
        api._LOAD_CACHE.clear()

    def state(self):
        api._LOAD_CACHE.clear()
        return api.load(api.INTEG_STATE_FILE) or {}


class _Call(unittest.TestCase):
    def run_handler(self, handler, *args, role="viewer", method="GET"):
        class Cap(SystemExit):
            pass
        out = {}

        def fake(status, data):
            out["status"], out["body"] = status, data
            raise Cap()
        saved = {n: getattr(api, n) for n in ("respond", "require_auth", "verify_token", "method")}
        api.respond = fake
        api.require_auth = lambda *a, **k: None
        api.verify_token = lambda t: ("someone", role)
        api.method = lambda: method
        os.environ.update({"REQUEST_METHOD": method, "QUERY_STRING": "", "CONTENT_LENGTH": "0"})
        api.sys.stdin = type("S", (), {"buffer": io.BytesIO(b"")})()
        try:
            handler(*args)
        except Cap:
            pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        return out["status"], out["body"]


class TestWhatThePollKeeps(_Base):

    def test_the_numbers_are_kept_for_an_instance_bound_to_a_host(self):
        self.configure(inst(1, "free memory"))
        self.poll(result(1, "free memory", metrics={"http_status": 200, "freeMemory": 412345, "zwave": "ok"}))
        entry = self.state()["history"]["i1"][-1]
        self.assertEqual(entry["m"], {"http_status": 200, "freeMemory": 412345},
                         "numbers only: a string is not a point on a trend")
        self.assertEqual(entry["status"], "ok")

    def test_an_instance_bound_to_nothing_keeps_the_history_it_always_kept(self):
        self.configure(inst(1, "free memory", device_id=""))
        self.poll(result(1, "free memory", metrics={"freeMemory": 412345}))
        entry = self.state()["history"]["i1"][-1]
        self.assertNotIn("m", entry, "nothing reads the numbers of an unbound instance")
        self.assertEqual(set(entry), {"ts", "status", "detail"})

    def test_a_site_binding_alone_is_not_a_host_binding(self):
        self.configure(inst(1, "free memory", device_id="", site="hq"))
        self.poll(result(1, "free memory", metrics={"freeMemory": 1}))
        self.assertNotIn("m", self.state()["history"]["i1"][-1])

    def test_booleans_and_non_finite_numbers_are_not_points(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"up": True, "bad": float("nan"), "inf": float("inf"), "n": 3, "f": 2.5}))
        self.assertEqual(self.state()["history"]["i1"][-1]["m"], {"n": 3, "f": 2.5})

    def test_the_numeric_filter_on_its_own(self):
        self.assertEqual(api._integ_numeric_metrics(
            {"a": 1, "b": 2.5, "c": True, "d": float("nan"), "e": float("-inf"), "f": "7", "g": None}),
            {"a": 1, "b": 2.5})
        self.assertEqual(api._integ_numeric_metrics(None), {})
        self.assertEqual(api._integ_numeric_metrics({"x" * 100: 1}), {"x" * 64: 1})

    def test_a_nan_from_a_remote_service_is_dropped_wherever_it_sits(self):
        """json.loads takes NaN and Infinity; the store refuses them. Found in a custom probe
        against a hub that prints NaN when a sensor read fails: save() raised and the whole
        batch was lost."""
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"top": float("nan"), "n": 4}) | {
            "top_blocked": [{"name": "a", "count": float("inf")}], "nested": {"deep": [float("nan")]}})
        latest = self.state()["latest"]["i1"]
        self.assertIsNone(latest["metrics"]["top"])
        self.assertEqual(latest["metrics"]["n"], 4)
        self.assertIsNone(latest["top_blocked"][0]["count"])
        self.assertEqual(latest["nested"], {"deep": [None]})

    def test_one_poisoned_instance_does_not_stop_the_others_being_saved(self):
        self.configure(inst(1, "bad probe"), inst(2, "good probe"))
        self.poll(result(1, "bad probe", metrics={"freeMemory": float("nan")}),
                  result(2, "good probe", metrics={"freeMemory": 900}))
        st = self.state()
        self.assertIn("i1", st["latest"])
        self.assertEqual(st["latest"]["i2"]["metrics"], {"freeMemory": 900})
        self.assertEqual(st["history"]["i2"][-1]["m"], {"freeMemory": 900})

    def test_a_poisoned_value_is_not_an_alert_either(self):
        """A 'not equal to' threshold reads NaN != 5 as true. Cleaned first, it is None and
        compares as nothing."""
        self.configure(inst(1, "x", metric_thresholds=[{"metric": "freeMemory", "op": "ne",
                                                         "value": 5, "severity": "high"}]))
        fired = []
        api.fire_webhook = lambda e, p: fired.append(e)
        self.poll(result(1, "x", metrics={"freeMemory": float("nan")}))
        self.assertNotIn("integration_metric_alert", fired)

    def test_at_most_twelve_numbers_a_poll(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={f"m{i:02d}": i for i in range(30)}))
        self.assertEqual(len(self.state()["history"]["i1"][-1]["m"]), 12)

    def test_an_instance_with_no_numbers_adds_no_empty_dict(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"zwave": "ok"}))
        self.assertNotIn("m", self.state()["history"]["i1"][-1])

    def test_the_history_is_still_capped_at_a_hundred_polls(self):
        self.configure(inst(1, "x"))
        for n in range(130):
            self.poll(result(1, "x", metrics={"n": n}, ts=1000 + n))
        h = self.state()["history"]["i1"]
        self.assertEqual(len(h), 100)
        self.assertEqual(h[-1]["m"], {"n": 129})


class TestTheAnswer(_Base, _Call):

    def get(self, dev_id=HUB, **kw):
        return self.run_handler(api.handle_device_integrations, dev_id, **kw)

    def test_it_lists_the_instances_bound_to_this_host_and_no_others(self):
        self.configure(inst(1, "free memory"), inst(2, "temperature"),
                       inst(3, "other host's probe", device_id=OTHER), inst(4, "unbound", device_id=""))
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["label"] for r in body["integrations"]), ["free memory", "temperature"])

    def test_each_row_carries_status_detail_type_and_the_latest_values(self):
        self.configure(inst(1, "free memory"))
        self.poll(result(1, "free memory", status="warning", detail="freeMemory=412345 fails (lt 500000)",
                         metrics={"http_status": 200, "freeMemory": 412345}, ts=1700000000))
        row = self.get()[1]["integrations"][0]
        self.assertEqual(row["status"], "warning")
        self.assertEqual(row["detail"], "freeMemory=412345 fails (lt 500000)")
        self.assertEqual(row["type"], "custom_probe")
        self.assertEqual(row["type_label"], "Custom HTTP probe")
        self.assertEqual(row["checked"], 1700000000)
        self.assertEqual(row["metrics"], {"http_status": 200, "freeMemory": 412345})
        self.assertTrue(row["enabled"])

    def test_the_numbers_come_back_as_a_series_per_metric(self):
        self.configure(inst(1, "free memory"))
        for n, mem in enumerate((500, 480, 455)):
            self.poll(result(1, "free memory", metrics={"freeMemory": mem}, ts=1000 + n))
        row = self.get()[1]["integrations"][0]
        self.assertEqual(row["series"]["freeMemory"],
                         [{"ts": 1000, "val": 500}, {"ts": 1001, "val": 480}, {"ts": 1002, "val": 455}])

    def test_the_status_history_comes_back_oldest_first_and_bounded(self):
        self.configure(inst(1, "x"))
        for n in range(80):
            self.poll(result(1, "x", status="critical" if n == 79 else "ok", ts=1000 + n))
        hist = self.get()[1]["integrations"][0]["history"]
        self.assertEqual(len(hist), 60)
        self.assertEqual(hist[-1], {"ts": 1079, "status": "critical"})
        self.assertLess(hist[0]["ts"], hist[-1]["ts"])

    def test_an_instance_never_polled_is_unknown(self):
        self.configure(inst(1, "new probe"))
        row = self.get()[1]["integrations"][0]
        self.assertEqual(row["status"], "unknown")
        self.assertIsNone(row["checked"])
        self.assertEqual(row["metrics"], {})
        self.assertEqual(row["series"], {})

    def test_a_disabled_instance_says_so_and_shows_no_stale_values(self):
        self.configure(inst(1, "paused", enabled=False))
        self.poll(result(1, "paused", metrics={"freeMemory": 1}))
        row = self.get()[1]["integrations"][0]
        self.assertFalse(row["enabled"])
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["detail"], "disabled")
        self.assertEqual((row["metrics"], row["series"], row["history"]), ({}, {}, []))

    def test_the_worst_comes_first(self):
        self.configure(inst(1, "a ok"), inst(2, "b crit"), inst(3, "c warn"))
        self.poll(result(1, "a ok", status="ok"), result(2, "b crit", status="critical"),
                  result(3, "c warn", status="warning"))
        self.assertEqual([r["label"] for r in self.get()[1]["integrations"]], ["b crit", "c warn", "a ok"])

    def test_a_host_marked_unmonitored_still_shows_its_integrations(self):
        """Telemetry views show unmonitored hosts; only alerting stays quiet."""
        self.configure(inst(1, "free memory"))
        devs = api.load(api.DEVICES_FILE)
        devs[HUB]["monitored"] = False
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self.get()[1]["integrations"]), 1)

    def test_a_host_with_nothing_bound_gets_an_empty_list_not_an_error(self):
        self.configure(inst(3, "other host's probe", device_id=OTHER))
        status, body = self.get()
        self.assertEqual((status, body["integrations"]), (200, []))

    def test_the_homelab_switch_hides_it(self):
        self.configure(inst(1, "x"), show_homelab=False)
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(body["integrations"], [])
        self.assertIs(body["show_homelab"], False)

    def test_an_unknown_host_is_a_404(self):
        self.configure(inst(1, "x"))
        self.assertEqual(self.get("nope")[0], 404)
        self.assertEqual(self.get("a/b")[0], 404)

    def test_only_get_is_allowed(self):
        self.assertEqual(self.get(method="POST")[0], 405)

    def test_a_caller_who_is_not_signed_in_is_refused_before_anything_else(self):
        """Auth comes first, so a wrong method is not a way to learn the route exists."""
        class Cap(SystemExit):
            pass
        seen = {}

        def refuse():
            seen["order"] = "auth"
            raise Cap()
        real = (api.require_auth, api.method)
        api.require_auth = refuse
        api.method = lambda: seen.setdefault("order", "method") and "POST"
        try:
            with self.assertRaises(Cap):
                api.handle_device_integrations(HUB)
        finally:
            api.require_auth, api.method = real
        self.assertEqual(seen["order"], "auth")

    def test_a_long_detail_is_cut_for_the_card(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", detail="z" * 5000))
        self.assertEqual(len(self.get()[1]["integrations"][0]["detail"]), 300)

    def test_the_answer_never_carries_the_address_or_a_credential(self):
        """The URL of a probe holds a token, and the secret is a bearer token. A viewer can open
        a host's card, and neither is theirs to read."""
        self.configure(inst(1, "free memory"))
        self.poll(result(1, "free memory", metrics={"freeMemory": 1}))
        for role in ("viewer", "admin"):
            text = json.dumps(self.get(role=role)[1])
            for leak in ("SUPERSECRETTOKEN", "hubitat.lan", SECRET, "svc", "access_token"):
                self.assertNotIn(leak, text, f"{role} was given {leak!r}")

    def test_a_value_a_probe_returns_cannot_break_the_answer(self):
        """A metric is whatever a remote service said. Nested data and long strings are cut
        down to scalars, so the card draws text and numbers only."""
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"nested": {"a": 1}, "long": "z" * 500, "list": [1, 2], "n": 5}))
        m = self.get()[1]["integrations"][0]["metrics"]
        self.assertNotIn("nested", m)
        self.assertNotIn("list", m)
        self.assertEqual(len(m["long"]), 64)
        self.assertEqual(m["n"], 5)


class TestRouteAndScope(_Base):

    def test_the_route_resolves_to_the_handler(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/devices/hub1/integrations")[0], "handle_device_integrations")

    def test_a_delete_on_that_path_is_not_a_host_delete(self):
        """The device DELETE catch-all names the suffixes that are NOT a host id; a new GET
        path has to be on that list or DELETE /api/devices/<id>/integrations is read as
        'delete the host called <id>/integrations'."""
        from routing_harness import resolve_route
        self.assertNotEqual(resolve_route("DELETE", "/api/devices/hub1/integrations")[0], "handle_device_delete")

    def test_the_function_copy_of_that_guard_agrees_with_the_table(self):
        self.assertFalse(api._route_code_5("/api/devices/hub1/integrations", "DELETE"))

    def test_the_two_copies_of_the_guard_list_the_same_suffixes(self):
        """The dispatch table keeps the condition as text, which only the OpenAPI generator
        reads; the function is what runs. Nothing else makes them agree, so a suffix added to
        one and not the other documents a guard that is not there (or the reverse)."""
        import inspect
        import re
        fn = set(re.findall(r"'(/[a-z_\-/]+)'", inspect.getsource(api._route_code_5)))
        row = next(r for r in api._PATTERN_ROUTE_DEFS if r[0] == "code" and r[4] == "_route_code_5")
        table = set(re.findall(r"'(/[a-z_\-/]+)'", row[5]))
        fn.discard("/api/devices/")
        table.discard("/api/devices/")
        self.assertGreater(len(fn), 20, "the guard list was not found")
        self.assertEqual(fn, table)

    def test_the_pre_dispatch_gate_covers_the_path(self):
        """A host another tenant owns is refused before the handler is reached, like every other
        /api/devices/<id>/... read."""
        self.configure(inst(1, "x"))
        real = (api.path_info, api._tenant_visible, api.respond)
        seen = {}

        def fake(status, data):
            seen["status"] = status
            raise SystemExit()
        api.path_info = lambda: f"/api/devices/{HUB}/integrations"
        api._tenant_visible = lambda dev: False
        api.respond = fake
        try:
            with self.assertRaises(SystemExit):
                api._enforce_device_scope()
        finally:
            api.path_info, api._tenant_visible, api.respond = real
        self.assertEqual(seen["status"], 403)


if __name__ == "__main__":
    unittest.main()
