"""v6.3.1 — flow-verified service-dependency links.

The discovery half (suggest depends_on from observed traffic) already existed;
this covers the VERIFICATION half: a declared depends_on edge that was carrying
observed traffic (agent peer-conns OR the NetFlow/IPFIX receiver) and then went
silent while both endpoints stayed online fires dependency_missing, and recovers
via dependency_restored. Opt-in; edge-triggered; both-online guarded.
"""
import importlib.util
import os
import tempfile
import time
import unittest

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-flowdeps-"))

_SPEC = importlib.util.spec_from_file_location(
    "api", os.path.join(os.path.dirname(__file__), "..", "server", "cgi-bin", "api.py"))
api = importlib.util.module_from_spec(_SPEC)
import sys
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


def _alerts():
    a = api.load(api.ALERTS_FILE) or {}
    return list(a.get("alerts", [])) if isinstance(a, dict) else list(a)


class TestRegistryWiring(unittest.TestCase):
    def test_events_registered(self):
        self.assertIn("dependency_missing", api.EVENT_REGISTRY)
        self.assertIn("dependency_restored", api.EVENT_REGISTRY)
        self.assertEqual(api.EVENT_REGISTRY["dependency_missing"]["kind"], "dependency")
        # restored resolves the missing event
        self.assertIn("dependency_missing",
                      api.EVENT_REGISTRY["dependency_restored"]["resolves"])
        # missing lands in the inbox (has a severity)
        self.assertEqual(api.EVENT_REGISTRY["dependency_missing"]["severity"], "high")

    def test_dependency_kind_defined(self):
        kinds = {k for (k, _l, _g) in api.CHANNEL_KIND_DEFS}
        self.assertIn("dependency", kinds)

    def test_match_key_whitelisted_and_recover_wired(self):
        # dep_edge must be in _record_alert's payload whitelist (else the open
        # alert never carries it and dependency_restored can't find it).
        src = api._record_alert.__doc__ or ""
        # inspect the source directly for the whitelisted key
        import inspect
        body = inspect.getsource(api._record_alert)
        self.assertIn("dep_edge", body)
        resolve = inspect.getsource(api._auto_resolve_alerts)
        self.assertIn("dependency_restored", resolve)
        self.assertIn("dep_edge", resolve)

    def test_cadence_registered_both_registries(self):
        # main() _safe block
        main_src = __import__("inspect").getsource(api.main)
        self.assertIn("run_flow_dep_check_if_due", main_src)
        # scheduler CADENCE
        sched = importlib.util.spec_from_file_location(
            "scheduler", os.path.join(os.path.dirname(__file__), "..",
                                      "server", "cgi-bin", "scheduler.py"))
        mod = importlib.util.module_from_spec(sched)
        sched.loader.exec_module(mod)
        self.assertIn("run_flow_dep_check_if_due", mod.CADENCE)


class TestDependencyHealth(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "app": {"name": "app-01", "ip": "10.0.0.1", "last_seen": self.now,
                    "depends_on": ["db"]},
            "db":  {"name": "db-03", "ip": "10.0.0.2", "last_seen": self.now},
        })
        api.save(api.FLOW_DEPS_FILE, {})
        api.save(api.FLOW_FILE, {})
        api.save(api.PEER_CONNS_FILE, {})
        api.save(api.ALERTS_FILE, {})       # isolate alert accounting per test
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["dependency_link_alerts"] = True
        cfg["dependency_silence_min"] = 1
        api.save(api.CONFIG_FILE, cfg)

    def _flow(self, ts, convs):
        api.save(api.FLOW_FILE, {"rtr": {"latest": {"ts": ts, "conversations": convs}}})

    def _conv(self):
        return [{"src": "10.0.0.1", "dst": "10.0.0.2", "dport": 5432, "proto": 6, "bytes": 9}]

    def test_unverifiable_when_never_observed(self):
        rows = api._dependency_health()
        self.assertEqual(rows[0]["status"], "unverifiable")

    def test_ok_when_flow_shows_traffic(self):
        self._flow(self.now, self._conv())
        rows = api._dependency_health()
        self.assertEqual(rows[0]["status"], "ok")

    def test_peer_conns_are_also_evidence(self):
        # no flow; agent on app reports outbound peer to db's ip
        api.save(api.PEER_CONNS_FILE,
                 {"app": {"ts": self.now, "peers": [{"ip": "10.0.0.2", "port": 5432}]}})
        rows = api._dependency_health()
        self.assertEqual(rows[0]["status"], "ok")

    def test_missing_fires_after_silence_both_online(self):
        # observe, then go silent past the threshold with both hosts online
        self._flow(self.now, self._conv())
        api.run_flow_dep_check_if_due()
        st = api.load(api.FLOW_DEPS_FILE)
        st["edges"]["app:db"]["last_observed"] = self.now - 3600
        st["last_run"] = self.now - 3600
        api.save(api.FLOW_DEPS_FILE, st)
        self._flow(self.now - 3600, [])          # stale flow = no current evidence
        api.run_flow_dep_check_if_due()
        events = [a.get("event") for a in _alerts()]
        self.assertIn("dependency_missing", events)
        self.assertTrue(api.load(api.FLOW_DEPS_FILE)["edges"]["app:db"].get("alerted"))

    def test_restore_auto_resolves(self):
        self._flow(self.now, self._conv())
        api.run_flow_dep_check_if_due()
        st = api.load(api.FLOW_DEPS_FILE)
        st["edges"]["app:db"]["last_observed"] = self.now - 3600
        st["last_run"] = self.now - 3600
        api.save(api.FLOW_DEPS_FILE, st)
        self._flow(self.now - 3600, [])
        api.run_flow_dep_check_if_due()          # fire
        # traffic returns
        self._flow(int(time.time()), self._conv())
        st = api.load(api.FLOW_DEPS_FILE)
        st["last_run"] = int(time.time()) - 3600
        api.save(api.FLOW_DEPS_FILE, st)
        api.run_flow_dep_check_if_due()          # restore
        openm = [a for a in _alerts()
                 if a.get("event") == "dependency_missing" and not a.get("resolved_at")]
        self.assertEqual(openm, [])
        self.assertFalse(api.load(api.FLOW_DEPS_FILE)["edges"]["app:db"].get("alerted"))

    def test_no_fire_when_upstream_offline(self):
        # Fresh device ids (save() has a per-device last_seen-REGRESSION guard, so
        # lowering an already-online device's last_seen is reverted — use ids with
        # no prior on-disk record). Upstream offline, edge already seen-then-silent
        # -> collateral of device_offline, must NOT fire dependency_missing.
        api.save(api.DEVICES_FILE, {
            "ap2": {"name": "app-2", "ip": "10.5.0.1", "last_seen": self.now,
                    "depends_on": ["db2"]},
            "db2": {"name": "db-2", "ip": "10.5.0.2", "last_seen": self.now - 999999},
        })
        api.save(api.FLOW_DEPS_FILE, {
            "edges": {"ap2:db2": {"last_observed": self.now - 3600,
                                  "ever_observed": True, "alerted": False}},
            "last_run": self.now - 3600})
        self._flow(self.now - 3600, [])          # no current evidence
        api.run_flow_dep_check_if_due()
        events = [a.get("event") for a in _alerts()]
        self.assertNotIn("dependency_missing", events)
        rows = api._dependency_health()
        self.assertEqual(rows[0]["status"], "silent")

    def test_opt_in_gate_off_never_fires(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["dependency_link_alerts"] = False
        api.save(api.CONFIG_FILE, cfg)
        self._flow(self.now, self._conv())
        api.run_flow_dep_check_if_due()
        st = api.load(api.FLOW_DEPS_FILE)
        st["edges"]["app:db"]["last_observed"] = self.now - 3600
        st["last_run"] = self.now - 3600
        api.save(api.FLOW_DEPS_FILE, st)
        self._flow(self.now - 3600, [])
        api.run_flow_dep_check_if_due()
        self.assertEqual([a for a in _alerts()
                          if a.get("event") == "dependency_missing"], [])
        # but the observed-state timestamp is still maintained for the view
        self.assertTrue(api.load(api.FLOW_DEPS_FILE)["edges"]["app:db"].get("ever_observed"))

    def test_state_dropped_when_edge_undeclared(self):
        self._flow(self.now, self._conv())
        api.run_flow_dep_check_if_due()
        self.assertIn("app:db", api.load(api.FLOW_DEPS_FILE)["edges"])
        devs = api.load(api.DEVICES_FILE)
        devs["app"]["depends_on"] = []           # dependency removed
        api.save(api.DEVICES_FILE, devs)
        st = api.load(api.FLOW_DEPS_FILE)
        st["last_run"] = self.now - 3600
        api.save(api.FLOW_DEPS_FILE, st)
        api.run_flow_dep_check_if_due()
        self.assertNotIn("app:db", api.load(api.FLOW_DEPS_FILE)["edges"])


def _import_request_models():
    import importlib.util as ilu
    spec = ilu.spec_from_file_location(
        "request_models", os.path.join(os.path.dirname(__file__), "..",
                                       "server", "cgi-bin", "request_models.py"))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestConfigWiring(unittest.TestCase):
    def test_keys_in_request_model(self):
        # both keys must be declared on ConfigSaveRequest or extra='ignore'
        # silently drops them before handle_config_save reads them.
        rm = _import_request_models()
        fields = getattr(rm.ConfigSaveRequest, "model_fields", {}) or {}
        if not fields:
            self.skipTest("pydantic absent — model_fields unavailable")
        self.assertIn("dependency_link_alerts", fields)
        self.assertIn("dependency_silence_min", fields)

    def test_save_and_get_wired_in_source(self):
        # handle_config_save writes them; handle_config_get setdefaults them.
        import inspect
        save_src = inspect.getsource(api.handle_config_save)
        get_src = inspect.getsource(api.handle_config_get)
        self.assertIn("dependency_link_alerts", save_src)
        self.assertIn("dependency_silence_min", save_src)
        self.assertIn("dependency_link_alerts", get_src)


if __name__ == "__main__":
    unittest.main()
