"""v6.4.2 — the control plane tells on itself.

Of 183 registered events only `server_disk_low`/`_ok` concerned the control
plane. All the self-health data existed and was rendered on Server status —
per-sweep `last_ok`/`err` in self_observability.json, the scheduler heartbeat,
`systemctl is-active` rows for the three sidecars — and NONE of it was wired to
an event. Three concrete gaps:

  1. `_external_scheduler_active()` decided whether the request path runs the
     cadence purely from a config/env FLAG, never from the scheduler's liveness.
     On the single-node default the scheduler owns all ~33 sweeps, so when it
     OOMs at 02:00 offline detection, monitors, integrations, ticket SLA, the
     daily backup and every alerting sweep stop — and because the flag was still
     set the request path REFUSED to pick them up. The dashboard kept showing
     the last-known-good state and the fleet looked perfectly healthy.

  2. A sweep that FAILS while the scheduler still lives had no event.
     `_self_obs_mark` wrote SELF_OBS_FILE and its only consumers were the
     Server-status handler and the RAG corpus.

  3. No sidecar-down event. docs/self-monitoring.md said the sidecar rows are
     "deliberately never a health input" — and when the KMIP key server dies,
     every appliance storing its volume keys there silently fails to unlock on
     its next reboot.

Gap 1's fix lives in test_v600_scheduler (it replaced a test pinning the old
premise). This file covers 2 and 3.

Deliberately NOT added: an internal `scheduler_stalled` event. An event cannot
fire when the process that fires events is dead — the product already ships the
architecturally correct answer, `ping_healthchecks_if_due`, an outbound
dead-man's-switch that goes silent exactly when the scheduler does.
"""

import importlib.util
import os
import shutil as _real_shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-cphealth642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestSweepFailureAlerts(unittest.TestCase):
    def setUp(self):
        self._fire = api.fire_webhook
        self._name = api.get_server_name
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api.get_server_name = lambda: "rp"
        api.save(api.SELF_OBS_FILE, {"sweeps": {}, "errors": []})
        api._LOAD_CACHE.clear()
        # _self_obs_load memoises into a MODULE-level `_SELF_OBS`, so saving the
        # file is not enough — the previous test's err_count and _alerted flag
        # survive into this one and the streak logic reads them.
        api._SELF_OBS = None

    def tearDown(self):
        api.fire_webhook = self._fire
        api.get_server_name = self._name
        api._SELF_OBS = None

    def mark(self, ok, label="run_monitors_if_due"):
        self.fired.clear()
        api._self_obs_mark(label, ok, None if ok else RuntimeError("boom"))
        return [e for e, _p in self.fired]

    def test_one_transient_failure_is_silent(self):
        """A DNS blip in the integrations sweep is exactly the noise that gets
        an event muted, and a muted event catches nothing."""
        self.assertEqual(self.mark(False), [])

    def test_it_fires_at_the_streak_threshold(self):
        for _ in range(api._SWEEP_FAIL_STREAK - 1):
            self.mark(False)
        self.assertEqual(self.mark(False), ["sweep_failing"])

    def test_it_is_edge_triggered(self):
        for _ in range(api._SWEEP_FAIL_STREAK):
            self.mark(False)
        self.assertEqual(self.mark(False), [],
                         "re-fires every cadence — muted within the hour")

    def test_it_recovers(self):
        for _ in range(api._SWEEP_FAIL_STREAK):
            self.mark(False)
        self.assertEqual(self.mark(True), ["sweep_recovered"])

    def test_it_can_fire_again_after_a_recovery(self):
        for _ in range(api._SWEEP_FAIL_STREAK):
            self.mark(False)
        self.mark(True)
        for _ in range(api._SWEEP_FAIL_STREAK - 1):
            self.mark(False)
        self.assertEqual(self.mark(False), ["sweep_failing"],
                         "a second outage of the same sweep stays silent")

    def test_the_notify_sweeps_never_alert(self):
        """An event about the thing that DELIVERS events is a loop. Their
        failure is what the outbound dead-man's-switch is for."""
        for label in api._SELF_OBS_NO_ALERT:
            with self.subTest(sweep=label):
                api.save(api.SELF_OBS_FILE, {"sweeps": {}, "errors": []})
                api._LOAD_CACHE.clear()
                api._SELF_OBS = None
                got = []
                for _ in range(api._SWEEP_FAIL_STREAK + 2):
                    got += self.mark(False, label)
                self.assertEqual(got, [])

    def test_the_payload_names_the_sweep(self):
        for _ in range(api._SWEEP_FAIL_STREAK - 1):
            self.mark(False)
        self.mark(False)          # `mark` clears self.fired, so assert on the
        self.assertTrue(self.fired)   # call that actually fires
        self.assertEqual(self.fired[0][1]["sweep"], "run_monitors_if_due")
        self.assertIn("boom", self.fired[0][1]["detail"])

    def test_a_firing_failure_does_not_lose_the_observability_record(self):
        """fire_webhook is self-locking and runs AFTER the state write — a
        failure there must not swallow the record that is the whole point."""
        api.fire_webhook = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
        for _ in range(api._SWEEP_FAIL_STREAK):
            api._self_obs_mark("run_monitors_if_due", False, RuntimeError("boom"))
        st = api.load(api.SELF_OBS_FILE) or {}
        self.assertGreaterEqual(
            st["sweeps"]["run_monitors_if_due"]["err_count"],
            api._SWEEP_FAIL_STREAK)


class _ShutilProxy:
    """Only `which` is stubbed. api.shutil is also used for copy2 in the save
    path, and a blanket stub breaks a real code path — the kind of over-broad
    test double that produces a failure with nothing to do with the test."""
    def __init__(self, which_result):
        self._w = which_result

    def __getattr__(self, n):
        return getattr(_real_shutil, n)

    def which(self, x):
        return self._w


class TestSidecarWatch(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(api, k) for k in
                       ("fire_webhook", "get_server_name", "shutil", "subprocess")}
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api.get_server_name = lambda: "rp"
        api.shutil = _ShutilProxy("/usr/bin/systemctl")
        self.status = {}

        class _R:
            def __init__(s, o): s.stdout = o

        api.subprocess = type("P", (), {"run": staticmethod(
            lambda cmd, **k: _R(self.status.get(cmd[-1], "inactive")))})()
        api.save(api.KMIP_FILE, {})
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": []})
        api.save(api.SIDECAR_STATE_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def sweep(self):
        self.fired.clear()
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["last_sidecar_watch"] = 0
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.run_sidecar_watch_if_due()
        return [(e, p.get("unit")) for e, p in self.fired]

    def test_nothing_enabled_is_silent(self):
        self.assertEqual(self.sweep(), [])

    def test_an_enabled_and_running_sidecar_is_silent(self):
        api.save(api.KMIP_FILE, {"enabled": True})
        self.status["remotepower-kmipd"] = "active"
        self.assertEqual(self.sweep(), [])

    def test_a_stopped_kmipd_fires(self):
        """The case that makes this worth an event at all: when the key server
        dies, every appliance storing its volume keys there fails to unlock on
        its next reboot, and an informational row on a page nobody has open
        during an outage is not a control."""
        api.save(api.KMIP_FILE, {"enabled": True})
        self.status["remotepower-kmipd"] = "failed"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-kmipd")])

    def test_it_is_edge_triggered(self):
        api.save(api.KMIP_FILE, {"enabled": True})
        self.status["remotepower-kmipd"] = "failed"
        self.sweep()
        self.assertEqual(self.sweep(), [])

    def test_it_recovers(self):
        api.save(api.KMIP_FILE, {"enabled": True})
        self.status["remotepower-kmipd"] = "failed"
        self.sweep()
        self.status["remotepower-kmipd"] = "active"
        self.assertEqual(self.sweep(),
                         [("sidecar_recovered", "remotepower-kmipd")])

    def test_a_transitional_state_is_not_a_failure(self):
        """`activating` / `deactivating` / `unknown` all mean "cannot tell right
        now", and a restart must not page."""
        api.save(api.KMIP_FILE, {"enabled": True})
        for st in ("activating", "deactivating", "unknown", ""):
            with self.subTest(status=st):
                api.save(api.SIDECAR_STATE_FILE, {})
                api._LOAD_CACHE.clear()
                self.status["remotepower-kmipd"] = st
                self.assertEqual(self.sweep(), [])

    def test_a_disabled_sidecar_is_never_watched(self):
        """A sidecar may legitimately run on a DIFFERENT host and POST over the
        network, so "no local unit" is not a fault — the enablement check is the
        gate, which is what preserves the original informational contract."""
        self.status["remotepower-flowd"] = "inactive"
        self.assertEqual(self.sweep(), [])

    def test_no_systemd_means_no_opinion(self):
        api.save(api.KMIP_FILE, {"enabled": True})
        api.shutil = _ShutilProxy(None)
        self.status["remotepower-kmipd"] = "failed"
        self.assertEqual(self.sweep(), [])

    def test_syslog_and_flow_are_watched_when_enrolled(self):
        api.save(api.INBOUND_WEBHOOKS_FILE,
                 {"tokens": [{"kind": "syslog"}, {"kind": "flow"}]})
        api._LOAD_CACHE.clear()
        self.status["remotepower-syslogd"] = "failed"
        self.status["remotepower-flowd"] = "active"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-syslogd")])

    def test_it_is_in_both_cadence_registries(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_safe(run_sidecar_watch_if_due", src)
        self.assertIn("run_sidecar_watch_if_due",
                      (_CGI / "scheduler.py").read_text())


class TestRegistryWiring(unittest.TestCase):
    def test_all_four_events_are_registered(self):
        for ev in ("sweep_failing", "sweep_recovered", "sidecar_down",
                   "sidecar_recovered"):
            with self.subTest(ev=ev):
                self.assertIn(ev, api.EVENT_REGISTRY)
                self.assertEqual(api.EVENT_KIND_MAP.get(ev), "health")

    def test_the_recovers_resolve(self):
        self.assertEqual(api._ALERT_RECOVER.get("sweep_recovered"),
                         "sweep_failing")
        self.assertEqual(api._ALERT_RECOVER.get("sidecar_recovered"),
                         "sidecar_down")

    def test_the_message_builder_has_a_branch(self):
        import notify
        for ev in ("sweep_failing", "sidecar_down"):
            with self.subTest(ev=ev):
                msg = notify._webhook_message(ev, {"name": "rp",
                                                   "detail": "the reason"})
                self.assertEqual(msg, "the reason")

    def test_the_frontend_registries_have_them(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        for ev in ("sweep_failing", "sweep_recovered", "sidecar_down",
                   "sidecar_recovered"):
            with self.subTest(ev=ev):
                self.assertIn(f"'{ev}'", js)
                self.assertIn(f"case '{ev}':", js)


if __name__ == "__main__":
    unittest.main()


class TestConfiguredIsNotTheSameAsActive(unittest.TestCase):
    """The Server-status panel derived BOTH `scheduler_configured` and
    `cadence_in_request` from one call. Once that call became liveness-aware, a
    dead scheduler would have made the panel say "not configured" — hiding the
    exact state it exists to show. They are two different facts: "you told me a
    scheduler owns this" and "one actually does"."""

    def setUp(self):
        self._env = os.environ.get("RP_EXTERNAL_SCHEDULER")
        os.environ["RP_EXTERNAL_SCHEDULER"] = "1"

    def tearDown(self):
        if self._env is None:
            os.environ.pop("RP_EXTERNAL_SCHEDULER", None)
        else:
            os.environ["RP_EXTERNAL_SCHEDULER"] = self._env

    def _beat(self, age_s):
        import time as _t
        api.save(api.SCHEDULER_STATE_FILE,
                 {"ts": int(_t.time()) - age_s, "interval": 60})
        api._invalidate_load_cache(api.SCHEDULER_STATE_FILE)

    def test_a_dead_scheduler_still_reads_as_configured(self):
        self._beat(9999)
        info = api._runtime_serving_info()
        self.assertTrue(info["scheduler_configured"],
                        "the panel would say 'not configured' about a "
                        "scheduler the operator definitely configured")
        self.assertFalse(info["scheduler_running"])

    def test_a_dead_scheduler_hands_the_cadence_to_the_request_path(self):
        self._beat(9999)
        self.assertTrue(api._runtime_serving_info()["cadence_in_request"],
                        "nothing is running the ~33 maintenance sweeps")

    def test_a_live_scheduler_keeps_the_cadence(self):
        self._beat(10)
        info = api._runtime_serving_info()
        self.assertTrue(info["scheduler_configured"])
        self.assertTrue(info["scheduler_running"])
        self.assertFalse(info["cadence_in_request"],
                         "both would be running the sweeps")
