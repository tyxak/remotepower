"""v6.1.2 "AfterglowMatters" — regression tests for the three live bugs fixed
this release. Each test drives the REAL code path (not a hand-built fixture), so
a regression re-breaks the test rather than silently passing.

1. Alert mutes never lifted fleet health. A mute is documented as silencing the
   inbox AND needs-attention, but only the alert-FIRING path consulted
   _alert_muted(); _compute_attention() didn't. Fleet health is derived purely
   from NA items, so muting an alert left the host's score depressed forever.

2. The container-image CVE scan (trivy) could never be triggered. The agent has
   always honoured a `force_image_scan` flag in the heartbeat response, but the
   server never set one — so the ONLY path to a scan was the agent's
   `poll_count % 1440 == 0` cadence, which resets on every agent restart.

3. POST /api/cve/scan 500'd on Postgres. Its status write is non_blocking, and
   Postgres was the only backend whose non-blocking acquire had NO retry budget
   (JSON retries 20x5ms, SQLite sets busy_timeout=100) — so a write the other
   backends completed raised LockBusy here, which propagated uncaught.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-bugs-"))
_spec = importlib.util.spec_from_file_location("api_v612_bugs", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestMutedAlertsLiftHealth(unittest.TestCase):
    """Bug 1: a muted (host, event) must drop out of Needs-Attention, and so
    must stop dragging the device's — and the fleet's — health score down."""

    def setUp(self):
        import time

        api.save(api.ALERT_MUTES_FILE, {"mutes": []})
        api.save(
            api.DEVICES_FILE,
            {
                "d1": {
                    "name": "muted-host",
                    # Heartbeated once, long ago -> a critical `offline` NA item.
                    # (last_seen=0 means "never enrolled" and is skipped by design.)
                    "last_seen": int(time.time()) - 86400,
                    "monitored": True,
                },
            },
        )
        # Drop the NA cache so each case recomputes.
        try:
            api.save(api._attention_cache_file(), {})
        except Exception:
            pass

    def _health(self):
        return api._fleet_health(use_cache=False)

    def test_offline_item_present_and_scores_low_when_not_muted(self):
        items = api._compute_attention()
        kinds = {(i["kind"], i.get("device_id")) for i in items}
        self.assertIn(("offline", "d1"), kinds)
        h = self._health()
        self.assertLess(h["score"], 100, "an offline host must cost health")

    def test_muting_the_event_removes_the_na_item_and_restores_health(self):
        api.save(
            api.ALERT_MUTES_FILE,
            {"mutes": [{"id": "m1", "device_id": "d1", "event": "device_offline"}]},
        )
        items = api._compute_attention()
        kinds = {(i["kind"], i.get("device_id")) for i in items}
        self.assertNotIn(
            ("offline", "d1"),
            kinds,
            "a muted (host, event) must not appear in Needs Attention",
        )
        h = self._health()
        self.assertEqual(
            h["score"], 100, "muting the only signal must restore the health score"
        )

    def test_mute_is_severity_scoped_not_kind_scoped(self):
        # Muting av_warning must NOT also silence a critical av_infected item:
        # the mute set is keyed by EVENT, and the two map from different
        # severities of the same NA kind.
        self.assertEqual(api._NA_MUTE_EVENTS[("av_posture", "warning")], ("av_warning",))
        self.assertEqual(api._NA_MUTE_EVENTS[("av_posture", "critical")], ("av_infected",))
        muted_warn = api._na_item_muted  # bound for readability
        api.save(
            api.ALERT_MUTES_FILE,
            {"mutes": [{"id": "m2", "device_id": "d1", "event": "av_warning"}]},
        )
        warn_item = {"kind": "av_posture", "severity": "warning", "device_id": "d1"}
        crit_item = {"kind": "av_posture", "severity": "critical", "device_id": "d1"}
        self.assertTrue(muted_warn(warn_item))
        self.assertFalse(
            muted_warn(crit_item), "muting the warning must not hide the critical"
        )

    def test_mute_does_not_leak_across_devices(self):
        api.save(
            api.ALERT_MUTES_FILE,
            {"mutes": [{"id": "m3", "device_id": "other", "event": "device_offline"}]},
        )
        item = {"kind": "offline", "severity": "critical", "device_id": "d1"}
        self.assertFalse(api._na_item_muted(item))

    def test_fleet_level_item_without_device_is_never_muted(self):
        self.assertFalse(
            api._na_item_muted({"kind": "offline", "severity": "critical"})
        )

    def test_attention_cache_busts_immediately_when_a_mute_changes(self):
        # The 10s NA cache must not keep serving a pre-mute payload. Behavioural:
        # warm the cache, add a mute, and the very next cached call must reflect
        # it (the cache fingerprint covers ALERT_MUTES_FILE).
        warm = api._attention_payload(use_cache=True)
        self.assertTrue(
            any(i["kind"] == "offline" for i in warm["items"]), "expected a warm item"
        )
        api.save(
            api.ALERT_MUTES_FILE,
            {"mutes": [{"id": "m9", "device_id": "d1", "event": "device_offline"}]},
        )
        after = api._attention_payload(use_cache=True)   # cache ON, must still bust
        self.assertFalse(
            any(i["kind"] == "offline" for i in after["items"]),
            "muting must take effect immediately, not after the cache TTL",
        )

    def test_attention_cache_survives_device_telemetry_churn(self):
        # PERF: the cache used to bust on ANY devices.json write, so on a fleet
        # whose hosts heartbeat faster than the TTL it never hit at all. A
        # heartbeat-shaped write must NOT invalidate it.
        import time as _t

        first = api._attention_payload(use_cache=True)
        devs = api.load(api.DEVICES_FILE)
        devs["d1"]["last_seen"] = int(_t.time()) - 86400   # a heartbeat-ish write
        api.save(api.DEVICES_FILE, devs)
        second = api._attention_payload(use_cache=True)
        self.assertEqual(
            first.get("ts"),
            second.get("ts"),
            "device telemetry churn must not bust the NA cache within its TTL",
        )


class TestImageCveScanIsTriggerable(unittest.TestCase):
    """Bug 2: the trivy image scan had no reachable trigger."""

    def test_server_delivers_force_image_scan_to_the_agent(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("common_resp['force_image_scan'] = True", src)
        self.assertIn("saved_dev['force_image_scan'] = True", src)

    def test_scan_endpoint_is_routed(self):
        routes = api._build_exact_routes()
        self.assertIn(("POST", "/api/image-cves/scan"), routes)

    def test_agent_cadence_is_time_based_not_poll_count(self):
        # The poll-count modulo reset on every agent restart, so a host that
        # restarted its agent more often than 24h never scanned at all.
        agent = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn("IMAGE_SCAN_INTERVAL_S", agent)
        self.assertIn("last_image_scan_ts", agent)
        self.assertNotIn(
            "poll_count % IMAGE_SCAN_EVERY == 0",
            agent,
            "the restart-fragile poll-count gate must be gone",
        )

    def test_agent_persists_the_scan_timestamp_across_restarts(self):
        agent = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn("def _load_image_scan_ts", agent)
        self.assertIn("def _save_image_scan_ts", agent)
        # It must be READ at startup, not just written.
        self.assertIn("last_image_scan_ts = _load_image_scan_ts()", agent)

    def test_scan_endpoint_refuses_when_the_feature_is_off(self):
        api.save(api.CONFIG_FILE, {"image_scan_enabled": False})
        api.require_write_role = lambda *a, **k: "admin"
        api.get_json_obj = lambda: {}
        with self.assertRaises(api.HTTPError) as ctx:
            api.handle_image_cve_scan()
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("Settings", str(ctx.exception.body))


class TestNonBlockingLockParityAcrossBackends(unittest.TestCase):
    """Bug 3: Postgres was the only backend that gave a contended non_blocking
    write zero grace, turning a survivable collision into a 500."""

    def test_postgres_retries_a_contended_nonblocking_lock(self):
        pg = (_CGI / "storage_pg.py").read_text()
        self.assertIn("def _try_lock", pg)
        self.assertIn("_NB_RETRIES", pg)
        # The budget must match the other two backends (~100 ms).
        self.assertIn("_NB_RETRIES = 20", pg)
        self.assertIn("_NB_SLEEP_S = 0.005", pg)

    def test_json_backend_budget_is_the_reference(self):
        self.assertEqual(api.LOCK_NB_RETRIES * api.LOCK_NB_SLEEP_S, 0.1)

    def test_lockbusy_renders_503_not_500(self):
        wsgi_src = (_CGI / "wsgi.py").read_text()
        self.assertIn("except api.LockBusy", wsgi_src)
        self.assertIn("503", wsgi_src)
        # And it must be caught BEFORE the generic 500 arm, or it never fires.
        self.assertLess(
            wsgi_src.index("except api.LockBusy"),
            wsgi_src.index("'error': 'Internal server error'"),
        )

    def test_cve_scan_handler_handles_lock_contention_itself(self):
        src = (_CGI / "api.py").read_text()
        scan = src[src.index("def handle_cve_scan("):]
        scan = scan[: scan.index("\ndef ")]
        self.assertIn("except LockBusy", scan)
        self.assertIn("409", scan)


if __name__ == "__main__":
    unittest.main()
