#!/usr/bin/env python3
"""Unit tests for v1.11.10: API enrollment tokens + metric alerting.

Two feature areas, each with their own test class.

API enrollment (one-time pre-shared tokens):
  - Token creation, listing, revocation
  - Token consumed atomically by /api/enroll/register
  - Same token can't be used twice (one-time-use guarantee)
  - Expired tokens rejected
  - Default group/tags applied at enrollment
  - Token TTL clamping (60s min, 7 days max)

Metric thresholds (disk/memory/swap/cpu):
  - Default thresholds applied when no overrides
  - Per-device overrides via PATCH endpoint
  - Per-mount disk overrides
  - Hysteresis (recovery_buffer prevents oscillation spam)
  - State transitions (ok → warn → crit → ok)
  - Webhook fires on transitions, not on every heartbeat
  - Orphan mount cleanup when a mount disappears between reports
  - Validation: warn < crit, ranges enforced
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

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v11110", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _capture(t):
    def fake(status, data):
        raise _Captured(status, data)
    t.respond = fake


def _set_request(method, path, body=None, headers=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    for k in ("HTTP_X_TOKEN",):
        os.environ.pop(k, None)
    for k, v in (headers or {}).items():
        os.environ[k] = v


def _call(handler, *args, **kwargs):
    _capture(api)
    try:
        handler(*args, **kwargs)
    except _Captured as c:
        return c.status, c.body
    raise AssertionError(f"{handler.__name__} did not call respond()")


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "CMDB_FILE",
        "AUDIT_LOG_FILE", "CONFIG_FILE", "CMD_OUTPUT_FILE",
        "UPDATE_LOGS_FILE", "CMDS_FILE", "CONTAINERS_FILE",
        "WEBHOOK_LOG_FILE", "SERVICES_FILE", "PINS_FILE",
        "ENROLL_TOKENS_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


def _seed_admin():
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": user, "created": int(time.time()),
        "ttl": 3600, "admin": True, "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return user, token


# ─── API enrollment tokens ───────────────────────────────────────────────────


class TestEnrollmentTokenLifecycle(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        _, self.token = _seed_admin()

    def _auth(self):
        return {"HTTP_X_TOKEN": self.token}

    def test_create_returns_token(self):
        _set_request("POST", "/api/enrollment-tokens",
                     body={"label": "ansible-batch-1"},
                     headers=self._auth())
        status, body = _call(api.handle_enroll_token_create)
        self.assertEqual(status, 201)
        self.assertIn("token", body)
        # 32 url-safe bytes encodes to 43 chars
        self.assertGreaterEqual(len(body["token"]), 32)
        # Default expiry should be ~24h from now
        self.assertGreater(body["expires"], int(time.time()) + 23 * 3600)
        self.assertLess(body["expires"], int(time.time()) + 25 * 3600)
        self.assertEqual(body["label"], "ansible-batch-1")

    def test_create_with_custom_expiry(self):
        _set_request("POST", "/api/enrollment-tokens",
                     body={"expires_in": 3600, "default_group": "lab"},
                     headers=self._auth())
        status, body = _call(api.handle_enroll_token_create)
        self.assertEqual(status, 201)
        # ~1h from now
        delta = body["expires"] - int(time.time())
        self.assertGreater(delta, 3500)
        self.assertLess(delta, 3700)

    def test_create_rejects_too_long_ttl(self):
        # 8 days > 7-day cap
        _set_request("POST", "/api/enrollment-tokens",
                     body={"expires_in": 8 * 24 * 3600},
                     headers=self._auth())
        status, _ = _call(api.handle_enroll_token_create)
        self.assertEqual(status, 400)

    def test_create_rejects_too_short_ttl(self):
        _set_request("POST", "/api/enrollment-tokens",
                     body={"expires_in": 30},
                     headers=self._auth())
        status, _ = _call(api.handle_enroll_token_create)
        self.assertEqual(status, 400)

    def test_create_requires_admin(self):
        _set_request("POST", "/api/enrollment-tokens", body={})
        status, _ = _call(api.handle_enroll_token_create)
        self.assertIn(status, (401, 403))

    def test_list_does_not_leak_full_tokens(self):
        # Create a token, then list — list should only return the prefix
        _set_request("POST", "/api/enrollment-tokens",
                     body={"label": "test"}, headers=self._auth())
        _, body = _call(api.handle_enroll_token_create)
        full_token = body["token"]

        _set_request("GET", "/api/enrollment-tokens", headers=self._auth())
        status, listing = _call(api.handle_enroll_token_list)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing), 1)
        # The listing entry MUST NOT contain the full token anywhere
        self.assertNotIn(full_token, json.dumps(listing))
        # But it should contain a recognisable prefix
        self.assertTrue(listing[0]["prefix"].startswith(full_token[:8]))

    def test_list_skips_expired(self):
        # Plant an already-expired token directly into the file
        tokens = api.load(api.ENROLL_TOKENS_FILE)
        tokens["expired-token-xxxxxxxxxxxxxxxx"] = {
            "created": int(time.time()) - 10000,
            "expires": int(time.time()) - 100,
            "label":   "expired",
            "actor":   "admin",
            "default_group": "", "default_tags": [],
        }
        api.save(api.ENROLL_TOKENS_FILE, tokens)

        _set_request("GET", "/api/enrollment-tokens", headers=self._auth())
        status, listing = _call(api.handle_enroll_token_list)
        self.assertEqual(status, 200)
        # Expired token shouldn't appear in the listing
        self.assertEqual(listing, [])
        # And should have been purged from disk
        tokens = api.load(api.ENROLL_TOKENS_FILE)
        self.assertNotIn("expired-token-xxxxxxxxxxxxxxxx", tokens)

    def test_revoke_by_prefix(self):
        _set_request("POST", "/api/enrollment-tokens",
                     body={"label": "test"}, headers=self._auth())
        _, body = _call(api.handle_enroll_token_create)
        full_token = body["token"]
        prefix = full_token[:8]

        _set_request("DELETE", f"/api/enrollment-tokens/{prefix}",
                     headers=self._auth())
        status, _ = _call(api.handle_enroll_token_revoke, prefix)
        self.assertEqual(status, 200)

        # Token gone from store
        tokens = api.load(api.ENROLL_TOKENS_FILE)
        self.assertNotIn(full_token, tokens)

    def test_revoke_unknown_prefix_404(self):
        _set_request("DELETE", "/api/enrollment-tokens/notarealtoken",
                     headers=self._auth())
        status, _ = _call(api.handle_enroll_token_revoke, "notarealtoken")
        self.assertEqual(status, 404)

    def test_revoke_too_short_prefix_400(self):
        _set_request("DELETE", "/api/enrollment-tokens/abc",
                     headers=self._auth())
        status, _ = _call(api.handle_enroll_token_revoke, "abc")
        self.assertEqual(status, 400)


class TestEnrollmentTokenConsumption(unittest.TestCase):
    """Token must be consumed atomically — second use returns 403."""
    def setUp(self):
        _isolate(self)
        _, self.admin_token = _seed_admin()

    def _create_token(self, **kwargs):
        body = {"label": "test"}
        body.update(kwargs)
        _set_request("POST", "/api/enrollment-tokens", body=body,
                     headers={"HTTP_X_TOKEN": self.admin_token})
        _, resp = _call(api.handle_enroll_token_create)
        return resp["token"]

    def _enroll_with_token(self, token, hostname="test-host", **extra):
        body = {
            "enrollment_token": token,
            "hostname": hostname,
            "name": hostname,
            "os": "Linux",
            "ip": "10.0.0.1",
            "version": "1.11.10",
        }
        body.update(extra)
        _set_request("POST", "/api/enroll/register", body=body)
        return _call(api.handle_enroll_register)

    def test_token_enrolls_device(self):
        token = self._create_token(default_group="prod", default_tags=["linux"])
        status, body = self._enroll_with_token(token)
        self.assertEqual(status, 201)
        self.assertTrue(body.get("ok"))
        self.assertIn("device_id", body)
        self.assertIn("token", body)

        # Device should have group + tags from the enrollment token
        devices = api.load(api.DEVICES_FILE)
        dev = devices[body["device_id"]]
        self.assertEqual(dev["group"], "prod")
        self.assertEqual(dev["tags"], ["linux"])

    def test_token_consumed_atomically(self):
        # First use succeeds, second use returns 403
        token = self._create_token()
        status1, _ = self._enroll_with_token(token, hostname="host-1")
        self.assertEqual(status1, 201)
        status2, _ = self._enroll_with_token(token, hostname="host-2")
        self.assertEqual(status2, 403)

    def test_expired_token_rejected(self):
        # Manually plant an expired token
        tokens = api.load(api.ENROLL_TOKENS_FILE)
        expired = "x" * 32
        tokens[expired] = {
            "created": int(time.time()) - 10000,
            "expires": int(time.time()) - 100,  # in the past
            "label":   "test", "actor": "admin",
            "default_group": "", "default_tags": [],
        }
        api.save(api.ENROLL_TOKENS_FILE, tokens)
        status, _ = self._enroll_with_token(expired)
        self.assertEqual(status, 403)

    def test_pin_path_still_works(self):
        # Backward-compat: existing PIN flow must still work
        _set_request("POST", "/api/enroll/pin",
                     headers={"HTTP_X_TOKEN": self.admin_token})
        status, body = _call(api.handle_enroll_pin)
        self.assertEqual(status, 200)
        pin = body["pin"]

        # Use the PIN to enroll
        _set_request("POST", "/api/enroll/register",
                     body={"pin": pin, "hostname": "h", "name": "h",
                           "os": "Linux", "ip": "10.0.0.1", "version": "1.11.10"})
        status, body = _call(api.handle_enroll_register)
        self.assertEqual(status, 201)

    def test_neither_pin_nor_token_400(self):
        _set_request("POST", "/api/enroll/register",
                     body={"hostname": "h", "name": "h", "os": "Linux",
                           "ip": "10.0.0.1", "version": "1.11.10"})
        status, _ = _call(api.handle_enroll_register)
        self.assertEqual(status, 400)


# ─── Metric thresholds ───────────────────────────────────────────────────────


class TestMetricThresholdResolution(unittest.TestCase):
    """_resolve_metric_thresholds applies overrides correctly."""

    def test_defaults_when_no_overrides(self):
        dev = {}
        warn, crit = api._resolve_metric_thresholds(dev, "memory")
        self.assertEqual(warn, 85)
        self.assertEqual(crit, 95)

    def test_per_device_override(self):
        dev = {"metric_thresholds": {"mem_warn_percent": 70, "mem_crit_percent": 80}}
        warn, crit = api._resolve_metric_thresholds(dev, "memory")
        self.assertEqual(warn, 70)
        self.assertEqual(crit, 80)

    def test_per_mount_disk_override(self):
        dev = {
            "metric_thresholds": {
                "disk_warn_percent": 80,  # device-level disk default
                "disk_per_mount": {
                    "/var": {"warn": 60, "crit": 75},  # /var more sensitive
                },
            }
        }
        # /var uses the per-mount override
        warn, crit = api._resolve_metric_thresholds(dev, "disk", "/var")
        self.assertEqual(warn, 60)
        self.assertEqual(crit, 75)
        # / falls back to the device-level disk default
        warn, crit = api._resolve_metric_thresholds(dev, "disk", "/")
        self.assertEqual(warn, 80)
        # 90 = the default disk_crit_percent (since dev didn't set it)
        self.assertEqual(crit, 90)

    def test_cpu_load_ratio_default(self):
        warn, crit = api._resolve_metric_thresholds({}, "cpu")
        self.assertEqual(warn, 1.5)
        self.assertEqual(crit, 3.0)


class TestMetricClassification(unittest.TestCase):
    """_classify_metric returns the right level."""

    def test_below_warn_is_ok(self):
        self.assertEqual(api._classify_metric(70, 80, 90), "ok")

    def test_at_warn_is_warning(self):
        self.assertEqual(api._classify_metric(80, 80, 90), "warning")

    def test_between_warn_and_crit_is_warning(self):
        self.assertEqual(api._classify_metric(85, 80, 90), "warning")

    def test_at_crit_is_critical(self):
        self.assertEqual(api._classify_metric(90, 80, 90), "critical")

    def test_above_crit_is_critical(self):
        self.assertEqual(api._classify_metric(99, 80, 90), "critical")

    def test_below_recovery_buffer(self):
        # warn=80, recovery buffer = 5, so values < 75 should be "recovered"
        self.assertTrue(api._below_recovery(74, 80))
        self.assertFalse(api._below_recovery(76, 80))
        self.assertFalse(api._below_recovery(80, 80))


class TestProcessMetricThresholds(unittest.TestCase):
    """End-to-end: heartbeat with sysinfo triggers right webhooks."""

    def setUp(self):
        _isolate(self)
        self._fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda event, payload: self._fired.append((event, payload))

        devices = api.load(api.DEVICES_FILE)
        devices["dev-test"] = {
            "name": "test", "hostname": "test", "os": "Linux",
            "ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff",
            "token": "device-secret", "tags": [], "group": "",
            "enrolled": int(time.time()), "last_seen": int(time.time()),
            "monitored": True,
        }
        api.save(api.DEVICES_FILE, devices)

    def tearDown(self):
        api.fire_webhook = self._orig_fire

    def _process(self, mem=None, swap=None, load=None, cpu_count=4, mounts=None):
        """Simulate a sysinfo heartbeat."""
        devices = api.load(api.DEVICES_FILE)
        dev = devices["dev-test"]
        si = {}
        if mem is not None:    si["mem_percent"] = mem
        if swap is not None:   si["swap_percent"] = swap
        if load is not None:   si["loadavg_1m"] = load
        si["cpu_count"] = cpu_count
        if mounts is not None: si["mounts"] = mounts
        api.process_metric_thresholds("dev-test", dev, si)
        devices["dev-test"] = dev
        api.save(api.DEVICES_FILE, devices)
        return dev

    def test_low_metrics_no_webhooks(self):
        self._process(mem=50, swap=10, load=0.5, mounts=[
            {"path": "/", "percent": 30.0, "used_gb": 5, "total_gb": 30}
        ])
        self.assertEqual(self._fired, [])

    def test_memory_warning_fires(self):
        self._process(mem=87)  # > warn (85), < crit (95)
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_warning"])
        self.assertEqual(self._fired[0][1]["kind"], "memory")

    def test_memory_critical_fires(self):
        self._process(mem=97)
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_critical"])

    def test_memory_warn_then_crit(self):
        # Start at warning, then escalate to critical — both fire
        self._process(mem=87)
        self._process(mem=97)
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_warning", "metric_critical"])

    def test_warning_does_not_refire_at_same_level(self):
        # Once in warning, staying in warning shouldn't refire
        self._process(mem=87)
        self._process(mem=88)
        self._process(mem=89)
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_warning"])

    def test_recovery_with_hysteresis(self):
        # warn=85, buffer=5, so recovery requires < 80
        self._process(mem=87)            # warn fires
        self._fired.clear()
        self._process(mem=82)            # below warn but in buffer: no fire
        self.assertEqual(self._fired, [])
        self._process(mem=78)            # below buffer: recovered fires
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_recovered"])

    def test_per_mount_disk_isolated(self):
        # Two mounts with different fill levels — each tracked independently
        mounts = [
            {"path": "/",    "percent": 50.0},
            {"path": "/var", "percent": 92.0},
        ]
        self._process(mounts=mounts)
        events = [(e, p["target"]) for e, p in self._fired]
        # Only /var should have fired
        self.assertEqual(events, [("metric_critical", "/var")])

    def test_orphan_mount_state_cleaned(self):
        # First report: /var is at warning. Second report: /var disappears
        # entirely. The state for /var should be cleaned up.
        self._process(mounts=[
            {"path": "/",    "percent": 50.0},
            {"path": "/var", "percent": 85.0},
        ])
        # Now /var is gone
        self._process(mounts=[
            {"path": "/", "percent": 50.0},
        ])
        devices = api.load(api.DEVICES_FILE)
        state = devices["dev-test"].get("metric_state", {})
        self.assertNotIn("disk:/var", state)

    def test_cpu_load_ratio(self):
        # 4 CPUs, load=6.5 → ratio 1.625 → warn (>1.5, <3.0)
        self._process(load=6.5, cpu_count=4)
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["metric_warning"])
        self.assertEqual(self._fired[0][1]["kind"], "cpu")
        self.assertEqual(self._fired[0][1]["cpu_count"], 4)


class TestMetricThresholdsEndpoint(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        _, self.admin_token = _seed_admin()
        # Seed a device
        devices = api.load(api.DEVICES_FILE)
        devices["dev-test"] = {
            "name": "test", "hostname": "test", "os": "Linux",
            "ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff",
            "token": "device-secret", "tags": [], "group": "",
            "enrolled": int(time.time()), "last_seen": int(time.time()),
        }
        api.save(api.DEVICES_FILE, devices)

    def _auth(self):
        return {"HTTP_X_TOKEN": self.admin_token}

    def test_get_returns_defaults_when_no_overrides(self):
        _set_request("GET", "/api/devices/dev-test/metric-thresholds",
                     headers=self._auth())
        status, body = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 200)
        self.assertEqual(body["overrides"], {})
        self.assertEqual(body["effective"]["mem_warn_percent"], 85)
        self.assertEqual(body["effective"]["disk_crit_percent"], 90)

    def test_patch_sets_override(self):
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"mem_warn_percent": 70, "mem_crit_percent": 80},
                     headers=self._auth())
        status, body = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 200)
        # And it persists
        _set_request("GET", "/api/devices/dev-test/metric-thresholds",
                     headers=self._auth())
        _, body = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(body["overrides"]["mem_warn_percent"], 70)
        self.assertEqual(body["effective"]["mem_warn_percent"], 70)
        # Other defaults untouched
        self.assertEqual(body["effective"]["disk_warn_percent"], 80)

    def test_patch_warn_must_be_less_than_crit(self):
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"mem_warn_percent": 95, "mem_crit_percent": 90},
                     headers=self._auth())
        status, _ = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 400)

    def test_patch_rejects_out_of_range_percent(self):
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"mem_warn_percent": 150},
                     headers=self._auth())
        status, _ = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 400)

    def test_patch_per_mount_disk(self):
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"disk_per_mount": {
                         "/var": {"warn": 60, "crit": 75}
                     }},
                     headers=self._auth())
        status, body = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 200)
        self.assertEqual(body["overrides"]["disk_per_mount"]["/var"]["warn"], 60)

    def test_patch_per_mount_warn_lt_crit(self):
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"disk_per_mount": {
                         "/var": {"warn": 90, "crit": 80}
                     }},
                     headers=self._auth())
        status, _ = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 400)

    def test_delete_clears_overrides(self):
        # First set
        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"mem_warn_percent": 70, "mem_crit_percent": 80},
                     headers=self._auth())
        _call(api.handle_device_metric_thresholds, "dev-test")
        # Now delete
        _set_request("DELETE", "/api/devices/dev-test/metric-thresholds",
                     headers=self._auth())
        status, _ = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(status, 200)
        # GET should now show defaults
        _set_request("GET", "/api/devices/dev-test/metric-thresholds",
                     headers=self._auth())
        _, body = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertEqual(body["overrides"], {})

    def test_patch_clears_metric_state(self):
        # Setting thresholds should clear the in-memory alert state so
        # the next heartbeat re-evaluates under the new thresholds.
        devices = api.load(api.DEVICES_FILE)
        devices["dev-test"]["metric_state"] = {"memory:": "warning"}
        api.save(api.DEVICES_FILE, devices)

        _set_request("PATCH", "/api/devices/dev-test/metric-thresholds",
                     body={"mem_warn_percent": 70, "mem_crit_percent": 80},
                     headers=self._auth())
        _call(api.handle_device_metric_thresholds, "dev-test")

        devices = api.load(api.DEVICES_FILE)
        self.assertNotIn("metric_state", devices["dev-test"])

    def test_unknown_device_404(self):
        _set_request("GET", "/api/devices/notreal/metric-thresholds",
                     headers=self._auth())
        status, _ = _call(api.handle_device_metric_thresholds, "notreal")
        self.assertEqual(status, 404)

    def test_requires_admin(self):
        _set_request("GET", "/api/devices/dev-test/metric-thresholds")
        status, _ = _call(api.handle_device_metric_thresholds, "dev-test")
        self.assertIn(status, (401, 403))


class TestNewWebhookEvents(unittest.TestCase):
    """Smoke check: the three new events are registered and produce sane messages."""

    def test_events_in_registry(self):
        names = [e[0] for e in api.WEBHOOK_EVENTS]
        self.assertIn("metric_warning", names)
        self.assertIn("metric_critical", names)
        self.assertIn("metric_recovered", names)

    def test_message_for_disk_warning(self):
        msg = api._webhook_message("metric_warning", {
            "name": "host-1", "kind": "disk", "target": "/var",
            "value": 85.5, "threshold": 80,
        })
        self.assertIn("disk", msg)
        self.assertIn("/var", msg)
        self.assertIn("85.5", msg)

    def test_message_for_cpu_critical(self):
        msg = api._webhook_message("metric_critical", {
            "name": "host-1", "kind": "cpu", "target": "",
            "value": 12.5, "threshold": 3.0, "cpu_count": 4,
        })
        self.assertIn("cpu", msg.lower())
        self.assertIn("12.5", msg)

    def test_priority_critical_higher_than_warning(self):
        self.assertGreater(api._webhook_priority("metric_critical"),
                           api._webhook_priority("metric_warning"))


if __name__ == "__main__":
    unittest.main()
