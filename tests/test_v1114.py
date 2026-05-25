#!/usr/bin/env python3
"""Unit tests for v1.11.4: container alerts and stale detection.

Covers:
  - containers.is_stale boundary behaviour and edge cases
  - heartbeat ingest now overwrites with empty list (the v1.11.4 bugfix —
    previously empty lists were silently dropped, causing stale data)
  - process_container_report fires container_stopped when a previously-
    running container vanishes
  - process_container_report fires container_stopped when status flips
    from running to exited
  - process_container_report fires container_restarting on restart_count
    delta
  - check_container_webhooks fires containers_stale once per stale period
  - heartbeat resets the containers_stale_notified flag on fresh report
  - GET /api/devices/{id}/containers exposes is_stale + stale_ttl
  - GET /api/containers exposes is_stale per device
  - get_container_stale_ttl floors at 300s and clamps insane values
  - WEBHOOK_EVENTS contains the three new container events
  - _webhook_message renders sane strings for new events
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

_spec = importlib.util.spec_from_file_location("api_v1114", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import containers as containers_mod  # noqa: E402


# ─── Test helpers (mirroring tests/test_v1110.py) ────────────────────────────


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


def _set_request(method, path, body=None, headers=None, query=""):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    os.environ["QUERY_STRING"] = query
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
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


def _seed_admin():
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": user,
        "created": int(time.time()),
        "ttl": 3600,
        "admin": True,
        "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return user, token


def _auth(token):
    return {"HTTP_X_TOKEN": token}


def _seed_device(dev_id="dev-test", **kwargs):
    devices = api.load(api.DEVICES_FILE)
    devices[dev_id] = {
        "name": kwargs.get("name", dev_id),
        "hostname": kwargs.get("hostname", dev_id),
        "os": kwargs.get("os", "Ubuntu 22.04"),
        "ip": kwargs.get("ip", "10.0.0.5"),
        "mac": kwargs.get("mac", "aa:bb:cc:dd:ee:ff"),
        "token": "devtoken",
        "last_seen": kwargs.get("last_seen", int(time.time())),
        "enrolled": int(time.time()),
        "tags": [],
        "group": "",
        "sysinfo": {},
        "monitored": kwargs.get("monitored", True),
    }
    api.save(api.DEVICES_FILE, devices)
    return dev_id


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "CMDB_FILE",
        "AUDIT_LOG_FILE", "CONFIG_FILE", "CMD_OUTPUT_FILE",
        "UPDATE_LOGS_FILE", "CMDS_FILE", "CONTAINERS_FILE",
        "WEBHOOK_LOG_FILE", "SERVICES_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


# ─── containers.is_stale ─────────────────────────────────────────────────────


class TestIsStale(unittest.TestCase):
    def test_zero_reported_at_is_stale(self):
        # A device that never reported is "stale" (no fresh data ever).
        self.assertTrue(containers_mod.is_stale(0, 1_000_000_000, ttl=900))

    def test_fresh_report_not_stale(self):
        now = 1_000_000_000
        self.assertFalse(containers_mod.is_stale(now - 60, now, ttl=900))

    def test_just_under_threshold(self):
        now = 1_000_000_000
        # 899 seconds old, ttl 900 → still fresh
        self.assertFalse(containers_mod.is_stale(now - 899, now, ttl=900))

    def test_just_over_threshold(self):
        now = 1_000_000_000
        # 901 seconds old, ttl 900 → stale
        self.assertTrue(containers_mod.is_stale(now - 901, now, ttl=900))

    def test_garbage_input_treated_as_stale(self):
        # Non-numeric reported_at shouldn't crash — defensively counted as stale.
        self.assertTrue(containers_mod.is_stale("not-a-number", 1_000_000_000, ttl=900))

    def test_default_ttl_constant(self):
        # The default should be a reasonable 15 minutes.
        self.assertEqual(containers_mod.DEFAULT_STALE_TTL, 900)


# ─── webhook event registry ──────────────────────────────────────────────────


class TestWebhookRegistry(unittest.TestCase):
    def test_new_events_present(self):
        names = api.WEBHOOK_EVENT_NAMES
        self.assertIn("container_stopped", names)
        self.assertIn("container_restarting", names)
        self.assertIn("containers_stale", names)

    def test_new_events_default_enabled(self):
        # All three should default to enabled (third tuple element = True)
        events_dict = {ev: default for ev, _label, default in api.WEBHOOK_EVENTS}
        self.assertTrue(events_dict["container_stopped"])
        self.assertTrue(events_dict["container_restarting"])
        self.assertTrue(events_dict["containers_stale"])

    def test_message_strings(self):
        # Each event renders some non-empty human-readable string
        for ev in ("container_stopped", "container_restarting", "containers_stale"):
            msg = api._webhook_message(ev, {
                "name": "host-1", "container": "nginx",
                "previous_status": "Up", "status": "gone",
                "delta": 2, "restart_count": 7,
                "age_minutes": 30, "ttl_minutes": 15, "reported_at": 0,
                "runtime": "docker",
            })
            self.assertIsInstance(msg, str)
            self.assertGreater(len(msg), 5)
            self.assertIn("host-1", msg)


# ─── get_container_stale_ttl ─────────────────────────────────────────────────


class TestGetStaleTtl(unittest.TestCase):
    def setUp(self):
        _isolate(self)

    def test_default(self):
        self.assertEqual(api.get_container_stale_ttl(), 900)

    def test_user_override_within_range(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["container_stale_ttl"] = 1800
        api.save(api.CONFIG_FILE, cfg)
        self.assertEqual(api.get_container_stale_ttl(), 1800)

    def test_below_floor_clamped(self):
        # Anything under 300s is clamped to 300s — protects against the user
        # setting it stupidly low and getting alert-storms during normal poll
        # jitter.
        cfg = api.load(api.CONFIG_FILE)
        cfg["container_stale_ttl"] = 30
        api.save(api.CONFIG_FILE, cfg)
        self.assertEqual(api.get_container_stale_ttl(), 300)

    def test_garbage_falls_back_to_default(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["container_stale_ttl"] = "not-a-number"
        api.save(api.CONFIG_FILE, cfg)
        self.assertEqual(api.get_container_stale_ttl(), 900)


# ─── process_container_report transitions ────────────────────────────────────


class TestProcessContainerReport(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-test")
        self._fired = []
        self._orig_fire = api.fire_webhook
        # Stub fire_webhook so we can assert what would have been sent without
        # actually opening sockets.
        api.fire_webhook = lambda event, payload: self._fired.append((event, dict(payload)))

    def tearDown(self):
        api.fire_webhook = self._orig_fire

    def _seed_prev(self, items):
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {"ts": int(time.time()) - 60, "items": items}
        api.save(api.CONTAINERS_FILE, store)

    def test_first_report_no_webhooks(self):
        # No previous report → no transitions → no webhooks
        api.process_container_report(self.dev_id, [
            {"name": "nginx", "image": "nginx", "tag": "latest", "status": "Up 3 minutes",
             "namespace": "", "runtime": "docker", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ], int(time.time()))
        self.assertEqual(self._fired, [])

    def test_disappeared_running_container_fires_stopped(self):
        self._seed_prev([
            {"name": "nginx", "image": "nginx", "tag": "latest", "status": "Up 3 minutes",
             "namespace": "", "runtime": "docker", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ])
        # New report has no nginx
        api.process_container_report(self.dev_id, [], int(time.time()))
        self.assertEqual(len(self._fired), 1)
        ev, payload = self._fired[0]
        self.assertEqual(ev, "container_stopped")
        self.assertEqual(payload["container"], "nginx")
        self.assertEqual(payload["status"], "gone")
        self.assertEqual(payload["runtime"], "docker")

    def test_status_flip_running_to_exited_fires_stopped(self):
        self._seed_prev([
            {"name": "redis", "image": "redis", "tag": "7", "status": "Up 1 hour",
             "namespace": "", "runtime": "docker", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ])
        api.process_container_report(self.dev_id, [
            {"name": "redis", "image": "redis", "tag": "7", "status": "Exited (1) 5s ago",
             "namespace": "", "runtime": "docker", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ], int(time.time()))
        self.assertEqual(len(self._fired), 1)
        ev, payload = self._fired[0]
        self.assertEqual(ev, "container_stopped")
        self.assertEqual(payload["previous_status"], "Up 1 hour")
        self.assertEqual(payload["status"], "Exited (1) 5s ago")

    def test_already_stopped_doesnt_refire(self):
        # If previous status was already not-running, vanishing now isn't
        # a new transition — no webhook.
        self._seed_prev([
            {"name": "old", "image": "x", "tag": "", "status": "Exited (0)",
             "namespace": "", "runtime": "docker", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ])
        api.process_container_report(self.dev_id, [], int(time.time()))
        self.assertEqual(self._fired, [])

    def test_restart_count_delta_fires_restarting(self):
        self._seed_prev([
            {"name": "api-pod", "image": "api", "tag": "v1", "status": "Running",
             "namespace": "default", "runtime": "kubernetes", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 3},
        ])
        api.process_container_report(self.dev_id, [
            {"name": "api-pod", "image": "api", "tag": "v1", "status": "Running",
             "namespace": "default", "runtime": "kubernetes", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 5},
        ], int(time.time()))
        self.assertEqual(len(self._fired), 1)
        ev, payload = self._fired[0]
        self.assertEqual(ev, "container_restarting")
        self.assertEqual(payload["container"], "api-pod")
        self.assertEqual(payload["delta"], 2)
        self.assertEqual(payload["restart_count"], 5)

    def test_no_restart_no_alert(self):
        self._seed_prev([
            {"name": "api-pod", "image": "api", "tag": "v1", "status": "Running",
             "namespace": "default", "runtime": "kubernetes", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 3},
        ])
        api.process_container_report(self.dev_id, [
            {"name": "api-pod", "image": "api", "tag": "v1", "status": "Running",
             "namespace": "default", "runtime": "kubernetes", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 3},
        ], int(time.time()))
        self.assertEqual(self._fired, [])


# ─── heartbeat empty-list bugfix ─────────────────────────────────────────────


class TestHeartbeatEmptyList(unittest.TestCase):
    """The headline v1.11.4 fix: the agent sends an empty list when a
    runtime exists but has no containers, and the server must clear out
    the previously-stored list rather than keep it forever.
    """

    def setUp(self):
        _isolate(self)
        self.dev_id = "dev-hb"
        # Seed a device with an enrolment token and an existing container list
        devices = api.load(api.DEVICES_FILE)
        devices[self.dev_id] = {
            "name": "hb-host", "hostname": "hb", "os": "Ubuntu",
            "ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa",
            "token": "hb-secret",
            "last_seen": int(time.time()),
            "enrolled": int(time.time()),
            "tags": [], "group": "", "sysinfo": {},
            "monitored": True,
        }
        api.save(api.DEVICES_FILE, devices)
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {
            "ts": int(time.time()) - 600,
            "items": [{
                "name": "old-nginx", "image": "nginx", "tag": "latest",
                "status": "Up 1 day", "namespace": "", "runtime": "docker",
                "ports": [], "started_at": 0, "uptime_seconds": 0,
                "restart_count": 0,
            }],
        }
        api.save(api.CONTAINERS_FILE, store)

    def test_heartbeat_with_empty_list_clears_stored_state(self):
        body = {
            "device_id": self.dev_id,
            "token": "hb-secret",
            "containers": [],     # ← the empty list the v1.11.4 agent sends
        }
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)
        # Stored items should now be empty — old-nginx is gone.
        store = api.load(api.CONTAINERS_FILE)
        self.assertEqual(store[self.dev_id]["items"], [])


# ─── containers_stale webhook check ──────────────────────────────────────────


class TestCheckContainerWebhooks(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-stale")
        self._fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda event, payload: self._fired.append((event, dict(payload)))

    def tearDown(self):
        api.fire_webhook = self._orig_fire

    def _seed_containers(self, ts):
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {"ts": ts, "items": []}
        api.save(api.CONTAINERS_FILE, store)

    def test_fresh_report_no_webhook(self):
        self._seed_containers(int(time.time()) - 60)
        api.check_container_webhooks()
        self.assertEqual(self._fired, [])

    def test_stale_report_fires_once(self):
        self._seed_containers(int(time.time()) - 4000)  # well over default 900s
        api.check_container_webhooks()
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["containers_stale"])
        # Notification flag is now set
        cfg = api.load(api.CONFIG_FILE)
        self.assertTrue(cfg.get("containers_stale_notified", {}).get(self.dev_id))

        # Second sweep should NOT re-fire
        self._fired.clear()
        api.check_container_webhooks()
        self.assertEqual(self._fired, [])

    def test_offline_device_skipped(self):
        # An offline device already has device_offline firing — don't
        # double-page on its containers also being stale.
        devices = api.load(api.DEVICES_FILE)
        devices[self.dev_id]["last_seen"] = int(time.time()) - 10_000
        api.save(api.DEVICES_FILE, devices)
        self._seed_containers(int(time.time()) - 4000)
        api.check_container_webhooks()
        self.assertEqual(self._fired, [])

    def test_unmonitored_device_skipped(self):
        devices = api.load(api.DEVICES_FILE)
        devices[self.dev_id]["monitored"] = False
        api.save(api.DEVICES_FILE, devices)
        self._seed_containers(int(time.time()) - 4000)
        api.check_container_webhooks()
        self.assertEqual(self._fired, [])


# ─── API responses expose is_stale ───────────────────────────────────────────


class TestApiExposesStale(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-api")
        _, self.token = _seed_admin()

    def _seed_containers(self, ts, items=None):
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {"ts": ts, "items": items or []}
        api.save(api.CONTAINERS_FILE, store)

    def test_per_device_endpoint_is_stale_true(self):
        self._seed_containers(int(time.time()) - 4000)
        _set_request("GET", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        status, body = _call(api.handle_device_containers, self.dev_id)
        self.assertEqual(status, 200)
        self.assertTrue(body["is_stale"])
        self.assertEqual(body["stale_ttl"], 900)

    def test_per_device_endpoint_is_stale_false(self):
        self._seed_containers(int(time.time()) - 30)
        _set_request("GET", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        status, body = _call(api.handle_device_containers, self.dev_id)
        self.assertEqual(status, 200)
        self.assertFalse(body["is_stale"])

    def test_overview_endpoint_is_stale(self):
        self._seed_containers(int(time.time()) - 4000)
        _set_request("GET", "/api/containers", headers=_auth(self.token))
        status, body = _call(api.handle_containers_overview)
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 1)
        self.assertTrue(body[0]["is_stale"])


# ─── heartbeat clears notified flag on fresh report ──────────────────────────


class TestHeartbeatClearsStaleFlag(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = "dev-clear"
        devices = api.load(api.DEVICES_FILE)
        devices[self.dev_id] = {
            "name": "n", "hostname": "h", "os": "Ubuntu",
            "ip": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:ff",
            "token": "tok",
            "last_seen": int(time.time()),
            "enrolled": int(time.time()),
            "tags": [], "group": "", "sysinfo": {},
            "monitored": True,
        }
        api.save(api.DEVICES_FILE, devices)
        # Mark device as already-notified for stale containers
        cfg = api.load(api.CONFIG_FILE)
        cfg["containers_stale_notified"] = {self.dev_id: True}
        api.save(api.CONFIG_FILE, cfg)

    def test_fresh_heartbeat_clears_flag(self):
        body = {
            "device_id": self.dev_id, "token": "tok",
            "containers": [{"name": "x", "runtime": "docker"}],
        }
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)
        cfg = api.load(api.CONFIG_FILE)
        self.assertFalse(cfg.get("containers_stale_notified", {}).get(self.dev_id, False))


# ─── manual clear endpoint (DELETE /api/devices/{id}/containers) ─────────────


class TestContainersClearEndpoint(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-clr")
        _, self.token = _seed_admin()
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {
            "ts": int(time.time()),
            "items": [{
                "name": "nginx", "image": "nginx", "tag": "latest",
                "status": "Up 1h", "namespace": "", "runtime": "docker",
                "ports": [], "started_at": 0, "uptime_seconds": 0,
                "restart_count": 0,
            }],
        }
        api.save(api.CONTAINERS_FILE, store)
        # Pre-set a stale-notified flag so we can confirm it gets cleared
        cfg = api.load(api.CONFIG_FILE)
        cfg["containers_stale_notified"] = {self.dev_id: True}
        api.save(api.CONFIG_FILE, cfg)

    def test_clear_removes_entry(self):
        _set_request("DELETE", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        status, body = _call(api.handle_device_containers_clear, self.dev_id)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(body["cleared"])
        store = api.load(api.CONTAINERS_FILE)
        self.assertNotIn(self.dev_id, store)

    def test_clear_clears_stale_notified_flag(self):
        _set_request("DELETE", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        _call(api.handle_device_containers_clear, self.dev_id)
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotIn(self.dev_id, cfg.get("containers_stale_notified", {}))

    def test_clear_idempotent(self):
        # Call once, succeeds with cleared=True. Call again, succeeds with
        # cleared=False (nothing to do but not an error).
        _set_request("DELETE", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        _call(api.handle_device_containers_clear, self.dev_id)
        _set_request("DELETE", f"/api/devices/{self.dev_id}/containers", headers=_auth(self.token))
        status, body = _call(api.handle_device_containers_clear, self.dev_id)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertFalse(body["cleared"])

    def test_clear_unknown_device_404(self):
        _set_request("DELETE", "/api/devices/dev-nonesuch/containers", headers=_auth(self.token))
        status, _ = _call(api.handle_device_containers_clear, "dev-nonesuch")
        self.assertEqual(status, 404)

    def test_clear_requires_admin(self):
        # No auth header at all → fails
        _set_request("DELETE", f"/api/devices/{self.dev_id}/containers")
        status, _ = _call(api.handle_device_containers_clear, self.dev_id)
        self.assertIn(status, (401, 403))


# ─── device delete cleans up container state ────────────────────────────────


class TestDeviceDeleteCleansContainers(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-del")
        _, self.token = _seed_admin()
        store = api.load(api.CONTAINERS_FILE)
        store[self.dev_id] = {"ts": int(time.time()), "items": [
            {"name": "redis", "runtime": "docker", "status": "Up", "image": "redis",
             "tag": "", "namespace": "", "ports": [],
             "started_at": 0, "uptime_seconds": 0, "restart_count": 0},
        ]}
        api.save(api.CONTAINERS_FILE, store)
        cfg = api.load(api.CONFIG_FILE)
        cfg["containers_stale_notified"] = {self.dev_id: True}
        api.save(api.CONFIG_FILE, cfg)

    def test_device_delete_removes_container_entry(self):
        _set_request("DELETE", f"/api/devices/{self.dev_id}", headers=_auth(self.token))
        status, _ = _call(api.handle_device_delete, self.dev_id)
        self.assertEqual(status, 200)
        store = api.load(api.CONTAINERS_FILE)
        self.assertNotIn(self.dev_id, store)

    def test_device_delete_clears_stale_notified(self):
        _set_request("DELETE", f"/api/devices/{self.dev_id}", headers=_auth(self.token))
        _call(api.handle_device_delete, self.dev_id)
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotIn(self.dev_id, cfg.get("containers_stale_notified", {}))


if __name__ == "__main__":
    unittest.main()
