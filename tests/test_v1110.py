#!/usr/bin/env python3
"""Unit tests for v1.11.0.

Covers:
  - containers.py: normalisation, summarise, listing cap
  - tls_monitor.py: target validation, status thresholds, days_until_expiry
  - Heartbeat acceptance of containers field
  - GET /api/devices/{id}/containers + /api/containers
  - GET /api/network-map (nodes + edges from connected_to)
  - PUT /api/devices/{id}/connected-to
  - POST /api/devices/agentless
  - TLS targets CRUD endpoints
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

_spec = importlib.util.spec_from_file_location("api_v1110", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import containers as containers_mod
import tls_monitor


# ─── Helpers ──────────────────────────────────────────────────────────────────


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
        "last_seen": int(time.time()),
        "enrolled": int(time.time()),
        "tags": [],
        "group": "",
        "sysinfo": {},
        "agentless": kwargs.get("agentless", False),
        "connected_to": kwargs.get("connected_to", ""),
        "device_type": kwargs.get("device_type", ""),
    }
    api.save(api.DEVICES_FILE, devices)
    return dev_id


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE",
        "TOKENS_FILE",
        "DEVICES_FILE",
        "CMDB_FILE",
        "CMDB_VAULT_FILE",
        "AUDIT_LOG_FILE",
        "CONFIG_FILE",
        "CMD_OUTPUT_FILE",
        "UPDATE_LOGS_FILE",
        "CMDS_FILE",
        "CONTAINERS_FILE",
        "TLS_TARGETS_FILE",
        "TLS_RESULTS_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


# ─── containers.py ───────────────────────────────────────────────────────────


class TestContainersModule(unittest.TestCase):
    def test_normalize_minimal(self):
        n = containers_mod.normalize_container({"name": "nginx"})
        self.assertEqual(n["name"], "nginx")
        self.assertEqual(n["restart_count"], 0)
        self.assertEqual(n["runtime"], "unknown")

    def test_normalize_drops_nameless(self):
        self.assertIsNone(containers_mod.normalize_container({}))
        self.assertIsNone(containers_mod.normalize_container({"image": "nginx"}))

    def test_normalize_runtime_aliases(self):
        for given, expected in (
            ("docker", "docker"),
            ("Docker", "docker"),
            ("PODMAN", "podman"),
            ("k8s", "kubernetes"),
            ("kube", "kubernetes"),
            ("kubernetes", "kubernetes"),
            ("rkt", "unknown"),
            ("", "unknown"),
            (None, "unknown"),
        ):
            n = containers_mod.normalize_container({"name": "x", "runtime": given})
            self.assertEqual(n["runtime"], expected, f"{given!r} → {n['runtime']!r}")

    def test_normalize_caps_ports(self):
        ports = [f"{p}/tcp" for p in range(50)]
        n = containers_mod.normalize_container({"name": "x", "ports": ports})
        self.assertEqual(len(n["ports"]), containers_mod.MAX_PORTS_PER_CONTAINER)

    def test_normalize_listing_caps_total(self):
        items = [{"name": f"c{i}", "runtime": "docker"} for i in range(150)]
        out = containers_mod.normalize_listing(items)
        self.assertEqual(len(out), containers_mod.MAX_CONTAINERS_PER_DEVICE)

    def test_normalize_listing_handles_garbage(self):
        self.assertEqual(containers_mod.normalize_listing(None), [])
        self.assertEqual(containers_mod.normalize_listing("string"), [])
        self.assertEqual(containers_mod.normalize_listing(42), [])

    def test_summarise_counts(self):
        items = [
            {"name": "a", "status": "running", "restart_count": 0, "runtime": "docker"},
            {"name": "b", "status": "Up 3 hours", "restart_count": 1, "runtime": "docker"},
            {"name": "c", "status": "exited", "restart_count": 0, "runtime": "docker"},
            {"name": "d", "status": "Running", "restart_count": 7, "runtime": "kubernetes"},
        ]
        s = containers_mod.summarise(items)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["running"], 3)
        self.assertEqual(s["stopped"], 1)
        self.assertEqual(s["restarting"], 1)
        self.assertEqual(s["by_runtime"], {"docker": 3, "kubernetes": 1})


# ─── tls_monitor.py ──────────────────────────────────────────────────────────


class TestTLSMonitor(unittest.TestCase):
    def test_parse_target_basic(self):
        t = tls_monitor.parse_target({"host": "example.com"})
        self.assertEqual(t["host"], "example.com")
        self.assertEqual(t["port"], 443)
        self.assertEqual(t["warn_days"], 14)
        self.assertEqual(t["crit_days"], 3)

    def test_parse_target_custom_values(self):
        t = tls_monitor.parse_target(
            {"host": "MAIL.EXAMPLE.COM", "port": 465, "warn_days": 30, "crit_days": 7, "label": "MX"}
        )
        self.assertEqual(t["host"], "mail.example.com")  # lowercased
        self.assertEqual(t["port"], 465)
        self.assertEqual(t["warn_days"], 30)
        self.assertEqual(t["crit_days"], 7)
        self.assertEqual(t["label"], "MX")

    def test_parse_target_rejects_bad(self):
        for bad in (
            {},
            {"host": ""},
            {"host": "x" * 300},
            {"host": "has spaces"},
            {"host": "a/b"},
            {"host": "ok", "port": 0},
            {"host": "ok", "port": 70000},
            {"host": "ok", "port": "abc"},
        ):
            self.assertIsNone(tls_monitor.parse_target(bad), f"expected None for {bad}")

    def test_parse_target_clamps_warn_crit(self):
        t = tls_monitor.parse_target({"host": "x", "warn_days": 5, "crit_days": 100})
        # crit can't exceed warn — clamped to warn
        self.assertLessEqual(t["crit_days"], t["warn_days"])

    def test_status_for_thresholds(self):
        now = int(time.time())
        ok = {"expires_at": now + 30 * 86400}
        warn = {"expires_at": now + 7 * 86400}
        crit = {"expires_at": now + 1 * 86400}
        err = {"dns_error": "no such host"}
        self.assertEqual(tls_monitor.status_for(ok, 14, 3), "ok")
        self.assertEqual(tls_monitor.status_for(warn, 14, 3), "warning")
        self.assertEqual(tls_monitor.status_for(crit, 14, 3), "critical")
        self.assertEqual(tls_monitor.status_for(err, 14, 3), "error")
        self.assertEqual(tls_monitor.status_for({}, 14, 3), "error")

    def test_days_until_expiry(self):
        now = int(time.time())
        self.assertEqual(tls_monitor.days_until_expiry({"expires_at": now + 5 * 86400}), 5)
        self.assertEqual(tls_monitor.days_until_expiry({"expires_at": now - 2 * 86400}), -2)
        self.assertEqual(tls_monitor.days_until_expiry({}), 0)

    def test_probe_returns_structured_result_on_dns_failure(self):
        """Regression: handle_tls_scan crashed with AttributeError when the
        cert-parsing fallback reached for a private ssl symbol. _probe_tls
        must always return a dict with the documented keys, even when the
        host doesn't resolve."""
        result = tls_monitor._probe_tls("nope.invalid.example.invalid", 443)
        self.assertIsInstance(result, dict)
        for key in ("host", "port", "checked_at", "addresses",
                    "dns_error", "tls_error", "verify_error",
                    "expires_at", "issuer", "subject", "san"):
            self.assertIn(key, result, f"missing key: {key}")
        # DNS failure path: dns_error populated, no exception leaks
        self.assertTrue(result["dns_error"])

    def test_probe_all_handles_unreachable_target(self):
        """Same regression at the probe_all level — must not propagate
        exceptions even if every target is unreachable."""
        targets = {
            "tls_x": {"host": "127.0.0.1", "port": 1, "warn_days": 14, "crit_days": 3},
        }
        results = tls_monitor.probe_all(targets)
        self.assertIn("tls_x", results)
        # Either tls_error or dns_error should be populated; expires_at
        # should be 0 (we never got a cert)
        self.assertEqual(results["tls_x"]["expires_at"], 0)


# ─── Heartbeat container intake ──────────────────────────────────────────────


class TestHeartbeatContainers(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.dev_id = _seed_device("dev-hb")
        # Need the device's token for heartbeat
        self.dev_token = api.load(api.DEVICES_FILE)[self.dev_id]["token"]

    def test_heartbeat_accepts_containers(self):
        body = {
            "device_id": self.dev_id,
            "token": self.dev_token,
            "containers": [
                {"name": "nginx", "runtime": "docker", "status": "Up 3 hours"},
                {"name": "redis", "runtime": "docker", "status": "Up 1 hour", "restart_count": 2},
            ],
        }
        _set_request("POST", "/api/heartbeat", body=body)
        s, b = _call(api.handle_heartbeat)
        self.assertEqual(s, 200)
        store = api.load(api.CONTAINERS_FILE)
        self.assertIn(self.dev_id, store)
        self.assertEqual(len(store[self.dev_id]["items"]), 2)

    def test_heartbeat_overwrites_previous_containers(self):
        # Seed initial state
        api.save(
            api.CONTAINERS_FILE,
            {self.dev_id: {"ts": 1, "items": [{"name": "old"}]}},
        )
        body = {
            "device_id": self.dev_id,
            "token": self.dev_token,
            "containers": [{"name": "new", "runtime": "docker"}],
        }
        _set_request("POST", "/api/heartbeat", body=body)
        s, _b = _call(api.handle_heartbeat)
        self.assertEqual(s, 200)
        store = api.load(api.CONTAINERS_FILE)
        names = [c["name"] for c in store[self.dev_id]["items"]]
        self.assertEqual(names, ["new"])


# ─── Container endpoints ─────────────────────────────────────────────────────


class TestContainerEndpoints(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()
        self.dev = _seed_device()

    def test_overview_empty(self):
        _set_request("GET", "/api/containers", headers=_auth(self.token))
        s, b = _call(api.handle_containers_overview)
        self.assertEqual(s, 200)
        self.assertEqual(b, [])

    def test_overview_returns_summary(self):
        api.save(
            api.CONTAINERS_FILE,
            {
                self.dev: {
                    "ts": int(time.time()),
                    "items": [
                        {"name": "a", "status": "running", "runtime": "docker"},
                        {"name": "b", "status": "exited", "runtime": "docker"},
                    ],
                }
            },
        )
        _set_request("GET", "/api/containers", headers=_auth(self.token))
        s, b = _call(api.handle_containers_overview)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["device_id"], self.dev)
        self.assertEqual(b[0]["summary"]["total"], 2)
        self.assertEqual(b[0]["summary"]["running"], 1)

    def test_per_device_containers_returns_full_list(self):
        items = [{"name": f"c{i}", "runtime": "docker", "status": "running"} for i in range(3)]
        api.save(api.CONTAINERS_FILE, {self.dev: {"ts": 100, "items": items}})
        _set_request(
            "GET", f"/api/devices/{self.dev}/containers", headers=_auth(self.token)
        )
        s, b = _call(api.handle_device_containers, self.dev)
        self.assertEqual(s, 200)
        self.assertEqual(len(b["items"]), 3)
        self.assertEqual(b["summary"]["running"], 3)

    def test_per_device_404(self):
        _set_request(
            "GET", "/api/devices/no-such/containers", headers=_auth(self.token)
        )
        s, b = _call(api.handle_device_containers, "no-such")
        self.assertEqual(s, 404)


# ─── Network map ─────────────────────────────────────────────────────────────


class TestNetworkMap(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()
        _seed_device("dev-a")
        _seed_device("dev-b", connected_to="dev-a")
        _seed_device("dev-c", connected_to="dev-a")
        _seed_device("dev-d", connected_to="dev-orphan")  # dangling edge

    def test_network_map_shape(self):
        _set_request("GET", "/api/network-map", headers=_auth(self.token))
        s, b = _call(api.handle_network_map)
        self.assertEqual(s, 200)
        self.assertEqual(len(b["nodes"]), 4)
        # Two valid edges, the dangling one is dropped
        self.assertEqual(len(b["edges"]), 2)
        froms = {e["from"] for e in b["edges"]}
        self.assertEqual(froms, {"dev-b", "dev-c"})
        for e in b["edges"]:
            self.assertEqual(e["to"], "dev-a")

    def test_connected_to_self_rejected(self):
        _set_request(
            "PUT",
            "/api/devices/dev-a/connected-to",
            body={"connected_to": "dev-a"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_device_connected_to, "dev-a")
        self.assertEqual(s, 400)

    def test_connected_to_nonexistent_rejected(self):
        _set_request(
            "PUT",
            "/api/devices/dev-a/connected-to",
            body={"connected_to": "ghost"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_device_connected_to, "dev-a")
        self.assertEqual(s, 400)

    def test_connected_to_clear_with_empty(self):
        _set_request(
            "PUT",
            "/api/devices/dev-b/connected-to",
            body={"connected_to": ""},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_device_connected_to, "dev-b")
        self.assertEqual(s, 200)
        devices = api.load(api.DEVICES_FILE)
        self.assertEqual(devices["dev-b"]["connected_to"], "")


# ─── Agentless device creation ───────────────────────────────────────────────


class TestAgentless(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()

    def test_create_minimal(self):
        _set_request(
            "POST",
            "/api/devices/agentless",
            body={"name": "core-switch-1", "device_type": "switch"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_agentless_create)
        self.assertEqual(s, 200)
        self.assertTrue(b["id"].startswith("al_"))
        devices = api.load(api.DEVICES_FILE)
        self.assertIn(b["id"], devices)
        self.assertTrue(devices[b["id"]]["agentless"])
        self.assertEqual(devices[b["id"]]["device_type"], "switch")

    def test_create_rejects_no_name(self):
        _set_request(
            "POST",
            "/api/devices/agentless",
            body={"device_type": "switch"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_agentless_create)
        self.assertEqual(s, 400)

    def test_create_rejects_bad_type(self):
        _set_request(
            "POST",
            "/api/devices/agentless",
            body={"name": "x", "device_type": "warp_drive"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_agentless_create)
        self.assertEqual(s, 400)

    def test_create_rejects_bad_connected_to(self):
        _set_request(
            "POST",
            "/api/devices/agentless",
            body={"name": "x", "connected_to": "nonexistent"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_agentless_create)
        self.assertEqual(s, 400)

    def test_devices_list_surfaces_agentless_flag(self):
        _set_request(
            "POST",
            "/api/devices/agentless",
            body={"name": "ap-1", "device_type": "access_point"},
            headers=_auth(self.token),
        )
        _, _b = _call(api.handle_agentless_create)
        _set_request("GET", "/api/devices", headers=_auth(self.token))
        s, b = _call(api.handle_devices_list)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertTrue(b[0]["agentless"])
        self.assertEqual(b[0]["device_type"], "access_point")


# ─── TLS targets endpoints ───────────────────────────────────────────────────


class TestTLSEndpoints(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()

    def test_add_minimal(self):
        _set_request(
            "POST",
            "/api/tls/targets",
            body={"host": "example.com"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_tls_add)
        self.assertEqual(s, 200)
        self.assertTrue(b["id"].startswith("tls_"))

    def test_add_rejects_bad_host(self):
        _set_request(
            "POST",
            "/api/tls/targets",
            body={"host": "has spaces"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_tls_add)
        self.assertEqual(s, 400)

    def test_list_includes_status(self):
        api.save(
            api.TLS_TARGETS_FILE,
            {"tls_xyz": {"host": "example.com", "port": 443, "warn_days": 14, "crit_days": 3}},
        )
        _set_request("GET", "/api/tls/targets", headers=_auth(self.token))
        s, b = _call(api.handle_tls_list)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["status"], "unknown")  # never scanned

    def test_delete_removes_target_and_results(self):
        api.save(
            api.TLS_TARGETS_FILE,
            {"tls_xyz": {"host": "example.com", "port": 443}},
        )
        api.save(
            api.TLS_RESULTS_FILE,
            {"tls_xyz": {"checked_at": 1, "expires_at": 2}},
        )
        _set_request(
            "DELETE", "/api/tls/targets/tls_xyz", headers=_auth(self.token)
        )
        s, b = _call(api.handle_tls_delete, "tls_xyz")
        self.assertEqual(s, 200)
        self.assertNotIn("tls_xyz", api.load(api.TLS_TARGETS_FILE))
        self.assertNotIn("tls_xyz", api.load(api.TLS_RESULTS_FILE))

    def test_delete_404_unknown(self):
        _set_request(
            "DELETE", "/api/tls/targets/tls_ghost", headers=_auth(self.token)
        )
        s, b = _call(api.handle_tls_delete, "tls_ghost")
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
