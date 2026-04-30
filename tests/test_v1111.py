#!/usr/bin/env python3
"""Unit tests for v1.11.1: persisted positions + tunnels.

Covers:
  - PUT /api/network-map/positions: batch save, clearing, validation
  - GET /api/network-map: surfaces pos_x/pos_y and tunnels
  - POST /api/network-map/tunnels: add, duplicate detection, self-tunnel rejection
  - DELETE /api/network-map/tunnels/{id}
  - GET /api/network-map/tunnels: filters dangling endpoints
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

_spec = importlib.util.spec_from_file_location("api_v1111", _CGI_BIN / "api.py")
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


def _seed_device(dev_id):
    devices = api.load(api.DEVICES_FILE)
    devices[dev_id] = {
        "name": dev_id,
        "hostname": dev_id,
        "os": "Ubuntu 22.04",
        "ip": "10.0.0.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "token": "devtoken",
        "last_seen": int(time.time()),
        "enrolled": int(time.time()),
        "tags": [],
        "group": "",
        "sysinfo": {},
        "agentless": False,
        "connected_to": "",
        "device_type": "",
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
        "AUDIT_LOG_FILE",
        "CONFIG_FILE",
        "TUNNELS_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)


# ─── Positions ────────────────────────────────────────────────────────────────


class TestPositions(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()
        _seed_device("dev-a")
        _seed_device("dev-b")

    def test_batch_save(self):
        _set_request(
            "PUT",
            "/api/network-map/positions",
            body={"positions": [
                {"id": "dev-a", "x": 100, "y": 200},
                {"id": "dev-b", "x": 300, "y": 400},
            ]},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_network_positions)
        self.assertEqual(s, 200)
        self.assertEqual(b["updated"], 2)
        devs = api.load(api.DEVICES_FILE)
        self.assertEqual(devs["dev-a"]["pos_x"], 100)
        self.assertEqual(devs["dev-a"]["pos_y"], 200)
        self.assertEqual(devs["dev-b"]["pos_x"], 300)

    def test_null_clears(self):
        # Set, then clear
        api.save(api.DEVICES_FILE, {**api.load(api.DEVICES_FILE),
                                    "dev-a": {**api.load(api.DEVICES_FILE)["dev-a"],
                                              "pos_x": 100, "pos_y": 200}})
        _set_request(
            "PUT",
            "/api/network-map/positions",
            body={"positions": [{"id": "dev-a", "x": None, "y": None}]},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_network_positions)
        self.assertEqual(s, 200)
        devs = api.load(api.DEVICES_FILE)
        self.assertNotIn("pos_x", devs["dev-a"])
        self.assertNotIn("pos_y", devs["dev-a"])

    def test_unknown_device_silently_skipped(self):
        _set_request(
            "PUT",
            "/api/network-map/positions",
            body={"positions": [
                {"id": "dev-a", "x": 50, "y": 60},
                {"id": "ghost", "x": 999, "y": 999},
            ]},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_network_positions)
        self.assertEqual(s, 200)
        self.assertEqual(b["updated"], 1)

    def test_out_of_range_skipped(self):
        _set_request(
            "PUT",
            "/api/network-map/positions",
            body={"positions": [
                {"id": "dev-a", "x": 50000, "y": 100},
                {"id": "dev-b", "x": -50000, "y": 100},
            ]},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_network_positions)
        self.assertEqual(s, 200)
        self.assertEqual(b["updated"], 0)

    def test_non_list_400s(self):
        _set_request(
            "PUT",
            "/api/network-map/positions",
            body={"positions": "not a list"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_network_positions)
        self.assertEqual(s, 400)

    def test_network_map_surfaces_positions(self):
        api.save(
            api.DEVICES_FILE,
            {
                **api.load(api.DEVICES_FILE),
                "dev-a": {**api.load(api.DEVICES_FILE)["dev-a"], "pos_x": 100, "pos_y": 200},
            },
        )
        _set_request("GET", "/api/network-map", headers=_auth(self.token))
        s, b = _call(api.handle_network_map)
        self.assertEqual(s, 200)
        node_a = next(n for n in b["nodes"] if n["id"] == "dev-a")
        self.assertEqual(node_a["pos_x"], 100)
        self.assertEqual(node_a["pos_y"], 200)
        node_b = next(n for n in b["nodes"] if n["id"] == "dev-b")
        self.assertIsNone(node_b["pos_x"])
        self.assertIsNone(node_b["pos_y"])


# ─── Tunnels ──────────────────────────────────────────────────────────────────


class TestTunnels(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()
        _seed_device("dev-a")
        _seed_device("dev-b")
        _seed_device("dev-c")

    def test_add_tunnel(self):
        _set_request(
            "POST",
            "/api/network-map/tunnels",
            body={"endpoints": ["dev-a", "dev-b"]},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_tunnel_add)
        self.assertEqual(s, 200)
        self.assertTrue(b["id"].startswith("tun_"))
        # Endpoints normalised to sorted order
        self.assertEqual(b["endpoints"], ["dev-a", "dev-b"])

    def test_add_normalises_order(self):
        _set_request(
            "POST",
            "/api/network-map/tunnels",
            body={"endpoints": ["dev-b", "dev-a"]},  # reversed
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_tunnel_add)
        self.assertEqual(s, 200)
        self.assertEqual(b["endpoints"], ["dev-a", "dev-b"])  # canonical

    def test_duplicate_detected_either_direction(self):
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-a", "dev-b"]},
                     headers=_auth(self.token))
        _call(api.handle_tunnel_add)
        # Try the reverse — should be rejected as duplicate
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-b", "dev-a"]},
                     headers=_auth(self.token))
        s, b = _call(api.handle_tunnel_add)
        self.assertEqual(s, 409)

    def test_reject_self_tunnel(self):
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-a", "dev-a"]},
                     headers=_auth(self.token))
        s, b = _call(api.handle_tunnel_add)
        self.assertEqual(s, 400)

    def test_reject_unknown_endpoint(self):
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-a", "ghost"]},
                     headers=_auth(self.token))
        s, b = _call(api.handle_tunnel_add)
        self.assertEqual(s, 400)

    def test_reject_wrong_endpoints_shape(self):
        for bad in ([], ["dev-a"], ["dev-a", "dev-b", "dev-c"], "string", None):
            _set_request("POST", "/api/network-map/tunnels",
                         body={"endpoints": bad}, headers=_auth(self.token))
            s, b = _call(api.handle_tunnel_add)
            self.assertEqual(s, 400, f"expected 400 for endpoints={bad!r}")

    def test_delete_tunnel(self):
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-a", "dev-b"]},
                     headers=_auth(self.token))
        _, addb = _call(api.handle_tunnel_add)
        tid = addb["id"]
        _set_request("DELETE", f"/api/network-map/tunnels/{tid}",
                     headers=_auth(self.token))
        s, b = _call(api.handle_tunnel_delete, tid)
        self.assertEqual(s, 200)
        self.assertEqual(api.load(api.TUNNELS_FILE), {})

    def test_delete_404_unknown(self):
        _set_request("DELETE", "/api/network-map/tunnels/tun_ghost",
                     headers=_auth(self.token))
        s, b = _call(api.handle_tunnel_delete, "tun_ghost")
        self.assertEqual(s, 404)

    def test_list_filters_dangling_endpoints(self):
        # Manually seed a tunnel referencing a now-deleted device
        api.save(api.TUNNELS_FILE, {
            "tun_x": {"endpoints": ["dev-a", "dev-deleted"]},
            "tun_y": {"endpoints": ["dev-a", "dev-b"]},
        })
        _set_request("GET", "/api/network-map/tunnels", headers=_auth(self.token))
        s, b = _call(api.handle_tunnels_list)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["id"], "tun_y")

    def test_network_map_includes_tunnels(self):
        _set_request("POST", "/api/network-map/tunnels",
                     body={"endpoints": ["dev-a", "dev-b"]},
                     headers=_auth(self.token))
        _call(api.handle_tunnel_add)
        _set_request("GET", "/api/network-map", headers=_auth(self.token))
        s, b = _call(api.handle_network_map)
        self.assertEqual(s, 200)
        self.assertIn("tunnels", b)
        self.assertEqual(len(b["tunnels"]), 1)
        self.assertEqual(b["tunnels"][0]["endpoints"], ["dev-a", "dev-b"])


if __name__ == "__main__":
    unittest.main()
