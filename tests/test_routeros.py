#!/usr/bin/env python3
"""v3.3.4: RouterOS (MikroTik) REST client + endpoints.

The REST client is tested with a mocked transport (no real router); the
server handlers are tested through the real auth path (admin token), with
routeros.overview / routeros.action mocked so no network is touched.
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
from unittest.mock import patch

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
import routeros as ros

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"
_spec = importlib.util.spec_from_file_location("api_ros", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


# ── REST client (mocked transport) ─────────────────────────────────────────
def _fake_request(host, user, password, method, path, body=None, verify=False, timeout=6.0):
    table = {
        "/system/resource": {"version": "7.14", "board-name": "RB5009",
                             "cpu-load": 5, "uptime": "1w2d", "free-memory": 100},
        "/system/routerboard": {"model": "RB5009", "current-firmware": "7.14",
                               "upgrade-firmware": "7.15"},
        "/system/package/update": {"installed-version": "7.14",
                                  "latest-version": "7.15", "status": "available"},
        "/interface": [{".id": "*1", "name": "ether1", "type": "ether",
                       "running": "true", "disabled": "false",
                       "rx-byte": "1000", "tx-byte": "2000"}],
        "/ip/dhcp-server/lease": [{"address": "10.0.0.5", "mac-address": "AA:BB",
                                  "host-name": "nas", "status": "bound",
                                  "dynamic": "true"}],
        "/ip/firewall/filter": [{}, {}],
        "/ip/firewall/nat": [{}],
        "/ip/route": [{}, {}, {}],
    }
    if path in table:
        return table[path]
    if path == "/interface/wifi/registration-table":
        return [{"interface": "wifi1", "mac-address": "CC:DD", "signal": "-55"}]
    if path.endswith("/registration-table"):
        raise ros.RouterOSError("no such command")
    raise ros.RouterOSError("404")


class TestRouterosClient(unittest.TestCase):
    def test_overview_parses_all_sections(self):
        with patch.object(ros, "_request", side_effect=_fake_request):
            ov = ros.overview("h", "u", "p")
        self.assertEqual(ov["system"]["version"], "7.14")
        self.assertEqual(ov["routerboard"]["model"], "RB5009")
        self.assertEqual(ov["update"]["latest_version"], "7.15")
        self.assertEqual(ov["interfaces"][0]["rx_byte"], 1000)   # coerced to int
        self.assertFalse(ov["interfaces"][0]["disabled"])
        self.assertEqual(ov["dhcp_leases"][0]["mac"], "AA:BB")
        self.assertEqual(ov["firewall"], {"filter": 2, "nat": 1})
        self.assertEqual(ov["routes"], 3)
        self.assertEqual(ov["wireless"][0]["mac"], "CC:DD")
        self.assertEqual(ov["errors"], {})

    def test_overview_section_degrades(self):
        def boom(host, user, pw, method, path, **k):
            if path == "/ip/route":
                raise ros.RouterOSError("perm denied")
            return _fake_request(host, user, pw, method, path, **k)
        with patch.object(ros, "_request", side_effect=boom):
            ov = ros.overview("h", "u", "p")
        self.assertIn("routes", ov["errors"])
        self.assertEqual(ov["system"]["version"], "7.14")   # rest still there

    def test_action_allowlist_and_calls(self):
        calls = []

        def cap(host, user, pw, method, path, body=None, **k):
            calls.append((method, path, body))
            return "config text" if path == "/export" else {}
        with patch.object(ros, "_request", side_effect=cap):
            ros.action("h", "u", "p", "reboot")
            ros.action("h", "u", "p", "disable_interface", arg="*3")
            exp = ros.action("h", "u", "p", "export")
        self.assertIn(("POST", "/system/reboot", {}), calls)
        self.assertIn(("POST", "/interface/disable", {".id": "*3"}), calls)
        self.assertEqual(exp["export"], "config text")

    def test_action_rejects_unknown(self):
        with self.assertRaises(ros.RouterOSError):
            ros.action("h", "u", "p", "format_disk")

    def test_disable_requires_arg(self):
        with self.assertRaises(ros.RouterOSError):
            ros.action("h", "u", "p", "disable_interface")


# ── server handlers (real auth, mocked routeros) ───────────────────────────
class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}")
        self.status, self.body = status, body


api.respond = lambda status, data: (_ for _ in ()).throw(_Captured(status, data))


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def _req(method, path, body=None, token=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode()
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    if token:
        os.environ["HTTP_X_TOKEN"] = token
    else:
        os.environ.pop("HTTP_X_TOKEN", None)


def _call(fn, *args):
    try:
        fn(*args)
        return None, None
    except _Captured as c:
        return c.status, c.body


def _admin():
    api.ensure_default_user()
    user = next(iter(api.load(api.USERS_FILE)))
    tok = api.make_token()
    toks = api.load(api.TOKENS_FILE)
    toks[tok] = {"user": user, "created": int(time.time()), "ttl": 3600,
                 "admin": True, "remember": False}
    api.save(api.TOKENS_FILE, toks)
    return tok


class TestRouterosHandlers(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.TOKENS_FILE):
            api.save(f, {})
        self.tok = _admin()
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                                           "ip": "10.0.0.1"}})

    def test_enable_requires_credentials(self):
        _req("PATCH", "/api/devices/r1/routeros", {"enabled": True}, self.tok)
        st, _ = _call(api.handle_device_routeros, "r1")
        self.assertEqual(st, 400)

    def test_save_config_redacts_password(self):
        _req("PATCH", "/api/devices/r1/routeros",
             {"enabled": True, "username": "rp", "password": "secret", "port": 8443}, self.tok)
        st, body = _call(api.handle_device_routeros, "r1")
        self.assertEqual(st, 200)
        self.assertTrue(body["config"]["has_password"])
        self.assertEqual(body["config"]["username"], "rp")
        self.assertNotIn("password", body["config"])
        stored = api.load(api.DEVICES_FILE)["r1"]["routeros"]
        self.assertEqual(stored["password"], "secret")
        self.assertEqual(stored["port"], 8443)

    def test_empty_password_preserves(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "keepme"}}})
        _req("PATCH", "/api/devices/r1/routeros",
             {"enabled": True, "username": "rp", "password": ""}, self.tok)
        _call(api.handle_device_routeros, "r1")
        self.assertEqual(api.load(api.DEVICES_FILE)["r1"]["routeros"]["password"], "keepme")

    def test_get_returns_overview_when_enabled(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "x"}}})
        with patch.object(ros, "overview", return_value={"system": {"version": "7.14"}}):
            _req("GET", "/api/devices/r1/routeros", None, self.tok)
            st, body = _call(api.handle_device_routeros, "r1")
        self.assertEqual(st, 200)
        self.assertEqual(body["overview"]["system"]["version"], "7.14")

    def test_action_blocked_when_not_enabled(self):
        _req("POST", "/api/devices/r1/routeros/action", {"action": "reboot"}, self.tok)
        st, _ = _call(api.handle_device_routeros_action, "r1")
        self.assertEqual(st, 403)

    def test_action_runs_when_enabled(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "x"}}})
        with patch.object(ros, "action", return_value={"ok": True}) as act:
            _req("POST", "/api/devices/r1/routeros/action", {"action": "reboot"}, self.tok)
            st, body = _call(api.handle_device_routeros_action, "r1")
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        act.assert_called_once()


if __name__ == "__main__":
    unittest.main()
