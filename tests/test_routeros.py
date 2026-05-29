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

    def test_check_update_action(self):
        calls = []

        def cap(host, user, pw, method, path, body=None, **k):
            calls.append((method, path))
            if path == "/system/package/update":
                return {"installed-version": "7.23", "latest-version": "7.24",
                        "status": "New version is available", "channel": "stable"}
            return {}
        with patch.object(ros, "_request", side_effect=cap):
            r = ros.action("h", "u", "p", "check_update")
        self.assertIn(("POST", "/system/package/update/check-for-updates"), calls)
        self.assertEqual(r["update"]["installed"], "7.23")
        self.assertEqual(r["update"]["latest"], "7.24")

    def test_upgrade_action_calls_install(self):
        calls = []

        def cap(host, user, pw, method, path, body=None, **k):
            calls.append((method, path))
            return {}
        with patch.object(ros, "_request", side_effect=cap):
            r = ros.action("h", "u", "p", "upgrade")
        self.assertTrue(r.get("rebooting"))
        self.assertIn(("POST", "/system/package/update/install"), calls)

    def test_firewall_parsing(self):
        def cap(host, user, pw, method, path, body=None, **k):
            if path == "/ip/firewall/filter":
                return [{".id": "*1", "chain": "input", "action": "drop",
                         "src-address": "1.2.3.4", "disabled": "false", "comment": "x"}]
            if path == "/ip/firewall/nat":
                return [{".id": "*2", "chain": "srcnat", "action": "masquerade"}]
            return []
        with patch.object(ros, "_request", side_effect=cap):
            fw = ros.firewall("h", "u", "p")
        self.assertEqual(fw["filter"][0]["chain"], "input")
        self.assertFalse(fw["filter"][0]["disabled"])
        self.assertEqual(fw["nat"][0]["action"], "masquerade")

    def test_sanitize_rule_whitelists_and_requires(self):
        r = ros._sanitize_rule({"chain": "input", "action": "drop",
                                "src_address": "1.2.3.4", "evil": "x", "dst-port": "22"})
        self.assertEqual(r["chain"], "input")
        self.assertEqual(r["src-address"], "1.2.3.4")   # underscore normalised
        self.assertEqual(r["dst-port"], "22")
        self.assertNotIn("evil", r)                     # not whitelisted
        with self.assertRaises(ros.RouterOSError):
            ros._sanitize_rule({"action": "drop"})       # no chain

    def test_add_rule_defaults_disabled(self):
        calls = []

        def cap(host, user, pw, method, path, body=None, **k):
            calls.append((method, path, body))
            return {}
        with patch.object(ros, "_request", side_effect=cap):
            ros.action("h", "u", "p", "add_firewall_rule",
                       rule={"chain": "input", "action": "drop"})
        method, path, body = calls[0]
        self.assertEqual((method, path), ("POST", "/ip/firewall/filter"))
        self.assertEqual(body["disabled"], "yes")        # safety default

    def test_rule_toggle_calls(self):
        calls = []

        def cap(host, user, pw, method, path, body=None, **k):
            calls.append((method, path, body))
            return {}
        with patch.object(ros, "_request", side_effect=cap):
            ros.action("h", "u", "p", "disable_rule", arg="*5")
        self.assertEqual(calls[0], ("POST", "/ip/firewall/filter/disable", {".id": "*5"}))

    def test_qos_parsing(self):
        def cap(host, user, pw, method, path, body=None, **k):
            if path == "/queue/simple":
                return [{"name": "q1", "target": "192.168.1.0/24",
                         "max-limit": "100M/100M", "disabled": "false"}]
            return []
        with patch.object(ros, "_request", side_effect=cap):
            q = ros.qos("h", "u", "p")
        self.assertEqual(q["simple"][0]["name"], "q1")
        self.assertEqual(q["simple"][0]["max_limit"], "100M/100M")

    def test_traffic_computes_rates(self):
        seq = [
            [{"name": "ether1", "rx-byte": "1000", "tx-byte": "2000"}],
            [{"name": "ether1", "rx-byte": "9000", "tx-byte": "2000"}],  # +8000 rx
        ]
        state = {"n": 0}

        def cap(host, user, pw, method, path, body=None, **k):
            i = min(state["n"], len(seq) - 1)
            state["n"] += 1
            return seq[i]
        with patch.object(ros, "_request", side_effect=cap), \
             patch.object(ros.time, "sleep"):     # no real 1s wait
            rates = ros.traffic("h", "u", "p")
        r = next(x for x in rates if x["name"] == "ether1")
        self.assertGreater(r["rx_bps"], 0)        # rx changed
        self.assertEqual(r["tx_bps"], 0)          # tx unchanged


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

    def test_check_update_caches_state(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "x"}}})
        upd = {"ok": True, "update": {"installed": "7.23", "latest": "7.24", "status": "avail"}}
        with patch.object(ros, "action", return_value=upd):
            _req("POST", "/api/devices/r1/routeros/action", {"action": "check_update"}, self.tok)
            st, _ = _call(api.handle_device_routeros_action, "r1")
        self.assertEqual(st, 200)
        self.assertEqual(api.load(api.DEVICES_FILE)["r1"]["routeros_update"]["latest"], "7.24")

    def test_update_sweep_caches_state(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "x"}}})
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["last_routeros_update_check"] = 0
        api.save(api.CONFIG_FILE, cfg)
        with patch.object(ros, "action",
                          return_value={"ok": True, "update": {"installed": "7.23", "latest": "7.24"}}):
            api.run_routeros_update_check_if_due()
        self.assertEqual(api.load(api.DEVICES_FILE)["r1"]["routeros_update"]["latest"], "7.24")

    def test_patch_report_includes_routeros_firmware(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "reachability": "manual", "manual_status": True,
                 "routeros": {"enabled": True, "username": "rp", "password": "x"},
                 "routeros_update": {"installed": "7.23", "latest": "7.24", "last_checked": 1}}})
        _req("GET", "/api/patch-report", None, self.tok)
        st, body = _call(api.handle_patch_report)
        self.assertEqual(st, 200)
        row = next(d for d in body["devices"] if d["device_id"] == "r1")
        self.assertEqual(row["pkg_manager"], "routeros")
        self.assertEqual(row["upgradable"], 1)
        self.assertEqual(row["patch_status"], "patches_available")
        self.assertEqual(row["firmware"]["latest"], "7.24")

    def _enable_routeros(self):
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True,
                 "ip": "10.0.0.1", "routeros": {"enabled": True, "username": "rp",
                 "password": "x"}}})

    def test_firewall_endpoint(self):
        self._enable_routeros()
        with patch.object(ros, "firewall",
                          return_value={"filter": [{"chain": "input"}], "nat": [], "errors": {}}):
            _req("GET", "/api/devices/r1/routeros/firewall", None, self.tok)
            st, body = _call(api.handle_device_routeros_firewall, "r1")
        self.assertEqual(st, 200)
        self.assertTrue(body["enabled"])
        self.assertEqual(len(body["filter"]), 1)

    def test_add_rule_via_action_passes_rule(self):
        self._enable_routeros()
        with patch.object(ros, "action", return_value={"ok": True}) as act:
            _req("POST", "/api/devices/r1/routeros/action",
                 {"action": "add_firewall_rule", "rule": {"chain": "input", "action": "drop"}}, self.tok)
            st, _ = _call(api.handle_device_routeros_action, "r1")
        self.assertEqual(st, 200)
        self.assertEqual(act.call_args.kwargs.get("rule"), {"chain": "input", "action": "drop"})

    def test_firewall_blocked_when_not_enabled(self):
        # device exists but routeros not enabled -> action gate 403
        api.save(api.DEVICES_FILE, {"r1": {"name": "router", "agentless": True, "ip": "10.0.0.1"}})
        _req("POST", "/api/devices/r1/routeros/action",
             {"action": "add_firewall_rule", "rule": {"chain": "input", "action": "drop"}}, self.tok)
        st, _ = _call(api.handle_device_routeros_action, "r1")
        self.assertEqual(st, 403)

    def test_qos_endpoint(self):
        self._enable_routeros()
        with patch.object(ros, "qos",
                          return_value={"simple": [{"name": "q"}], "tree": [], "errors": {}}):
            _req("GET", "/api/devices/r1/routeros/qos", None, self.tok)
            st, body = _call(api.handle_device_routeros_qos, "r1")
        self.assertEqual(st, 200)
        self.assertTrue(body["enabled"])
        self.assertEqual(len(body["simple"]), 1)

    def test_traffic_endpoint(self):
        self._enable_routeros()
        with patch.object(ros, "traffic",
                          return_value=[{"name": "ether1", "rx_bps": 100, "tx_bps": 200}]):
            _req("GET", "/api/devices/r1/routeros/traffic", None, self.tok)
            st, body = _call(api.handle_device_routeros_traffic, "r1")
        self.assertEqual(st, 200)
        self.assertEqual(body["interfaces"][0]["rx_bps"], 100)


if __name__ == "__main__":
    unittest.main()
