#!/usr/bin/env python3
"""v3.4.0: OPNsense firewall REST client + endpoints.

Mirrors test_routeros.py: the REST client is tested with a mocked transport
(no real firewall), and the server handlers through the real admin-auth path
with opnsense.* mocked so no network is touched.
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
import opnsense as opn

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"
_spec = importlib.util.spec_from_file_location("api_opn", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


# ── REST client (mocked transport) ─────────────────────────────────────────
class TestOpnsenseClient(unittest.TestCase):
    def test_sanitize_filter_whitelists_and_normalises(self):
        r = opn._sanitize_rule({"action": "pass", "interface": "lan",
                                "source-net": "any", "log": True, "evil": "x"},
                               opn._FILTER_FIELDS)
        self.assertEqual(r["source_net"], "any")   # dash normalised
        self.assertEqual(r["log"], "1")            # bool -> "1"
        self.assertNotIn("evil", r)

    def test_sanitize_nat_allows_target(self):
        r = opn._sanitize_rule({"interface": "wan", "target": "1.2.3.4",
                                "target_port": "8080", "evil": "y"},
                               opn._NAT_FIELDS)
        self.assertEqual(r["target"], "1.2.3.4")
        self.assertEqual(r["target_port"], "8080")
        self.assertNotIn("evil", r)

    def test_uuid_validation(self):
        self.assertEqual(opn._validate_uuid("abcd-1234-EF"), "abcd-1234-EF")
        for bad in ("", "../etc", "a/b", "x" * 65):
            with self.assertRaises(opn.OPNsenseError):
                opn._validate_uuid(bad)

    def test_actions_registered(self):
        for a in ("add_filter_rule", "enable_filter_rule", "disable_filter_rule",
                  "delete_filter_rule", "add_nat_rule", "enable_nat_rule",
                  "disable_nat_rule", "delete_nat_rule"):
            self.assertIn(a, opn.ACTIONS)

    def test_add_filter_disabled_then_apply(self):
        calls = []

        def cap(host, k, s, method, path, body=None, **kw):
            calls.append((method, path, body))
            return {"result": "saved", "uuid": "u1"}
        with patch.object(opn, "_request", side_effect=cap):
            opn.action("h", "k", "s", "add_filter_rule",
                       rule={"action": "pass", "interface": "lan"})
        self.assertEqual(calls[0][0:2], ("POST", "/firewall/filter/addRule"))
        self.assertEqual(calls[0][2]["rule"]["enabled"], "0")     # lands disabled
        self.assertEqual(calls[1][0:2], ("POST", "/firewall/filter/apply"))

    def test_add_nat_targets_source_nat(self):
        calls = []

        def cap(host, k, s, method, path, body=None, **kw):
            calls.append((method, path, body))
            return {"result": "saved", "uuid": "u2"}
        with patch.object(opn, "_request", side_effect=cap):
            opn.action("h", "k", "s", "add_nat_rule",
                       rule={"interface": "wan", "target": "1.2.3.4"})
        self.assertEqual(calls[0][0:2], ("POST", "/firewall/source_nat/addRule"))

    def test_delete_and_toggle_paths(self):
        calls = []

        def cap(host, k, s, method, path, body=None, **kw):
            calls.append((method, path))
            return {}
        with patch.object(opn, "_request", side_effect=cap):
            opn.action("h", "k", "s", "delete_filter_rule", arg="aaaa-bbbb")
            opn.action("h", "k", "s", "enable_nat_rule", arg="cccc-dddd")
        self.assertIn(("POST", "/firewall/filter/delRule/aaaa-bbbb"), calls)
        self.assertIn(("POST", "/firewall/source_nat/toggleRule/cccc-dddd/1"), calls)

    def test_add_validation_failure_raises(self):
        def cap(host, k, s, method, path, body=None, **kw):
            return {"result": "failed", "validations": {"rule.interface": "required"}}
        with patch.object(opn, "_request", side_effect=cap):
            with self.assertRaises(opn.OPNsenseError):
                opn.action("h", "k", "s", "add_filter_rule", rule={"action": "pass"})

    def test_delete_requires_uuid(self):
        with self.assertRaises(opn.OPNsenseError):
            opn.action("h", "k", "s", "delete_nat_rule")

    def test_unknown_action_rejected(self):
        with self.assertRaises(opn.OPNsenseError):
            opn.action("h", "k", "s", "rm_rf")

    def test_system_actions_registered_and_routed(self):
        for a in ("reboot", "check_update", "upgrade"):
            self.assertIn(a, opn.ACTIONS)
        calls = []

        def cap(host, k, s, method, path, body=None, **kw):
            calls.append((method, path))
            return {"product_version": "OPNsense 24.1", "status": "update",
                    "new_packages": [1, 2]}
        with patch.object(opn, "_request", side_effect=cap):
            self.assertEqual(opn.action("h", "k", "s", "reboot"), {"ok": True})
            r = opn.action("h", "k", "s", "check_update")
            opn.action("h", "k", "s", "upgrade")
        self.assertIn(("POST", "/core/system/reboot"), calls)
        self.assertIn(("POST", "/core/firmware/check"), calls)
        self.assertIn(("POST", "/core/firmware/upgrade"), calls)
        self.assertEqual(r["update"]["updates_available"], 2)

    def test_probe_fails_fast_on_unreachable(self):
        with self.assertRaises(opn.OPNsenseError):
            opn._probe("203.0.113.250:443", timeout=1)

    def test_firewall_parses_and_normalises(self):
        def cap(host, k, s, method, path, body=None, **kw):
            if "filter/searchRule" in path:
                return {"rows": [{"uuid": "u1", "enabled": "1", "action": "pass",
                                  "interface": "lan", "source_net": "any",
                                  "destination_net": "10.0.0.0/24", "protocol": "TCP",
                                  "destination_port": "443", "description": "web"}]}
            if "source_nat/searchRule" in path:
                return {"rows": [{"uuid": "u2", "enabled": "0", "interface": "wan",
                                  "target": "1.1.1.1", "target_port": "80",
                                  "source_net": "192.168.1.0/24"}]}
            return {}
        with patch.object(opn, "_request", side_effect=cap), \
             patch.object(opn, "_probe", return_value=True):
            fw = opn.firewall("h", "k", "s")
        self.assertEqual(fw["filter"][0]["id"], "u1")
        self.assertFalse(fw["filter"][0]["disabled"])
        self.assertEqual(fw["filter"][0]["dst_address"], "10.0.0.0/24")
        self.assertTrue(fw["nat"][0]["disabled"])          # enabled "0"
        self.assertEqual(fw["nat"][0]["to_addresses"], "1.1.1.1")


# ── server handlers (real auth, mocked opnsense) ───────────────────────────
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


class TestOpnsenseHandlers(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.TOKENS_FILE):
            api.save(f, {})
        self.tok = _admin()
        api.save(api.DEVICES_FILE, {"o1": {"name": "fw", "agentless": True,
                                           "ip": "10.0.0.1"}})

    def test_target_and_redacted(self):
        dev = {"ip": "10.0.0.1", "opnsense": {"enabled": True, "api_key": "K",
               "api_secret": "S", "port": 443}}
        self.assertEqual(api._opnsense_target(dev), ("10.0.0.1:443", "K", "S", False))
        red = api._opnsense_redacted(dev)
        self.assertTrue(red["has_secret"])
        self.assertNotIn("api_secret", red)

    def test_enable_requires_credentials(self):
        _req("PATCH", "/api/devices/o1/opnsense", {"enabled": True}, self.tok)
        st, _ = _call(api.handle_device_opnsense, "o1")
        self.assertEqual(st, 400)

    def test_save_config_redacts_secret(self):
        _req("PATCH", "/api/devices/o1/opnsense",
             {"enabled": True, "api_key": "KEY", "api_secret": "SEC", "port": 8443},
             self.tok)
        st, body = _call(api.handle_device_opnsense, "o1")
        self.assertEqual(st, 200)
        self.assertTrue(body["config"]["has_secret"])
        self.assertEqual(body["config"]["api_key"], "KEY")
        self.assertNotIn("api_secret", body["config"])
        stored = api.load(api.DEVICES_FILE)["o1"]["opnsense"]
        self.assertEqual(stored["api_secret"], "SEC")
        self.assertEqual(stored["port"], 8443)

    def test_empty_secret_preserves(self):
        api.save(api.DEVICES_FILE, {"o1": {"name": "fw", "agentless": True,
                 "ip": "10.0.0.1", "opnsense": {"enabled": True, "api_key": "K",
                 "api_secret": "keepme"}}})
        _req("PATCH", "/api/devices/o1/opnsense", {"api_secret": ""}, self.tok)
        _call(api.handle_device_opnsense, "o1")
        self.assertEqual(api.load(api.DEVICES_FILE)["o1"]["opnsense"]["api_secret"], "keepme")

    def test_firewall_endpoint(self):
        api.save(api.DEVICES_FILE, {"o1": {"name": "fw", "agentless": True,
                 "ip": "10.0.0.1", "opnsense": {"enabled": True, "api_key": "K",
                 "api_secret": "S"}}})
        _req("GET", "/api/devices/o1/opnsense/firewall", None, self.tok)
        with patch.object(opn, "firewall", return_value={"filter": [{"id": "u1"}], "nat": []}):
            st, body = _call(api.handle_device_opnsense_firewall, "o1")
        self.assertEqual(st, 200)
        self.assertTrue(body["enabled"])
        self.assertEqual(body["filter"][0]["id"], "u1")

    def test_check_update_caches_for_patch_report(self):
        api.save(api.DEVICES_FILE, {"o1": {"name": "fw", "agentless": True,
                 "ip": "10.0.0.1", "opnsense": {"enabled": True, "api_key": "K",
                 "api_secret": "S"}}})
        _req("POST", "/api/devices/o1/opnsense/action", {"action": "check_update"}, self.tok)
        upd = {"version": "26.1.8_5", "latest": "26.1.8", "updates_available": 0,
               "needs_reboot": False, "status": "none"}
        with patch.object(opn, "action", return_value={"ok": True, "update": upd}):
            st, _ = _call(api.handle_device_opnsense_action, "o1")
        self.assertEqual(st, 200)
        cached = api.load(api.DEVICES_FILE)["o1"].get("opnsense_update")
        self.assertEqual(cached["installed"], "26.1.8_5")
        self.assertEqual(cached["updates_available"], 0)

    def test_patch_report_includes_opnsense(self):
        api.save(api.DEVICES_FILE, {"o1": {
            "name": "fw", "agentless": True, "ip": "10.0.0.1", "manual_status": True,
            "opnsense": {"enabled": True, "api_key": "K", "api_secret": "S"},
            "opnsense_update": {"installed": "26.1.8_5", "latest": "26.1.8",
                                "updates_available": 0, "status": "none"}}})
        _req("GET", "/api/patch-report", None, self.tok)
        st, body = _call(api.handle_patch_report)
        self.assertEqual(st, 200)
        row = next(d for d in body["devices"] if d["device_id"] == "o1")
        self.assertEqual(row["pkg_manager"], "opnsense")
        self.assertEqual(row["upgradable"], 0)
        self.assertEqual(row["patch_status"], "fully_patched")   # not "no_data"
        self.assertEqual(row["firmware"]["installed"], "26.1.8_5")

    def test_action_admin_and_unknown(self):
        api.save(api.DEVICES_FILE, {"o1": {"name": "fw", "agentless": True,
                 "ip": "10.0.0.1", "opnsense": {"enabled": True, "api_key": "K",
                 "api_secret": "S"}}})
        _req("POST", "/api/devices/o1/opnsense/action",
             {"action": "add_filter_rule", "rule": {"action": "pass", "interface": "lan"}},
             self.tok)
        with patch.object(opn, "action", return_value={"ok": True}):
            st, body = _call(api.handle_device_opnsense_action, "o1")
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        # unknown action rejected before reaching the lib
        _req("POST", "/api/devices/o1/opnsense/action", {"action": "rm_rf"}, self.tok)
        st, _ = _call(api.handle_device_opnsense_action, "o1")
        self.assertEqual(st, 400)


if __name__ == "__main__":
    unittest.main()
