#!/usr/bin/env python3
"""An inbound token pinned to a host belongs to whoever may see that host.

An API key can carry a device scope, and the scope confines even an administrator's key. Creating a token, or pinning one to a host,
already refuses a host outside the scope (`_scope_block_device`). The list, the edit and the revoke asked only for the tenant, so a key
that could reach the web servers only read a database host's name and address from the table of tokens, switched that host's
ingest off and deleted its token. Found with the confirmation ledger and the smart-group routes, while counting the handlers that
read the fleet and call no helper that folds the caller's scope.

With real keys, through the real route table and the real token check (a process of its own on a data directory of its own):

* a key with a device scope lists, switches off and revokes the tokens pinned to its own hosts, and for a token pinned to a host
  outside the scope gets what another tenant's token gets (404) and changes nothing; the table does not show it, and with it goes the
  host's name and address;
* the other direction: a key with no scope still manages every token, and a token with no pin (it attributes by tag or by payload
  across the fleet) is shown to a scoped key as it always was;
* a ratchet over every route of the table of tokens, by syntax tree.
"""
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyscope_scan  # noqa: E402
import routing_harness  # noqa: E402  (imports the api module from server/cgi-bin)

api = routing_harness.api
_ROOT = Path(__file__).resolve().parent.parent
_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_STACK_DRIVER = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
client = wsgi.application.test_client()


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


put("CONFIG_FILE", {})
put("USERS_FILE", {"alice": {"role": "admin", "tenant_id": "default", "created": 1}})
put("DEVICES_FILE", {
    "web1": {"name": "web-one", "group": "web", "ip": "10.0.0.1", "os": "Debian 12", "monitored": True},
    "db1": {"name": "db-payroll", "group": "db", "ip": "10.9.9.9", "os": "Debian 12", "monitored": True}})
key = lambda token, user, **extra: dict({"name": token, "key_hash": api._apikey_hash(token), "user": user, "role": "admin", "active": True,
                                         "created": 1}, **extra)
put("APIKEYS_FILE", {"k1": key("SCOPED", "svc", scope={"type": "groups", "values": ["web"]}), "k2": key("PLAIN", "boss")})
tok = lambda tid, dev, **extra: dict({"id": tid, "label": tid, "token": tid * 8, "kind": "syslog", "source_format": "auto",
                                      "scope_device_id": dev, "scope_tag": None, "enabled": True, "created_by": "alice",
                                      "created_at": 1, "last_seen": None, "hit_count": 0}, **extra)
put("INBOUND_WEBHOOKS_FILE", {"tokens": [tok("iwh_web", "web1"), tok("iwh_db", "db1"), tok("iwh_fleet", None, kind="alert", scope_tag="prod")]})


def call(method, path, token, body=None):
    kw = {"headers": {"X-Token": token}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(client, method.lower())(path, **kw)
    return [r.status_code, json.loads(r.data.decode() or "null")]


def state():
    api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)
    return {t["id"]: t["enabled"] for t in (api.load(api.INBOUND_WEBHOOKS_FILE) or {}).get("tokens", [])}


out = {}
out["scoped_list"] = call("GET", "/api/inbound-webhooks", "SCOPED")
out["plain_list"] = call("GET", "/api/inbound-webhooks", "PLAIN")
out["scoped_toggle_out"] = call("PATCH", "/api/inbound-webhooks/iwh_db", "SCOPED", {"enabled": False})
out["scoped_revoke_out"] = call("DELETE", "/api/inbound-webhooks/iwh_db", "SCOPED")
out["after_out_of_scope"] = state()
out["scoped_toggle_in"] = call("PATCH", "/api/inbound-webhooks/iwh_web", "SCOPED", {"enabled": False})
out["after_toggle_in"] = state()
out["scoped_revoke_in"] = call("DELETE", "/api/inbound-webhooks/iwh_web", "SCOPED")
out["after_revoke_in"] = state()
out["plain_toggle"] = call("PATCH", "/api/inbound-webhooks/iwh_db", "PLAIN", {"enabled": False})
out["after_plain_toggle"] = state()
out["plain_revoke"] = call("DELETE", "/api/inbound-webhooks/iwh_db", "PLAIN")
out["after_plain_revoke"] = state()
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-inboundscope-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_STACK_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_ROOT / "server" / "cgi-bin")], capture_output=True, text=True,
                              env=dict(os.environ, RP_DATA_DIR=str(data)), timeout=300)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-1500:])
        cls.out = json.loads(proc.stdout.strip().splitlines()[-1])

    @staticmethod
    def ids(res):
        return sorted(t["id"] for t in res[1]["tokens"])

    def test_the_table_holds_the_tokens_of_hosts_in_reach_and_not_a_hosts_name_outside_it(self):
        self.assertEqual(self.out["scoped_list"][0], 200)
        self.assertEqual(self.ids(self.out["scoped_list"]), ["iwh_fleet", "iwh_web"], "a token pinned to a database host was listed")
        text = json.dumps(self.out["scoped_list"])
        for word in ("db-payroll", "10.9.9.9", "iwh_db"):
            self.assertNotIn(word, text, "the table told a web key about the database host")
        self.assertEqual(self.ids(self.out["plain_list"]), ["iwh_db", "iwh_fleet", "iwh_web"], "control: the tokens are in the store")
        self.assertIn("db-payroll", json.dumps(self.out["plain_list"]), "control: the name is what the table shows for a pinned token")

    def test_a_token_pinned_outside_the_scope_cannot_be_switched_off_or_deleted(self):
        for name in ("scoped_toggle_out", "scoped_revoke_out"):
            self.assertEqual(self.out[name], [404, {"error": "token not found"}], name)
        self.assertEqual(self.out["after_out_of_scope"], {"iwh_web": True, "iwh_db": True, "iwh_fleet": True},
                         "a database host's ingest was changed by a key scoped to the web servers")

    def test_the_other_direction_a_token_in_scope_is_switched_off_and_deleted(self):
        self.assertEqual(self.out["scoped_toggle_in"], [200, {"ok": True}])
        self.assertEqual(self.out["after_toggle_in"]["iwh_web"], False)
        self.assertEqual(self.out["scoped_revoke_in"], [200, {"ok": True}])
        self.assertEqual(sorted(self.out["after_revoke_in"]), ["iwh_db", "iwh_fleet"])

    def test_a_key_with_no_scope_still_manages_every_token(self):
        self.assertEqual(self.out["plain_toggle"], [200, {"ok": True}])
        self.assertEqual(self.out["after_plain_toggle"]["iwh_db"], False)
        self.assertEqual(self.out["plain_revoke"], [200, {"ok": True}])
        self.assertEqual(sorted(self.out["after_plain_revoke"]), ["iwh_fleet"])


class TestTheHelper(unittest.TestCase):

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in ("_caller_scope", "_tenant_gate", "_tenant_visible", "device_get")}
        api.device_get = lambda did: {"web1": {"group": "web"}, "db1": {"group": "db"}}.get(did)
        api._tenant_gate = lambda: None

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def test_a_pinned_token_follows_the_scope_and_an_unpinned_one_does_not(self):
        pinned_web, pinned_db, unpinned, gone = ({"scope_device_id": "web1"}, {"scope_device_id": "db1"}, {"scope_device_id": None},
                                                 {"scope_device_id": "gone"})
        api._caller_scope = lambda: None
        self.assertTrue(all(api._inbound_token_visible(t) for t in (pinned_web, pinned_db, unpinned, gone)), "nothing confines the caller")
        api._caller_scope = lambda: {"type": "groups", "values": ["web"]}
        self.assertEqual([api._inbound_token_visible(t) for t in (pinned_web, pinned_db, unpinned, gone)], [True, False, True, False])

    def test_the_tenant_leg_is_still_there_under_a_scope(self):
        api._caller_scope = lambda: {"type": "groups", "values": ["web"]}
        api._tenant_gate = lambda: "acme"
        api._tenant_visible = lambda dev: False
        self.assertFalse(api._inbound_token_visible({"scope_device_id": "web1"}), "another tenant's host, whatever the scope says")
        self.assertFalse(api._inbound_token_visible({"scope_device_id": None}), "an unpinned token is the platform operator's under tenancy")
        api._tenant_visible = lambda dev: True
        self.assertTrue(api._inbound_token_visible({"scope_device_id": "web1"}))


def _table():
    """{handler name: source} of every handler an /api/inbound-webhooks route reaches (the receiver at /api/webhook/in/<token>
    authenticates by the token itself and is another family)."""
    out = {}
    for (_m, path), fn in api._build_exact_routes().items():
        if path.startswith("/api/inbound-webhooks"):
            out[fn.__name__] = inspect.getsource(fn)
    for kind, _methods, a, b, name, _src in api._PATTERN_ROUTE_DEFS:
        path = a if kind == "eq" else a + "{}" + b if kind == "pat" else ""
        if path.startswith("/api/inbound-webhooks"):
            out[name] = inspect.getsource(getattr(api, name))
    return out


class TestEveryRouteOfTheTableOfTokensDecidesByReach(unittest.TestCase):

    AWARE = ("_inbound_token_visible", "_inbound_tokens_visible_ids", "_scope_block_device")

    def test_the_scan_sees_the_table(self):
        self.assertEqual(sorted(_table()), ["handle_inbound_webhook_revoke", "handle_inbound_webhook_toggle",
                                            "handle_inbound_webhooks_create", "handle_inbound_webhooks_list"])

    def test_every_handler_that_touches_the_tokens_asks_who_may_see_them(self):
        self.assertEqual(keyscope_scan.unconfined(_table(), self.AWARE, reads=("INBOUND_WEBHOOKS_FILE",)), [],
                         "a route of the table of tokens decides without the visibility helper or the pin check")

    def test_the_helper_folds_the_scope_and_the_tenant(self):
        calls, _reads = keyscope_scan.facts(inspect.getsource(api._inbound_token_visible))
        self.assertTrue({"_caller_scope", "_device_in_scope", "_tenant_gate", "_tenant_visible"} <= calls, sorted(calls))

    def test_control_the_scan_finds_a_handler_that_does_not(self):
        src = inspect.getsource(api.handle_inbound_webhooks_list)
        old = src.replace("_inbound_token_visible(t)", "True")
        self.assertNotEqual(old, src, "the anchor did not match")
        self.assertEqual(keyscope_scan.unconfined({"handle_inbound_webhooks_list": old}, self.AWARE, reads=("INBOUND_WEBHOOKS_FILE",)),
                         ["handle_inbound_webhooks_list"])


if __name__ == "__main__":
    unittest.main()
