#!/usr/bin/env python3
"""A pending confirmation is a command waiting for a second administrator, and approving it runs the command.

An API key can carry a device scope, and the scope confines even an administrator's key: it is how a service account is given part of
the fleet. The four routes of the confirmation ledger (list, approve, reject, clear) checked the tenant of a confirmation's host and
not the scope of the key, so a key that could reach the web servers only could list a confirmation for a database host, approve it
(which queued the command on that host) and reject it, and clear its history. Found while counting the handlers that read the fleet
and name no helper that folds the caller's scope (the same gap as the smart-group routes of this release).

What this holds, with real keys through the real route table, the real request gates and the real token check (a process of its own on
a data directory of its own, so that nothing is stubbed):

* a key with a device scope lists, approves, rejects and clears the confirmations of the hosts in its scope, and for a host outside it
  gets the answer a tenant gets for another tenant's host (404, so that the id is not confirmed to exist) and changes nothing: no
  command is queued, the confirmation stays pending, its history is not cleared;
* the other direction: a key with no scope still does all four, and a key with a scope still does them for its own hosts;
* the helper that decides it, over both of its legs (the tenant and the scope);
* a ratchet over every route of the ledger, by syntax tree: a handler that touches the ledger has to call the helper.
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
import json, os, sys, time
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
client = wsgi.application.test_client()
now = int(time.time())


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


put("CONFIG_FILE", {})
put("USERS_FILE", {"alice": {"role": "admin", "tenant_id": "default", "created": 1}})
put("DEVICES_FILE", {
    "web1": {"name": "web-one", "group": "web", "os": "Debian 12", "monitored": True, "last_seen": now},
    "db1": {"name": "db-payroll", "group": "db", "os": "Debian 12", "monitored": True, "last_seen": now}})
key = lambda token, user, **extra: dict({"name": token, "key_hash": api._apikey_hash(token), "user": user, "role": "admin", "active": True,
                                         "created": 1}, **extra)
put("APIKEYS_FILE", {"k1": key("SCOPED", "svc", scope={"type": "groups", "values": ["web"]}), "k2": key("PLAIN", "boss")})


def row(cid, dev, status="pending"):
    return {"id": cid, "action": "reboot_device", "device_id": dev, "params": {}, "requested_by": "alice", "requested_at": now,
            "ai_host": None, "ai_prompt": None, "reason": None, "ticket_ref": None, "status": status,
            "decided_by": None if status == "pending" else "alice", "decided_at": None if status == "pending" else now}


put("CONFIRMATIONS_FILE", {"confirmations": [row("cf_web", "web1"), row("cf_db", "db1"), row("cf_db2", "db1"),
                                              row("cf_old_web", "web1", "approved"), row("cf_old_db", "db1", "rejected")]})


def call(method, path, token):
    r = getattr(client, method.lower())(path, headers={"X-Token": token})
    return [r.status_code, json.loads(r.data.decode() or "null")]


def state():
    api._invalidate_load_cache(api.CONFIRMATIONS_FILE)
    api._invalidate_load_cache(api.CMDS_FILE)
    rows = (api.load(api.CONFIRMATIONS_FILE) or {}).get("confirmations", [])
    return {"status": {c["id"]: c["status"] for c in rows}, "queued": api.load(api.CMDS_FILE) or {}}


ids = lambda res: sorted(c["id"] for c in res[1]["confirmations"])
out = {}
out["scoped_list"] = ids(call("GET", "/api/confirmations", "SCOPED"))
out["plain_list"] = ids(call("GET", "/api/confirmations", "PLAIN"))
out["scoped_approve_out"] = call("POST", "/api/confirmations/cf_db/approve", "SCOPED")
out["scoped_reject_out"] = call("POST", "/api/confirmations/cf_db2/reject", "SCOPED")
out["after_out_of_scope"] = state()
out["scoped_approve_in"] = call("POST", "/api/confirmations/cf_web/approve", "SCOPED")
out["after_in_scope"] = state()
out["scoped_clear"] = call("DELETE", "/api/confirmations", "SCOPED")
out["after_scoped_clear"] = state()
out["plain_approve"] = call("POST", "/api/confirmations/cf_db/approve", "PLAIN")
out["plain_reject"] = call("POST", "/api/confirmations/cf_db2/reject", "PLAIN")
out["after_plain"] = state()
out["plain_clear"] = call("DELETE", "/api/confirmations", "PLAIN")
out["after_plain_clear"] = state()
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-confscope-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_STACK_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_ROOT / "server" / "cgi-bin")], capture_output=True, text=True,
                              env=dict(os.environ, RP_DATA_DIR=str(data)), timeout=300)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-1500:])
        cls.out = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_the_list_holds_the_confirmations_of_the_hosts_in_reach(self):
        self.assertEqual(self.out["scoped_list"], ["cf_old_web", "cf_web"],
                         "a key scoped to the web servers was shown a database host's confirmations")
        self.assertEqual(self.out["plain_list"], ["cf_db", "cf_db2", "cf_old_db", "cf_old_web", "cf_web"],
                         "control: the confirmations are in the ledger")

    def test_a_confirmation_for_a_host_outside_the_scope_cannot_be_approved_or_rejected(self):
        for name in ("scoped_approve_out", "scoped_reject_out"):
            self.assertEqual(self.out[name], [404, {"error": "confirmation not found"}], name)
        after = self.out["after_out_of_scope"]
        self.assertEqual(after["queued"], {}, "a command was queued on a host outside the key's scope")
        self.assertEqual((after["status"]["cf_db"], after["status"]["cf_db2"]), ("pending", "pending"))

    def test_the_other_direction_a_confirmation_in_scope_is_approved_and_runs(self):
        self.assertEqual(self.out["scoped_approve_in"][0], 200, self.out["scoped_approve_in"])
        after = self.out["after_in_scope"]
        self.assertEqual(after["status"]["cf_web"], "approved")
        self.assertEqual(after["queued"], {"web1": ["reboot"]})

    def test_clear_removes_the_resolved_entries_in_reach_and_keeps_the_rest(self):
        self.assertEqual(self.out["scoped_clear"], [200, {"ok": True, "removed": 2}], "cf_old_web and the approved cf_web are in reach")
        left = self.out["after_scoped_clear"]["status"]
        self.assertEqual(sorted(left), ["cf_db", "cf_db2", "cf_old_db"], "a database host's resolved history was cleared by a web key")

    def test_a_key_with_no_scope_still_decides_every_confirmation_and_clears_what_is_resolved(self):
        self.assertEqual(self.out["plain_approve"][0], 200, self.out["plain_approve"])
        self.assertEqual(self.out["plain_reject"], [200, {"ok": True}])
        after = self.out["after_plain"]
        self.assertEqual((after["status"]["cf_db"], after["status"]["cf_db2"]), ("approved", "rejected"))
        self.assertEqual(after["queued"], {"web1": ["reboot"], "db1": ["reboot"]})
        self.assertEqual(self.out["plain_clear"][0:1], [200])
        self.assertEqual(sorted(self.out["after_plain_clear"]["status"]), [], "control: everything left was resolved and is cleared")


class TestTheHelper(unittest.TestCase):

    def setUp(self):
        self._tv = api._tenant_visible

    def tearDown(self):
        api._tenant_visible = self._tv

    def test_both_legs_have_to_pass(self):
        row, hosts = {"device_id": "a"}, {"a": {"tenant": "acme"}}
        api._tenant_visible = lambda dev: True
        self.assertTrue(api._confirmation_in_reach(row, hosts, None), "nothing confines the caller")
        self.assertTrue(api._confirmation_in_reach(row, hosts, {"a", "b"}), "the host is in the caller's scope")
        self.assertFalse(api._confirmation_in_reach(row, hosts, {"b"}), "the host is outside the caller's scope")
        self.assertFalse(api._confirmation_in_reach(row, hosts, set()), "the caller can see no host")
        api._tenant_visible = lambda dev: False
        self.assertFalse(api._confirmation_in_reach(row, hosts, None), "another tenant's host")
        self.assertFalse(api._confirmation_in_reach(row, hosts, {"a"}), "another tenant's host, whatever the scope says")

    def test_a_confirmation_for_a_host_that_is_gone(self):
        row = {"device_id": "gone"}
        api._tenant_visible = lambda dev: True
        self.assertTrue(api._confirmation_in_reach(row, {}, None), "a caller nothing confines still sees it, as before")
        self.assertFalse(api._confirmation_in_reach(row, {}, {"a"}), "a caller with a scope has no host to show it by")


def _ledger():
    """{handler name: source} of every handler a /api/confirmations route reaches, found the way the application finds its handlers."""
    out = {}
    for (_m, path), fn in api._build_exact_routes().items():
        if path.startswith("/api/confirmations"):
            out[fn.__name__] = inspect.getsource(fn)
    for kind, _methods, a, b, name, _src in api._PATTERN_ROUTE_DEFS:
        path = a if kind == "eq" else a + "{}" + b if kind == "pat" else ""
        if path.startswith("/api/confirmations"):
            out[name] = inspect.getsource(getattr(api, name))
    return out


class TestEveryRouteOfTheLedgerDecidesByReach(unittest.TestCase):
    """The tenant check was added to the four routes by a sweep, and the scope check was in none of them: a rule applied in the helper
    of one family and missed in another is found by listing every site, so this lists them."""

    def test_the_scan_sees_the_ledger(self):
        self.assertEqual(sorted(_ledger()), ["handle_confirmation_approve", "handle_confirmation_reject", "handle_confirmations_clear",
                                             "handle_confirmations_list"])

    def test_every_handler_that_touches_the_ledger_calls_the_helper_and_reads_the_callers_reach(self):
        sources = _ledger()
        self.assertEqual(keyscope_scan.unconfined(sources, ("_confirmation_in_reach",), reads=("CONFIRMATIONS_FILE",)), [],
                         "a confirmation route decides without _confirmation_in_reach: a key with a device scope would run a command "
                         "on a host outside its scope")
        self.assertEqual(keyscope_scan.unconfined(sources, ("_confined_host_ids",), reads=("CONFIRMATIONS_FILE",)), [],
                         "a confirmation route does not ask for the hosts the caller can see")

    def test_control_the_scan_finds_a_handler_that_does_not(self):
        old = inspect.getsource(api.handle_confirmation_approve).replace(
            "_confirmation_in_reach(entry, load(DEVICES_FILE) or {}, visible)", "_tenant_visible(load(DEVICES_FILE) or {})")
        self.assertNotEqual(old, inspect.getsource(api.handle_confirmation_approve), "the anchor did not match")
        self.assertEqual(keyscope_scan.unconfined({"handle_confirmation_approve": old}, ("_confirmation_in_reach",),
                                                  reads=("CONFIRMATIONS_FILE",)), ["handle_confirmation_approve"])
        comment = "def handle_x():\n    # _confirmation_in_reach(c, d, v)\n    return load(CONFIRMATIONS_FILE)\n"
        self.assertEqual(keyscope_scan.unconfined({"x": comment}, ("_confirmation_in_reach",), reads=("CONFIRMATIONS_FILE",)), ["x"])


if __name__ == "__main__":
    unittest.main()
