#!/usr/bin/env python3
"""Look at a smart group's members before saving it: POST /api/smart-groups/preview.

A smart group is a saved rule whose members are worked out from the fleet, and the only way to learn what a rule matched was to
save the group and open its member list. The preview takes the rules of the editor as they stand and answers with how many hosts
they match and the first 50 of them (id and display name), and changes nothing.

It has no matcher of its own. The count and the names come from `_materialize_smart_group`, the function a saved group's members
are worked out with, and the rules go through the validation a save applies. This module drives the real handler, with only the
token lookup stubbed (a stub of `require_admin_auth` passes a handler that has no gate), and holds:

* the shapes the brief names: an empty rule, a rule that matches every host, a rule that matches none, the cap of 50 over 120
  hosts, an invalid rule, a tenant administrator who must not see, or count, another tenant's hosts;
* an API key with a device scope, which confines even an administrator's key: the preview, the list of groups (counts, and ids with
  ?members=1) and a group's members answer over the hosts of the scope and no others, with real keys through the real token check and
  once more through the real route table, and a ratchet over every route of the family so that the next one cannot read hosts
  without it;
* that the preview and a saved group agree: for each rule the same count and the same members, in the same order, whether the
  group is created or edited, over a fleet under the cap and over one past it;
* the gate (administrators only, as viewing the groups is), that the call changes nothing (no store written, no audit line), that a
  body naming hosts, a tenant or a scope is not read for them, and that the work is bounded: the conditions are capped as a save
  caps them and every host is looked at once;
* the route: it resolves to the handler, the other smart-group routes are where they were, and the OpenAPI document describes it;
* the editor: the button and the box, and the real page functions run in V8 against a stand-in for the page: the rules the preview
  sends are the rules a save sends, names and ids are escaped, an error is shown as text, an answer that comes back after a rule
  changed is dropped, and the six languages are there.
"""
import ast
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _jsload_harness  # noqa: E402
import browser_required  # noqa: E402
import routing_harness  # noqa: E402  (imports the api module from server/cgi-bin)
import srcpin  # noqa: E402
from i18n_engine import dict_rows  # noqa: E402

api = routing_harness.api
_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js"
_NODE = shutil.which("node")
_GATE_NODE = bool(_NODE) or browser_required.required()
_TMP = []


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)

FILES = ("DEVICES_FILE", "SMART_GROUPS_FILE", "USERS_FILE", "TENANTS_FILE", "CONFIG_FILE", "ROLES_FILE", "AUDIT_LOG_FILE",
         "DRIFT_STATE_FILE", "APIKEYS_FILE", "TOKENS_FILE")
STUBS = ("verify_token", "get_token_from_request", "method", "get_json_body", "respond", "audit_log", "_env")


class _Base(unittest.TestCase):
    """Drive the real handlers on a throwaway store. Only the token lookup is stubbed, so the gate under test is the real one."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-sgprev-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self._files = {n: getattr(api, n) for n in FILES}
        for n, old in self._files.items():
            setattr(api, n, self.d / Path(old).name)              # the basename is the storage key on SQLite and Postgres
        self._stubs = {n: getattr(api, n) for n in STUBS}
        self.who = ("jakob", "admin")
        self.audit = []
        self.http_method = "POST"
        self.body = {}
        self.cap = {}
        api.verify_token = lambda token: self.who
        api.get_token_from_request = lambda: "t"
        api.method = lambda: self.http_method
        api.get_json_body = lambda: self.body
        api.audit_log = lambda *a, **k: self.audit.append((a, k))
        self.qs = ""
        api._env = lambda key, default=None: self.qs if key == "QUERY_STRING" else self._stubs["_env"](key, default)

        def _respond(status, body=None):
            self.cap["status"], self.cap["body"] = status, body
            raise api.HTTPError(status, body)

        api.respond = _respond
        api._begin_request()
        self.put("USERS_FILE", {"jakob": {"role": "admin", "created": 1}, "bob": {"role": "viewer", "created": 1}})
        self.put("CONFIG_FILE", {})
        self.put("DEVICES_FILE", {})

    def tearDown(self):
        for n, v in self._stubs.items():
            setattr(api, n, v)
        for n, v in self._files.items():
            setattr(api, n, v)
        api._begin_request()

    def put(self, attr, data):
        api.save(getattr(api, attr), data)
        api._invalidate_load_cache(getattr(api, attr))

    def read(self, attr):
        api._invalidate_load_cache(getattr(api, attr))
        return api.load(getattr(api, attr)) or {}

    def call(self, fn, *args, method="POST", body=None):
        self.cap = {}
        self.http_method = method
        self.body = {} if body is None else body
        try:
            fn(*args)
        except api.HTTPError:
            pass
        return self.cap.get("status"), self.cap.get("body")

    def preview(self, rules, **extra):
        return self.call(api.handle_smart_group_preview, body=dict({"rules": rules}, **extra))

    def create(self, name, rules):
        status, body = self.call(api.handle_smart_groups, body={"name": name, "rules": rules})
        self.assertEqual(status, 201, body)
        return (self.read("SMART_GROUPS_FILE")[name] or {}).get("members")

    @staticmethod
    def fleet(n, **over):
        """n hosts, h000 ... : one group, one tag, memory climbing with the number, every fifth host unmonitored and every tenth
        carrying a second tag. The names are `host-000`."""
        out = {}
        for i in range(n):
            rec = {"name": "host-%03d" % i, "group": "web" if i % 3 else "db", "tags": ["prod"] + (["edge"] if i % 10 == 0 else []),
                   "os": "Debian 12" if i % 2 else "Ubuntu 24.04", "monitored": i % 5 != 0,
                   "sysinfo": {"mem_percent": float(i % 100), "disk": 1}}
            rec.update(over)
            out["h%03d" % i] = rec
        return out

    def two_tenants(self):
        self.put("TENANTS_FILE", {"default": {"name": "Default", "builtin": True}, "acme": {"name": "Acme", "status": "active"}})
        self.put("USERS_FILE", {"jakob": {"role": "admin", "tenant_id": "default"}, "acmeadmin": {"role": "admin", "tenant_id": "acme"},
                                "bob": {"role": "viewer", "tenant_id": "default"}})
        self.put("CONFIG_FILE", {"tenancy_enforced": True})


class TestTheShapesTheBriefNames(_Base):

    def test_an_empty_rule_is_refused_as_a_save_refuses_it(self):
        status, body = self.preview({})
        self.assertEqual((status, body), (400, {"error": "at least one rule is required"}))
        saved, saved_body = self.call(api.handle_smart_groups, body={"name": "x", "rules": {}})
        self.assertEqual((status, body), (saved, saved_body), "the same status and the same words as the save")

    def test_a_rule_that_matches_every_host(self):
        self.put("DEVICES_FILE", self.fleet(30, monitored=True))
        status, body = self.preview({"monitored": True})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["count"], 30)
        self.assertEqual([h["id"] for h in body["hosts"]], ["h%03d" % i for i in range(30)])
        self.assertEqual(body["hosts"][0], {"id": "h000", "name": "host-000"})

    def test_a_rule_that_matches_none(self):
        self.put("DEVICES_FILE", self.fleet(30))
        status, body = self.preview({"group": "no-such-group"})
        self.assertEqual((status, body), (200, {"count": 0, "limit": 50, "hosts": []}))

    def test_the_names_are_capped_at_50_and_the_count_is_not(self):
        self.put("DEVICES_FILE", self.fleet(120, monitored=True))
        status, body = self.preview({"monitored": True})
        self.assertEqual(status, 200)
        self.assertEqual((body["count"], body["limit"], len(body["hosts"])), (120, 50, 50))
        self.assertEqual([h["id"] for h in body["hosts"]], ["h%03d" % i for i in range(50)], "the first 50, in the order a saved group lists")

    def test_exactly_at_the_cap_and_one_past_it(self):
        for n, shown in ((49, 49), (50, 50), (51, 50)):
            with self.subTest(hosts=n):
                self.put("DEVICES_FILE", self.fleet(n, monitored=True))
                _status, body = self.preview({"monitored": True})
                self.assertEqual((body["count"], len(body["hosts"])), (n, shown))

    def test_an_invalid_rule_is_refused_with_the_words_of_the_save(self):
        for rules in ({"mem_gt": "lots"}, {"disk_gt": "x", "group": "web"}, {"cpu_gt": [1]}, {"swap_gt": {"a": 1}}):
            with self.subTest(rules=rules):
                status, body = self.preview(rules)
                saved, saved_body = self.call(api.handle_smart_groups, body={"name": "bad", "rules": rules})
                self.assertEqual(status, 400, body)
                self.assertEqual((status, body), (saved, saved_body))
                self.assertRegex(body["error"], r"must be a number")

    def test_rules_that_are_not_an_object_are_refused_as_a_save_refuses_them(self):
        for rules in ("web", ["group"], 5, None, True):
            with self.subTest(rules=rules):
                status, body = self.preview(rules)
                saved, saved_body = self.call(api.handle_smart_groups, body={"name": "bad", "rules": rules})
                self.assertEqual((status, body), (saved, saved_body))
                self.assertEqual(status, 400)

    def test_out_of_range_numbers_are_dropped_as_a_save_drops_them(self):
        self.put("DEVICES_FILE", self.fleet(10))
        status, body = self.preview({"mem_gt": 250})
        self.assertEqual(status, 400, "a rule set that holds nothing after validation is empty, here as in a save")
        status, body = self.preview({"mem_gt": 250, "group": "web"})
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 6)               # h001 h002 h004 h005 h007 h008: the group rule alone

    def test_the_display_name_is_the_hosts_name_or_its_id_and_is_cut_to_a_bound(self):
        devs = self.fleet(3)
        devs["h000"]["name"] = "x" * 400
        del devs["h001"]["name"]
        devs["h002"]["name"] = None
        self.put("DEVICES_FILE", devs)
        _status, body = self.preview({"tag": "prod"})
        names = [h["name"] for h in body["hosts"]]
        self.assertEqual(names, ["x" * 128, "h001", "h002"])

    def test_a_name_is_returned_as_text_and_never_as_markup(self):
        devs = self.fleet(2)
        devs["h000"]["name"] = "<img src=x onerror=alert(1)>"
        self.put("DEVICES_FILE", devs)
        status, body = self.preview({"tag": "prod"})
        self.assertEqual(status, 200)
        self.assertEqual(body["hosts"][0]["name"], "<img src=x onerror=alert(1)>")      # the page escapes it where it draws it


class TestThePreviewAndASavedGroupAgree(_Base):
    """There is one matcher. For every rule the preview and the group saved from it list the same hosts in the same order."""

    RULES = (
        {"group": "web"}, {"group": "db"}, {"group_in": ["db", "web"]}, {"tag": "edge"}, {"tags_any": ["edge", "nope"]},
        {"tags_all": ["prod", "edge"]}, {"os_contains": "debian"}, {"agent_version_contains": "1."}, {"monitored": False},
        {"monitored": True, "group": "web"}, {"agentless": False}, {"reboot_required": True}, {"mem_gt": 60}, {"mem_gt": 10, "group": "db"},
        {"cpu_gt": 0}, {"disk_gt": 0}, {"swap_gt": 5.5}, {"drift": True}, {"drift": True, "group": "web", "mem_gt": 20},
        {"group": "web", "tag": "edge", "os_contains": "ubuntu", "monitored": False},
    )

    def fleet_with_extras(self, n):
        devs = self.fleet(n)
        for i, rec in enumerate(devs.values()):
            rec["version"] = "1.%d.0" % (i % 4)
            rec["agentless"] = i % 7 == 0
            rec["sysinfo"].update({"reboot_required": i % 4 == 0, "cpu_percent": float(i % 13), "swap_percent": float(i % 9),
                                   "mounts": [{"path": "/", "percent": float(i % 60)}]})
        self.put("DEVICES_FILE", devs)
        return devs

    def test_each_rule_over_a_fleet_under_the_cap(self):
        devs = self.fleet_with_extras(45)
        # the shape _ingest_drift_report writes: a record per host holding its watched files, a file drifted when its hash moved
        drifted = {"files": {"/etc/ssh/sshd_config": {"baseline_hash": "aa", "current_hash": "bb", "exists": True}}}
        steady = {"files": {"/etc/hosts": {"baseline_hash": "cc", "current_hash": "cc", "exists": True}}}
        self.put("DRIFT_STATE_FILE", {"h003": drifted, "h010": drifted, "h021": drifted, "h004": steady})
        status, body = self.preview({"drift": True})
        self.assertEqual((status, [h["id"] for h in body["hosts"]]), (200, ["h003", "h010", "h021"]), "control: the drift rule matches")
        total = 0
        for k, rules in enumerate(self.RULES):
            with self.subTest(rules=rules):
                status, body = self.preview(rules)
                members = self.create("g%d" % k, rules)
                self.assertEqual(status, 200, body)
                self.assertEqual([h["id"] for h in body["hosts"]], members)
                self.assertEqual(body["count"], len(members))
                self.assertEqual([h["name"] for h in body["hosts"]], [devs[i]["name"] for i in members])
                total += len(members)
        self.assertGreater(total, 100, "control: the rules matched something between them")

    def test_each_rule_over_a_fleet_past_the_cap(self):
        self.fleet_with_extras(130)
        shown = 0
        for k, rules in enumerate(self.RULES):
            if "drift" in rules:
                continue
            with self.subTest(rules=rules):
                status, body = self.preview(rules)
                members = self.create("g%d" % k, rules)
                self.assertEqual(status, 200, body)
                self.assertEqual(body["count"], len(members))
                self.assertEqual([h["id"] for h in body["hosts"]], members[:50])
                shown += len(body["hosts"])
        self.assertGreater(shown, 200, "control: several rules filled the box")

    def test_an_edited_group_and_the_preview_of_its_new_rules_agree(self):
        self.fleet_with_extras(60)
        self.create("hot", {"group": "web"})
        for rules in ({"mem_gt": 80}, {"tag": "edge", "monitored": False}, {"os_contains": "ubuntu"}):
            with self.subTest(rules=rules):
                _status, body = self.preview(rules)
                status, _b = self.call(api.handle_smart_group, "hot", method="PATCH", body={"rules": rules})
                self.assertEqual(status, 200)
                members = self.read("SMART_GROUPS_FILE")["hot"]["members"]
                self.assertEqual([h["id"] for h in body["hosts"]], members[:50])
                self.assertEqual(body["count"], len(members))

    def test_the_preview_calls_the_function_a_saved_group_is_worked_out_with(self):
        """No second implementation: the answer is `_materialize_smart_group`'s, whatever it says."""
        self.put("DEVICES_FILE", self.fleet(5))
        real = api._materialize_smart_group
        seen = []

        def fake(rules, devices, tenant=None):
            seen.append((dict(rules), tenant))
            return ["h002", "h004"]

        api._materialize_smart_group = fake
        try:
            status, body = self.preview({"group": "web"})
        finally:
            api._materialize_smart_group = real
        self.assertEqual(status, 200)
        self.assertEqual([h["id"] for h in body["hosts"]], ["h002", "h004"])
        self.assertEqual(body["count"], 2)
        self.assertEqual(seen, [({"group": "web"}, "default")])


class TestTenants(_Base):

    def hosts(self):
        devs = {}
        for i in range(8):
            devs["d%d" % i] = {"name": "default-web-%d" % i, "tenant": "default", "group": "web", "monitored": True}
            devs["a%d" % i] = {"name": "acme-web-%d" % i, "tenant": "acme", "group": "web", "monitored": True}
        devs["a0"]["name"] = "acme-secret-name"
        self.put("DEVICES_FILE", devs)

    def test_a_tenant_administrator_sees_and_counts_only_their_own_hosts(self):
        self.two_tenants()
        self.hosts()
        self.who = ("acmeadmin", "admin")
        status, body = self.preview({"group": "web"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["count"], 8, "another tenant's hosts are not even counted")
        self.assertEqual({h["id"] for h in body["hosts"]}, {"a%d" % i for i in range(8)})
        self.assertNotIn("default-web", json.dumps(body))

    def test_the_default_tenant_previews_what_it_would_save(self):
        self.two_tenants()
        self.hosts()
        status, body = self.preview({"group": "web"})
        saved = self.create("web-hosts", {"group": "web"})
        self.assertEqual(status, 200)
        self.assertEqual([h["id"] for h in body["hosts"]], saved)
        self.assertEqual({h["id"] for h in body["hosts"]}, {"d%d" % i for i in range(8)})
        self.assertNotIn("acme-", json.dumps(body))

    def test_a_tenant_administrator_cannot_name_another_tenant_or_its_hosts(self):
        self.two_tenants()
        self.hosts()
        self.who = ("acmeadmin", "admin")
        extra = {"tenant": "default", "tenant_id": "default", "device_ids": ["d0", "d1"], "devices": ["d2"], "hosts": ["d3"],
                 "scope": {"type": "all"}, "scope_device_id": "d4", "tenancy_enforced": False, "name": "default-web-0"}
        status, body = self.preview({"group": "web"}, **extra)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 8)
        self.assertEqual({h["id"] for h in body["hosts"]}, {"a%d" % i for i in range(8)})
        # and the same body, as a rule inside `rules`, is not a facet the matcher reads
        status, body = self.preview({"group": "web", "tenant": "default", "device_ids": ["d0"], "scope": {"type": "all"}})
        self.assertEqual((status, body["count"]), (200, 8))

    def test_an_api_key_of_a_tenant_previews_that_tenants_hosts(self):
        """verify_token leaves the tenant a key was minted for in _RCTX, and a key's own display name matches no account, so resolving
        it through the user list would answer the default tenant, the platform operator's. The handler asks the way every other one
        does."""
        self.two_tenants()
        self.hosts()
        self.who = ("ci-key", "admin")
        api._RCTX.apikey_tenant = "acme"
        self.addCleanup(lambda: setattr(api._RCTX, "apikey_tenant", None))
        status, body = self.preview({"group": "web"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["count"], 8)
        self.assertEqual({h["id"] for h in body["hosts"]}, {"a%d" % i for i in range(8)})

    def test_a_rule_that_only_another_tenant_matches_matches_nothing(self):
        self.two_tenants()
        devs = {"d0": {"name": "d0", "tenant": "default", "group": "payroll"}, "a0": {"name": "a0", "tenant": "acme", "group": "web"}}
        self.put("DEVICES_FILE", devs)
        self.who = ("acmeadmin", "admin")
        status, body = self.preview({"group": "payroll"})
        self.assertEqual((status, body), (200, {"count": 0, "limit": 50, "hosts": []}),
                         "a count of 1 would tell a tenant that another tenant has a group called payroll")

    def test_with_tenancy_off_the_whole_fleet_is_one_tenant(self):
        self.hosts()
        status, body = self.preview({"group": "web"})
        self.assertEqual((status, body["count"]), (200, 16))


class TestAnApiKeyWithADeviceScope(_Base):
    """An API key can carry a device scope, and the scope confines even an administrator's key: it is how a service account is given
    part of the fleet. GET /api/devices answers such a key with the hosts of its scope. A smart group is a view over hosts, so the
    preview, the list of groups (member counts, and with ?members=1 the ids) and a group's members have to answer over the same
    hosts and no others: a count over the whole fleet would say how many hosts outside the scope carry a tag or sit in a group, and
    the names would be the hosts themselves.

    Driven with real keys through the real token check. Only the read of the token from the request is stubbed, because that is what
    puts a key's scope on the request and a stub of the check itself would put nothing there."""

    HOSTS = {
        "web1": {"name": "web-one", "group": "web", "site": "dc1", "tags": ["prod", "edge"], "os": "Debian 12", "monitored": True},
        "web2": {"name": "web-two", "group": "web", "site": "dc2", "tags": ["prod"], "os": "Debian 12", "monitored": True},
        "db1": {"name": "db-payroll-a", "group": "db", "site": "dc1", "tags": ["prod", "payroll"], "os": "Debian 12", "monitored": True},
        "db2": {"name": "db-payroll-b", "group": "db", "site": "dc2", "tags": ["prod", "payroll", "edge"], "os": "Debian 12",
                "monitored": True},
        "cache1": {"name": "cache-one", "group": "cache", "site": "dc1", "tags": [], "os": "Debian 12", "monitored": True},
    }
    EVERYONE = sorted(HOSTS)
    # token -> (the scope stored on the key, the hosts of that scope). Three kinds of scope, one of each type a key may have.
    SCOPES = {
        "KEY-WEB": ({"type": "groups", "values": ["web"]}, ["web1", "web2"]),
        "KEY-EDGE": ({"type": "tags", "values": ["edge"]}, ["db2", "web1"]),
        "KEY-DC1": ({"type": "sites", "values": ["dc1"]}, ["cache1", "db1", "web1"]),
    }

    def setUp(self):
        super().setUp()
        api.verify_token = self._stubs["verify_token"]
        self.token = "KEY-ALL"
        api.get_token_from_request = lambda: self.token
        keys = {"all": {"name": "no scope", "key_hash": api._apikey_hash("KEY-ALL"), "user": "api", "role": "admin", "active": True,
                        "created": 1}}
        for i, (token, (scope, _hosts)) in enumerate(self.SCOPES.items()):
            keys["k%d" % i] = {"name": "scoped %d" % i, "key_hash": api._apikey_hash(token), "user": "api", "role": "admin",
                               "active": True, "created": 1, "scope": scope}
        self.put("APIKEYS_FILE", keys)
        self.put("DEVICES_FILE", self.HOSTS)

    def ids(self, body):
        return [h["id"] for h in body["hosts"]]

    def groups(self, members=False):
        self.qs = "members=1" if members else ""
        status, body = self.call(api.handle_smart_groups, method="GET")
        self.assertEqual(status, 200, body)
        return {g["name"]: g for g in body["smart_groups"]}

    def seed_groups(self):
        """Two groups as the cadence leaves them: the members of a rule over the whole fleet."""
        self.token = "KEY-ALL"
        self.assertEqual(self.create("everyone", {"monitored": True}), self.EVERYONE)
        self.assertEqual(self.create("payroll", {"tag": "payroll"}), ["db1", "db2"])

    def test_control_the_scope_is_on_the_request_and_the_host_list_follows_it(self):
        """The instrument. The fleet read through the host list's own filter is confined by each scoped key and not by the other
        one; without this a pass below could be a scope that never reached the request."""
        for token, (scope, hosts) in self.SCOPES.items():
            self.token = token
            self.assertEqual(api._caller_scope(), scope, token)
            self.assertEqual(sorted(api._scope_filter_devices(api._load_ro(api.DEVICES_FILE))), hosts, token)
        self.token = "KEY-ALL"
        self.assertIsNone(api._caller_scope())
        self.assertEqual(sorted(api._scope_filter_devices(api._load_ro(api.DEVICES_FILE))), self.EVERYONE)

    def test_the_preview_counts_and_lists_the_hosts_of_the_scope_and_no_others(self):
        for token, (_scope, hosts) in self.SCOPES.items():
            with self.subTest(key=token):
                self.token = token
                status, body = self.preview({"monitored": True})                  # a rule that every host matches
                self.assertEqual(status, 200, body)
                self.assertEqual((body["count"], self.ids(body)), (len(hosts), hosts))
                text = json.dumps(body)
                self.assertEqual([h["name"] for i, h in self.HOSTS.items() if i not in hosts and h["name"] in text], [],
                                 "the name of a host outside the scope is in the answer")

    def test_a_rule_that_only_hosts_outside_the_scope_match_matches_nothing(self):
        """The count is an answer too: 2 for the payroll tag would tell the key that two hosts it cannot see carry that tag."""
        self.token = "KEY-WEB"
        for rules in ({"tags_any": ["payroll"]}, {"group": "db"}, {"group_in": ["db", "cache"]}, {"tag": "payroll", "monitored": True},
                      {"os_contains": "debian", "group": "cache"}):
            with self.subTest(rules=rules):
                self.assertEqual(self.preview(rules), (200, {"count": 0, "limit": 50, "hosts": []}))
        self.token = "KEY-ALL"
        self.assertEqual(self.preview({"tags_any": ["payroll"]})[1]["count"], 2, "control: those hosts are in the fleet")
        self.assertEqual(self.preview({"group": "db"})[1]["count"], 2)

    def test_a_key_with_no_scope_and_a_signed_in_administrator_still_see_every_host(self):
        """The other direction: nothing changes for a caller that nothing confines."""
        self.token = "KEY-ALL"
        status, body = self.preview({"monitored": True})
        self.assertEqual((status, body["count"], self.ids(body)), (200, 5, self.EVERYONE))
        api.verify_token = lambda token: ("jakob", "admin")                       # a session: no key, so no key scope
        status, body = self.preview({"monitored": True})
        self.assertEqual((status, body["count"], self.ids(body)), (200, 5, self.EVERYONE))

    def test_the_list_counts_and_names_only_the_members_in_reach(self):
        self.seed_groups()
        for token, (_scope, hosts) in self.SCOPES.items():
            with self.subTest(key=token):
                self.token = token
                rows = self.groups(members=True)
                for name, whole in (("everyone", self.EVERYONE), ("payroll", ["db1", "db2"])):
                    reach = [i for i in whole if i in hosts]
                    self.assertEqual(rows[name]["members"], reach, name)
                    self.assertEqual(rows[name]["member_count"], len(reach), name)
                # without ?members=1 there is no list of ids, and the count is still the number in reach
                rows = self.groups()
                self.assertTrue(all("members" not in g for g in rows.values()))
                self.assertEqual(rows["everyone"]["member_count"], len(hosts))
                self.assertEqual(rows["payroll"]["member_count"], len([i for i in ("db1", "db2") if i in hosts]))
        self.token = "KEY-ALL"
        rows = self.groups(members=True)
        self.assertEqual((rows["everyone"]["member_count"], rows["payroll"]["member_count"]), (5, 2), "control: whole for a caller no scope confines")
        self.assertEqual(rows["everyone"]["members"], self.EVERYONE)

    def test_a_groups_members_route_lists_only_the_members_in_reach(self):
        self.seed_groups()
        for token, (_scope, hosts) in self.SCOPES.items():
            with self.subTest(key=token):
                self.token = token
                status, body = self.call(api.handle_smart_group, "everyone", method="GET")
                self.assertEqual(status, 200, body)
                self.assertEqual([m["id"] for m in body["members"]], hosts)
                self.assertEqual([m["name"] for m in body["members"]], [self.HOSTS[i]["name"] for i in hosts])
        self.token = "KEY-WEB"
        status, body = self.call(api.handle_smart_group, "payroll", method="GET")
        self.assertEqual((status, body["members"]), (200, []), "a group whose members are all out of reach lists none, and still exists")
        self.token = "KEY-ALL"
        status, body = self.call(api.handle_smart_group, "everyone", method="GET")
        self.assertEqual([m["id"] for m in body["members"]], self.EVERYONE)

    def test_the_stored_list_is_the_whole_tenants_and_the_cadence_agrees(self):
        """Create and edit answer with no host and store the tenant-wide list, which is what the cadence works out every minute with
        no caller. The narrowing is on the read: a list narrowed when it is saved would change by itself a minute later."""
        self.token = "KEY-WEB"
        status, body = self.call(api.handle_smart_groups, body={"name": "by-key", "rules": {"monitored": True}})
        self.assertEqual(status, 201, body)
        self.assertEqual(sorted(body), ["name", "ok", "scope_value"], "no host is in the answer to a create")
        stored = self.read("SMART_GROUPS_FILE")["by-key"]["members"]
        self.assertEqual(stored, self.EVERYONE)
        groups = self.read("SMART_GROUPS_FILE")
        groups["_meta"] = {"last_run": 0}
        self.put("SMART_GROUPS_FILE", groups)
        api.run_smart_groups_if_due()
        self.assertEqual(self.read("SMART_GROUPS_FILE")["by-key"]["members"], stored, "the cadence stored another list")
        self.assertEqual([m["id"] for m in self.call(api.handle_smart_group, "by-key", method="GET")[1]["members"]], ["web1", "web2"])
        status, _b = self.call(api.handle_smart_group, "by-key", method="PATCH", body={"rules": {"tag": "payroll"}})
        self.assertEqual(status, 200)
        self.assertEqual(self.read("SMART_GROUPS_FILE")["by-key"]["members"], ["db1", "db2"], "an edit stores the tenant-wide list too")
        self.assertEqual(self.call(api.handle_smart_group, "by-key", method="GET")[1]["members"], [])
        self.token = "KEY-ALL"
        self.assertEqual([m["id"] for m in self.call(api.handle_smart_group, "by-key", method="GET")[1]["members"]], ["db1", "db2"])

    def test_a_key_scoped_to_a_smart_group_previews_the_hosts_that_group_matches(self):
        self.put("SMART_GROUPS_FILE", {"webs": {"rules": {"group": "web"}, "members": ["web1", "web2"], "tenant": api.DEFAULT_TENANT}})
        keys = self.read("APIKEYS_FILE")
        keys["ksg"] = {"name": "smart", "key_hash": api._apikey_hash("KEY-SMART"), "user": "api", "role": "admin", "active": True,
                       "created": 1, "scope": {"type": "groups", "values": ["smart:webs"]}}
        self.put("APIKEYS_FILE", keys)
        self.token = "KEY-SMART"
        status, body = self.preview({"monitored": True})
        self.assertEqual((status, body["count"], self.ids(body)), (200, 2, ["web1", "web2"]))

    def test_a_key_of_a_tenant_is_held_by_the_tenant_and_by_its_scope(self):
        self.put("TENANTS_FILE", {"default": {"name": "Default", "builtin": True}, "acme": {"name": "Acme", "status": "active"}})
        self.put("CONFIG_FILE", {"tenancy_enforced": True})
        self.put("DEVICES_FILE", {
            "a1": {"name": "acme-web", "tenant": "acme", "group": "web", "monitored": True},
            "a2": {"name": "acme-db", "tenant": "acme", "group": "db", "monitored": True},
            "d1": {"name": "default-web", "tenant": "default", "group": "web", "monitored": True}})
        keys = self.read("APIKEYS_FILE")
        keys["ka"] = {"name": "acme", "key_hash": api._apikey_hash("KEY-ACME"), "user": "api", "role": "admin", "active": True,
                      "created": 1, "tenant_id": "acme"}
        keys["kaw"] = {"name": "acme web", "key_hash": api._apikey_hash("KEY-ACME-WEB"), "user": "api", "role": "admin", "active": True,
                       "created": 1, "tenant_id": "acme", "scope": {"type": "groups", "values": ["web"]}}
        self.put("APIKEYS_FILE", keys)
        self.token = "KEY-ACME"
        status, body = self.preview({"monitored": True})
        self.assertEqual((status, self.ids(body)), (200, ["a1", "a2"]), "the tenant alone")
        self.token = "KEY-ACME-WEB"
        status, body = self.preview({"monitored": True})
        self.assertEqual((status, body["count"], self.ids(body)), (200, 1, ["a1"]), "the tenant, then the scope")
        self.assertEqual(self.preview({"group": "db"})[1]["count"], 0)


def _family():
    """{handler name: source} of every handler a /api/smart-groups route reaches, found the way the application finds its handlers."""
    out = {}
    for (_m, path), fn in api._build_exact_routes().items():
        if path.startswith("/api/smart-groups"):
            out[fn.__name__] = inspect.getsource(fn)
    for kind, _methods, a, b, name, _src in api._PATTERN_ROUTE_DEFS:
        path = a if kind == "eq" else a + "{}" + b if kind == "pat" else ""
        if path.startswith("/api/smart-groups"):
            out[name] = inspect.getsource(getattr(api, name))
    return out


# What a handler does that tells a caller about hosts: it reads the fleet, or it reads a group's stored member list.
# What makes the answer the caller's own: a helper that folds `_caller_scope()` (the role's scope and the API key's), and the tenant.
_KEY_SCOPE_AWARE = ("_confined_host_ids", "_scope_filter_devices")


def unconfined(sources):
    """The handlers that read hosts or a stored member list and call no helper that folds the caller's device scope. Read by syntax
    tree: a name in a comment or a docstring is not a call."""
    out = []
    for name, src in sorted(sources.items()):
        reads, calls = False, set()
        for node in ast.walk(ast.parse(textwrap.dedent(src))):
            if isinstance(node, ast.Call):
                fn = node.func
                calls.add(fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "")
            if isinstance(node, ast.Name) and node.id == "DEVICES_FILE" or isinstance(node, ast.Attribute) and node.attr == "DEVICES_FILE":
                reads = True
            if isinstance(node, ast.Constant) and node.value == "members":
                reads = True
        if reads and not calls & set(_KEY_SCOPE_AWARE):
            out.append(name)
    return out


class TestEveryRouteOfTheFamilyAnswersOverTheHostsOfTheCaller(unittest.TestCase):
    """The preview was added with a tenant filter and no scope filter, beside a list and a members route that had neither. A rule the
    code applies in most places and misses in one is found by listing every site, so this lists them: every handler a smart-group
    route reaches, and for each one that reads hosts or a stored member list, the helper that makes the answer the caller's own."""

    def test_the_scan_sees_the_family(self):
        family = _family()
        self.assertEqual(sorted(family), ["handle_smart_group", "handle_smart_group_preview", "handle_smart_groups"])
        for name, src in family.items():
            self.assertGreater(len(src.splitlines()), 8, name + " has no source to read")

    def test_every_handler_that_reads_hosts_folds_the_callers_scope(self):
        self.assertEqual(unconfined(_family()), [],
                         "these smart-group handlers read hosts or a member list with no helper that folds the API key's device scope "
                         "(_confined_host_ids, _scope_filter_devices): a key with a scope would read the whole tenant through them")

    def test_control_the_scan_finds_a_handler_that_does_not(self):
        bad = "def handle_x():\n    devices = A._load_ro(A.DEVICES_FILE) or {}\n    return A._tenant_filter_devices(devices)\n"
        good = "def handle_x():\n    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})\n    return devices\n"
        members = "def handle_x(g):\n    return len(g.get('members') or [])\n"
        in_a_comment = "def handle_x():\n    # _scope_filter_devices(...)\n    '''_confined_host_ids()'''\n    return load(DEVICES_FILE)\n"
        elsewhere = "def handle_x():\n    return 1\n"
        self.assertEqual(unconfined({"bad": bad, "good": good, "members": members, "comment": in_a_comment, "none": elsewhere}),
                         ["bad", "comment", "members"])

    def test_control_the_old_preview_is_found(self):
        src = inspect.getsource(api.handle_smart_group_preview)
        old = src.replace("A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})", "A._load_ro(A.DEVICES_FILE) or {}")
        self.assertNotEqual(old, src, "the anchor did not match")
        self.assertEqual(unconfined({"handle_smart_group_preview": old}), ["handle_smart_group_preview"])


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
put("USERS_FILE", {"boss": {"role": "admin", "tenant_id": "default", "created": 1}})
put("DEVICES_FILE", {
    "web1": {"name": "web-one", "group": "web", "os": "Debian 12", "monitored": True},
    "web2": {"name": "web-two", "group": "web", "os": "Debian 12", "monitored": True},
    "db1": {"name": "db-payroll", "group": "db", "os": "Debian 12", "monitored": True, "tags": ["payroll"]}})
key = lambda token, **extra: dict({"name": token, "key_hash": api._apikey_hash(token), "user": "api", "role": "admin", "active": True,
                                   "created": 1}, **extra)
put("APIKEYS_FILE", {"k1": key("SCOPED", scope={"type": "groups", "values": ["web"]}), "k2": key("PLAIN")})


def call(method, path, token, body=None):
    kw = {"headers": {"X-Token": token}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(client, method.lower())(path, **kw)
    return [r.status_code, json.loads(r.data.decode() or "null")]


out = {}
for who in ("SCOPED", "PLAIN"):
    out[who] = {
        "devices": call("GET", "/api/devices", who),
        "preview": call("POST", "/api/smart-groups/preview", who, {"rules": {"os_contains": "debian"}}),
        "payroll": call("POST", "/api/smart-groups/preview", who, {"rules": {"tags_any": ["payroll"]}}),
        "create": call("POST", "/api/smart-groups", who, {"name": "g-" + who.lower(), "rules": {"os_contains": "debian"}}),
    }
    out[who]["list"] = call("GET", "/api/smart-groups?members=1", who)
    out[who]["members"] = call("GET", "/api/smart-groups/g-" + who.lower() + "/members", who)
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):
    """The same question through the real route table, the real request gates and the real token check (Flask test client over
    api.main()), in a process of its own on a data directory of its own: nothing is stubbed."""

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-sgstack-"))
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
    def names(call):
        return sorted(h["name"] for h in call[1])

    def test_control_the_host_list_is_confined_for_the_scoped_key_and_whole_for_the_other(self):
        self.assertEqual((self.out["SCOPED"]["devices"][0], self.names(self.out["SCOPED"]["devices"])), (200, ["web-one", "web-two"]))
        self.assertEqual(self.names(self.out["PLAIN"]["devices"]), ["db-payroll", "web-one", "web-two"])

    def test_the_preview_answers_over_the_hosts_of_the_scope(self):
        scoped = self.out["SCOPED"]
        self.assertEqual(scoped["preview"][0], 200)
        self.assertEqual((scoped["preview"][1]["count"], sorted(h["name"] for h in scoped["preview"][1]["hosts"])), (2, ["web-one", "web-two"]))
        self.assertEqual(scoped["payroll"][1]["count"], 0, "the key was told how many hosts outside its scope carry the tag")
        self.assertEqual(self.out["PLAIN"]["preview"][1]["count"], 3)
        self.assertEqual(self.out["PLAIN"]["payroll"][1]["count"], 1)

    def test_a_group_a_scoped_key_creates_is_listed_and_read_through_the_scope(self):
        scoped, plain = self.out["SCOPED"], self.out["PLAIN"]
        self.assertEqual(scoped["create"][0], 201)
        mine = next(g for g in scoped["list"][1]["smart_groups"] if g["name"] == "g-scoped")
        self.assertEqual((mine["member_count"], sorted(mine["members"])), (2, ["web1", "web2"]))
        self.assertEqual(sorted(m["name"] for m in scoped["members"][1]["members"]), ["web-one", "web-two"])
        theirs = next(g for g in plain["list"][1]["smart_groups"] if g["name"] == "g-plain")
        self.assertEqual((theirs["member_count"], sorted(theirs["members"])), (3, ["db1", "web1", "web2"]))
        self.assertEqual(sorted(m["name"] for m in plain["members"][1]["members"]), ["db-payroll", "web-one", "web-two"])


class TestWhoMayAskAndWhatItChanges(_Base):

    def test_viewing_the_groups_and_previewing_one_need_the_same_role(self):
        self.put("DEVICES_FILE", self.fleet(5))
        cases = (("jakob", "admin", True), ("bob", "viewer", False), ("mcp", "mcp", False), ("auditor", "auditor", False),
                 ("finance", "finance", False), ("custom", "no-such-role", False))
        for user, role, allowed in cases:
            with self.subTest(role=role):
                self.who = (user, role)
                listed, _b = self.call(api.handle_smart_groups, method="GET")
                status, body = self.preview({"group": "web"})
                self.assertEqual(listed == 200, allowed, (role, listed))
                self.assertEqual(status == 200, allowed, (role, status, body))
                if not allowed:
                    self.assertEqual(status, listed)
                    self.assertEqual(status, 403)

    def test_a_custom_role_that_holds_action_permissions_is_not_an_administrator(self):
        self.put("ROLES_FILE", {"roles": [{"name": "operator", "permissions": ["reboot", "patch"], "scope": {"type": "all"}}]})
        self.put("USERS_FILE", {"op": {"role": "operator", "created": 1}})
        self.who = ("op", "operator")
        status, _body = self.preview({"group": "web"})
        self.assertEqual(status, 403)

    def test_no_token_is_refused(self):
        self.who = (None, None)
        status, _body = self.preview({"group": "web"})
        self.assertEqual(status, 401)

    def test_only_a_post_is_answered(self):
        for verb in ("GET", "PUT", "PATCH", "DELETE"):
            with self.subTest(verb=verb):
                status, _body = self.call(api.handle_smart_group_preview, method=verb, body={"rules": {"group": "web"}})
                self.assertEqual(status, 405)

    def test_a_malformed_body_is_a_400_and_never_a_500(self):
        for body in ({"rules": {"group": "web"}, "name": 5}, {"name": ["x"], "rules": {"group": "web"}}):
            status, _b = self.call(api.handle_smart_group_preview, body=body)
            self.assertIn(status, (200, 400))
        for raw in ([], "x", 7, None):
            self.cap = {}
            self.http_method = "POST"
            self.body = raw
            try:
                api.handle_smart_group_preview()
            except api.HTTPError:
                pass
            self.assertEqual(self.cap["status"], 400, raw)

    def test_it_changes_nothing(self):
        devs = self.fleet(40)
        self.put("DEVICES_FILE", devs)
        before_files = sorted(p.name for p in self.d.iterdir())
        before_devices = json.dumps(self.read("DEVICES_FILE"), sort_keys=True)
        saves, locks = [], []
        real_save, real_lock = api.save, api._LockedUpdate

        def counting_save(path, *a, **k):
            saves.append(Path(path).name)
            return real_save(path, *a, **k)

        def counting_lock(path, *a, **k):
            locks.append(Path(path).name)
            return real_lock(path, *a, **k)

        api.save, api._LockedUpdate = counting_save, counting_lock
        try:
            status, _body = self.preview({"group": "web", "mem_gt": 10})
        finally:
            api.save, api._LockedUpdate = real_save, real_lock
        self.assertEqual(status, 200)
        self.assertEqual(saves, [], "a store was written")
        self.assertEqual(locks, [], "a store was locked for writing")
        self.assertEqual(self.audit, [], "a preview is not an event: nothing goes in the audit log")
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), before_files)
        self.assertEqual(json.dumps(self.read("DEVICES_FILE"), sort_keys=True), before_devices)
        self.assertNotIn("smart_groups.json", [p.name for p in self.d.iterdir()], "no group was stored")

    def test_it_does_not_run_the_cadence_or_the_limits_of_a_save(self):
        """A save refuses a 101st group and a name that is taken; a preview has neither, because it stores nothing."""
        self.put("DEVICES_FILE", self.fleet(5))
        self.put("SMART_GROUPS_FILE", dict({"g%d" % i: {"rules": {"group": "web"}, "members": []} for i in range(100)}))
        status, _body = self.call(api.handle_smart_groups, body={"name": "one-more", "rules": {"group": "web"}})
        self.assertEqual(status, 400)
        status, body = self.preview({"group": "web"}, name="g1")
        self.assertEqual(status, 200, body)


class TestTheWorkIsBounded(_Base):

    def test_the_conditions_are_capped_as_a_save_caps_them(self):
        """Only the first 50 of a list are kept and each string is cut at 128: a host that only the 55th tag would match does not
        match, in the preview and in the saved group alike."""
        devs = self.fleet(10)
        devs["h003"]["tags"] = ["tag-54"]
        devs["h004"]["tags"] = ["tag-10"]
        self.put("DEVICES_FILE", devs)
        rules = {"tags_any": ["tag-%d" % i for i in range(60)]}
        status, body = self.preview(rules)
        members = self.create("capped", rules)
        self.assertEqual(status, 200)
        self.assertEqual([h["id"] for h in body["hosts"]], members)
        self.assertEqual(members, ["h004"], "tag-10 is inside the first 50, tag-54 is not")
        long_group = {"group": "w" * 500}
        status, body = self.preview(long_group)
        self.assertEqual((status, body["count"]), (200, 0))

    def test_every_host_is_looked_at_once_and_a_big_fleet_answers_in_a_few_kilobytes(self):
        n = 20000
        self.put("DEVICES_FILE", {"h%05d" % i: {"name": "host-%05d" % i, "group": "web", "monitored": True} for i in range(n)})
        calls = []
        real = api._smart_group_match

        def counting(dev, rules, dev_id=None, drift_ids=None):
            calls.append(dev_id)
            return real(dev, rules, dev_id, drift_ids)

        api._smart_group_match = counting
        try:
            status, body = self.preview({"group": "web"})
        finally:
            api._smart_group_match = real
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], n)
        self.assertEqual(len(body["hosts"]), 50)
        self.assertEqual(len(calls), n, "each host is matched once")
        self.assertEqual(len(set(calls)), n)
        self.assertLess(len(json.dumps(body)), 8000)

    def test_the_fleet_is_read_without_a_copy(self):
        """The host list is read through the shared read-only view: nothing below mutates it, and a copy of a large one is the one
        cost that grows with the fleet."""
        self.put("DEVICES_FILE", self.fleet(5))
        reads = []
        real_ro, real_load = api._load_ro, api.load

        def ro(path, *a, **k):
            reads.append(("ro", Path(path).name))
            return real_ro(path, *a, **k)

        def ld(path, *a, **k):
            reads.append(("load", Path(path).name))
            return real_load(path, *a, **k)

        api._load_ro, api.load = ro, ld
        try:
            status, _body = self.preview({"group": "web"})
        finally:
            api._load_ro, api.load = real_ro, real_load
        self.assertEqual(status, 200)
        self.assertIn(("ro", Path(api.DEVICES_FILE).name), reads)
        self.assertNotIn(("load", Path(api.DEVICES_FILE).name), reads)


class TestTheRoute(_Base):

    def test_the_route_reaches_the_handler_and_the_neighbours_are_where_they_were(self):
        self.assertEqual(routing_harness.routes_to("POST", "/api/smart-groups/preview"), "handle_smart_group_preview")
        self.assertEqual(routing_harness.routes_to("POST", "/api/smart-groups"), "handle_smart_groups")
        self.assertEqual(routing_harness.routes_to("GET", "/api/smart-groups"), "handle_smart_groups")
        self.assertEqual(routing_harness.routes_to("GET", "/api/smart-groups/hot/members"), "handle_smart_group")
        self.assertEqual(routing_harness.routes_to("PATCH", "/api/smart-groups/hot"), "handle_smart_group")
        self.assertEqual(routing_harness.routes_to("DELETE", "/api/smart-groups/hot"), "handle_smart_group")
        # a group may be called preview: its own routes are unchanged
        self.assertEqual(routing_harness.routes_to("PATCH", "/api/smart-groups/preview"), "handle_smart_group")
        self.assertEqual(routing_harness.routes_to("DELETE", "/api/smart-groups/preview"), "handle_smart_group")
        self.assertEqual(routing_harness.routes_to("GET", "/api/smart-groups/preview/members"), "handle_smart_group")

    def test_the_handler_is_bound_from_its_module_and_calls_through_the_api_namespace(self):
        self.assertEqual(api.handle_smart_group_preview.__module__, "smart_group_handlers")
        src = (_ROOT / "server" / "cgi-bin" / "smart_group_handlers.py").read_text(encoding="utf-8")
        self.assertIn("_materialize_smart_group(", src)
        self.assertIn("require_admin_auth()", src)

    def test_the_openapi_document_describes_it(self):
        import openapi_spec
        routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
        self.assertIn(("POST", "/api/smart-groups/preview"), routes)
        spec = openapi_spec.build_spec(api.SERVER_VERSION, routes=routes)
        op = spec["paths"]["/smart-groups/preview"]["post"]
        self.assertIn("rules", json.dumps(op["requestBody"]))
        ok = json.dumps(op["responses"]["200"])
        for word in ("count", "hosts", "limit"):
            self.assertIn(word, ok)
        self.assertIn("403", op["responses"])
        self.assertIn("preview", op["summary"].lower())


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# the editor
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# The real client code in V8 (every script, in index.html order, the way the repo's load harness evaluates it) with the page's own
# functions run against a stand-in for the few elements the editor touches. `api`, `toast`, `closeModal` and `loadSmartGroups` are
# replaced; everything else is the shipped code. A scenario is an async function body that returns what it saw.
_UI_RUNNER = r"""
const vm = require('vm'), fs = require('fs');
const [clientPath, scenarioPath] = process.argv.slice(2);
const ctx = vm.createContext({ console });
vm.runInContext(fs.readFileSync(clientPath, 'utf8'), ctx, { filename: 'client.js' });
const scenarios = JSON.parse(fs.readFileSync(scenarioPath, 'utf8'));
const PRELUDE = `
  const els = {};
  const writes = [];     // every write to a control's disabled flag: the editor's functions have to make none (the dispatcher owns it)
  const mk = (id, o) => {
    const e = Object.assign({ id, value: '', checked: false, innerHTML: '', textContent: '',
      dataset: {}, listeners: {}, addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } }, o || {});
    let off = false;
    Object.defineProperty(e, 'disabled', { configurable: true, get() { return off; }, set(v) { writes.push([id, !!v]); off = !!v; } });
    return (els[id] = e);
  };
  ['sg-name', 'sg-group', 'sg-tag', 'sg-os', 'sg-mem', 'sg-disk', 'sg-cpu', 'sg-drift', 'sg-reboot', 'sg-preview', 'sg-preview-btn',
   'smart-group-modal', 'smart-group-modal-title'].forEach(id => mk(id));
  document = { getElementById: id => els[id] || null };
  const calls = [];
  window = { RPi18n: { current: 'en' } };
  toast = () => {}; closeModal = () => {}; loadSmartGroups = () => {};
  _smartGroupEdit = null;
  const answer = a => { api = async (m, p, b) => { calls.push([m, p, b]); return typeof a === 'function' ? a(m, p, b) : a; }; };
`;
(async () => {
  const out = {};
  for (const [name, body] of Object.entries(scenarios)) {
    try {
      const fn = vm.runInContext('(async function () {\n' + PRELUDE + body + '\n})', ctx);
      out[name] = await fn();
    } catch (e) { out[name] = { threw: String(e && e.stack || e) }; }
  }
  process.stdout.write(JSON.stringify(out));
})();
"""

# The preview button as a browser has it, for the scenarios that run the dispatcher's own helpers (_btnInflight, _btnFocusBack): a control
# that is disabled while it has focus leaves focus on the body. `dispatch(fn)` is what the page's click handler does around a handler
# call: it reads whether the button has focus before the handler runs and passes that on.
_BROWSER_BUTTON = """
      const btn = els['sg-preview-btn'];
      const body = { id: 'body' };
      document.body = body; document.contains = () => true; document.activeElement = btn;
      let off = false; const classes = new Set(); const attrs = {};
      Object.defineProperty(btn, 'disabled', { configurable: true, get() { return off; }, set(v) {
        writes.push(['btn', !!v]); off = !!v; if (off && document.activeElement === btn) document.activeElement = body; } });
      btn.tagName = 'BUTTON';
      btn.classList = { add: c => classes.add(c), remove: c => classes.delete(c) };
      btn.setAttribute = (k, v) => { attrs[k] = v; };
      btn.removeAttribute = k => { delete attrs[k]; };
      btn.focus = () => { if (!off) document.activeElement = btn; };
      setTimeout = () => 0;
      const state = () => ({ disabled: off, busy: attrs['aria-busy'] || null, inflight: classes.has('btn-inflight'),
                             focus: document.activeElement === btn, text: els['sg-preview'].textContent });
      const dispatch = (fn, o) => { const had = document.activeElement === btn; const ret = fn();
                                    _btnInflight(btn, ret, o && o.note === false ? undefined : had); return ret; };
"""

_SCENARIOS = {
    "rules_empty": "return _smartGroupRulesFromForm();",
    "rules_full": """
      els['sg-group'].value = ' web '; els['sg-tag'].value = 'prod'; els['sg-os'].value = 'Debian'; els['sg-mem'].value = '80';
      els['sg-disk'].value = '90.5'; els['sg-cpu'].value = 'x'; els['sg-drift'].checked = true; els['sg-reboot'].checked = true;
      els['sg-name'].value = 'a-name-is-not-a-rule';
      return _smartGroupRulesFromForm();""",
    "preview_and_save_send_the_same_rules": """
      els['sg-group'].value = 'db'; els['sg-mem'].value = '70'; els['sg-reboot'].checked = true; els['sg-name'].value = 'dbs';
      answer({ count: 3, limit: 50, hosts: [] });
      await previewSmartGroup();
      answer({ ok: true, name: 'dbs' });
      await saveSmartGroup();
      return { calls };""",
    "edit_saves_the_same_rules_too": """
      els['sg-tag'].value = 'edge'; _smartGroupEdit = 'hot';
      answer({ count: 1, limit: 50, hosts: [] });
      await previewSmartGroup();
      answer({ ok: true });
      await saveSmartGroup();
      return { calls };""",
    "count_and_names": """
      els['sg-group'].value = 'web';
      const hosts = Array.from({ length: 50 }, (_, i) => ({ id: 'h' + i, name: 'host-' + i }));
      answer({ count: 120, limit: 50, hosts });
      await previewSmartGroup();
      return { html: els['sg-preview'].innerHTML, calls, disabled: els['sg-preview-btn'].disabled, writes };""",
    "one_host": """
      els['sg-group'].value = 'web'; answer({ count: 1, limit: 50, hosts: [{ id: 'h0', name: 'only' }] });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "no_host": """
      els['sg-group'].value = 'web'; answer({ count: 0, limit: 50, hosts: [] });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "every_host_shown_says_nothing_about_a_cap": """
      els['sg-group'].value = 'web'; answer({ count: 2, limit: 50, hosts: [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }] });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "markup_in_a_name_and_an_id": """
      els['sg-group'].value = 'web';
      answer({ count: 2, limit: 50, hosts: [{ id: 'x"><svg onload=1>', name: '<img src=x onerror=alert(1)>' }, { id: 'y', name: '' }] });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "an_error_is_text": """
      answer({ error: 'at least one rule is required' });
      await previewSmartGroup(); return { html: els['sg-preview'].innerHTML, disabled: els['sg-preview-btn'].disabled, writes };""",
    "an_error_with_markup_is_text": """
      answer({ error: '<b onmouseover=1>x</b>' });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "a_failed_request": """
      api = async () => { throw new Error('network'); };
      await previewSmartGroup(); return { html: els['sg-preview'].innerHTML, disabled: els['sg-preview-btn'].disabled, writes };""",
    "no_answer": """
      api = async () => null;
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "a_malformed_answer": """
      answer({ count: 'many', hosts: 'all' });
      await previewSmartGroup(); return els['sg-preview'].innerHTML;""",
    "the_handler_leaves_the_button_to_the_dispatcher": """
      let release; const pending = new Promise(r => { release = r; });
      api = async () => pending;
      els['sg-group'].value = 'web';
      const run = previewSmartGroup();
      const during = { disabled: els['sg-preview-btn'].disabled, text: els['sg-preview'].textContent };
      release({ count: 5, limit: 50, hosts: [] });
      await run;
      return { during, after: els['sg-preview-btn'].disabled, html: els['sg-preview'].innerHTML, writes };""",
    "an_answer_after_a_rule_changed_is_dropped": """
      _wireSmartGroupPreview();
      let release; const pending = new Promise(r => { release = r; });
      api = async () => pending;
      els['sg-group'].value = 'web';
      const run = previewSmartGroup();
      els['sg-tag'].value = 'edge';
      els['smart-group-modal'].listeners.input[0]({ target: els['sg-tag'] });      // the person typed in a rule
      release({ count: 9, limit: 50, hosts: [{ id: 'a', name: 'A' }] });
      await run;
      return { html: els['sg-preview'].innerHTML, disabled: els['sg-preview-btn'].disabled, writes };""",
    # The dispatcher's side, with the real _btnInflight and _btnFocusBack against a button as a browser has it: a control that is
    # disabled while it has focus leaves focus on the body. `dispatch` is what the click handler does around a handler call.
    "dispatcher_dims_the_button_and_gives_focus_back": _BROWSER_BUTTON + """
      els['sg-group'].value = 'web';
      let release; const pending = new Promise(r => { release = r; });
      api = async () => pending;
      const ret = dispatch(previewSmartGroup);
      const during = state();
      release({ count: 1, limit: 50, hosts: [{ id: 'h', name: 'H' }] });
      await ret;
      return { during, after: state(), writes, html: els['sg-preview'].innerHTML };""",
    "a_button_whose_handler_disables_it_gets_focus_back": _BROWSER_BUTTON + """
      let release; const pending = new Promise(r => { release = r; });
      const ret = dispatch(async () => { btn.disabled = true; await pending; btn.disabled = false; });
      const during = state();
      release();
      await ret;
      return { during, after: state() };""",
    "control_without_the_note_a_disabled_button_stays_without_focus": _BROWSER_BUTTON + """
      let release; const pending = new Promise(r => { release = r; });
      const ret = dispatch(async () => { btn.disabled = true; await pending; btn.disabled = false; }, { note: false });
      release();
      await ret;
      return { after: state() };""",
    "focus_that_moved_is_not_taken_back": _BROWSER_BUTTON + """
      const field = { id: 'a-field' };
      let release; const pending = new Promise(r => { release = r; });
      const ret = dispatch(async () => { btn.disabled = true; await pending; btn.disabled = false; });
      document.activeElement = field;                    // the person tabbed to a field, or a dialog took focus
      release();
      await ret;
      return { after: state(), onField: document.activeElement === field };""",
    "a_button_left_disabled_does_not_take_focus": _BROWSER_BUTTON + """
      let release; const pending = new Promise(r => { release = r; });
      const ret = dispatch(async () => { btn.disabled = true; await pending; });
      release();
      await ret;
      return { after: state() };""",
    "a_handler_that_returns_nothing_is_left_alone": _BROWSER_BUTTON + """
      const ret = dispatch(() => { btn.disabled = true; });
      return { after: state(), same: ret === undefined };""",
    "a_rule_empties_the_box_and_the_name_does_not": """
      _wireSmartGroupPreview(); _wireSmartGroupPreview();
      const seen = { inputs: els['smart-group-modal'].listeners.input.length, changes: els['smart-group-modal'].listeners.change.length };
      els['sg-group'].value = 'web'; answer({ count: 4, limit: 50, hosts: [{ id: 'a', name: 'A' }] });
      await previewSmartGroup();
      const before = els['sg-preview'].innerHTML !== '';
      els['smart-group-modal'].listeners.input[0]({ target: els['sg-name'] });
      const afterName = els['sg-preview'].innerHTML !== '';
      els['smart-group-modal'].listeners.change[0]({ target: els['sg-drift'] });
      const afterRule = els['sg-preview'].innerHTML !== '';
      return { seen, before, afterName, afterRule };""",
    "opening_the_form_empties_the_box": """
      els['sg-preview'].innerHTML = 'an old answer';
      _fillSmartGroupForm({ name: '', rules: { group: 'web' } });
      return { html: els['sg-preview'].innerHTML, group: els['sg-group'].value };""",
}


def run_ui():
    d = Path(tempfile.mkdtemp(prefix="rp-sgui-"))
    _TMP.append(d)
    (d / "runner.js").write_text(_UI_RUNNER, encoding="utf-8")
    (d / "client.js").write_text(_jsload_harness.concat(), encoding="utf-8")
    (d / "scenarios.json").write_text(json.dumps(_SCENARIOS), encoding="utf-8")
    proc = subprocess.run([_NODE, str(d / "runner.js"), str(d / "client.js"), str(d / "scenarios.json")], capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise AssertionError("node failed:\n" + proc.stderr.decode(errors="replace")[-1500:])
    return json.loads(proc.stdout.decode("utf-8"))


class TestTheEditorMarkup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
        cls.app = (_JS / "app.js").read_text(encoding="utf-8")
        m = re.search(r'<div class="modal-overlay"[^>]*id="smart-group-modal">(.*?)</div></div>\n', cls.html, re.S)
        assert m, "the smart-group editor was not found"
        cls.modal = m.group(1)

    def test_the_button_and_the_box_are_in_the_editor_before_save(self):
        self.assertRegex(self.modal, r'<button class="btn-secondary" id="sg-preview-btn" data-action="previewSmartGroup">Preview members</button>')
        self.assertRegex(self.modal, r'<div id="sg-preview" class="[^"]*" role="status" aria-live="polite"></div>')
        self.assertLess(self.modal.index('id="sg-preview-btn"'), self.modal.index('data-action="saveSmartGroup"'))

    def test_every_field_of_the_form_but_the_name_is_a_rule_the_preview_reads(self):
        fields = set(re.findall(r'id="(sg-[a-z]+)"', self.modal)) - {"sg-name", "sg-preview", "sg-preview-btn"}
        self.assertGreaterEqual(len(fields), 7, "control: the form's fields were found")
        body = srcpin.js_function(self.app, "_smartGroupRulesFromForm")
        self.assertEqual({f for f in fields if "'%s'" % f not in body}, set(), "a field of the form is not read into the rules")

    def test_the_preview_and_the_save_read_the_form_through_the_one_function(self):
        self.assertIn("_smartGroupRulesFromForm()", srcpin.js_function(self.app, "previewSmartGroup"))
        self.assertIn("_smartGroupRulesFromForm()", srcpin.js_function(self.app, "saveSmartGroup"))
        self.assertNotIn("rules.mem_gt", srcpin.js_function(self.app, "saveSmartGroup"), "the save builds rules of its own again")

    def test_the_note_names_the_number_the_server_caps_at(self):
        self.assertEqual(api.smart_group_handlers_mod.PREVIEW_HOSTS, 50, "the note in the dictionary says 50")

    def test_the_new_strings_are_in_six_languages(self):
        rows = dict_rows((_JS / "i18n.js").read_text(encoding="utf-8"))
        for key in ("Preview members", "hosts match", "host matches", "The first 50 are shown.", "Could not preview the members",
                    "Checking…", "at least one rule is required"):
            with self.subTest(key=key):
                self.assertIn(key, rows)
                self.assertEqual(set(rows[key]), {"zh", "hi", "es", "ar", "de", "fr"})
        source = self.html + "\n".join(p.read_text(encoding="utf-8") for p in _JS.glob("app*.js"))
        for key in ("Preview members", "hosts match", "host matches", "Could not preview the members"):
            self.assertIn(key, source)

    def test_the_guide_and_the_api_table_name_it(self):
        doc = (_ROOT / "docs" / "sites.md").read_text(encoding="utf-8")
        self.assertIn("**Preview members**", doc)
        self.assertRegex(doc, r"\| POST \| `/api/smart-groups/preview` \|")


@unittest.skipUnless(_GATE_NODE, "node is not installed")
class TestTheEditorFunctionsInV8(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _NODE:
            browser_required.skip_or_fail("node is not installed")
        cls.out = run_ui()

    def test_no_scenario_threw(self):
        self.assertEqual({k: v for k, v in self.out.items() if isinstance(v, dict) and "threw" in v}, {})
        self.assertEqual(set(self.out), set(_SCENARIOS))

    def test_the_form_becomes_the_rules_a_save_sends(self):
        self.assertEqual(self.out["rules_empty"], {})
        self.assertEqual(self.out["rules_full"], {"group": "web", "tag": "prod", "os_contains": "Debian", "mem_gt": 80.0, "disk_gt": 90.5,
                                                  "drift": True, "reboot_required": True})

    def test_the_preview_sends_the_rules_a_save_sends(self):
        calls = self.out["preview_and_save_send_the_same_rules"]["calls"]
        self.assertEqual([c[:2] for c in calls], [["POST", "/smart-groups/preview"], ["POST", "/smart-groups"]])
        rules = {"group": "db", "mem_gt": 70.0, "reboot_required": True}
        self.assertEqual(calls[0][2], {"rules": rules})
        self.assertEqual(calls[1][2], {"name": "dbs", "rules": rules})
        calls = self.out["edit_saves_the_same_rules_too"]["calls"]
        self.assertEqual([c[:2] for c in calls], [["POST", "/smart-groups/preview"], ["PATCH", "/smart-groups/hot"]])
        self.assertEqual(calls[0][2]["rules"], calls[1][2]["rules"])

    def test_the_count_the_names_and_the_cap_note(self):
        r = self.out["count_and_names"]
        self.assertIn("<strong>120</strong> hosts match", r["html"])
        self.assertEqual(r["html"].count("data-sg-host"), 50)
        self.assertIn('data-id="h0">host-0</div>', r["html"])
        self.assertIn("The first 50 are shown.", r["html"])
        self.assertIn("scroll-cap-sm", r["html"], "the list scrolls inside a box")
        self.assertFalse(r["disabled"])
        self.assertIn("<strong>1</strong> host matches", self.out["one_host"])
        self.assertNotIn("are shown", self.out["one_host"])
        none = self.out["no_host"]
        self.assertIn("<strong>0</strong> hosts match", none)
        self.assertNotIn("data-sg-host", none)
        self.assertNotIn("are shown", self.out["every_host_shown_says_nothing_about_a_cap"])

    def test_a_name_and_an_id_are_escaped(self):
        html = self.out["markup_in_a_name_and_an_id"]
        self.assertNotIn("<img", html)
        self.assertNotIn("<svg", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertNotIn('data-id="x">', html)
        self.assertIn('data-id="y">y</div>', html, "a host without a name is listed by its id")

    def test_an_error_is_shown_as_text_and_the_button_comes_back(self):
        r = self.out["an_error_is_text"]
        self.assertIn("at least one rule is required", r["html"])
        self.assertNotIn("hosts match", r["html"])
        self.assertFalse(r["disabled"])
        self.assertNotIn("<b", self.out["an_error_with_markup_is_text"])
        self.assertIn("&lt;b onmouseover=1&gt;", self.out["an_error_with_markup_is_text"])
        failed = self.out["a_failed_request"]
        self.assertIn("Could not preview the members", failed["html"])
        self.assertFalse(failed["disabled"])
        self.assertIn("Could not preview the members", self.out["no_answer"])
        self.assertIn("Could not preview the members", self.out["a_malformed_answer"])

    def test_the_handler_never_writes_the_buttons_disabled_flag(self):
        """The button's busy state belongs to the dispatcher (_btnInflight). A handler that disabled its own button made the dispatcher
        step aside, so nothing gave focus back after a press from the keyboard: it stayed on the body."""
        for name in ("count_and_names", "an_error_is_text", "a_failed_request", "the_handler_leaves_the_button_to_the_dispatcher",
                     "an_answer_after_a_rule_changed_is_dropped"):
            with self.subTest(scenario=name):
                self.assertEqual(self.out[name]["writes"], [], "the editor's own functions wrote a disabled flag")
        r = self.out["the_handler_leaves_the_button_to_the_dispatcher"]
        self.assertEqual(r["during"], {"disabled": False, "text": "Checking…"})
        self.assertIn("<strong>5</strong> hosts match", r["html"])

    def test_the_dispatcher_dims_the_button_while_the_server_works_and_gives_focus_back(self):
        r = self.out["dispatcher_dims_the_button_and_gives_focus_back"]
        self.assertEqual(r["during"], {"disabled": True, "busy": "true", "inflight": True, "focus": False, "text": "Checking…"})
        self.assertEqual({k: r["after"][k] for k in ("disabled", "busy", "inflight", "focus")},
                         {"disabled": False, "busy": None, "inflight": False, "focus": True})
        self.assertIn("<strong>1</strong> host matches", r["html"])
        self.assertEqual(r["writes"], [["btn", True], ["btn", False]], "the handler wrote the flag as well as the dispatcher")

    def test_a_button_whose_handler_disables_it_gets_focus_back_too(self):
        """Older handlers disable the button they were started from, before their first await: a scan of the 810 async handlers that a
        data-action starts finds 35 besides this one that set a disabled flag in their body. The dispatcher read nothing before them
        and stepped aside, so the focus they dropped never came back."""
        r = self.out["a_button_whose_handler_disables_it_gets_focus_back"]
        self.assertEqual((r["during"]["disabled"], r["during"]["focus"], r["during"]["busy"]), (True, False, None),
                         "the handler's own state is left to the handler")
        self.assertEqual((r["after"]["disabled"], r["after"]["focus"]), (False, True))

    def test_control_without_the_note_the_focus_is_lost_as_it_was(self):
        """The instrument can see the defect: the same handler and a dispatcher that did not read the focus first."""
        self.assertEqual(self.out["control_without_the_note_a_disabled_button_stays_without_focus"]["after"]["focus"], False)

    def test_focus_that_moved_meanwhile_is_not_taken_back(self):
        r = self.out["focus_that_moved_is_not_taken_back"]
        self.assertTrue(r["onField"], "focus was taken from the field the person had moved to")
        self.assertFalse(r["after"]["focus"])

    def test_a_button_left_disabled_does_not_take_focus_and_a_sync_handler_is_untouched(self):
        self.assertEqual(self.out["a_button_left_disabled_does_not_take_focus"]["after"], {
            "disabled": True, "busy": None, "inflight": False, "focus": False, "text": ""})
        r = self.out["a_handler_that_returns_nothing_is_left_alone"]
        self.assertTrue(r["same"])
        self.assertEqual((r["after"]["busy"], r["after"]["inflight"]), (None, False))

    def test_an_answer_made_for_other_rules_is_dropped(self):
        r = self.out["an_answer_after_a_rule_changed_is_dropped"]
        self.assertEqual(r["html"], "", "the answer came back after a rule changed and was drawn anyway")
        self.assertFalse(r["disabled"])

    def test_a_rule_empties_the_box_and_the_name_does_not(self):
        r = self.out["a_rule_empties_the_box_and_the_name_does_not"]
        self.assertEqual(r["seen"], {"inputs": 1, "changes": 1}, "the listeners are added once, however often the form opens")
        self.assertTrue(r["before"])
        self.assertTrue(r["afterName"], "typing the name is not a change of rules")
        self.assertFalse(r["afterRule"])

    def test_opening_the_form_empties_the_box(self):
        r = self.out["opening_the_form_empties_the_box"]
        self.assertEqual((r["html"], r["group"]), ("", "web"))


if __name__ == "__main__":
    unittest.main()
