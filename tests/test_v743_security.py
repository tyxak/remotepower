#!/usr/bin/env python3
"""v7.4.3 security review: what it found, each driven for real and watched failing first.

  1. POST /api/integrations/test was gated for admins, not for the platform operator, while the save beside
     it was. Under tenancy a tenant admin could press Test and have the server call any private address it
     can reach, then read the values back (reproduced over HTTP against a listener on the private address).
  2. GET /api/integrations handed a tenant admin the raw address of every integration and, from 7.4.3, a
     probe's path (which can carry a token) and a Prometheus instance's lines, and it listed the integrations
     bound to other tenants' hosts with their state and numbers.
  3. A window that raises no alerts was audited like one that holds notifications: the trail did not say
     which. It hides more than the other, so it has to say so.
  4. A report from a host could take its own heartbeat down with a 500: nine bare float()/int() calls on
     figures the host sends (an integer too large for a float, NaN, an infinity, a string, a list). Found by
     placing hostile values in realistic reports; 33 of every 100 such reports failed before.
"""
import copy
import importlib.util
import json
import os
import random
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402
from test_v743_prometheus import FakeClient, NODE_EXPORTER, EXPORTER, I  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _seed_module():
    spec = importlib.util.spec_from_file_location("seed_demo_743_sec", ROOT / "packaging" / "seed-demo-data.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Tenancy(_Base):
    """Two tenants, a platform operator (alice), one admin and one viewer of tenant A, and a host in each."""

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": now},
                                    "tenantB": {"name": "B", "status": "active", "created": now}})
        api.save(api.USERS_FILE, {
            "alice": {"role": "admin", "password_hash": "x", "created": now},
            "tadmin": {"role": "admin", "tenant_id": "tenantA", "password_hash": "x", "created": now},
            "tviewer": {"role": "viewer", "tenant_id": "tenantA", "password_hash": "x", "created": now}})
        api.save(api.DEVICES_FILE, {
            "hostA": {"id": "hostA", "name": "a", "tenant": "tenantA", "token": "ta", "sysinfo": {}},
            "hostB": {"id": "hostB", "name": "b", "tenant": "tenantB", "token": "tb", "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        self._client = api._integration_client
        api._integration_client = lambda inst: FakeClient({"/metrics": I.Resp(200, NODE_EXPORTER)}, base=inst["url"])

    def tearDown(self):
        api._integration_client = self._client
        super().tearDown()

    def as_user(self, user, handler, body=None, verb="POST"):
        """Run a handler for one signed-in user, with the tenant and platform checks left real."""
        names = ("verify_token",)
        saved = {n: getattr(api, n) for n in names}
        role = api.load(api.USERS_FILE)[user]["role"]
        try:
            api.verify_token = lambda t: (user, role)
            return _call_as(handler, body, verb)
        finally:
            for n, v in saved.items():
                setattr(api, n, v)


def _call_as(handler, body, verb):
    """Like test_v743_prometheus._call, but the auth gates are the real ones: only verify_token is replaced."""
    names = ("get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: box.setdefault("audit", []).append((a, k))

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class TestTheTestRouteIsThePlatformOperators(_Tenancy):

    def press(self, user):
        return self.as_user(user, api.handle_integration_test, dict(EXPORTER, prom_lines="m = node_memory_active_bytes"))

    def test_the_platform_operator_can(self):
        box = self.press("alice")
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(box["body"]["metrics"], {"m": 1840291840})

    def test_a_tenant_admin_cannot_read_a_private_address_through_it(self):
        box = self.press("tadmin")
        self.assertEqual(box["status"], 403, box)
        self.assertNotIn("metrics", json.dumps(box["body"]))

    def test_a_viewer_cannot(self):
        self.assertEqual(self.press("tviewer")["status"], 403)

    def test_with_tenancy_off_any_admin_still_can(self):
        """A single-tenant install sees no difference."""
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.press("tadmin")["status"], 200)

    def test_it_matches_the_save_beside_it(self):
        """The rule is one rule: the same callers pass or fail at both."""
        body = {"integrations": [dict(EXPORTER)]}
        for user in ("alice", "tadmin", "tviewer"):
            saved = self.as_user(user, api.handle_integrations_save, body)["status"]
            tested = self.press(user)["status"]
            self.assertEqual(saved == 200, tested == 200, f"{user}: save {saved}, test {tested}")


class TestTheListIsRedactedForATenantAdmin(_Tenancy):

    def setUp(self):
        super().setUp()
        cfg = api.load(api.CONFIG_FILE)
        cfg["integrations"] = [
            {"id": "own", "type": "prometheus_exporter", "label": "own", "url": "http://192.168.1.50:9100/?key=URLTOKEN",
             "enabled": True, "device_id": "hostA", "prom_lines": "m = LINESMARK", "prom_path": "/m?t=PATHTOKEN",
             "secret": "SECRETVALUE", "metric_thresholds": [{"metric": "m", "op": "gt", "value": 1}]},
            {"id": "foreign", "type": "custom_probe", "label": "other tenant's hub", "url": "http://192.168.1.51/",
             "enabled": True, "device_id": "hostB", "probe_path": "/PROBEPATH?k=1"},
            {"id": "shared", "type": "pihole", "label": "shared dns", "url": "http://192.168.1.2/", "enabled": True}]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def listed(self, user):
        box = self.as_user(user, api.handle_integrations_list, None, "GET")
        self.assertEqual(box["status"], 200, box)
        return box["body"]["integrations"], json.dumps(box["body"]["integrations"])

    def test_the_platform_operator_sees_everything_but_the_secret(self):
        rows, text = self.listed("alice")
        self.assertEqual({r["id"] for r in rows}, {"own", "foreign", "shared"})
        for needle in ("URLTOKEN", "PATHTOKEN", "LINESMARK", "PROBEPATH", "metric_thresholds"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("SECRETVALUE", text)

    def test_a_tenant_admin_gets_a_viewers_view(self):
        rows, text = self.listed("tadmin")
        for needle in ("URLTOKEN", "PATHTOKEN", "LINESMARK", "PROBEPATH", "metric_thresholds", "SECRETVALUE", "192.168.1."):
            self.assertNotIn(needle, text, f"a tenant admin was handed {needle!r}")
        self.assertTrue(all(r.get("url_set") is not None for r in rows))

    def test_an_integration_bound_to_another_tenants_host_is_not_listed(self):
        for user in ("tadmin", "tviewer"):
            ids = {r["id"] for r in self.listed(user)[0]}
            self.assertEqual(ids, {"own", "shared"}, user)

    def test_with_tenancy_off_an_admin_sees_what_an_admin_always_saw(self):
        api.save(api.CONFIG_FILE, dict(api.load(api.CONFIG_FILE), tenancy_enforced=False))
        api._LOAD_CACHE.clear()
        rows, text = self.listed("tadmin")
        self.assertEqual({r["id"] for r in rows}, {"own", "foreign", "shared"})
        self.assertIn("URLTOKEN", text)


class TestTheTestHandlersThatTakeADestinationFromTheRequest(_Tenancy):
    """Five handlers named *_test take a destination, a recipient or a directory from the request, and a
    tenant admin passed every one of their gates: the integration Test button (above), the mail test (any
    recipient, sent as the platform), the directory test (any LDAP address), the directory login test (a
    password oracle), the ticket-mailbox test (any host and port, no address guard) and the Proxmox test.
    The rest fire only at destinations already saved."""

    CASES = (
        ("smtp", "handle_smtp_test", {"recipient": "no-at-sign"}),
        ("ldap", "handle_ldap_test", {}),
        ("ldap user", "handle_ldap_test_user", {}),
        ("ticket mailbox", "handle_ticket_imap_test", {"host": ""}),
        ("proxmox", "handle_proxmox_test", {}),
    )

    def test_a_tenant_admin_is_refused_by_each(self):
        for label, name, body in self.CASES:
            with self.subTest(handler=label):
                box = self.as_user("tadmin", getattr(api, name), body)
                self.assertEqual(box["status"], 403, box)
                self.assertIn("platform operator", json.dumps(box["body"]))

    def test_the_platform_operator_gets_past_the_gate_and_reaches_no_network(self):
        for label, name, body in self.CASES:
            with self.subTest(handler=label):
                box = self.as_user("alice", getattr(api, name), body)
                self.assertNotEqual(box["status"], 403, box)
                self.assertLess(box["status"], 500, box)

    def test_with_tenancy_off_a_plain_admin_is_not_refused(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        for label, name, body in self.CASES:
            with self.subTest(handler=label):
                self.assertNotEqual(self.as_user("tadmin", getattr(api, name), body)["status"], 403)

    def test_a_viewer_is_still_refused_by_the_admin_gate_first(self):
        for label, name, body in self.CASES:
            with self.subTest(handler=label):
                self.assertEqual(self.as_user("tviewer", getattr(api, name), body)["status"], 403)


class TestEveryTestHandlerHasDecidedAboutTenants(unittest.TestCase):
    """The population is every handler whose name says it is a test, in every server module. A new one has to
    be put in a list, with its reason, before this passes: the instance-gate test derives its population from
    handlers that write config.json, which a Test button does not, so this class was outside it."""

    GATE = ("_require_platform_operator", "require_instance_admin_auth", "require_superadmin_auth",
            "_caller_is_superadmin")
    GATED = {
        "handle_integration_test": "the poll runs from the server and hands back what it read",
        "handle_smtp_test": "the recipient comes from the request, sent as the platform",
        "handle_ldap_test": "the directory address comes from the request",
        "handle_ldap_test_user": "a password oracle for the platform's directory",
        "handle_ticket_imap_test": "the host and port come from the request, with no address guard",
        "handle_proxmox_test": "a fresh host comes from the request",
        "handle_ip_intel_edge_test": "already instance-gated in 7.3.0",
    }
    EXEMPT = {
        "handle_webhook_test": "fires only at destinations already saved; the id picks one of them",
        "handle_siem_test": "sends to the saved SIEM address and takes nothing from the request",
        "handle_otlp_test": "sends to the saved OTLP address and takes nothing from the request",
        "handle_otlp_traces_test": "sends to the saved OTLP address and takes nothing from the request",
        "handle_audit_forward_test": "sends to the saved forwarding address and takes nothing from the request",
        "handle_push_test": "sends to the caller's own push subscriptions",
        "handle_push_channel_test": "sends to a saved channel and takes no address from the request",
        "handle_ai_test": "calls the saved provider and takes nothing from the request",
        "handle_oidc_test": "reads the saved issuer's discovery document and takes nothing from the request",
        "handle_posture_digest_test": "mails the saved recipients and takes nothing from the request",
        "handle_snmp_trap_rule_test": "matches a rule against sample text and makes no connection",
        "handle_backup_test_restore": "restores a saved backup into a scratch directory on this host",
        "handle_detection_selftest": "runs the server's own detections against built-in samples",
        "handle_self_test": "checks the server's own health and makes no outbound connection",
        "handle_device_speedtest": "queues a command for one host; the per-host gates apply",
    }

    @classmethod
    def population(cls):
        import ast
        import re
        found = {}
        for f in sorted((ROOT / "server" / "cgi-bin").glob("*.py")):
            src = f.read_text(encoding="utf-8")
            lines = src.splitlines()
            for node in ast.walk(ast.parse(src)):
                if isinstance(node, ast.FunctionDef) and re.match(r"^handle_\w*test", node.name):
                    found[node.name] = "\n".join(lines[node.lineno - 1:node.end_lineno])
        return found

    def test_the_population_is_not_empty(self):
        self.assertGreater(len(self.population()), 14, "the scan found almost nothing: it measures nothing")

    def test_every_one_is_classified_and_nothing_stale_is_listed(self):
        pop = self.population()
        listed = set(self.GATED) | set(self.EXEMPT)
        self.assertEqual(sorted(set(pop) - listed), [], "a handler named *_test has not been decided")
        self.assertEqual(sorted(listed - set(pop)), [], "a listed handler no longer exists")
        self.assertFalse(set(self.GATED) & set(self.EXEMPT))

    def test_each_gated_one_carries_the_gate(self):
        pop = self.population()
        missing = [n for n in self.GATED if not any(g in pop[n] for g in self.GATE)]
        self.assertEqual(missing, [], "these take a destination from the request and have no platform-operator gate")

    def test_every_reason_is_a_reason(self):
        for n, why in {**self.GATED, **self.EXEMPT}.items():
            self.assertGreater(len(why), 25, n)

    def test_the_exempt_ones_really_take_nothing_from_the_request(self):
        """The reason is a claim; this checks the part a regex can: none of them reads a destination key."""
        import re
        pop = self.population()
        dest = re.compile(r"""\.get\(\s*['"](url|host|server|endpoint|base_url|hostname|address|port|dsn|target|recipient)['"]""")
        offenders = {n: sorted(set(dest.findall(pop[n]))) for n in self.EXEMPT if dest.search(pop[n])}
        # the webhook test reads `url` from its saved destination, not from the request
        offenders.pop("handle_webhook_test", None)
        self.assertEqual(offenders, {})


class TestTheAuditTrailSaysWhatKindOfWindow(_Base):

    def run_as_admin(self, handler, body, *path, verb="POST"):
        saved = api.verify_token
        api.verify_token = lambda t: ("alice", "admin")
        try:
            return _call_as(lambda: handler(*path), body, verb)
        finally:
            api.verify_token = saved

    def window(self, suppress):
        body = {"reason": "backup", "scope": "global", "target": "", "start": "", "end": "", "cron": "30 2 * * *",
                "duration": 60, "events": []}
        if suppress is not None:
            body["suppress"] = suppress
        return body

    def test_a_window_that_raises_no_alerts_is_audited_as_one(self):
        box = self.run_as_admin(api.handle_maintenance_add, self.window("alerts"))
        self.assertEqual(box["status"], 200, box)
        self.assertIn("suppress=alerts", json.dumps(box["audit"]))

    def test_an_ordinary_window_says_notifications(self):
        box = self.run_as_admin(api.handle_maintenance_add, self.window(None))
        self.assertEqual(box["status"], 200, box)
        self.assertIn("suppress=notifications", json.dumps(box["audit"]))

    def test_an_edit_that_changes_the_kind_is_audited_too(self):
        wid = self.run_as_admin(api.handle_maintenance_add, self.window("notifications"))["body"]["window"]["id"]
        box = self.run_as_admin(api.handle_maintenance_update, self.window("alerts"), wid, verb="PUT")
        self.assertEqual(box["status"], 200, box)
        self.assertIn("suppress=alerts", json.dumps(box["audit"]))


class TestAWindowThatRaisesNoAlertsReachesOnlyItsOwnTenant(_Tenancy):
    """A window that raises no alerts hides more than one that holds notifications, and a tenant administrator can
    write one. The setting is one more value on a window that in_maintenance() already scopes by the window's tenant,
    so this pins the reach of the new kind. The windows go through the real add handler, so the tenant stamp is the
    real one."""

    def add(self, user, scope="global", target=""):
        now = int(time.time())
        iso = lambda ts: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))   # noqa: E731
        body = {"reason": "backup", "scope": scope, "target": target, "start": iso(now - 60), "end": iso(now + 3600),
                "cron": "", "duration": 0, "events": [], "suppress": "alerts"}
        box = self.as_user(user, api.handle_maintenance_add, body)
        api._LOAD_CACHE.clear()
        return box

    def reach(self, host):
        return (api.in_maintenance("container_stopped", {"device_id": host}) or {}).get("suppress")

    def test_a_tenant_admins_global_window_covers_its_own_hosts_and_not_another_tenants(self):
        self.assertEqual(self.add("tadmin")["status"], 200)
        self.assertEqual(self.reach("hostA"), "alerts")
        self.assertIsNone(self.reach("hostB"))

    def test_the_platform_operators_global_window_covers_every_tenant(self):
        self.assertEqual(self.add("alice")["status"], 200)
        self.assertEqual(self.reach("hostA"), "alerts")
        self.assertEqual(self.reach("hostB"), "alerts")

    def test_a_tenant_admin_cannot_aim_a_window_at_another_tenants_host(self):
        self.add("tadmin", scope="device", target="hostB")      # refused or stored, it must not reach hostB
        self.assertIsNone(self.reach("hostB"))


class TestAReportFromAHostCannotMakeItsOwnHeartbeatFail(_Base):
    """The sites, one by one, then the whole report with hostile values anywhere in it."""

    def beat(self, sysinfo, **extra):
        body = dict({"device_id": DEV, "token": "tok", "sysinfo": sysinfo}, **extra)
        raw = json.dumps(body, allow_nan=True).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            return c.status
        return None

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(DEV, {}).get("sysinfo", {})

    def test_every_site_answers_200_and_drops_what_it_cannot_read(self):
        huge, inf, nan = 10 ** 400, float("inf"), float("nan")
        si = {
            "hostname": "serverbox",
            "guard_quarantine": [{"id": "a", "orig": "/x", "check": "c", "ts": inf}, {"id": "b", "ts": "x"}],
            "custom_metrics": {"bad_big": huge, "bad_nan": nan, "good": 1.5},
            "mounts": [{"path": "/", "percent": 50.0, "used_gb": huge, "total_gb": inf, "fstype": "ext4"}],
            "clock": {"synced": True, "offset_ms": huge},
            "top_processes": [{"pid": 1, "name": "a", "cpu": "<svg onload=1>", "mem": {"x": 1}},
                              {"pid": 2, "name": "b", "cpu": huge, "mem": [1]}, {"pid": 3, "name": "c", "cpu": nan, "mem": 2.5}],
            "platform_health": {"fans": [{"name": "f1", "rpm": inf}, {"name": "f2", "rpm": huge}, {"name": "f3", "rpm": 1200}]},
            "last_boot": inf,
        }
        self.assertEqual(self.beat(si), 200)
        got = self.stored()
        self.assertEqual(got["custom_metrics"], {"good": 1.5})
        self.assertEqual(got["mounts"][0]["used_gb"], 0.0)
        self.assertEqual(got["mounts"][0]["total_gb"], 0.0)
        self.assertNotIn("offset_ms", got["clock"])
        self.assertEqual([(p["pid"], p["cpu"], p["mem"]) for p in got["top_processes"]],
                         [(1, 0.0, 0.0), (2, 0.0, 0.0), (3, 0.0, 2.5)])
        self.assertEqual([f["rpm"] for f in got["platform_health"]["fans"]], [1200])
        self.assertNotIn("last_boot", got)
        self.assertEqual([e["ts"] for e in got["guard_quarantine"]], [0, 0])

    def test_a_good_report_is_stored_as_it_always_was(self):
        si = {"hostname": "serverbox", "custom_metrics": {"queue": 12}, "last_boot": 1700000000.9,
              "mounts": [{"path": "/", "percent": 40.0, "used_gb": 12.345, "total_gb": 100, "fstype": "ext4"}],
              "clock": {"synced": True, "offset_ms": 3.14159},
              "top_processes": [{"pid": 7, "name": "nginx", "cpu": "12.34", "mem": 1.234},
                                {"pid": 8, "name": "idle", "cpu": None, "mem": 0}],
              "platform_health": {"fans": [{"name": "cpu", "rpm": 1200.7}]}}
        self.assertEqual(self.beat(si), 200)
        got = self.stored()
        self.assertEqual(got["custom_metrics"], {"queue": 12.0})
        self.assertEqual(got["last_boot"], 1700000000)
        self.assertEqual((got["mounts"][0]["used_gb"], got["mounts"][0]["total_gb"]), (12.35, 100.0))
        self.assertEqual(got["clock"]["offset_ms"], 3.1)
        self.assertEqual([(p["cpu"], p["mem"]) for p in got["top_processes"]], [(12.3, 1.23), (0.0, 0.0)])
        self.assertEqual(got["platform_health"]["fans"][0]["rpm"], 1200)

    def test_hostile_values_placed_anywhere_in_a_realistic_report_never_make_a_500(self):
        seed = _seed_module()
        templates = [copy.deepcopy(d["sysinfo"]) for d in seed.build_devices().values()
                     if d.get("sysinfo") and not d.get("agentless")]
        self.assertGreater(len(templates), 8, "the population is the seeded fleet")
        hostile = [10 ** 400, -10 ** 400, float("nan"), float("inf"), -float("inf"), 1e308, -1e308, 2 ** 63, 0, -1, True,
                   None, "", "x" * 3000, "\x00", [], {}, [None], {"a": {"b": 1}}, "NaN", "1e999", "<svg onload=1>", 1.5]

        def leaves(o, path=()):
            if isinstance(o, dict):
                for k, v in o.items():
                    yield from leaves(v, path + (k,))
            elif isinstance(o, list):
                for i, v in enumerate(o[:40]):
                    yield from leaves(v, path + (i,))
            else:
                yield path

        rng = random.Random(7430)
        bad = []
        for i in range(400):
            si = copy.deepcopy(rng.choice(templates))
            paths = list(leaves(si))
            mutated = []
            for _ in range(rng.choice([1, 2, 5, 20])):
                path, value = rng.choice(paths), rng.choice(hostile)
                node = si
                for k in path[:-1]:
                    node = node[k]
                node[path[-1]] = value
                mutated.append((path, str(value)[:20]))
            extra = {"sysinfo_partial": True} if rng.random() < 0.2 else {}
            if self.beat(si, **extra) != 200:
                bad.append(mutated[:3])
        self.assertEqual(bad, [], f"{len(bad)} of 400 hostile reports did not get a 200: {bad[:3]}")

    def test_the_fuzz_can_fail(self):
        """The control: a report that is not a JSON object at all is refused, not waved through."""
        raw = b'["not", "an", "object"]'
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw)
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertNotEqual(c.status, 200)


if __name__ == "__main__":
    unittest.main()
