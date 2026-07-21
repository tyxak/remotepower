"""v6.3.1 "Tr1ageMatters" — release pins + feature tests.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened). Headline: the hail-mary log sweep ("Diagnose from
logs" — bounded /var/log snapshot, secret-redacted at ingest, AI root-cause
pass) and the agentic alert triage loop (read-only evidence tools, strict-JSON
protocol, verdict + evidence trail stored on the alert).
"""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v631-"))
_spec = importlib.util.spec_from_file_location("api_v631_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.3.1"
CODENAME = "Tr1ageMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


def _call(handler, *args):
    """Drive a handler; return (status, body) captured from respond()'s
    HTTPError (the post-v6.1.2 contract — never stub api.respond)."""
    try:
        handler(*args)
    except api.HTTPError as e:
        return e.status, e.body
    except SystemExit:
        pass
    return None, None


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, V)

    def test_agent_versions(self):
        self.assertIn(
            f"VERSION      = '{V}'",
            (_ROOT / "client/remotepower-agent.py").read_text(),
        )
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{V}", (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={V}", _html())

    def test_no_stale_cachebust(self):
        self.assertNotIn("?v=6.3.0", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f'## v{V} — "{CODENAME}"', (_ROOT / "CHANGELOG.md").read_text()[:400])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{V}.md").exists())

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 3, f"expected exactly 3 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{V}", _html())

    def test_whats_new_cards_capped_at_three(self):
        self.assertEqual(_html().count("What's new — v"), 3)


class TestModuleBinding(unittest.TestCase):
    """The subsystem lives in ai_triage_handlers.py, bound the standard way."""

    def test_names_bound_and_sourced_from_module(self):
        import inspect
        for name in ("handle_log_sweep_run", "handle_log_sweep_get",
                     "handle_log_sweep_diagnose", "handle_alert_ai_triage",
                     "_ingest_log_sweep", "_redact_log_line",
                     "_run_alert_triage", "_parse_triage_json",
                     "_sweep_excerpt", "_triage_tools"):
            fn = getattr(api, name)
            self.assertEqual(fn.__module__, "ai_triage_handlers", name)
            self.assertTrue(inspect.getsource(fn), name)

    def test_routes_present(self):
        rows = [r for r in api._PATTERN_ROUTE_DEFS
                if "log-sweep" in str(r) or "ai-triage" in str(r)]
        self.assertEqual(len(rows), 5, rows)   # wave 2 added /ai-triage/feedback

    def test_openapi_covers_the_new_routes(self):
        routes = api._dispatcher_routes()
        self.assertIn(("POST", "/api/devices/{device_id}/log-sweep/run"), routes)
        self.assertIn(("POST", "/api/devices/{device_id}/log-sweep/diagnose"), routes)
        self.assertIn(("GET", "/api/devices/{device_id}/log-sweep"), routes)
        # Non-devices prefix routes are templated as /api/alerts/{id} (the
        # same collapsed form ack/resolve/unack document under).
        self.assertIn(("POST", "/api/alerts/{id}"), routes)

    def test_prompts_registered(self):
        import ai_provider
        for key in ("log_sweep_rca", "alert_triage"):
            self.assertIn(key, ai_provider.SYSTEM_PROMPTS, key)
            self.assertIn(key, api._AI_PROMPT_LABELS, key)


class TestRedaction(unittest.TestCase):
    def test_kv_secrets(self):
        red = api._redact_log_line("db password=hunter2 api_key: sk-live-123 client_secret='abc12345'")
        self.assertNotIn("hunter2", red)
        self.assertNotIn("sk-live-123", red)
        self.assertNotIn("abc12345", red)
        self.assertIn("[REDACTED]", red)

    def test_bearer_before_kv(self):
        # `Authorization: Bearer <tok>` — the KV pass alone would consume
        # "Bearer" as the value and leave the token; ordering matters.
        red = api._redact_log_line("Authorization: Bearer abcdef123456789")
        self.assertNotIn("abcdef123456789", red)

    def test_url_credentials(self):
        red = api._redact_log_line("fetch https://user:s3cretpw@host.example/x failed")
        self.assertNotIn("s3cretpw", red)
        self.assertIn("user:[REDACTED]@", red)

    def test_plain_lines_untouched(self):
        line = "Jul 21 host kernel: eth0 link up 1000Mbps"
        self.assertEqual(api._redact_log_line(line), line)


class TestIngest(unittest.TestCase):
    def setUp(self):
        api.save(api.LOG_SWEEP_FILE, {})

    def test_caps_redacts_and_stores(self):
        sweep = {
            "files": [{"path": "/var/log/app.log", "mtime": 5, "size": 100,
                       "score": 3.5,
                       "lines": ["ok line", "password=topsecret99"]}],
            "scanned": 4, "skipped": 1,
        }
        api._ingest_log_sweep("dev1", sweep)
        rec = api.load(api.LOG_SWEEP_FILE)["dev1"]
        self.assertEqual(rec["file_count"], 1)
        self.assertEqual(rec["scanned"], 4)
        joined = "\n".join(rec["files"][0]["lines"])
        self.assertNotIn("topsecret99", joined)
        self.assertIn("ok line", joined)

    def test_server_side_caps_do_not_trust_the_agent(self):
        big = {"files": [{"path": f"/var/log/f{i}.log", "mtime": 0, "size": 1,
                          "lines": ["x" * 2000] * 500} for i in range(200)]}
        api._ingest_log_sweep("dev1", big)
        rec = api.load(api.LOG_SWEEP_FILE)["dev1"]
        self.assertLessEqual(rec["file_count"], 48)
        self.assertLessEqual(rec["total_bytes"], 320 * 1024 + 2048)
        for f in rec["files"]:
            for ln in f["lines"]:
                self.assertLessEqual(len(ln), 1024)

    def test_keeps_request_stamp_and_prior_ai(self):
        api.save(api.LOG_SWEEP_FILE, {"dev1": {"requested_at": 111,
                                               "ai": {"summary": "old"}}})
        api._ingest_log_sweep("dev1", {"files": [
            {"path": "/var/log/a", "mtime": 0, "size": 1, "lines": ["l"]}]})
        rec = api.load(api.LOG_SWEEP_FILE)["dev1"]
        self.assertEqual(rec["requested_at"], 111)
        self.assertEqual(rec["ai"]["summary"], "old")

    def test_garbage_shapes_do_not_raise(self):
        for junk in (None, [], "x", {"files": "nope"},
                     {"files": [{"path": "/p", "lines": "no"}, 7]},
                     {"files": [{"path": "/p", "lines": ["a"], "mtime": "NaNny"}],
                      "scanned": "many"}):
            api._ingest_log_sweep("dev1", junk)   # must not raise

    def test_heartbeat_wires_the_ingest(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("if 'log_sweep' in body and isinstance(body['log_sweep'], dict):", src)
        self.assertIn("_ingest_log_sweep(dev_id, body['log_sweep'])", src)


class TestForceFlagContract(unittest.TestCase):
    """The 'flag the server never sets / the agent never honours' class."""

    def test_server_persists_and_delivers_the_flag(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("if dev.get('force_log_sweep'):", src)
        self.assertIn("saved_dev['force_log_sweep'] = True", src)
        self.assertIn("if saved_dev.get('force_log_sweep'):", src)
        self.assertIn("common_resp['force_log_sweep'] = True", src)

    def test_all_three_agents_honour_it(self):
        for rel in ("client/remotepower-agent.py",
                    "client/remotepower-agent-mac.py",
                    "client/remotepower-agent-win.py"):
            src = (_ROOT / rel).read_text()
            self.assertIn("resp.get('force_log_sweep')", src, rel)
            self.assertIn("def collect_log_sweep", src, rel)
            self.assertIn("payload['log_sweep']", src, rel)


class TestSweepHandlers(unittest.TestCase):
    def setUp(self):
        self._orig_verify = api.verify_token
        self._orig_get_token = api.get_token_from_request
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api.save(api.DEVICES_FILE, {"dev1": {"name": "web01", "os": "Linux"}})
        api.save(api.LOG_SWEEP_FILE, {})

    def tearDown(self):
        api.verify_token = self._orig_verify
        api.get_token_from_request = self._orig_get_token

    def test_run_sets_flag_and_stamp(self):
        status, body = _call(api.handle_log_sweep_run, "dev1")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(api.load(api.DEVICES_FILE)["dev1"].get("force_log_sweep"))
        self.assertGreater(api.load(api.LOG_SWEEP_FILE)["dev1"]["requested_at"], 0)

    def test_run_unknown_device_404(self):
        status, _ = _call(api.handle_log_sweep_run, "nope")
        self.assertEqual(status, 404)

    def test_get_reports_pending(self):
        _call(api.handle_log_sweep_run, "dev1")
        status, body = _call(api.handle_log_sweep_get, "dev1")
        self.assertEqual(status, 200)
        self.assertTrue(body["pending"])
        api._ingest_log_sweep("dev1", {"files": [
            {"path": "/var/log/a", "mtime": 0, "size": 1, "lines": ["boom"]}]})
        status, body = _call(api.handle_log_sweep_get, "dev1")
        self.assertFalse(body["pending"])
        self.assertEqual(body["file_count"], 1)

    def test_diagnose_needs_a_sweep(self):
        status, body = _call(api.handle_log_sweep_diagnose, "dev1")
        self.assertEqual(status, 400)

    def test_diagnose_calls_ai_and_stores_summary(self):
        api._ingest_log_sweep("dev1", {"files": [
            {"path": "/var/log/nginx/error.log", "mtime": 0, "size": 1,
             "score": 9, "lines": ["upstream timed out"]}]})
        seen = {}

        def fake_ai(system_prompt, user_prompt, key):
            seen["key"] = key
            seen["prompt"] = user_prompt
            return {"ok": True, "text": "Verdict: upstream dead."}

        orig = api._call_ai_with_prompts
        api._call_ai_with_prompts = fake_ai
        try:
            status, body = _call(api.handle_log_sweep_diagnose, "dev1")
        finally:
            api._call_ai_with_prompts = orig
        self.assertEqual(status, 200)
        self.assertEqual(seen["key"], "log_sweep_rca")
        self.assertIn("upstream timed out", seen["prompt"])
        self.assertIn("web01", seen["prompt"])
        stored = api.load(api.LOG_SWEEP_FILE)["dev1"]["ai"]
        self.assertEqual(stored["summary"], "Verdict: upstream dead.")

    def test_diagnose_provider_error_is_502_not_200(self):
        api._ingest_log_sweep("dev1", {"files": [
            {"path": "/var/log/a", "mtime": 0, "size": 1, "lines": ["x"]}]})
        orig = api._call_ai_with_prompts
        api._call_ai_with_prompts = lambda *a: {"ok": False, "error": "boom"}
        try:
            status, body = _call(api.handle_log_sweep_diagnose, "dev1")
        finally:
            api._call_ai_with_prompts = orig
        self.assertEqual(status, 502)


class TestTriageParsing(unittest.TestCase):
    def test_bare_json(self):
        self.assertEqual(api._parse_triage_json('{"action":"verdict"}'),
                         {"action": "verdict"})

    def test_fenced_json_with_prose(self):
        t = 'Sure!\n```json\n{"action":"tool","tool":"journal_tail","args":{}}\n```'
        self.assertEqual(api._parse_triage_json(t)["tool"], "journal_tail")

    def test_garbage_is_none(self):
        self.assertIsNone(api._parse_triage_json("no json here"))
        self.assertIsNone(api._parse_triage_json(""))
        self.assertIsNone(api._parse_triage_json(None))


class TestTriageLoop(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"dev1": {
            "name": "web01", "journal": ["line one", "ERROR two"],
            "services": [{"name": "nginx", "status": "failed"}],
            "sysinfo": {"cpu_percent": 5},
        }})
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.save(api.LOG_SWEEP_FILE, {})
        api.save(api.CMD_OUTPUT_FILE, {})
        self.alert = {"id": "al1", "event": "service_down", "severity": "high",
                      "device_id": "dev1", "ts": int(time.time()),
                      "payload": {"service": "nginx"}}

    def _run(self, replies):
        it = iter(replies)

        def fake_ai(system_prompt, user_prompt, key):
            self.prompts.append(user_prompt)
            return {"ok": True, "text": next(it)}

        self.prompts = []
        orig = api._call_ai_with_prompts
        api._call_ai_with_prompts = fake_ai
        try:
            return api._run_alert_triage(self.alert, "dev1",
                                         api.load(api.DEVICES_FILE)["dev1"])
        finally:
            api._call_ai_with_prompts = orig

    def test_tool_then_verdict(self):
        out = self._run([
            '{"action":"tool","tool":"journal_tail","args":{"lines":10},"why":"check errors"}',
            '{"action":"verdict","root_cause":"nginx died","confidence":"high",'
            '"evidence":["journal: ERROR two"],"recommended_action":"restart nginx"}',
        ])
        self.assertEqual(out["verdict"]["root_cause"], "nginx died")
        self.assertEqual(len(out["steps"]), 1)
        self.assertEqual(out["steps"][0]["tool"], "journal_tail")
        # the tool's result must actually reach the next prompt
        self.assertIn("ERROR two", self.prompts[1])

    def test_tool_budget_is_hard(self):
        replies = ['{"action":"tool","tool":"device_summary","args":{}}'] * 10 + [
            '{"action":"verdict","root_cause":"x","confidence":"low",'
            '"evidence":[],"recommended_action":""}']
        out = self._run(replies)
        self.assertLessEqual(len(out["steps"]), 4)
        self.assertIsNotNone(out["verdict"])

    def test_unknown_tool_is_survivable(self):
        out = self._run([
            '{"action":"tool","tool":"rm_rf_slash","args":{}}',
            '{"action":"verdict","root_cause":"y","confidence":"low",'
            '"evidence":[],"recommended_action":"NONE"}',
        ])
        self.assertIn("unknown tool", self.prompts[1])
        self.assertEqual(out["verdict"]["root_cause"], "y")

    def test_unparseable_reply_gets_a_nudge(self):
        out = self._run([
            "let me think about this in prose",
            '{"action":"verdict","root_cause":"z","confidence":"low",'
            '"evidence":[],"recommended_action":""}',
        ])
        self.assertIn("not parseable JSON", self.prompts[1])
        self.assertEqual(out["verdict"]["root_cause"], "z")

    def test_tools_are_read_only_lookups(self):
        tools = api._triage_tools("dev1", api.load(api.DEVICES_FILE)["dev1"])
        self.assertEqual(
            set(tools),
            {"device_summary", "journal_tail", "services", "open_alerts",
             "recent_commands", "log_search", "log_sweep",
             "cves", "metrics_trend"})   # wave 2 added cves + metrics_trend
        self.assertIn("ERROR two", tools["journal_tail"]({}))
        self.assertIn("nginx", tools["services"]({}))
        self.assertIn("no hail-mary sweep", tools["log_sweep"]({}))
        self.assertIn('needs a "pattern"', tools["log_search"]({}))

    def test_journal_tool_redacts(self):
        devs = api.load(api.DEVICES_FILE)
        devs["dev1"]["journal"] = ["app password=supersecret1 failed"]
        api.save(api.DEVICES_FILE, devs)
        tools = api._triage_tools("dev1", devs["dev1"])
        self.assertNotIn("supersecret1", tools["journal_tail"]({}))


class TestTriageHandler(unittest.TestCase):
    def setUp(self):
        self._orig_verify = api.verify_token
        self._orig_get_token = api.get_token_from_request
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api.save(api.DEVICES_FILE, {"dev1": {"name": "web01"}})
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "al1", "event": "service_down", "severity": "high",
             "device_id": "dev1", "ts": 1}]})

    def tearDown(self):
        api.verify_token = self._orig_verify
        api.get_token_from_request = self._orig_get_token

    def test_unknown_alert_404(self):
        status, _ = _call(api.handle_alert_ai_triage, "nope")
        self.assertEqual(status, 404)

    def test_stores_verdict_on_alert(self):
        orig = api._call_ai_with_prompts
        api._call_ai_with_prompts = lambda *a: {"ok": True, "text":
            '{"action":"verdict","root_cause":"rc","confidence":"high",'
            '"evidence":["e1"],"recommended_action":"do x"}'}
        try:
            status, body = _call(api.handle_alert_ai_triage, "al1")
        finally:
            api._call_ai_with_prompts = orig
        self.assertEqual(status, 200)
        self.assertEqual(body["ai_triage"]["verdict"]["root_cause"], "rc")
        stored = api.load(api.ALERTS_FILE)["alerts"][0]
        self.assertEqual(stored["ai_triage"]["verdict"]["root_cause"], "rc")
        self.assertEqual(stored["ai_triage"]["by"], "admin")

    def test_visibility_goes_through_the_caller_filter(self):
        # The handler must resolve the alert through _filter_alerts_for_caller
        # (RBAC scope + tenant gate) — an id the filter hides is a 404, so a
        # cross-tenant caller can't even confirm the alert exists.
        orig = api._filter_alerts_for_caller
        api._filter_alerts_for_caller = lambda alerts: []
        try:
            status, _ = _call(api.handle_alert_ai_triage, "al1")
        finally:
            api._filter_alerts_for_caller = orig
        self.assertEqual(status, 404)

    def test_provider_failure_is_502(self):
        orig = api._call_ai_with_prompts
        api._call_ai_with_prompts = lambda *a: {"ok": False, "error": "down"}
        try:
            status, _ = _call(api.handle_alert_ai_triage, "al1")
        finally:
            api._call_ai_with_prompts = orig
        self.assertEqual(status, 502)


class TestAgentCollector(unittest.TestCase):
    """Drive the REAL Linux collector against a synthetic /var/log."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "rpagent_v631", _ROOT / "client/remotepower-agent.py")
        cls.ag = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.ag)

    def _sweep(self, build):
        td = tempfile.mkdtemp(prefix="rp-varlog-")
        build(Path(td))
        orig_hp, orig_uh = self.ag.host_path, self.ag.unhost_path
        self.ag.host_path = lambda p: td if p == "/var/log" else p
        self.ag.unhost_path = lambda p: p
        try:
            return self.ag.collect_log_sweep()
        finally:
            self.ag.host_path, self.ag.unhost_path = orig_hp, orig_uh

    def test_error_dense_file_ranks_first(self):
        def build(d):
            (d / "app").mkdir()
            (d / "app" / "error.log").write_text(
                "\n".join(f"ERROR request failed {i}" for i in range(50)))
            (d / "quiet.log").write_text(
                "\n".join(f"all fine {i}" for i in range(200)))
        sw = self._sweep(build)
        paths = [f["path"] for f in sw["files"]]
        self.assertEqual(len(paths), 2)
        self.assertTrue(paths[0].endswith("error.log"), paths)

    def test_skips_binary_compressed_rotated_and_old(self):
        def build(d):
            (d / "wtmp").write_bytes(b"\x00" * 64)
            (d / "app.log.gz").write_bytes(b"\x1f\x8b")
            (d / "app.log.1").write_text("rotated ERROR\n")
            old = d / "old.log"
            old.write_text("ancient ERROR\n")
            past = time.time() - 100000
            os.utime(old, (past, past))
            (d / "fresh.log").write_text("hello\n")
        sw = self._sweep(build)
        paths = [f["path"] for f in sw["files"]]
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].endswith("fresh.log"))

    def test_budgets_hold(self):
        def build(d):
            for i in range(60):
                (d / f"f{i}.log").write_text(
                    "\n".join(f"ERROR spam {j} " + "x" * 600 for j in range(300)))
        sw = self._sweep(build)
        self.assertLessEqual(len(sw["files"]), 40)
        total = sum(len(l) + 1 for f in sw["files"] for l in f["lines"])
        self.assertLessEqual(total, 256 * 1024 + 1024)
        for f in sw["files"]:
            self.assertLessEqual(len(f["lines"]), 200)


class TestFrontendWiring(unittest.TestCase):
    def test_drawer_action(self):
        app = _js("app.js")
        self.assertIn("'Diagnose from logs'", app)
        self.assertIn("openLogSweep(id, name)", app)
        self.assertIn("fileSearch:", app)

    def test_log_sweep_modal_module(self):
        ai = _js("app-ai.js")
        for sym in ("function openLogSweep", "function logSweepRun",
                    "function logSweepDiagnose", "log-sweep/diagnose"):
            self.assertIn(sym, ai)

    def test_alert_triage_ui(self):
        al = _js("app-alerts.js")
        self.assertIn('data-action="aiTriageAlert"', al)
        self.assertIn('data-action="showAlertTriage"', al)
        self.assertIn("function aiTriageAlert", al)
        self.assertIn("/ai-triage", al)

    def test_i18n_entries(self):
        i18n = _js("i18n.js")
        for key in ("'Diagnose from logs'", "'Collect logs'", "'AI verdict'"):
            self.assertIn(key, i18n)


if __name__ == "__main__":
    unittest.main()


# ── v6.3.1 wave 2: auto-triage, feedback loop, new tools, syslog watcher ─────
class TestAutoTriage(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True,
            'auto_triage': {'enabled': True, 'min_severity': 'high',
                            'daily_cap': 2}}})
        api.save(api.AI_TRIAGE_STATE_FILE, {})
        api.save(api.DEVICES_FILE, {"dev1": {"name": "web01", "journal": []}})
        now = int(time.time())
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "old", "event": "e", "severity": "high", "device_id": "dev1",
             "ts": now - 100},
            {"id": "med", "event": "e", "severity": "medium", "device_id": "dev1",
             "ts": now - 5},
            {"id": "new", "event": "e", "severity": "critical", "device_id": "dev1",
             "ts": now - 10},
        ]})
        self.calls = []
        self._orig_ai = api._call_ai_with_prompts
        # v6.3.1: auto-triage now only runs under the out-of-band scheduler
        # (never the request path) — stub it active for these tests.
        self._orig_sched = api._external_scheduler_active
        api._external_scheduler_active = lambda: True

        def fake(system_prompt, user_prompt, key):
            self.calls.append(key)
            return {"ok": True, "text":
                    '{"action":"verdict","root_cause":"auto rc","confidence":"low",'
                    '"evidence":[],"recommended_action":""}'}
        api._call_ai_with_prompts = fake

    def tearDown(self):
        api._call_ai_with_prompts = self._orig_ai
        api._external_scheduler_active = self._orig_sched

    def _triaged_ids(self):
        return [a["id"] for a in api.load(api.ALERTS_FILE)["alerts"]
                if a.get("ai_triage")]

    def test_off_by_default_in_defaults(self):
        self.assertFalse(api._AI_DEFAULTS['auto_triage']['enabled'])

    def test_disabled_makes_no_ai_calls(self):
        api.save(api.CONFIG_FILE, {'ai': {'enabled': True,
                                          'auto_triage': {'enabled': False}}})
        api.run_ai_triage_if_due()
        self.assertEqual(self.calls, [])

    def test_triages_newest_matching_alert_as_auto(self):
        api.run_ai_triage_if_due()
        # newest severity>=high alert is 'new' (critical, ts now-10);
        # 'med' is newer but below the floor.
        self.assertEqual(self._triaged_ids(), ["new"])
        stored = next(a for a in api.load(api.ALERTS_FILE)["alerts"]
                      if a["id"] == "new")
        self.assertEqual(stored["ai_triage"]["by"], "auto")

    def test_one_per_tick_and_interval_throttle(self):
        api.run_ai_triage_if_due()
        self.assertEqual(len(self._triaged_ids()), 1)
        api.run_ai_triage_if_due()   # within the min interval → no second run
        self.assertEqual(len(self._triaged_ids()), 1)

    def test_daily_cap_stops_runs(self):
        today = time.strftime('%Y-%m-%d', time.gmtime())
        api.save(api.AI_TRIAGE_STATE_FILE, {'day': today, 'count': 2,
                                            'last_run': 0})
        api.run_ai_triage_if_due()
        self.assertEqual(self.calls, [])

    def test_severity_floor(self):
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "med2", "event": "e", "severity": "medium",
             "device_id": "dev1", "ts": int(time.time())}]})
        api.run_ai_triage_if_due()
        self.assertEqual(self._triaged_ids(), [])

    def test_requires_the_out_of_band_scheduler(self):
        # v6.3.1 hardening: never run the multi-call loop on the request path.
        api._external_scheduler_active = lambda: False
        api.run_ai_triage_if_due()
        self.assertEqual(self.calls, [])
        self.assertEqual(self._triaged_ids(), [])

    def test_picks_severity_then_oldest_not_lifo(self):
        # v6.3.1 anti-starvation: within the floor, most-severe + longest-waiting
        # drains first (was newest-first LIFO, which starved the backlog).
        now = int(time.time())
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "high_new", "event": "e", "severity": "high",
             "device_id": "dev1", "ts": now - 5},
            {"id": "high_old", "event": "e", "severity": "high",
             "device_id": "dev1", "ts": now - 500},
            {"id": "crit", "event": "e", "severity": "critical",
             "device_id": "dev1", "ts": now - 50},
        ]})
        api.run_ai_triage_if_due()
        # critical outranks both highs regardless of age.
        self.assertEqual(self._triaged_ids(), ["crit"])

    def test_registered_in_both_cadence_registries(self):
        import scheduler
        self.assertIn('run_ai_triage_if_due', scheduler.CADENCE)
        from tests import apisrc
        self.assertIn("_safe(run_ai_triage_if_due, 'run_ai_triage_if_due')",
                      apisrc.api_source())


class TestTriageFeedback(unittest.TestCase):
    def setUp(self):
        self._orig_verify = api.verify_token
        self._orig_get_token = api.get_token_from_request
        self._orig_gjo = api.get_json_obj
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("op", "admin")
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "al1", "event": "e", "severity": "high", "device_id": "d",
             "ai_triage": {"verdict": {"root_cause": "rc"}, "by": "op"}},
            {"id": "al2", "event": "e", "severity": "high", "device_id": "d"},
        ]})

    def tearDown(self):
        api.verify_token = self._orig_verify
        api.get_token_from_request = self._orig_get_token
        api.get_json_obj = self._orig_gjo

    def test_stores_feedback(self):
        api.get_json_obj = lambda: {"helpful": True, "note": "spot on"}
        status, body = _call(api.handle_alert_triage_feedback, "al1")
        self.assertEqual(status, 200)
        fb = api.load(api.ALERTS_FILE)["alerts"][0]["ai_triage"]["feedback"]
        self.assertTrue(fb["helpful"])
        self.assertEqual(fb["note"], "spot on")
        self.assertEqual(fb["by"], "op")

    def test_400_without_stored_triage(self):
        api.get_json_obj = lambda: {"helpful": False}
        status, _ = _call(api.handle_alert_triage_feedback, "al2")
        self.assertEqual(status, 400)

    def test_404_unknown_alert(self):
        api.get_json_obj = lambda: {"helpful": True}
        status, _ = _call(api.handle_alert_triage_feedback, "nope")
        self.assertEqual(status, 404)


class TestWave2Tools(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"dev1": {"name": "web01"}})
        api.save(api.LOG_SWEEP_FILE, {})
        api.save(api.CVE_FINDINGS_FILE, {"dev1": {"findings": [
            {"vuln_id": "CVE-2026-1", "severity": "critical", "package": "openssl",
             "fixed_version": "3.2.1"},
            {"vuln_id": "CVE-2026-2", "severity": "low", "package": "vim",
             "ignored": True},
        ]}})
        api.save(api.METRICS_HIST_FILE, {"dev1": {"samples": [
            {"ts": int(time.time()), "mounts": [
                {"path": "/", "used_gb": 40, "total_gb": 100}]}]}})

    def _tools(self):
        return api._triage_tools("dev1", api.load(api.DEVICES_FILE)["dev1"])

    def test_menu_has_nine_tools(self):
        self.assertEqual(len(self._tools()), 9)

    def test_cves_tool(self):
        out = self._tools()["cves"]({})
        self.assertIn("CVE-2026-1", out)
        self.assertIn("openssl", out)
        self.assertNotIn("CVE-2026-2", out)   # ignored findings stay hidden

    def test_metrics_trend_tool(self):
        # v6.3.1 wave 6: reads the CPU/mem/swap/disk roll-up series (5-min
        # tier preferred), not the daily disk-mount store.
        now = int(time.time())
        five = api._rollup_merge(
            [], [{"ts": now - 300, "cpu": 12, "mem": 40, "swap": 1, "disk": 55},
                 {"ts": now, "cpu": 88, "mem": 42, "swap": 2, "disk": 55}],
            api.ROLLUP_5MIN_SEC)
        api.save(api.METRICS_ROLLUP_FILE, {"dev1": {"fivemin": five}})
        out = self._tools()["metrics_trend"]({})
        self.assertIn("cpu=", out)
        self.assertIn("5-min", out)
        self.assertIn("max 88", out)

    def test_metrics_trend_empty(self):
        api.save(api.METRICS_ROLLUP_FILE, {})
        self.assertIn("no CPU/memory roll-up", self._tools()["metrics_trend"]({}))

    def test_stale_sweep_auto_requests_a_fresh_one(self):
        api.save(api.LOG_SWEEP_FILE, {"dev1": {
            "ts": int(time.time()) - 3600, "file_count": 1,
            "files": [{"path": "/var/log/a", "mtime": 0, "score": 1,
                       "lines": ["old line"]}]}})
        out = self._tools()["log_sweep"]({})
        self.assertIn("STALE", out)
        self.assertIn("fresh sweep has been requested", out)
        self.assertTrue(api.load(api.DEVICES_FILE)["dev1"].get("force_log_sweep"))
        self.assertGreater(
            api.load(api.LOG_SWEEP_FILE)["dev1"].get("requested_at", 0), 0)

    def test_missing_sweep_auto_requests_too(self):
        out = self._tools()["log_sweep"]({})
        self.assertIn("no hail-mary sweep stored", out)
        self.assertTrue(api.load(api.DEVICES_FILE)["dev1"].get("force_log_sweep"))


class TestTicketVerdictEmbed(unittest.TestCase):
    def test_detail_carries_the_verdict(self):
        al = {"event": "service_down", "severity": "high", "ts": 1,
              "title": "nginx down", "payload": {"service": "nginx"},
              "ai_triage": {"by": "auto", "verdict": {
                  "root_cause": "OOM killed nginx",
                  "confidence": "high",
                  "evidence": ["journal: oom-killer invoked"],
                  "recommended_action": "raise memory limit"}}}
        detail = api._alert_ticket_detail(al, {"sysinfo": {}})
        self.assertIn("AI triage verdict (by auto", detail)
        self.assertIn("OOM killed nginx", detail)
        self.assertIn("journal: oom-killer invoked", detail)
        self.assertIn("raise memory limit", detail)

    def test_no_verdict_no_section(self):
        al = {"event": "service_down", "severity": "high", "ts": 1,
              "payload": {"service": "nginx"}}
        self.assertNotIn("AI triage verdict", api._alert_ticket_detail(al, {}))


class TestAutoTriageConfig(unittest.TestCase):
    def setUp(self):
        self._orig_verify = api.verify_token
        self._orig_get_token = api.get_token_from_request
        self._orig_gjo = api.get_json_obj
        self._orig_method = api.method
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api.method = lambda: "POST"
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        api.verify_token = self._orig_verify
        api.get_token_from_request = self._orig_get_token
        api.get_json_obj = self._orig_gjo
        api.method = self._orig_method

    def test_save_whitelist_roundtrip(self):
        # The classic silent-drop bug: a Settings toggle that never persists
        # because the save whitelist wasn't extended. Drive the real handler.
        api.get_json_obj = lambda: {"auto_triage": {
            "enabled": True, "min_severity": "medium", "daily_cap": 5,
            "evil_key": "x"}}
        status, _ = _call(api.handle_ai_config_set)
        self.assertEqual(status, 200)
        at = api._ai_cfg()["auto_triage"]
        self.assertTrue(at["enabled"])
        self.assertEqual(at["min_severity"], "medium")
        self.assertEqual(at["daily_cap"], 5)
        self.assertNotIn("evil_key", at)

    def test_bad_values_ignored(self):
        api.get_json_obj = lambda: {"auto_triage": {
            "min_severity": "apocalyptic", "daily_cap": 99999}}
        status, _ = _call(api.handle_ai_config_set)
        self.assertEqual(status, 200)
        at = api._ai_cfg()["auto_triage"]
        self.assertEqual(at["min_severity"], "high")   # default kept
        self.assertEqual(at["daily_cap"], 20)


class TestSyslogWatcherAndCatalog(unittest.TestCase):
    def test_subsystems_report_syslog_sources(self):
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": [
            {"token": "a", "kind": "syslog", "last_seen": 123},
            {"token": "b", "kind": "syslog", "last_seen": 456},
            {"token": "c", "kind": "alert", "last_seen": 999},
        ]})
        out = api._subsystems_status(int(time.time()))
        self.assertIn("syslog", out)
        self.assertEqual(out["syslog"]["sources"], 2)
        self.assertEqual(out["syslog"]["last_ingest"], 456)
        self.assertIn("unit", out["syslog"])

    def test_catalog_offers_the_optional_syslogd_row(self):
        import checks
        row = next((c for c in checks.CHECK_BASELINE_CATALOG
                    if c.get("id") == "rp_syslogd_running"), None)
        self.assertIsNotNone(row, "rp_syslogd_running catalog row missing")
        self.assertEqual(row["type"], "systemd_unit")
        self.assertEqual(row["param"], "remotepower-syslogd.service")
        # opt-in: tag-targeted, never fleet-wide
        self.assertEqual(row["target_kind"], "tag")

    def test_self_page_row_is_informational(self):
        app = _js("app.js")
        self.assertIn("const syslogRow", app)
        # the not-detected/not-in-use states must be 'muted', never warn/bad
        i = app.index("const syslogRow")
        block = app[i:i + 900]
        self.assertNotIn("'warn'", block)
        self.assertNotIn("'bad'", block)


class TestWave2FrontendWiring(unittest.TestCase):
    def test_settings_auto_triage_controls(self):
        html = _html()
        for el_id in ("ai-triage-auto", "ai-triage-minsev", "ai-triage-cap"):
            self.assertIn(f'id="{el_id}"', html)
        ai = _js("app-ai.js")
        self.assertIn("auto_triage:", ai)
        self.assertIn("ai-triage-minsev", ai)

    def test_feedback_and_propose_buttons(self):
        al = _js("app-alerts.js")
        self.assertIn('data-action="triageFeedback"', al)
        self.assertIn("function triageFeedback", al)
        self.assertIn('data-action="triageProposeFix"', al)
        self.assertIn("/ai-exec/propose", al)
        app = _js("app.js")
        self.assertIn("thumbsUp:", app)
        self.assertIn("thumbsDown:", app)

    def test_stats_scoreboard_served(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("'feedback_up'", src.replace('"', "'"))
