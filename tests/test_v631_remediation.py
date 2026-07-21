"""v6.3.1 wave 3 — guarded, verified auto-remediation.

The existing automation rules could already run a saved script on an event;
this wave makes that channel safe to trust: per-host cooldown, a
max-hosts-per-hour blast cap, an attempt ledger, and a verify loop that fires
`remediation_failed` (and eventually disables the rule) when the fix doesn't
clear the triggering alert.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v631rem-"))
_spec = importlib.util.spec_from_file_location("api_v631_rem", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _rule(**kw):
    r = {"id": "r-test01", "name": "Restart nginx", "enabled": True,
         "match": {"events": ["service_down"], "severities": [],
                   "device_match": {}},
         "actions": [{"type": "run_script", "script_id": "s1"}],
         "cooldown_seconds": 0,
         "host_cooldown_seconds": 3600, "max_hosts_per_hour": 3,
         "verify_seconds": 300, "disable_after_failures": 3}
    r.update(kw)
    return r


class TestGuards(unittest.TestCase):
    def setUp(self):
        api.save(api.REMEDIATIONS_FILE, {})
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}, "d2": {"name": "h2"},
                                    "d3": {"name": "h3"}, "d4": {"name": "h4"}})

    def test_first_attempt_allowed(self):
        ok, reason = api._remediation_guard_ok(_rule(), "d1", int(time.time()))
        self.assertTrue(ok, reason)

    def test_host_cooldown_blocks_a_repeat(self):
        now = int(time.time())
        api._record_remediation_attempt(_rule(), "d1", "service_down", "s1", "queued")
        ok, reason = api._remediation_guard_ok(_rule(), "d1", now)
        self.assertFalse(ok)
        self.assertEqual(reason, "host_cooldown")
        # a DIFFERENT host is still fine
        ok, _ = api._remediation_guard_ok(_rule(), "d2", now)
        self.assertTrue(ok)

    def test_blast_cap_blocks_the_nth_host(self):
        now = int(time.time())
        for d in ("d1", "d2", "d3"):
            api._record_remediation_attempt(_rule(), d, "service_down", "s1", "queued")
        ok, reason = api._remediation_guard_ok(_rule(), "d4", now)
        self.assertFalse(ok)
        self.assertEqual(reason, "blast_cap")

    def test_suppressed_attempts_do_not_count(self):
        for d in ("d1", "d2", "d3"):
            api._record_remediation_attempt(_rule(), d, "service_down", "s1",
                                            "suppressed", "blast_cap")
        ok, _ = api._remediation_guard_ok(_rule(), "d4", int(time.time()))
        self.assertTrue(ok)

    def test_ledger_is_capped(self):
        r = _rule(host_cooldown_seconds=0, max_hosts_per_hour=100)
        for i in range(520):
            api._record_remediation_attempt(r, "d1", "e", "s1", "suppressed", "x")
        attempts = api.load(api.REMEDIATIONS_FILE)["attempts"]
        self.assertLessEqual(len(attempts), 500)


class TestActionIntegration(unittest.TestCase):
    """Drive the REAL _run_automation_action run_script branch."""

    def setUp(self):
        api.save(api.REMEDIATIONS_FILE, {})
        api.save(api.CMDS_FILE, {})
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.SCRIPTS_FILE, {"scripts": [
            {"id": "s1", "name": "restart", "body": "systemctl restart nginx"}]})

    def _run(self, rule, event="service_down", dev="d1"):
        api._run_automation_action({"type": "run_script", "script_id": "s1"},
                                   event, {"device_id": dev}, dev, {}, rule)

    def test_queues_script_and_ledgers_attempt(self):
        self._run(_rule())
        q = api.load(api.CMDS_FILE).get("d1") or []
        self.assertTrue(any("systemctl restart nginx" in c for c in q))
        att = api.load(api.REMEDIATIONS_FILE)["attempts"]
        self.assertEqual(len(att), 1)
        self.assertEqual(att[0]["status"], "queued")
        self.assertIsNotNone(att[0]["verify_at"])

    def test_verify_off_records_done(self):
        self._run(_rule(verify_seconds=0))
        att = api.load(api.REMEDIATIONS_FILE)["attempts"][0]
        self.assertEqual(att["status"], "done")
        self.assertIsNone(att["verify_at"])

    def test_guard_suppression_queues_nothing(self):
        api._record_remediation_attempt(_rule(), "d1", "service_down", "s1", "queued")
        api.save(api.CMDS_FILE, {})
        self._run(_rule())
        self.assertEqual(api.load(api.CMDS_FILE).get("d1") or [], [])
        att = api.load(api.REMEDIATIONS_FILE)["attempts"]
        self.assertEqual(att[-1]["status"], "suppressed")
        self.assertEqual(att[-1]["reason"], "host_cooldown")

    def test_never_auto_fixes_a_failed_auto_fix(self):
        # The loop guard: run_script on remediation_failed must be a no-op.
        self._run(_rule(match={"events": ["remediation_failed"],
                               "severities": [], "device_match": {}}),
                  event="remediation_failed")
        self.assertEqual(api.load(api.CMDS_FILE).get("d1") or [], [])
        self.assertEqual(api.load(api.REMEDIATIONS_FILE).get("attempts") or [], [])


class TestVerifySweep(unittest.TestCase):
    def setUp(self):
        api.save(api.REMEDIATIONS_FILE, {})
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.RULES_FILE, {"rules": [_rule()]})
        self.fired = []
        self._orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **kw: self.fired.append((ev, p or {}))

    def tearDown(self):
        api.fire_webhook = self._orig_fw

    def _seed_attempt(self, verify_offset=-10, status="queued"):
        now = int(time.time())
        api.save(api.REMEDIATIONS_FILE, {"attempts": [{
            "id": "rem-1", "ts": now - 400, "rule_id": "r-test01",
            "rule_name": "Restart nginx", "device_id": "d1",
            "device_name": "h1", "event": "service_down", "script_id": "s1",
            "status": status, "reason": "", "verify_at": now + verify_offset,
        }], "last_verify": 0})

    def test_verified_when_alert_cleared(self):
        self._seed_attempt()
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.run_remediation_verify_if_due()
        att = api.load(api.REMEDIATIONS_FILE)["attempts"][0]
        self.assertEqual(att["status"], "verified")
        self.assertEqual(self.fired, [])
        rule = api.load(api.RULES_FILE)["rules"][0]
        self.assertEqual(rule.get("consecutive_failures"), 0)

    def test_failed_when_alert_still_open_fires_event(self):
        self._seed_attempt()
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "event": "service_down", "device_id": "d1"}]})
        api.run_remediation_verify_if_due()
        att = api.load(api.REMEDIATIONS_FILE)["attempts"][0]
        self.assertEqual(att["status"], "failed")
        self.assertEqual(len(self.fired), 1)
        ev, payload = self.fired[0]
        self.assertEqual(ev, "remediation_failed")
        self.assertEqual(payload["device_id"], "d1")
        self.assertEqual(payload["rule_name"], "Restart nginx")
        self.assertFalse(payload["rule_disabled"])
        rule = api.load(api.RULES_FILE)["rules"][0]
        self.assertEqual(rule.get("consecutive_failures"), 1)
        self.assertTrue(rule.get("enabled"))

    def test_consecutive_failures_disable_the_rule(self):
        api.save(api.RULES_FILE, {"rules": [
            _rule(consecutive_failures=2, disable_after_failures=3)]})
        self._seed_attempt()
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "event": "service_down", "device_id": "d1"}]})
        api.run_remediation_verify_if_due()
        rule = api.load(api.RULES_FILE)["rules"][0]
        self.assertEqual(rule.get("consecutive_failures"), 3)
        self.assertFalse(rule.get("enabled"), "rule must auto-disable")
        self.assertTrue(self.fired[0][1]["rule_disabled"])

    def test_resolved_alert_does_not_count_as_open(self):
        self._seed_attempt()
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "event": "service_down", "device_id": "d1",
             "resolved_at": int(time.time())}]})
        api.run_remediation_verify_if_due()
        self.assertEqual(api.load(api.REMEDIATIONS_FILE)["attempts"][0]["status"],
                         "verified")

    def test_not_due_yet_is_untouched(self):
        self._seed_attempt(verify_offset=600)
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.run_remediation_verify_if_due()
        self.assertEqual(api.load(api.REMEDIATIONS_FILE)["attempts"][0]["status"],
                         "queued")

    def test_interval_throttle(self):
        self._seed_attempt()
        api.save(api.ALERTS_FILE, {"alerts": []})
        st = api.load(api.REMEDIATIONS_FILE)
        st["last_verify"] = int(time.time())
        api.save(api.REMEDIATIONS_FILE, st)
        api.run_remediation_verify_if_due()
        self.assertEqual(api.load(api.REMEDIATIONS_FILE)["attempts"][0]["status"],
                         "queued")


class TestValidatorAndRegistry(unittest.TestCase):
    def test_validate_rule_carries_the_guard_knobs(self):
        rule, err = api._validate_rule({
            "name": "R", "match": {"events": ["service_down"]},
            "actions": [{"type": "run_script", "script_id": "s1"}],
            "host_cooldown_seconds": 120, "max_hosts_per_hour": 5,
            "verify_seconds": 900, "disable_after_failures": 2,
        })
        self.assertIsNone(err)
        self.assertEqual(rule["host_cooldown_seconds"], 120)
        self.assertEqual(rule["max_hosts_per_hour"], 5)
        self.assertEqual(rule["verify_seconds"], 900)
        self.assertEqual(rule["disable_after_failures"], 2)

    def test_validate_rule_clamps_nonsense(self):
        rule, err = api._validate_rule({
            "name": "R", "match": {"events": ["e"]},
            "actions": [{"type": "run_script", "script_id": "s1"}],
            "max_hosts_per_hour": 99999, "verify_seconds": -5,
        })
        self.assertIsNone(err)
        self.assertEqual(rule["max_hosts_per_hour"], 100)
        self.assertEqual(rule["verify_seconds"], 0)

    def test_event_registered_and_derived(self):
        self.assertIn("remediation_failed", api.EVENT_REGISTRY)
        self.assertIn("remediation_failed",
                      {e[0] for e in api.WEBHOOK_EVENTS})
        # severity present → it reaches the alert inbox
        self.assertEqual(api._alert_severity("remediation_failed", {}), "high")

    def test_cadence_registered_in_both_registries(self):
        import scheduler
        self.assertIn("run_remediation_verify_if_due", scheduler.CADENCE)
        from tests import apisrc
        self.assertIn(
            "_safe(run_remediation_verify_if_due, 'run_remediation_verify_if_due')",
            apisrc.api_source())

    def test_alert_whitelist_carries_rule_fields(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("'rule_name', 'rule_id', 'script_id', 'rule_disabled',", src)


class TestLedgerEndpoint(unittest.TestCase):
    def setUp(self):
        self._orig_verify = api.verify_token
        self._orig_get_token = api.get_token_from_request
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.REMEDIATIONS_FILE, {"attempts": [
            {"id": "rem-1", "ts": 10, "rule_id": "r1", "rule_name": "R",
             "device_id": "d1", "event": "e", "status": "verified"},
            {"id": "rem-2", "ts": 20, "rule_id": "r1", "rule_name": "R",
             "device_id": "ghost", "event": "e", "status": "failed"},
        ]})

    def tearDown(self):
        api.verify_token = self._orig_verify
        api.get_token_from_request = self._orig_get_token

    def _call(self):
        try:
            api.handle_remediation_log()
        except api.HTTPError as e:
            return e.status, e.body
        return None, None

    def test_lists_visible_devices_only(self):
        status, body = self._call()
        self.assertEqual(status, 200)
        ids = [a["id"] for a in body["attempts"]]
        self.assertEqual(ids, ["rem-1"])   # ghost's device isn't in DEVICES_FILE
        self.assertEqual(body["counts"], {"verified": 1})


class TestFrontendWiring(unittest.TestCase):
    def test_editor_and_ledger_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        for el_id in ("auto-host-cooldown", "auto-max-hosts", "auto-verify-s",
                      "auto-disable-after", "automation-remediations"):
            self.assertIn(f'id="{el_id}"', html)
        app = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("_loadRemediationLog", app)
        self.assertIn("host_cooldown_seconds:", app)
        self.assertIn("'remediation_failed',", app)   # FLEET_EVENTS
        self.assertIn("case 'remediation_failed':", app)


if __name__ == "__main__":
    unittest.main()
