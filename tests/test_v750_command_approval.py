#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, finding W2-F1): change approval is applied to every command a person or a schedule puts on a host.

Change approval (four-eyes) parks a command of a gated kind for a second admin. `_queue_command` and the two batch gateways did it,
and about a dozen other functions that write the command queue did not:

* a library script run (POST /api/exec/batch), a package install or removal, the file manager's writes, the compose action and
  the Docker clean-up wrote `exec:` or `compose:` into the queue themselves;
* a smart-plug power-off or cycle is a shutdown or a reboot done outside the agent;
* a scheduled command fired from the sweep, and a rollout started from a draft, were never asked at all.

What this holds:

* Each of those paths parks when its kind is gated, writes nothing to the queue, and records a confirmation that says in words what
  it will do (a file write is base64 on the wire). With the kind not gated, or approval off, each one goes on as before.
* The paths that used to write the queue themselves now also refuse a quarantined host, an audit-mode host and maintenance mode.
* A file written through the file manager is an `exec` kind; listing and reading are not.
* An approved smart-plug request, rollout start and scheduled command run when a second admin approves, and not before; the person
  who scheduled a job cannot approve its confirmation (the separation-of-duties rule sees through `scheduler(<name>)`).
* A ratchet over the whole class: every function in the server that writes the command queue asks for approval itself, calls a
  gateway, or is on a short list with the reason it does not.
"""

import ast
import glob
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-appr-"))

_spec = importlib.util.spec_from_file_location("api_v750_appr", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    FILES = ("CONFIG_FILE", "DEVICES_FILE", "CMDS_FILE", "CONFIRMATIONS_FILE", "BATCH_JOBS_FILE", "SCRIPTS_FILE", "LONGPOLL_FILE",
             "SCHEDULE_FILE", "ROLLOUTS_FILE", "USERS_FILE", "TOKENS_FILE")
    GATED = ["exec", "compose", "reboot", "shutdown", "upgrade", "update", "uninstall", "container"]
    WHO = "alice"

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-appr-d-"))
        self._saved = {n: getattr(api, n) for n in self.FILES}
        for n in self.FILES:
            setattr(api, n, self.d / self._saved[n].name)   # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        self.audit, self.logged, self.hooks = [], [], []
        for name, value in (("verify_token", lambda token=None, *a, **k: (self.WHO, "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: "POST"),
                            ("audit_log", lambda *a, **k: self.audit.append((a, k))),
                            ("log_command", lambda *a, **k: self.logged.append(a)),
                            ("fire_webhook", lambda *a, **k: self.hooks.append(a))):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        # A request that is not held would wait up to 90 s for the agent. Nothing here has an agent, so the wait fails the test at once
        # (the one test that goes on to the wait on purpose patches it again).
        def _no_wait(dev_id, timeout):
            raise AssertionError("the request went on to wait for the agent")
        p = mock.patch.object(api, "_longpoll_wait", _no_wait)
        p.start()
        self.addCleanup(p.stop)
        self.set_config(change_approval_enabled=True, approval_gated_kinds=list(self.GATED))
        self.devices = {
            "d1": {"name": "web01", "compose_projects": [{"dir": "/opt/app"}],
                   "pdu": {"kind": "tasmota", "host": "192.0.2.10"}},
            "dq": {"name": "quarantined", "quarantined": True},
            "da": {"name": "auditmode", "sysinfo": {"audit_mode": True}},
        }
        api.save(api.DEVICES_FILE, self.devices)
        api.save(api.CMDS_FILE, {})
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api.save(api.BATCH_JOBS_FILE, {"jobs": {}})
        api.save(api.SCRIPTS_FILE, {"scripts": [{"id": "a1b2c3d4", "name": "tidy", "body": "echo hello\nrm -f /tmp/x\n"}]})
        api.save(api.USERS_FILE, {"alice": {"role": "admin"}, "bob": {"role": "admin"}})
        api._LOAD_CACHE.clear()

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def set_config(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def call(self, fn, *args, body=None):
        with mock.patch.object(api, "get_json_obj", lambda: dict(body or {})), \
                mock.patch.object(api, "get_json_body", lambda: dict(body or {})), \
                mock.patch.object(api, "_read_valid", lambda model, *a, **k: dict(body or {})):
            try:
                fn(*args)
            except api.HTTPError as e:
                return e.status, e.body
        self.fail(f"{getattr(fn, '__name__', fn)} answered nothing")

    def queue(self):
        api._LOAD_CACHE.clear()
        return {k: v for k, v in (api.load(api.CMDS_FILE) or {}).items() if v}

    def pending(self):
        api._LOAD_CACHE.clear()
        return [c for c in (api.load(api.CONFIRMATIONS_FILE) or {}).get("confirmations", []) if c.get("status") == "pending"]

    def approve(self, conf_id, who="bob"):
        self.WHO = who
        return self.call(api.handle_confirmation_approve, conf_id)


class TestWhatGetsParked(_Base):

    def assert_parked(self, status, body, summary_has):
        self.assertEqual(status, 202, body)
        self.assertTrue(body.get("approval_required"), body)
        self.assertEqual(self.queue(), {}, "a parked change writes nothing to the queue")
        pend = self.pending()
        self.assertEqual(len(pend), 1, pend)
        self.assertIn(summary_has, (pend[0].get("params") or {}).get("summary", ""), pend[0])
        return pend[0]

    def test_a_library_script_run(self):
        status, body = self.call(api.handle_exec_batch, body={"script_id": "a1b2c3d4", "device_ids": ["d1"], "reason": "tidy up", "ticket_ref": "CHG-9"})
        self.assertEqual((status, body.get("parked"), body.get("queued")), (202, 1, 0))
        self.assertEqual(body["per_device"]["d1"]["reason"], "approval_required")
        pend = self.pending()
        self.assertEqual(self.queue(), {})
        self.assertEqual(len(pend), 1)
        self.assertEqual((pend[0].get("params") or {}).get("summary"), 'run script "tidy"')
        self.assertEqual((pend[0]["reason"], pend[0]["ticket_ref"]), ("tidy up", "CHG-9"), "the operator's justification rides along")
        job = (api.load(api.BATCH_JOBS_FILE) or {})["jobs"][body["job_id"]]
        self.assertFalse(job["per_device"]["d1"]["queued"], "the job record does not claim the host was queued")
        self.assertEqual(job["per_device"]["d1"]["reason"], "approval_required")

    def test_a_package_install_and_a_removal(self):
        for fn, verb in ((api.handle_install_packages, "install"), (api.handle_uninstall_packages, "uninstall")):
            with self.subTest(verb=verb):
                api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
                api._LOAD_CACHE.clear()
                status, body = self.call(fn, body={"device_ids": ["d1"], "packages": "htop"})
                pend = self.assert_parked(status, body, f"{verb} packages: htop")
                self.assertEqual(body["per_device"]["d1"]["confirmation_id"], pend["id"])

    def test_every_file_manager_write_reads_in_words(self):
        root = api._FILE_MGR_DEFAULT_ROOTS[0].rstrip("/")
        cases = (({"op": "write", "path": f"{root}/rp-x.conf", "content": "abc"}, f"write file {root}/rp-x.conf (3 bytes)"),
                 ({"op": "mkdir", "path": f"{root}/rp-dir"}, f"create folder {root}/rp-dir"),
                 ({"op": "delete", "path": f"{root}/rp-x.conf"}, f"delete {root}/rp-x.conf"),
                 ({"op": "upload", "path": f"{root}/rp-up.bin", "content": "aGVsbG8="}, f"upload file {root}/rp-up.bin (5 bytes)"))
        for body, words in cases:
            with self.subTest(op=body["op"]):
                api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
                api._LOAD_CACHE.clear()
                status, answer = self.call(api.handle_device_files, "d1", body=body)
                self.assert_parked(status, answer, words)

    def test_the_compose_action(self):
        status, body = self.call(api.handle_device_compose_action, "d1", body={"action": "restart", "dir": "/opt/app"})
        self.assert_parked(status, body, "compose:restart:/opt/app")

    def test_the_docker_cleanup_and_what_it_deletes(self):
        status, body = self.call(api.handle_device_docker_prune, "d1", body={"targets": ["images"]})
        pend = self.assert_parked(status, body, "docker clean-up")
        self.assertNotIn("DELETES", pend["params"]["summary"])
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api._LOAD_CACHE.clear()
        status, body = self.call(api.handle_device_docker_prune, "d1",
                                 body={"targets": ["volumes"], "confirm": api._DOCKER_PRUNE_CONFIRM})
        self.assert_parked(status, body, "DELETES VOLUME DATA")

    def test_a_smart_plug_off_and_cycle_but_not_on(self):
        ran = []
        with mock.patch.object(api, "_pdu_power_run", lambda pdu, action: ran.append(action) or ([{"step": action, "status": 200}], "")):
            for action, kind in (("off", "shutdown"), ("cycle", "reboot")):
                api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
                api._LOAD_CACHE.clear()
                status, body = self.call(api.handle_device_power_control, "d1", body={"action": action})
                pend = self.assert_parked(status, body, "smart plug: power")
                self.assertEqual(pend["params"]["kind"], kind)
                self.assertEqual(ran, [], "nothing was sent to the plug")
            status, body = self.call(api.handle_device_power_control, "d1", body={"action": "on"})
            self.assertEqual((status, body.get("ok"), ran), (200, True, ["on"]), "switching ON is never held")

    def test_a_scheduled_command_when_it_comes_due(self):
        api.save(api.SCHEDULE_FILE, {"jobs": [{"id": "j1", "device_id": "d1", "device_name": "web01", "command": "reboot", "run_at": 1,
                                               "cron": None, "actor": "alice", "created": 1, "recurring": False}]})
        api._LOAD_CACHE.clear()
        api.process_schedule()
        self.assertEqual(self.queue(), {}, "the reboot is not queued")
        pend = self.pending()
        self.assertEqual([(c["requested_by"], c["params"]["command"]) for c in pend], [("scheduler(alice)", "reboot")])
        self.assertIn("(parked for approval)", self.logged[-1][3])

    def test_a_scheduled_command_of_a_kind_that_is_not_gated_still_goes_straight_to_the_queue(self):
        api.save(api.SCHEDULE_FILE, {"jobs": [{"id": "j2", "device_id": "d1", "device_name": "web01", "command": "suspend", "run_at": 1,
                                               "cron": None, "actor": "alice", "created": 1, "recurring": False}]})
        api._LOAD_CACHE.clear()
        api.process_schedule()
        self.assertEqual(self.queue(), {"d1": ["suspend"]})
        self.assertEqual(self.pending(), [])

    def rollout(self, action="upgrade", state="draft"):
        roll = {"id": "r1", "name": "ring test", "action": action, "script_id": "", "rollback_script_id": "",
                "rings": [{"name": "ring 1", "selector": {"type": "ids", "ids": ["d1"]}}],
                "rings_state": [{"state": "pending", "dispatched_ids": [], "total": 0, "ok_count": 0, "failed_count": 0}],
                "auto_promote": False, "verify_minutes": 30, "health_gate": {"enabled": False, "threshold": 70},
                "state": state, "current_ring": 0, "history": [], "created_by": "alice", "created_at": 1, "updated_at": 1,
                "tenant_gate": None}
        api.save(api.ROLLOUTS_FILE, {"rollouts": [roll]})
        api._LOAD_CACHE.clear()

    def rollout_state(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.ROLLOUTS_FILE) or {})["rollouts"][0]["state"]

    def test_a_rollout_is_parked_at_start_and_stays_a_draft(self):
        self.rollout()
        status, body = self.call(api.handle_rollout_action, "r1", "start", body={"reason": "patch window"})
        self.assertEqual((status, body.get("approval_required")), (202, True), body)
        self.assertEqual(self.rollout_state(), "draft")
        self.assertEqual(self.queue(), {})
        pend = self.pending()
        self.assertEqual((pend[0]["action"], pend[0]["params"]["rollout_id"], pend[0]["reason"]), ("rollout_start", "r1", "patch window"))
        self.assertIn('start rollout "ring test"', pend[0]["params"]["summary"])

    def test_a_rollout_is_held_by_the_kind_of_what_it_runs(self):
        """With only `exec` gated, an upgrade rollout starts and a script rollout waits: the kind comes from the rollout's action."""
        self.set_config(change_approval_enabled=True, approval_gated_kinds=["exec"])
        self.rollout(action="upgrade")
        status, body = self.call(api.handle_rollout_action, "r1", "start")
        self.assertEqual((status, body.get("ok"), self.pending()), (200, True, []), body)
        self.rollout(action="script")
        status, body = self.call(api.handle_rollout_action, "r1", "start")
        self.assertEqual((status, body.get("approval_required")), (202, True), body)
        self.assertEqual(self.rollout_state(), "draft")
        for action, kind in (("reboot", "reboot"), ("self-update", "update"), ("upgrade", "upgrade"), ("script", "exec")):
            self.assertEqual(api._rollout_kind({"action": action}), kind, action)

    def test_resuming_a_paused_rollout_asks_nothing(self):
        self.rollout(state="paused")
        status, body = self.call(api.handle_rollout_action, "r1", "start")
        self.assertEqual((status, body.get("ok")), (200, True), body)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.rollout_state(), "running")


class TestWhatStillGoesStraightThrough(_Base):

    def test_with_approval_off_every_path_queues_as_before(self):
        self.set_config(change_approval_enabled=False)
        status, body = self.call(api.handle_exec_batch, body={"script_id": "a1b2c3d4", "device_ids": ["d1"]})
        self.assertEqual((status, body["queued"], body["parked"]), (202, 1, 0))
        status, body = self.call(api.handle_install_packages, body={"device_ids": ["d1"], "packages": "htop"})
        self.assertEqual((status, body["queued"], body["parked"]), (202, 1, 0))
        status, body = self.call(api.handle_device_compose_action, "d1", body={"action": "restart", "dir": "/opt/app"})
        self.assertEqual((status, body.get("queued")), (200, "compose:restart:/opt/app"))
        self.assertEqual(self.pending(), [])
        self.assertEqual(len(self.queue()["d1"]), 3)

    def test_a_kind_that_is_not_gated_is_not_held(self):
        """The gate is by kind: with only reboot and shutdown gated, a script run and a file write are not held."""
        self.set_config(change_approval_enabled=True, approval_gated_kinds=["reboot", "shutdown"])
        status, body = self.call(api.handle_exec_batch, body={"script_id": "a1b2c3d4", "device_ids": ["d1"]})
        self.assertEqual((status, body["queued"]), (202, 1))
        root = api._FILE_MGR_DEFAULT_ROOTS[0].rstrip("/")
        with mock.patch.object(api, "_longpoll_wait", lambda dev, t: ("timeout", None)):
            status, body = self.call(api.handle_device_files, "d1", body={"op": "mkdir", "path": f"{root}/rp-dir"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.pending(), [])

    def test_a_file_manager_read_is_never_held(self):
        self.assertEqual(api._command_kind("files:list:L2V0Yw=="), "other")
        self.assertEqual(api._command_kind("files:read:L2V0Yy9ob3N0cw=="), "other")
        for op in ("write", "mkdir", "delete", "upload"):
            self.assertEqual(api._command_kind(f"files:{op}:L2V0Yw=="), "exec", op)


class TestTheSharedRefusals(_Base):
    """These paths wrote the queue themselves, so they did not refuse a host that every other command path refuses."""

    def test_a_script_run_and_a_package_install_refuse_quarantined_and_audit_mode_hosts(self):
        self.set_config(change_approval_enabled=False)
        status, body = self.call(api.handle_exec_batch, body={"script_id": "a1b2c3d4", "device_ids": ["d1", "dq", "da"]})
        self.assertEqual(status, 202)
        self.assertEqual({d: (e["queued"], e.get("reason")) for d, e in body["per_device"].items()},
                         {"d1": (True, None), "dq": (False, "quarantined"), "da": (False, "audit_mode")})
        self.assertEqual(self.queue(), {"d1": [self.queue()["d1"][0]]})
        status, body = self.call(api.handle_install_packages, body={"device_ids": ["dq", "da"], "packages": "htop"})
        self.assertEqual({d: e.get("reason") for d, e in body["per_device"].items()}, {"dq": "quarantined", "da": "audit_mode"})

    def test_maintenance_mode_holds_a_script_run_a_compose_action_and_a_cleanup(self):
        self.set_config(change_approval_enabled=False, maintenance_mode=True, maintenance_reason="upgrade")
        status, body = self.call(api.handle_exec_batch, body={"script_id": "a1b2c3d4", "device_ids": ["d1"]})
        self.assertEqual((status, body.get("maintenance")), (503, True))
        status, body = self.call(api.handle_device_compose_action, "d1", body={"action": "restart", "dir": "/opt/app"})
        self.assertEqual((status, body.get("maintenance")), (503, True))
        status, body = self.call(api.handle_device_docker_prune, "d1", body={"targets": ["images"]})
        self.assertEqual((status, body.get("maintenance")), (503, True))
        self.assertEqual(self.queue(), {})

    def test_a_cleanup_and_a_compose_action_refuse_a_quarantined_host(self):
        self.set_config(change_approval_enabled=False)
        for dev in ("dq", "da"):
            self.devices[dev]["compose_projects"] = [{"dir": "/opt/app"}]
        api.save(api.DEVICES_FILE, self.devices)
        api._LOAD_CACHE.clear()
        for dev in ("dq", "da"):
            status, _ = self.call(api.handle_device_docker_prune, dev, body={"targets": ["images"]})
            self.assertEqual(status, 409, dev)
            status, _ = self.call(api.handle_device_compose_action, dev, body={"action": "restart", "dir": "/opt/app"})
            self.assertEqual(status, 409, dev)
        self.assertEqual(self.queue(), {})

    def test_a_smart_plug_is_not_stopped_by_quarantine(self):
        """Cutting the power is how a host that is no longer trusted is stopped: quarantine and audit mode stop commands to the agent."""
        self.set_config(change_approval_enabled=False)
        self.devices["dq"]["pdu"] = {"kind": "tasmota", "host": "192.0.2.11"}
        api.save(api.DEVICES_FILE, self.devices)
        api._LOAD_CACHE.clear()
        with mock.patch.object(api, "_pdu_power_run", lambda pdu, action: ([{"step": action, "status": 200}], "")):
            status, body = self.call(api.handle_device_power_control, "dq", body={"action": "off"})
        self.assertEqual((status, body.get("ok")), (200, True))

    def test_a_plug_at_a_blocked_address_is_a_400_and_not_a_green_result(self):
        """The refusal used to be a respond() inside a try/except Exception, which turned it into a result row and a 200."""
        self.set_config(change_approval_enabled=False)
        self.devices["d1"]["pdu"] = {"kind": "tasmota", "host": "127.0.0.1"}
        api.save(api.DEVICES_FILE, self.devices)
        api._LOAD_CACHE.clear()
        status, body = self.call(api.handle_device_power_control, "d1", body={"action": "off"})
        self.assertEqual(status, 400)
        self.assertIn("blocked", body["error"])


class TestApprovalRunsWhatWasParked(_Base):

    def park_a_scheduled_reboot(self):
        api.save(api.SCHEDULE_FILE, {"jobs": [{"id": "j1", "device_id": "d1", "device_name": "web01", "command": "reboot", "run_at": 1,
                                               "cron": None, "actor": "alice", "created": 1, "recurring": False}]})
        api._LOAD_CACHE.clear()
        api.process_schedule()
        return self.pending()[0]["id"]

    def test_the_person_who_scheduled_a_job_cannot_approve_it(self):
        cid = self.park_a_scheduled_reboot()
        status, body = self.approve(cid, who="alice")
        self.assertEqual(status, 403, body)
        self.assertIn("different admin", body["error"])
        self.assertEqual(self.queue(), {})

    def test_a_second_admin_approves_and_it_is_queued(self):
        cid = self.park_a_scheduled_reboot()
        status, body = self.approve(cid, who="bob")
        self.assertEqual((status, body.get("ok")), (200, True), body)
        self.assertEqual(self.queue(), {"d1": ["reboot"]})

    def test_an_approved_power_off_reaches_the_plug_once(self):
        ran = []
        with mock.patch.object(api, "_pdu_power_run", lambda pdu, action: ran.append((pdu["host"], action)) or ([{"step": action, "status": 200}], "")):
            status, body = self.call(api.handle_device_power_control, "d1", body={"action": "off"})
            self.assertEqual((status, ran), (202, []))
            status, body = self.approve(body["confirmation_id"], who="bob")
        self.assertEqual((status, body.get("ok"), ran), (200, True, [("192.0.2.10", "off")]))

    def test_an_approved_power_off_that_the_plug_does_not_answer_is_a_failure_and_not_a_success(self):
        with mock.patch.object(api, "_pdu_power_run", lambda pdu, action: ([{"step": action, "error": "timed out"}], "")):
            status, body = self.call(api.handle_device_power_control, "d1", body={"action": "off"})
            status, body = self.approve(body["confirmation_id"], who="bob")
        self.assertEqual(status, 500, body)
        self.assertIn("did not answer", body["error"])

    def test_an_approved_rollout_starts_and_a_stale_one_does_not(self):
        TestWhatGetsParked.rollout(self)
        status, body = self.call(api.handle_rollout_action, "r1", "start")
        cid = body["confirmation_id"]
        status, body = self.approve(cid, who="bob")
        self.assertEqual((status, body.get("ok")), (200, True), body)
        self.assertEqual(TestWhatGetsParked.rollout_state(self), "running")
        # a start that was parked, then cancelled before anyone approved it, is not started by the approval
        self.WHO = "alice"
        TestWhatGetsParked.rollout(self)
        status, body = self.call(api.handle_rollout_action, "r1", "start")
        cid = body["confirmation_id"]
        TestWhatGetsParked.rollout(self, state="cancelled")
        status, body = self.approve(cid, who="bob")
        self.assertEqual(status, 500, body)
        self.assertIn("not waiting to start", body["error"])
        self.assertEqual(TestWhatGetsParked.rollout_state(self), "cancelled")

    def test_a_rollback_waits_for_a_second_admin_when_scripts_are_gated(self):
        roll = {"id": "r1", "name": "deploy", "action": "script", "script_id": "a1b2c3d4", "rollback_script_id": "a1b2c3d4",
                "rings": [{"name": "ring 1", "selector": {"type": "ids", "ids": ["d1"]}}],
                "rings_state": [{"state": "done", "dispatched_ids": ["d1"], "total": 1, "ok_count": 1, "failed_count": 0}],
                "auto_promote": False, "verify_minutes": 30, "health_gate": {"enabled": False, "threshold": 70},
                "state": "done", "current_ring": 0, "history": [], "created_by": "alice", "created_at": 1, "updated_at": 1, "tenant_gate": None}
        api.save(api.ROLLOUTS_FILE, {"rollouts": [roll]})
        api._LOAD_CACHE.clear()
        status, body = self.call(api.handle_rollout_action, "r1", "rollback")
        self.assertEqual((status, body.get("approval_required")), (202, True), body)
        rolls = (api.load(api.ROLLOUTS_FILE) or {})["rollouts"]
        rb = next(r for r in rolls if r.get("rolled_back_from") == "r1")
        self.assertEqual(rb["state"], "draft", "the rollback that runs a script on every host waits")
        self.assertEqual(body["rollback_id"], rb["id"])
        self.assertEqual(self.queue(), {})


def _names_in(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _mentions_queue_file(node):
    return any((isinstance(n, ast.Name) and n.id == "CMDS_FILE") or (isinstance(n, ast.Attribute) and n.attr == "CMDS_FILE")
               for n in ast.walk(node))


def _find_queue_writers(node, stack, module, found):
    """Record, by innermost function name, every function that opens the command queue store for writing."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _find_queue_writers(child, stack + [child], module, found)
        else:
            _find_queue_writers(child, stack, module, found)
    if isinstance(node, ast.Call) and stack:
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
        if name in ("_LockedUpdate", "save", "_locked_update") and node.args and _mentions_queue_file(node.args[0]):
            found.setdefault(stack[-1].name, (module, stack[-1]))


class TestEveryWriterOfTheCommandQueue(unittest.TestCase):
    """The class, not the paths. Whatever writes the queue asks for approval itself, calls a gateway that does, or is on this list
    with the reason it does not. A listed function that stops writing the queue fails too, so the list only shrinks."""

    ASKS = {"_queue_command", "_queue_command_batch", "_queue_command_map", "_preflight_command", "_needs_approval",
            "_park_for_approval", "_create_confirmation"}
    EXEMPT = {
        "handle_heartbeat": "dispatch: takes the next command for the agent out of the queue, nothing is added",
        "_purge_device": "removes the queue of a deleted host",
        "handle_command_queue_clear": "removes queued commands",
        "handle_command_queue_clear_all": "removes queued commands",
        "handle_acme_cancel": "removes queued certificate commands",
        "handle_acme_ignore": "removes queued certificate commands",
        "_acme_queue_command": "certificate issue, renewal and revocation: not one of the command kinds change approval can gate",
        "_mcp_execute": "runs a change a second admin has just approved",
        "_ups_shutdown_dependents": "unattended safety response to a failing UPS; waiting for a second admin would defeat it (docs/power.md)",
        "_run_automation_action": "a standing rule an administrator wrote, with its own blast-radius guards (cooldown, host cap, verify, auto-disable)",
        "handle_device_poll_interval": "poll_interval only changes the agent's local timer and is exempt from every gate",
        "handle_files_archive_start": "read-only: the agent builds a tar of a folder",
        "handle_drift_fetch_content": "read-only: fetches the stored text of a drifted file",
        "request_patch_preview": "read-only: a dry run that changes nothing",
        "_backup_queue_and_wait": "the command of a backup job an administrator configured, generated by the server",
        "process_backup_jobs": "the scheduled run of a backup job an administrator configured",
        "_rollout_tick": "dispatches the rings of a rollout whose START was approved (handle_rollout_action parks the start)",
        "_drop_unrun_block": "removes the block command Threat Intel queued for an address whose time ran out; it queues nothing",
    }

    @classmethod
    def setUpClass(cls):
        cls.found = {}
        for path in sorted(glob.glob(str(_CGI / "*.py"))):
            tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
            _find_queue_writers(tree, [], pathlib.Path(path).name, cls.found)

    @staticmethod
    def _names(node):
        return _names_in(node)

    def test_the_walk_finds_the_population(self):
        """Control: an empty population would make every other assertion here pass."""
        self.assertGreaterEqual(len(self.found), 25, sorted(self.found))
        for known in ("_queue_command", "handle_device_files", "handle_device_compose_action", "process_schedule", "handle_heartbeat",
                      "_rollout_tick"):
            self.assertIn(known, self.found)
        for converted in ("handle_exec_batch", "_handle_pkg_action"):
            self.assertNotIn(converted, self.found, "goes through the batch gateway now, no longer writes the queue itself")

    def test_each_writer_asks_or_is_listed_with_a_reason(self):
        unasked = sorted(n for n, (_, node) in self.found.items() if not (self._names(node) & self.ASKS) and n not in self.EXEMPT)
        self.assertEqual(unasked, [], "these functions write the command queue without asking for change approval and are not listed "
                                      "as exempt: " + ", ".join(unasked))

    def test_the_exempt_list_names_writers_that_still_exist(self):
        stale = sorted(n for n in self.EXEMPT if n not in self.found)
        self.assertEqual(stale, [], "listed as exempt but no longer writing the queue: " + ", ".join(stale))

    def test_a_listed_function_does_not_also_ask(self):
        """If an exempt function started asking, the list is carrying a reason that is no longer true."""
        both = sorted(n for n in self.EXEMPT if n in self.found and self._names(self.found[n][1]) & self.ASKS)
        self.assertEqual(both, [], "asks already, so it does not need to be listed: " + ", ".join(both))

    def test_the_ratio_is_printed(self):
        asks = sum(1 for _, node in self.found.values() if self._names(node) & self.ASKS)
        print(f"\ncommand-queue writers: {len(self.found)} (ask {asks}, exempt {len(self.EXEMPT)})", file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
