"""v6.4.2 — a bulk action leaves a record of what actually happened.

A real batch-job tracker already existed: BATCH_JOBS_FILE, GET /api/exec/batch,
the "Recent installs & jobs" card on Rollouts, with per-host done/failed/pending
marks and live polling. It was created by exactly TWO paths — one-time package
install, and batch script exec.

The four bulk actions an operator actually reaches for from the Devices batch
bar (shutdown, reboot, upgrade packages, update agent) all returned a per-device
`results` dict that the server persisted nowhere, and the client threw away in
favour of a toast: "Reboot queued for 412 device(s)".

So the quarantined, audit-mode and queue-full rejections — already computed,
already in the HTTP response — vanished. The operator triggers "Upgrade
packages" on 800 hosts during a maintenance window, sees a green toast, closes
the window, and finds out three weeks later during a CVE audit that N hosts were
never patched.

(An OFFLINE host is NOT one of those rejections: the command simply waits in its
queue. The rejections are invalid/unknown id, quarantined, audit-mode, and a
full queue.)
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-batchjob642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestTheRecord(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("log_command", "fire_webhook")}
        api.log_command = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {
            "bok": {"name": "web01"},
            "bquar": {"name": "quarantined", "quarantined": True},
            "baudit": {"name": "auditmode", "sysinfo": {"audit_mode": True}},
            "bfull": {"name": "fullq"},
        })
        api.save(api.CMDS_FILE, {"bfull": ["x"] * api.MAX_QUEUED_PER_DEVICE})
        api.save(api.BATCH_JOBS_FILE, {"jobs": {}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _run(self):
        res = api._queue_command_batch(
            ["bok", "bquar", "baudit", "bfull", "bnope"], "reboot", "jakob")
        jid = api._record_batch_job("reboot", "Reboot 5 device(s)", "reboot",
                                    "jakob", res)
        job = (api.load(api.BATCH_JOBS_FILE) or {}).get("jobs", {}).get(jid)
        return res, jid, job

    def test_a_job_is_recorded(self):
        _res, jid, job = self._run()
        self.assertTrue(jid)
        self.assertIsNotNone(job, "the bulk action still persists nothing")

    def test_only_the_queued_hosts_are_targets(self):
        _res, _jid, job = self._run()
        self.assertEqual(job["targets"], ["bok"])

    def test_every_rejection_is_kept_with_its_reason(self):
        """These are the ones that used to vanish. The reason matters: 'queue
        full' and 'quarantined' need completely different follow-ups."""
        _res, _jid, job = self._run()
        errs = {d: e.get("error") for d, e in job["per_device"].items()
                if not e["queued"]}
        self.assertEqual(set(errs), {"bquar", "baudit", "bfull", "bnope"})
        self.assertIn("quarantined", errs["bquar"])
        self.assertIn("audit", errs["baudit"])
        self.assertIn("Queue full", errs["bfull"])

    def test_it_records_the_host_name_not_just_the_id(self):
        """Three weeks later, `bquar` means nothing to anybody."""
        _res, _jid, job = self._run()
        self.assertEqual(job["per_device"]["bok"]["name"], "web01")

    def test_a_parked_approval_is_recorded_as_such(self):
        """With change approval on, every target is parked — recording those as
        plain failures would read as "the reboot did not happen" when it is
        waiting for a second admin."""
        jid = api._record_batch_job(
            "reboot", "x", "reboot", "jakob",
            {"bok": {"ok": True, "approval_required": True,
                     "confirmation_id": "cf_1"}})
        job = (api.load(api.BATCH_JOBS_FILE) or {}).get("jobs", {})[jid]
        self.assertTrue(job["per_device"]["bok"]["approval_required"])
        self.assertEqual(job["per_device"]["bok"]["confirmation_id"], "cf_1")

    def test_a_failure_to_record_does_not_cost_the_action(self):
        """The record is bookkeeping. Losing it must never mean losing the
        reboot the operator asked for."""
        saved = api._LockedUpdate
        api._LockedUpdate = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
        try:
            self.assertIsNone(api._record_batch_job("reboot", "x", "reboot",
                                                    "jakob", {"bok": {"ok": True}}))
        finally:
            api._LockedUpdate = saved

    def test_an_empty_result_records_nothing(self):
        self.assertIsNone(api._record_batch_job("reboot", "x", "reboot",
                                                "jakob", {}))

    def test_it_lands_in_the_existing_tracker(self):
        """Deliberately the SAME store and shape the install/script jobs use, so
        the Rollouts card renders it with no client change."""
        _res, jid, job = self._run()
        for k in ("id", "kind", "label", "actor", "created", "targets",
                  "per_device"):
            with self.subTest(field=k):
                self.assertIn(k, job)


class TestAllFourActionsRecord(unittest.TestCase):
    """shutdown / reboot / update agent / upgrade packages — the four the batch
    bar offers. Missing one leaves exactly the gap this closes."""

    def test_each_handler_records_a_job(self):
        src = (_CGI / "api.py").read_text()
        for fn, kind in (("handle_shutdown", "shutdown"),
                         ("handle_reboot", "reboot"),
                         ("handle_update_device", "agent_update"),
                         ("handle_upgrade_device", "upgrade")):
            with self.subTest(handler=fn):
                sys.path.insert(0, str(ROOT / "tests"))
                import srcpin
                body = srcpin.py_function(src, fn)
                self.assertIn("_record_batch_job(", body,
                              f"{fn} persists nothing")
                self.assertIn(f"'{kind}'", body)

    def test_the_job_id_is_returned_to_the_client(self):
        src = (_CGI / "api.py").read_text()
        self.assertGreaterEqual(src.count("'job_id': _record_batch_job("), 3)


class TestTheToastStopsClaimingSuccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()

    def test_it_counts_what_actually_queued(self):
        body = self.js[self.js.index("async function batchAction"):]
        body = body[:body.index("\nfunction openNotesModal")]
        self.assertIn("data.results", body,
                      "the per-device outcomes are still discarded")
        self.assertIn("failed.length", body)

    def test_it_names_the_failures(self):
        body = self.js[self.js.index("async function batchAction"):]
        body = body[:body.index("\nfunction openNotesModal")]
        self.assertIn("res[k].error", body,
                      "'12 refused' without saying why is barely better than "
                      "a green toast")

    def test_a_partial_failure_is_not_reported_as_success(self):
        body = self.js[self.js.index("async function batchAction"):]
        body = body[:body.index("\nfunction openNotesModal")]
        i = body.index("failed.length")
        self.assertIn("'error'", body[i:i + 700],
                      "a batch with refusals still toasts green")


if __name__ == "__main__":
    unittest.main()
