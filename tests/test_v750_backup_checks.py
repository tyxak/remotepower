#!/usr/bin/env python3
"""A backup that is fresh and cannot be restored is a finding, in every place that judges backups.

A backup has two checks beyond freshness: the integrity check of its repository (`verify_status`) and the restore
drill (`drill_status`). Both are stored and both page the operator (backup_verify_failed, restore_drill_failed), and
the compliance report (SOC 2 A1.2, E8-8, HIPAA 164.308(a)(7)(ii)(A)), the Security Advisory and the risk score read
freshness only. A host whose backup was a day old and corrupt passed all three.

The state is written by the real heartbeat (the agent's report shape), so the keys the readers use are the keys the
ingest stores.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-bk-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import advisory  # noqa: E402
import compliance  # noqa: E402
import posture_signals as ps  # noqa: E402

PATH = "/srv/backups/db"


class _Beats(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {"backup_monitors": [{"path": PATH, "label": "database", "max_age_hours": 24}]})
        api.save(api.DATA_DIR / "backup_state.json", {})
        api._LOAD_CACHE.clear()

    def beat(self, **extra):
        body = {"device_id": DEV, "token": "tok"}
        body.update(extra)
        raw = json.dumps(body).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return
        self.fail("heartbeat did not answer")

    def status(self, age_h=2):
        return [{"path": PATH, "label": "database", "exists": True, "mtime": int(time.time()) - int(age_h * 3600),
                 "size": 1000, "age_h": age_h}]

    def fresh(self):
        """A backup file two hours old."""
        self.beat(backup_status=self.status())

    def checks(self, age_h=2, **extra):
        """What the agent sends: the file's age and the results of its checks in ONE report. The server keeps the checks only
        when the same report carries the age, because they are written into the one state it loads for the age."""
        self.beat(backup_status=self.status(age_h), **extra)

    def state(self):
        api._LOAD_CACHE.clear()
        return api.load(api.DATA_DIR / "backup_state.json") or {}


class TestTheHelper(unittest.TestCase):

    def test_both_checks_are_found_with_the_label_and_the_tool(self):
        out = ps.failed_backup_checks_by_device(
            {"d1:/srv/b": {"ok": True, "verify_status": "failed", "verify_tool": "restic", "drill_status": "timeout"}},
            [{"path": "/srv/b", "label": "database"}])
        self.assertEqual(out, {"d1": ["database — integrity check failed (restic)", "database — restore drill timeout"]})

    def test_the_bad_sets_are_the_ones_the_alerts_use(self):
        for s in ("failed", "timeout", "error", "unreachable"):
            self.assertIn("d", ps.failed_backup_checks_by_device({"d:/p": {"verify_status": s}}))
        for s in ("failed", "timeout", "error"):
            self.assertIn("d", ps.failed_backup_checks_by_device({"d:/p": {"drill_status": s}}))

    def test_what_is_not_a_failure_is_not_listed(self):
        for entry in ({"verify_status": "ok"}, {"verify_status": "unknown"}, {"drill_status": "ok"},
                      {"drill_status": "tool_missing"}, {"drill_status": "unknown"}, {}):
            self.assertEqual(ps.failed_backup_checks_by_device({"d:/p": entry}), {}, entry)

    def test_keys_without_a_host_and_rows_that_are_not_maps_are_ignored(self):
        self.assertEqual(ps.failed_backup_checks_by_device({"nocolon": {"verify_status": "failed"}, "d:/p": 5}), {})
        for junk in (None, [], "x", 7):
            self.assertEqual(ps.failed_backup_checks_by_device(junk), {})

    def test_a_path_with_a_colon_is_split_on_the_first_one_only(self):
        out = ps.failed_backup_checks_by_device({"d:/srv/a:b": {"verify_status": "failed"}})
        self.assertIn("d", out)
        self.assertIn("/srv/a:b", out["d"][0])

    def test_the_heartbeat_uses_the_same_sets(self):
        src = (ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn("posture_signals.VERIFY_BAD", src)
        self.assertIn("posture_signals.DRILL_BAD", src)
        self.assertNotIn("('failed', 'timeout', 'error', 'unreachable')", src)


class TestThroughTheHeartbeat(_Beats):

    def test_the_premise_the_ingest_stores_the_keys_the_readers_use(self):
        self.checks(backup_verify=[{"path": PATH, "tool": "restic", "verify_status": "failed",
                                    "verify_output": "pack 1a2b is damaged"}],
                    restore_drills=[{"path": PATH, "tool": "restic", "drill_status": "failed", "drill_output": "sha mismatch"}])
        e = self.state()[f"{DEV}:{PATH}"]
        self.assertEqual((e["verify_status"], e["drill_status"]), ("failed", "failed"))
        self.assertTrue(e.get("ok", True), "the file is fresh, which is what the old checks looked at")

    def test_compliance_fails_a_fresh_backup_whose_checks_fail(self):
        self.checks(backup_verify=[{"path": PATH, "tool": "restic", "verify_status": "failed", "verify_output": "x"}])
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual(facts["failed_backups"], [], "nothing is stale")
        self.assertEqual(len(facts["failed_backup_checks"]), 1)
        self.assertIn("serverbox: database — integrity check failed (restic)", facts["failed_backup_checks"][0])
        status, evidence = compliance._backup_control(facts)
        self.assertEqual(status, compliance.FAIL)
        self.assertIn("failing", evidence)
        self.assertIn("database", evidence)

    def test_a_healthy_backup_still_passes(self):
        self.checks(backup_verify=[{"path": PATH, "tool": "restic", "verify_status": "ok"}],
                    restore_drills=[{"path": PATH, "tool": "restic", "drill_status": "ok"}])
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual((facts["failed_backups"], facts["failed_backup_checks"]), ([], []))
        self.assertEqual(compliance._backup_control(facts)[0], compliance.PASS)

    def test_a_check_that_recovers_clears_the_failure(self):
        self.checks(restore_drills=[{"path": PATH, "tool": "restic", "drill_status": "failed"}])
        self.checks(restore_drills=[{"path": PATH, "tool": "restic", "drill_status": "ok"}])
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual(facts["failed_backup_checks"], [])

    def test_the_stale_and_the_failing_are_both_listed(self):
        self.checks(age_h=111, backup_verify=[{"path": PATH, "tool": "restic", "verify_status": "error"}])
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual(len(facts["failed_backups"]), 1)
        self.assertEqual(len(facts["failed_backup_checks"]), 1)
        status, evidence = compliance._backup_control(facts)
        self.assertEqual(status, compliance.FAIL)
        self.assertIn("stale/missing", evidence)
        self.assertIn("failing", evidence)

    def test_the_advisory_names_the_failing_check_as_its_own_finding(self):
        self.checks(restore_drills=[{"path": PATH, "tool": "restic", "drill_status": "failed"}])
        devs = {DEV: api.load(api.DEVICES_FILE)[DEV]}
        built = api._build_advisory(devs)
        ids = {f["id"] for f in built["findings"]}
        self.assertIn("data.backup_check", ids)
        self.assertNotIn("data.backup", ids, "the file is fresh")
        f = [x for x in built["findings"] if x["id"] == "data.backup_check"][0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("restore drill failed", " ".join(f["evidence"]))

    def test_the_risk_score_counts_it(self):
        self.checks(backup_verify=[{"path": PATH, "tool": "restic", "verify_status": "failed"}])
        row = {r["device_id"]: r for r in api._compute_fleet_risk()}[DEV]
        f = [x for x in row["factors"] if x["kind"] == "backup_stale"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["points"], api._RISK_WEIGHTS["backup_stale"])
        self.assertIn("failing a check", f[0]["detail"])

    def test_a_clean_fleet_has_no_such_finding_or_factor(self):
        self.fresh()
        devs = {DEV: api.load(api.DEVICES_FILE)[DEV]}
        self.assertNotIn("data.backup_check", {f["id"] for f in api._build_advisory(devs)["findings"]})
        row = {r["device_id"]: r for r in api._compute_fleet_risk()}[DEV]
        self.assertEqual([x for x in row["factors"] if x["kind"] == "backup_stale"], [])


class TestAdvisoryBuild(unittest.TestCase):

    def test_build_takes_the_checks_and_leaves_stale_alone(self):
        devs = {"d1": {"name": "web", "sysinfo": {}}}
        out = advisory.build(devs, backup_checks_by_dev={"d1": ["x — integrity check failed"]}, now=1)
        self.assertEqual([f["id"] for f in out["findings"] if f["id"].startswith("data.")], ["data.backup_check"])
        out = advisory.build(devs, backups_by_dev={"d1": ["x — 96h old"]}, now=1)
        self.assertEqual([f["id"] for f in out["findings"] if f["id"].startswith("data.")], ["data.backup"])


if __name__ == "__main__":
    unittest.main()
