#!/usr/bin/env python3
"""v6.4.1 guardrail: a self-update rollout ring verifies on the agent's
REPORTED VERSION, not on command delivery.

The old check counted a ring device as verified the moment the `update`
command left the queue — but the queue draining proves the agent picked the
command up, not that it survived the binary swap. With auto-promote on, a
canary that died on the new agent still verified and the broken update went
fleet-wide: the exact failure a canary ring exists to stop.

Drives the real `_rollout_ring_progress` and the real `_rollout_advance`
state machine (no hand-built verdicts). Runs under both backends.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import api  # noqa: E402


def _dev(version, last_seen):
    return {"name": "d", "token": "t", "version": version,
            "last_seen": last_seen, "sysinfo": {}}


class TestSelfUpdateRingProgress(unittest.TestCase):
    def _progress(self, devices, cmds, dispatched_at):
        roll = {"action": "self-update"}
        rstate = {"dispatched_ids": list(devices), "queued": "update",
                  "dispatched_at": dispatched_at}
        return api._rollout_ring_progress(roll, rstate, devices, cmds)

    def test_still_queued_is_pending_not_verified(self):
        now = int(time.time())
        devices = {"d1": _dev(api.SERVER_VERSION, now)}
        ok, failed, total = self._progress(devices, {"d1": ["update"]}, now - 60)
        self.assertEqual((ok, failed, total), (0, 0, 1))

    def test_new_version_heartbeat_after_dispatch_verifies(self):
        now = int(time.time())
        devices = {"d1": _dev(api.SERVER_VERSION, now)}
        ok, failed, total = self._progress(devices, {"d1": []}, now - 60)
        self.assertEqual((ok, failed, total), (1, 0, 1))

    def test_consumed_but_old_version_is_NOT_verified(self):
        # The regression this file exists for: delivery alone must never count.
        now = int(time.time())
        devices = {"d1": _dev("0.0.1", now)}
        ok, failed, total = self._progress(devices, {"d1": []}, now - 60)
        self.assertEqual(ok, 0, "delivery-only verification is back — a dead "
                                "or un-updated agent counts as verified")
        self.assertEqual(failed, 0, "still inside the grace window")

    def test_past_grace_without_new_version_is_stalled(self):
        now = int(time.time())
        old_beat = now - 3600
        devices = {"d1": _dev("0.0.1", now),        # alive, update didn't take
                   "d2": _dev("0.0.1", old_beat)}   # silent since dispatch
        cmds = {"d1": [], "d2": []}
        ok, failed, total = self._progress(devices, cmds, now - 1200)
        self.assertEqual((ok, failed, total), (0, 2, 2))

    def test_already_current_device_verifies_on_next_beat(self):
        now = int(time.time())
        devices = {"d1": _dev(api.SERVER_VERSION, now)}   # no-op self-update
        ok, failed, _ = self._progress(devices, {"d1": []}, now - 30)
        self.assertEqual((ok, failed), (1, 0))


class TestAdvanceHaltsOnDeadCanary(unittest.TestCase):
    """The state machine must HALT (not promote) when the canary never comes
    back on the new version — driven through the real _rollout_advance."""

    def test_dead_canary_halts_instead_of_promoting(self):
        now = int(time.time())
        # Window expired, command consumed, canary silent since dispatch.
        devices = {"c1": _dev("0.0.1", now - 4000)}
        cmds = {"c1": []}
        roll = {
            "state": "running", "action": "self-update", "auto_promote": True,
            "current_ring": 0, "verify_minutes": 30,
            "rings": [{"name": "canary", "selector": "ids:c1"},
                      {"name": "fleet", "selector": "ids:f1"}],
            "rings_state": [
                {"state": "verifying", "dispatched_ids": ["c1"],
                 "dispatched_at": now - 3600, "total": 1, "queued": "update"},
                {"state": "pending"},
            ],
        }
        api._rollout_advance(roll, devices, cmds, pending=[])
        self.assertEqual(roll["state"], "failed",
                         "a dead canary must halt the rollout")
        self.assertEqual(roll["rings_state"][0]["state"], "failed")
        self.assertEqual(roll.get("current_ring"), 0,
                         "the fleet ring must never be released")

    def test_verified_canary_still_auto_promotes(self):
        now = int(time.time())
        devices = {"c1": _dev(api.SERVER_VERSION, now)}
        cmds = {"c1": []}
        roll = {
            "state": "running", "action": "self-update", "auto_promote": True,
            "current_ring": 0, "verify_minutes": 30,
            "rings": [{"name": "canary", "selector": "ids:c1"},
                      {"name": "fleet", "selector": "ids:f1"}],
            "rings_state": [
                {"state": "verifying", "dispatched_ids": ["c1"],
                 "dispatched_at": now - 120, "total": 1, "queued": "update"},
                {"state": "pending"},
            ],
        }
        api._rollout_advance(roll, devices, cmds, pending=[])
        self.assertEqual(roll["rings_state"][0]["state"], "done")
        self.assertEqual(roll.get("current_ring"), 1,
                         "a verified canary must promote to the next ring")


if __name__ == "__main__":
    unittest.main(verbosity=2)
