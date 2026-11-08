#!/usr/bin/env python3
"""8.0.0: a Timeline row that is a fleet event carries `event`, which is what POST /api/webhook/replay takes; the other rows carry none.

The Timeline page puts a replay button on a row only when the row has `event`, so the field is the whole difference between a fleet event, a command run and the CVE state row. It is checked
against the real producers: an event recorded by `_record_fleet_event`, a command run in the shape the command-output store holds, and the replay route fed the row's own `event` and `ts`.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800tl-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

PASSWORD = "correct horse battery staple 42"


class _Captured(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


class TestTheTimelineRowsAndTheReplayRoute(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="rp-v800tl-")
        os.environ["RP_DATA_DIR"] = d
        self._saved = {}
        for name in ("USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "AUDIT_LOG_FILE", "CONFIG_FILE", "RATELIMIT_FILE", "FLEET_EVENTS_FILE", "CMD_OUTPUT_FILE", "CVE_FINDINGS_FILE", "CVE_IGNORE_FILE", "WEBHOOK_LOG_FILE"):
            if hasattr(api, name):
                self._saved[name] = getattr(api, name)
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        users["alice"] = {"password_hash": api.hash_password(PASSWORD), "role": "admin", "created": int(time.time())}
        api.save(api.USERS_FILE, users)
        self.admin = api._mint_session("alice")
        api.save(api.DEVICES_FILE, {"d1": {"name": "web", "ip": "10.0.0.5", "token": "t", "last_seen": int(time.time())}})
        # the real producer of a fleet event, and a command run in the shape the store holds
        api._record_fleet_event("device_offline", {"device_id": "d1", "name": "web"})
        api.save(api.CMD_OUTPUT_FILE, {"d1": [{"ts": int(time.time()), "cmd": "uptime", "rc": 0}]})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)

    def rows(self):
        return api._timeline_collect({"d1"}, {"d1": "web"})

    def test_a_fleet_event_carries_its_own_name_and_the_other_rows_none(self):
        rows = self.rows()
        events = [r for r in rows if r["kind"] == "device_offline"]
        commands = [r for r in rows if r["kind"] == "command"]
        self.assertEqual(len(events), 1, rows)
        self.assertEqual(len(commands), 1, rows)
        self.assertEqual(events[0]["event"], "device_offline")
        self.assertNotIn("event", commands[0])

    def test_the_rows_own_event_and_time_find_the_event_in_the_replay_route(self):
        row = next(r for r in self.rows() if r.get("event"))
        sent = []
        raw = json.dumps({"event": row["event"], "ts": row["ts"]}).encode()
        os.environ.update(REQUEST_METHOD="POST", PATH_INFO="/api/webhook/replay", REMOTE_ADDR="203.0.113.9", CONTENT_LENGTH=str(len(raw)), HTTP_X_TOKEN=self.admin)
        api.sys.stdin = _Stdin(raw)

        def fake(status, data=None, *a, **k):
            raise _Captured(status, data)

        with mock.patch.object(api, "respond", fake), mock.patch.object(api, "fire_webhook", lambda ev, payload: sent.append((ev, dict(payload)))), mock.patch("time.sleep"):
            api._begin_request()
            with self.assertRaises(_Captured) as ctx:
                api.handle_webhook_replay()
        self.assertEqual((ctx.exception.status, (ctx.exception.body or {}).get("ok")), (200, True), ctx.exception.body)
        self.assertEqual([e for e, _ in sent], ["device_offline"])
        self.assertTrue(sent[0][1].get("_replay"), "a replay is marked as one")
        self.assertEqual(sent[0][1].get("device_id"), "d1")


if __name__ == "__main__":
    unittest.main()
