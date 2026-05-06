#!/usr/bin/env python3
"""Unit tests for v1.11.8: periodic monitor runner.

Background: prior to v1.11.8, monitor checks (ping/tcp/http) ran ONLY
when somebody opened the Monitor page in the dashboard. The
``monitor_interval`` config existed but was never read — the dashboard
just refetched the data on each visit. Symptom in the wild: "monitor
history shows checks at 14:50:27 and 14:50:13 (page refresh), then
nothing for 4 hours, then 18:40:26 (next refresh)". Webhooks for down
services missed the entire 4-hour gap.

The fix introduces ``run_monitors_if_due()``, called from main() on
every CGI request, gated on ``monitor_interval``. Most CGI requests
do nothing (gate not yet expired); when expired, the existing check
logic runs and appends to history.

These tests cover:
  - Gate logic: doesn't run when within the interval, runs when past it.
  - last_monitor_run timestamp gets updated on a real run.
  - Skipped cleanly when no monitors are configured.
  - User-triggered run (the GET /api/monitor handler) updates the
    timestamp so the periodic runner doesn't pile on.
  - Webhook firing on transitions still works through the new code path.
  - Race condition: two near-simultaneous calls don't both run (the
    second sees the timestamp updated by the first).

We don't actually run pings or HTTP fetches — that'd need network
access in CI. Instead we monkey-patch ``_execute_monitor_checks``
to return synthesised results, then verify the gate / persistence /
webhook code around it does the right thing.
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v1118", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _capture(t):
    def fake(status, data):
        raise _Captured(status, data)
    t.respond = fake


def _set_request(method, path, body=None, headers=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    for k in ("HTTP_X_TOKEN",):
        os.environ.pop(k, None)
    for k, v in (headers or {}).items():
        os.environ[k] = v


def _call(handler, *args, **kwargs):
    _capture(api)
    try:
        handler(*args, **kwargs)
    except _Captured as c:
        return c.status, c.body
    raise AssertionError(f"{handler.__name__} did not call respond()")


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "CMDB_FILE",
        "AUDIT_LOG_FILE", "CONFIG_FILE", "CMD_OUTPUT_FILE",
        "UPDATE_LOGS_FILE", "CMDS_FILE", "CONTAINERS_FILE",
        "WEBHOOK_LOG_FILE", "SERVICES_FILE", "MON_HIST_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


def _seed_admin():
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": user, "created": int(time.time()),
        "ttl": 3600, "admin": True, "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return user, token


# ─── run_monitors_if_due gate logic ──────────────────────────────────────────


class TestPeriodicMonitorGate(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        # Stub out the actual check logic — we don't want to ping anything.
        # Tests focus on whether the gate decides to call us, not on what
        # the checks do.
        self._orig_exec = api._execute_monitor_checks
        self._exec_calls = []
        def fake_exec(monitors):
            self._exec_calls.append(int(time.time()))
            # Return one synthesised result so the persistence code has
            # something to work with.
            return [{
                "label":   monitors[0]["label"],
                "type":    monitors[0]["type"],
                "target":  monitors[0]["target"],
                "ok":      True,
                "detail":  "stubbed",
                "checked": int(time.time()),
            }] if monitors else []
        api._execute_monitor_checks = fake_exec

    def tearDown(self):
        api._execute_monitor_checks = self._orig_exec

    def _config_monitors(self, interval=300, last_run=None):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = [
            {"label": "test", "type": "ping", "target": "1.1.1.1"},
        ]
        cfg["monitor_interval"] = interval
        if last_run is not None:
            cfg["last_monitor_run"] = last_run
        api.save(api.CONFIG_FILE, cfg)

    def test_no_monitors_no_op(self):
        # Empty config — gate does nothing, no exec call
        api.run_monitors_if_due()
        self.assertEqual(self._exec_calls, [])

    def test_first_call_runs(self):
        # No last_monitor_run yet (never executed) — gate must run
        self._config_monitors(interval=300)
        api.run_monitors_if_due()
        self.assertEqual(len(self._exec_calls), 1)

    def test_within_interval_skips(self):
        # last_run was 10s ago, interval is 300s — gate should skip
        now = int(time.time())
        self._config_monitors(interval=300, last_run=now - 10)
        api.run_monitors_if_due()
        self.assertEqual(self._exec_calls, [])

    def test_past_interval_runs(self):
        # last_run was 400s ago, interval is 300s — gate should run
        now = int(time.time())
        self._config_monitors(interval=300, last_run=now - 400)
        api.run_monitors_if_due()
        self.assertEqual(len(self._exec_calls), 1)

    def test_run_updates_timestamp(self):
        now = int(time.time())
        self._config_monitors(interval=300, last_run=now - 400)
        api.run_monitors_if_due()
        cfg = api.load(api.CONFIG_FILE)
        # Updated timestamp should be very recent
        self.assertGreaterEqual(cfg["last_monitor_run"], now)

    def test_back_to_back_calls_only_run_once(self):
        # Simulates two CGI requests hitting near-simultaneously — the
        # second should see the timestamp updated by the first.
        now = int(time.time())
        self._config_monitors(interval=300, last_run=now - 400)
        api.run_monitors_if_due()
        api.run_monitors_if_due()  # second call: gate now blocks
        self.assertEqual(len(self._exec_calls), 1)

    def test_interval_clamped_to_60s_minimum(self):
        # Even if the user sets monitor_interval=10 in config, the runner
        # treats it as 60 to prevent CGI-flood disasters. The handler's
        # explicit POST validation (60-3600) is the primary defence; this
        # is belt-and-braces for a corrupt config file.
        now = int(time.time())
        self._config_monitors(interval=10, last_run=now - 30)
        # 30 < 60 (clamped), so should skip
        api.run_monitors_if_due()
        self.assertEqual(self._exec_calls, [])
        # 70 > 60, should run
        cfg = api.load(api.CONFIG_FILE)
        cfg["last_monitor_run"] = now - 70
        api.save(api.CONFIG_FILE, cfg)
        api.run_monitors_if_due()
        self.assertEqual(len(self._exec_calls), 1)


# ─── handle_monitor_run still works (regression check) ───────────────────────


class TestUserTriggeredMonitorRun(unittest.TestCase):
    """The synchronous ``GET /api/monitor`` handler should keep working
    exactly as before. v1.11.8 refactored the underlying check logic
    into a shared helper but the user-facing behaviour is unchanged.
    """

    def setUp(self):
        _isolate(self)
        _, self.token = _seed_admin()
        self._orig_exec = api._execute_monitor_checks
        api._execute_monitor_checks = lambda monitors: [
            {"label": "stub", "type": "ping", "target": "1.1.1.1",
             "ok": True, "detail": "up", "checked": int(time.time())}
        ]

    def tearDown(self):
        api._execute_monitor_checks = self._orig_exec

    def test_get_returns_results_and_updates_timestamp(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = [{"label": "stub", "type": "ping", "target": "1.1.1.1"}]
        api.save(api.CONFIG_FILE, cfg)
        _set_request("GET", "/api/monitor", headers={"HTTP_X_TOKEN": self.token})
        status, body = _call(api.handle_monitor_run)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["monitors"]), 1)
        self.assertEqual(body["monitors"][0]["ok"], True)
        # Timestamp was updated
        cfg2 = api.load(api.CONFIG_FILE)
        self.assertGreater(cfg2.get("last_monitor_run", 0), 0)


# ─── webhook firing through the periodic path ────────────────────────────────


class TestPeriodicMonitorFiresWebhook(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self._fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda event, payload: self._fired.append((event, payload))
        self._orig_exec = api._execute_monitor_checks

    def tearDown(self):
        api.fire_webhook = self._orig_fire
        api._execute_monitor_checks = self._orig_exec

    def _config_one(self, interval=300, last_run=None):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = [{"label": "site", "type": "http", "target": "https://example.com"}]
        cfg["monitor_interval"] = interval
        if last_run is not None:
            cfg["last_monitor_run"] = last_run
        api.save(api.CONFIG_FILE, cfg)

    def test_first_failure_fires_monitor_down(self):
        now = int(time.time())
        self._config_one(interval=60, last_run=now - 100)
        api._execute_monitor_checks = lambda m: [
            {"label": "site", "type": "http", "target": "https://example.com",
             "ok": False, "detail": "500", "checked": now},
        ]
        api.run_monitors_if_due()
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["monitor_down"])

    def test_recovery_fires_monitor_up(self):
        now = int(time.time())
        self._config_one(interval=60, last_run=now - 100)
        # Pre-mark as already-down so the recovery is a transition.
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitor_notified"] = {"site": True}
        api.save(api.CONFIG_FILE, cfg)
        api._execute_monitor_checks = lambda m: [
            {"label": "site", "type": "http", "target": "https://example.com",
             "ok": True, "detail": "200", "checked": now},
        ]
        api.run_monitors_if_due()
        events = [e for e, _ in self._fired]
        self.assertEqual(events, ["monitor_up"])

    def test_persistent_state_no_dup_fires(self):
        # Two consecutive 500s on the same monitor should fire monitor_down
        # exactly once, not twice. The gate logic combined with the
        # monitor_notified flag handles this.
        now = int(time.time())
        self._config_one(interval=60, last_run=now - 100)
        api._execute_monitor_checks = lambda m: [
            {"label": "site", "type": "http", "target": "https://example.com",
             "ok": False, "detail": "500", "checked": int(time.time())},
        ]
        api.run_monitors_if_due()
        # Force the gate open again by rewinding last_run
        cfg = api.load(api.CONFIG_FILE)
        cfg["last_monitor_run"] = now - 100
        api.save(api.CONFIG_FILE, cfg)
        api.run_monitors_if_due()
        events = [e for e, _ in self._fired]
        # Only ONE monitor_down — the second check sees was_down=True
        # and stays quiet.
        self.assertEqual(events, ["monitor_down"])


if __name__ == "__main__":
    unittest.main()
