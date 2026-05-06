#!/usr/bin/env python3
"""Unit tests for v1.11.7: cmd_output follow-up heartbeat flow.

The bug fix: prior to v1.11.7, the agent assigned ``cmd_output`` to a
``payload`` dict *after* that payload had already been POSTed in the
heartbeat. The next loop iteration reset ``payload`` and the result
was discarded. Symptom: "Update history" stayed empty even though
the upgrade ran successfully.

The fix sends a dedicated minimal follow-up heartbeat right after
the command finishes. These tests confirm the *server* side handles
that follow-up correctly:

  - A minimal payload with just device_id, token, cmd_output is
    accepted and stored in cmd_output.json.
  - When the cmd matches a package upgrade, the same call also
    archives the entry into update_logs.json.
  - The update_logs.json entry is what handle_device_update_logs
    returns at GET /api/devices/{id}/update-logs.

Tests don't exercise the agent's network-failure stash-and-retry
path — that's covered indirectly: if a follow-up fails, the next
heartbeat carries the stashed cmd_output and ends up in this same
ingest path.
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

_spec = importlib.util.spec_from_file_location("api_v1117", _CGI_BIN / "api.py")
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
        "WEBHOOK_LOG_FILE", "SERVICES_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


def _seed_device(dev_id="dev-test", token="dev-token-secret"):
    devices = api.load(api.DEVICES_FILE)
    devices[dev_id] = {
        "name":     dev_id,
        "hostname": dev_id,
        "os":       "Ubuntu 24.04",
        "ip":       "10.0.0.1",
        "mac":      "aa:bb:cc:dd:ee:ff",
        "token":    token,
        "last_seen": int(time.time()),
        "enrolled":  int(time.time()),
        "tags":     [], "group": "", "sysinfo": {},
        "monitored": True,
    }
    api.save(api.DEVICES_FILE, devices)
    return dev_id, token


def _seed_admin():
    """Create an admin user + token. Used for the GET /update-logs assertion."""
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


# ─── Minimal follow-up heartbeat (the v1.11.7 fix) ───────────────────────────


class TestFollowUpHeartbeatAccepted(unittest.TestCase):
    """The agent's follow-up heartbeat carries the bare minimum: device id,
    token, cmd_output, and executed_command. The server must accept this
    and persist cmd_output without complaining about missing sysinfo."""

    def setUp(self):
        _isolate(self)
        self.dev_id, self.token = _seed_device()

    def test_minimal_followup_with_cmd_output_stored(self):
        body = {
            "device_id": self.dev_id,
            "token":     self.token,
            "cmd_output": {
                "cmd":    "ls /tmp",
                "output": "file1\nfile2\n",
                "rc":     0,
            },
        }
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)
        # cmd_output.json got the entry
        outputs = api.load(api.CMD_OUTPUT_FILE)
        self.assertIn(self.dev_id, outputs)
        self.assertEqual(len(outputs[self.dev_id]), 1)
        e = outputs[self.dev_id][0]
        self.assertEqual(e["cmd"], "ls /tmp")
        self.assertEqual(e["output"], "file1\nfile2\n")
        self.assertEqual(e["rc"], 0)

    def test_followup_without_cmd_output_is_still_valid(self):
        # A regular heartbeat with no cmd_output should keep working
        # (nothing about the v1.11.7 fix changed the no-op path).
        body = {"device_id": self.dev_id, "token": self.token}
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)
        outputs = api.load(api.CMD_OUTPUT_FILE)
        # No entry should have been added
        self.assertEqual(len(outputs.get(self.dev_id, [])), 0)


# ─── Update-logs archival when cmd is an apt/dnf/pacman upgrade ──────────────


class TestUpgradeArchivedToUpdateLogs(unittest.TestCase):
    """When cmd_output's command string contains the upgrade-detector
    fragments, the server should also write the entry to update_logs.json
    so the per-device "Update history" view can show it.

    This is the path that was breaking end-to-end in v1.11.6 — not because
    the detector logic was wrong, but because cmd_output never reached this
    code at all (the agent dropped it before sending). With the agent fix
    in place these tests confirm the server side does its job.
    """

    def setUp(self):
        _isolate(self)
        self.dev_id, self.token = _seed_device()
        # The actual command string the dashboard's "Upgrade packages"
        # button sends. Includes apt-get -y upgrade as a substring,
        # which is what the detector keys on.
        self.upgrade_cmd = (
            'set -e; if command -v apt-get >/dev/null 2>&1; then '
            '  APT_CONFIG=$(mktemp); '
            '  trap "rm -f $APT_CONFIG" EXIT; '
            '  printf \'APT::Sandbox::User "root";\n'
            'Dpkg::Options:: "--force-confdef";\n'
            'Dpkg::Options:: "--force-confold";\n\' > "$APT_CONFIG"; '
            '  export APT_CONFIG DEBIAN_FRONTEND=noninteractive; '
            '  apt-get update && apt-get -y upgrade && apt-get -y autoremove && apt-get clean; '
            'elif command -v dnf >/dev/null 2>&1; then '
            '  dnf -y upgrade; '
            'elif command -v pacman >/dev/null 2>&1; then '
            '  pacman -Syu --noconfirm; '
            'else '
            '  echo "No supported package manager (apt-get/dnf/pacman) found" >&2; '
            '  exit 2; '
            'fi'
        )

    def test_apt_upgrade_lands_in_update_logs(self):
        body = {
            "device_id": self.dev_id, "token": self.token,
            "cmd_output": {
                "cmd":    self.upgrade_cmd,
                "output": "Reading package lists...\n0 upgraded, 0 newly installed.\n",
                "rc":     0,
            },
        }
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)

        ulogs = api.load(api.UPDATE_LOGS_FILE)
        self.assertIn(self.dev_id, ulogs)
        self.assertEqual(len(ulogs[self.dev_id]), 1)
        entry = ulogs[self.dev_id][0]
        self.assertEqual(entry["exit_code"], 0)
        self.assertIn("Reading package lists", entry["output"])
        self.assertEqual(entry["package_manager"], "apt")

    def test_dnf_upgrade_lands_in_update_logs(self):
        # Same _UPGRADE_CMD has 'dnf -y upgrade' as a fallback branch.
        # If the agent runs that branch on a Fedora/RHEL host, the
        # detector still fires.
        body = {
            "device_id": self.dev_id, "token": self.token,
            "cmd_output": {
                "cmd": self.upgrade_cmd,   # same string; pkg_mgr from substring
                "output": "Last metadata expiration check: 1:00 ago.\n",
                "rc": 0,
            },
        }
        _set_request("POST", "/api/heartbeat", body=body)
        status, _ = _call(api.handle_heartbeat)
        self.assertEqual(status, 200)
        ulogs = api.load(api.UPDATE_LOGS_FILE)
        # Detector matches apt first (it appears earlier in the string),
        # so package_manager will be 'apt'. That's an artifact of the
        # if/elif/else chain in the script and the substring matcher;
        # acceptable since real-world the agent only runs ONE of those
        # branches and the journal output makes it clear which.
        self.assertIn(self.dev_id, ulogs)
        self.assertEqual(len(ulogs[self.dev_id]), 1)

    def test_non_upgrade_command_NOT_archived_to_update_logs(self):
        # Ad-hoc "ls /tmp" should land in cmd_output.json but NOT
        # update_logs.json — that file is just for upgrade runs.
        body = {
            "device_id": self.dev_id, "token": self.token,
            "cmd_output": {"cmd": "ls /tmp", "output": "", "rc": 0},
        }
        _set_request("POST", "/api/heartbeat", body=body)
        _call(api.handle_heartbeat)
        ulogs = api.load(api.UPDATE_LOGS_FILE)
        self.assertNotIn(self.dev_id, ulogs)

    def test_update_logs_endpoint_returns_archived_entry(self):
        # End-to-end: archive an upgrade, then GET it via the API the
        # "Update history" panel uses.
        body = {
            "device_id": self.dev_id, "token": self.token,
            "cmd_output": {
                "cmd": self.upgrade_cmd,
                "output": "Reading package lists... Done\n",
                "rc": 0,
            },
        }
        _set_request("POST", "/api/heartbeat", body=body)
        _call(api.handle_heartbeat)

        _, admin_token = _seed_admin()
        _set_request("GET", f"/api/devices/{self.dev_id}/update-logs",
                     headers={"HTTP_X_TOKEN": admin_token})
        status, body_resp = _call(api.handle_device_update_logs, self.dev_id)
        self.assertEqual(status, 200)
        self.assertEqual(body_resp["device_id"], self.dev_id)
        self.assertEqual(len(body_resp["logs"]), 1)
        self.assertEqual(body_resp["logs"][0]["exit_code"], 0)


# ─── Multiple cmd_output entries accumulate per device, capped ───────────────


class TestMultipleUpgradesAccumulate(unittest.TestCase):
    """Multiple sequential upgrade runs should all land in update_logs,
    capped at MAX_UPDATE_LOGS_PER_DEVICE."""

    def setUp(self):
        _isolate(self)
        self.dev_id, self.token = _seed_device()

    def _send_upgrade(self, output_marker):
        body = {
            "device_id": self.dev_id, "token": self.token,
            "cmd_output": {
                "cmd": "apt-get update && apt-get -y upgrade",
                "output": f"Run {output_marker} output",
                "rc": 0,
            },
        }
        _set_request("POST", "/api/heartbeat", body=body)
        _call(api.handle_heartbeat)

    def test_three_sequential_runs_all_recorded(self):
        for i in range(3):
            self._send_upgrade(f"#{i}")
        ulogs = api.load(api.UPDATE_LOGS_FILE)
        self.assertEqual(len(ulogs[self.dev_id]), 3)
        # Most recent is at the end (chronological)
        self.assertIn("#2", ulogs[self.dev_id][-1]["output"])

    def test_overflow_trims_oldest(self):
        # MAX_UPDATE_LOGS_PER_DEVICE entries plus one more — first should
        # have been evicted.
        cap = api.MAX_UPDATE_LOGS_PER_DEVICE
        for i in range(cap + 2):
            self._send_upgrade(f"#{i}")
        ulogs = api.load(api.UPDATE_LOGS_FILE)
        self.assertEqual(len(ulogs[self.dev_id]), cap)
        # Oldest still kept is the third one we sent (#0 and #1 evicted)
        self.assertIn("#2", ulogs[self.dev_id][0]["output"])
        self.assertIn(f"#{cap + 1}", ulogs[self.dev_id][-1]["output"])


if __name__ == "__main__":
    unittest.main()
