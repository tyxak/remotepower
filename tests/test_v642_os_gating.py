"""v6.4.2: two features that accepted targets they can never act on.

The project calls this class "success-toast-then-silence": the server returns
200, the operator sees a success toast, and nothing ever happens on the host.

1. **Structured file-backup jobs are POSIX-only.** `filebackup._is_abs_path`
   rejects any path not starting with '/', and the generated command is
   rsync/tar over ssh — but `handle_backup_job_create` resolved targets through
   a bare `_resolve_targets` with no OS gate, so a Windows file server could be
   picked from the same device picker as everything else and the job then failed
   silently on every cron tick.

2. **Desired-state host config is Linux-agent-only.** Both the Windows and macOS
   agents list `host_config_desired` in their docstrings as a heartbeat-response
   key they deliberately do not read, yet the PUT returned a plain success.

`_split_targets_by_os_support` — the helper the project prescribes for exactly
this — already existed and was already used by SCAP; it simply had not been
applied here.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-osgate-"))

_spec = importlib.util.spec_from_file_location("api_v642_osgate", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_LINUX_SPEC = {
    "paths": ["/srv/data"],
    "method": "rsync",
    "dest": {"transport": "ssh", "host": "nas.example", "user": "backup",
             "port": 22, "remote_path": "/backups/rp"},
}


class _Call:
    """Drive a handler the way the dispatcher does and capture the response."""

    def __init__(self, testcase, body=None):
        self.tc = testcase
        self.body = json.dumps(body or {}).encode()
        self._saved = {}

    def __enter__(self):
        for name, stub in (
            ("get_body", lambda: self.body),
            ("method", lambda: "POST"),
            ("require_admin_auth", lambda *a, **k: "tester"),
            ("audit_log", lambda *a, **k: None),
        ):
            self._saved[name] = getattr(api, name)
            setattr(api, name, stub)
        return self

    def __exit__(self, *exc):
        for name, orig in self._saved.items():
            setattr(api, name, orig)      # never leak a monkeypatch
        return False

    def run(self, fn, *args):
        try:
            fn(*args)
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, "status", None), getattr(e, "body", None)
        return None, None


class _OsGateBase(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            "lin-1": {"name": "linux-box", "os": "Ubuntu 22.04"},
            "win-1": {"name": "fileserver", "os": "Windows Server 2022 (Build 20348)"},
            "mac-1": {"name": "designer-mac", "os": "macOS 14.5 (23F79)"},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)


class TestFileBackupJobTargets(_OsGateBase):
    def _create(self, ids):
        body = {"name": "nightly", "type": "file", "spec": _LINUX_SPEC,
                "device_ids": ids}
        with _Call(self, body) as c:
            return c.run(api.handle_backup_job_create)

    def test_windows_only_target_is_refused_with_a_reason(self):
        status, body = self._create(["win-1"])
        self.assertEqual(status, 400, body)
        self.assertIn("Linux hosts only", body["error"])
        self.assertIn("fileserver", body["error"],
                      "the refusal must name the host the operator picked")

    def test_mixed_batch_keeps_linux_and_reports_the_rest(self):
        status, body = self._create(["lin-1", "win-1", "mac-1"])
        self.assertEqual(status, 200, body)
        self.assertEqual(sorted(body["skipped_unsupported"]),
                         ["designer-mac", "fileserver"])
        self.assertIn("2 non-Linux host(s)", body["note"])
        jobs = api._backup_jobs_load()["jobs"]
        job = [j for j in jobs if j["id"] == body["id"]][0]
        self.assertEqual(job["device_ids"], ["lin-1"],
                         "a host that cannot run the job must not be stored as a target")

    def test_all_linux_batch_is_unchanged(self):
        status, body = self._create(["lin-1"])
        self.assertEqual(status, 200, body)
        self.assertEqual(body["skipped_unsupported"], [])
        self.assertEqual(body["note"], "")

    def test_command_jobs_are_not_os_gated(self):
        """A raw command job is whatever the operator wrote — including
        PowerShell — so it must keep working on every platform."""
        body = {"name": "win-cmd", "command": "wbadmin start backup",
                "device_ids": ["win-1"]}
        with _Call(self, body) as c:
            status, out = c.run(api.handle_backup_job_create)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["skipped_unsupported"], [])


class TestHostConfigDesiredState(_OsGateBase):
    def _put(self, dev_id):
        with _Call(self, {"motd": "hello", "apply_enabled": True}) as c:
            return c.run(api.handle_device_host_config_put, dev_id)

    def test_linux_host_reports_supported(self):
        status, body = self._put("lin-1")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["supported"])
        self.assertEqual(body["note"], "")

    def test_windows_host_says_nothing_will_be_enforced(self):
        status, body = self._put("win-1")
        self.assertEqual(status, 200, body)
        self.assertFalse(body["supported"])
        self.assertIn("Linux agent only", body["note"])

    def test_macos_host_says_nothing_will_be_enforced(self):
        status, body = self._put("mac-1")
        self.assertEqual(status, 200, body)
        self.assertFalse(body["supported"])

    def test_the_policy_is_still_stored_for_audit(self):
        """Refusing the save would lose an operator's policy record; the fix is
        to tell the truth about enforcement, not to drop the data."""
        self._put("win-1")
        api._invalidate_load_cache(api.DEVICES_FILE)
        hc = (api.load(api.DEVICES_FILE)["win-1"].get("host_config") or {})
        self.assertEqual((hc.get("desired") or {}).get("motd"), "hello")


class TestAgentsStillDocumentTheGap(unittest.TestCase):
    """If an agent ever implements this, the gate above must be revisited —
    fail loudly rather than silently keep refusing a supported platform."""

    def test_win_and_mac_agents_list_host_config_as_unread(self):
        for name in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            p = _ROOT / "client" / name
            if not p.exists():
                self.skipTest(f"{name} excluded from this tree")
            self.assertIn("`host_config_desired`", p.read_text(),
                          f"{name} no longer documents host_config_desired as "
                          "unread — if it now applies it, drop the OS gate in "
                          "handle_device_host_config_put")


if __name__ == "__main__":
    unittest.main()
