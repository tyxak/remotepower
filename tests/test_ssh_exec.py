#!/usr/bin/env python3
"""v3.4.0: SSH exec for agentless devices + the Synology DSM-upgrade button.

ssh_exec shells out to the system `ssh` (no paramiko), so the subprocess is
mocked — the tests assert how the argv is built (key vs sshpass) and how the
detached upgrade result is interpreted, plus the endpoint gating through the
real admin-auth path.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import ssh_exec

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"
_spec = importlib.util.spec_from_file_location("api_ssh", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestSshExec(unittest.TestCase):
    def test_argv_key_uses_dash_i_batchmode(self):
        argv = ssh_exec._ssh_base_argv("10.0.0.1", "root", 22, key_path="/tmp/k")
        self.assertEqual(argv[0], "ssh")
        self.assertIn("-i", argv)
        self.assertIn("/tmp/k", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertTrue(argv[-1] == "root@10.0.0.1")

    def test_argv_password_uses_sshpass_env(self):
        with patch.object(ssh_exec.shutil, "which", return_value="/usr/bin/sshpass"):
            argv = ssh_exec._ssh_base_argv("h", "root", 2222, password=True)
        self.assertEqual(argv[0:2], ["sshpass", "-e"])   # password via $SSHPASS, not argv
        self.assertIn("2222", argv)

    def test_password_without_sshpass_raises(self):
        with patch.object(ssh_exec.shutil, "which", return_value=None):
            with self.assertRaises(ssh_exec.SshError):
                ssh_exec._ssh_base_argv("h", "root", 22, password=True)

    def test_run_script_requires_auth(self):
        with self.assertRaises(ssh_exec.SshError):
            ssh_exec.run_script("h", "root", 22, "echo hi")   # no key/password

    def test_synology_upgrade_detached_marker(self):
        # Success when the detached launcher echoes its marker.
        with patch.object(ssh_exec, "run_script",
                          return_value={"ok": True, "code": 0,
                                        "stdout": "rp-upgrade-started\n", "stderr": ""}):
            r = ssh_exec.synology_upgrade("10.0.0.1", "root", 22, password="x")
        self.assertTrue(r["ok"])
        self.assertIn("log", r["message"].lower())   # tells the operator where progress goes
        # the script we send must drive synoupgrade + reboot
        self.assertIn("synoupgrade", ssh_exec.DSM_UPGRADE_SCRIPT)
        self.assertIn("reboot", ssh_exec.DSM_UPGRADE_SCRIPT)

    def test_synology_upgrade_failure(self):
        with patch.object(ssh_exec, "run_script",
                          return_value={"ok": False, "code": 255,
                                        "stdout": "", "stderr": "Permission denied"}):
            r = ssh_exec.synology_upgrade("10.0.0.1", "root", 22, key="KEY")
        self.assertFalse(r["ok"])
        self.assertIn("Permission denied", r["error"])


# ── endpoints (real admin auth, ssh_exec mocked) ───────────────────────────
class _Cap(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


api.respond = lambda s, d: (_ for _ in ()).throw(_Cap(s, d))


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def _req(method, path, body=None, token=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode()
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    if token:
        os.environ["HTTP_X_TOKEN"] = token
    else:
        os.environ.pop("HTTP_X_TOKEN", None)


def _admin():
    api.ensure_default_user()
    user = next(iter(api.load(api.USERS_FILE)))
    tok = api.make_token()
    toks = api.load(api.TOKENS_FILE)
    toks[tok] = {"user": user, "created": int(time.time()), "ttl": 3600,
                 "admin": True, "remember": False}
    api.save(api.TOKENS_FILE, toks)
    return tok


def _call(fn, *a):
    try:
        fn(*a)
        return None, None
    except _Cap as c:
        return c.status, c.body


class TestSshEndpoints(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.TOKENS_FILE):
            api.save(f, {})
        self.tok = _admin()
        api.save(api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                                             "ip": "10.0.0.1"}})

    def test_target_and_redacted(self):
        dev = {"ip": "10.0.0.1", "ssh": {"enabled": True, "username": "admin",
               "port": 2222, "password": "p"}}
        tgt = api._ssh_target(dev)
        self.assertEqual((tgt["host"], tgt["user"], tgt["port"]), ("10.0.0.1", "admin", 2222))
        red = api._ssh_redacted(dev)
        self.assertTrue(red["has_password"])
        self.assertNotIn("password", red)

    def test_enable_requires_credentials(self):
        _req("PATCH", "/api/devices/nas1/ssh", {"enabled": True}, self.tok)
        st, _ = _call(api.handle_device_ssh, "nas1")
        self.assertEqual(st, 400)

    def test_save_redacts_secrets(self):
        _req("PATCH", "/api/devices/nas1/ssh",
             {"enabled": True, "username": "root", "password": "s3cr3t", "port": 22}, self.tok)
        st, body = _call(api.handle_device_ssh, "nas1")
        self.assertEqual(st, 200)
        self.assertTrue(body["config"]["has_password"])
        self.assertNotIn("password", body["config"])
        self.assertEqual(api.load(api.DEVICES_FILE)["nas1"]["ssh"]["password"], "s3cr3t")

    def test_upgrade_requires_ssh_configured(self):
        _req("POST", "/api/devices/nas1/synology/upgrade", None, self.tok)  # no ssh cfg
        st, _ = _call(api.handle_device_synology_upgrade, "nas1")
        self.assertEqual(st, 403)

    def test_upgrade_success(self):
        api.save(api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                 "ip": "10.0.0.1", "ssh": {"enabled": True, "username": "root",
                 "password": "p"}}})
        _req("POST", "/api/devices/nas1/synology/upgrade", None, self.tok)
        with patch("ssh_exec.synology_upgrade",
                   return_value={"ok": True, "message": "started"}):
            st, body = _call(api.handle_device_synology_upgrade, "nas1")
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])

    def test_upgrade_requires_admin(self):
        api.save(api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                 "ip": "10.0.0.1", "ssh": {"enabled": True, "password": "p"}}})
        denied = {"hit": False}

        def deny():
            denied["hit"] = True
            raise _Cap(403, {"error": "admin required"})
        orig = api.require_admin_auth
        api.require_admin_auth = deny
        try:
            os.environ["REQUEST_METHOD"] = "POST"
            st, _ = _call(api.handle_device_synology_upgrade, "nas1")
        finally:
            api.require_admin_auth = orig
        self.assertTrue(denied["hit"])
        self.assertEqual(st, 403)


if __name__ == "__main__":
    unittest.main()
