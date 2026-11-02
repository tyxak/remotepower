#!/usr/bin/env python3
"""A DNS provider token must not reach the command-output history (7.4.9).

An ACME run is queued as `exec:#acme:<id>#export CF_Token='...' && acme.sh --issue ...`, with the provider's credentials from
Settings in front of the acme.sh call. The agent echoes the whole command back with its result, and `handle_heartbeat` stored the
echo in the host's command-output history. `GET /api/devices/<id>/output` gives that history to every signed-in role, a viewer
included, so the token sat in plain text where any account could read it. The Command Queue page already ran the command through
`_scrub_acme_credentials`; this store did not.

The fix scrubs before the 512-character cap. The order matters: the scrubber matches NAME='value' with a closing quote, so a cap
that cuts inside a long value leaves a quote it cannot match, and the kept part of the secret would stay.

The probe that found it (a subagent's) is reproduced here through the real heartbeat handler. The controls: a command with no
credentials is stored as it was, a variable that is not a provider's credential is kept, and with the scrubber made a no-op the
token is back in the store, which is the old behaviour.
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

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-acme-"))
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v749_acme", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]

DEV = "d1"
SECRET = "cf-SUPERSECRET-token-0123456789"


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


class TestAcmeCredentialsStayOutOfTheHistory(unittest.TestCase):

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond", "verify_token")}
        self._env = dict(os.environ)
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.CONFIG_FILE, {}),
                         (api.MAINT_FILE, {"windows": []}), (api.MAINT_SUPPRESS_LOG, {"entries": []}),
                         (api.CMD_OUTPUT_FILE, {})):
            api.save(f, empty)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {DEV: {"id": DEV, "name": "serverbox", "hostname": "serverbox", "token": "tok",
                                          "last_seen": now, "enrolled": now, "tags": [], "group": "", "sysinfo": {},
                                          "monitored": True}})
        api._LOAD_CACHE.clear()

        def fake(status, data):
            raise _Captured(status, data)
        setattr(api, "respond", fake)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def store_credential(self, value):
        with api._LockedUpdate(api.CONFIG_FILE) as cfg:
            cfg.setdefault("acme_dns_credentials", {})["dns_cf"] = {"CF_Token": value}
        api._LOAD_CACHE.clear()

    def echo(self, cmd):
        """The agent's heartbeat carrying one command result, through the real handler; the stored history rows."""
        raw = json.dumps({"device_id": DEV, "token": "tok", "cmd_output": {"cmd": cmd, "output": "ok", "rc": 0}}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured:
            pass
        api._LOAD_CACHE.clear()
        return (api.load(api.CMD_OUTPUT_FILE) or {}).get(DEV, [])

    def queued(self, secret=SECRET, tag=True):
        self.store_credential(secret)
        prefix = api._acme_credential_env_prefix("dns_cf")
        self.assertIn(secret, prefix, "the queued command carries the credential, as the leak needs")
        cmd = prefix + "'/root/.acme.sh/acme.sh' --issue --dns dns_cf -d 'example.com' --keylength 4096"
        return f"exec:#acme:abc123#{cmd}" if tag else f"exec:{cmd}"

    # ── the leak ──────────────────────────────────────────────────────────────────
    def test_the_tagged_acme_command_is_stored_without_the_token(self):
        rows = self.echo(self.queued())
        self.assertEqual(len(rows), 1)
        self.assertNotIn(SECRET, rows[0]["cmd"])
        self.assertIn("***REDACTED***", rows[0]["cmd"])
        self.assertIn("acme.sh", rows[0]["cmd"], "the structure of the command is still shown")

    def test_an_echo_without_the_tag_is_scrubbed_too(self):
        rows = self.echo(self.queued(tag=False))
        self.assertNotIn(SECRET, rows[0]["cmd"])
        self.assertIn("***REDACTED***", rows[0]["cmd"])

    def test_a_long_value_is_scrubbed_before_the_cap_can_cut_it(self):
        long_secret = "tk-" + "Zx9q" * 200                       # 803 characters, so the 512 cap falls inside it
        rows = self.echo(self.queued(secret=long_secret))
        stored = rows[0]["cmd"]
        self.assertNotIn("Zx9qZx9q", stored, "no part of the value is kept")
        self.assertIn("***REDACTED***", stored)

    def test_the_history_endpoint_every_role_can_read_does_not_return_it(self):
        self.echo(self.queued())
        os.environ["HTTP_X_TOKEN"] = "viewer-token"
        setattr(api, "verify_token", lambda *_a, **_k: ("viewer1", "viewer"))   # only verify_token is stubbed: the real gate runs
        try:
            api.handle_cmd_output(DEV)
        except _Captured as c:
            self.assertEqual(c.status, 200)
            self.assertNotIn(SECRET, json.dumps(c.body))
        else:
            self.fail("handle_cmd_output did not respond")

    # ── rows an earlier release stored ────────────────────────────────────────────
    def seed_old_row(self):
        old_cmd = "exec:#acme:abc123#export CF_Token='%s' && '/root/.acme.sh/acme.sh' --issue -d 'example.com'" % SECRET
        api.save(api.CMD_OUTPUT_FILE, {DEV: [{"ts": 1, "cmd": old_cmd, "output": "ok", "rc": 0}]})
        api._LOAD_CACHE.clear()

    def test_a_row_stored_before_the_fix_is_not_returned_to_a_reader(self):
        self.seed_old_row()
        self.assertIn(SECRET, json.dumps(api.load(api.CMD_OUTPUT_FILE)), "the old row is in the store")
        os.environ["HTTP_X_TOKEN"] = "viewer-token"
        setattr(api, "verify_token", lambda *_a, **_k: ("viewer1", "viewer"))
        try:
            api.handle_cmd_output(DEV)
        except _Captured as c:
            self.assertNotIn(SECRET, json.dumps(c.body))
            self.assertIn("***REDACTED***", json.dumps(c.body))
        else:
            self.fail("handle_cmd_output did not respond")

    def test_a_row_stored_before_the_fix_is_cleaned_when_the_host_next_reports(self):
        self.seed_old_row()
        rows = self.echo("exec:uptime -p")
        self.assertEqual(len(rows), 2)
        self.assertNotIn(SECRET, json.dumps(rows))

    # ── controls ──────────────────────────────────────────────────────────────────
    def test_control_with_the_scrubber_off_the_token_is_in_the_store(self):
        real = api._scrub_acme_credentials
        setattr(api, "_scrub_acme_credentials", lambda cmd: cmd)
        try:
            rows = self.echo(self.queued())
        finally:
            setattr(api, "_scrub_acme_credentials", real)
        self.assertIn(SECRET, rows[0]["cmd"], "the test can see the old behaviour")

    def test_control_a_plain_command_is_stored_as_it_was(self):
        rows = self.echo("exec:uptime -p")
        self.assertEqual(rows[0]["cmd"], "exec:uptime -p")

    def test_control_a_variable_that_is_not_a_provider_credential_is_kept(self):
        cmd = "exec:export WORKDIR='/srv/app' && make deploy"
        rows = self.echo(cmd)
        self.assertEqual(rows[0]["cmd"], cmd)


if __name__ == "__main__":
    unittest.main()
