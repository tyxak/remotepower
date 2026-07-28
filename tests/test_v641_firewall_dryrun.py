#!/usr/bin/env python3
"""v6.4.1 guardrail: firewall on-host dry-run (roadmap B17).

The preview branch of handle_device_firewall_rule now hands the client a
NATIVE check command for the backends that have one (ufw --dry-run, nft -c),
so the UI can run it through the run-and-wait exec path and show the host's
own verdict before queueing. Functional — drives the real handler, no source
greps. Runs under both backends via `make test-both`.
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


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestFirewallDryRunPreview(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method",
                                "require_perm")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"
        api.require_perm = lambda *a, **k: "tester"
        self.dev_id = "fw-host"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {"name": self.dev_id, "token": "t", "os": "Linux",
                          "last_seen": int(time.time()), "sysinfo": {}}})
        api.save(api.CMDS_FILE, {})

    def _preview(self, body):
        body = dict(body, preview=True)
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_device_firewall_rule(self.dev_id)
        except _Captured as c:
            return c.status, c.body
        raise AssertionError("handler did not respond")

    def test_ufw_add_carries_native_dry_run(self):
        status, body = self._preview(
            {"backend": "ufw", "op": "add", "spec": "allow 22/tcp"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["command"], "ufw allow 22/tcp")
        self.assertEqual(body["dryrun_command"], "ufw --dry-run allow 22/tcp")

    def test_ufw_delete_carries_native_dry_run(self):
        status, body = self._preview(
            {"backend": "ufw", "op": "delete", "ref": "3"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["dryrun_command"], "ufw --dry-run --force delete 3")

    def test_nftables_add_carries_check_command(self):
        spec = "add rule inet filter input tcp dport 22 accept"
        status, body = self._preview(
            {"backend": "nftables", "op": "add", "spec": spec})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["dryrun_command"], f"nft -c {spec}")

    def test_backends_without_dry_run_stay_command_only(self):
        for req in (
                {"backend": "iptables", "op": "add",
                 "spec": "-A INPUT -p tcp --dport 22 -j ACCEPT"},
                {"backend": "firewalld", "op": "add",
                 "spec": "--add-port=22/tcp"}):
            status, body = self._preview(req)
            self.assertEqual(status, 200, body)
            self.assertIn("command", body)
            self.assertNotIn(
                "dryrun_command", body,
                f"{req['backend']} has no native dry-run — offering one would "
                "run a broken command on the host")

    def test_preview_never_queues(self):
        self._preview({"backend": "ufw", "op": "add", "spec": "allow 22/tcp"})
        self.assertEqual(api.load(api.CMDS_FILE) or {}, {},
                         "a preview must not queue anything")

    def test_dry_run_command_passes_the_exec_validator_shape(self):
        # The UI feeds dryrun_command into /exec/wait, which caps at 512 chars
        # — the composed command must fit even for a long-but-valid spec.
        spec = "add rule inet filter input ip saddr 10.0.0.0/8 tcp dport 5432 accept"
        _status, body = self._preview(
            {"backend": "nftables", "op": "add", "spec": spec})
        self.assertLess(len(body["dryrun_command"]), 512)


if __name__ == "__main__":
    unittest.main(verbosity=2)
