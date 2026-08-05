"""v6.4.2 — the SSH key audit stops being a list you can only read.

`GET /api/ssh-keys` ranks weak key types first, then most-reused first, and the
page subtitle calls that out: it is explicitly a remediation worklist. It then
offered no action on any row — six read-only columns, zero `data-action` — and
the `ssh_key` mitigation playbook has `'fix': None` and only fires from an
`ssh_key_added` alert, i.e. only for keys added AFTER enrolment, never for the
pre-existing weak/reused ones this page exists to surface. An operator finding an
`ssh-dss` key on 14 hosts had to note the fingerprint, open Host config for each
of the 14, find the user, and hand-edit an authorized_keys block.

A write path already existed (`POST /api/devices/{id}/user-action`
`{action: revokekey}`); nothing linked to it, and it wanted the key LINE, which
the audit deliberately does not send to the browser. So the fix is: let revoke
name the key by FINGERPRINT and resolve the line server-side from the same
baseline the audit is built from.

That resolution is the security-relevant part and is driven here, including the
two ways it must refuse.
"""

import base64
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sshrev642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)

_BLOB = base64.b64encode(b"fake-key-material-for-tests-aaaa").decode()
_LINE = f"ssh-rsa {_BLOB} jakob work laptop"


class _ServerBase(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.fp = api._ssh_key_sha256(_BLOB)
        api.save(api.DEVICES_FILE,
                 {"h1": {"name": "web-01", "token": "t", "last_seen": self.now}})
        api.save(api.SSH_KEY_BASELINE_FILE, {"h1": {"deploy": [_LINE]}})
        self._saved = {n: getattr(api, n) for n in
                       ("verify_token", "get_token_from_request", "_queue_command",
                        "audit_log", "require_perm", "method", "get_json_body")}
        self.queued = []
        api.verify_token = lambda *a, **k: {"user": "admin", "role": "admin"}
        api.get_token_from_request = lambda: "x"
        api._queue_command = lambda d, c, a, **k: self.queued.append((d, c, a))
        api.audit_log = lambda *a, **k: None
        api.require_perm = lambda *a, **k: "admin"
        api.method = lambda: "POST"

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)      # never leak a stub into the next module

    def revoke(self, **body):
        api.get_json_body = lambda: dict({"action": "revokekey"}, **body)
        try:
            api.handle_device_user_action("h1")
        except api.HTTPError as e:
            return e.status, e.body
        return None, None


class TestTheAuditStillDoesNotShipTheKey(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"h1": {"name": "web-01", "last_seen": 1}})
        api.save(api.SSH_KEY_BASELINE_FILE, {"h1": {"deploy": [_LINE]}})
        self._verify = api.verify_token
        api.verify_token = lambda *a, **k: {"user": "admin", "role": "admin"}

    def tearDown(self):
        api.verify_token = self._verify

    def test_response_carries_a_fingerprint_not_the_key_line(self):
        """`GET /api/ssh-keys` is require_auth — every role including viewer
        reads it. Adding the raw key line so the client could revoke would have
        been the easy fix and the wrong one."""
        try:
            api.handle_ssh_keys_fleet()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        self.assertNotIn(_BLOB, json.dumps(body),
                         "the raw key blob is now in the audit response")
        self.assertTrue(body["keys"][0]["fingerprint"].startswith("SHA256:"))
        self.assertIn("device_id", body["keys"][0],
                      "the row needs a device_id or the revoke cannot address it")


class TestRevokeByFingerprint(_ServerBase):
    def test_it_resolves_the_line_and_queues_the_real_command(self):
        status, body = self.revoke(username="deploy", fingerprint=self.fp)
        self.assertTrue(self.queued, f"nothing queued (responded {status} {body})")
        cmd = self.queued[0][1]
        self.assertIn(_LINE, cmd,
                      "the queued command must remove the exact key line")
        self.assertIn("/home/deploy/.ssh/authorized_keys", cmd)

    def test_an_unknown_fingerprint_is_refused(self):
        status, body = self.revoke(username="deploy", fingerprint="SHA256:nope")
        self.assertEqual(status, 404)
        self.assertFalse(self.queued, "queued a command for a key that is not "
                                      "on this host")

    def test_another_users_fingerprint_on_the_same_host_is_refused(self):
        """The lookup is keyed by (device, user, fingerprint). Matching on
        fingerprint alone would let a revoke aimed at `deploy` rewrite root's
        authorized_keys — the command is built from the username."""
        api.save(api.SSH_KEY_BASELINE_FILE, {"h1": {"deploy": [_LINE], "root": []}})
        status, _ = self.revoke(username="root", fingerprint=self.fp)
        self.assertEqual(status, 404)
        self.assertFalse(self.queued)

    def test_another_hosts_fingerprint_is_refused(self):
        """A reused key is the case this page ranks first, so the same
        fingerprint legitimately exists on several hosts. Revoking must still
        only ever touch the host it was addressed to."""
        api.save(api.SSH_KEY_BASELINE_FILE,
                 {"h1": {"deploy": []}, "h2": {"deploy": [_LINE]}})
        status, _ = self.revoke(username="deploy", fingerprint=self.fp)
        self.assertEqual(status, 404)
        self.assertFalse(self.queued)

    def test_the_key_line_form_still_works(self):
        """Additive change — the pre-existing caller passes `sshkey`."""
        status, body = self.revoke(username="deploy", sshkey=_LINE)
        self.assertTrue(self.queued, f"regressed the sshkey form ({status} {body})")

    def test_addkey_is_unaffected_by_the_fingerprint_path(self):
        """You cannot ADD a key by naming a fingerprint — there would be nothing
        to add. It must still 400 on a missing key rather than silently resolve
        one out of the baseline."""
        api.get_json_body = lambda: {"action": "addkey", "username": "deploy",
                                     "fingerprint": self.fp}
        try:
            api.handle_device_user_action("h1")
            status = None
        except api.HTTPError as e:
            status = e.status
        self.assertEqual(status, 400)
        self.assertFalse(self.queued)

    def test_the_resolved_line_still_passes_the_pubkey_guard(self):
        """The baseline is agent-reported. Resolving out of it must not skip the
        validation the sshkey path gets — the line is interpolated into a shell
        command."""
        api.save(api.SSH_KEY_BASELINE_FILE,
                 {"h1": {"deploy": [f"ssh-rsa {_BLOB} evil'; rm -rf /; #"]}})
        bad_fp = api._ssh_key_sha256(_BLOB)
        status, _ = self.revoke(username="deploy", fingerprint=bad_fp)
        self.assertEqual(status, 400,
                         "a baseline line with a quote reached the shell")
        self.assertFalse(self.queued)


class TestRequestModel(unittest.TestCase):
    def test_fingerprint_is_an_accepted_field(self):
        """A model narrower than the handler 400s a body the handler accepts."""
        import request_models
        ok, err = request_models.validate(
            request_models.DeviceUserActionRequest,
            {"action": "revokekey", "username": "deploy",
             "fingerprint": "SHA256:abc"})
        self.assertTrue(ok, err)

    def test_an_empty_body_still_validates(self):
        import request_models
        ok, _ = request_models.validate(
            request_models.DeviceUserActionRequest, {})
        self.assertTrue(ok, "the model became required-field — that is a "
                            "breaking change for every existing client")


class TestClientHalf(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app.js").read_text()
        self.html = (ROOT / "server" / "html" / "index.html").read_text()

    def test_the_table_has_an_action_column(self):
        i = self.html.index('id="ssh-keys-thead"')
        head = self.html[i:self.html.index("</thead>", i)]
        self.assertEqual(head.count("<th "), 7,
                         "the audit table is still six read-only columns")

    def test_the_renderer_emits_a_revoke_action(self):
        self.assertIn('data-action="sshKeyRevoke"', self.js)
        self.assertRegex(self.js, r"\bfunction sshKeyRevoke\s*\(",
                         "a data-action with no function is a dead click")

    def test_revoke_confirms_before_acting(self):
        body = self.js[self.js.index("async function sshKeyRevoke"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("uiConfirm", body,
                      "revoking someone's only SSH key must not be one "
                      "mis-click away")
        self.assertLess(body.index("uiConfirm"), body.index("api('POST'"),
                        "the confirm must precede the request")

    def test_revoke_sends_the_fingerprint_not_a_key(self):
        body = self.js[self.js.index("async function sshKeyRevoke"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("fingerprint: fp", body)
        self.assertIn("action: 'revokekey'", body)

    def test_the_arg_cannot_be_coerced_to_a_number(self):
        """The dispatcher runs `!isNaN(v) ? Number(v) : v` on data-arg. An id
        that can parse as a number arrives as one; `1e5000000000` becomes
        Infinity. The composite arg is separator-joined, so it never can."""
        m = re.search(r'data-action="sshKeyRevoke" data-arg="\$\{([^}]+)\}"',
                      self.js)
        self.assertIsNotNone(m, "revoke arg not found")
        self.assertIn("'|'", m.group(1),
                      "the arg must be composite so isNaN is always true")

    def test_the_reuse_chip_filters_to_that_key(self):
        """The page ranks reused keys first so they get dealt with, then made
        the operator find the other hosts by eye down a fingerprint column."""
        self.assertIn('data-action="sshKeyFilterFp"', self.js)
        self.assertRegex(self.js, r"\bfunction sshKeyFilterFp\s*\(")
        self.assertIn("_sshKeyFpFilter", self.js)

    def test_the_filter_is_escapable(self):
        """A filter with no way out is a trap — the empty state must offer one."""
        body = self.js[self.js.index("function _renderSshKeys"):]
        body = body[:body.index("\n// v6.4.2: narrow the audit")]
        self.assertIn("Show all keys", body)

    def test_colspans_match_the_new_column_count(self):
        body = self.js[self.js.index("async function loadSshKeys"):]
        body = body[:body.index("\n// v6.4.2: narrow the audit")]
        self.assertNotIn('colspan="6"', body,
                         "a stale colspan leaves the empty/error row short of "
                         "the table width")
        self.assertIn("_capFleetRows(rows, 7,", body)

    def test_no_inline_handlers_or_styles(self):
        body = self.js[self.js.index("function _renderSshKeys"):]
        body = body[:body.index("\nasync function sshKeyRevoke")]
        self.assertNotRegex(body, r"\son\w+=", "inline handler dies under CSP")
        self.assertNotRegex(body, r'\sstyle="', "inline style dies under CSP")


if __name__ == "__main__":
    unittest.main()
