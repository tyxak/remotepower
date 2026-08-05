"""v6.4.2 — an encrypted backup can be restored through the UI.

`handle_backup_restore` has accepted an encrypted `*.tar.gz.enc` and taken the
key from `X-RP-Backup-Passphrase` since encryption shipped. The UI never sent
that header, never prompted for a passphrase, and the file picker's `accept`
list did not even offer `.enc`. So the only in-app restore worked exclusively
for plaintext archives, or on a box that already had the passphrase in its
environment — which is precisely NOT the rebuilt-host case the header exists for.

The DR scenario is: the controller is gone, the operator stands up a fresh box,
installs RemotePower, logs in, and picks their `.enc` off a USB stick. The
picker hid it; forcing it through returned "supply the passphrase via the
X-RP-Backup-Passphrase header", with no field anywhere in the product to supply
it. They then had to find a shell, edit api.env and restart the app server —
during an outage, guided by documentation that still said there was no in-UI
restore at all and handed them a `tar -xzf` recipe.

The server half is DRIVEN (real crypto, real handler, all three passphrase
cases); it was never the broken half, and pinning it is what stops the fix
regressing on the side nobody was looking at.
"""

import importlib.util
import io
import os
import pathlib
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-drrestore642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_HTML = ROOT / "server" / "html"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestEncryptedRestoreDriven(unittest.TestCase):
    def setUp(self):
        try:
            import backup_crypto
        except ImportError:
            self.skipTest("backup_crypto unavailable")
        if not backup_crypto.available():
            self.skipTest("cryptography library unavailable")
        self.bc = backup_crypto
        d = pathlib.Path(tempfile.mkdtemp())
        inner = d / "remotepower"
        inner.mkdir()
        (inner / "config.json").write_text('{"restored": true}')
        tgz = d / "b.tar.gz"
        with tarfile.open(tgz, "w:gz") as t:
            t.add(inner, arcname="remotepower")
        enc = d / "b.tar.gz.enc"
        self.bc.encrypt_file(tgz, enc, "pass123")
        self.blob = enc.read_bytes()
        self._saved = {k: getattr(api, k) for k in
                       ("require_admin_auth", "audit_log", "method", "_env",
                        "_backup_passphrase")}
        api.require_admin_auth = lambda *a, **k: "admin"
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"
        api._backup_passphrase = lambda: ""

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _restore(self, header=None):
        env = {"CONTENT_LENGTH": str(len(self.blob))}
        if header is not None:
            env["HTTP_X_RP_BACKUP_PASSPHRASE"] = header
        api._env = lambda k, d="": env.get(k, d)
        api.sys.stdin = type("I", (), {"buffer": io.BytesIO(self.blob)})()
        try:
            api.handle_backup_restore()
            return None, None
        except api.HTTPError as e:
            return e.status, e.body

    def test_the_right_passphrase_restores(self):
        status, body = self._restore("pass123")
        self.assertEqual(status, 200, body)
        self.assertGreaterEqual(body.get("restored", 0), 1)

    def test_no_passphrase_says_exactly_what_is_missing(self):
        status, body = self._restore(None)
        self.assertEqual(status, 400)
        self.assertIn("X-RP-Backup-Passphrase", body["error"])

    def test_a_wrong_passphrase_fails_closed(self):
        """GCM tag verification — a wrong key must fail, never half-restore."""
        status, body = self._restore("nope")
        self.assertEqual(status, 400)
        self.assertIn("decryption failed", body["error"])


class TestTheClientSendsIt(unittest.TestCase):
    def setUp(self):
        self.js = (_HTML / "static" / "js" / "app.js").read_text()
        self.html = (_HTML / "index.html").read_text()

    def test_the_header_is_sent(self):
        self.assertIn("X-RP-Backup-Passphrase", self.js,
                      "the header the server requires is named nowhere in the "
                      "client — an encrypted archive cannot be restored")

    def test_it_prompts_only_for_an_encrypted_file(self):
        """A passphrase prompt on every plaintext restore would be noise."""
        body = self.js[self.js.index("async function restoreBackup"):]
        body = body[:body.index("\n}\n")]
        self.assertRegex(body, r"\\\.enc\$?/i")
        self.assertIn("uiPrompt", body)

    def test_the_prompt_is_a_password_field(self):
        body = self.js[self.js.index("async function restoreBackup"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("type: 'password'", body)

    def test_cancelling_the_prompt_aborts_the_restore(self):
        """uiPrompt resolves null on cancel. Treating that as an empty
        passphrase would upload the archive anyway and 400 — after the operator
        explicitly backed out of a destructive action."""
        body = self.js[self.js.index("async function restoreBackup"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("pass === null", body)

    def test_the_file_picker_offers_enc(self):
        m = re.search(r'id="restore-file-input"[^>]*accept="([^"]+)"', self.html)
        self.assertIsNotNone(m, "restore file input not found")
        self.assertIn(".enc", m.group(1),
                      "the picker hides the exact file the DR case needs")

    def test_the_confirm_still_precedes_everything(self):
        """Restore overwrites the live data dir. The passphrase prompt must not
        get in front of the are-you-sure."""
        body = self.js[self.js.index("async function restoreBackup"):]
        body = body[:body.index("\n}\n")]
        self.assertLess(body.index("uiConfirm"), body.index("uiPrompt"))


class TestDocsNoLongerPointAway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ROOT / "docs" / "self-monitoring.md"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.doc = p.read_text()

    def test_it_no_longer_says_there_is_no_in_ui_restore(self):
        self.assertNotIn("There's no in-UI restore", self.doc,
                         "the documentation points away from the feature it "
                         "should be explaining")

    def test_it_documents_the_encrypted_case(self):
        self.assertIn(".enc", self.doc)
        self.assertIn("passphrase", self.doc.lower())

    def test_it_does_not_claim_openssl_compatibility(self):
        """`.enc` is a custom AES-256-GCM container (RPBKENC1 magic, PBKDF2
        header), NOT an `openssl enc` file. An openssl recipe in a DR document
        is worse than no recipe — it fails at the moment it is needed."""
        self.assertNotIn("openssl enc -d", self.doc)

    def test_the_documented_manual_recipe_actually_works(self):
        """The doc hands the operator a `backup_crypto.decrypt_file` snippet.
        Drive it, because a DR recipe nobody has run is a guess."""
        try:
            import backup_crypto
        except ImportError:
            self.skipTest("backup_crypto unavailable")
        if not backup_crypto.available():
            self.skipTest("cryptography library unavailable")
        self.assertIn("backup_crypto.decrypt_file", self.doc)
        d = pathlib.Path(tempfile.mkdtemp())
        src, enc, out = d / "a", d / "a.enc", d / "b"
        src.write_bytes(b"payload" * 500)
        backup_crypto.encrypt_file(src, enc, "pw")
        backup_crypto.decrypt_file(enc, out, "pw")
        self.assertEqual(out.read_bytes(), src.read_bytes())
        self.assertEqual(enc.read_bytes()[:8], b"RPBKENC1",
                         "the magic the doc names is wrong")


if __name__ == "__main__":
    unittest.main()


class TestChangeApprovalRecordsWhoAndWhy(unittest.TestCase):
    """The four-eyes approver saw neither.

    `_create_confirmation` stored no reason and no change reference, and the
    Confirmations table was still shaped for MCP — Status / Requested / Action /
    Device / **AI host** / **Prompt** — so a human-originated reboot showed the
    second admin two blank cells and no name, while `requested_by`, which the API
    does return, was rendered nowhere. Change approval is the control an auditor
    tests for CC8.1 and A.8.32; without who and why it degrades to
    rubber-stamping. The precedent already existed in the same renderer: an
    `ai_exec_action` proposal DOES surface a reason, so the approver saw *why*
    for an AI request and nothing for a human one.
    """

    def setUp(self):
        self._saved = {k: getattr(api, k, None) for k in
                       ("audit_log", "require_admin_auth", "_tenant_visible")}
        api.audit_log = lambda *a, **k: None
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api.save(api.DEVICES_FILE, {"capp1": {"name": "web01"}})

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                setattr(api, k, v)

    def _entry(self, cid):
        rows = (api.load(api.CONFIRMATIONS_FILE) or {}).get("confirmations") or []
        return next(c for c in rows if c["id"] == cid)

    def test_a_reason_and_ticket_are_stored(self):
        cid = api._create_confirmation(
            "queue_command", "capp1", {"command": "reboot"}, "jakob", None, None,
            reason="post-patch reboot window", ticket_ref="CHG-1042")
        e = self._entry(cid)
        self.assertEqual(e["reason"], "post-patch reboot window")
        self.assertEqual(e["ticket_ref"], "CHG-1042")
        self.assertEqual(e["requested_by"], "jakob")

    def test_it_stays_additive(self):
        """Every existing call site passes neither."""
        cid = api._create_confirmation("queue_command", "capp1", {}, "jakob",
                                       None, None)
        e = self._entry(cid)
        self.assertIsNone(e["reason"])
        self.assertIsNone(e["ticket_ref"])

    def test_the_reason_is_sanitised_and_bounded(self):
        cid = api._create_confirmation("queue_command", "capp1", {}, "jakob",
                                       None, None, reason="x" * 900,
                                       ticket_ref="y" * 200)
        e = self._entry(cid)
        self.assertLessEqual(len(e["reason"]), 500)
        self.assertLessEqual(len(e["ticket_ref"]), 64)

    def test_the_list_handler_returns_them(self):
        cid = api._create_confirmation("queue_command", "capp1", {}, "jakob",
                                       None, None, reason="why",
                                       ticket_ref="CHG-1")
        api.require_admin_auth = lambda *a, **k: "admin"
        api._tenant_visible = lambda d: True
        try:
            api.handle_confirmations_list()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        row = next(c for c in body["confirmations"] if c["id"] == cid)
        for k in ("requested_by", "reason", "ticket_ref"):
            with self.subTest(field=k):
                self.assertIn(k, row)

    def test_park_for_approval_threads_it(self):
        """The queue path is the one every human reboot/upgrade/uninstall takes;
        a reason that stops at the handler boundary helps nobody."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def _park_for_approval("):]
        fn = fn[:fn.index("\ndef ")]
        self.assertIn("reason=reason", fn)
        self.assertIn("ticket_ref=ticket_ref", fn)

    def test_the_renderer_shows_who_and_why(self):
        js = (_HTML / "static" / "js" / "app.js").read_text()
        body = js[js.index("function _renderConfirmations"):]
        body = body[:body.index("\nasync function approveConfirmation")]
        self.assertIn("c.requested_by", body,
                      "the API returns it and the table still hides it")
        self.assertIn("_confirmationWhy(c)", body)

    def test_a_missing_reason_is_called_out_not_blank(self):
        """A blank cell reads as "nothing to see"; the approver needs to know
        they are about to approve on the action name alone."""
        js = (_HTML / "static" / "js" / "app.js").read_text()
        fn = js[js.index("function _confirmationWhy"):]
        fn = fn[:fn.index("\n}\n")]
        self.assertIn("no reason given", fn)

    def test_the_approve_dialog_stops_calling_everything_mcp(self):
        js = (_HTML / "static" / "js" / "app.js").read_text()
        body = js[js.index("async function approveConfirmation"):]
        body = body[:body.index("\n}\n")]
        code = re.sub(r"^\s*//.*$", "", body, flags=re.M)
        self.assertNotIn("MCP write action", code)
        self.assertIn("requested_by", code,
                      "the dialog should name who asked")

    def test_the_cache_it_reads_actually_exists(self):
        """`_confirmationsCache` did not exist when the dialog first referenced
        it — an undefined global in JS dies at runtime in a branch nobody
        exercises, which is why the standing rule is to grep for the definition
        rather than trust the name."""
        js = (_HTML / "static" / "js" / "app.js").read_text()
        self.assertRegex(js, r"\blet _confirmationsCache\b")
        self.assertIn("_confirmationsCache = (data && data.confirmations)", js,
                      "declared and never filled")

    def test_the_table_header_matches_the_row_width(self):
        html = (_HTML / "index.html").read_text()
        i = html.index('id="confirmations-thead"')
        head = html[i:html.index("</thead>", i)]
        self.assertEqual(head.count("<th "), 8)
        self.assertIn('colspan="8"', html[i:i + 1400],
                      "the empty-state row is narrower than the table")
