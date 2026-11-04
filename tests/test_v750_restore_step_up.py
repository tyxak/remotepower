#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, follow-up to the gated command kinds): a restore is a governance step, so it asks for a fresh step-up.

The step-up re-authentication protects the switches that govern the product: four-eyes approval, MFA-required roles, SSO-only,
the IP allow-list, the WORM sink, audit retention and forwarding, tenancy and the litigation hold. Saving one of them from
Settings asks for it. Three other routes replace the same switches without asking:

* `POST /api/config/revisions/restore` swaps the whole settings document for a saved revision, so a revision from before
  four-eyes was switched on switches it off again.
* `POST /api/backup/restore` and `POST /api/backup/s3-restore` replace the whole data directory: the settings, the users (a
  restored `users.json` can hold an administrator that creating one by hand would have needed a step-up for) and the tokens.

What this holds:

* The three routes answer 403 `step_up_required` without a fresh step-up, change nothing and read nothing (the upload is not read,
  the bucket is not contacted, no safety snapshot is written). An API key cannot step up, so it cannot restore.
* A revision restore asks only when a governance switch would change, compared the way the gate reads it (a missing key is its
  default, a list is a set, a hold is on or off, `approval_gated_kinds` asks only when it narrows). A revision that differs in
  nothing but ordinary settings restores without a prompt, because a prompt that fires when nothing sensitive changes is one
  operators click through.
* With a fresh step-up the restore goes through and the audit trail names the switches it changed.
* Every handler that hands an archive to `_restore_apply` asks for the step-up (an AST walk, with a control that the walk finds both).
* The three buttons in the web client send the request again after the password prompt (run in node, not read as text).
"""

import ast
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-rst-"))

import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v750_rst", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# One (stronger, weaker) pair per governance key: restoring the weaker value over the stronger one is a change the gate has to see.
PAIRS = {
    "change_approval_enabled": (True, False),
    "change_approval_no_self": (True, False),
    "mfa_required_roles": (["admin"], []),
    "sso_only": (True, False),
    "ip_allowlist": (["10.0.0.0/8"], []),
    "audit_worm_path": ("/var/log/worm", ""),
    "audit_log_retention_days": (365, 30),
    "audit_forward_enabled": (True, False),
    "tenancy_enforced": (True, False),
    "approval_gated_kinds": (["reboot", "shutdown", "upgrade"], ["reboot"]),
    "litigation_hold": ({"enabled": True, "reason": "case 12"}, {"enabled": False}),
}


class TestThePopulation(unittest.TestCase):
    """The table above is the population of the checks below: a key added to the gate must be added to it."""

    def test_the_table_covers_every_governance_key(self):
        self.assertEqual(set(PAIRS), set(api._GOVERNANCE_CONFIG_KEYS))
        self.assertGreaterEqual(len(PAIRS), 10)


class TestWhatCountsAsAChange(unittest.TestCase):

    def changed(self, new, cur):
        return api._governance_keys_changed_by_document(new, cur)

    def test_each_key_is_seen_in_the_direction_that_weakens_it(self):
        for key, (strong, weak) in PAIRS.items():
            with self.subTest(key=key):
                self.assertEqual(self.changed({key: weak}, {key: strong}), [key])

    def test_a_key_the_revision_does_not_have_counts_as_its_default(self):
        """A revision saved before a switch existed carries no key: restoring it removes the switch."""
        for key in ("change_approval_enabled", "mfa_required_roles", "sso_only", "ip_allowlist", "audit_worm_path",
                    "audit_forward_enabled", "tenancy_enforced", "litigation_hold", "change_approval_no_self"):
            with self.subTest(key=key):
                # the value of the pair that is not the default (no-self approval is ON by default, so its weaker value is the one)
                other = next(v for v in PAIRS[key] if api._governance_effective({key: v}, key) != api._governance_effective({}, key))
                self.assertEqual(self.changed({}, {key: other}), [key])
        self.assertEqual(self.changed({}, {"audit_log_retention_days": 365}), ["audit_log_retention_days"])
        self.assertEqual(self.changed({}, {"approval_gated_kinds": list(api._APPROVAL_GATED_KINDS)}), [])  # the default, written out

    def test_the_default_written_out_is_not_a_change(self):
        """Nothing sensitive changes, so nothing asks."""
        same = [
            {"change_approval_no_self": True},
            {"change_approval_enabled": False},
            {"litigation_hold": {"enabled": False}},
            {"approval_gated_kinds": list(api._APPROVAL_GATED_KINDS)},
            {"audit_log_retention_days": 90},
            {"ip_allowlist": []},
            {"mfa_required_roles": []},
            {"audit_worm_path": ""},
            {"sso_only": False},
            {"tenancy_enforced": False},
            {"audit_forward_enabled": False},
        ]
        for doc in same:
            with self.subTest(doc=doc):
                self.assertEqual(self.changed(doc, {}), [])
                self.assertEqual(self.changed({}, doc), [])

    def test_a_list_is_compared_as_a_set(self):
        self.assertEqual(self.changed({"ip_allowlist": ["b", "a"]}, {"ip_allowlist": ["a", "b"]}), [])
        self.assertEqual(self.changed({"ip_allowlist": ["a"]}, {"ip_allowlist": ["a", "b"]}), ["ip_allowlist"])
        self.assertEqual(self.changed({"mfa_required_roles": ["ops", "admin"]}, {"mfa_required_roles": ["admin", "ops"]}), [])

    def test_a_kind_list_asks_only_when_it_narrows(self):
        wide = list(api._APPROVAL_GATED_KINDS) + [k for k in api._APPROVAL_KINDS_ALL if k not in api._APPROVAL_GATED_KINDS][:1]
        self.assertGreater(len(wide), len(api._APPROVAL_GATED_KINDS))
        self.assertEqual(self.changed({"approval_gated_kinds": wide}, {}), [])
        self.assertEqual(self.changed({}, {"approval_gated_kinds": wide}), ["approval_gated_kinds"])

    def test_ordinary_settings_are_not_governance(self):
        self.assertEqual(self.changed({"default_poll_interval": 30, "brand_name": "A"},
                                      {"default_poll_interval": 60, "brand_name": "B", "online_ttl": 300}), [])

    def test_a_document_that_is_not_a_map_does_not_raise(self):
        self.assertEqual(self.changed(None, {"sso_only": True}), ["sso_only"])
        self.assertEqual(self.changed({"sso_only": True}, None), ["sso_only"])
        self.assertEqual(self.changed({"audit_log_retention_days": float("inf")}, {}), [])


class _Base(unittest.TestCase):
    FILES = ("CONFIG_FILE", "CONFIG_REVS_FILE", "TOKENS_FILE", "USERS_FILE")

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-rst-cfg-"))
        self._saved = {n: getattr(api, n) for n in self.FILES}
        for n in self.FILES:
            setattr(api, n, self.d / self._saved[n].name)   # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        self.tkey = api._token_hash("t")
        api.save(api.TOKENS_FILE, {self.tkey: {"user": "root", "created": int(time.time())}})
        api.save(api.USERS_FILE, {"root": {"password_hash": api.hash_password("correct horse"), "role": "admin"}})
        self.audit = []
        for name, value in (("verify_token", lambda token=None, *a, **k: ("root", "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: "POST"),
                            ("audit_log", lambda *a, **k: self.audit.append((a, k)))):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
            api._invalidate_load_cache(v)

    def stamp(self, ago=0):
        tokens = api.load(api.TOKENS_FILE)
        tokens[self.tkey]["step_up_at"] = int(time.time()) - ago
        api.save(api.TOKENS_FILE, tokens)

    def as_api_key(self):
        """An API key has no session token to stamp: the token does not resolve to a session entry."""
        api.save(api.TOKENS_FILE, {})
        api._invalidate_load_cache(api.TOKENS_FILE)

    def call(self, fn, body=None):
        with mock.patch.object(api, "get_json_obj", lambda: dict(body or {})), \
                mock.patch.object(api, "_read_valid", lambda model, *a, **k: dict(body or {})):
            try:
                fn()
            except api.HTTPError as e:
                return e.status, e.body
        self.fail(f"{fn.__name__} answered nothing")

    def audited(self, action):
        """The (args, kwargs) of each audit_log call for `action`."""
        return [(a, k) for a, k in self.audit if len(a) > 1 and a[1] == action]


class TestRevisionRestore(_Base):

    def setUp(self):
        super().setUp()
        # The live document has four-eyes on, an allow-list and a narrow-but-default kind list; the revision is an older state.
        self.live = {"change_approval_enabled": True, "ip_allowlist": ["10.0.0.0/8"], "default_poll_interval": 60,
                     "litigation_hold": {"enabled": True, "reason": "case 12"}}
        api.save(api.CONFIG_FILE, dict(self.live))
        api._invalidate_load_cache(api.CONFIG_FILE)

    def revision(self, config):
        api.save(api.CONFIG_REVS_FILE, {"revisions": [{"id": "rev-a", "ts": 1, "user": "x", "changed_keys": [], "config": config}]})
        api._invalidate_load_cache(api.CONFIG_REVS_FILE)

    def stored(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}

    def revisions_now(self):
        api._invalidate_load_cache(api.CONFIG_REVS_FILE)
        return (api.load(api.CONFIG_REVS_FILE) or {}).get("revisions") or []

    def restore(self):
        return self.call(api.handle_config_revision_restore, {"id": "rev-a"})

    def test_a_revision_that_switches_four_eyes_off_asks_and_changes_nothing(self):
        self.revision({"change_approval_enabled": False, "ip_allowlist": ["10.0.0.0/8"],
                       "litigation_hold": {"enabled": True, "reason": "case 12"}})
        status, body = self.restore()
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.stored(), self.live)
        self.assertEqual(len(self.revisions_now()), 1, "a refused restore records no pre-restore revision")
        self.assertEqual(self.audited("config_restored"), [])

    def test_a_revision_older_than_the_switch_asks(self):
        """The key is simply missing from the old document, which is what turns it off once restored."""
        self.revision({"default_poll_interval": 30, "ip_allowlist": ["10.0.0.0/8"], "litigation_hold": {"enabled": True}})
        status, body = self.restore()
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.stored(), self.live)

    def test_lifting_the_litigation_hold_or_emptying_the_allow_list_asks(self):
        for doc in ({"change_approval_enabled": True, "ip_allowlist": ["10.0.0.0/8"], "litigation_hold": {"enabled": False}},
                    {"change_approval_enabled": True, "ip_allowlist": [], "litigation_hold": {"enabled": True}}):
            with self.subTest(doc=doc):
                self.revision(doc)
                status, body = self.restore()
                self.assertEqual((status, body.get("code")), (403, "step_up_required"))
                self.assertEqual(self.stored(), self.live)

    def test_a_stale_step_up_asks(self):
        self.stamp(ago=api.STEP_UP_WINDOW_SECONDS + 60)
        self.revision({"default_poll_interval": 30})
        status, body = self.restore()
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))

    def test_an_api_key_cannot_restore_such_a_revision(self):
        self.as_api_key()
        self.revision({"default_poll_interval": 30})
        status, body = self.restore()
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.stored(), self.live)

    def test_a_fresh_step_up_lets_it_through_and_the_audit_trail_names_the_switches(self):
        self.stamp(ago=30)
        old = {"default_poll_interval": 30}
        self.revision(old)
        status, body = self.restore()
        self.assertEqual((status, body.get("ok")), (200, True), body)
        self.assertEqual(self.stored(), old)
        self.assertEqual(len(self.revisions_now()), 2, "the replaced document is kept as a revision of its own")
        named = self.audited("governance_config_change")
        self.assertEqual(len(named), 1)
        detail = named[0][1].get("detail", "")
        for key in ("change_approval_enabled", "ip_allowlist", "litigation_hold"):
            self.assertIn(key, detail)
        self.assertEqual(len(self.audited("config_restored")), 1)

    def test_a_revision_that_differs_only_in_ordinary_settings_restores_without_a_prompt(self):
        """Control on the other direction: no stamp at all, and it goes through, with no governance entry in the trail."""
        old = dict(self.live, default_poll_interval=30)
        self.revision(old)
        status, body = self.restore()
        self.assertEqual((status, body.get("ok")), (200, True), body)
        self.assertEqual(self.stored()["default_poll_interval"], 30)
        self.assertEqual(self.audited("governance_config_change"), [])

    def test_the_default_written_out_does_not_ask(self):
        self.revision(dict(self.live, change_approval_no_self=True, audit_log_retention_days=90, mfa_required_roles=[],
                           approval_gated_kinds=list(api._APPROVAL_GATED_KINDS), default_poll_interval=45))
        status, body = self.restore()
        self.assertEqual((status, body.get("ok")), (200, True), body)

    def test_an_unknown_revision_is_still_a_404(self):
        self.revision({})
        status, _ = self.call(api.handle_config_revision_restore, {"id": "rev-none"})
        self.assertEqual(status, 404)

    def test_the_lock_is_released_by_a_refusal(self):
        """The refusal comes from inside the locked read-modify-write; the next save must not hang or lose the document."""
        self.revision({"default_poll_interval": 30})
        self.restore()
        api.save(api.CONFIG_FILE, dict(self.live, default_poll_interval=61))
        self.assertEqual(self.stored()["default_poll_interval"], 61)


class TestBackupRestores(_Base):

    def setUp(self):
        super().setUp()
        self.reads = []
        p = mock.patch.object(api, "get_body", lambda: self.reads.append("body") or b"")
        p.start()
        self.addCleanup(p.stop)
        self.snap = api.DATA_DIR / api._BACKUP_SNAPSHOT_DIR
        shutil.rmtree(self.snap, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.snap, True)

    def test_the_upload_without_a_step_up_is_refused_before_anything_is_read(self):
        status, body = self.call(api.handle_backup_restore)
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.reads, [], "the upload must not be read before the gate")
        self.assertFalse(self.snap.exists(), "no safety snapshot is written for a refused restore")

    def test_the_upload_with_a_fresh_step_up_reaches_the_archive_check(self):
        """Control: the stamp is what lets the request through to the next step (an empty body is a 400)."""
        self.stamp(ago=10)
        status, body = self.call(api.handle_backup_restore)
        self.assertEqual(status, 400)
        self.assertIn("empty body", body.get("error", ""))
        self.assertEqual(self.reads, ["body"])

    def test_an_api_key_cannot_restore_an_upload(self):
        self.as_api_key()
        status, body = self.call(api.handle_backup_restore)
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.reads, [])

    def test_the_bucket_restore_without_a_step_up_never_contacts_the_bucket(self):
        def boom(*a, **k):
            raise AssertionError("the bucket code was reached before the gate")
        with mock.patch.object(api, "_s3_request_settings", boom), mock.patch.object(api, "_s3_client", boom):
            status, body = self.call(api.handle_backup_s3_restore, {"name": "remotepower-20260101-000000.tar.gz.enc"})
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertFalse(self.snap.exists())

    def test_the_bucket_restore_with_a_fresh_step_up_reaches_its_own_checks(self):
        self.stamp(ago=10)
        status, body = self.call(api.handle_backup_s3_restore, {"name": "not-an-archive"})
        self.assertEqual(status, 400)
        self.assertIn("archive", body.get("error", ""))


class TestEveryRestoreHandlerAsks(unittest.TestCase):
    """The class, not the three routes: whatever hands an archive to `_restore_apply` has to have asked first."""

    @classmethod
    def setUpClass(cls):
        tree = ast.parse((_CGI / "backups_handlers.py").read_text())
        cls.callers = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name != "_restore_apply":
                calls = {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
                if "_restore_apply" in calls:
                    cls.callers.append(node)

    def test_the_walk_finds_both_the_upload_and_the_bucket_restore(self):
        self.assertEqual(sorted(f.name for f in self.callers), ["handle_backup_restore", "handle_backup_s3_restore"])

    def test_each_of_them_asks_for_the_step_up_before_it_reads_anything(self):
        for fn in self.callers:
            with self.subTest(handler=fn.name):
                names = [c.func.attr for c in ast.walk(fn)
                         if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)]
                self.assertIn("require_step_up", names)
                first_step = min(c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                                 and c.func.attr == "require_step_up")
                reads = [c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                         and c.func.attr in ("get_body", "get_json_obj", "_s3_request_settings", "_s3_client")]
                self.assertTrue(all(first_step < r for r in reads), (fn.name, first_step, reads))


_NODE = shutil.which("node")

_STUBS = r"""
const out = {fetches: [], apiCalls: [], toasts: [], modal: 0, text: null, hidden: null, sent: []};
const queue = [];
const DECISION = __DECISION__;
const result = {hidden: true, textContent: ''};
const document = {getElementById(id) {
  if (id === 'restore-file-input') return {files: [{name: 'backup.tar.gz'}], value: 'x'};
  if (id === 'backup-result') return result;
  return null;
}};
function getToken() { return 't'; }
async function uiConfirm() { return true; }
async function uiPrompt() { return ''; }
function toast(m, t) { out.toasts.push([String(m), t]); }
function failToast(r) { out.toasts.push(['FAIL', (r && r.code) || '']); }
function loadSettings() {}
function loadAlertParams() {}
function closeModal() {}
function _backupS3Form() { return {}; }
async function _openStepUpModal() { out.modal++; return DECISION; }
async function api(method, path, body) { out.apiCalls.push(method + ' ' + path); return queue.shift(); }
async function fetch(url, opts) {
  out.fetches.push(url + ' ' + opts.method);
  const r = queue.shift();
  return {ok: r.status === 200, status: r.status, json: async () => r.body};
}
"""

_STEP = {"status": 403, "body": {"error": "step-up re-authentication required", "code": "step_up_required"}}
_DONE = {"status": 200, "body": {"ok": True, "restored": 3, "snapshot": "pre-restore-1"}}


@unittest.skipUnless(_NODE, "node is needed to run the client functions")
class TestTheButtonsAskAndSendAgain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = (_JS / "app.js").read_text()
        cls.s3 = (_JS / "app-s3restore.js").read_text()

    def run_js(self, funcs, scenario, decision="true"):
        script = _STUBS.replace("__DECISION__", decision) + "\n".join(funcs) + "\n" + scenario
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, dir=tempfile.gettempdir()) as fh:
            fh.write(script)
            path = fh.name
        self.addCleanup(os.unlink, path)
        proc = subprocess.run([_NODE, path], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def fn(self, src, name):
        """The definition of `name`, with its `async` prefix (srcpin anchors on `function name(` and leaves the prefix behind)."""
        text = srcpin.js_function(src, name)
        return "async " + text if f"async function {name}(" in src else text

    def revision_scenario(self):
        return ("queue.push({error: 'step-up re-authentication required', code: 'step_up_required'}, {ok: true, restored: 'rev-a'});\n"
                "(async () => { await restoreConfigRevision('rev-a'); console.log(JSON.stringify(out)); })();")

    def test_a_revision_restore_asks_for_the_password_and_sends_again(self):
        out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "restoreConfigRevision")], self.revision_scenario())
        self.assertEqual(out["modal"], 1)
        self.assertEqual(out["apiCalls"], ["POST /config/revisions/restore"] * 2)
        self.assertEqual(out["toasts"][-1][0], "Configuration restored")

    def test_declining_the_prompt_sends_nothing_more_and_says_so(self):
        out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "restoreConfigRevision")],
                          self.revision_scenario(), decision="false")
        self.assertEqual(out["modal"], 1)
        self.assertEqual(out["apiCalls"], ["POST /config/revisions/restore"])
        self.assertEqual(out["toasts"][-1], ["FAIL", "step_up_required"])

    def upload_scenario(self, name):
        return (f"queue.push({json.dumps(_STEP)}, {json.dumps(_DONE)});\n"
                f"(async () => {{ await {name}('backup-20260101-000000.tar.gz.enc'); out.text = result.textContent; "
                "console.log(JSON.stringify(out)); })();")

    def test_the_upload_restore_asks_and_uploads_the_file_again(self):
        out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "fetchWithStepUp"), self.fn(self.app, "restoreBackup")],
                          self.upload_scenario("restoreBackup"))
        self.assertEqual(out["modal"], 1)
        self.assertEqual(out["fetches"], ["/api/backup/restore POST"] * 2)
        self.assertIn("Restored 3 files", out["text"])

    def test_the_bucket_restore_asks_and_sends_again(self):
        out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "fetchWithStepUp"), self.fn(self.s3, "_s3RestoreRun")],
                          self.upload_scenario("_s3RestoreRun"))
        self.assertEqual(out["modal"], 1)
        self.assertEqual(out["fetches"], ["/api/backup/s3-restore POST"] * 2)
        self.assertIn("Restored 3 files", out["text"])

    def test_a_refused_restore_shows_the_servers_reason_or_the_status(self):
        """The error branch reads the status and the message from the helper's answer, not from a response that is no longer in scope."""
        for name, funcs, js in (
                ("restoreBackup", ("restoreBackup",), self.app),
                ("_s3RestoreRun", ("_s3RestoreRun",), self.s3)):
            for response, expected in (({"status": 400, "body": {"error": "not a valid .tar.gz"}}, "Restore failed: not a valid .tar.gz"),
                                       ({"status": 502, "body": {}}, "Restore failed: HTTP 502")):
                with self.subTest(handler=name, status=response["status"]):
                    scenario = (f"queue.push({json.dumps(response)});\n"
                                f"(async () => {{ await {name}('x.tar.gz.enc'); out.text = result.textContent; "
                                "console.log(JSON.stringify(out)); })();")
                    out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "fetchWithStepUp")]
                                      + [self.fn(js, f) for f in funcs], scenario)
                    self.assertEqual(out["text"], expected)
                    self.assertEqual(out["modal"], 0, "only a step_up_required answer opens the prompt")
                    self.assertEqual(out["toasts"][-1][1], "error")

    def test_a_restore_that_needs_no_prompt_is_sent_once(self):
        """Control: the helper does not prompt when the first answer is a success."""
        scenario = (f"queue.push({json.dumps(_DONE)});\n"
                    "(async () => { await restoreBackup(); out.text = result.textContent; console.log(JSON.stringify(out)); })();")
        out = self.run_js([self.fn(self.app, "withStepUp"), self.fn(self.app, "fetchWithStepUp"), self.fn(self.app, "restoreBackup")], scenario)
        self.assertEqual((out["modal"], len(out["fetches"])), (0, 1))


if __name__ == "__main__":
    unittest.main()
