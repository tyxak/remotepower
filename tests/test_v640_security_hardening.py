"""v6.4.0 pre-prod hardening — two LOW items from the release security review.

1. handle_alert_unresolve returned 500 (not 404/409) on a denied reopen because
   its guard respond()s sat inside a try/except Exception that swallowed the
   HTTPError. Guards hoisted out of the try.
2. The Linux agent's guard-vault delete/restore branches now charset-clamp the
   server-supplied vault id before any path use (the rebaseline branch already
   did). Defense-in-depth against `/`/`..` in a vault id.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-harden-"))
_spec = importlib.util.spec_from_file_location("api_v640_harden", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestUnresolveStatusCodes(unittest.TestCase):
    """A denied reopen must return its real status, not a swallowed 500."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._af = api.ALERTS_FILE
        api.ALERTS_FILE = self.d / "alerts.json"
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("_check_alert_mutation_perm", "_alert_mutable_by_caller",
                       "audit_log", "respond", "method")}
        api._check_alert_mutation_perm = lambda: "u"
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"] = s
            self.cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.ALERTS_FILE = self._af
        api._LOAD_CACHE.clear()

    def _run(self, alerts):
        api.save(api.ALERTS_FILE, {"alerts": alerts})
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api.handle_alert_unresolve("a1")
        except api.HTTPError:
            pass
        return self.cap.get("s")

    def test_out_of_scope_reopen_is_404_not_500(self):
        api._alert_mutable_by_caller = lambda a: False
        s = self._run([{"id": "a1", "resolved_at": 123}])
        self.assertEqual(s, 404)

    def test_not_resolved_reopen_is_409_not_500(self):
        api._alert_mutable_by_caller = lambda a: True
        s = self._run([{"id": "a1"}])   # never resolved
        self.assertEqual(s, 409)

    def test_happy_path_reopens(self):
        api._alert_mutable_by_caller = lambda a: True
        s = self._run([{"id": "a1", "resolved_at": 123, "resolved_by": "u"}])
        self.assertEqual(s, 200)
        rows = (api.load(api.ALERTS_FILE) or {}).get("alerts")
        self.assertIsNone(rows[0]["resolved_at"])

    def test_source_guards_are_outside_the_try(self):
        # Structural: the denied status must not be inside the except-Exception
        # try (the AST error-path gate also covers this).
        src = (_CGI / "api.py").read_text()
        i = src.index("def handle_alert_unresolve")
        block = src[i:src.find("\ndef ", i + 10)]
        self.assertIn("denied", block)
        self.assertIn("respond(denied[0]", block)


class TestAgentGuardVaultIdSanitized(unittest.TestCase):
    def test_delete_restore_clamp_before_path_use(self):
        src = (ROOT / "client" / "remotepower-agent.py").read_text()
        i = src.index("def _apply_guard_actions")
        block = src[i:src.find("\ndef ", i + 10)]
        entry = block.index("e = _guard_vault_entry(qid)")
        pathb = block.index("src, meta = vault / qid")
        # the clamp must run before BOTH the vault lookup and the path build.
        clamp_before_entry = block.rfind(
            "re.sub(r'[^A-Za-z0-9_.\\-]', '', qid)[:64]", 0, entry)
        self.assertGreater(clamp_before_entry, 0,
                           "vault id not clamped before path use in "
                           "delete/restore branch")
        self.assertLess(clamp_before_entry, pathb)

    def test_extensionless_agent_in_sync(self):
        a = (ROOT / "client" / "remotepower-agent.py").read_bytes()
        b = (ROOT / "client" / "remotepower-agent").read_bytes()
        self.assertEqual(a, b, "run: cp remotepower-agent.py remotepower-agent")


if __name__ == "__main__":
    unittest.main()
