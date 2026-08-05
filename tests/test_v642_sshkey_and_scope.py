"""v6.4.2: three defects in the host-user / software-policy path.

All three were found by auditing "read-only view" findings and turned out to be
bugs in the code behind the views, not the missing buttons:

1. `GET /api/software-policy/violations` had NO scope or tenant filter — a
   group/site-scoped operator, and under multi-tenancy a tenant admin (who
   resolves to `_caller_scope() == None`), read every other slice's device names
   and the packages found on them. Its sibling fleet reader always filtered.
2. Revoking a user's ONLY SSH key silently did nothing and reported success.
3. The public-key validator rejected two entirely normal authorized_keys lines.

Run: python3 -m pytest tests/test_v642_sshkey_and_scope.py -q
"""
import os
import sys
import shutil
import tempfile
import subprocess
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_sshscope", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestSoftwarePolicyViolationsAreScoped(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n) for n in ("require_auth", "_caller_scope")}
        api.require_auth = lambda *a, **k: "op"
        api.save(api.DEVICES_FILE, {
            "mine": {"name": "my-host", "token": "t", "group": "alpha", "monitored": True},
            "theirs": {"name": "THEIR-HOST", "token": "t", "group": "beta", "monitored": True}})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {
            "mine": {"name": "my-host", "violations": [{"type": "banned", "package": "telnet"}]},
            "theirs": {"name": "THEIR-HOST",
                       "violations": [{"type": "banned", "package": "secret-pkg"}]}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _rows(self):
        api._LOAD_CACHE.clear()
        api._RCTX.environ = {"REQUEST_METHOD": "GET", "QUERY_STRING": "",
                             "PATH_INFO": "/api/software-policy/violations"}
        try:
            api.handle_software_policy_violations()
        except (SystemExit, api.HTTPError) as e:
            body = getattr(e, "body", None) or {}
            return [r["device"] for r in (body.get("violations") or [])]
        return []

    def test_a_scoped_operator_sees_only_their_own(self):
        api._caller_scope = lambda: {"type": "groups", "values": ["alpha"]}
        rows = self._rows()
        self.assertEqual(rows, ["my-host"])
        self.assertNotIn("THEIR-HOST", rows)

    def test_an_unscoped_admin_is_unaffected(self):
        """The fix must be a no-op on the common single-org install."""
        api._caller_scope = lambda: None
        self.assertEqual(sorted(self._rows()), ["THEIR-HOST", "my-host"])

    def test_it_uses_the_same_helper_as_its_sibling(self):
        """_scope_filter_devices folds in BOTH role scope and the tenant gate;
        a hand-rolled scope check would miss the tenant half."""
        import inspect
        self.assertIn("_scope_filter_devices",
                      inspect.getsource(api.handle_software_policy_violations))


class TestSshPublicKeyValidator(unittest.TestCase):
    ACCEPT = [
        ("plain", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc"),
        ("single-word comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc jakob@laptop"),
        # ssh-keygen -C accepts these; the validator used to 400 them.
        ("multi-word comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc jakob work laptop"),
        ("from= options prefix",
         'from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc admin'),
        ("no-pty options", "no-pty,no-agent-forwarding ssh-rsa AAAAB3NzaC1yc2E bkp"),
    ]
    REJECT = [
        # The key is interpolated into a single-quoted shell word — a quote is
        # the one character that must never get through.
        ("single quote", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc x'; rm -rf / #"),
        ("backslash", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc a\\b"),
        ("newline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc a\nb"),
        ("not a key at all", "hello world"),
        ("unknown algorithm", "ssh-magic AAAAC3NzaC1lZDI1NTE5AAAAIabc"),
    ]

    def test_real_authorized_keys_lines_are_accepted(self):
        for label, key in self.ACCEPT:
            with self.subTest(label):
                self.assertTrue(api._SSH_PUBKEY_RE.match(key), key)

    def test_shell_metacharacters_are_still_refused(self):
        for label, key in self.REJECT:
            with self.subTest(label):
                self.assertFalse(api._SSH_PUBKEY_RE.match(key), key)


@unittest.skipUnless(shutil.which("sh"), "no POSIX shell")
class TestRevokeRemovesTheOnlyKey(unittest.TestCase):
    """The command runs on the AGENT, so the only honest test is to run it.

    `grep -v` exits 1 when it selects no lines — exactly the case where the key
    being revoked is the user's only one. The old `&& mv` was therefore skipped,
    the file was left untouched, and the trailing `chmod` made the overall status
    0, so the operator got a success toast for a revoke that did nothing.
    """
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIonly onlykey"

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.ak = self.d / "authorized_keys"

    def _cmd(self):
        """The exact shell the handler builds, with the same interpolation."""
        ak = str(self.ak)
        return (f"test -f {ak} && {{ grep -vxF '{self.KEY}' {ak} > {ak}.rp_tmp; "
                f"rc=$?; if [ $rc -le 1 ]; then mv {ak}.rp_tmp {ak}; "
                f"else rm -f {ak}.rp_tmp; exit $rc; fi; }}; chmod 600 {ak}")

    def _run(self):
        return subprocess.run(["sh", "-c", self._cmd()], capture_output=True, text=True).returncode

    def test_the_only_key_is_actually_removed(self):
        self.ak.write_text(self.KEY + "\n")
        rc = self._run()
        self.assertEqual(rc, 0)
        self.assertNotIn(self.KEY, self.ak.read_text())
        self.assertEqual(self.ak.read_text().strip(), "")

    def test_other_keys_survive(self):
        self.ak.write_text(self.KEY + "\nssh-rsa AAAAB3keep keeper\n")
        self.assertEqual(self._run(), 0)
        body = self.ak.read_text()
        self.assertNotIn(self.KEY, body)
        self.assertIn("keeper", body)

    def test_no_temp_file_is_left_behind(self):
        self.ak.write_text(self.KEY + "\n")
        self._run()
        self.assertFalse((self.d / "authorized_keys.rp_tmp").exists())

    def test_the_handler_builds_this_exact_shape(self):
        """Pins the fix against a future 'simplification' back to `&& mv`."""
        import inspect
        src = inspect.getsource(api.handle_device_user_action)
        self.assertIn("rc=$?", src)
        self.assertIn("[ $rc -le 1 ]", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
