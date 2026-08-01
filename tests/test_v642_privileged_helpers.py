"""v6.4.2: the privileged helpers must not offer an action they cannot perform.

`server/conf/remotepower-wsgi.service` ships `NoNewPrivileges=true`. Both
`packaging/remotepower-server-restart.sh` and `-update.sh` escalate with
`exec sudo -n "$0"`, which NoNewPrivileges blocks regardless of any sudoers
drop-in — the product documents this itself in `vpn_handlers._wg_direct`, which
is precisely why the WireGuard helper runs sudo-free on ambient capabilities.

So on a stock install the "Restart server" and "Run update now" buttons were
offered (`restart_available` was a bare file-exists check) and always failed,
with an error telling the operator to go check a sudoers rule that cannot help.

This pins: the preflight, the systemd path-unit route that works *under* the
hardening, and the fact that a queued request never rides into a DR archive.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_PKG = _ROOT / "packaging"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-priv-"))

_spec = importlib.util.spec_from_file_location("api_v642_priv", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestPreflight(unittest.TestCase):
    def setUp(self):
        self._nnp = api._no_new_privs
        self._geteuid = os.geteuid
        self.script = Path(tempfile.mkdtemp(prefix="rp-priv-bin-")) / "helper"

    def tearDown(self):
        api._no_new_privs = self._nnp
        os.geteuid = self._geteuid

    def _mode(self, *, nnp, script_exists, euid=1000, spool=None):
        api._no_new_privs = lambda: nnp
        os.geteuid = lambda: euid
        if script_exists:
            self.script.write_text("#!/bin/sh\n")
        elif self.script.exists():
            self.script.unlink()
        orig = api.PRIV_SPOOL_DIR
        if spool is not None:
            api.PRIV_SPOOL_DIR = spool
        try:
            return api._privileged_helper_mode(str(self.script))
        finally:
            api.PRIV_SPOOL_DIR = orig

    def test_missing_helper_is_absent(self):
        self.assertEqual(
            self._mode(nnp=False, script_exists=False,
                       spool=Path("/nonexistent-rp-spool")), "absent")

    def test_missing_helper_is_absent_even_with_a_writable_spool(self):
        """The path unit's ExecStart points at the same script, so a writable
        spool proves nothing when the helper itself is not installed."""
        self.assertEqual(
            self._mode(nnp=True, script_exists=False, spool=api.DATA_DIR), "absent")

    def test_sudo_when_no_new_privs_is_off(self):
        self.assertEqual(self._mode(nnp=False, script_exists=True), "sudo")

    def test_root_short_circuits(self):
        self.assertEqual(self._mode(nnp=True, script_exists=True, euid=0), "root")

    def test_no_new_privs_without_a_spool_is_blocked(self):
        """The exact stock-install case that used to report 'available'."""
        self.assertEqual(
            self._mode(nnp=True, script_exists=True,
                       spool=Path("/nonexistent-rp-spool")), "blocked")

    def test_no_new_privs_with_a_writable_spool_uses_systemd(self):
        self.assertEqual(
            self._mode(nnp=True, script_exists=True, spool=api.DATA_DIR), "spool")

    def test_blocked_help_names_the_real_cause_not_sudoers(self):
        help_text = api._PRIV_BLOCKED_HELP
        self.assertIn("NoNewPrivileges", help_text)
        self.assertIn("sudoers drop-in will not change that", help_text)


class TestRequestFile(unittest.TestCase):
    def tearDown(self):
        for k in ("restart", "update"):
            p = api.PRIV_SPOOL_DIR / f".{k}.request"
            if p.exists():
                p.unlink()

    def test_request_is_empty_and_owner_only(self):
        """The web process can express WHICH action, never a command."""
        p = api._request_privileged_action("restart")
        self.assertTrue(p.exists())
        self.assertEqual(p.read_bytes(), b"")
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_unknown_action_is_refused(self):
        with self.assertRaises(ValueError):
            api._request_privileged_action("rm -rf /")

    def test_request_files_never_enter_a_backup(self):
        """Restoring an archive must not queue a restart on the target host."""
        self.assertFalse(api._backup_include(".restart.request"))
        self.assertFalse(api._backup_include(".update.request"))


class TestShippedUnits(unittest.TestCase):
    """The path units exist, watch the file api.py writes, and consume it."""

    def _read(self, name):
        p = _PKG / name
        if not p.exists():
            self.skipTest(f"{name} excluded from this tree")
        return p.read_text()

    def test_path_units_watch_the_filenames_api_writes(self):
        for kind in ("restart", "update"):
            unit = self._read(f"remotepower-server-{kind}.path")
            self.assertIn(f".{kind}.request", unit,
                          f"the {kind} path unit watches a file api.py never writes")

    def test_run_units_consume_the_request_before_acting(self):
        """ExecStartPre removes it, so a failing action cannot loop forever."""
        for kind in ("restart", "update"):
            unit = self._read(f"remotepower-server-{kind}-run.service")
            pre = [l for l in unit.splitlines() if l.startswith("ExecStartPre=")]
            self.assertTrue(pre, f"{kind} run unit does not consume the request")
            self.assertIn(f".{kind}.request", pre[0])
            self.assertIn("ExecStart=/usr/local/sbin/remotepower-server-", unit)

    def test_units_do_not_declare_the_shared_runtime_directory(self):
        """remotepower-wsgi.service documents why RuntimeDirectory=remotepower
        must not be declared — systemd would delete /run/remotepower on every
        restart. The request file lives in DATA_DIR precisely to avoid it."""
        for name in ("remotepower-server-restart.path",
                     "remotepower-server-restart-run.service",
                     "remotepower-server-update.path",
                     "remotepower-server-update-run.service"):
            self.assertNotIn("RuntimeDirectory", self._read(name))


class TestHelperScriptsStillNeedTheFallback(unittest.TestCase):
    """Both helpers keep their sudo path for hosts that are not NNP-hardened."""

    def test_scripts_take_the_root_branch_first(self):
        for name in ("remotepower-server-restart.sh", "remotepower-server-update.sh"):
            p = _PKG / name
            if not p.exists():
                self.skipTest(f"{name} excluded from this tree")
            src = p.read_text()
            self.assertIn("sudo -n", src)
            self.assertIn("id -u", src,
                          f"{name} must short-circuit when already root — that is "
                          "the branch the systemd path unit relies on")


if __name__ == "__main__":
    unittest.main()
