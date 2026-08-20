#!/usr/bin/env python3
"""Restart and Self-update reported success for an action nothing would perform.

`remotepower-wsgi.service` sets `NoNewPrivileges=true`, which blocks sudo's
setuid transition whatever a sudoers drop-in says. So the web process cannot run
the root-owned helpers itself. The route that works is a systemd path unit: the
web process creates an empty request file in its data directory, and systemd —
running as root — starts a oneshot service that performs the action.

Two halves were missing and they hid each other.

1. `_privileged_helper_mode` decided the spool route was available from
   `PRIV_SPOOL_DIR.is_dir() and os.access(..., W_OK)`. PRIV_SPOOL_DIR defaults
   to DATA_DIR, which the server owns and can always write — so the condition
   was true on every install, including every install where no unit existed.
   `handle_server_self_update` then answered 200 with "Update requested —
   systemd is running it as root. The service restarts when it finishes."

2. Nothing installed the units. The four files shipped in packaging/ since
   v6.4.2 with install instructions in their own headers, and no installer,
   image or package acted on them.

So the operator clicked Update, was told root was handling it, and a file
appeared in the data directory that no process ever read.

This is the same shape as the safety-guard class in CLAUDE.md, inverted: that
one tests a proxy and blocks a healthy host, this one tests a proxy and claims
a capability it does not have.
"""
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-priv-'))
_spec = importlib.util.spec_from_file_location('api_priv_escalation', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _text(rel):
    p = _ROOT / rel
    return p.read_text() if p.exists() else None


class TestSpoolRequiresAUnitNotJustAWritableDirectory(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='rp-spool-'))
        self._spool = api.PRIV_SPOOL_DIR
        self._nnp = api._no_new_privs
        self._helper = self.tmp / 'helper'
        self._helper.write_text('#!/bin/sh\n')
        api.PRIV_SPOOL_DIR = self.tmp          # exists and is writable
        api._no_new_privs = lambda: True       # sudo is blocked, as in production

    def tearDown(self):
        api.PRIV_SPOOL_DIR = self._spool
        api._no_new_privs = self._nnp

    def test_a_writable_spool_alone_is_blocked_not_spool(self):
        """The dev box has no RemotePower path units, which is exactly the
        state of a stock install. Before the fix this returned 'spool'."""
        if os.geteuid() == 0:
            self.skipTest('running as root takes the earlier branch')
        self.assertFalse(api._priv_path_unit_enabled('restart'),
                         'this box has the units installed; the negative case '
                         'below cannot be measured here')
        self.assertEqual('blocked',
                         api._privileged_helper_mode(str(self._helper)))

    def test_it_is_spool_once_the_unit_is_installed_and_enabled(self):
        """Positive control. Without it the assertion above passes for any
        reason at all, including a helper that returns 'blocked' always."""
        if os.geteuid() == 0:
            self.skipTest('running as root takes the earlier branch')
        units = self.tmp / 'systemd'
        (units / 'multi-user.target.wants').mkdir(parents=True)
        (units / 'remotepower-server-restart.path').write_text('[Path]\n')
        (units / 'multi-user.target.wants'
                 / 'remotepower-server-restart.path').write_text('')
        real = api._priv_path_unit_enabled

        def _fake(kind):
            unit = f'remotepower-server-{kind}.path'
            return ((units / unit).exists()
                    and (units / 'multi-user.target.wants' / unit).exists())

        api._priv_path_unit_enabled = _fake
        try:
            self.assertEqual('spool',
                             api._privileged_helper_mode(str(self._helper)))
            # ...and a unit that is installed but NOT enabled is still blocked:
            # systemd is not watching either way.
            (units / 'multi-user.target.wants'
                     / 'remotepower-server-restart.path').unlink()
            self.assertEqual('blocked',
                             api._privileged_helper_mode(str(self._helper)))
        finally:
            api._priv_path_unit_enabled = real

    def test_the_update_helper_is_checked_against_the_update_unit(self):
        """Restart and update are separate units. Checking the restart unit for
        an update request would report a route that is not there."""
        seen = []
        real = api._priv_path_unit_enabled
        api._priv_path_unit_enabled = lambda k: (seen.append(k), False)[1]
        try:
            api._privileged_helper_mode(str(self._helper), kind='update')
            self.assertEqual(['update'], seen)
            seen.clear()
            api._privileged_helper_mode(str(self._helper))
            self.assertEqual(['restart'], seen)
        finally:
            api._priv_path_unit_enabled = real

    def test_the_update_handler_asks_about_the_update_unit(self):
        src = _text('server/cgi-bin/api.py')
        self.assertIn("_privileged_helper_mode(cmd, kind='update')", src)


class TestTheUnitsAreActuallyInstalled(unittest.TestCase):
    """A correct check that reports 'blocked' everywhere is not a fix — it just
    tells the truth about a capability nobody installed."""

    _ACTS = ('restart', 'update')

    def test_the_files_exist_to_install(self):
        for act in self._ACTS:
            for suffix in ('.sh', '.path', '-run.service'):
                self.assertIsNotNone(
                    _text(f'packaging/remotepower-server-{act}{suffix}'),
                    f'packaging/remotepower-server-{act}{suffix} is missing')

    def test_install_server_installs_and_enables_both(self):
        sh = _text('install-server.sh')
        self.assertIn('/etc/systemd/system/remotepower-server-$_act.path', sh)
        self.assertIn('remotepower-server-$_act-run.service', sh)
        self.assertIn('systemctl enable --now "remotepower-server-$_act.path"', sh)

    def test_the_aur_package_ships_both_units(self):
        pkg = _text('packaging/aur/remotepower-server/PKGBUILD')
        self.assertIn('remotepower-server-$_act.path', pkg)
        self.assertIn('remotepower-server-$_act-run.service', pkg)
        inst = _text('packaging/aur/remotepower-server/remotepower-server.install')
        self.assertIn('remotepower-server-restart.path', inst)
        self.assertIn('remotepower-server-update.path', inst)

    def test_the_path_units_point_at_the_service_units_that_exist(self):
        """A `Unit=` naming a service that is not packaged makes the path unit
        install cleanly and do nothing when it fires."""
        for act in self._ACTS:
            unit = _text(f'packaging/remotepower-server-{act}.path')
            want = f'Unit=remotepower-server-{act}-run.service'
            self.assertIn(want, unit)
            self.assertIsNotNone(
                _text(f'packaging/remotepower-server-{act}-run.service'))

    def test_the_watched_path_matches_where_the_server_writes(self):
        """The path unit watches an absolute path; the server derives its own
        from PRIV_SPOOL_DIR. If they disagree the request is never seen."""
        for act in self._ACTS:
            unit = _text(f'packaging/remotepower-server-{act}.path')
            self.assertIn(f'PathExists=/var/lib/remotepower/.{act}.request', unit)
            run = _text(f'packaging/remotepower-server-{act}-run.service')
            self.assertIn(f'/var/lib/remotepower/.{act}.request', run,
                          'the oneshot must consume the same file the path '
                          'unit watches, or it retriggers forever')


if __name__ == '__main__':
    unittest.main()
