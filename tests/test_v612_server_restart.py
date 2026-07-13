"""v6.1.2 — in-app "Restart server" endpoint (scoped-sudo systemctl), plus the
pre-existing self-update 500 bug it surfaced.

The restart runs a fixed, root-owned script via passwordless sudo scoped to that
one path (the same model as the WG helper and self-update). The scoped sudoers rule
is the enable gate; no operator input reaches a shell.
"""
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CGI))


def _fresh_api(restart_script=None):
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v612-rst-')
    if restart_script is not None:
        os.environ['RP_RESTART_SCRIPT'] = restart_script
    else:
        os.environ.pop('RP_RESTART_SCRIPT', None)
    spec = importlib.util.spec_from_file_location('api_v612_rst', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _script(body):
    p = Path(tempfile.mktemp(suffix='-restart.sh'))
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


class _Base(unittest.TestCase):
    def _setup(self, api):
        self.api = api
        self.api.require_admin_auth = lambda *a, **k: 'admin'
        self.api.audit_log = lambda *a, **k: None
        self.api.method = lambda: 'POST'
        self.cap = {}

        def _r(s, d=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _r

    def _call(self, fn):
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        return self.cap.get('s'), self.cap.get('d')


class TestServerRestart(_Base):
    def test_not_set_up_returns_a_clear_400(self):
        self._setup(_fresh_api(restart_script='/nonexistent/remotepower-server-restart'))
        s, d = self._call(self.api.handle_server_restart)
        self.assertEqual(s, 400)
        self.assertFalse(d.get('configured'))
        self.assertIn('scoped restart script', d.get('error', ''))

    def test_a_scheduled_restart_returns_200(self):
        api = _fresh_api(restart_script=_script('#!/bin/sh\necho scheduled\nexit 0\n'))
        self._setup(api)
        s, d = self._call(api.handle_server_restart)
        self.assertEqual(s, 200, 'a successful respond() must NOT be caught and '
                                 'rewritten to a 500 (the try/except-Exception trap)')
        self.assertTrue(d.get('ok'))
        self.assertIn('Restart scheduled', d.get('message', ''))

    def test_a_failing_script_returns_400_not_500(self):
        """A non-zero script (e.g. the sudoers drop-in is missing) is a
        configuration error, surfaced as a 400 with guidance — not a 500."""
        api = _fresh_api(restart_script=_script('#!/bin/sh\necho "sudo: a password is required">&2\nexit 1\n'))
        self._setup(api)
        s, d = self._call(api.handle_server_restart)
        self.assertEqual(s, 400)
        self.assertFalse(d.get('ok'))

    def test_get_is_405(self):
        api = _fresh_api(restart_script=_script('#!/bin/sh\nexit 0\n'))
        self._setup(api)
        api.method = lambda: 'GET'
        s, _d = self._call(api.handle_server_restart)
        self.assertEqual(s, 405)

    def test_the_command_is_fixed_no_operator_input_reaches_a_shell(self):
        """The whole point of the scoped-script model: the endpoint runs ONE fixed
        path with no arguments and no shell. Body content must not influence it."""
        api = _fresh_api(restart_script=_script('#!/bin/sh\necho ok\nexit 0\n'))
        self._setup(api)
        # a body trying to inject is ignored entirely (get_json_obj is never read)
        api.get_json_obj = lambda: {'cmd': 'rm -rf /', 'service': '; reboot'}
        s, d = self._call(api.handle_server_restart)
        self.assertEqual(s, 200)
        src = (CGI / 'api.py').read_text()
        i = src.index('def handle_server_restart')
        body = src[i:i + 2500]
        self.assertIn('subprocess.run([RESTART_SCRIPT]', body,
                      'must run the fixed script path as a single argv element')
        self.assertNotIn('shell=True', body)

    def test_version_check_reports_restart_availability(self):
        api = _fresh_api(restart_script='/nonexistent/x')
        self._setup(api)
        api.require_auth = lambda *a, **k: 'admin'
        s, d = self._call(api.handle_version_check)
        self.assertIn('restart_available', d)
        self.assertFalse(d['restart_available'])   # script absent


class TestSelfUpdateRespondBugFixed(_Base):
    """The restart work surfaced that handle_server_self_update's success
    respond(200) sat INSIDE a `try/except Exception`, so the HTTPError it raises
    (respond() raises to unwind) was caught and rewritten to a 500 — the handler
    had shipped broken since v5.0.0."""

    def test_a_successful_self_update_returns_200_not_500(self):
        api = _fresh_api()
        self._setup(api)
        cmd = _script('#!/bin/sh\necho done\nexit 0\n')
        api.save(api.CONFIG_FILE, {'self_update_command': cmd})
        api._LOAD_CACHE.clear()
        s, d = self._call(api.handle_server_self_update)
        self.assertEqual(s, 200, 'the success respond() must reach the client, not '
                                 'get swallowed by except Exception')
        self.assertTrue(d.get('ok'))


class TestRestartScriptAndPackaging(unittest.TestCase):
    def test_the_scoped_script_ships_and_is_shell_valid(self):
        p = ROOT / 'packaging' / 'remotepower-server-restart.sh'
        self.assertTrue(p.exists())
        import subprocess
        r = subprocess.run(['bash', '-n', str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, str(r.stderr))

    def test_the_script_uses_sudo_n_and_detaches(self):
        txt = (ROOT / 'packaging' / 'remotepower-server-restart.sh').read_text()
        self.assertIn('sudo -n', txt, 'must never prompt — fail fast if unprivileged')
        self.assertIn('setsid', txt, 'the restart must outlive its own worker')

    def test_the_installers_grant_scoped_sudo(self):
        deploy = (ROOT / 'deploy-server.sh').read_text()
        self.assertIn('remotepower-server-restart', deploy)
        self.assertIn('/etc/sudoers.d/remotepower-self-restart', deploy)
        pkgbuild = (ROOT / 'packaging' / 'aur' / 'remotepower-server' / 'PKGBUILD').read_text()
        self.assertIn('remotepower-server-restart', pkgbuild)

    def test_the_route_is_registered(self):
        src = (CGI / 'api.py').read_text()
        self.assertIn("('POST', '/api/server/restart'): handle_server_restart", src)


if __name__ == '__main__':
    unittest.main()
