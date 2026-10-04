"""packaging/install-sshgw.sh adds the SSH gateway to a server installed another way.

The server package ships the application, not the gateway daemon, so a package
install had no route to the gateway short of copying files by hand. The script
runs here against a DESTDIR with a fake server tree: it installs the daemon and
the unit, shares one secret between the daemon and the API, and can be run again.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / 'packaging' / 'install-sshgw.sh'


def _run(dest, *args, web='/var/www/remotepower'):
    return subprocess.run(
        ['bash', str(_SCRIPT), '--web', web, *args],
        env={**os.environ, 'DESTDIR': str(dest)}, capture_output=True, text=True, timeout=60)


def _server(dest, web='/var/www/remotepower', with_gateway=True, wsgi_reads_env=True):
    cgi = Path(str(dest) + web) / 'cgi-bin'
    cgi.mkdir(parents=True)
    (cgi / 'api.py').write_text('# api\n')
    if with_gateway:
        (cgi / 'sshgw_handlers.py').write_text('# handlers\n')
    unit = Path(str(dest) + '/etc/systemd/system/remotepower-wsgi.service')
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text('[Service]\n' + ('EnvironmentFile=-/etc/remotepower/api.env\n' if wsgi_reads_env else '') + 'ExecStart=/bin/true\n')


class TestInstallSshgw(unittest.TestCase):
    def setUp(self):
        if not _SCRIPT.is_file():
            self.skipTest('packaging/ excluded from this tree')
        if not (_ROOT / 'server' / 'sshgw' / 'remotepower-sshgw.py').is_file():
            self.skipTest('gateway sources not in this tree')
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _p(self, rel):
        return Path(str(self.dest) + rel)

    def test_script_is_valid_bash_and_executable(self):
        self.assertEqual(0, subprocess.run(['bash', '-n', str(_SCRIPT)]).returncode)
        self.assertTrue(_SCRIPT.stat().st_mode & stat.S_IXUSR)

    def test_fresh_install_places_daemon_unit_and_one_shared_secret(self):
        _server(self.dest)
        r = _run(self.dest)
        self.assertEqual(0, r.returncode, r.stderr + r.stdout)
        daemon = self._p('/usr/local/bin/remotepower-sshgw')
        self.assertTrue(daemon.is_file())
        self.assertTrue(daemon.stat().st_mode & stat.S_IXUSR)
        unit = self._p('/etc/systemd/system/remotepower-sshgw.service').read_text()
        self.assertIn('ExecStart=/usr/local/bin/remotepower-sshgw', unit)
        self.assertIn('Environment=RP_CGI_BIN=/var/www/remotepower/cgi-bin', unit)
        secret_file = self._p('/etc/remotepower/sshgw-secret')
        secret = secret_file.read_text().strip()
        self.assertRegex(secret, r'^[0-9a-f]{64}$')
        self.assertEqual(0o600, secret_file.stat().st_mode & 0o777)
        api_env = self._p('/etc/remotepower/api.env')
        self.assertEqual(0o600, api_env.stat().st_mode & 0o777)
        self.assertEqual([f'RP_SSHGW_SECRET={secret}'],
                         [ln for ln in api_env.read_text().splitlines() if ln.startswith('RP_SSHGW_SECRET=')])
        self.assertFalse(self._p('/etc/systemd/system/remotepower-wsgi.service.d/sshgw.conf').exists(),
                         'the unit already reads api.env, so no drop-in is needed')
        self.assertIn('TCP 2222', r.stdout)

    def test_running_it_again_keeps_the_secret_and_the_other_api_env_lines(self):
        _server(self.dest)
        env = self._p('/etc/remotepower/api.env')
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text('RP_OTHER=keep-me\n')
        self.assertEqual(0, _run(self.dest).returncode)
        first = self._p('/etc/remotepower/sshgw-secret').read_text()
        r = _run(self.dest)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual(first, self._p('/etc/remotepower/sshgw-secret').read_text())
        lines = env.read_text().splitlines()
        self.assertEqual(1, sum(ln.startswith('RP_SSHGW_SECRET=') for ln in lines), lines)
        self.assertIn('RP_OTHER=keep-me', lines)

    def test_a_stale_secret_in_api_env_is_replaced_by_the_daemons(self):
        _server(self.dest)
        self.assertEqual(0, _run(self.dest).returncode)
        env = self._p('/etc/remotepower/api.env')
        env.write_text('RP_SSHGW_SECRET=stale\nRP_OTHER=1\n')
        self.assertEqual(0, _run(self.dest).returncode)
        secret = self._p('/etc/remotepower/sshgw-secret').read_text().strip()
        lines = env.read_text().splitlines()
        self.assertIn(f'RP_SSHGW_SECRET={secret}', lines)
        self.assertNotIn('RP_SSHGW_SECRET=stale', lines)
        self.assertIn('RP_OTHER=1', lines)

    def test_a_wsgi_unit_that_ignores_api_env_gets_a_drop_in(self):
        _server(self.dest, wsgi_reads_env=False)
        self.assertEqual(0, _run(self.dest).returncode)
        drop = self._p('/etc/systemd/system/remotepower-wsgi.service.d/sshgw.conf')
        self.assertIn('EnvironmentFile=-/etc/remotepower/api.env', drop.read_text())

    def test_port_and_public_host_are_written_and_a_bad_value_is_refused(self):
        _server(self.dest)
        r = _run(self.dest, '--port', '22', '--public-host', 'gw.example.com')
        self.assertEqual(0, r.returncode, r.stderr)
        env = self._p('/etc/remotepower/sshgw.env').read_text().splitlines()
        self.assertIn('SSHGW_SSH_PORT=22', env)
        self.assertIn('SSHGW_PUBLIC_HOST=gw.example.com', env)
        self.assertIn('TCP 22 ', r.stdout)
        for bad in (('--port', '99999'), ('--port', 'x'), ('--public-host', 'a b;rm -rf')):
            self.assertNotEqual(0, _run(self.dest, *bad).returncode, bad)

    def test_a_non_default_web_root_is_followed(self):
        _server(self.dest, web='/srv/rp')
        self.assertEqual(0, _run(self.dest, web='/srv/rp').returncode)
        unit = self._p('/etc/systemd/system/remotepower-sshgw.service').read_text()
        self.assertIn('Environment=RP_CGI_BIN=/srv/rp/cgi-bin', unit)

    def test_it_refuses_a_server_without_gateway_support_and_installs_nothing(self):
        _server(self.dest, with_gateway=False)
        r = _run(self.dest)
        self.assertNotEqual(0, r.returncode)
        self.assertIn('7.1.0', r.stderr)
        self.assertFalse(self._p('/usr/local/bin/remotepower-sshgw').exists())
        self.assertFalse(self._p('/etc/remotepower/sshgw-secret').exists())

    def test_it_refuses_when_there_is_no_server_at_all(self):
        r = _run(self.dest)
        self.assertNotEqual(0, r.returncode)
        self.assertFalse(self._p('/usr/local/bin/remotepower-sshgw').exists())


if __name__ == '__main__':
    unittest.main()
