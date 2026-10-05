"""The Docker image can run the SSH gateway, and runs it only when asked.

There is no Docker in the test environment, so this runs the entrypoint's
secret setup as real shell in a scratch directory and pins the rest of the image
by what its files must contain. The ordering matters most: the app server reads
RP_SSHGW_SECRET from its environment, so the secret has to be exported before
gunicorn starts.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_ENTRY = _ROOT / 'docker' / 'entrypoint.sh'
_START = 'SSHGW_ON=0\n'
_END = '# ── Persistent gunicorn'


def _block():
    src = _ENTRY.read_text()
    return src[src.index(_START):src.index(_END)]


@unittest.skipUnless(shutil.which('openssl') and shutil.which('bash'), 'openssl or bash missing')
class TestSecretSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **env):
        # SSHGW_ON is read in this shell; the secret is read from a CHILD shell,
        # which proves it was exported and not just set.
        script = ('set -euo pipefail\nDATA_DIR=%s\n' % self.dir + _block() +
                  '\necho "ON=$SSHGW_ON"\nbash -c \'echo "SECRET=${RP_SSHGW_SECRET:-}"\'\n')
        r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)
        got = dict(ln.split('=', 1) for ln in r.stdout.splitlines() if ln.startswith(('ON=', 'SECRET=')))
        return got['ON'], got['SECRET']

    def test_off_by_default_and_creates_nothing(self):
        on, secret = self._run(PATH='/usr/bin:/bin')
        self.assertEqual(('0', ''), (on, secret))
        self.assertFalse((self.dir / 'sshgw').exists())

    def test_on_creates_one_private_secret_and_exports_it(self):
        on, secret = self._run(PATH='/usr/bin:/bin', RP_WITH_SSHGW='1')
        self.assertEqual('1', on)
        self.assertRegex(secret, r'^[0-9a-f]{64}$')
        f = self.dir / 'sshgw' / 'secret'
        self.assertEqual(secret, f.read_text().strip())
        self.assertEqual(0o600, f.stat().st_mode & 0o777)
        self.assertEqual(0o700, f.parent.stat().st_mode & 0o777)

    def test_a_restart_keeps_the_same_secret(self):
        first = self._run(PATH='/usr/bin:/bin', RP_WITH_SSHGW='true')[1]
        second = self._run(PATH='/usr/bin:/bin', RP_WITH_SSHGW='true')[1]
        self.assertEqual(first, second)

    def test_a_supplied_secret_wins_and_is_what_the_daemon_reads(self):
        self._run(PATH='/usr/bin:/bin', RP_WITH_SSHGW='1')
        on, secret = self._run(PATH='/usr/bin:/bin', RP_WITH_SSHGW='1', RP_SSHGW_SECRET='my-own-secret')
        self.assertEqual('my-own-secret', secret)
        self.assertEqual('my-own-secret', (self.dir / 'sshgw' / 'secret').read_text().strip())


class TestImagePieces(unittest.TestCase):
    def setUp(self):
        self.entry = _ENTRY.read_text()

    def test_secret_is_exported_before_gunicorn_starts(self):
        self.assertLess(self.entry.index('export RP_SSHGW_SECRET'),
                        self.entry.index('gunicorn --workers'),
                        'the app server must start with RP_SSHGW_SECRET already in its environment')

    def test_the_daemon_only_starts_when_enabled_and_after_the_secret(self):
        m = re.search(r'if \[ "\$SSHGW_ON" = "1" \]; then\n(.*?)\nfi\n', self.entry, re.S)
        self.assertIsNotNone(m, 'daemon launch must sit inside `if [ "$SSHGW_ON" = "1" ]`')
        self.assertIn('/usr/local/bin/remotepower-sshgw', m.group(1))
        self.assertIn('SSHGW_SECRET_FILE="$SSHGW_DIR/secret"', m.group(1))
        self.assertIn('SSHGW_HOST_KEY="$SSHGW_DIR/ssh_host_ed25519_key"', m.group(1))
        self.assertLess(self.entry.index('export RP_SSHGW_SECRET'), self.entry.index('remotepower-sshgw --verbose'))

    def test_dockerfile_carries_the_daemon_and_its_dependency(self):
        df = (_ROOT / 'Dockerfile').read_text()
        self.assertRegex(df, r"asyncssh>=2\.14\.2")
        self.assertIn('COPY server/sshgw/remotepower-sshgw.py /usr/local/bin/remotepower-sshgw', df)
        self.assertRegex(df, r'/usr/local/bin/remotepower-sshgw \\\n')   # in the chmod list
        self.assertIn('EXPOSE 2222', df)

    def test_nginx_routes_the_tunnel_exactly_and_to_the_daemon_port(self):
        conf = (_ROOT / 'docker' / 'nginx-docker-locations.conf').read_text()
        m = re.search(r'location = /api/sshgw/tunnel \{(.*?)\n\}', conf, re.S)
        self.assertIsNotNone(m)
        self.assertIn('proxy_pass http://127.0.0.1:8767;', m.group(1))
        self.assertIn('Upgrade $http_upgrade', m.group(1))
        self.assertLess(conf.index('location = /api/sshgw/tunnel'), conf.index('location /api/ {'))

    def test_compose_leaves_the_gateway_and_its_port_off(self):
        compose = (_ROOT / 'docker-compose.yml').read_text()
        live = [ln for ln in compose.splitlines() if not ln.lstrip().startswith('#')]
        self.assertFalse([ln for ln in live if 'RP_WITH_SSHGW' in ln], 'must be commented out by default')
        self.assertFalse([ln for ln in live if ':2222' in ln], 'the public port must not be published by default')
        self.assertIn('# RP_WITH_SSHGW: "1"', compose)
        self.assertIn('${RP_SSHGW_PORT:-2222}:2222', compose)


if __name__ == '__main__':
    unittest.main()
