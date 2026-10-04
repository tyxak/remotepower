"""The ~/.ssh/config block the SSH gateway page hands out names the gateway as its own Host.

Under `Host *.rp` an IdentityFile applies to the server being reached, never to
the jump host, so with several keys ssh offered the wrong one to the gateway and
every login was "Permission denied (publickey)". The block now has a Host entry
for the gateway, which is where User and IdentityFile belong.
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_JS = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js' / 'app-sshgw.js'


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestConfigBlock(unittest.TestCase):
    def _text(self, st):
        fn = srcpin.js_function(_JS.read_text(), '_sshgwConfigText')
        out = subprocess.run(['node', '-e', fn + '\nconsole.log(JSON.stringify(_sshgwConfigText(%s)))' % json.dumps(st)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout)

    def test_gateway_is_its_own_host_entry_and_the_target_jumps_through_it(self):
        t = self._text({'public_host': 'gw.example.com', 'public_port': 2222, 'username': 'alice'})
        self.assertIn('Host rp-gateway\n    HostName gw.example.com\n    Port 2222\n    User alice\n', t)
        self.assertIn('Host *.rp\n    ProxyJump rp-gateway\n', t)
        gw, targets = t.split('Host *.rp')
        self.assertNotIn('IdentityFile', targets.replace('# IdentityFile', ''))
        self.assertIn('# IdentityFile', gw, 'the identity hint belongs under the gateway entry')

    def test_port_22_is_left_out_and_placeholders_survive_a_missing_status(self):
        self.assertNotIn('Port', self._text({'public_host': 'gw', 'public_port': 22, 'username': 'a'}))
        t = self._text(None)
        self.assertIn('HostName gateway.example.com', t)
        self.assertIn('User you', t)


if __name__ == '__main__':
    unittest.main()
