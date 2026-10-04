"""The Server status page has a row for the SSH gateway daemon.

Every other co-located sidecar (push, satellites, syslog, flow, KMIP) had one;
the gateway shipped without, so a running daemon and a dead one looked the same
on the page an operator opens to ask "is it up?".
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sshgw-status-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402

_JS = _TESTS.parent / 'server' / 'html' / 'static' / 'js' / 'app-self.js'


def _setup(api, enabled, devices=None, state=None):
    api.save(api.CONFIG_FILE, {'sshgw_enabled': enabled})
    api.save(api.DEVICES_FILE, devices or {})
    if state is not None:
        api.save(api.SSHGW_STATE_FILE, state)


class TestServerSide(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._env = os.environ.get('RP_SSHGW_WS_PORT')
        os.environ['RP_SSHGW_WS_PORT'] = str(self.port)

    def tearDown(self):
        self.sock.close()
        if self._env is None:
            os.environ.pop('RP_SSHGW_WS_PORT', None)
        else:
            os.environ['RP_SSHGW_WS_PORT'] = self._env

    def test_module_off_reports_off_and_probes_nothing(self):
        _setup(self.api, False)
        self.assertEqual({'enabled': False}, self.api._subsystems_status(int(time.time()))['sshgw'])

    def test_a_listening_daemon_is_running_and_tunnels_are_counted(self):
        now = int(time.time())
        devs = {'a': {'sshgw_enabled': True}, 'b': {'sshgw_enabled': True},
                'c': {'sshgw_enabled': True}, 'd': {}}
        _setup(self.api, True, devs, {'a': {'tunnel_seen': now - 30},
                                      'b': {'tunnel_seen': now - 5000}})
        g = self.api._subsystems_status(now)['sshgw']
        self.assertTrue(g['enabled'])
        self.assertTrue(g['reachable'])
        self.assertEqual(self.port, g['port'])
        self.assertEqual((3, 1), (g['opted_in'], g['tunnels']))

    def test_nothing_listening_is_unreachable(self):
        _setup(self.api, True)
        self.sock.close()
        g = self.api._subsystems_status(int(time.time()))['sshgw']
        self.assertTrue(g['enabled'])
        self.assertFalse(g['reachable'])


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestRow(unittest.TestCase):
    # Helpers the real function calls and this test does not exercise.
    _STUBS = ('function _selfApplyMutes(s, r){return r;} function _selfFmtAgo(t){return "x";} '
              'function _selfNameSources(){return "";} function _selfNameExporters(){return "";}\n')

    def _rows(self, sshgw):
        fn = srcpin.js_function(_JS.read_text(), '_selfSidecarRows')
        script = self._STUBS + fn + '\nconsole.log(JSON.stringify(_selfSidecarRows({subsystems: %s})));' % json.dumps({'sshgw': sshgw})
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        rows = [r for r in json.loads(out.stdout) if r['key'] == 'sshgw-daemon']
        self.assertEqual(1, len(rows), 'exactly one SSH gateway row')
        return rows[0]

    def test_off_is_muted_running_is_ok_and_unreachable_is_bad(self):
        self.assertEqual(('muted', 'Off'), tuple(self._rows({'enabled': False})[k] for k in ('state', 'status')))
        up = self._rows({'enabled': True, 'reachable': True, 'port': 8767, 'ssh_port': 2222,
                         'opted_in': 5, 'tunnels': 3})
        self.assertEqual(('ok', 'Running'), (up['state'], up['status']))
        self.assertIn('3 of 5', up['detail'])
        down = self._rows({'enabled': True, 'reachable': False, 'port': 8767})
        self.assertEqual('bad', down['state'])
        self.assertIn('remotepower-sshgw', down['detail'])

    def test_a_server_that_predates_the_field_shows_off_not_an_error(self):
        fn = srcpin.js_function(_JS.read_text(), '_selfSidecarRows')
        out = subprocess.run(['node', '-e', self._STUBS + fn + '\nconsole.log(_selfSidecarRows({}).length>0)'],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual('true', out.stdout.strip(), out.stderr)


if __name__ == '__main__':
    unittest.main()
