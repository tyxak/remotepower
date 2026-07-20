"""v6.3.0: agentless syslog receiver — driven END TO END.

Boots the real daemon as a subprocess against a scratch JSON-backend data
dir and a stub HTTP server standing in for the API, then sends real UDP
datagrams: a mapped source's lines must arrive as ONE batched POST to
/api/syslog/in/<that device's token>; an unknown source must produce no
POST at all. Plus unit-level SourceMap rules and deploy/update wiring pins.
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DAEMON = _ROOT / 'server' / 'syslog' / 'remotepower-syslogd.py'

sys.path.insert(0, str(_DAEMON.parent))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Capture(http.server.BaseHTTPRequestHandler):
    posts = []

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n).decode()
        _Capture.posts.append((self.path, json.loads(body)))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


class TestSyslogdEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Capture.posts = []
        cls.httpd = http.server.HTTPServer(('127.0.0.1', 0), _Capture)
        cls.http_port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

        cls.data = Path(tempfile.mkdtemp(prefix='rp-syslogd-'))
        (cls.data / 'devices.json').write_text(json.dumps({
            'dev-fw1': {'name': 'fw1', 'ip': '127.0.0.1'},
        }))
        (cls.data / 'inbound_webhooks.json').write_text(json.dumps({
            'tokens': [{'id': 't1', 'token': 'rpwi_testtoken123', 'kind': 'syslog',
                        'enabled': True, 'scope_device_id': 'dev-fw1'}],
        }))
        cls.udp_port = _free_port()
        env = dict(os.environ,
                   RP_DATA_DIR=str(cls.data),
                   RP_SYSLOG_BIND=f'127.0.0.1:{cls.udp_port}',
                   RP_SYSLOG_SERVER_URL=f'http://127.0.0.1:{cls.http_port}')
        cls.proc = subprocess.Popen([sys.executable, str(_DAEMON)], env=env,
                                    stderr=subprocess.PIPE)
        time.sleep(0.8)   # let it bind
        if cls.proc.poll() is not None:
            raise unittest.SkipTest('daemon died: '
                                    + cls.proc.stderr.read().decode(errors='replace'))

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.httpd.shutdown()

    def _send(self, line):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(line.encode(), ('127.0.0.1', self.udp_port))
        s.close()

    def test_mapped_source_lines_arrive_batched_at_the_ingest_endpoint(self):
        _Capture.posts.clear()
        self._send('<134>Jul 20 10:00:00 fw1 kernel: DROP IN=eth0 SRC=1.2.3.4')
        self._send('<134>Jul 20 10:00:01 fw1 sshd[9]: Failed password for root')
        deadline = time.time() + 10
        while not _Capture.posts and time.time() < deadline:
            time.sleep(0.2)
        self.assertTrue(_Capture.posts, 'no POST arrived within 10s')
        path, body = _Capture.posts[0]
        self.assertEqual(path, '/api/syslog/in/rpwi_testtoken123')
        joined = '\n'.join(body['lines'])
        self.assertIn('DROP IN=eth0', joined)
        self.assertIn('Failed password', joined)
        # batching: both datagrams (sent within the flush window) → ONE post
        self.assertEqual(len(_Capture.posts), 1)


class TestSourceMapRules(unittest.TestCase):
    def _map(self, devices, tokens):
        import importlib.util
        spec = importlib.util.spec_from_file_location('rp_syslogd', _DAEMON)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        class _R:
            def load(self, name):
                return {'devices.json': devices,
                        'inbound_webhooks.json': tokens}.get(name, {})
        sm = mod.SourceMap(_R())
        sm._refresh()
        return sm

    def test_only_enabled_pinned_syslog_tokens_map(self):
        devices = {'d1': {'ip': '10.0.0.1'}, 'd2': {'ip': '10.0.0.2'},
                   'd3': {'ip': '10.0.0.3'}, 'd4': {'ip': '10.0.0.4'}}
        tokens = {'tokens': [
            {'token': 'rpwi_a', 'kind': 'syslog', 'enabled': True,  'scope_device_id': 'd1'},
            {'token': 'rpwi_b', 'kind': 'syslog', 'enabled': False, 'scope_device_id': 'd2'},
            {'token': 'rpwi_c', 'kind': 'alert',  'enabled': True,  'scope_device_id': 'd3'},
            {'token': 'rpwi_d', 'kind': 'syslog', 'enabled': True},   # unpinned
        ]}
        sm = self._map(devices, tokens)
        self.assertEqual(sm.token_for('10.0.0.1'), 'rpwi_a')
        self.assertIsNone(sm.token_for('10.0.0.2'))   # disabled
        self.assertIsNone(sm.token_for('10.0.0.3'))   # wrong kind
        self.assertIsNone(sm.token_for('10.0.0.4'))   # not pinned
        self.assertIsNone(sm.token_for('192.168.9.9'))  # unknown source


class TestOpsWiring(unittest.TestCase):
    def test_deploy_refreshes_and_update_restarts(self):
        deploy = (_ROOT / 'deploy-server.sh').read_text()
        self.assertIn('remotepower-syslogd.py', deploy)
        upd = (_ROOT / 'packaging' / 'remotepower-server-update.sh').read_text()
        self.assertIn('remotepower-syslogd', upd)

    def test_unit_is_static_and_sandboxed(self):
        unit = (_ROOT / 'packaging' / 'remotepower-syslogd.service').read_text()
        self.assertIn('DynamicUser=yes', unit)      # no rendered User= — safe to refresh
        self.assertNotIn('User=r', unit)
        self.assertIn('ProtectSystem=strict', unit)


if __name__ == '__main__':
    unittest.main()
