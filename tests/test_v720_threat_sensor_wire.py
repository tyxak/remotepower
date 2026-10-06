#!/usr/bin/env python3
"""The threat sensor over real HTTP: can the feature fire at all?

The other v7.2.0 tests stub the collector and the submit, or call the handlers
in process, so none of them crosses the wire. This one does. It runs the agent's
own sensor thread, over real files under a fake host root, against the real
gunicorn + wsgi stack from tests/e2e_harness, and reads the result back through
GET /api/ip-intel the way the Threat intel page does. What it can see that the
rest cannot: authentication by the device token in the body, main()'s
pre-dispatch gates, the JSON framing, and the setting that reaches the agent in a
heartbeat response.

The agent insists on HTTPS (right for production); the harness speaks plain HTTP
on loopback. `http_post` is replaced in this test's own copy of the agent by the
same call with only that check left out. Everything else is the shipped code.
"""
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import browser_required  # noqa: E402
import e2e_harness  # noqa: E402
from test_v720_threat_sensor_agent import load_agent  # noqa: E402

_MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
ATTACKER = '185.220.101.7'          # public and hostile
PROBER = '45.155.205.10'            # public, three probes
CLOUDFLARE = '104.16.0.5'           # inside 104.16.0.0/13: never queued, never reported
VISITOR = '91.92.241.5'             # an ordinary visitor

NGINX_CONF = '''
user www-data;
events { worker_connections 768; }
http {
    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log;
    server { listen 80; server_name example.test; root /var/www/html; }
}
'''


def _stamp(epoch):
    t = time.gmtime(epoch)
    return f'{t.tm_mday:02d}/{_MONTHS[t.tm_mon - 1]}/{t.tm_year}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000'


def _log_line(ip, epoch, request, status):
    return f'{ip} - - [{_stamp(epoch)}] "{request}" {status} 153 "-" "Mozilla/5.0"'


class TestTheSensorOverRealHttp(unittest.TestCase):
    """One stack for the class. The tests run in the order of their numbers: each
    one starts from where the one before left the server."""

    @classmethod
    def setUpClass(cls):
        try:
            import gunicorn  # noqa: F401
        except ImportError:
            browser_required.skip_or_fail('gunicorn is not installed, so there is no stack to drive')
        cls.base, shutdown = e2e_harness.start_stack()
        cls.addClassCleanup(shutdown)
        cls.host = Path(tempfile.mkdtemp(prefix='rp-v720-wire-host-'))
        cls.addClassCleanup(shutil.rmtree, cls.host, ignore_errors=True)

        _, r = cls.call('POST', '/api/login', {'username': 'admin', 'password': 'remotepower'})
        cls.admin = r['token']
        cls.linux = cls._enroll('e2e-web01', 'Debian GNU/Linux 12')
        cls.windows = cls._enroll('e2e-win01', 'Windows Server 2022')
        cls._write_the_host()

    @classmethod
    def call(cls, method, path, body=None, token=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(cls.base + path, data=data, method=method)
        req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('X-Token', token)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode()
                return resp.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                return e.code, json.loads(text)
            except ValueError:
                return e.code, text

    @classmethod
    def _enroll(cls, name, os_name):
        _, tok = cls.call('POST', '/api/enrollment-tokens', {}, cls.admin)
        status, dev = cls.call('POST', '/api/enroll/register', {
            'enrollment_token': tok['token'], 'hostname': name, 'name': name, 'os': os_name,
            'ip': '10.1.2.3', 'mac': 'aa:bb:cc:00:11:22', 'version': '7.2.0'})
        assert status in (200, 201), (status, dev)
        dev['os'] = os_name
        return dev

    @classmethod
    def _write_the_host(cls):
        logs = cls.host / 'var/log/nginx'
        logs.mkdir(parents=True)
        (cls.host / 'etc/nginx').mkdir(parents=True)
        (cls.host / 'etc/nginx/nginx.conf').write_text(NGINX_CONF)
        (logs / 'error.log').write_text('')
        t0 = int(time.time()) - 300
        rows = []
        rows += [_log_line(ATTACKER, t0 + i, 'GET /index.php?id=1%20union%20select%201,2,3,4--%20- HTTP/1.1', 200)
                 for i in range(14)]
        rows += [_log_line(ATTACKER, t0 + 20 + i, 'GET /download?file=../../../../etc/passwd HTTP/1.1', 404)
                 for i in range(6)]
        rows += [_log_line(PROBER, t0 + 40 + i, 'GET /.env HTTP/1.1', 404) for i in range(3)]
        rows += [_log_line(CLOUDFLARE, t0 + 50 + i, 'GET /wp-login.php HTTP/1.1', 404) for i in range(30)]
        rows += [_log_line(VISITOR, t0 + 90 + i, 'GET /index.html HTTP/1.1', 200) for i in range(10)]
        (logs / 'access.log').write_text('\n'.join(rows) + '\n')

    def beat(self, dev):
        status, resp = self.call('POST', '/api/heartbeat', {
            'device_id': dev['device_id'], 'token': dev['token'], 'version': '7.2.0',
            'hostname': dev.get('name', ''), 'os': dev['os']})
        self.assertEqual(status, 200, resp)
        return resp

    def intel(self):
        status, resp = self.call('GET', '/api/ip-intel', token=self.admin)
        self.assertEqual(status, 200, resp)
        return resp

    # ── 1: off until the admin turns it on ─────────────────────────────────────

    def test_1_it_is_off_until_the_admin_turns_it_on(self):
        self.assertNotIn('threat_sensor', self.beat(self.linux))
        status, resp = self.call('POST', '/api/threat-events', {
            'device_id': self.linux['device_id'], 'token': self.linux['token'],
            'events': [{'ip': ATTACKER, 'src': {'web': 9}, 'tok': {'web': {'req:sqli': 9}}}]})
        self.assertEqual(status, 200, resp)
        self.assertIs(resp.get('enabled'), False, 'a switched-off intake says so and keeps nothing')
        self.assertEqual(self.intel()['queued'], 0)

    # ── 2: the setting reaches Linux hosts and nobody else ─────────────────────

    def test_2_the_setting_reaches_linux_hosts_only(self):
        status, resp = self.call('POST', '/api/ip-intel/settings', {'sensor_enabled': True}, self.admin)
        self.assertEqual(status, 200, resp)
        self.assertEqual(self.beat(self.linux).get('threat_sensor'), {'enabled': True, 'paths': []})
        self.assertNotIn('threat_sensor', self.beat(self.windows),
                         'a Windows agent has no web or WAF logs to read and must not be asked to')

    # ── 3: what is not a device is refused, and never a 500 ────────────────────

    def test_3_the_intake_refuses_what_is_not_a_device(self):
        good = {'ip': ATTACKER, 'src': {'web': 9}, 'tok': {'web': {'req:sqli': 9}}}
        mine = {'device_id': self.linux['device_id'], 'events': [good]}
        cases = {
            'wrong token': (dict(mine, token='wrong'), None),
            "another device's token": (dict(mine, token=self.windows['token']), None),
            'an admin session in the header': (dict(mine, token='wrong'), self.admin),
        }
        for what, (body, header_token) in cases.items():
            with self.subTest(what):
                status, resp = self.call('POST', '/api/threat-events', body, token=header_token)
                self.assertIn(status, (401, 403), (status, resp))
        for what, raw in {'a JSON array': b'[1, 2, 3]', 'not JSON': b'not json', 'an empty body': b''}.items():
            with self.subTest(what):
                status, resp = self.call('POST', '/api/threat-events', raw=raw)
                self.assertLess(status, 500, (status, resp))
        self.assertEqual(self.intel()['queued'], 0, 'none of the refused posts left anything behind')

    # ── 4: a valid device is still not trusted with what it says ───────────────

    def test_4_the_intake_drops_what_it_should_not_keep(self):
        """The agent drops Cloudflare addresses itself, so the thread never sends one
        and the test below cannot tell whether the server would also refuse. A
        compromised host, or an older agent, could send one. Post it directly."""
        status, _ = self.call('POST', '/api/ip-intel/settings', {'sensor_enabled': True}, self.admin)
        self.assertEqual(status, 200)
        status, resp = self.call('POST', '/api/threat-events', {
            'device_id': self.linux['device_id'], 'token': self.linux['token'],
            'events': [
                {'ip': CLOUDFLARE, 'src': {'web': 30}, 'tok': {'web': {'req:probe': 30}}},
                {'ip': 'not an address', 'src': {'web': 5}, 'tok': {'web': {'req:sqli': 5}}},
            ]})
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp.get('accepted'), 0, resp)
        self.assertEqual(resp.get('ignored'), {'cloudflare': 1, 'invalid': 1}, resp)
        self.assertEqual(self.intel()['queued'], 0, 'something the intake ignored was queued anyway')

    # ── 5: the agent's own thread, to the page ─────────────────────────────────

    def test_5_the_real_thread_gets_a_hostile_address_to_the_page(self):
        status, resp = self.call('POST', '/api/ip-intel/settings', {'sensor_enabled': True}, self.admin)
        self.assertEqual(status, 200, resp)
        agent = load_agent('agent_v720_wire')
        agent.HOST_ROOT = str(self.host)
        agent.THREAT_STATE_FILE = self.host / 'state.json'
        agent._which = lambda prog, _cache={}: None          # no cscli or fail2ban-client on this box

        def http_post_plain(url, data, timeout=10):
            self.assertTrue(url.startswith('http://127.0.0.1:'), url)
            req = agent.request.Request(
                url, data=json.dumps(data).encode(),
                headers={'Content-Type': 'application/json', 'User-Agent': f'RemotePower-Agent/{agent.VERSION}'})
            with agent._OPENER.open(req, timeout=timeout) as resp:
                return json.loads(resp.read(agent.MAX_JSON_RESP))
        agent.http_post = http_post_plain

        creds = {'server_url': self.base, 'device_id': self.linux['device_id'], 'token': self.linux['token']}
        holder = {'cfg': self.beat(self.linux)['threat_sensor']}
        stop = threading.Event()
        thread = threading.Thread(target=agent._threat_sensor_thread, args=(creds, holder, stop, 1, 0), daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop.set(), thread.join(timeout=10)))

        # The agent posts within a second or two. The page shows an address once the
        # server's own once-a-minute sweep has taken it off the queue, so allow for that.
        deadline = time.monotonic() + 120
        view, row = {}, None
        while time.monotonic() < deadline and not row:
            view = self.intel()
            row = {a['ip']: a for a in view.get('attackers') or []}.get(ATTACKER)
            if not row:
                time.sleep(2)
        self.assertIsNotNone(row, f'the hostile address never reached the page; queued={view.get("queued")}')

        evidence = row.get('evidence') or {}
        classes = {c['id']: c['n'] for c in evidence.get('classes') or []}
        self.assertEqual(classes, {'sqli': 14, 'traversal': 6})
        self.assertEqual([(s['id'], s['n']) for s in evidence.get('sources') or []], [('web', 20)])

        kept = {a['ip'] for a in view.get('attackers') or []}
        self.assertNotIn(CLOUDFLARE, kept, 'a Cloudflare edge address was kept')
        self.assertNotIn(VISITOR, kept, 'an ordinary visitor was kept')
        self.assertIs(view.get('sensor_enabled'), True)

        paths = [s['path'] for r in view.get('sensors') or [] for s in r.get('sources') or []]
        self.assertIn('/var/log/nginx/access.log', paths, 'the Log sources card does not list the log')


if __name__ == '__main__':
    unittest.main()
