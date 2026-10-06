"""The threat sensor's intake: a Linux agent's summaries reach Threat intel.

The handler is driven for real against a real store. What matters is who is let
in (only a device speaking for itself), what is let through (only the fixed
vocabulary), and what one host can do to the install (not spend its report
budget on invented sources).
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v720-intake-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_ip_intel import ATTACKER, _Case  # noqa: E402

CLOUDFLARE = '104.16.5.5'
SECOND = '185.220.101.8'


def raw_event(ip=ATTACKER, n=12, **kw):
    now = int(time.time())
    e = {'ip': ip, 'first': now - 60, 'last': now, 'src': {'web': n},
         'tok': {'web': {'req:probe': n}}}
    e.update(kw)
    return e


class _Intake(_Case):
    def setUp(self):
        super().setUp()
        self.policy(sensor_enabled=True)

    def call(self, fn, method='POST', body=None, role='admin'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def post(self, events=None, dev='d1', token='t', sources=None, **extra):
        body = {'device_id': dev, 'token': token, 'events': events or [], 'sources': sources or []}
        body.update(extra)
        return self.call(self.api.handle_threat_events, 'POST', body)

    def store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IPINTEL_FILE) or {}

    def queue(self):
        return self.store().get('queue') or []


class TestWhoIsLetIn(_Intake):
    def test_only_a_device_speaking_for_itself(self):
        self.assertEqual(self.post([raw_event()], token='wrong')[0], 403)
        self.assertEqual(self.post([raw_event()], dev='nope')[0], 403)
        self.assertEqual(self.post([raw_event()], dev='../etc')[0], 403)
        self.assertEqual(self.post([raw_event()], token='')[0], 403)
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.post([raw_event()])[0], 200)
        self.assertEqual(self.call(self.api.handle_threat_events, 'GET', {})[0], 405)

    def test_a_logged_in_users_session_is_not_a_way_in(self):
        """An admin's session proves nothing here: the body's device token is the
        only credential the handler reads."""
        self.api.get_token_from_request = lambda: 'a-valid-admin-session'
        st, _ = self.post([raw_event()], token='wrong')
        self.assertEqual(st, 403)

    def test_off_means_off_and_it_is_not_an_error(self):
        self.policy(sensor_enabled=False)
        st, d = self.post([raw_event()])
        self.assertEqual((st, d.get('enabled')), (200, False))
        self.assertEqual(self.queue(), [])
        self.assertNotIn('sensors', self.store())

    def test_a_windows_host_is_not_a_sensor(self):
        st, d = self.post([raw_event()], dev='d2')
        self.assertEqual((st, d.get('enabled')), (200, False))
        self.assertEqual(self.queue(), [])

    def test_an_agentless_device_is_not_a_sensor(self):
        devices = self.api.load(self.api.DEVICES_FILE)
        devices['d3']['agentless'] = True
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.post([raw_event()], dev='d3')[1].get('enabled'), False)


class TestWhatIsLetThrough(_Intake):
    def test_events_are_queued_with_their_evidence(self):
        st, d = self.post([raw_event(n=12, ans=2, blk=9)], sources=[
            {'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 400, 'parsed': 399,
             'events': 12, 'fmt': 'custom', 'proxied': True}])
        self.assertEqual((st, d['accepted'], d['throttled']), (200, 1, 0))
        q = self.queue()
        self.assertEqual(len(q), 1)
        item = q[0]
        self.assertEqual((item['ip'], item['device_id'], item['unit'], item['count']), (ATTACKER, 'd1', 'threat-sensor', 12))
        ev = item['evidence']
        self.assertEqual((ev['src'], ev['ans'], ev['blk']), ({'web': 12}, 2, 9))
        self.assertEqual(ev['tok']['web'], {'req:probe': 12})

    def test_the_same_address_is_one_entry_that_grows_per_host(self):
        for _ in range(3):
            self.post([raw_event(n=12)])
        q = self.queue()
        self.assertEqual(len(q), 1, 'a minute-by-minute attack is one entry, not sixty')
        self.assertEqual((q[0]['count'], q[0]['evidence']['src']), (36, {'web': 36}))
        self.post([raw_event(n=5)], dev='d3')
        self.assertEqual(len(self.queue()), 2, 'another host is its own entry')

    def test_what_is_not_a_public_attacker_is_ignored_and_counted(self):
        events = [raw_event(), raw_event(ip='10.1.2.3'), raw_event(ip='192.168.0.4'), raw_event(ip='not-an-ip'),
                  raw_event(ip=CLOUDFLARE), raw_event(ip='2606:4700::1111'), {'ip': SECOND}, 'garbage', 7, None]
        st, d = self.post(events)
        self.assertEqual(d['accepted'], 1)
        self.assertEqual(d['ignored'], {'invalid': 7, 'cloudflare': 2})
        self.assertEqual([x['ip'] for x in self.queue()], [ATTACKER])
        self.assertEqual(self.store()['sensors']['d1']['ignored'], {'invalid': 7, 'cloudflare': 2})

    def test_the_vocabulary_is_enforced(self):
        ev = raw_event(tok={'web': {'req:probe': 4, 'req:drop table': 9, 'jail:x\ny': 3, 'req:probe\n': 2}},
                       ban=['sshd', 'bad jail;'], cve=['CVE-2021-44228', '<script>'])
        self.post([ev])
        got = self.queue()[0]['evidence']
        self.assertEqual(got['tok']['web'], {'req:probe': 4})
        self.assertEqual((got['ban'], got['cve']), (['sshd'], ['CVE-2021-44228']))

    def test_more_than_the_cap_in_one_post_is_cut_and_said_so(self):
        events = [raw_event(ip=f'45.{i // 250 + 1}.{i % 250 + 1}.9') for i in range(320)]
        st, d = self.post(events)
        self.assertEqual((d['accepted'], d['ignored']), (300, {'over_limit': 20}))

    def test_sources_are_reduced_to_a_fixed_shape(self):
        messy = [
            {'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 10, 'parsed': 9,
             'events': 3, 'fmt': 'custom', 'proxied': 1},
            {'kind': 'waf', 'path': '/var/log/modsec_audit.log', 'state': 'melting', 'lines': -4,
             'parsed': 'many', 'events': 10 ** 12, 'fmt': '<b>x</b>', 'proxied': True},
            {'kind': 'cs', 'path': 'cscli', 'state': 'denied'},
            {'kind': 'f2b', 'path': 'fail2ban', 'state': 'unsupported'},
            {'kind': 'evil', 'path': '/var/log/x', 'state': 'ok'},
            {'kind': 'web', 'path': '/etc/shadow; rm -rf /', 'state': 'ok'},
            {'kind': 'web', 'path': 'relative.log', 'state': 'ok'},
            {'kind': 'web', 'path': '/var/log/' + 'a' * 400, 'state': 'ok'},
            'not a dict', None, 5,
        ]
        self.post([raw_event()], sources=messy)
        rows = self.store()['sensors']['d1']['sources']
        self.assertEqual([r['kind'] for r in rows], ['web', 'waf', 'cs', 'f2b'])
        self.assertEqual(rows[0], {'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 10,
                                   'parsed': 9, 'events': 3, 'fmt': 'custom', 'proxied': True})
        self.assertEqual((rows[1]['state'], rows[1]['lines'], rows[1]['parsed'], rows[1]['events']),
                         ('error', 0, 0, 10 ** 9))
        self.assertNotIn('fmt', rows[1])
        self.assertNotIn('proxied', rows[1], 'only a web log can be behind a proxy')

    def test_a_report_with_no_events_still_records_the_hosts_health(self):
        self.post([], sources=[{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'denied'}], dropped=5)
        s = self.store()
        self.assertEqual(s.get('queue') or [], [])
        rec = s['sensors']['d1']
        self.assertEqual((rec['sources'][0]['state'], rec['dropped'], rec['events']), ('denied', 5, 0))
        self.assertLessEqual(abs(rec['at'] - int(time.time())), 5)

    def test_the_agents_own_numbers_cannot_be_negative_or_huge(self):
        self.post([raw_event()], dropped=-5)
        self.assertEqual(self.store()['sensors']['d1']['dropped'], 0)
        self.post([raw_event()], dropped=10 ** 12)
        self.assertEqual(self.store()['sensors']['d1']['dropped'], 10 ** 6)

    def test_a_body_that_is_not_shaped_like_one_does_not_break_it(self):
        for body in ({'device_id': 'd1', 'token': 't', 'events': 'x', 'sources': 'y'},
                     {'device_id': 'd1', 'token': 't', 'events': {'a': 1}, 'sources': {'b': 2}},
                     {'device_id': 'd1', 'token': 't'}):
            st, d = self.call(self.api.handle_threat_events, 'POST', body)
            self.assertEqual(st, 200, body)
            self.assertEqual(d['accepted'], 0)


class TestWhatOneHostCanDo(_Intake):
    def test_the_hourly_allowance_stops_a_flood_and_resets(self):
        mod = self.api.ip_intel_handlers_mod
        old = mod.SENSOR_EVENTS_PER_HOUR
        mod.SENSOR_EVENTS_PER_HOUR = 5
        self.addCleanup(setattr, mod, 'SENSOR_EVENTS_PER_HOUR', old)
        st, d = self.post([raw_event(ip=f'45.1.1.{i + 1}') for i in range(8)])
        self.assertEqual((d['accepted'], d['throttled']), (5, 3))
        self.assertEqual(len(self.queue()), 5)
        st, d = self.post([raw_event(ip='45.1.2.1')])
        self.assertEqual((d['accepted'], d['throttled']), (0, 1), 'still the same hour')
        s = self.store()
        s['sensors']['d1']['hour'] = {'h': 1, 'n': 5}            # a long time ago
        self.api.save(self.api.IPINTEL_FILE, s)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.post([raw_event(ip='45.1.2.2')])[1]['accepted'], 1)

    def test_another_hosts_allowance_is_its_own(self):
        mod = self.api.ip_intel_handlers_mod
        old = mod.SENSOR_EVENTS_PER_HOUR
        mod.SENSOR_EVENTS_PER_HOUR = 2
        self.addCleanup(setattr, mod, 'SENSOR_EVENTS_PER_HOUR', old)
        self.post([raw_event(ip=f'45.1.1.{i + 1}') for i in range(4)], dev='d1')
        st, d = self.post([raw_event(ip='45.2.2.2')], dev='d3')
        self.assertEqual(d['accepted'], 1)

    def test_a_full_queue_keeps_what_matters_and_the_order(self):
        mod = self.api.ip_intel_handlers_mod
        old = mod.QUEUE_CAP
        mod.QUEUE_CAP = 6
        self.addCleanup(setattr, mod, 'QUEUE_CAP', old)
        self.post([raw_event(ip=f'45.1.1.{i + 1}', n=3 + i) for i in range(6)])
        banned = raw_event(ip='45.9.9.9', n=1, ban=['sshd'], tok={'f2b': {'jail:sshd': 1}}, src={'f2b': 1})
        self.post([banned, raw_event(ip='45.1.1.50', n=3)])
        ips = [x['ip'] for x in self.queue()]
        self.assertEqual(len(ips), 6)
        self.assertIn('45.9.9.9', ips, 'an address a ban engine decided on stays')
        self.assertNotIn('45.1.1.1', ips, 'the least notable goes')
        self.assertEqual(ips, sorted(ips, key=lambda ip: [x['ip'] for x in self.queue()].index(ip)), 'order kept')

    def test_a_brute_force_entry_outranks_an_unconfirmed_web_hit_when_the_queue_is_full(self):
        mod = self.api.ip_intel_handlers_mod
        old = mod.QUEUE_CAP
        mod.QUEUE_CAP = 3
        self.addCleanup(setattr, mod, 'QUEUE_CAP', old)
        self.attack(ip='45.7.7.7', count=25)
        self.post([raw_event(ip=f'45.1.1.{i + 1}', n=3) for i in range(5)])
        self.assertIn('45.7.7.7', [x['ip'] for x in self.queue()])

    def test_stale_hosts_are_forgotten(self):
        s = self.store()
        s['sensors'] = {'d9': {'at': int(time.time()) - 31 * 86400, 'sources': []},
                        'd8': {'at': int(time.time()) - 86400, 'sources': []}}
        self.api.save(self.api.IPINTEL_FILE, s)
        self.api._LOAD_CACHE.clear()
        self.post([raw_event()])
        self.assertEqual(set(self.store()['sensors']), {'d1', 'd8'})


class TestTheSettingReachesAgents(_Intake):
    def beat(self, dev_id='d1', token='t'):
        self.api.method = lambda: 'POST'
        self.api.get_json_body = lambda: {'device_id': dev_id, 'token': token}
        self.api.get_json_obj = self.api.get_json_body
        self.cap.clear()
        try:
            self.api.handle_heartbeat()
        except (self.api.HTTPError, SystemExit):
            pass
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.cap.get('status'), 200, self.cap)
        return self.cap['data']

    def test_a_linux_agent_is_told_and_a_windows_one_is_not(self):
        self.policy(sensor_enabled=True, sensor_paths=['/var/log/app/access.log'])
        self.assertEqual(self.beat('d1').get('threat_sensor'), {'enabled': True, 'paths': ['/var/log/app/access.log']})
        self.assertNotIn('threat_sensor', self.beat('d2'))

    def test_off_sends_nothing_so_the_agent_stops(self):
        self.policy(sensor_enabled=False)
        self.assertNotIn('threat_sensor', self.beat('d1'))

    def test_the_config_builder_directly(self):
        f = self.api.threat_sensor_config_for
        self.assertEqual(f({'os': 'Ubuntu 24.04'}), {'enabled': True, 'paths': []})
        self.assertIsNone(f({'os': 'Windows 11'}))
        self.assertIsNone(f({'os': 'macOS 14.5'}))
        self.assertIsNone(f({'os': 'Debian 12', 'agentless': True}))
        self.assertIsNone(f(None))
        self.assertIsNone(f('x'))
        self.policy(sensor_enabled=False)
        self.assertIsNone(f({'os': 'Ubuntu 24.04'}))

    def test_a_failure_in_the_builder_cannot_fail_a_heartbeat(self):
        self.api.ip_intel_policy = lambda: (_ for _ in ()).throw(RuntimeError('store unreadable'))
        self.assertIsNone(self.api.threat_sensor_config_for({'os': 'Ubuntu 24.04'}))


class TestTheAllowlistNeverSilencesTheSensor(_Intake):
    def test_exempt_like_the_other_device_token_endpoints(self):
        self.api.save(self.api.CONFIG_FILE, dict(self.api.load(self.api.CONFIG_FILE),
                                                 ip_allowlist_enabled=True, ip_allowlist=['10.0.0.0/24']))
        self.api._LOAD_CACHE.clear()
        self.api._get_client_ip = lambda: '198.51.100.9'     # a host on a dynamic address

        def status(path):
            self.api.path_info = lambda: path
            self.cap.clear()
            try:
                self.api._enforce_ip_allowlist()
                return 200
            except self.api.HTTPError:
                return self.cap.get('status')
        self.assertEqual(status('/api/threat-events'), 200)
        self.assertEqual(status('/api/logs'), 200)
        self.assertEqual(status('/api/devices'), 403, 'and the allowlist still protects the rest')
        self.assertEqual(status('/api/threat-events/x'), 403)
        self.assertEqual(status('/api/threat-eventsX'), 403)

    def test_the_route_exists_and_is_post_only(self):
        routes = self.api._build_exact_routes()
        self.assertIs(routes[('POST', '/api/threat-events')], self.api.handle_threat_events)
        self.assertNotIn(('GET', '/api/threat-events'), routes)


class TestSettings(_Intake):
    def view(self):
        return self.call(self.api.handle_ip_intel, 'GET')[1]['settings']

    def save(self, **body):
        return self.call(self.api.handle_ip_intel_settings, 'POST', body)

    def test_defaults_are_off_and_empty(self):
        self.policy(sensor_enabled=False)
        s = self.view()
        self.assertEqual((s['sensor_enabled'], s['sensor_paths']), (False, []))
        self.assertIs(ip_intel.DEFAULTS['sensor_enabled'], False)

    def test_save_and_read_back(self):
        st, d = self.save(sensor_enabled=True, sensor_paths='/var/log/app/a.log\n/var/log/app/b.log, /var/log/app/a.log')
        self.assertEqual(st, 200, d)
        s = self.view()
        self.assertEqual((s['sensor_enabled'], s['sensor_paths']), (True, ['/var/log/app/a.log', '/var/log/app/b.log']))
        self.assertTrue(any('sensor_enabled=True' in a[2] and 'sensor_paths=2' in a[2] for a in self.audit if a[1] == 'ip_intel_settings'))

    def test_the_switch_and_the_paths_are_independent(self):
        self.save(sensor_paths=['/var/log/app/a.log'])
        self.save(sensor_enabled=False)
        s = self.view()
        self.assertEqual((s['sensor_enabled'], s['sensor_paths']), (False, ['/var/log/app/a.log']))
        self.save(sensor_paths=[])
        self.assertEqual(self.view()['sensor_paths'], [])

    def test_a_bad_path_is_refused_and_changes_nothing(self):
        self.save(sensor_paths=['/var/log/ok.log'])
        for bad in (['/etc/shadow'], ['relative.log'], ['/var/log/../etc/shadow'], ['/var/log/a b.log'],
                    ['/var/log/x;rm'], ['/var/logx/a.log'], ['/var/log/' + 'a' * 300],
                    [f'/var/log/{i}.log' for i in range(21)], '/var/log/ok.log\n/tmp/evil'):
            st, d = self.save(sensor_paths=bad)
            self.assertEqual(st, 400, bad)
            self.assertIn('error', d)
        self.assertEqual(self.view()['sensor_paths'], ['/var/log/ok.log'])

    def test_only_admins_change_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'sensor_enabled': True}, role='viewer')
        self.assertEqual(st, 403)

    def test_the_path_checker_alone(self):
        f = ip_intel.clean_sensor_paths
        self.assertEqual(f(['/var/log/a.log', '/var/log/a.log']), (['/var/log/a.log'], None))
        self.assertEqual(f('/var/log/a.log,/var/log/b.log'), (['/var/log/a.log', '/var/log/b.log'], None))
        self.assertEqual(f(None), ([], None))
        self.assertEqual(f(''), ([], None))
        for bad in ('/var/log', '/var/log/', '/var/log/..', '/var/log/a/../b', '/var/log/\x00', '/var/log/a\n/etc/x'):
            self.assertIsNotNone(f([bad])[1] if bad != '/var/log/a\n/etc/x' else f(['/var/log/a\n/etc/x'])[1], bad)


class TestEvidenceThroughTheRealSweep(_Intake):
    """What the intake queues must be something the sweep can already handle."""

    def test_an_evidence_entry_is_swept_into_the_attackers_store_without_error(self):
        self.policy(sensor_enabled=True, lookup_enabled=True)
        self.post([raw_event(n=12)])
        st = self.sweep()
        att = st['attackers'][ATTACKER]
        self.assertEqual(att['devices']['d1']['count'], 12)
        self.assertEqual(att['devices']['d1']['unit'], 'threat-sensor')
        self.assertEqual(att['verdict']['score'], 100)
        self.assertEqual(st.get('queue') or [], [])

    def test_detection_only_mode_needs_no_provider_at_all(self):
        """Sensor on, nothing else: the page can still say who is attacking."""
        self.policy(sensor_enabled=True, lookup_enabled=False)
        self.post([raw_event(n=12)])
        st = self.sweep()
        self.assertIn(ATTACKER, st['attackers'])
        self.assertEqual(self.calls, [], 'nothing was sent anywhere')


if __name__ == '__main__':
    unittest.main()
