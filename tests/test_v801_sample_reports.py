"""Samples on the server: the setting, the intake, the ledger, the page and the report (8.0.1).

The vocabulary and the agent have their own modules (test_v801_evidence_samples, test_v801_agent_samples). This one is about what the server
does with a sample once it has one:

  * `sensor_samples` (default on) is the operator's say on whether request samples leave the hosts at all. The agent only sends them when the
    heartbeat says so, so a switch that did not reach the config would be a feature nobody could turn off.
  * The intake rebuilds every sample, whatever the body held: a hostile one is cut or dropped before it reaches the queue or the ledger.
  * The ledger keeps them with the evidence; the page shows them escaped; a report carries them only when the operator has said so.

The sweep and the handlers run for real over a real store; only the socket is replaced.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-samples-'))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'server' / 'cgi-bin'))
from test_ip_intel import ATTACKER  # noqa: E402
from test_v720_threat_intake import _Intake, raw_event  # noqa: E402

import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402

ROOT = HERE.parent


def smp(path='/wp-login.php', method='GET', status=404, fam='web'):
    return {'f': fam, 'm': method, 'p': path, 'c': status, 't': int(time.time()) - 20}


class _Beats(_Intake):
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


class TestTheSwitchReachesTheAgents(_Beats):
    LINUX = {'os': 'Ubuntu 24.04'}

    def test_on_by_default(self):
        self.assertIs(ip_intel.DEFAULTS['sensor_samples'], True)
        self.assertIs(self.api.threat_sensor_config_for(self.LINUX)['samples'], True)
        self.assertEqual(self.beat('d1')['threat_sensor']['samples'], True)

    def test_off_tells_the_agent_to_send_none_and_the_sensor_keeps_working(self):
        self.policy(sensor_samples=False)
        cfg = self.api.threat_sensor_config_for(self.LINUX)
        self.assertEqual(cfg, {'enabled': True, 'paths': [], 'samples': False})
        self.assertEqual(self.beat('d1')['threat_sensor'], cfg)

    def test_a_windows_host_is_told_nothing_either_way(self):
        self.policy(sensor_samples=True)
        self.assertNotIn('threat_sensor', self.beat('d2'))

    def test_the_sensor_off_sends_nothing_whatever_this_says(self):
        self.policy(sensor_enabled=False, sensor_samples=True)
        self.assertNotIn('threat_sensor', self.beat('d1'))

    def test_it_is_saved_shown_and_left_alone_by_a_save_that_does_not_name_it(self):
        self.assertIs(self.call(self.api.handle_ip_intel, 'GET')[1]['settings']['sensor_samples'], True)
        st, d = self.call(self.api.handle_ip_intel_settings, 'POST', {'sensor_samples': False})
        self.assertEqual(st, 200, d)
        self.assertIs(self.call(self.api.handle_ip_intel, 'GET')[1]['settings']['sensor_samples'], False)
        self.call(self.api.handle_ip_intel_settings, 'POST', {'block_min_score': 80})
        self.assertIs(self.call(self.api.handle_ip_intel, 'GET')[1]['settings']['sensor_samples'], False)
        self.call(self.api.handle_ip_intel_settings, 'POST', {'sensor_samples': True})
        self.assertIs(self.call(self.api.handle_ip_intel, 'GET')[1]['settings']['sensor_samples'], True)

    def test_only_an_administrator_changes_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'sensor_samples': False}, role='viewer')
        self.assertEqual(st, 403)
        self.assertIs(self.call(self.api.handle_ip_intel, 'GET')[1]['settings']['sensor_samples'], True)

    def test_the_request_model_declares_the_key(self):
        import request_models
        self.assertIn('sensor_samples', request_models.IpIntelSettingsRequest.model_fields)


class TestTheIntakeRebuildsWhatItIsGiven(_Intake):
    def test_a_good_sample_reaches_the_queue(self):
        self.post([raw_event(smp=[smp('/.env', status=403), smp('/wp-login.php', 'POST', 404)])])
        got = self.queue()[0]['evidence']['smp']
        self.assertEqual([(s['m'], s['p'], s['c']) for s in got], [('GET', '/.env', 403), ('POST', '/wp-login.php', 404)])

    def test_a_hostile_one_is_cut_or_dropped_before_it_is_kept(self):
        hostile = [
            smp('/a<script>alert(1)</script>'),
            smp('/p?token=SECRET&x=<img src=x onerror=alert(1)>'),
            smp('/jsessionid;jsessionid=SECRET'),
            smp('http://evil.example/steal'),
            smp('/img.jpg%20768w,%20https:/private.corp.example/x'),
            dict(smp('/ok'), f='cf'),                       # an agent cannot speak for Cloudflare
            dict(smp('/also-ok'), ua='sqlmap', ref='https://h/', cookie='SESSION=abc'),
            {'p': '/no-family'},
            'GET /raw line as text',
            ['/a', '/b'],
        ]
        self.post([raw_event(smp=hostile)])
        stored = json.dumps(self.store())
        for needle in ('<script', 'onerror', 'SECRET', 'evil.example', 'corp.example', 'sqlmap', 'SESSION=abc', 'raw line'):
            self.assertNotIn(needle, stored, needle)
        got = [s['p'] for s in self.queue()[0]['evidence']['smp']]
        self.assertEqual(got, ['/a...', '/p', '/jsessionid...'])

    def test_a_body_with_a_huge_list_is_cut_to_three(self):
        self.post([raw_event(smp=[smp(f'/path{i}') for i in range(5000)])])
        self.assertEqual(len(self.queue()[0]['evidence']['smp']), threat_evidence.MAX_SAMPLES)

    def test_two_posts_of_one_address_keep_the_first_samples_and_add_new_ones(self):
        self.post([raw_event(smp=[smp('/a'), smp('/b')])])
        self.post([raw_event(smp=[smp('/b'), smp('/c'), smp('/d')])])
        self.assertEqual([s['p'] for s in self.queue()[0]['evidence']['smp']], ['/a', '/b', '/c'])

    def test_the_ledger_keeps_them_with_the_evidence(self):
        self.post([raw_event(smp=[smp('/.env', status=403)])])
        self.sweep()
        ev = self.store()['attackers'][ATTACKER]['ev']
        self.assertEqual([(s['m'], s['p'], s['c']) for s in ev['smp']], [('GET', '/.env', 403)])


class TestSamplesDoNotChangeWhatIsDecided(_Intake):
    def test_what_is_reported_and_why_is_the_same_with_and_without(self):
        plain = threat_evidence.normalize_event(raw_event(n=12), now=int(time.time()))
        rich = threat_evidence.normalize_event(raw_event(n=12, smp=[smp('/.env')]), now=int(time.time()))
        self.assertEqual(threat_evidence.qualifies(plain, 10), threat_evidence.qualifies(rich, 10))
        self.assertEqual(threat_evidence.categories(plain, 'abuseipdb'), threat_evidence.categories(rich, 'abuseipdb'))
        self.assertEqual(ip_intel.evidence_comment(plain), ip_intel.evidence_comment(rich),
                         'without the operator\'s say, a report does not change')

    def test_the_shape_registry_leaves_the_ledgers_samples_as_they_are(self):
        # the registry does not list a ledger's `ev` today, so what protects a damaged one is the check in threat_evidence.merge and
        # in the page's view (TestTheDetail). This holds that the registry itself does not change a sample list on the way through
        import store_shapes
        self.post([raw_event(smp=[smp('/.env', status=403)])])
        self.sweep()
        st = self.store()
        again = store_shapes.normalize(self.api.IPINTEL_FILE.name, json.loads(json.dumps(st)))
        self.assertEqual(again['attackers'][ATTACKER]['ev']['smp'], st['attackers'][ATTACKER]['ev']['smp'])


if __name__ == '__main__':
    unittest.main()
