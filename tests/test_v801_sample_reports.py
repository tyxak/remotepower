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
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-samples-'))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
import test_v710_ipintel_settings_js as settings_js  # noqa: E402
from test_ip_intel import ATTACKER  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402
from test_v720_ipintel_page import node  # noqa: E402
from test_v720_threat_intake import _Intake, raw_event  # noqa: E402
from test_v720_threat_report_engine import _Engine  # noqa: E402
from test_v720_threat_report_engine import raw_event as engine_event  # noqa: E402

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


class TestTheViewAndTheOutcome(_Intake):
    def row(self):
        rows = self.call(self.api.handle_ip_intel, 'GET')[1]['attackers']
        return next(r for r in rows if r['ip'] == ATTACKER)

    def test_the_view_carries_the_samples_and_the_scenarios(self):
        self.post([raw_event(src={'cs': 1}, tok={'cs': {'cs:crowdsecurity/http-generic-test': 1, 'cs:crowdsecurity/ssh-bf': 1}}, dec=1,
                             smp=[smp('/wp-content/uploads/x.jpg/', status=403, fam='waf')])])
        self.sweep()
        ev = self.row()['evidence']
        self.assertEqual([(s['f'], s['m'], s['p'], s['c']) for s in ev['samples']], [('waf', 'GET', '/wp-content/uploads/x.jpg/', 403)])
        self.assertEqual(ev['scenarios'], [{'id': 'crowdsecurity/http-generic-test', 'n': 1, 'class': ''},
                                           {'id': 'crowdsecurity/ssh-bf', 'n': 1, 'class': 'ssh_brute'}])

    def test_an_address_with_no_samples_has_an_empty_list_not_a_missing_one(self):
        self.post([raw_event()])
        self.sweep()
        self.assertEqual(self.row()['evidence']['samples'], [])

    def test_a_damaged_ledger_is_rebuilt_in_the_view(self):
        self.post([raw_event(smp=[smp('/ok')])])
        self.sweep()
        st = self.store()
        st['attackers'][ATTACKER]['ev']['smp'] = [
            {'f': 'web', 'm': 'GET', 'p': '/a<script>alert(1)</script>', 'c': 403, 't': 5}, 'junk', None,
            {'f': 'zzz', 'm': 'GET', 'p': '/not-a-family', 'c': 1, 't': 1}, {'f': 'web', 'm': 'GET', 'p': 'http://evil.example/x'}]
        ipintel_store.write(self.api, st)
        self.api._LOAD_CACHE.clear()
        self.assertEqual([s['p'] for s in self.row()['evidence']['samples']], ['/a...'])
        for junk in ('text', 5, {'p': '/x'}, [[]]):
            st['attackers'][ATTACKER]['ev']['smp'] = junk
            ipintel_store.write(self.api, st)
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.row()['evidence']['samples'], [], repr(junk))


class TestTheOutcomeNamesWhatHeldItUp(_Engine):
    def reported(self):
        return len(self.posts()) > 0

    def test_a_scenario_with_no_category_is_named(self):
        self.feed(engine_event(src={'cs': 1}, tok={'cs': {'cs:crowdsecurity/http-generic-test': 1}}, dec=1))
        self.sweep()
        self.assertFalse(self.reported())
        for prov in ('abuseipdb', 'sniffcat'):
            self.assertEqual(self.att()['errors'][prov],
                             'not reported: no attack category for the CrowdSec scenario crowdsecurity/http-generic-test')

    def test_the_uploads_listing_rule_is_reported_now(self):
        self.feed(engine_event(src={'cs': 1}, tok={'cs': {'cs:crowdsecurity/generic-wordpress-uploads-listing': 1}}, dec=1))
        self.sweep()
        self.assertTrue(self.reported(), 'the address that started this: one AppSec rule, one CrowdSec decision')
        self.assertEqual(self.abuse_form()['categories'], ['21'])

    def test_a_decision_that_names_nothing_keeps_the_old_words(self):
        self.feed(engine_event(src={'cs': 1}, dec=1))
        self.sweep()
        self.assertEqual(self.att()['errors']['abuseipdb'], 'not reported: nothing recognisable in the logs')


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestThePage(unittest.TestCase):
    _run = settings_js.TestPage._run

    EV = {'classes': [], 'sources': [{'id': 'waf', 'n': 1}], 'kinds': [], 'rules': [], 'cves': [], 'jails': [], 'ans': 0, 'blk': 1,
          'confirmed': 'CrowdSec', 'first': 1, 'last': 2, 'sent': False, 'scenarios': [], 'samples': []}

    def detail(self, **kw):
        ev = dict(self.EV, **kw)
        return node('console.log(JSON.stringify(_ipiDetailHtml({evidence: %s, report_log: []})));' % json.dumps(ev))

    def test_the_requests_are_listed_with_the_log_and_the_time(self):
        html = self.detail(samples=[{'f': 'waf', 'm': 'GET', 'p': '/wp-content/uploads/x.jpg/', 'c': 403, 't': 5},
                                    {'f': 'web', 'm': '', 'p': '/old', 'c': 0, 't': 0}])
        self.assertIn('<dt><span>Requests</span></dt>', html)
        self.assertIn('<div class="ipi-sample"><code>GET /wp-content/uploads/x.jpg/</code> 403 '
                      '<span class="hint"><span>WAF audit log</span> · 5m ago</span></div>', html)
        self.assertIn('<div class="ipi-sample"><code>/old</code> <span class="hint"><span>Web server log</span></span></div>', html)

    def test_what_the_page_prints_is_escaped_whatever_the_server_sent(self):
        hostile = '/<img src=x onerror=alert(1)>"' + "'" + '`'
        html = self.detail(samples=[{'f': '<b>x</b>', 'm': '<i>', 'p': hostile, 'c': '<u>', 't': 5}],
                           scenarios=[{'id': '<script>alert(1)</script>', 'n': 1, 'class': ''}])
        for raw in ('<img', '<script', '<b>', '<i>', '<u>', 'onerror=alert(1)>'):
            self.assertNotIn(raw, html, raw)
        self.assertIn('&lt;img', html)
        self.assertIn('&lt;script&gt;', html)

    def test_no_samples_no_row(self):
        html = self.detail()
        self.assertNotIn('Requests', html)
        self.assertNotIn('ipi-sample', html)

    def test_the_scenarios_join_the_rules(self):
        html = self.detail(rules=['942100'], jails=['sshd'], scenarios=[{'id': 'crowdsecurity/ssh-bf', 'n': 3, 'class': 'ssh_brute'}])
        self.assertIn('<dt><span>Rules</span></dt><dd><code>942100</code> <code>sshd</code> <code>crowdsecurity/ssh-bf</code></dd>', html)

    def test_the_filter_finds_a_path_and_a_scenario(self):
        ev = dict(self.EV, scenarios=[{'id': 'crowdsecurity/http-generic-test', 'n': 1, 'class': ''}],
                  samples=[{'f': 'web', 'm': 'GET', 'p': '/wp-login.php', 'c': 404, 't': 1}])
        text = node('console.log(JSON.stringify(_ipiEvidenceText({evidence: %s})));' % json.dumps(ev))
        self.assertIn('/wp-login.php', text)
        self.assertIn('crowdsecurity/http-generic-test', text)

    def test_the_outcome_line_names_the_scenario_or_the_jail(self):
        reasons = ['not reported: no attack category for the CrowdSec scenario crowdsecurity/http-generic-test',
                   'not reported: no attack category for the fail2ban jail recidive',
                   'not reported: no attack category for the CrowdSec scenario x"><img src=x onerror=alert(1)>',
                   'not reported: nothing recognisable in the logs',
                   'not reported: no attack category for the CrowdSec scenario two words']
        got = node('console.log(JSON.stringify(%s.map(_ipiReason)));' % json.dumps(reasons))
        self.assertEqual(got[0], '<span>not reported:</span> <span>no attack category for the CrowdSec scenario</span> '
                                 '<code>crowdsecurity/http-generic-test</code>')
        self.assertEqual(got[1], '<span>not reported:</span> <span>no attack category for the fail2ban jail</span> <code>recidive</code>')
        self.assertNotIn('<img', got[2])
        self.assertIn('&lt;img', got[2])
        self.assertEqual(got[3], '<span>not reported:</span> <span>nothing recognisable in the logs</span>')
        # a name with a space is not one the server writes; it falls through to the plain phrase
        self.assertEqual(got[4], '<span>not reported:</span> <span>no attack category for the CrowdSec scenario two words</span>')

    def test_what_the_server_writes_is_what_the_page_reads(self):
        import threat_evidence as te
        now = int(time.time())
        for name in ('crowdsecurity/http-generic-test', 'tyxak/own-thing', 'a_b.c/d-e'):
            ev = te.normalize_event({'ip': '45.33.32.156', 'src': {'cs': 1}, 'tok': {'cs': {'cs:' + name: 1}}, 'dec': 1}, now=now)
            why = 'not reported: ' + te.qualifies(ev, 10)[1]
            html = node('console.log(JSON.stringify(_ipiReason(%s)));' % json.dumps(why))
            self.assertIn('<code>%s</code>' % name, html)
        ev = te.normalize_event({'ip': '45.33.32.156', 'src': {'f2b': 1}, 'ban': ['recidive']}, now=now)
        why = 'not reported: ' + te.qualifies(ev, 10)[1]
        self.assertIn('<code>recidive</code>', node('console.log(JSON.stringify(_ipiReason(%s)));' % json.dumps(why)))

    def test_the_new_words_are_translated(self):
        rows = dict_rows()
        langs = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
        for phrase in ('Send up to three request samples with each address',
                       'no attack category for the CrowdSec scenario', 'no attack category for the fail2ban jail', 'Requests'):
            self.assertTrue(rows.get(phrase) and all(rows[phrase].get(lang) for lang in langs), phrase)
        hint = next((k for k in rows if k.startswith('A sample is one request an address made')), None)
        self.assertTrue(hint and all(rows[hint].get(lang) for lang in langs))

    def test_the_card_no_longer_says_a_path_never_leaves_the_host(self):
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        i18n = (ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text()
        for needle in ('never log lines, paths or host names', 'Only counts and attack types leave the host'):
            self.assertNotIn(needle, html)
            self.assertNotIn(needle, i18n)
        card = html[html.index('id="ipintel-sensor-card"'):html.index('id="ipintel-appliance-card"')]
        self.assertIn('Counts and attack types are sent for every address; log lines and host names never leave the host.', card)
        self.assertRegex(card, r'<input type="checkbox" id="ipintel-sensor-samples"> Send up to three request samples with each address</label>')
        self.assertIn('Untick this and hosts send counts and attack types only.', card)
        self.assertLess(card.index('id="ipintel-sensor"'), card.index('id="ipintel-sensor-samples"'))
        self.assertLess(card.index('id="ipintel-sensor-samples"'), card.index('id="ipintel-sensor-paths"'))

    def test_the_page_shows_the_stored_value_and_sends_what_was_ticked(self):
        got = self._run("""
          _ipiFillSettings({sensor_samples: false}, {});
          const off = els['ipintel-sensor-samples'].checked;
          _ipiFillSettings({}, {});
          const unset = els['ipintel-sensor-samples'].checked;
          _ipiFillSettings({sensor_samples: true}, {});
          const on = els['ipintel-sensor-samples'].checked;
          els['ipintel-sensor-samples'].checked = false;
          await saveIpIntelSettings();
          const sentOff = sent.body.sensor_samples;
          els['ipintel-sensor-samples'].checked = true;
          await saveIpIntelSettings();
          console.log(JSON.stringify({off, unset, on, sentOff, sentOn: sent.body.sensor_samples}));""")
        self.assertEqual(got, {'off': False, 'unset': True, 'on': True, 'sentOff': False, 'sentOn': True},
                         'a server that does not send the key means on, the way the agent reads it')

    def test_the_stamp_moved_with_the_script(self):
        sw = (ROOT / 'server' / 'html' / 'sw.js').read_text()
        stamp = re.search(r'remotepower-shell-v([0-9.]+-\d+)', sw)
        self.assertTrue(stamp)
        self.assertNotEqual(stamp.group(1) if stamp else '', '8.0.1-3', 'app-ipintel.js, i18n.js and styles.css changed')


if __name__ == '__main__':
    unittest.main()
