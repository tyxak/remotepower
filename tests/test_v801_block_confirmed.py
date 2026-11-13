"""An address a ban engine has already banned can be blocked without a reputation score (8.0.1).

Found on a live instance: 65.109.37.201 was banned by fail2ban in three jails, by CrowdSec and by the WAF, and RemotePower made no block, because
a new scanner has no reputation yet (AbuseIPDB 44 from six reports, SniffCat 0) and a block waited for a score of 90. The setting `block_confirmed`
(default off) lets who decided count: threat_evidence.confirmed_by is fail2ban, CrowdSec, the edge honeypot or a decoy port.

The sweep and the settings handler run for real; only the socket is replaced. With the setting off, nothing changes.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-blockconf-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
import srcpin  # noqa: E402
from test_ip_intel import _Case  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402
from test_v710_ipintel_settings_js import TestPage as _SettingsPage  # noqa: E402
from test_v730_edge_blocklist_sync import _Lists  # noqa: E402

import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402

T = 1_790_000_000
MIN = 60
IP = '65.109.37.201'
ROOT = Path(__file__).resolve().parent.parent


def event(ip=IP, ban=('modsec', 'nginx-blocked', 'recidive'), dec=0, now=T):
    """What the sensor sends for an address the WAF refused three times and a ban engine banned (the live case)."""
    src = {'waf': 3}
    ev = {'ip': ip, 'first': now - 60, 'last': now - 58, 'src': src, 'tok': {'waf': {'crs:949110': 3, 'req:probe': 2}},
          'ans': 0, 'blk': 3, 'ban': list(ban), 'dec': dec, 'cve': []}
    if ban:
        src['f2b'] = len(ban)
        ev['tok']['f2b'] = {'jail:' + j: 1 for j in ban}
    return threat_evidence.normalize_event(ev, now=now)


class TestTheDecision(unittest.TestCase):
    POL = dict(ip_intel.DEFAULTS, block_enabled=True)

    def test_it_is_off_by_default_and_the_score_still_decides(self):
        self.assertIs(ip_intel.DEFAULTS['block_confirmed'], False)
        self.assertEqual(ip_intel.block_decision(self.POL, {'score': 44}, 3, 'fail2ban'), (False, 'score 44 is below 90'))
        self.assertEqual(ip_intel.block_decision(self.POL, None, 3, 'fail2ban'), (False, 'no reputation answer'))
        self.assertTrue(ip_intel.block_decision(self.POL, {'score': 95}, 3)[0])

    def test_with_it_on_who_decided_is_enough_and_the_score_is_not_asked(self):
        pol = dict(self.POL, block_confirmed=True)
        for who in ('fail2ban', 'CrowdSec', 'the edge honeypot', 'a decoy port'):
            self.assertEqual(ip_intel.block_decision(pol, {'score': 0}, 3, who), (True, ''), who)
        self.assertEqual(ip_intel.block_decision(pol, None, 0, 'fail2ban'), (True, ''), 'no score and no count')

    def test_without_a_ban_engine_nothing_changes(self):
        pol = dict(self.POL, block_confirmed=True)
        self.assertEqual(ip_intel.block_decision(pol, {'score': 44}, 3, ''), (False, 'score 44 is below 90'))
        self.assertEqual(ip_intel.block_decision(pol, None, 3), (False, 'no reputation answer'))

    def test_what_a_provider_lists_as_legitimate_is_never_blocked_and_blocking_off_is_off(self):
        pol = dict(self.POL, block_confirmed=True)
        self.assertEqual(ip_intel.block_decision(pol, {'score': 0, 'whitelisted': True}, 3, 'fail2ban'),
                         (False, 'listed as legitimate by a provider'))
        self.assertEqual(ip_intel.block_decision(dict(pol, block_enabled=False), {'score': 99}, 3, 'fail2ban'),
                         (False, 'auto-block is off'))

    def test_the_four_phrases_the_page_may_show_are_the_ones_the_server_can_say(self):
        said = {threat_evidence.confirmed_by(e) for e in (
            {'ban': ['x']}, {'dec': 1}, {'trp': 1, 'tok': {'trp': {'trap:bait': 1}}}, {'trp': 1, 'tok': {'trp': {'trap:dp': 1}}})}
        said.discard('')
        rows = dict_rows()
        for phrase in said:
            proper_noun = phrase in ('fail2ban', 'CrowdSec')
            self.assertTrue(proper_noun or (rows.get(phrase) and all(rows[phrase].get(l) for l in
                            ('de', 'fr', 'es', 'zh', 'hi', 'ar'))), 'a phrase the blocks table can show has no six languages: ' + phrase)
        self.assertTrue({'fail2ban', 'CrowdSec'} <= said, said)


class _Sweep(_Case):
    def setUp(self):
        super().setUp()
        self.scores = {'abuseipdb': 10, 'sniffcat': 10}
        self.policy(lookup_enabled=True, report_enabled=False, block_enabled=True, block_min_score=90)

    def call(self, fn, method='GET', body=None, role='admin'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', role)
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def sweep(self, *events, at=T + MIN, dev='d1'):
        evs = [e for e in events if e]
        with mock.patch('time.time', return_value=at - MIN):
            self.api.ip_intel_note_evidence(dev, evs, {'sources': [], 'ignored': {}, 'dropped': 0}, at - MIN)
        self.api._LOAD_CACHE.clear()
        ipintel_store.update(self.api, last_sweep=0)
        with mock.patch('time.time', return_value=at):
            self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        return ipintel_store.read(self.api)

    def block_commands(self, dev='d1'):
        return [c for c in (self.api.load(self.api.CMDS_FILE) or {}).get(dev, [])
                if 'rp-ipintel' in (c if isinstance(c, str) else c.get('command', ''))]


class TestTheSweep(_Sweep):
    def test_off_the_ban_is_not_enough_and_the_page_says_why(self):
        st = self.sweep(event())
        self.assertEqual(st.get('blocks') or {}, {})
        self.assertEqual(self.block_commands(), [])
        self.assertEqual(st['attackers'][IP]['devices']['d1']['not_blocked'], 'score 10 is below 90')

    def test_on_a_banned_address_is_blocked_and_the_block_says_who_decided(self):
        self.policy(block_confirmed=True)
        st = self.sweep(event())
        rec = st['blocks']['d1'][IP]
        self.assertEqual((rec['by'], rec['why'], rec['score']), ('auto', 'fail2ban', 10))
        self.assertGreater(rec['until'], rec['at'])
        self.assertEqual(len(self.block_commands()), 1)
        line = ' '.join(str(x) for x in next(a for a in self.audit if a[1] == 'ip_intel_block'))
        self.assertIn('confirmed=fail2ban', line)
        self.assertNotIn('not_blocked', st['attackers'][IP]['devices']['d1'])

    def test_a_new_scanner_with_no_score_at_all_is_blocked_and_nothing_breaks(self):
        """The case the setting is for. The verdict is None here; reading a score from it used to be safe only
        because a block needed a score, and a sweep that raises after it claimed its batch loses the batch."""
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('abuseipdb_api_key'); cfg.pop('sniffcat_api_key')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(block_confirmed=True)
        st = self.sweep(event())
        rec = st['blocks']['d1'][IP]
        self.assertEqual((rec['why'], rec['score']), ('fail2ban', None))
        self.assertEqual(st.get('queue') or [], [], 'the batch was processed, not lost')

    def test_crowdsec_decides_too(self):
        self.policy(block_confirmed=True)
        ev = threat_evidence.normalize_event(
            {'ip': IP, 'first': T - 60, 'last': T - 58, 'src': {'cs': 1}, 'tok': {'cs': {'scen:crowdsecurity/ssh-bf': 1}},
             'ans': 0, 'blk': 0, 'ban': [], 'dec': 1, 'cve': []}, now=T)
        self.assertEqual(threat_evidence.confirmed_by(ev), 'CrowdSec')
        st = self.sweep(ev)
        self.assertEqual(st['blocks']['d1'][IP]['why'], 'CrowdSec')

    def test_refusals_without_a_ban_are_not_a_decision(self):
        self.policy(block_confirmed=True)
        st = self.sweep(event(ban=()))
        self.assertEqual(st.get('blocks') or {}, {})

    def test_a_block_that_the_score_alone_would_make_does_not_claim_the_ban(self):
        self.policy(block_confirmed=True)
        self.scores = {'abuseipdb': 95, 'sniffcat': 10}
        st = self.sweep(event())
        self.assertNotIn('why', st['blocks']['d1'][IP])

    def test_what_protects_an_address_still_does(self):
        self.policy(block_confirmed=True, never_block=[IP])
        st = self.sweep(event())
        self.assertEqual(st.get('blocks') or {}, {})
        self.assertEqual(st['attackers'][IP]['devices']['d1']['not_blocked'], 'on the never-block list')

    def test_a_provider_that_lists_it_as_legitimate_wins(self):
        self.policy(block_confirmed=True)
        base = self.api._ip_intel_http

        def http(req):
            status, body = base(req)
            if 'abuseipdb' in req['url'] and req['method'] == 'GET':
                body['data']['isWhitelisted'] = True
            return status, body
        self.api._ip_intel_http = http
        st = self.sweep(event())
        self.assertEqual(st.get('blocks') or {}, {})

    def test_the_hourly_limit_per_host_still_holds(self):
        self.policy(block_confirmed=True, block_max_per_hour=1)
        st = self.sweep(event('185.220.101.1'), event('185.220.101.2'))
        self.assertEqual(len(st['blocks']['d1']), 1)
        refused = [a for a in st['attackers'].values() if a['devices']['d1'].get('not_blocked')]
        self.assertEqual([a['devices']['d1']['not_blocked'] for a in refused], ['hourly block limit reached for this host'])

    def test_the_page_is_sent_who_decided(self):
        self.policy(block_confirmed=True)
        self.sweep(event())
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(st, 200, d)
        self.assertEqual([(b['ip'], b['why']) for b in d['blocks']], [(IP, 'fail2ban')])


class TestTheEdge(_Lists):
    """The ban that stops a visitor behind Cloudflare is the one at the edge, and it is the reason for the setting."""

    def setUp(self):
        super().setUp()
        api = self.api
        self.scores = {'abuseipdb': 10, 'sniffcat': 10}       # the harness's provider stub reads this; its Cloudflare stays
        cfg = api.load(api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        api.save(api.CONFIG_FILE, cfg)
        self.policy(lookup_enabled=True, report_enabled=False, block_enabled=True, edgelist_abuseipdb=False,
                    edgelist_sniffcat=False)

    # tviweb01's web logs say visitors arrive through Cloudflare: no host rule can match them. The agent sends this with
    # every pass and the server rewrites the host's record from it, so it has to travel with the evidence.
    SOURCES = [{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'proxied': True}]

    def sweep(self):
        api = self.api
        with mock.patch('time.time', return_value=T):
            api.ip_intel_note_evidence('d1', [event()], {'sources': self.SOURCES, 'ignored': {}, 'dropped': 0}, T)
        api._LOAD_CACHE.clear()
        ipintel_store.update(api, last_sweep=0)
        with mock.patch('time.time', return_value=T + MIN):
            api.run_ip_intel_if_due()
        api._LOAD_CACHE.clear()
        return ipintel_store.read(api)

    def test_a_banned_address_behind_a_proxy_is_banned_at_the_edge_and_not_on_the_host(self):
        self.policy(block_confirmed=True)
        st = self.sweep()
        self.assertEqual(st.get('blocks') or {}, {}, 'a rule on the host would match nothing')
        ban = st['edgeban'][IP]
        self.assertEqual(ban['by'], 'auto')
        self.assertGreater(ban['until'], ban['at'])
        self.assertEqual(st['attackers'][IP]['devices']['d1']['not_blocked'], 'web attacks arrive through a proxy')

    def test_off_there_is_no_edge_ban(self):
        st = self.sweep()
        self.assertNotIn(IP, st.get('edgeban') or {})

    def test_the_next_sync_puts_it_in_the_list(self):
        self.policy(block_confirmed=True, edgelist_own=False)
        self.sweep()
        self.tick(at=T + 2 * MIN)
        self.assertIn(IP, set(self.only_list()['items']))

    def test_on_a_multi_tenant_install_a_tenants_host_does_not_write_to_the_list(self):
        self.policy(block_confirmed=True)
        self.api._tenancy_enforced = lambda: True
        st = self.sweep()
        self.assertNotIn(IP, st.get('edgeban') or {})


class TestTheSetting(_Sweep):
    def test_it_is_saved_shown_and_left_alone_by_a_save_that_does_not_name_it(self):
        st, d = self.call(self.api.handle_ip_intel)
        self.assertIs(d['settings']['block_confirmed'], False)
        st, d = self.call(self.api.handle_ip_intel_settings, 'POST', {'block_confirmed': True})
        self.assertEqual(st, 200, d)
        self.assertIs(self.call(self.api.handle_ip_intel)[1]['settings']['block_confirmed'], True)
        self.call(self.api.handle_ip_intel_settings, 'POST', {'block_min_score': 80})
        self.assertIs(self.call(self.api.handle_ip_intel)[1]['settings']['block_confirmed'], True)
        self.call(self.api.handle_ip_intel_settings, 'POST', {'block_confirmed': False})
        self.assertIs(self.call(self.api.handle_ip_intel)[1]['settings']['block_confirmed'], False)

    def test_the_request_model_declares_the_key(self):
        """The model only checks a body and lets a key it does not know through, so a missing field changes no
        behaviour; the list of what the settings request carries is still the one place that says what it carries."""
        import request_models
        self.assertIn('block_confirmed', request_models.IpIntelSettingsRequest.model_fields)

    def test_only_an_administrator_changes_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'block_confirmed': True}, role='viewer')
        self.assertEqual(st, 403)
        self.assertIs(self.call(self.api.handle_ip_intel)[1]['settings']['block_confirmed'], False, 'a refused save changed it')


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestThePage(unittest.TestCase):
    _run = _SettingsPage._run

    def test_the_box_is_in_the_providers_card_with_its_words(self):
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        card = html[html.index('id="ipintel-settings-card"'):html.index('id="ipintel-sensor-card"')]
        self.assertRegex(card, r'<input type="checkbox" id="ipintel-block-confirmed"> Also block addresses that fail2ban, CrowdSec or a honeypot has already banned, whatever their score</label>')
        self.assertIn('It needs automatic blocking on.', card)
        rows = dict_rows()
        for phrase in ('Also block addresses that fail2ban, CrowdSec or a honeypot has already banned, whatever their score',
                       'It needs automatic blocking on. The block lasts as long as any other, and the addresses that are never blocked stay protected.'):
            self.assertTrue(rows.get(phrase) and all(rows[phrase].get(l) for l in ('de', 'fr', 'es', 'zh', 'hi', 'ar')), phrase)

    def test_the_page_shows_the_stored_value_and_sends_what_was_ticked(self):
        got = self._run('''
          _ipiFillSettings({block_confirmed: true}, {});
          const shown = els['ipintel-block-confirmed'].checked;
          els['ipintel-block-confirmed'].checked = false;
          await saveIpIntelSettings();
          const off = sent.body.block_confirmed;
          els['ipintel-block-confirmed'].checked = true;
          await saveIpIntelSettings();
          console.log(JSON.stringify({shown, off, on: sent.body.block_confirmed}));''')
        self.assertEqual(got, {'shown': True, 'off': False, 'on': True})

    def test_the_blocks_table_says_who_decided_and_leaves_a_score_block_alone(self):
        js = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
        import subprocess
        app = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        parts = [re.search(r'^function escHtml\(.*$', app, re.M).group(0), re.search(r'^function escAttr\(.*$', app, re.M).group(0),
                 'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", hidden: false});',
                 'const document = {getElementById: mk};', 'let _ipiData = null;',
                 'function timeAgoHtml(t) { return "<time>" + t + "</time>"; } function _fmtDuration(s) { return Math.round(s) + "s"; }',
                 'const tableCtl = {sortRows(n, rows, k) { rows.forEach(k); return rows; }};',
                 'function _ipiWindow(w, rows) { return rows; } function _ipiRenderMore() {}',
                 'const _IPI_MORE_WORD = {total: "x"};',
                 srcpin.js_function(js, '_ipiPhrase'), srcpin.js_function(js, '_ipiRenderBlocks')]
        script = ('\n'.join(parts) + '\n_ipiData = {blocks: ['
                  '{ip: "1.1.1.1", device_id: "d", name: "web01", score: 10, by: "auto", why: "fail2ban", at: 1, until: 99999999999},'
                  '{ip: "2.2.2.2", device_id: "d", name: "web01", score: 95, by: "auto", at: 1, until: 99999999999},'
                  '{ip: "3.3.3.3", device_id: "d", name: "web01", score: null, by: "alice", at: 1, until: 99999999999},'
                  '{ip: "4.4.4.4", device_id: "d", name: "web01", score: 5, by: "auto", why: "<img src=x onerror=1>", at: 1, until: 99999999999}]};'
                  '_ipiRenderBlocks(); console.log(JSON.stringify(mk("ipintel-blk-tbody").innerHTML));')
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        html = json.loads(out.stdout.strip().splitlines()[-1])
        rows = html.split('</tr>')
        self.assertIn('<span>automatic</span> · <span>fail2ban</span>', rows[0])
        self.assertIn('<span>automatic</span></td>', rows[1])
        self.assertNotIn('·', rows[1])
        self.assertIn('<td>alice</td>', rows[2])
        self.assertNotIn('<img', html)
        self.assertIn('&lt;img', rows[3])


if __name__ == '__main__':
    unittest.main()
