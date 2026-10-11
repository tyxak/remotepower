"""The Threat intel page's ban by hand (v7.3.0): the cell, the buttons and the dialog.

Same questions as the other halves of this page. Do the words match what the server
sends, has every phrase six languages, is everything printed from the server escaped,
and do the controls do what they say: the dialog offers the edge only when the
operator has it on, defaults the hosts to the ones that saw the address, sends
exactly what the endpoint reads, and an unban lifts the edge ban and the host
blocks together.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-banpage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
HAVE_NODE = bool(shutil.which('node'))


def _const(name):
    m = re.search(r'^const %s = \{.*?^\};' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    return m.group(0)


def node(script, timeout=30):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
    prelude = '\n'.join([
        esc, esca,
        _const('_IPI_BAN_WORD'), _const('_IPI_BAN_DIALOG'), _const('_IPI_LIST_DIALOG'),
        _const('_IPI_LIST_WORD'), _const('_IPI_LIST_SRC'),
        'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: "", checked: false,'
        ' disabled: false, hidden: false, options: []});',
        'const document = {getElementById: mk, querySelector: () => null};',
        'function timeAgo(t) { return t ? "5m ago" : "never"; }',
        'let _ipiData = null; const sent = []; const asked = []; const toasts = []; const opened = []; let answer = true; '
        'let reply = {ok: true}; let loads = 0;',
        'async function api(m, p, body) { sent.push({m, p, body}); return reply; }',
        'async function uiConfirm(o) { asked.push(o); return answer; }',
        'function toast(t, k) { toasts.push([t, k]); } function loadIpIntel() { loads++; }',
        'function openModal(id) { opened.push(id); } function closeModal(id) { opened.push("close:" + id); }',
        srcpin.js_function(_JS, '_ipiPhrase'), srcpin.js_function(_JS, '_ipiListWhy'),
        srcpin.js_function(_JS, '_ipiNotBlockedReason'), srcpin.js_function(_JS, '_ipiEdgeState'),
        srcpin.js_function(_JS, '_ipiReason'), srcpin.js_function(_JS, '_ipiStatus'),
        srcpin.js_function(_JS, '_ipiStatusHtml'),
        'let _ipiBanIp = "";',
        srcpin.js_function(_JS, 'openIpIntelBan'), srcpin.js_function(_JS, 'closeIpIntelBan'),
        srcpin.js_function(_JS, '_ipiBanResultHtml'),
        'async ' + srcpin.js_function(_JS, 'applyIpIntelBan'),
        'async ' + srcpin.js_function(_JS, 'unbanIpIntel')])
    out = subprocess.run(['node', '-e', prelude + '\n(async () => {' + script + '})()'],
                         capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def table(name):
    return node(f'console.log(JSON.stringify({name}));')


EDGE_ON = {'enabled': True, 'token_set': True, 'last': {}, 'preview': {}}
HOSTS = [{'device_id': 'd1', 'name': 'web01', 'not_blocked': ''},
         {'device_id': 'd2', 'name': 'web02', 'not_blocked': ''}]
EDGE = [{'device_id': 'edge:cloudflare', 'name': 'Cloudflare edge',
         'not_blocked': 'seen at the edge only, so there is no host to block it on'}]


def page(attackers, edge_list=EDGE_ON, **extra):
    return dict({'attackers': attackers, 'blocks': [], 'settings': {'block_ttl_hours': 24}, 'edge_list': edge_list,
                 'ban_hosts': 14}, **extra)


def attacker(ip='203.0.113.9', devices=EDGE, **kw):
    return dict({'ip': ip, 'reported': {}, 'errors': {}, 'devices': devices, 'in_list': None, 'edge_ban': None}, **kw)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWords(unittest.TestCase):
    def test_every_word_is_used_and_every_use_is_in_the_table(self):
        words = set(table('_IPI_BAN_WORD'))
        used = set(re.findall(r'\bB\.([a-z_]+)', _JS)) | set(re.findall(r'_IPI_BAN_WORD\.([a-z_]+)', _JS))
        used |= set(re.findall(r"_IPI_BAN_WORD\[\{[^}]*\}\[", _JS) and ['in_list', 'edge_ban', 'edge_wait'])
        self.assertEqual(used - words, set(), 'a word the page prints that is not in the table')
        self.assertEqual(words - used, set(), 'a word nobody prints')

    def test_every_phrase_is_translated(self):
        rows = dict_rows()
        phrases = set(table('_IPI_BAN_WORD').values())
        for d in table('_IPI_BAN_DIALOG').values():
            phrases |= set(d.values())
        phrases |= {'Ban', 'Unban', 'Ban an address', 'At the edge: add it to the Cloudflare list',
                    'On hosts: add a firewall rule', 'Which hosts', 'The hosts that saw it', 'Every Linux host',
                    'Ban for', '1 hour', '24 hours', '7 days', '30 days', '90 days', 'Cancel'}
        self.assertGreaterEqual(len(phrases), 30, len(phrases))
        for key in sorted(phrases):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_the_static_dialog_text_is_in_the_page(self):
        modal = _HTML[_HTML.index('id="ipintel-ban-modal"'):]
        modal = modal[:modal.index('<!-- v6.2.3: Docker cleanup')]
        for text in ('Ban an address', 'At the edge: add it to the Cloudflare list', 'On hosts: add a firewall rule',
                     'Which hosts', 'The hosts that saw it', 'Every Linux host', 'Ban for', '1 hour', '24 hours',
                     '7 days', '30 days', '90 days', 'Cancel', '>Ban<'):
            self.assertIn(text, modal, text)
        hint = ("Traffic that reaches your sites through Cloudflare arrives from Cloudflare's addresses, so a rule on a "
                "host only stops connections that reach it directly, such as SSH, mail or the origin's own address. "
                "The edge ban is what stops proxied visitors.")
        self.assertIn(hint, modal)
        self.assertTrue(dict_rows().get(hint) and all(dict_rows()[hint].get(l) for l in _LANGS))

    def test_the_dialog_sends_what_the_endpoint_reads(self):
        from request_models import IpIntelBanRequest
        fields = set(IpIntelBanRequest.model_fields)
        sent = set(re.findall(r"body\.(\w+) = ", _JS[_JS.index('async function applyIpIntelBan'):]))
        sent |= {'ip', 'hours'}
        self.assertEqual(sent - fields, set(), 'the page sends a field the server does not read')
        self.assertTrue({'edge', 'hosts'} <= sent)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheCell(unittest.TestCase):
    def cell(self, a, edge_list=EDGE_ON, blocks=()):
        d = page([a], edge_list, blocks=list(blocks))
        return node('''_ipiData = %s;
          console.log(JSON.stringify({html: _ipiStatusHtml(%s), text: _ipiStatus(%s)}));'''
                    % (json.dumps(d), json.dumps(a), json.dumps(a)))

    def test_an_address_the_list_holds_says_so_and_not_that_it_is_unblocked(self):
        out = self.cell(attacker(in_list=1790000000))
        self.assertIn('<span>in the edge blocklist</span>', out['html'])
        self.assertNotIn('not blocked', out['html'], 'the edge is where it is blocked')
        self.assertIn('in the edge blocklist', out['text'])

    def test_a_ban_by_hand_says_it_was_banned(self):
        out = self.cell(attacker(in_list=1, edge_ban={'until': 9}))
        self.assertIn('<span>banned at the edge</span>', out['html'])
        self.assertNotIn('in the edge blocklist', out['html'], 'one phrase, not two')

    def test_a_ban_the_list_does_not_hold_yet_says_it_is_waiting(self):
        out = self.cell(attacker(in_list=None, edge_ban={'until': 9}))
        self.assertIn('<span>edge ban waiting for the next sync</span>', out['html'])

    def test_a_stamp_is_ignored_once_the_blocklist_is_off(self):
        out = self.cell(attacker(in_list=1), edge_list={'enabled': False, 'token_set': True})
        self.assertNotIn('in the edge blocklist', out['html'])
        self.assertIn('no host to block it on', out['html'], 'back to the plain reason')
        out = self.cell(attacker(in_list=1), edge_list=None)
        self.assertNotIn('in the edge blocklist', out['html'])

    def test_a_hosts_reason_still_shows_next_to_the_marker(self):
        devs = EDGE + [{'device_id': 'd1', 'name': 'web01', 'not_blocked': 'web attacks arrive through a proxy'}]
        out = self.cell(attacker(devices=devs, in_list=1))
        self.assertIn('<span>in the edge blocklist</span>', out['html'])
        self.assertIn('<span>web attacks arrive through a proxy</span>', out['html'])
        self.assertNotIn('no host to block it on', out['html'])

    def test_a_block_on_a_host_still_wins_the_wording(self):
        out = self.cell(attacker(devices=HOSTS, in_list=1), blocks=[{'ip': '203.0.113.9', 'device_id': 'd1'}])
        self.assertIn('<span>blocked on</span> 1', out['html'])
        self.assertNotIn('not blocked', out['html'])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheRowAndTheDialog(unittest.TestCase):
    def render_row(self, a, blocks=()):
        src = srcpin.js_function(_JS, '_ipiRenderAttackers')
        self.assertIn('data-ipi-ban', src)
        self.assertIn('data-ipi-unban', src)
        return src

    def test_the_wiring_opens_the_dialog_and_lifts_by_address(self):
        wire = srcpin.js_function(_JS, '_ipiWire')
        self.assertIn("button[data-ipi-ban]", wire)
        self.assertIn('openIpIntelBan(ban.dataset.ipiBan)', wire)
        self.assertIn("button[data-ipi-unban]", wire)
        self.assertIn('unbanIpIntel(unban.dataset.ipiUnban)', wire)

    def test_an_unban_button_only_where_something_can_be_lifted(self):
        src = srcpin.js_function(_JS, '_ipiRenderAttackers')
        self.assertIn("const liftable = a.edge_ban || (_ipiData.blocks || []).some(b => b.ip === a.ip);", src)
        self.assertIn("liftable\n      ? `<button", src)

    def open(self, a, edge_list=EDGE_ON, **extra):
        d = page([a], edge_list, **extra)
        return node('''_ipiData = %s;
          const sel = {value: '', options: [{value: '1'}, {value: '24'}, {value: '168'}],
                       querySelector: () => seenOpt};
          const seenOpt = {disabled: false};
          els['ipintel-ban-which'] = sel; els['ipintel-ban-hours'] = {value: '', options: sel.options};
          openIpIntelBan(%s);
          console.log(JSON.stringify({edge: els['ipintel-ban-edge'], note: els['ipintel-ban-edge-note'].innerHTML,
            hosts: els['ipintel-ban-hosts'].checked, which: sel.value, seenDisabled: seenOpt.disabled,
            counts: els['ipintel-ban-counts'].innerHTML, hours: els['ipintel-ban-hours'].value,
            ip: els['ipintel-ban-ip'].textContent, opened}));''' % (json.dumps(d), json.dumps(a['ip'])))

    def test_the_operator_with_the_list_on_gets_the_edge_ticked(self):
        r = self.open(attacker(devices=HOSTS))
        self.assertTrue(r['edge']['checked'])
        self.assertFalse(r['edge']['disabled'])
        self.assertEqual(r['note'], '')
        self.assertEqual(r['opened'], ['ipintel-ban-modal'])
        self.assertEqual(r['ip'], '203.0.113.9')

    def test_hosts_default_to_the_ones_that_saw_it(self):
        r = self.open(attacker(devices=HOSTS))
        self.assertTrue(r['hosts'])
        self.assertEqual(r['which'], 'seen')
        self.assertFalse(r['seenDisabled'])
        self.assertIn('<span>Hosts that saw it</span>: 2', r['counts'])
        self.assertIn('<span>Linux hosts in all</span>: 14', r['counts'])

    def test_an_edge_only_address_offers_every_host_but_does_not_tick_it(self):
        r = self.open(attacker(devices=EDGE))
        self.assertFalse(r['hosts'], 'a rule on every host is a deliberate step')
        self.assertEqual(r['which'], 'all')
        self.assertTrue(r['seenDisabled'])
        self.assertTrue(r['edge']['checked'])

    def test_with_the_list_off_the_edge_is_unavailable_and_says_why(self):
        r = self.open(attacker(devices=HOSTS), edge_list={'enabled': False, 'token_set': False})
        self.assertTrue(r['edge']['disabled'])
        self.assertFalse(r['edge']['checked'])
        self.assertIn('Turn on the Edge blocklist', r['note'])

    def test_a_caller_who_is_not_the_operator_is_told_so(self):
        r = self.open(attacker(devices=HOSTS), edge_list=None)
        self.assertTrue(r['edge']['disabled'])
        self.assertIn('Only the platform operator', r['note'])

    def test_the_duration_follows_the_setting_when_it_is_offered(self):
        d = page([attacker(devices=HOSTS)], settings={'block_ttl_hours': 168})
        r = node('''_ipiData = %s;
          const sel = {value: '', options: [{value: '24'}, {value: '168'}], querySelector: () => ({})};
          els['ipintel-ban-which'] = sel; els['ipintel-ban-hours'] = {value: '', options: sel.options};
          openIpIntelBan('203.0.113.9');
          console.log(JSON.stringify(els['ipintel-ban-hours'].value));''' % json.dumps(d))
        self.assertEqual(r, '168')

    def apply(self, ticks, reply, ip='203.0.113.9'):
        return node('''_ipiData = %s; _ipiBanIp = %s; reply = %s;
          els['ipintel-ban-edge'] = {checked: %s, disabled: %s};
          els['ipintel-ban-hosts'] = {checked: %s};
          els['ipintel-ban-which'] = {value: %s}; els['ipintel-ban-hours'] = {value: '168'};
          await applyIpIntelBan();
          console.log(JSON.stringify({sent, result: els['ipintel-ban-result'], loads}));'''
                    % (json.dumps(page([attacker()])), json.dumps(ip), json.dumps(reply),
                       json.dumps(ticks.get('edge', False)), json.dumps(ticks.get('edge_off', False)),
                       json.dumps(ticks.get('hosts', False)), json.dumps(ticks.get('which', 'seen'))))

    def test_it_sends_exactly_what_was_chosen(self):
        r = self.apply({'edge': True, 'hosts': True, 'which': 'all'}, {'ok': True, 'edge': {'state': 'ok'},
                                                                     'hosts': {'queued': 14, 'approval': 0}})
        self.assertEqual(r['sent'], [{'m': 'POST', 'p': '/ip-intel/ban',
                                      'body': {'ip': '203.0.113.9', 'hours': 168, 'edge': True, 'hosts': 'all'}}])
        self.assertEqual(r['loads'], 1, 'the table behind the dialog is refreshed')
        r = self.apply({'edge': True}, {'ok': True, 'edge': {'state': 'ok'}})
        self.assertNotIn('hosts', r['sent'][0]['body'])
        r = self.apply({'hosts': True, 'which': 'seen'}, {'ok': True, 'hosts': {'queued': 1}})
        self.assertNotIn('edge', r['sent'][0]['body'])

    def test_an_edge_box_that_is_disabled_is_not_sent(self):
        r = self.apply({'edge': True, 'edge_off': True, 'hosts': True}, {'ok': True, 'hosts': {'queued': 1}})
        self.assertNotIn('edge', r['sent'][0]['body'])

    def test_choosing_nothing_sends_nothing(self):
        r = self.apply({}, {'ok': True})
        self.assertEqual(r['sent'], [])
        self.assertIn('<span>Choose at least one place.</span>', r['result']['innerHTML'])

    def test_the_result_says_what_each_half_did(self):
        r = self.apply({'edge': True, 'hosts': True},
                       {'ok': True, 'edge': {'state': 'ok', 'why': ''},
                        'hosts': {'queued': 2, 'approval': 1, 'extended': 1, 'skipped': 3, 'failed': []}})
        h = r['result']['innerHTML']
        self.assertIn('<span>At the edge:</span> <span class="c-green"><span>it is in the list</span></span>', h)
        self.assertIn('2 <span>queued</span> · 1 <span>waiting for approval</span> · '
                      '1 <span>already blocked, time extended</span> · 3 <span>skipped: not a Linux agent you can reach</span>', h)

    def test_a_held_sync_gives_its_reason_in_the_words_of_the_card(self):
        r = self.apply({'edge': True}, {'ok': True, 'edge': {'state': 'held', 'why': 'The list would shrink by more than half.'}})
        self.assertIn('<span class="c-amber"><span>The list would shrink by more than half.</span></span>',
                      r['result']['innerHTML'])
        r = self.apply({'edge': True}, {'ok': True, 'edge': {'state': 'needs_adopt', 'why': 'x'}})
        self.assertIn('<span>it goes in once the list has been taken over</span>', r['result']['innerHTML'])
        r = self.apply({'edge': True}, {'ok': True, 'edge': {'state': 'waiting', 'why': ''}})
        self.assertIn('<span>it goes in the list at the next sync</span>', r['result']['innerHTML'])

    def test_a_host_that_refused_is_named_and_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        r = self.apply({'hosts': True}, {'ok': True, 'hosts': {
            'queued': 0, 'failed': [{'device_id': 'd2', 'name': evil, 'error': evil}]}})
        h = r['result']['innerHTML']
        self.assertNotIn('<img', h)
        self.assertEqual(h.count('&lt;img'), 2)

    def test_an_error_answer_is_shown_as_text_and_not_thrown(self):
        r = self.apply({'edge': True}, {'error': 'The Edge blocklist is off. <b>x</b>'})
        self.assertEqual(r['result']['textContent'], 'The Edge blocklist is off. <b>x</b>')
        self.assertEqual(r['loads'], 0)

    def unban(self, edge_list, answer=True):
        return node('''_ipiData = %s; answer = %s; reply = {ok: true};
          await unbanIpIntel('203.0.113.9');
          console.log(JSON.stringify({sent, asked, toasts, loads}));'''
                    % (json.dumps(page([attacker()], edge_list)), json.dumps(answer)))

    def test_an_unban_asks_and_lifts_the_edge_and_every_host(self):
        r = self.unban(EDGE_ON)
        self.assertEqual(len(r['asked']), 1)
        self.assertTrue(r['asked'][0]['danger'])
        self.assertEqual(r['sent'], [{'m': 'POST', 'p': '/ip-intel/unban',
                                      'body': {'ip': '203.0.113.9', 'hosts': 'all', 'edge': True}}])
        self.assertEqual(r['toasts'], [['Unbanned', 'success']])
        self.assertEqual(r['loads'], 1)

    def test_a_caller_without_the_edge_asks_for_the_hosts_only(self):
        r = self.unban(None)
        self.assertNotIn('edge', r['sent'][0]['body'])

    def test_declining_lifts_nothing(self):
        r = self.unban(EDGE_ON, answer=False)
        self.assertEqual(r['sent'], [])


class TestTheMarkup(unittest.TestCase):
    def modal(self):
        start = _HTML.index('id="ipintel-ban-modal"')
        start = _HTML.rindex('<div', 0, start)
        return _HTML[start:_HTML.index('<!-- v6.2.3: Docker cleanup')]

    def test_it_sits_at_body_level_with_the_other_dialogs(self):
        self.assertGreater(_HTML.index('id="ipintel-ban-modal"'), _HTML.index('</div><!-- /app -->'))

    def test_it_is_a_named_dialog_with_labelled_controls(self):
        m = self.modal()
        self.assertIn('role="dialog" aria-modal="true" aria-labelledby="ipintel-ban-title"', m)
        self.assertIn('id="ipintel-ban-title"', m)
        for cid in ('ipintel-ban-which', 'ipintel-ban-hours'):
            self.assertRegex(m, r'<label[^>]*for="%s"' % cid)
        for cid in ('ipintel-ban-edge', 'ipintel-ban-hosts'):
            self.assertRegex(m, r'<label[^>]*><input type="checkbox" id="%s">' % cid)
        self.assertNotRegex(m, r'\sstyle="')
        self.assertNotRegex(m, r'\son[a-z]+="')

    def test_its_buttons_run_functions_that_exist(self):
        for name in re.findall(r'data-action="([A-Za-z]+)"', self.modal()):
            self.assertRegex(_JS, r'(?:async )?function %s\(' % name, name)

    def test_the_result_area_is_a_capped_live_region(self):
        self.assertIn('id="ipintel-ban-result" class="mt-8 scroll-cap" role="status" aria-live="polite"', self.modal())

    def test_the_duration_options_are_the_ones_the_server_accepts(self):
        hours = [int(x) for x in re.findall(r'<option value="(\d+)">', self.modal().split('id="ipintel-ban-hours"')[1])]
        self.assertEqual(hours, [1, 24, 168, 720, 2160])
        import edge_blocklist_handlers as h
        self.assertEqual(max(hours), h.BAN_HOURS_MAX)

    def test_the_row_buttons_have_a_style_that_wraps(self):
        css = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        self.assertRegex(css, r'\.ipi-actions \{[^}]*flex-wrap: wrap')


if __name__ == '__main__':
    unittest.main()
