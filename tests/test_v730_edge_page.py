"""The Threat Intel page's edge half (v7.3.0): the feeds' state, what was set
aside and why, the connection test, and the rows that came from the edge.

Same three questions as the host-log half: the page's words match what the server
sends (derived from the server's source, so a new reason on either side cannot
reach the screen as a raw id), every phrase has six languages, and everything the
page prints is escaped, because a provider's error sentence is free text.
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-page-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_HANDLERS = (_ROOT / 'server' / 'cgi-bin' / 'edge_intel_handlers.py').read_text()
_EVIDENCE = (_ROOT / 'server' / 'cgi-bin' / 'edge_evidence.py').read_text()
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
        _const('_IPI_FEED'), _const('_IPI_FEED_STATE'), _const('_IPI_FEED_STATE_CLASS'),
        _const('_IPI_ASIDE'), _const('_IPI_CHECK'), _const('_IPI_CHECK_STATE'),
        _const('_IPI_CLASS'), _const('_IPI_SOURCE'), _const('_IPI_BAN_WORD'),
        'const els = {}; const el = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: ""});',
        'const document = {getElementById: el};',
        'function timeAgo(t) { return t ? "5m ago" : "never"; }',
        'function timeAgoHtml(t) { return t ? "5m ago" : "never"; }',
        'const tableCtl = {sortRows: (name, rows, fn) => rows};',
        'let _ipiData = null;',
        srcpin.js_function(_JS, '_ipiPhrase'), srcpin.js_function(_JS, '_ipiRenderEdge'),
        srcpin.js_function(_JS, '_ipiReason'), srcpin.js_function(_JS, '_ipiStatus'),
        srcpin.js_function(_JS, '_ipiStatusHtml'), srcpin.js_function(_JS, '_ipiNotBlockedReason'),
        srcpin.js_function(_JS, '_ipiEdgeState'),
        srcpin.js_function(_JS, '_ipiEvidenceHtml'), srcpin.js_function(_JS, '_ipiClassName'),
        'const _ipiOpen = new Set();'])
    out = subprocess.run(['node', '-e', prelude + '\n' + script], capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def table(name):
    return node(f'console.log(JSON.stringify({name}));')


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWordsMatchTheServer(unittest.TestCase):
    def test_a_feed_is_a_family_the_server_reads(self):
        self.assertEqual(set(table('_IPI_FEED')), set(te.EDGE_SOURCES))

    def test_every_state_the_server_writes_has_words(self):
        polling = _HANDLERS[:_HANDLERS.index('def handle_ip_intel_edge_test')]
        written = set(re.findall(r"'state': '([a-z_]+)'", polling))
        fail = srcpin.py_function(polling, '_fail')
        self.assertIn("'no_access' if res.get('auth') else 'error'", fail)
        written |= {'no_access', 'error'}
        self.assertGreaterEqual(len(written), 5, written)
        shown = set(table('_IPI_FEED_STATE'))
        self.assertEqual(written - shown, set(), 'a state the page cannot say')
        self.assertEqual(shown - written, {'waiting'}, 'what the page adds for itself')
        self.assertEqual(set(table('_IPI_FEED_STATE_CLASS')), shown)

    def test_every_reason_a_line_is_set_aside_has_words(self):
        # edge_evidence.py is black-formatted, so its quotes are double
        reasons = set(re.findall(r"drop\([\"']([a-z_]+)[\"']", _EVIDENCE))
        self.assertGreaterEqual(len(reasons), 6, reasons)
        self.assertEqual(set(table('_IPI_ASIDE')), reasons)

    def test_every_check_has_words(self):
        checks = set(re.findall(r"checks\['([a-z]+)'\]", _HANDLERS))
        self.assertEqual(set(table('_IPI_CHECK')), checks)
        states = set(re.findall(r"'state': '([a-z_]+)'", _HANDLERS[_HANDLERS.index('def handle_ip_intel_edge_test'):]))
        states |= {'no_access', 'error', 'ok', 'refused'}   # the last two come through _fail()
        self.assertEqual(set(table('_IPI_CHECK_STATE')), states)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestEveryPhraseIsTranslated(unittest.TestCase):
    STATIC_HTML = (
        'Edge sources', 'Edge feeds', "Read Cloudflare's firewall events and the honeypot's log, and use them for reporting",
        'Cloudflare API token (read-only)', 'Account id', 'Firewall events', 'Honeypot Worker log',
        'Count refusals by a rule that also blocks an IP list',
        'Zones (one id per line, blank for all)', 'Worker names (one per line)',
        'Read every (minutes)', 'Test connection', 'Feed', 'State', 'Last read', 'Events read',
        'Counted', 'Set aside',
    )
    HINTS = (
        "RemotePower can read Cloudflare's firewall events and your honeypot Worker's log, and report what they "
        "show the same way it reports what your hosts' logs show. It only reads, with a read-only token, and "
        "nothing in this card blocks anything. Off until you turn it on.",
        "Leave the zones empty to read every zone the token can see. The account id is only needed for the "
        "honeypot's log, which Cloudflare keeps for about three days.",
        'What each feed read the last time, and what was set aside and why. Challenges, country and network '
        'rules, IP access rules and rules that also block an IP list are not evidence of an attack and are '
        'never reported.',
    )

    def test_the_static_labels_and_hints_are_in_the_page_and_translated(self):
        rows = dict_rows()
        for key in self.STATIC_HTML + self.HINTS:
            self.assertIn(key.replace("'", "'"), _HTML, key)
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), key)

    def test_the_server_reason_and_the_confirmer_are_translated(self):
        rows = dict_rows()
        for key in ('seen at the edge only, so there is no host to block it on', 'the edge honeypot', 'Test failed'):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), key)
        self.assertIn("'seen at the edge only, so there is no host to block it on'", (
            _ROOT / 'server' / 'cgi-bin' / 'ip_intel_handlers.py').read_text())

    def test_the_class_phrases_the_edge_adds_are_translated(self):
        rows = dict_rows()
        for cls in ('canary', 'decoy_login', 'ddos'):
            phrase = te.CLASSES[cls]['phrase']
            self.assertTrue(rows.get(phrase) and all(rows[phrase].get(l) for l in _LANGS), phrase)

    def test_the_cards_are_for_the_operator_only(self):
        for cid in ('ipintel-edge-card', 'ipintel-edge-status-card'):
            self.assertRegex(_HTML, r'id="%s" hidden' % cid)
        self.assertIn("document.getElementById('ipintel-edge-card').hidden = !edge", _JS)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatIsPrinted(unittest.TestCase):
    EDGE = {
        'enabled': True, 'token_set': True, 'polled': 1,
        'cf': {'state': 'ok', 'at': 1, 'rows': 12, 'kept': 7,
               'ignored': {'not_an_attack_source': 40, 'list_rule': 9, 'made_up': 3},
               'zones': [{'name': 'example.org'}], 'rules_unreadable': True, 'truncated': True},
        'trap': {'state': 'no_access', 'at': 1, 'error': 'Authentication error'},
    }

    def render(self, edge):
        return node('''_ipiData = {edge: %s};
          _ipiRenderEdge();
          console.log(JSON.stringify({rows: els["ipintel-edge-tbody"].innerHTML,
                                      notes: els["ipintel-edge-notes"].innerHTML}));''' % json.dumps(edge))

    def test_the_feed_table(self):
        out = self.render(self.EDGE)
        rows = out['rows']
        self.assertIn('<span>Cloudflare firewall events</span>', rows)
        self.assertIn('<span>Edge honeypot</span>', rows)
        self.assertIn('<span>Reading</span>', rows)
        self.assertIn('c-green', rows)
        self.assertIn('<span>No permission</span>', rows)
        self.assertIn('Authentication error', rows)
        self.assertIn('<span>country, network and security-level rules</span> ×40', rows)
        self.assertIn('<span>a rule that also blocks an IP list</span> ×9', rows)
        self.assertIn('<span>made_up</span> ×3', rows, 'an unknown reason is shown, not dropped')
        self.assertIn('example.org', rows)
        self.assertIn('Rules could not be read', out['notes'])
        self.assertIn('More events than one read can hold', out['notes'])

    def test_a_refusal_of_the_dataset_is_not_worded_as_a_permission(self):
        refusal = "zone '%s' does not have access to the path." % ('4' * 32)
        out = self.render(dict(self.EDGE, cf={'state': 'refused', 'at': 1, 'error': 'bymanden.dk: ' + refusal,
                                              'zones': [{'name': 'bymanden.dk'}]}))
        self.assertIn('<span>Refused by Cloudflare</span>', out['rows'])
        self.assertNotIn('<span>No permission</span> <', out['rows'].split('Edge honeypot')[0])
        self.assertIn('does not have access to the path', out['rows'])

    def test_a_zone_read_as_single_events_says_so_and_a_grouped_one_does_not(self):
        note = 'Cloudflare refused the grouped view, so the events are read one at a time.'
        for mode, shown in (('events', True), ('mixed', True), ('groups', False), (None, False)):
            cf = dict(self.EDGE['cf'], **({'mode': mode} if mode else {}))
            rows = self.render(dict(self.EDGE, cf=cf))['rows']
            self.assertEqual(('<span>%s</span>' % note) in rows, shown, mode)

    def test_the_note_is_for_a_feed_that_is_reading(self):
        cf = {'state': 'refused', 'at': 1, 'mode': 'events', 'error': 'x'}
        rows = self.render(dict(self.EDGE, cf=cf))['rows']
        self.assertNotIn('read one at a time', rows)

    def test_off_and_not_yet_read(self):
        rows = self.render({'enabled': False, 'cf': {}, 'trap': {}})['rows']
        self.assertEqual(rows.count('<span>Off</span>'), 2)
        rows = self.render({'enabled': True, 'cf': {}, 'trap': {}})['rows']
        self.assertEqual(rows.count('<span>Waiting for the first read</span>'), 2)

    def test_a_provider_sentence_is_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        edge = dict(self.EDGE, trap={'state': 'error', 'at': 1, 'error': evil},
                    cf=dict(self.EDGE['cf'], zones=[{'name': evil}], ignored={evil: 2}))
        out = self.render(edge)
        for part in out.values():
            self.assertNotIn('<img', part)
        self.assertIn('&lt;img', out['rows'])

    def test_the_honeypot_is_named_as_the_one_who_decided(self):
        ev = {'classes': [{'id': 'bad_bot', 'n': 3}], 'sources': [{'id': 'trap', 'n': 3}],
              'confirmed': 'the edge honeypot', 'ans': 0}
        h = node('console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: %s})));' % json.dumps(ev))
        self.assertIn('<span>confirmed by</span> <span>the edge honeypot</span>', h)
        self.assertIn('<span>unwanted web crawling</span>', h)
        ev['confirmed'] = '<b>x</b>'
        h = node('console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: %s})));' % json.dumps(ev))
        self.assertNotIn('<b>x', h)

    EDGE_WHY = 'seen at the edge only, so there is no host to block it on'

    def status(self, devices, blocks=()):
        a = {'ip': '203.0.113.9', 'reported': {'abuseipdb': 1, 'sniffcat': 1}, 'errors': {}, 'devices': devices}
        return node('''_ipiData = {blocks: %s};
          console.log(JSON.stringify({html: _ipiStatusHtml(%s), text: _ipiStatus(%s)}));'''
                    % (json.dumps(list(blocks)), json.dumps(a), json.dumps(a)))

    def test_an_address_seen_only_at_the_edge_says_why_there_is_no_host(self):
        out = self.status([{'device_id': 'edge:cloudflare', 'name': 'Cloudflare edge',
                            'not_blocked': self.EDGE_WHY}])
        self.assertIn('<span>%s</span>' % self.EDGE_WHY, out['html'])
        self.assertIn('not blocked: ' + self.EDGE_WHY, out['text'])

    def test_a_host_that_saw_it_is_never_hidden_by_the_edge_reason(self):
        """The cell showed the first device's reason, so an address seen by the edge and
        by a host read "no host to block it on" while a host existed."""
        for order in (0, 1):
            devs = [{'device_id': 'edge:cloudflare', 'name': 'Cloudflare edge', 'not_blocked': self.EDGE_WHY},
                    {'device_id': 'd1', 'name': 'web01', 'not_blocked': 'web attacks arrive through a proxy'}]
            if order:
                devs.reverse()
            out = self.status(devs)
            self.assertIn('<span>web attacks arrive through a proxy</span>', out['html'], order)
            self.assertNotIn('no host to block it on', out['html'], order)
            self.assertIn('not blocked: web attacks arrive through a proxy', out['text'], order)

    def test_a_block_on_a_host_is_still_the_whole_story(self):
        devs = [{'device_id': 'edge:cloudflare', 'name': 'Cloudflare edge', 'not_blocked': self.EDGE_WHY},
                {'device_id': 'd1', 'name': 'web01', 'not_blocked': ''}]
        out = self.status(devs, blocks=[{'ip': '203.0.113.9', 'device_id': 'd1'}])
        self.assertIn('<span>blocked on</span> 1', out['html'])
        self.assertNotIn('not blocked', out['html'])

    def test_an_address_with_no_reason_at_all_has_no_not_blocked_part(self):
        out = self.status([{'device_id': 'd1', 'name': 'web01', 'not_blocked': ''}])
        self.assertNotIn('not blocked', out['html'])

    def test_an_edge_row_has_no_block_button(self):
        src = srcpin.js_function(_JS, '_ipiRenderAttackers')
        self.assertIn("startsWith('edge:')", src)


if __name__ == '__main__':
    unittest.main()
