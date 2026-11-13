"""The Threat Intel page's Request log: what was sent to AbuseIPDB and SniffCat, and what the hosts' sensors sent (8.0.1).

Is the card there, hidden for anyone the server did not send the log to; does it print what the service said without letting
that text become markup; has every word it prints six languages; and does the demo's seeded log say what the server writes.
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-reqpage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

import ip_intel  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
HAVE_NODE = bool(shutil.which('node'))
TABLES = ('_IPI_REQ_PROV', '_IPI_REQ_OP', '_IPI_REQ_RESULT', '_IPI_REQ_CLASS')


def _const(name):
    m = re.search(r'^const %s = .*?;$' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    return m.group(0)


def table(name):
    return json.loads(subprocess.run(['node', '-e', _const(name) + '\nconsole.log(JSON.stringify(%s));' % name],
                                     capture_output=True, text=True, timeout=30, check=True).stdout)


def node(script):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    parts = [
        esc, *[_const(t) for t in TABLES], _const('_IPI_REQ_EMPTY'),
        'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", hidden: true});',
        'const document = {getElementById: mk};',
        'let _ipiData = null, _ipiAdmin = false;',
        'function timeAgoHtml(t) { return "<time>" + t + "</time>"; }',
        'const tableCtl = {sortRows(name, rows, key) { rows.forEach(key); return rows; }};',
        srcpin.js_function(_JS, '_ipiPhrase'),
        srcpin.js_function(_JS, '_ipiRenderRequests'),
    ]
    out = subprocess.run(['node', '-e', '\n'.join(parts) + '\n' + script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


class TestTheCard(unittest.TestCase):
    def card(self):
        i = _HTML.index('id="ipintel-requests-card"')
        start = _HTML.rindex('<div', 0, i)
        return _HTML[start:_HTML.index('id="ipintel-edgelist-card"', i)]

    def test_it_is_in_the_log_sources_tab_and_hidden_until_the_page_shows_it(self):
        card = self.card()
        tag = re.search(r'<div[^>]*id="ipintel-requests-card"[^>]*>', card).group(0)
        self.assertIn('data-pg-tab="sources"', tag)
        self.assertRegex(tag, r'\shidden[\s>]')

    def test_it_follows_the_page_rules_for_a_card_and_a_table(self):
        card = self.card()
        self.assertIn('<div class="section-title">Request log</div>', card)
        self.assertIn('scrollable-table-wrap audit-scroll', card)
        self.assertNotIn('style=', card)
        self.assertNotIn('onclick', card)
        heads = re.findall(r'<th scope="col" data-col="(\w+)">([^<]+)</th>', card)
        self.assertEqual([c for c, _ in heads], ['at', 'prov', 'op', 'ip', 'status', 'ms', 'note'])
        self.assertIn('id="ipintel-req-thead"', card)
        self.assertIn('id="ipintel-req-tbody"', card)

    def test_the_sort_is_wired_before_the_data_and_the_card_is_drawn_with_the_others(self):
        load = srcpin.js_function(_JS, 'loadIpIntel')
        self.assertIn("tableCtl.wireSortOnly('ipintel-req-thead', 'ipintel-req'", load)
        self.assertLess(load.index("wireSortOnly('ipintel-req-thead'"), load.index("await api('GET'"))
        self.assertIn('_ipiRenderRequests();', load)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatItPrints(unittest.TestCase):
    ROWS = [
        {'at': 1000, 'prov': 'sniffcat', 'op': 'report', 'ip': '185.220.101.10', 'status': 500, 'ms': 231,
         'result': 'server error', 'note': 'Internal server error. Please report this to: support@sniffcat.com'},
        {'at': 900, 'prov': 'abuseipdb', 'op': 'check', 'ip': '185.220.101.10', 'status': 200, 'ms': 120,
         'result': 'ok', 'note': ''},
        {'at': 800, 'prov': 'sniffcat', 'op': 'report', 'ip': '185.220.101.11', 'status': 0, 'ms': 8001,
         'result': 'no answer', 'note': 'unreachable: TimeoutError'},
        {'at': 700, 'prov': 'abuseipdb', 'op': 'blacklist', 'ip': '', 'status': 429, 'ms': 90,
         'result': 'rate limited', 'note': 'Too many'},
    ]

    def test_each_line_says_who_what_which_address_the_answer_and_how_long(self):
        out = node('_ipiData = {requests: %s}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({hidden: mk("ipintel-requests-card").hidden, html: mk("ipintel-req-tbody").innerHTML}));'
                   % json.dumps(self.ROWS))
        self.assertFalse(out['hidden'])
        html = out['html']
        self.assertEqual(html.count('<tr>'), 4)
        for want in ('<td>SniffCat</td>', '<td>AbuseIPDB</td>', '<span>Report</span>', '<span>Lookup</span>',
                     '<span>Blacklist download</span>', '185.220.101.10', '500 <span>Server error</span>',
                     '200 <span>OK</span>', '– <span>No answer</span>', '429 <span>Rate limited</span>',
                     '231 ms', 'Internal server error. Please report this to: support@sniffcat.com',
                     'unreachable: TimeoutError', 'c-red', 'c-green', 'c-amber'):
            self.assertIn(want, html)

    def test_a_line_for_what_a_host_sent_names_the_host_and_has_no_duration(self):
        row = {'at': 700, 'prov': 'web01', 'op': 'received', 'ip': '185.220.101.10', 'status': 200, 'ms': 0, 'result': 'ok',
               'note': 'queued 2 of 2: 185.220.101.10, 185.220.101.11'}
        out = node('_ipiData = {requests: %s}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({html: mk("ipintel-req-tbody").innerHTML}));' % json.dumps([row]))
        html = out['html']
        for want in ('<td>web01</td>', '<span>Sensor report</span>', '185.220.101.10', '200 <span>OK</span>',
                     'queued 2 of 2: 185.220.101.10, 185.220.101.11'):
            self.assertIn(want, html)
        self.assertNotIn(' ms', html, 'a received line took no time to make')
        evil = dict(row, prov='<img src=x onerror=alert(1)>')
        out = node('_ipiData = {requests: %s}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({html: mk("ipintel-req-tbody").innerHTML}));' % json.dumps([evil]))
        self.assertNotIn('<img', out['html'])

    def test_a_services_own_words_never_become_markup(self):
        evil = dict(self.ROWS[0], note='<img src=x onerror=alert(1)>', ip='<b>1</b>', prov='<i>x</i>', result='<u>y</u>')
        out = node('_ipiData = {requests: %s}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({html: mk("ipintel-req-tbody").innerHTML}));' % json.dumps([evil]))
        self.assertNotIn('<img', out['html'])
        self.assertNotIn('<b>1', out['html'])
        self.assertNotIn('<i>x', out['html'])
        self.assertNotIn('<u>y', out['html'])
        self.assertIn('&lt;img', out['html'])

    def test_the_card_stays_hidden_for_anyone_the_server_did_not_send_it_to(self):
        for data in ('{requests: null}', '{}', '{requests: "x"}'):
            out = node('_ipiData = %s; _ipiAdmin = true; mk("ipintel-requests-card").hidden = false;'
                       '_ipiRenderRequests(); console.log(JSON.stringify({hidden: mk("ipintel-requests-card").hidden,'
                       'html: mk("ipintel-req-tbody").innerHTML}));' % data)
            self.assertTrue(out['hidden'], data)
            self.assertEqual(out['html'], '', data)
        out = node('_ipiData = {requests: []}; _ipiAdmin = false; _ipiRenderRequests();'
                   'console.log(JSON.stringify({hidden: mk("ipintel-requests-card").hidden}));')
        self.assertTrue(out['hidden'], 'not an administrator')

    def test_an_empty_log_says_so(self):
        out = node('_ipiData = {requests: []}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({hidden: mk("ipintel-requests-card").hidden, html: mk("ipintel-req-tbody").innerHTML}));')
        self.assertFalse(out['hidden'])
        self.assertIn('Nothing has been logged yet.', out['html'])

    def test_a_word_the_page_does_not_know_is_shown_as_the_server_sent_it(self):
        row = dict(self.ROWS[0], result='HTTP 404', op='something', status=404)
        out = node('_ipiData = {requests: %s}; _ipiAdmin = true; _ipiRenderRequests();'
                   'console.log(JSON.stringify({html: mk("ipintel-req-tbody").innerHTML}));' % json.dumps([row]))
        self.assertIn('404 <span>HTTP 404</span>', out['html'])
        self.assertIn('<span>Other</span>', out['html'])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWords(unittest.TestCase):
    def test_every_word_the_card_prints_has_six_languages(self):
        rows = dict_rows()
        words = set(table('_IPI_REQ_OP').values()) | set(table('_IPI_REQ_RESULT').values())
        words |= {'Request log', 'Time', 'Service or host', 'Request', 'Address', 'Answer', 'Took', 'Note',
                  'The last requests RemotePower sent to AbuseIPDB and SniffCat and what each service answered, and the reports the log '
                  'sensors on your hosts sent to RemotePower. Keys and request bodies are never shown.',
                  re.search(r"_IPI_REQ_EMPTY = '([^']+)'", _JS).group(1),
                  'the service is not answering'}
        self.assertGreaterEqual(len(words), 17)
        for key in sorted(words):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_the_tables_agree_with_what_the_server_can_say(self):
        results = table('_IPI_REQ_RESULT')
        sent = {ip_intel.describe_answer(status, body)[0] for status, body in (
            (0, {}), (200, {}), (200, {'success': False}), (429, {'message': 'once in 15 minutes'}), (429, {}),
            (401, {}), (403, {}), (500, {}), (503, {}))}
        self.assertEqual(sent, set(results), 'the page and the server name different results')
        self.assertEqual(set(table('_IPI_REQ_CLASS')), set(results))
        self.assertEqual(set(table('_IPI_REQ_PROV')), {'abuseipdb', 'sniffcat'})
        self.assertEqual(set(table('_IPI_REQ_OP')), {'check', 'report', 'blacklist', 'received', 'other'})


class TestTheDemo(unittest.TestCase):
    def test_the_seeded_log_is_what_the_server_writes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('rp_seed', _ROOT / 'packaging' / 'seed-demo-data.py')
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        table_doc, _intake = seed._ip_intel_documents()
        rows = table_doc.get('reqlog')
        self.assertGreaterEqual(len(rows), 10, 'the demo shows an empty card')
        for r in rows:
            self.assertEqual(set(r), {'at', 'prov', 'op', 'ip', 'status', 'ms', 'result', 'note'})
            self.assertIn(r['prov'], ('abuseipdb', 'sniffcat'))
            self.assertIn(r['op'], ('check', 'report', 'blacklist'))
            self.assertEqual(ip_intel.describe_answer(r['status'], {'message': r['note']})[0], r['result'], r)
        self.assertEqual([r['at'] for r in rows], sorted(r['at'] for r in rows), 'the store keeps newest last')
        self.assertTrue({'ok', 'server error', 'no answer', 'already reported', 'rate limited'} <= {r['result'] for r in rows})

    def test_the_seeded_passes_of_the_hosts_are_what_the_server_writes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('rp_seed2', _ROOT / 'packaging' / 'seed-demo-data.py')
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        _table, intake = seed._ip_intel_documents()
        log = intake.get('log')
        self.assertGreaterEqual(len(log), 4, 'the demo shows no line for a host')
        for e in log:
            self.assertEqual(set(e), {'at', 'device_id', 'n', 'queued', 'throttled', 'ignored', 'dropped', 'ips'})
            self.assertLessEqual(len(e['ips']), 5)
        self.assertEqual([e['at'] for e in log], sorted(e['at'] for e in log), 'the intake keeps newest last')
        self.assertTrue(any(e['throttled'] for e in log) and any(e['ignored'] for e in log), 'the demo shows more than the plain case')


if __name__ == '__main__':
    unittest.main()
