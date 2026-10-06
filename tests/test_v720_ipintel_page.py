"""The Threat intel page shows what the logs said, and says when it cannot read them.

Three things are checked. The page's words match what the server sends (the class
ids, the source kinds, the states, the formats) so a new one added on either side
cannot reach the screen as a raw id; every phrase the page can show has a
translation, with the population DERIVED from the script so it cannot go stale; and
what the page prints is escaped, because the evidence includes strings that came
from attackers' requests and from log files.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from html.parser import HTMLParser
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v720-page-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
import threat_evidence as te  # noqa: E402
import threat_sensor_handlers as tsh  # noqa: E402
from test_ip_intel import ATTACKER, _Case  # noqa: E402
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
    fns = ['_ipiPhrase', '_ipiReason', '_ipiClassName', '_ipiEvidenceText', '_ipiEvidenceWeight',
           '_ipiEvidenceHtml', '_ipiProviderName', '_ipiDetailHtml', '_ipiRenderSources']
    prelude = '\n'.join([
        esc, esca, 'const _ipiOpen = new Set();',
        _const('_IPI_CLASS'), _const('_IPI_SOURCE'), _const('_IPI_STATE'), _const('_IPI_STATE_CLASS'),
        _const('_IPI_FMT'),
        'const els = {}; const el = id => (els[id] = els[id] || {innerHTML: ""});',
        'const document = {getElementById: el};',
        'const tableCtl = {sortRows: (name, rows, fn) => rows};',
        'function timeAgo(t) { return t ? "5m ago" : "never"; }',
        'let _ipiData = {sensors: []};',
        *[srcpin.js_function(_JS, f) for f in fns]])
    out = subprocess.run(['node', '-e', prelude + '\n' + script], capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


# ── the page and the server agree on the words ─────────────────────────────────

@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestVocabularyMatchesTheServer(unittest.TestCase):
    def table(self, name):
        return node(f'console.log(JSON.stringify({name}));')

    def test_classes(self):
        self.assertEqual(self.table('_IPI_CLASS'), {k: v['phrase'] for k, v in te.CLASSES.items()})

    def test_sources(self):
        self.assertEqual(set(self.table('_IPI_SOURCE')), set(te.SOURCES))
        self.assertEqual(set(self.table('_IPI_SOURCE')), set(tsh._SOURCE_KINDS))

    def test_states_and_their_colours(self):
        self.assertEqual(set(self.table('_IPI_STATE')), set(tsh._SOURCE_STATES))
        self.assertEqual(set(self.table('_IPI_STATE_CLASS')), set(tsh._SOURCE_STATES))

    def test_formats(self):
        shown = set(self.table('_IPI_FMT'))
        self.assertEqual(shown, set(tsh._SOURCE_FMTS) - {'nginx', 'apache'},
                         'nginx and apache name the error-log reader, shown as the format only when it is a layout')


# ── every phrase the page can show is translated ───────────────────────────────

@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestEveryPhraseIsTranslated(unittest.TestCase):
    STATIC = (
        'No host has reported its logs yet. Agents pick the setting up on their next heartbeat.',
        'The log sensor is off. An administrator can turn it on under Log sensor.',
    )

    def population(self):
        words = set()
        for name in ('_IPI_CLASS', '_IPI_SOURCE', '_IPI_STATE', '_IPI_FMT'):
            words |= set(node(f'console.log(JSON.stringify(Object.values({name})));'))
        for m in re.finditer(r"_ipiPhrase\('((?:[^'\\]|\\.)+)'\)|_ipiPhrase\(\"((?:[^\"\\]|\\.)+)\"\)", _JS):
            words.add((m.group(1) or m.group(2)).replace("\\'", "'"))
        for m in re.finditer(r"_ipiPhrase\(open \? '([^']+)' : '([^']+)'\)", _JS):
            words |= {m.group(1), m.group(2)}
        words |= set(self.STATIC)
        return words

    def test_the_population_is_derived_and_not_trivial(self):
        words = self.population()
        self.assertGreater(len(words), 45, sorted(words))
        for must in ('SQL injection', 'Web server log', 'No permission', 'answered', 'Details', 'attempts so far',
                     "From the server's config"):
            self.assertIn(must, words)
        for s in self.STATIC:
            self.assertIn(s, _JS, 'a listed string is no longer in the script')

    def test_every_phrase_has_all_six_languages(self):
        rows = dict_rows()
        missing = [w for w in sorted(self.population())
                   if not (rows.get(w) and all(rows[w].get(l) for l in _LANGS))]
        self.assertEqual(missing, [])

    def test_the_new_static_labels_have_them_too(self):
        rows = dict_rows()
        for key in ('Evidence', 'Log sources', 'Log sensor', 'Log', 'Lines read', 'Understood', 'Hostile', 'Format',
                    'Source', 'Host', 'State', 'Last report', 'Read web server, WAF, fail2ban and CrowdSec logs on Linux hosts',
                    'Extra log files (one path per line, under /var/log)'):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), key)


# ── what is printed ────────────────────────────────────────────────────────────

EVIDENCE = {
    'classes': [{'id': 'sqli', 'n': 30}, {'id': 'traversal', 'n': 11}, {'id': 'probe', 'n': 4}, {'id': 'rce', 'n': 1}],
    'sources': [{'id': 'web', 'n': 41}, {'id': 'waf', 'n': 12}, {'id': 'f2b', 'n': 0}],
    'rules': ['942100', '942190'], 'cves': ['CVE-2021-44228'], 'jails': ['nginx-blocked'],
    'ans': 3, 'blk': 31, 'confirmed': 'fail2ban', 'first': 1, 'last': 2, 'sent': False,
}


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatIsPrinted(unittest.TestCase):
    def test_the_evidence_cell(self):
        h = node('console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: %s})));' % json.dumps(EVIDENCE))
        self.assertEqual(h.count('class="ipi-chip"'), 3, 'three classes, the strongest first')
        self.assertIn('<span>SQL injection</span>', h)
        self.assertIn('<span>path traversal</span>', h)
        self.assertNotIn('remote code execution', h, 'only the top three')
        self.assertIn('<span>confirmed by</span> fail2ban', h)
        self.assertIn('<span>answered</span> 3', h)
        self.assertIn('data-ipi-toggle="1.2.3.4"', h)
        self.assertIn('<span>Details</span>', h)
        self.assertIn('aria-expanded="false"', h)

    def test_no_evidence_is_a_dash_not_a_blank(self):
        self.assertIn('—', node('console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: null})));'))

    def test_the_toggle_says_what_it_will_do(self):
        h = node('_ipiOpen.add("1.2.3.4"); console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: %s})));'
                 % json.dumps(EVIDENCE))
        self.assertIn('<span>Hide details</span>', h)
        self.assertIn('aria-expanded="true"', h)

    def test_a_class_the_page_does_not_know_yet_is_shown_not_dropped(self):
        h = node('console.log(JSON.stringify(_ipiEvidenceHtml({ip: "1.2.3.4", evidence: {classes: [{id: "new_thing", n: 2}]}})));')
        self.assertIn('new_thing', h)

    def test_the_detail_row(self):
        report_log = [
            {'prov': 'abuseipdb', 'at': 1, 'cats': [16, 21], 'ok': True,
             'comment': 'SQL injection: 41 attempts within 10 minutes, seen by web server log (reported by RemotePower)'},
            {'prov': 'sniffcat', 'at': 1, 'cats': [12, 21], 'error': 'rate limited or already reported', 'comment': 'x'}]
        h = node('console.log(JSON.stringify(_ipiDetailHtml({ip: "1.2.3.4", evidence: %s, report_log: %s})));'
                 % (json.dumps(EVIDENCE), json.dumps(report_log)))
        self.assertIn('<dt><span>Seen in</span></dt>', h)
        self.assertIn('<span>Web server log</span> ×41', h)
        self.assertIn('<span>WAF audit log</span> ×12', h)
        self.assertIn('<span>refused</span> 31', h)
        self.assertIn('<code>942100</code>', h)
        self.assertIn('<code>CVE-2021-44228</code>', h)
        self.assertIn('<code>nginx-blocked</code>', h)
        self.assertIn('<span>reported to</span> AbuseIPDB', h)
        self.assertIn('<span>categories</span> 16, 21', h)
        self.assertIn('<code class="ipi-comment">SQL injection: 41 attempts', h)
        self.assertIn('<span>reported to</span> SniffCat', h)
        self.assertIn('c-red', h)
        self.assertIn('<span>rate limited or already reported</span>', h)

    def test_everything_dynamic_is_escaped(self):
        hostile = '<img src=x onerror=alert(1)>'
        ev = dict(EVIDENCE, rules=[hostile], cves=[hostile], jails=[hostile], confirmed=hostile,
                  classes=[{'id': hostile, 'n': 1}], sources=[{'id': hostile, 'n': 1}])
        log = [{'prov': hostile, 'at': 1, 'cats': [hostile], 'comment': hostile}]
        out = node('''console.log(JSON.stringify([
          _ipiEvidenceHtml({ip: %s, evidence: %s}),
          _ipiDetailHtml({ip: "1.2.3.4", evidence: %s, report_log: %s}),
          _ipiEvidenceText({evidence: %s})]));''' % (json.dumps(hostile), json.dumps(ev), json.dumps(ev),
                                                      json.dumps(log), json.dumps(ev)))
        for h in out[:2]:
            self.assertNotIn('<img', h)
            self.assertNotIn('onerror=alert', h.replace('onerror=alert(1)&gt;', ''))
            self.assertIn('&lt;img', h)

    def test_the_reason_for_an_address_not_reported_yet(self):
        h = node('console.log(JSON.stringify(_ipiReason("not reported: 4 of 10 attempts so far")));')
        self.assertEqual(h, '<span>not reported:</span> 4 / 10 <span>attempts so far</span>')
        h = node('console.log(JSON.stringify(_ipiReason("not reported: nothing recognisable in the logs")));')
        self.assertEqual(h, '<span>not reported:</span> <span>nothing recognisable in the logs</span>')

    def test_the_log_sources_table(self):
        _ = EVIDENCE
        data = {'sensor_enabled': True, 'sensors': [
            {'name': 'web<01>', 'device_id': 'd1', 'at': 5, 'ignored': {'cloudflare': 412}, 'throttled': 7, 'sources': [
                {'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 400, 'parsed': 399,
                 'events': 12, 'fmt': 'custom'},
                {'kind': 'waf', 'path': '/var/log/modsec_audit.log', 'state': 'denied', 'lines': 0, 'parsed': 0, 'events': 0},
                {'kind': 'web', 'path': '/var/log/nginx/rl.log', 'state': 'unparsed', 'lines': 900, 'parsed': 0,
                 'events': 0, 'fmt': 'generic'},
                {'kind': 'web', 'path': '/var/log/x.log', 'state': '<b>odd</b>', 'lines': 1, 'parsed': 1, 'events': 0}]}]}
        out = node('''_ipiData = %s; _ipiRenderSources();
          console.log(JSON.stringify({body: els['ipintel-src-tbody'].innerHTML, notes: els['ipintel-src-notes'].innerHTML}));''' % json.dumps(data))
        body, notes = out['body'], out['notes']
        self.assertEqual(body.count('<tr>'), 4)
        self.assertIn('web&lt;01&gt;', body)
        self.assertIn('<span>Web server log</span>', body)
        self.assertIn('<span>From the server&#39;s config</span>', body, 'escaped; the browser decodes it for the dictionary')
        self.assertIn('<td class="c-green"><span>Reading</span></td>', body)
        self.assertIn('<td class="c-red"><span>No permission</span></td>', body)
        self.assertIn('<td class="c-amber"><span>Not understood</span></td>', body)
        self.assertNotIn('<b>odd</b>', body)
        self.assertIn('/var/log/nginx/access.log', body)
        self.assertIn('requests from Cloudflare addresses were ignored', notes)
        self.assertIn('(412)', notes)
        self.assertIn('over the hourly limit', notes)
        self.assertIn('web&lt;01&gt;', notes)

    def test_the_cloudflare_explanation_is_said_once_not_per_host(self):
        sensors = [{'name': n, 'device_id': n, 'at': 1, 'sources': [], 'ignored': {'cloudflare': 10 + i}}
                   for i, n in enumerate(('web01', 'web02', 'web03'))]
        notes = node('''_ipiData = {sensor_enabled: true, sensors: %s}; _ipiRenderSources();
          console.log(JSON.stringify(els['ipintel-src-notes'].innerHTML));''' % json.dumps(sensors))
        self.assertEqual(notes.count('requests from Cloudflare addresses were ignored'), 3, 'one short line per host')
        self.assertEqual(notes.count('real_ip_header'), 1, 'the how-to-fix is not repeated')
        self.assertLess(notes.rindex('web03'), notes.index('real_ip_header'), 'it follows the hosts it applies to')
        quiet = node('''_ipiData = {sensor_enabled: true, sensors: [{name: 'a', sources: [], ignored: {}}]}; _ipiRenderSources();
          console.log(JSON.stringify(els['ipintel-src-notes'].innerHTML));''')
        self.assertEqual(quiet, '', 'nothing to say when nothing was ignored')

    def test_empty_states_say_why(self):
        for enabled, text in ((True, 'No host has reported its logs yet.'), (False, 'The log sensor is off.')):
            body = node('''_ipiData = {sensor_enabled: %s, sensors: []}; _ipiRenderSources();
              console.log(JSON.stringify(els['ipintel-src-tbody'].innerHTML));''' % json.dumps(enabled))
            self.assertIn(text, body)
            self.assertIn('colspan="9"', body)


# ── the markup ─────────────────────────────────────────────────────────────────

class _Table(HTMLParser):
    def __init__(self, tid):
        super().__init__()
        self.tid, self.depth, self.cols, self.in_head = tid, 0, [], False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'thead' and a.get('id') == self.tid:
            self.in_head = True
        if self.in_head and tag == 'th':
            self.cols.append((a.get('data-col'), a.get('scope')))

    def handle_endtag(self, tag):
        if tag == 'thead':
            self.in_head = False


def columns(thead_id):
    p = _Table(thead_id)
    p.feed(_HTML)
    return p.cols


class TestMarkup(unittest.TestCase):
    def test_the_attackers_table_gained_one_sortable_column_and_every_colspan_followed(self):
        cols = columns('ipintel-att-thead')
        self.assertIn('evidence', [c for c, _ in cols])
        self.assertEqual(len(cols), 10)
        self.assertIn('colspan="10"', _HTML[_HTML.index('id="ipintel-att-tbody"'):][:200])
        self.assertIn('colspan="10"', _JS)
        self.assertNotIn('colspan="9"', _JS[_JS.index('function _ipiRenderAttackers'):_JS.index('function _ipiRenderSources')])

    def test_the_sources_table(self):
        cols = columns('ipintel-src-thead')
        self.assertEqual([c for c, _ in cols], ['host', 'kind', 'path', 'fmt', 'lines', 'parsed', 'events', 'at', 'state'])
        self.assertTrue(all(s == 'col' for _, s in cols))
        i = _HTML.index('id="ipintel-src-thead"')
        card = _HTML[_HTML.rindex('<div class="dash-card', 0, i):_HTML.index('id="ipintel-src-notes"')]
        self.assertIn('scrollable-table-wrap audit-scroll', card, 'a list that can grow is capped and scrolls')
        self.assertIn('colspan="9"', card)

    def test_every_sortable_header_is_wired_before_the_data_arrives(self):
        body = _JS[_JS.index('async function loadIpIntel'):]
        fetch_at = body.index("await api('GET', '/ip-intel')")
        for tid, name in (('ipintel-att-thead', 'ipintel-att'), ('ipintel-blk-thead', 'ipintel-blk'),
                          ('ipintel-src-thead', 'ipintel-src')):
            wire = body.index(f"tableCtl.wireSortOnly('{tid}', '{name}'")
            self.assertLess(wire, fetch_at, f'{tid} is wired after the fetch: headers show no sort arrow until data arrives')

    def test_the_sensor_card_is_for_admins_and_starts_hidden(self):
        i = _HTML.index('id="ipintel-sensor-card"')
        self.assertIn('hidden', _HTML[i:i + 60])
        self.assertIn("document.getElementById('ipintel-sensor-card').hidden = !_ipiAdmin;", _JS)
        for need in ('id="ipintel-sensor"', 'id="ipintel-sensor-paths"'):
            self.assertIn(need, _HTML)

    def test_nothing_inline_that_the_csp_would_kill(self):
        a, b = _HTML.index('id="page-ipintel"'), _HTML.index('id="page-sshgw"')
        page = _HTML[a:b]
        self.assertNotRegex(page, r'\son[a-z]+\s*=')
        self.assertNotRegex(page, r'\sstyle\s*=')
        js = _JS[_JS.index('function _ipiClassName'):_JS.index('function _ipiRenderBlocks')]
        self.assertNotRegex(js, r'\son[a-z]+\s*=')
        self.assertNotRegex(js, r'\sstyle\s*=')

    def test_no_emoji_in_the_new_markup_or_script(self):
        emoji = re.compile('[\U0001F300-\U0001FAFF☀-➿]')
        a, b = _HTML.index('id="page-ipintel"'), _HTML.index('id="page-sshgw"')
        self.assertIsNone(emoji.search(_HTML[a:b]))
        self.assertIsNone(emoji.search(_JS))

    def test_the_settings_page_sends_and_fills_the_two_new_fields(self):
        self.assertIn("sensor_enabled: v('ipintel-sensor').checked", _JS)
        self.assertIn("sensor_paths: v('ipintel-sensor-paths').value", _JS)
        self.assertIn("chk('ipintel-sensor', s.sensor_enabled)", _JS)
        self.assertIn("set('ipintel-sensor-paths', (s.sensor_paths || []).join('\\n'))", _JS)

    def test_the_message_hint_names_the_new_placeholders(self):
        for ph in ('{attack}', '{seen_by}'):
            self.assertIn(f'<code>{ph}</code>', _HTML)


# ── what the API sends ─────────────────────────────────────────────────────────

def _event(ip, **kw):
    now = int(time.time())
    e = {'ip': ip, 'first': now - 600, 'last': now, 'src': {'web': 41, 'waf': 12},
         'tok': {'web': {'req:sqli': 30, 'req:traversal': 11}, 'waf': {'crs:942100': 12, 'crs:949110': 12}},
         'ans': 3, 'blk': 31, 'cve': ['CVE-2021-44228']}
    e.update(kw)
    return te.normalize_event(e, now=now)


class TestPayload(_Case):
    def setUp(self):
        super().setUp()
        self.policy(sensor_enabled=True, report_enabled=True, report_min_count=10)

    def call(self, role='admin'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: 'GET'
        self.cap.clear()
        try:
            self.api.handle_ip_intel()
        except self.api.HTTPError:
            pass
        return self.cap.get('data') or {}

    def feed(self, ip=ATTACKER, dev='d1', **kw):
        self.api.ip_intel_note_evidence(dev, [_event(ip, **kw)], {'sources': [
            {'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 400, 'parsed': 399,
             'events': 41, 'fmt': 'custom', 'proxied': False}], 'ignored': {'cloudflare': 9}})
        self.api._LOAD_CACHE.clear()

    def test_an_unreported_address_carries_its_ledger_and_a_reported_one_what_was_said(self):
        self.policy(report_enabled=False)
        self.feed()
        self.sweep()
        row = self.call()['attackers'][0]
        ev = row['evidence']
        self.assertEqual([c['id'] for c in ev['classes']], ['sqli', 'traversal'])
        self.assertEqual((ev['ans'], ev['blk'], ev['sent']), (3, 31, False))
        self.assertEqual(ev['cves'], ['CVE-2021-44228'])
        self.assertEqual(ev['rules'], ['942100'], 'the anomaly summary 949110 says nothing about the attack')
        self.assertEqual([s['id'] for s in ev['sources']], ['web', 'waf'])
        self.policy(report_enabled=True)
        self.feed()
        self.sweep()
        row = self.call()['attackers'][0]
        self.assertTrue(row['evidence']['sent'], 'the ledger was started over; what was reported is shown')
        self.assertEqual(sorted(e['prov'] for e in row['report_log']), ['abuseipdb', 'sniffcat'])
        self.assertIn('SQL injection', row['report_log'][0]['comment'])

    def test_an_address_only_the_counter_knows_has_no_evidence(self):
        self.attack(count=40)
        self.sweep()
        self.assertIsNone(self.call()['attackers'][0]['evidence'])

    def test_the_hosts_sources_come_with_the_listing_and_only_for_visible_hosts(self):
        self.feed()
        d = self.call()
        self.assertTrue(d['sensor_enabled'])
        self.assertEqual([r['name'] for r in d['sensors']], ['web01'])
        r = d['sensors'][0]
        self.assertEqual((r['sources'][0]['path'], r['ignored']), ('/var/log/nginx/access.log', {'cloudflare': 9}))
        self.api._scope_filter_devices = lambda devs, scope=None: {}
        self.assertEqual(self.call()['sensors'], [])

    def test_everyone_sees_whether_the_sensor_is_on_but_only_admins_see_the_settings(self):
        d = self.call(role='viewer')
        self.assertTrue(d['sensor_enabled'])
        self.assertEqual(d['settings'], {})
        self.assertTrue(self.call()['settings']['sensor_enabled'])


class TestSeeder(unittest.TestCase):
    def test_the_demo_shows_evidence_and_every_kind_of_source_state(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('seed_v720', _ROOT / 'packaging' / 'seed-demo-data.py')
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        d = seed.build_ip_intel()
        json.dumps(d)
        with_ev = [a for a in d['attackers'].values() if a.get('ev') or a.get('ev_reported')]
        self.assertGreaterEqual(len(with_ev), 5)
        for a in with_ev:
            ev = a.get('ev') or a['ev_reported']['ev']
            self.assertIsNotNone(te.normalize_event(dict(ev, ip='185.220.101.7'), now=int(time.time())),
                                 'the demo evidence must be something the server would accept')
        states = {s['state'] for r in d['sensors'].values() for s in r['sources']}
        self.assertTrue({'ok', 'idle', 'denied', 'unparsed', 'missing'} <= states, states)
        self.assertTrue(any((r.get('ignored') or {}).get('cloudflare') for r in d['sensors'].values()))
        self.assertTrue(any(a.get('report_log') for a in d['attackers'].values()))
        for r in d['sensors'].values():
            self.assertEqual(len(tsh._clean_sources(r['sources'])), len(r['sources']),
                             'every seeded source passes the server\'s own sanitiser')


if __name__ == '__main__':
    unittest.main()
