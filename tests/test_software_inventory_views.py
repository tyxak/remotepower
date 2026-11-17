"""What the pages say about the software of a Windows or macOS host.

The server sends the pages two new facts (a host whose list is applications is "not checked" for vulnerabilities, and a policy
violation of such a host carries its manager), and the pages have to act on them. The page functions run under node, taken out of
the real scripts with stubs for what they call; none of the assertions reads the source text of a function for a string.

  * the CVE page says "not checked" for such a host, and "unsupported" where it said it before;
  * the host's CVE view and the drawer's CVE summary say that nothing on the host is checked, and print no "No vulnerabilities
    found" or "clean" under it (an empty list there would say the opposite of what is true);
  * the Software Policy page offers no install or remove button for a violation of such a host, and does for the rest;
  * the two new sentences are in the dictionary in all six languages, and the sentence in the page is the key;
  * what the guides say is what the code does: the file the Windows agent writes, the limits, the manager words, the anchors.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
_JS = ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-softinv-views-'))

import cve_scanner  # noqa: E402
import software_inventory as si  # noqa: E402
import srcpin  # noqa: E402

_APP = (_JS / 'app.js').read_text(encoding='utf-8')
_PAGE = (_JS / 'app-cve.js').read_text(encoding='utf-8')
_HTML = (ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_DOCS = {p.name: p.read_text(encoding='utf-8') for p in (ROOT / 'docs').glob('*.md')}


def fn(source, name):
    """A function of a page script as it is defined there, with its `async` (srcpin returns the part from `function`)."""
    body = srcpin.js_function(source, name)
    return ('async ' if re.search(r'^async function ' + re.escape(name) + r'\(', source, re.M) else '') + body


def node(script):
    r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def preamble():
    """escHtml and escAttr, the sentences of the host's CVE view and the function that prints them, as the page defines them."""
    return '\n'.join([
        re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
        re.search(r'^function escAttr\(.*$', _APP, re.M).group(0),
        re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE, re.M | re.S).group(0),
        srcpin.js_function(_PAGE, '_cveCoverageHtml'),
    ])


NO_MATCHER = 'The software of this host is listed, but no vulnerability database is matched against it'


class TestTheSentenceOfAHostNothingIsCheckedOf(unittest.TestCase):
    def html(self, data):
        return node(preamble() + '\nconsole.log(JSON.stringify({html: _cveCoverageHtml(%s)}));' % json.dumps(data))['html']

    def test_it_is_printed_for_the_word_the_server_sends(self):
        html = self.html({'coverage': 'no_matcher'})
        self.assertIn(NO_MATCHER, html)
        self.assertIn('data-cve-coverage="no_matcher"', html)

    def test_every_word_the_server_can_say_has_a_sentence(self):
        entries = [
            {'ecosystem': '', 'pkg_manager': 'windows', 'packages': [{'name': 'Google Chrome', 'version': '1'}]},
            {'ecosystem': 'Debian:12', 'pkg_manager': 'macos', 'packages': [{'name': 'Safari', 'version': '1'}]},
            {'ecosystem': '', 'pkg_manager': 'pacman', 'packages': [{'name': 'bash', 'version': '5'}]},
        ] + [{'ecosystem': e, 'sources': s, 'os_id': 'ubuntu', 'version_id': '22.04', 'packages': [{'name': 'a', 'version': '1'}]}
             for e in ('Debian:12', 'Ubuntu', 'Alpine:v3.18', 'Rocky Linux:9', 'AlmaLinux:9', 'Red Hat') for s in (True, False)]
        said = {cve_scanner.entry_coverage(e) for e in entries} - {''}
        words = set(re.findall(r"^  ([a-z_]+): '", re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE, re.M | re.S).group(0), re.M))
        self.assertIn('no_matcher', said)
        self.assertTrue(said <= words, said - words)


class _Page:
    """The host's CVE view and the drawer's CVE summary, run with the stubs they need."""

    @staticmethod
    def open_device_cve(data):
        script = preamble() + '\n' + fn(_PAGE, 'openDeviceCVE') + '''
const out = {body: '', title: ''};
const els = {'cve-detail-title': {set textContent(v) { out.title = v; }}, 'cve-detail-body': {set innerHTML(v) { out.body = v; }}};
const document = {getElementById: id => els[id]};
const _skeletonBlock = () => '';
const openModal = () => {};
const _errorState = () => { out.error = true; };
const api = async () => (%s);
const timeAgoHtml = (ts, o) => (ts ? 'ago' : (o && o.empty) || '');
const _icon = () => '';
const _cveRollupHtml = r => '';
let cveFixFilter = '';
openDeviceCVE('h1', 'host one').then(() => console.log(JSON.stringify(out)));
''' % json.dumps(data)
        return node(script)['body']

    @staticmethod
    def audit_cve(data):
        script = preamble() + '\n' + fn(_APP, '_loadAuditSection') + '''
const out = {body: '', badge: ''};
const els = {'audit-body-cve': {set innerHTML(v) { out.body = v; }, get innerHTML() { return out.body; }, insertAdjacentHTML(w, h) { out.body += h; }},
             'audit-badge-cve': {set textContent(v) { out.badge = v; }, set innerHTML(v) { out.badge = v; }}};
const document = {getElementById: id => els[id]};
let _drawerDeviceId = 'h1', _drawerDeviceName = 'host one';
const _drawerAuditLoaded = {};
const _skeletonBlock = () => '';
const api = async () => (%s);
const plural = (n, a, b) => n + ' ' + (n === 1 ? a : b);
const _icon = () => '';
_loadAuditSection('cve').then(() => console.log(JSON.stringify(out)));
''' % json.dumps(data)
        return node(script)


class TestTheHostsCveView(unittest.TestCase):
    NOTHING = {'findings': [], 'ecosystem': 'unsupported', 'packages_count': 187, 'collected_at': 5, 'scanned_at': 0,
               'error': '', 'cut': [], 'rollup': None}

    def test_a_host_nothing_is_checked_of_says_so_and_does_not_say_it_has_no_vulnerabilities(self):
        body = _Page.open_device_cve(dict(self.NOTHING, coverage='no_matcher'))
        self.assertIn(NO_MATCHER, body)
        self.assertNotIn('No vulnerabilities found', body)
        self.assertIn('187', body)                                  # the host still shows how many packages it has

    def test_a_scanned_host_with_nothing_found_still_says_so(self):
        """The control: the line is not gone for every host."""
        body = _Page.open_device_cve(dict(self.NOTHING, coverage='', ecosystem='Debian:12', scanned_at=9))
        self.assertIn('No vulnerabilities found', body)
        self.assertNotIn(NO_MATCHER, body)

    def test_the_drawers_summary_says_not_checked_and_has_no_tiles_of_zeros(self):
        out = _Page.audit_cve(dict(self.NOTHING, coverage='no_matcher'))
        self.assertEqual(out['badge'], 'not checked')
        self.assertIn(NO_MATCHER, out['body'])
        self.assertNotIn('sysinfo-pill', out['body'])
        self.assertNotIn('No CVEs found', out['body'])

    def test_the_drawers_summary_of_a_clean_host_is_as_it_was(self):
        out = _Page.audit_cve(dict(self.NOTHING, coverage='', ecosystem='Debian:12', scanned_at=9))
        self.assertEqual(out['badge'], 'clean')
        self.assertIn('No CVEs found', out['body'])
        self.assertIn('sysinfo-pill', out['body'])


class TestTheCvePageRow(unittest.TestCase):
    def row(self, status, scanned_at=0):
        script = '\n'.join([
            re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
            re.search(r'^function escAttr\(.*$', _APP, re.M).group(0),
            srcpin.js_function(_APP, '_registerCveTable'),
            '''
let _cveRegistered = false;
let cfg = null;
const tableCtl = {register: c => { cfg = c; }};
const timeAgoHtml = ts => 'ago';
const _icon = () => '';
_registerCveTable();
const d = {device_id: 'h1', name: 'host one', group: '', ecosystem: 'unsupported', status: %s, scanned_at: %d, kev: 0,
           counts: {critical: 0, high: 0, medium: 0, low: 0}, rollup: 0};
console.log(JSON.stringify({row: cfg.row(d)}));''' % (json.dumps(status), scanned_at)])
        return node(script)['row']

    @staticmethod
    def last_scan(row):
        return re.search(r'<td class="meta-sm-nm">(.*?)</td>', row).group(1)

    def test_an_application_host_is_not_checked_and_an_unsupported_one_is_unsupported(self):
        self.assertEqual(self.last_scan(self.row('no_matcher')), '<span class="c-amber">●</span> not checked')
        self.assertEqual(self.last_scan(self.row('unsupported')), '<span class="c-amber">●</span> unsupported')
        self.assertEqual(self.last_scan(self.row('no_packages')), '<span class="c-muted">●</span> no package list')
        self.assertEqual(self.last_scan(self.row('not_scanned')), '<span class="c-muted">●</span> not scanned')
        self.assertEqual(self.last_scan(self.row('scanned', 5)), 'ago')                # a host that was scanned says when

    def test_every_status_the_server_sends_has_its_words(self):
        """The statuses are derived from handle_cve_findings, not listed by hand here."""
        src = srcpin.py_function((_CGI / 'cve_handlers.py').read_text(encoding='utf-8'), 'handle_cve_findings')
        sent = {w for line in re.findall(r"^\s*status = (.*)$", src, re.M) for w in re.findall(r"(?<!get\()'([a-z_]+)'", line)}
        self.assertEqual(sent, {'scanned', 'no_packages', 'unsupported', 'no_matcher', 'not_scanned'})
        for status in sent - {'scanned'}:
            cell = self.last_scan(self.row(status))
            self.assertTrue(cell.startswith('<span class="c-'), (status, cell))     # a dot and a word; the fallback prints the raw status


class TestThePolicyPage(unittest.TestCase):
    def rows(self, violations, me=None):
        script = '\n'.join([
            re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
            re.search(r'^function escAttr\(.*$', _APP, re.M).group(0),
            srcpin.js_function(_APP, '_renderSwViolations'),
            '''
let out = '';
const els = {'swpol-viol-tbody': {set innerHTML(v) { out = v; }}};
const document = {getElementById: id => els[id]};
const tableCtl = {sortRows: (name, rows, f) => rows};
const _icon = () => '<svg/>';
let _meCache = %s;
let _swViolations = %s;
_renderSwViolations();
console.log(JSON.stringify({html: out}));''' % (json.dumps(me or {'admin': True, 'permissions': []}), json.dumps(violations))])
        return node(script)['html']

    LINUX = {'device_id': 'lnx1', 'device': 'LNX', 'type': 'banned', 'package': 'telnet', 'expected': 'not installed', 'found': '0.17'}
    WINDOWS = {'device_id': 'win1', 'device': 'WIN', 'type': 'banned', 'package': 'TeamViewer', 'expected': 'not installed',
               'found': '15.49.2', 'manager': 'windows'}
    MAC = dict(WINDOWS, device_id='mac1', device='MAC', manager='macos')

    def test_no_install_or_remove_button_for_an_application_host(self):
        html = self.rows([self.LINUX, self.WINDOWS, self.MAC])
        tr = re.findall(r'<tr>.*?</tr>', html, re.S)
        self.assertEqual(len(tr), 3)
        fix = [bool(re.search(r'data-action="swPolFixViolation"', t)) for t in tr]
        self.assertEqual(fix, [True, False, False])
        self.assertIn('TeamViewer', tr[1])                                # the row itself is there

    def test_a_reader_with_no_right_to_act_gets_no_button_on_any_row(self):
        html = self.rows([self.LINUX, self.WINDOWS], me={'admin': False, 'permissions': []})
        self.assertNotIn('swPolFixViolation', html)

    def test_the_text_of_a_violation_is_escaped(self):
        html = self.rows([dict(self.WINDOWS, package='<img src=x onerror=alert(1)>', found='"><script>')])
        self.assertNotIn('<img', html)
        self.assertNotIn('<script>', html)


class TestTheNewSentences(unittest.TestCase):
    HINT = ('A required rule with no tags is checked on Linux hosts only. To require an application on a Windows or macOS host, '
            'give the rule a tag that host carries. Application names are matched without regard to case.')

    def test_both_are_in_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        for text in (NO_MATCHER + ', so nothing on it is checked. No findings here does not mean no vulnerabilities.', self.HINT):
            self.assertTrue(rows.get(text), text[:60])
            self.assertEqual(sorted(rows[text]), ['ar', 'de', 'es', 'fr', 'hi', 'zh'], text[:60])
            for lang, value in rows[text].items():
                self.assertTrue(value.strip() and value != text, (lang, text[:40]))

    def test_the_sentence_of_the_page_is_the_key(self):
        sentence = re.search(r"^  no_matcher: '([^']+)',$", re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE, re.M | re.S).group(0), re.M).group(1)
        from test_v710_i18n_glue import dict_rows
        self.assertIn(sentence, dict_rows())
        self.assertIn('<p class="hint mb-8">' + self.HINT + '</p>', _HTML)

    def test_the_policy_sentence_is_what_the_server_does(self):
        """A required rule with no tags is not judged on a Windows or macOS host, and one with a tag is: the page says the same."""
        import importlib.util
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-softinv-views-'))
        spec = importlib.util.spec_from_file_location('api_softinv_views', _CGI / 'api.py')
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        saved = (api.fire_webhook, api.save, api.load, api.backend_exists)
        store = {api.SOFTWARE_VIOLATIONS_FILE: {}, api.SOFTWARE_POLICY_FILE: {'rules': [
            {'id': 'bare', 'type': 'required', 'package': 'Antivirus'},
            {'id': 'tagged', 'type': 'required', 'package': 'Antivirus', 'tags': ['windows']}]}}
        api.fire_webhook = lambda *a, **k: None
        api.backend_exists = lambda f: True
        api.load = lambda f: json.loads(json.dumps(store.get(f, {})))
        api.save = lambda f, data, **k: store.__setitem__(f, json.loads(json.dumps(data)))
        try:
            for manager, tags, want in (('windows', ['windows'], ['tagged']), ('macos', [], []), ('', [], ['bare'])):
                store[api.SOFTWARE_VIOLATIONS_FILE] = {}
                got = api._eval_software_policy('h1', 'host', [{'name': 'Other', 'version': '1'}], tags, host_manager=manager)
                self.assertEqual(sorted(v['rule_id'] for v in got), want, (manager, tags))
                if manager == '':
                    got = api._eval_software_policy('h1', 'host', [{'name': 'Other', 'version': '1'}], ['windows'], host_manager='')
                    self.assertEqual(sorted(v['rule_id'] for v in got), ['bare', 'tagged'])
        finally:
            api.fire_webhook, api.save, api.load, api.backend_exists = saved


class TestTheGuidesSayWhatTheCodeDoes(unittest.TestCase):
    def test_the_inventory_section_says_what_each_system_reports_and_the_limits(self):
        doc = _DOCS['patches.md']
        section = doc[doc.index('## Software inventory'):doc.index('## Packages apt keeps back')]
        for word in ('Linux', 'Windows', 'macOS', 'Uninstall', 'Info.plist', 'brew list --versions', 'Homebrew', 'publisher',
                     'install date', 'bundle identifier'):
            self.assertIn(word, section, word)
        self.assertIn(f'{si.MAX_PACKAGES:,}', section)
        self.assertIn(str(si.MAX_FIELD), section)
        self.assertIn('six hours', section)
        win = (ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        self.assertIn('PACKAGE_LIST_EVERY = 360', win)                       # 360 polls of a minute: the six hours the guide says

    def test_the_guides_say_no_cve_matching_is_done_for_applications(self):
        cve = _DOCS['cve.md']
        self.assertIn('CVE matching for Windows and macOS applications is not done', cve)
        self.assertIn('**not checked**', cve)
        self.assertNotIn('send no package list for CVE scanning', cve)                    # the sentence that stopped being true
        self.assertIn('Windows or macOS agent older than the one that sends its software list', cve)

    def test_the_windows_guide_names_the_file_the_agent_writes_and_the_keys_it_reads(self):
        win_doc = _DOCS['windows-client.md']
        agent = (ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        name = re.search(r"^_PKG_HASH_FILE = '([^']+)'", agent, re.M).group(1)
        self.assertIn(f'| `{name}` |', win_doc)
        for key in (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'):
            self.assertIn(key, agent)
        self.assertIn('WOW6432Node', win_doc)
        self.assertIn('SystemComponent', win_doc)
        self.assertIn('ParentKeyName', win_doc)

    def test_the_manager_words_of_the_explorer_are_the_ones_the_server_stores(self):
        text = _DOCS['data-explorer.md']
        for word in si.INVENTORY_MANAGERS:
            self.assertIn(f'`{word}`', text, word)

    def test_the_links_between_the_guides_have_somewhere_to_land(self):
        for name, fragment in (('patches.md', 'software-inventory'), ('cve.md', 'windows-and-macos-hosts'),
                               ('cve.md', 'which-hosts-are-scanned')):
            headings = {re.sub(r'[^a-z0-9 -]', '', h.lower()).strip().replace(' ', '-') for h in re.findall(r'^#+ (.*)$', _DOCS[name], re.M)}
            self.assertIn(fragment, headings, (name, fragment))


if __name__ == '__main__':
    unittest.main()
