"""The page says which of a host's packages a CVE scan checked, and why not the others (8.0.2).

The server side is in tests/test_cve_package_coverage.py. This holds the scripts: the host view and the drawer print how many
packages were checked and why the rest were not, the line "no vulnerabilities found" is only said when every package was
checked, the CVE page and the dashboard say what they know of the fleet, and every sentence is in the six languages. The
functions are cut out of the scripts and run under node.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import srcpin  # noqa: E402

_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text()
_PAGE = (_JS / 'app-cve.js').read_text()
_I18N = (_JS / 'i18n.js').read_text()
_HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()
HAVE_NODE = shutil.which('node') is not None
REASONS = ('no_source', 'no_matcher', 'no_release', 'not_published', 'ceiling', 'unanswered')


class TestThePageNamesEveryReason(unittest.TestCase):
    def test_the_page_names_every_reason_the_server_can_send_and_no_other(self):
        words = re.search(r'^const _CVE_NOT_CHECKED = \{(.*?)^\};', _PAGE, re.M | re.S).group(1)
        self.assertEqual(re.findall(r"^  ([a-z_]+): '", words, re.M), list(REASONS))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestThePage(unittest.TestCase):
    """The functions of the page, cut out of the scripts and run."""

    def run_js(self, source, expr):
        script = (
            'const escHtml = s => String(s).replace(/[&<>"\']/g, c => "&#" + c.charCodeAt(0) + ";");\n'
            'const escAttr = escHtml;\nvar _localeTag = () => "en-US";\n'
            + source + '\nconsole.log(JSON.stringify(' + expr + '));\n')
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def helpers(self):
        reasons = re.search(r'^const _CVE_NOT_CHECKED = \{.*?^\};', _PAGE, re.M | re.S).group(0)
        return '\n'.join([reasons, srcpin.js_function(_PAGE, '_cveCoveredHtml'), srcpin.js_function(_PAGE, '_cveNoneFoundHtml')])

    BLOCK = {'listed': 1901, 'checked': 1834, 'not_checked': 67, 'reasons': {'no_source': 52, 'no_release': 15},
             'packages': [{'name': 'libfoo', 'version': '1.0-1', 'reason': 'no_source'},
                          {'name': '<img src=x onerror=1>', 'version': '"><b>', 'reason': 'no_release'}], 'more': 65}

    def test_the_host_view_says_how_many_were_checked_and_why_not_the_others(self):
        html = self.run_js(self.helpers(), '_cveCoveredHtml(' + json.dumps(self.BLOCK) + ')')
        self.assertIn('<span>Packages checked:</span> <strong>1,834 / 1,901</strong>', html)
        self.assertIn('<span>Not checked:</span> <strong>67</strong>', html)
        self.assertIn('<tr><td>No source name</td><td class="ta-center">52</td></tr>', html)
        self.assertIn('<tr><td>Release not known</td><td class="ta-center">15</td></tr>', html)
        self.assertIn('<td class="mono-12" data-no-i18n="">libfoo</td>', html)
        self.assertIn('<span>Packages not shown:</span> <span>65</span>', html)
        self.assertIn('<details', html)                               # the first 200 are one click away

    def test_hostile_names_come_out_as_text(self):
        html = self.run_js(self.helpers(), '_cveCoveredHtml(' + json.dumps(self.BLOCK) + ')')
        self.assertNotIn('<img', html)
        self.assertNotIn('<b>', html)
        self.assertIn('&#60;img src=x onerror=1&#62;', html)

    def test_a_block_of_another_shape_prints_nothing_and_does_not_throw(self):
        for odd in (None, 7, 'x', [], {}, {'listed': 'many'}, {'listed': {'a': 1}, 'not_checked': {'b': 2}},
                    {'listed': 3, 'checked': 3, 'not_checked': 0, 'packages': 'x'},
                    {'listed': 3, 'not_checked': 3, 'checked': 0, 'reasons': 5, 'packages': [None, 7, {'name': {}}]}):
            html = self.run_js(self.helpers(), '_cveCoveredHtml(' + json.dumps(odd) + ')')
            self.assertNotIn('[object', html, odd)
            self.assertNotIn('undefined', html, odd)

    def test_everything_checked_is_one_line(self):
        html = self.run_js(self.helpers(), '_cveCoveredHtml({listed: 6, checked: 6, not_checked: 0, reasons: {}})')
        self.assertIn('<strong>6 / 6</strong>', html)
        self.assertNotIn('<details', html)
        self.assertNotIn('Not checked:', html)

    def test_no_vulnerabilities_found_is_only_said_when_everything_was_checked(self):
        said = lambda data: self.run_js(self.helpers(), '_cveNoneFoundHtml(' + json.dumps(data) + ')')  # noqa: E731
        self.assertIn('No vulnerabilities found.', said({}))
        self.assertIn('No vulnerabilities found.', said({'covered': {'listed': 5, 'checked': 5, 'not_checked': 0}}))
        part = said({'covered': {'listed': 9, 'checked': 4, 'not_checked': 5}})
        self.assertIn('<span>None found in the packages that could be checked:</span> <strong>4</strong>', part)
        self.assertNotIn('No vulnerabilities found', part)
        nothing = said({'covered': {'listed': 9, 'checked': 0, 'not_checked': 9}})
        self.assertIn('None found, but none of the packages could be checked.', nothing)
        self.assertNotIn('No vulnerabilities found', nothing)
        for odd in ('x', 7, {'covered': 'x'}, {'covered': {'not_checked': '9', 'checked': {}}}):
            self.assertIn('No vulnerabilities found.', said(odd), odd)

    def test_the_host_view_uses_both(self):
        view = srcpin.js_function(_PAGE, 'openDeviceCVE')
        self.assertIn('html += _cveCoveredHtml(data.covered);', view)
        self.assertIn("html += _cveNoneFoundHtml(data); }", view)
        self.assertNotIn('No vulnerabilities found.</div>', view)

    def fleet_note(self, total, hosts):
        page = srcpin.js_function(_PAGE, '_renderCveCoveredNote')
        reasons = re.search(r'^const _CVE_NOT_CHECKED = \{.*?^\};', _PAGE, re.M | re.S).group(0)
        script = '''
const escHtml = s => String(s).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const escAttr = escHtml;
var _localeTag = () => 'en-US';
const els = {};
const el = id => els[id] || (els[id] = {id, hidden: true, textContent: '', innerHTML: ''});
const document = {getElementById: id => el(id)};
%s
%s
_renderCveCoveredNote(%s, %s);
console.log(JSON.stringify(els));
''' % (reasons, page, json.dumps(total), json.dumps(hosts))
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_the_fleet_note_is_shown_when_something_was_not_checked(self):
        els = self.fleet_note({'listed': 1909, 'checked': 1834, 'not_checked': 75,
                               'reasons': {'no_source': 52, 'no_matcher': 8}},
                              [{'device_id': 'd1', 'name': 'web<01>', 'listed': 1000, 'not_checked': 60},
                               {'device_id': 'd2', 'name': 'db01', 'listed': 900, 'not_checked': 15}])
        self.assertFalse(els['cve-covered-note']['hidden'])
        self.assertEqual(els['cve-covered-total']['textContent'], '1,834 / 1,909')
        self.assertEqual(els['cve-covered-missed']['textContent'], '75')
        self.assertIn('<span>No source name</span> <strong>52</strong>', els['cve-covered-reasons']['innerHTML'])
        hosts = els['cve-covered-hosts']['innerHTML']
        self.assertIn('data-action="openDeviceCVE" data-arg="d1"', hosts)
        self.assertIn('60 / 1,000', hosts)
        self.assertNotIn('<01>', hosts)

    def test_the_fleet_note_is_hidden_when_everything_was_checked_or_nothing_is_known(self):
        for total in ({'listed': 10, 'checked': 10, 'not_checked': 0, 'reasons': {}}, None, 7, 'x', {}):
            els = self.fleet_note(total, [])
            self.assertTrue(els['cve-covered-note']['hidden'], total)

    def test_the_fleet_page_loads_the_note_and_the_markup_has_its_places(self):
        self.assertIn("_renderCveCoveredNote(data.summary.covered, data.summary.most_not_checked);",
                      srcpin.js_function(_PAGE, 'loadCVEReport'))
        for ident in ('cve-covered-note', 'cve-covered-total', 'cve-covered-missed', 'cve-covered-reasons',
                      'cve-covered-hosts'):
            self.assertEqual(_HTML.count(f'id="{ident}"'), 1, ident)

    def run_drawer(self, data):
        block = _APP[_APP.index("      case 'cve': {"):]
        block = block[:block.index('        // Cross-feature: CVE findings')]
        body = block[block.index('        const findings = data.findings || [];'):]
        script = '''
const escHtml = s => String(s).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const badge = {}, body = {};
const data = %s;
%s
console.log(JSON.stringify({badge: badge.innerHTML, body: body.innerHTML}));
''' % (json.dumps(data), body)
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_the_host_drawer_does_not_call_a_partly_checked_host_clean(self):
        part = self.run_drawer({'scanned_at': 5, 'findings': [], 'covered': {'listed': 9, 'checked': 4, 'not_checked': 5}})
        self.assertEqual(part['badge'], 'none found')
        self.assertIn('<span>None found in the packages that could be checked:</span> <strong>4</strong>', part['body'])
        self.assertIn('<span>Packages not checked:</span> <strong>5</strong>', part['body'])
        self.assertNotIn('No CVEs found.', part['body'])
        none = self.run_drawer({'scanned_at': 5, 'findings': [], 'covered': {'listed': 9, 'checked': 0, 'not_checked': 9}})
        self.assertEqual(none['badge'], 'none found')
        self.assertIn('None found, but none of the packages could be checked.', none['body'])

    def test_a_host_checked_whole_is_still_clean(self):
        whole = self.run_drawer({'scanned_at': 5, 'findings': [], 'covered': {'listed': 9, 'checked': 9, 'not_checked': 0}})
        self.assertEqual(whole['badge'], 'clean')
        self.assertIn('<div class="c-green">No CVEs found.</div>', whole['body'])
        self.assertNotIn('Packages not checked', whole['body'])
        for odd in ('x', 7, {'not_checked': 'many'}, {'not_checked': {}, 'checked': []}):
            out = self.run_drawer({'scanned_at': 5, 'findings': [], 'covered': odd})
            self.assertEqual(out['badge'], 'clean', odd)

    def test_findings_still_win_the_badge(self):
        out = self.run_drawer({'scanned_at': 5, 'findings': [{'vuln_id': 'CVE-2024-1', 'severity': 'high', 'package': 'p',
                                                              'version': '1'}],
                               'covered': {'listed': 9, 'checked': 4, 'not_checked': 5}})
        self.assertIn('1 high', out['badge'])
        self.assertIn('<span>Packages not checked:</span> <strong>5</strong>', out['body'])

    def test_the_dashboard_tile_is_not_green_over_a_fleet_that_was_not_all_checked(self):
        for fragment in ("acc.notChecked += (Number.isInteger(d.not_checked) && d.not_checked > 0) ? d.not_checked : 0;",
                         "(notCheckedPkgs > 0 && totalCves === 0 && countedCves === 0) ? '' : 'ok'",
                         "'None found in the packages that could be checked'"):
            self.assertIn(fragment, _APP)


class TestTheNewTextsAreInSixLanguages(unittest.TestCase):
    TEXTS = ['No source name', 'No matcher for the package manager', 'Release not known', 'Not published by the distribution',
             'Past the limit of packages a scan reads', 'Not answered in full by the data source', 'Packages checked:',
             'Not checked:', 'None found in the packages that could be checked:',
             'None found, but none of the packages could be checked.', 'Packages not checked:',
             'None found in the packages that could be checked', 'Most not checked:', 'none found']

    def test_every_text_the_page_prints_is_a_key_with_all_six(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        for text in self.TEXTS:
            self.assertTrue(rows.get(text) and all(rows[text].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')), text)

    def test_the_texts_are_the_ones_the_scripts_print(self):
        reasons = re.search(r'^const _CVE_NOT_CHECKED = \{(.*?)^\};', _PAGE, re.M | re.S).group(1)
        for text in re.findall(r": '([^']+)',?$", reasons, re.M):
            self.assertIn(text, self.TEXTS)
        for text in self.TEXTS:
            self.assertTrue(text in _PAGE or text in _APP or text in _HTML, text)


if __name__ == '__main__':
    unittest.main()
