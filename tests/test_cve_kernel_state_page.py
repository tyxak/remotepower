"""The page says which kernel a host runs and which findings only need a reboot (8.0.2).

The server side is in tests/test_cve_kernel_state.py. This holds the scripts: the host view prints the running kernel, its
package and a newer kernel installed beside it, or says it could not tell and why; a finding an installed kernel clears
reads "fixed by an installed kernel, reboot to apply" and names the kernel; the CVE page has a sixth tile for them; and every
sentence is in the six languages. The functions are cut out of the scripts and run under node.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cve_fixes  # noqa: E402
import srcpin  # noqa: E402

_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_PAGE = (_JS / 'app-cve.js').read_text()
_HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()
HAVE_NODE = shutil.which('node') is not None


def helpers():
    why = re.search(r'^const _CVE_KERNEL_WHY = \{.*?^\};', _PAGE, re.M | re.S).group(0)
    return '\n'.join([why, srcpin.js_function(_PAGE, '_cveKernelHtml'), srcpin.js_function(_PAGE, '_cveFixHtml'),
                      srcpin.js_function(_PAGE, '_cveFixKey')])


def run(expr, extra=''):
    script = ('const escHtml = s => String(s).replace(/[&<>"\']/g, c => "&#" + c.charCodeAt(0) + ";");\n'
              'const escAttr = escHtml;\nvar _localeTag = () => "en-US";\n' + helpers() + '\n' + extra
              + '\nconsole.log(JSON.stringify(' + expr + '));\n')
    r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


MATCHED = {'state': 'matched', 'running': '6.1.0-40-amd64', 'package': 'linux-image-6.1.0-40-amd64', 'version': '6.1.158-1',
           'newer': 'linux-image-6.1.0-48-amd64 6.1.192-1', 'left_out': 3}


class TestThePageNamesEveryWhy(unittest.TestCase):
    def test_a_sentence_for_each_reason_the_server_can_give_and_no_other(self):
        why = re.search(r'^const _CVE_KERNEL_WHY = \{(.*?)^\};', _PAGE, re.M | re.S).group(1)
        self.assertEqual(re.findall(r"^  ([a-z_]+): '", why, re.M), list(cve_fixes.KERNEL_WHY))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheKernelLine(unittest.TestCase):
    def test_a_host_that_runs_a_known_kernel_says_which_and_what_is_installed_beside_it(self):
        html = run('_cveKernelHtml(%s)' % json.dumps(MATCHED))
        self.assertIn('data-cve-kernel="matched"', html)
        self.assertIn('<span>Running kernel:</span> <span class="mono-12" data-no-i18n="">6.1.0-40-amd64</span>', html)
        self.assertIn('<span>Package:</span> <span class="mono-12" data-no-i18n="">linux-image-6.1.0-40-amd64 6.1.158-1</span>', html)
        self.assertIn('<span>Installed, not running:</span> <span class="mono-12" data-no-i18n="">'
                      'linux-image-6.1.0-48-amd64 6.1.192-1</span> <span>Reboot to start it.</span>', html)
        self.assertIn('<span>Packages of other installed kernels, not counted:</span> <span>3</span>', html)

    def test_what_is_not_there_is_not_printed(self):
        html = run('_cveKernelHtml(%s)' % json.dumps({'state': 'matched', 'running': 'r', 'package': 'p', 'version': '1'}))
        self.assertNotIn('Installed, not running', html)
        self.assertNotIn('not counted', html)

    def test_a_host_whose_kernel_could_not_be_told_says_so_and_why(self):
        for why in cve_fixes.KERNEL_WHY:
            html = run('_cveKernelHtml(%s)' % json.dumps({'state': 'unknown', 'running': '6.1.0-40-amd64', 'why': why}))
            self.assertIn('data-cve-kernel="unknown"', html)
            self.assertIn('It could not be matched to an installed package, so findings against the kernel are matched against '
                          'every installed kernel.', html)
            self.assertEqual(html.count('<span>'), 3, (why, html))              # the label, the sentence and the reason
        none = run('_cveKernelHtml(%s)' % json.dumps({'state': 'unknown', 'running': '', 'why': 'not_reported'}))
        self.assertIn('<span>not reported</span>', none)

    def test_a_reason_that_is_not_one_prints_no_reason(self):
        html = run('_cveKernelHtml(%s)' % json.dumps({'state': 'unknown', 'running': 'r', 'why': '<img src=x>'}))
        self.assertNotIn('<img', html)
        self.assertEqual(html.count('<span>'), 2)                               # the label and the sentence: no reason

    def test_hostile_names_come_out_as_text(self):
        evil = dict(MATCHED, running='<img src=x onerror=1>', package='"><b>', newer='<script>1</script>')
        html = run('_cveKernelHtml(%s)' % json.dumps(evil))
        for tag in ('<img', '<b>', '<script>'):
            self.assertNotIn(tag, html)

    def test_a_block_of_another_shape_prints_nothing_and_does_not_throw(self):
        for odd in (None, 7, 'x', [], {}, {'state': 'maybe'}, {'state': 'matched', 'package': {'a': 1}, 'version': [], 'newer': 5,
                                                                   'left_out': {'x': 1}, 'running': 9},
                    {'state': 'unknown', 'why': {'a': 1}, 'running': {}}):
            html = run('_cveKernelHtml(%s)' % json.dumps(odd))
            self.assertNotIn('[object', html, odd)
            self.assertNotIn('undefined', html, odd)

    def test_the_host_view_prints_it_above_the_packages_checked(self):
        view = srcpin.js_function(_PAGE, 'openDeviceCVE')
        self.assertIn('html += _cveKernelHtml(data.kernel);', view)
        self.assertLess(view.index('_cveKernelHtml(data.kernel)'), view.index('_cveCoveredHtml(data.covered)'))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestAFindingThatNeedsAReboot(unittest.TestCase):
    F = {'vuln_id': 'DEBIAN-CVE-2099-1', 'fix_status': 'reboot', 'fixed_version': '6.1.192-1',
         'reboot_to': 'linux-image-6.1.0-48-amd64 6.1.192-1'}

    def test_it_says_reboot_and_names_the_kernel_and_does_not_say_where_to_install(self):
        html = run('_cveFixHtml(%s)' % json.dumps(self.F))
        self.assertIn('<span class="c-green">Fixed by an installed kernel, reboot to apply</span>', html)
        self.assertIn('<span data-no-i18n="">linux-image-6.1.0-48-amd64 6.1.192-1</span>', html)
        self.assertNotIn('fixed in', html)
        self.assertNotIn('6.1.192-1</span>', html.replace('linux-image-6.1.0-48-amd64 6.1.192-1</span>', ''))

    def test_a_hostile_kernel_name_is_text_and_a_missing_one_is_not_printed(self):
        html = run('_cveFixHtml(%s)' % json.dumps(dict(self.F, reboot_to='<img src=x onerror=1>')))
        self.assertNotIn('<img', html)
        bare = run('_cveFixHtml(%s)' % json.dumps({'fix_status': 'reboot', 'fixed_version': '1'}))
        self.assertIn('reboot to apply', bare)
        self.assertNotIn('data-no-i18n', bare)
        for odd in (None, 7, {'a': 1}, ['x']):
            self.assertNotIn('[object', run('_cveFixHtml(%s)' % json.dumps(dict(self.F, reboot_to=odd))))

    def test_the_other_statuses_say_what_they_said(self):
        self.assertIn('fixed in <span class="c-green">9</span>', run('_cveFixHtml(%s)' % json.dumps({'fix_status': 'fixed', 'fixed_version': '9'})))
        self.assertIn('No fix yet', run('_cveFixHtml(%s)' % json.dumps({'fix_status': 'none'})))
        self.assertIn('Fixed with Ubuntu Pro', run('_cveFixHtml(%s)' % json.dumps({'fix_status': 'pro'})))

    def test_it_counts_in_its_own_tile_by_the_rule_of_the_server(self):
        findings = [self.F, {'fix_status': 'fixed', 'fixed_version': '1'}, {'fix_status': 'none'}, {}]
        keys = run('%s.map(_cveFixKey)' % json.dumps(findings))
        self.assertEqual(keys, [cve_fixes.fix_key(f) for f in findings])
        self.assertEqual(keys[0], 'reboot')

    def test_the_tile_is_on_the_page_in_the_order_of_the_server(self):
        names = re.search(r'^const _CVE_FIX_NAME = \{(.*)\};$', _PAGE, re.M).group(1)
        self.assertEqual(re.findall(r'(\w+): ', names), list(cve_fixes.FIX_KEYS))
        for key in cve_fixes.FIX_KEYS:
            self.assertEqual(_HTML.count(f'id="cve-fix-{key}"'), 1, key)
            self.assertIn(f'data-action="setCveFixFilter" data-arg="{key}" role="button" tabindex="0"', _HTML)
        # the tiles stand in the order the server lists them
        ids = [i for i in re.findall(r'id="cve-fix-(\w+)"', _HTML) if i != 'row']
        self.assertEqual(ids, list(cve_fixes.FIX_KEYS))


class TestTheNewTextsAreInSixLanguages(unittest.TestCase):
    TEXTS = ['Reboot to apply', 'Fixed by an installed kernel, reboot to apply', 'Running kernel:', 'Package:',
             'Installed, not running:', 'Reboot to start it.', 'Packages of other installed kernels, not counted:',
             'It could not be matched to an installed package, so findings against the kernel are matched against every installed '
             'kernel.', 'not reported']

    def test_every_text_the_page_prints_is_a_key_with_all_six(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        why = re.findall(r"^  [a-z_]+: '([^']+)',$", re.search(r'^const _CVE_KERNEL_WHY = \{.*?^\};', _PAGE, re.M | re.S).group(0),
                         re.M)
        self.assertEqual(len(why), len(cve_fixes.KERNEL_WHY))
        for text in self.TEXTS + why:
            self.assertTrue(rows.get(text) and all(rows[text].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')), text)

    def test_the_texts_are_the_ones_the_scripts_print(self):
        for text in self.TEXTS:
            self.assertTrue(text in _PAGE or text in _HTML, text)


if __name__ == '__main__':
    unittest.main()
