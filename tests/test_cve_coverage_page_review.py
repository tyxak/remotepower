"""The scripts of the CVE coverage work, run and not read (8.0.2 review).

tests/test_cve_package_coverage_page.py holds the first version's page tests, and its test of the dashboard tile was three
`assertIn(fragment, source)`: with the line that reads the packages not checked replaced by `const notCheckedPkgs = 0;` every
module and the browser module stayed green, and a fleet of which nothing was checked read "No active CVEs" in green. A source
text test proves a line exists. These run the real functions under node.

  * the Home tile of CVEs, from the real `_renderHomeTiles`, for every state of its payload that decides what it says;
  * the line of the host view that says what a reboot clears, for every fix status the server's sentence names;
  * the fleet note of the CVE page, with the hosts whose last scan says nothing of their packages;
  * the three places of the page that say what the count option counts.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import srcpin  # noqa: E402

_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text()
_PAGE = (_JS / 'app-cve.js').read_text()
_I18N = (_JS / 'i18n.js').read_text()
_HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()
HAVE_NODE = shutil.which('node') is not None
# a missing node is a skip, and with RP_NODE_REQUIRE=1 a failure: a suite whose absence looks like its success is no suite
NEEDS_NODE = unittest.skipUnless(HAVE_NODE or os.environ.get('RP_NODE_REQUIRE') == '1', 'node not installed')


def node(script):
    r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ── the tile ────────────────────────────────────────────────────────────────────────────────────────────────────────
def host(dev_id, monitored=True):
    return {'id': dev_id, 'monitored': monitored, 'online': True, 'sysinfo': {'packages': {'upgradable': 0}}}


def row(dev_id, critical=0, high=0, medium=0, low=0, counted=0, not_checked=0):
    return {'device_id': dev_id, 'counts': {'critical': critical, 'high': high, 'medium': medium, 'low': low},
            'counted': counted, 'not_checked': not_checked}


def tile_of(devs, rows):
    """The CVE tile of the Home page, as the real `_renderHomeTiles` draws it for these hosts and this payload."""
    script = '''
const target = {innerHTML: ''};
const document = {getElementById: id => id === 'home-tiles' ? target : null};
const statTiles = {enhanceAll() {}};
%s
_renderHomeTiles(%s, {devices: []}, {devices: %s}, {devices: []});
console.log(JSON.stringify(target.innerHTML));
''' % (srcpin.js_function(_APP, '_renderHomeTiles'), json.dumps(devs), json.dumps(rows))
    html = node(script)
    tiles = re.findall(r'<div class="tile ([^"]*)"([^>]*)>(.*?)<div class="tile-subtle">(.*?)</div>\s*</div>', html, re.S)
    for cls, attrs, body, sub in tiles:
        if 'data-arg="cve"' in attrs:
            return {'cls': cls.strip(), 'sub': sub.strip(), 'value': re.search(r'tile-value">(.*?)</div>', body, re.S).group(1).strip(),
                    'label': re.search(r'tile-label">(.*?)</div>', body, re.S).group(1).strip()}
    raise AssertionError('no CVE tile in: ' + html[:300])


@NEEDS_NODE
class TestTheHomeTileOfCves(unittest.TestCase):
    NEUTRAL = {'cls': '', 'sub': 'None found in the packages that could be checked'}
    CLEAR = {'cls': 'ok', 'sub': 'No active CVEs'}

    def check(self, devs, rows, want):
        got = tile_of(devs, rows)
        self.assertEqual({k: got[k] for k in want}, want, (rows, got))
        return got

    def test_the_control_the_instrument_reads_the_real_tile(self):
        got = tile_of([host('a')], [row('a')])
        self.assertEqual((got['label'], got['value']), ('Critical CVEs', '0'))

    def test_a_fleet_with_nothing_found_and_nothing_checked_is_not_green(self):
        self.check([host('a'), host('b')], [row('a', not_checked=300), row('b', not_checked=40)], self.NEUTRAL)

    def test_one_host_with_packages_that_were_not_checked_is_enough(self):
        self.check([host('a'), host('b')], [row('a'), row('b', not_checked=5)], self.NEUTRAL)
        self.check([host('a')], [row('a', not_checked=1)], self.NEUTRAL)

    def test_a_fleet_that_was_checked_whole_and_has_nothing_says_so_in_green(self):
        self.check([host('a'), host('b')], [row('a'), row('b')], self.CLEAR)
        self.check([host('a')], [], self.CLEAR)                      # a fleet no scan has reported on

    def test_a_number_that_is_not_a_whole_count_is_not_counted(self):
        for odd in (0, -3, 2.5, '7', None, True, {'n': 1}, [4]):
            self.check([host('a')], [row('a', not_checked=odd)], self.CLEAR)

    def test_what_is_found_is_said_first_and_green_stays_for_what_is_minor(self):
        self.check([host('a')], [row('a', critical=2, not_checked=9)], {'cls': 'alert'})
        self.check([host('a')], [row('a', high=1, not_checked=9)], {'cls': 'warn'})
        self.check([host('a')], [row('a', medium=3, not_checked=9)], {'cls': 'ok', 'sub': '3 total (med/low only)'})
        self.check([host('a')], [row('a', counted=4, not_checked=9)], {'cls': 'ok', 'sub': '4 counted per package'})

    def test_the_critical_count_is_the_value(self):
        got = tile_of([host('a')], [row('a', critical=2, high=1, medium=1)])
        self.assertEqual((got['value'], got['sub']), ('2', '1 high · 1 med/low'))

    def test_a_host_that_is_not_monitored_is_not_in_the_tile(self):
        self.check([host('a'), host('b', monitored=False)], [row('a'), row('b', not_checked=50)], self.CLEAR)
        self.check([host('a'), host('b', monitored=False)], [row('a', not_checked=2), row('b')], self.NEUTRAL)


# ── the line of the host view for what a reboot clears ──────────────────────────────────────────────────────────────────
def rollup_html(roll):
    """The roll-up of the host view, from the real `_cveRollupHtml`."""
    script = (
        'const escHtml = s => String(s).replace(/[&<>"\']/g, c => "&#" + c.charCodeAt(0) + ";");\n'
        + srcpin.js_function(_PAGE, '_cveRollupHtml')
        + '\nconsole.log(JSON.stringify(_cveRollupHtml(%s)));\n' % json.dumps(roll))
    return node(script)


def lines_of(html):
    """The "Of these, ..." lines of a roll-up, as (text, number)."""
    return re.findall(r'<div class="hint mt-6"><span>(Of these[^<]*)</span> <span>(\d+)</span></div>', html)


@NEEDS_NODE
class TestTheRollupOfTheHostViewSaysWhatARebootClears(unittest.TestCase):
    """A kernel has the most findings of any package, so the ceiling of a package (50 listed) is reached on the host the
    reboot status is for, and the counted rest is where an operator finds out that a reboot clears it."""

    def test_the_line_is_there_with_the_number_for_the_status(self):
        got = lines_of(rollup_html({'total': 20, 'severity': {'medium': 20}, 'fix': {'reboot': 20}}))
        self.assertEqual(got, [('Of these, fixed by an installed kernel, reboot to apply:', '20')])

    def test_every_line_has_its_own_number_and_they_come_in_order(self):
        got = lines_of(rollup_html({'total': 90, 'severity': {'critical': 2, 'high': 3, 'medium': 85},
                                    'fix': {'fixable': 30, 'reboot': 20, 'pro': 10, 'none': 30}}))
        self.assertEqual(got, [('Of these, critical or high:', '5'), ('Of these, cleared by an update:', '30'),
                               ('Of these, fixed by an installed kernel, reboot to apply:', '20'),
                               ('Of these, fixed with Ubuntu Pro:', '10')])

    def test_no_reboot_no_line_and_a_number_that_is_not_one_is_not_a_line(self):
        for fix in ({}, {'reboot': 0}, {'reboot': -2}, {'reboot': '20'}, {'reboot': None}, {'reboot': {'n': 20}}, None, 'x'):
            html = rollup_html({'total': 5, 'fix': fix})
            self.assertEqual(lines_of(html), [], fix)
            self.assertNotIn('installed kernel', html, fix)

    def test_the_page_has_a_line_for_every_status_the_servers_sentence_names(self):
        """The class, by population: derive what the server's own sentence names, status by status, and require a line for each."""
        import cve_fixes
        named = [key for key in cve_fixes.FIX_KEYS
                 if '(' in cve_fixes.rollup_words({'rollup': {'total': 5, 'fix': {key: 5}}})]
        self.assertTrue({'fixable', 'pro'} <= set(named), named)            # the control: the derivation sees what it should
        self.assertIn('reboot', named)
        for key in cve_fixes.FIX_KEYS:
            drawn = lines_of(rollup_html({'total': 5, 'fix': {key: 5}}))
            if key in named:
                self.assertEqual(len(drawn), 1, f'the sentence of the server names "{key}" and the host view has no line for it')
            else:
                self.assertEqual(drawn, [], key)

    def test_the_sentence_is_a_key_in_all_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        row = dict_rows().get('Of these, fixed by an installed kernel, reboot to apply:')
        self.assertTrue(row and all(row.get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')), row)
        self.assertEqual(sum(1 for _ in re.finditer(r'^\s*"Of these, fixed by an installed kernel, reboot to apply:":', _I18N, re.M)), 1)


# ── what the count option says it counts ────────────────────────────────────────────────────────────────────────────────
class TestEveryTextThatStatesWhatTheCountOptionCountsNamesTheReboot(unittest.TestCase):
    """With the option on, a finding counts and alerts when an update clears it, when it is known to be exploited, and, since
    8.0.2, when an installed kernel already holds the fix and a reboot applies it (cve_fixes.counted and alert_candidate).
    Only docs/cve.md said so: the Settings hint, its label, the note of the CVE page and the alert option still said that
    an update is what clears a finding that counts. The texts are found by what they state, in the dictionary every
    string of the page is a key of, so a text added later is held to it too."""
    REBOOT = {'zh': '重启', 'hi': 'रीबूट', 'es': 'reinici', 'ar': 'إعادة تشغيل', 'de': 'Neustart', 'fr': 'redémarr'}

    @staticmethod
    def population():
        from test_v710_i18n_glue import dict_rows
        return {k: v for k, v in dict_rows().items()
                if ('known to be exploited' in k or 'known-exploited' in k) and 'update' in k.lower()}

    def test_the_population_is_the_five_places_and_not_empty(self):
        texts = self.population()
        self.assertGreaterEqual(len(texts), 5, sorted(texts))
        for known in ('Count only CVEs an update or a reboot can fix, or that are known to be exploited',
                      'Only CVEs an update or a reboot can fix, or that are known to be exploited'):
            self.assertIn(known, texts)

    def test_each_one_names_the_reboot_in_english_and_in_the_six_languages(self):
        for text, translations in self.population().items():
            self.assertIn('reboot', text, text)
            for lang, word in self.REBOOT.items():
                self.assertIn(word, translations.get(lang, ''), f'{lang}: {text}')

    def test_each_one_is_the_text_a_page_shows(self):
        for text in self.population():
            self.assertTrue(any(text in source for source in (_HTML, _APP, _PAGE)), text)

    def test_the_rule_they_state_is_the_one_the_server_applies(self):
        import cve_fixes
        reboot = {'vuln_id': 'CVE-2099-1', 'severity': 'medium', 'fix_status': 'reboot'}
        nothing = {'vuln_id': 'CVE-2099-2', 'severity': 'medium', 'fix_status': 'none'}
        self.assertTrue(cve_fixes.counted(reboot, True))
        self.assertTrue(cve_fixes.alert_candidate(reboot, True, set()))
        self.assertFalse(cve_fixes.counted(nothing, True))
        self.assertFalse(cve_fixes.alert_candidate(nothing, True, set()))


if __name__ == '__main__':
    unittest.main()
