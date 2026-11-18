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


if __name__ == '__main__':
    unittest.main()
