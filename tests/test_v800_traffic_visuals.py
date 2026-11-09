#!/usr/bin/env python3
"""8.0.0: the Traffic overview, the note under the remote addresses and the Home widget, run as the real functions of the page under node.

Each case takes the function from the source (tests/srcpin.js_function) and runs it, so a reversed condition or a missing escape fails here. What the page draws came from a host
(an address, a program name) or from a lookup (a country, a network): every text goes in through escHtml and every attribute through escAttr, and the cases below feed all of
them markup. A bar is a share of the biggest row of its block, in two parts; a value that is not zero never draws as zero, and the biggest row's two parts add up to the whole bar.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
import srcpin  # noqa: E402

_NODE = shutil.which('node')
_JS = _TESTS.parent / 'server' / 'html' / 'static' / 'js'
APP = (_JS / 'app.js').read_text(encoding='utf-8')
TR = (_JS / 'app-traffic.js').read_text(encoding='utf-8')

FROM_APP = ('escAttr', '_fmtBytes', '_miniRows')
FROM_TR = ('_trBytes', '_trRate', '_trWhere', '_trShare', '_trBarRow', '_trBlock', '_trWhereTo', '_trOverview', '_trGeoNote', 'trafficWidgetHtml')
HOSTILE = '<img src=x onerror="window.__owned=1">'


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


def run(script, extra=''):
    esc = re.search(r'^function escHtml\(s\)[^\n]*$', APP, re.M).group(0)          # a one-line definition: the page's own, not a copy
    parts = [esc] + [srcpin.js_function(APP, n) for n in FROM_APP] + [srcpin.js_function(TR, n) for n in FROM_TR]
    code = ("const _TR_BARS = 6;\nconst els = {'traffic-overview': {innerHTML: ''}, 'traffic-overview-card': {hidden: true}, 'traffic-geo-note': {hidden: true}};\n"
            "const document = {getElementById: id => els[id] || null};\n" + extra + '\n' + '\n'.join(parts) + '\n' + script)
    r = subprocess.run([_NODE, '-'], input=code, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(r.stderr[-1500:])
    return json.loads(r.stdout)


def remote(ip, tx, rx, **kw):
    return dict({'ip': ip, 'tx': tx, 'rx': rx, 'scope': 'public', 'hosts_n': 1}, **kw)


@unittest.skipUnless(_NODE, 'node not installed')
class TestWhereTo(unittest.TestCase):

    def where(self, remotes):
        return run('console.log(JSON.stringify(_trWhereTo(%s)));' % json.dumps(remotes))

    def test_local_addresses_are_one_bar_and_a_country_is_one_bar_by_its_code(self):
        rows = self.where([remote('10.0.0.5', 100, 0, scope='private'), remote('10.0.0.6', 50, 0, scope='private'), remote('8.8.8.8', 10, 90, country='United States', country_code='US'),
                           remote('8.8.4.4', 5, 5, country_code='US'), remote('1.2.3.4', 1, 1)])
        self.assertEqual([(r['label'], r['tx'], r['rx']) for r in rows], [('Local network', 150, 0), ('United States', 15, 95), ('Unknown', 1, 1)])
        self.assertEqual(rows[2]['cls'], 'hint', 'the unknown bar is muted')

    def test_the_busiest_first_and_at_most_six(self):
        rows = self.where([remote('9.9.%d.1' % n, n, 0, country_code='C%d' % n) for n in range(1, 12)])
        self.assertEqual(len(rows), 6)
        self.assertEqual([r['label'] for r in rows], ['C11', 'C10', 'C9', 'C8', 'C7', 'C6'])

    def test_a_code_alone_is_shown_as_the_code_and_a_name_wins_over_it(self):
        self.assertEqual(self.where([remote('1.1.1.1', 1, 0, country_code='DE')])[0]['label'], 'DE')
        rows = self.where([remote('1.1.1.1', 1, 0, country_code='DE'), remote('2.2.2.2', 1, 0, country='Germany', country_code='DE')])
        self.assertEqual([(r['label'], r['tx']) for r in rows], [('Germany', 2)])


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheOverview(unittest.TestCase):

    def overview(self, fleet):
        return run('_trOverview(%s); console.log(JSON.stringify({html: els["traffic-overview"].innerHTML, hidden: els["traffic-overview-card"].hidden}));' % json.dumps(fleet))

    def fleet(self):
        return {'remotes': [remote('104.16.1.1', 600, 200, country='United States', country_code='US', org='Cloudflare'), remote('10.0.2.30', 100, 100, scope='private')],
                'programs': [{'proc': 'nginx', 'tx': 700, 'rx': 250}, {'proc': '-', 'tx': 10, 'rx': 0}],
                'ports': [{'d': 'in', 'port': 443, 'tx': 700, 'rx': 100}, {'d': 'out', 'port': 53, 'tx': 5, 'rx': 5}]}

    def test_four_blocks_in_a_fixed_order(self):
        out = self.overview(self.fleet())
        self.assertFalse(out['hidden'])
        titles = [t for t in ('Busiest addresses', 'Programs', 'Where to', 'Direction') if t in out['html']]
        self.assertEqual(titles, ['Busiest addresses', 'Programs', 'Where to', 'Direction'])
        self.assertEqual([out['html'].index(t) for t in titles], sorted(out['html'].index(t) for t in titles))
        self.assertIn('Local network', out['html'])
        self.assertIn('Inbound', out['html'])
        self.assertIn('Outbound', out['html'])
        self.assertIn('Unknown', out['html'], 'a connection with no program')

    def test_the_biggest_row_of_a_block_fills_the_bar_and_a_small_one_never_vanishes(self):
        out = self.overview({'remotes': [remote('1.1.1.1', 3000, 1000), remote('2.2.2.2', 1, 0), remote('3.3.3.3', 0, 0)], 'programs': [], 'ports': []})
        pcts = [int(x) for x in __import__('re').findall(r'data-pct="(\d+)"', out['html'].split('Busiest addresses', 1)[1].split('Programs', 1)[0])]
        self.assertEqual(pcts[:2], [75, 25], 'sent and received of the biggest row add up to the whole bar')
        self.assertEqual(pcts[2:4], [1, 0], 'one byte is a sliver and not nothing; no byte is nothing')
        self.assertEqual(pcts[4:6], [0, 0])

    def test_nothing_to_show_hides_the_card(self):
        out = self.overview({'remotes': [], 'programs': [], 'ports': []})
        self.assertTrue(out['hidden'])
        self.assertEqual(out['html'], '')

    def test_what_a_host_or_a_lookup_sent_is_text_in_every_block(self):
        f = {'remotes': [remote('9.9.9.9', 5, 5, country=HOSTILE, org=HOSTILE), remote(HOSTILE, 4, 4, scope='private')], 'programs': [{'proc': HOSTILE, 'tx': 2, 'rx': 2}], 'ports': []}
        out = self.overview(f)
        self.assertNotIn('<img', out['html'])
        self.assertIn('&lt;img', out['html'])

    def test_a_block_with_no_rows_says_so(self):
        out = self.overview({'remotes': [remote('1.1.1.1', 1, 1)], 'programs': [], 'ports': []})
        self.assertGreaterEqual(out['html'].count('Nothing to show.'), 2)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheNote(unittest.TestCase):

    def hidden(self, fleet):
        return run('_trGeoNote(%s); console.log(JSON.stringify(els["traffic-geo-note"].hidden));' % json.dumps(fleet))

    def test_it_shows_for_public_addresses_when_nothing_names_a_country_and_no_file_is_set_up(self):
        self.assertFalse(self.hidden({'geo': False, 'remotes': [remote('8.8.8.8', 1, 1)]}))

    def test_it_stays_away_when_a_file_is_set_up_or_something_is_named_or_all_is_local(self):
        self.assertTrue(self.hidden({'geo': True, 'remotes': [remote('8.8.8.8', 1, 1)]}))
        self.assertTrue(self.hidden({'geo': False, 'remotes': [remote('8.8.8.8', 1, 1, country_code='US')]}))
        self.assertTrue(self.hidden({'geo': False, 'remotes': [remote('8.8.8.8', 1, 1, org='Example')]}))
        self.assertTrue(self.hidden({'geo': False, 'remotes': [remote('10.0.0.1', 1, 1, scope='private')]}))
        self.assertTrue(self.hidden({'geo': False, 'remotes': []}))


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheWidget(unittest.TestCase):

    def html(self, tw):
        return run('console.log(JSON.stringify(trafficWidgetHtml(%s)));' % json.dumps(tw))

    def datum(self, **kw):
        base = {'on': True, 'hosts': 2, 'total': 3, 'tx': 2048, 'rx': 1024, 'conns': 17, 'hits': 0,
                'top': [remote('104.16.1.1', 3000, 1000, country='United States', org='Cloudflare'), remote('10.0.2.30', 500, 500, scope='private'), remote('8.8.8.8', 1, 0, country_code='US')]}
        base.update(kw)
        return base

    def test_the_rows_the_bars_and_the_way_in(self):
        h = self.html(self.datum())
        for text in ('Hosts reporting', '2 / 3', 'Sent', 'Received', 'Connections', '17', 'Open Traffic →', 'data-action="openTrafficTab"'):
            self.assertIn(text, h)
        self.assertNotIn('Watch list matches', h, 'no match, no row')
        self.assertEqual(h.count('class="tr-row"'), 3)
        self.assertIn('data-pct="75"', h)

    def test_a_watch_list_match_is_an_amber_row(self):
        h = self.html(self.datum(hits=4))
        self.assertIn('Watch list matches', h)
        self.assertIn('c-amber', h)

    def test_the_empty_states_use_the_words_the_page_already_has(self):
        self.assertIn('There is no host with an agent yet.', self.html(self.datum(total=0, hosts=0, top=[])))
        self.assertIn('No Linux host has reported yet.', self.html(self.datum(hosts=0, top=[])))

    def test_what_a_host_or_a_lookup_sent_is_text(self):
        h = self.html(self.datum(top=[remote(HOSTILE, 1, 1, country=HOSTILE, org=HOSTILE)]))
        self.assertNotIn('<img', h)
        self.assertIn('&lt;img', h)

    def test_a_datum_without_addresses_still_draws_its_numbers(self):
        h = self.html(self.datum(top=[]))
        self.assertIn('Hosts reporting', h)
        self.assertNotIn('class="tr-row"', h)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheSourceKeepsTheShape(unittest.TestCase):

    def test_the_widget_renderer_is_in_the_lazy_file_and_the_eager_one_only_loads_it(self):
        self.assertNotIn('function trafficWidgetHtml', APP)
        self.assertIn('function trafficWidgetHtml', TR)
        glue = srcpin.js_function(APP, '_trafficWidget')
        self.assertIn("_loadJsModule('app-traffic.js')", glue)

    def test_the_bars_set_their_widths_through_data_pct_and_never_a_style_attribute(self):
        for name in ('_trBarRow', 'trafficWidgetHtml'):
            body = srcpin.js_function(TR, name)
            self.assertIn('data-pct=', body)
            self.assertNotIn('style=', body, 'a style attribute is refused by the page\'s content security policy')


if __name__ == '__main__':
    unittest.main()
