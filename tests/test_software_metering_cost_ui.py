#!/usr/bin/env python3
"""The software metering table and its rule editor, as far as a function can say it without a browser.

The real functions are extracted from app.js and run under node:

  * `_parseMeterLines` reads the editor ("name = limit @ cost | alias1, alias2"): the cost and the aliases are optional, a cost that is not an amount
    (a third decimal, a sign, an exponent, a separator, a digit of another script) sets `bad` so that nothing is saved, and a name with an `@` in it keeps it;
  * `_meterMoney` writes an amount the server sent as text, grouped in thousands without a float and without losing a cent;
  * `_meterColumns` is what the table sorts by and what its CSV export carries: the columns in the order of the table, the amounts as numbers, and no cost column
    at all for a caller the server sent no currency to;
  * the CSV the export builds from those columns (the cell function is the page's own) has the header and the rows a spreadsheet should get.

The export itself (the Blob and the download) is exercised in a browser: tests/test_software_metering_cost_e2e.py. The words of the table are held to the six
languages here, and so is the sentence over the editor.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text(encoding='utf-8')
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402
from test_v430_i18n_gate import _htmldict_entries  # noqa: E402

_NODE = shutil.which('node')

WORDS = ['Owned', 'Unit cost', 'Short by', 'Cost to buy', 'Spare', 'Cost to reclaim', 'Fleet total', 'Rules without a cost',
         'A rule with no cost has no amount, so it is not in the cost totals.', 'A cost is an amount such as 49.99, with at most two decimals',
         'a software meter cost must be an amount from 0 to 1,000,000 with at most two decimals',
         'Software', 'Installed', 'Reclaim', 'Hosts']


def _subtitle():
    """The sentence over the editor, as the page translation keys it: its innerHTML with the spaces collapsed."""
    i = _HTML.index('Track install counts of named software')
    start = _HTML.rfind('<div', 0, i)
    inner = _HTML[_HTML.index('>', start) + 1:_HTML.index('</div>', i)]
    return re.sub(r'\s+', ' ', inner).strip()


class TestTheWordsAreTranslated(unittest.TestCase):

    def test_every_word_of_the_table_has_all_six_languages(self):
        rows = dict_rows()
        missing = {w: sorted(set(LANGS) - rows.get(w, set())) for w in WORDS if set(LANGS) - rows.get(w, set())}
        self.assertEqual(missing, {}, 'strings of the software metering table that are not in the dictionary in every language')

    def test_the_sentence_over_the_editor_names_the_cost_and_has_all_six_languages(self):
        sub = _subtitle()
        self.assertIn('name = limit @ cost', sub)
        self.assertIn('49.99', sub)
        entries = _htmldict_entries()
        self.assertGreater(len(entries), 100, 'control: the page-subtitle dictionary was read')
        self.assertIn(sub, entries, 'the sentence is not a key of the dictionary of page subtitles: it would stay in English')
        self.assertEqual(sorted(set(LANGS) - entries[sub]), [])

    def test_the_old_sentence_is_gone_from_both_places(self):
        old = 'against an allowance. One per line as <span class="ff-mono">name = limit</span> (limit 0 = just count). Matches'
        self.assertNotIn(old, _HTML)
        self.assertNotIn(old.replace('"', '\\"'), (_JS / 'i18n.js').read_text(encoding='utf-8'))


_STUB = r'''
function escHtml(s) { return String(s); }
'''


def _run(script_body):
    body = '\n'.join(srcpin.js_function(_APP, n) for n in ('_meterMoney', '_meterColumns', '_parseMeterLines', '_csvCell'))
    re_const = re.search(r'const _METER_COST_RE = .*;', _APP).group(0)
    script = _STUB + re_const + '\n' + body + '\n' + script_body
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-meter-ui-'))
    try:
        f = d / 'meter.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheEditorLines(unittest.TestCase):

    def parse(self, *texts):
        return _run('console.log(JSON.stringify(%s.map(_parseMeterLines)));' % json.dumps(list(texts)))

    def test_a_line_with_a_limit_a_cost_and_aliases(self):
        got = self.parse('openssl = 10 @ 49.99 | libssl3, openssl-libs\nnginx = 3\nteamviewer = 0 @ 0.10\npostgres')[0]
        self.assertFalse(got['bad'])
        self.assertEqual(got['meters'], [{'name': 'openssl', 'limit': 10, 'unit_cost': '49.99', 'aliases': ['libssl3', 'openssl-libs']}, {'name': 'nginx', 'limit': 3},
                                         {'name': 'teamviewer', 'limit': 0, 'unit_cost': '0.10'}, {'name': 'postgres', 'limit': 0}])

    def test_the_cost_is_sent_as_the_text_the_operator_typed(self):
        got = self.parse('a = 1 @ 5\nb = 1 @ 0\nc = 1 @ 1000000\nd = 1 @ 0.5')[0]['meters']
        self.assertEqual([m['unit_cost'] for m in got], ['5', '0', '1000000', '0.5'], 'the server canonicalises; the page does not reformat or round')

    def test_a_cost_that_is_not_an_amount_stops_the_save(self):
        for bad in ('1.999', '-1', '+1', '1e3', '1,000', '$5', '5.', '.5', 'abc', '٣٤', '４９', '12345678', '1 0', '5 USD', '0x10'):
            got = self.parse('nginx = 3 @ ' + bad)[0]
            self.assertTrue(got['bad'], bad)
            self.assertEqual(got['meters'], [], bad)

    def test_a_blank_cost_is_no_cost(self):
        got = self.parse('nginx = 3 @\nredis = 2 @   ')[0]
        self.assertFalse(got['bad'])
        self.assertEqual(got['meters'], [{'name': 'nginx', 'limit': 3}, {'name': 'redis', 'limit': 2}])

    def test_an_at_sign_in_a_name_or_an_alias_stays_where_it_is(self):
        got = self.parse('foo@bar = 4 @ 1.50 | a@b, c')[0]
        self.assertEqual(got['meters'], [{'name': 'foo@bar', 'limit': 4, 'unit_cost': '1.50', 'aliases': ['a@b', 'c']}])

    def test_blank_lines_and_a_line_without_a_name_are_left_out_as_before(self):
        got = self.parse('\n   \n = 3 @ 1.00\nok = 2\n')[0]
        self.assertEqual(got['meters'], [{'name': 'ok', 'limit': 2}])
        self.assertEqual(self.parse('')[0], {'meters': [], 'bad': False})


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheAmountsAndTheColumns(unittest.TestCase):

    def test_an_amount_is_grouped_from_its_text_and_never_loses_a_cent(self):
        got = _run('console.log(JSON.stringify([["0.30","USD"],["1234.50","USD"],["999999999999999.99","EUR"],["12.00",""],["864.15","USD"],[null,"USD"],["12.5","USD"],["x","USD"],'
                   '["1000000.00","NOK"]].map(a => _meterMoney(a[0], a[1]))));')
        self.assertEqual(got, ['USD 0.30', 'USD 1,234.50', 'EUR 999,999,999,999,999.99', '12.00', 'USD 864.15', '—', '—', '—', 'NOK 1,000,000.00'])

    def row(self, **kw):
        return dict({'name': 'nginx', 'installed': 4, 'owned': 3, 'shortfall': 1, 'surplus': 0, 'unit_cost': '49.99', 'shortfall_cost': '49.99', 'surplus_cost': '0.00',
                     'reclaimable': 2}, **kw)

    def test_the_columns_are_the_ones_of_the_table_in_its_order_with_the_amounts_as_numbers(self):
        got = _run('console.log(JSON.stringify([_meterColumns(%s, "USD"), _meterColumns(%s, "")]));' % (json.dumps(self.row()), json.dumps(self.row())))
        self.assertEqual(list(got[0]), ['software', 'installed', 'owned', 'unit_cost', 'shortfall', 'shortfall_cost', 'surplus', 'surplus_cost', 'reclaim', 'currency'])
        self.assertEqual(got[0], {'software': 'nginx', 'installed': 4, 'owned': 3, 'unit_cost': 49.99, 'shortfall': 1, 'shortfall_cost': 49.99, 'surplus': 0,
                                  'surplus_cost': 0, 'reclaim': 2, 'currency': 'USD'})
        self.assertEqual(list(got[1]), ['software', 'installed', 'owned', 'shortfall', 'surplus', 'reclaim'], 'no currency from the server: no cost column and no currency column')

    def test_a_rule_with_no_cost_or_nothing_owned_is_empty_in_those_cells_and_not_zero(self):
        row = self.row(owned=None, shortfall=None, surplus=None, unit_cost=None, shortfall_cost=None, surplus_cost=None)
        got = _run('console.log(JSON.stringify(_meterColumns(%s, "USD")));' % json.dumps(row))
        self.assertEqual({k: v for k, v in got.items() if k not in ('software', 'installed', 'reclaim', 'currency')}, dict.fromkeys(
            ('owned', 'unit_cost', 'shortfall', 'shortfall_cost', 'surplus', 'surplus_cost')))
        zero = self.row(unit_cost='0.00', shortfall_cost='0.00', surplus_cost='0.00', shortfall=0, surplus=0)
        got = _run('console.log(JSON.stringify(_meterColumns(%s, "USD")));' % json.dumps(zero))
        self.assertEqual((got['unit_cost'], got['shortfall_cost'], got['shortfall']), (0, 0, 0), 'a rule that is free is 0, and sorts as 0')

    def test_the_csv_the_export_builds_has_the_header_and_the_rows_and_quotes_what_a_spreadsheet_would_run(self):
        # exportCsv takes its columns from the keys of the first projected row and writes each cell with the page's own _csvCell
        src = srcpin.js_function(_APP, 'exportCsv')
        self.assertIn('Object.keys(proj(rows[0]))', src)
        self.assertIn('const esc = _csvCell;', src)
        self.assertIn('esc(rec[c])', src)
        rows = [self.row(), self.row(name='=HYPERLINK("x")', installed=1, owned=None, shortfall=None, surplus=None, unit_cost=None, shortfall_cost=None, surplus_cost=None),
                self.row(name='a,b "c"', unit_cost='0.10', surplus_cost='0.30')]
        script = ('const rows = %s;\nconst proj = r => _meterColumns(r, "USD");\nconst cols = Object.keys(proj(rows[0]));\nconst lines = [cols.join(",")];\n'
                  'for (const r of rows) { const rec = proj(r); lines.push(cols.map(c => _csvCell(rec[c])).join(",")); }\nconsole.log(JSON.stringify(lines));' % json.dumps(rows))
        lines = _run(script)
        self.assertEqual(lines[0], 'software,installed,owned,unit_cost,shortfall,shortfall_cost,surplus,surplus_cost,reclaim,currency')
        self.assertEqual(lines[1], 'nginx,4,3,49.99,1,49.99,0,0,2,USD')
        self.assertEqual(lines[2], '"\'=HYPERLINK(""x"")",1,,,,,,,2,USD')
        self.assertEqual(lines[3], '"a,b ""c""",4,3,0.1,1,49.99,0,0.3,2,USD')


if __name__ == '__main__':
    unittest.main()
