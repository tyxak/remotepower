#!/usr/bin/env python3
"""8.0.0: a CSV the page builds does not run as a formula when a spreadsheet opens it.

A cell that starts with = + - or @ (or a tab or a carriage return, which a spreadsheet strips back to one of them) is a formula to Excel, Sheets and LibreOffice, and the
text of a cell can come from a host: a program name, a host name, a process. Every export the SERVER builds quotes such a cell with a leading ' (api._csv_safe). The two
builders in the page, the table export of tableCtl and the metric explorer's, did not: a program called =HYPERLINK(...) ran when the file was opened.

This holds three things, each from the population and not from a list of names:
  * the helper the page uses (`_csvCell`, run under node) gives the same cell as the server's rule followed by the csv module, for every kind of cell;
  * every function in the page's scripts that builds a text/csv blob calls it (found by what it outputs, so a third builder cannot be added without it);
  * every csv writer call on the server either guards its cells or writes a heading the code defines (an exemption that stops applying fails, so the list only shrinks).
"""
import ast
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-csv-guard-'))
import srcpin  # noqa: E402

_NODE = shutil.which('node')

HOSTILE = ['=HYPERLINK("http://attacker.example","x")', '+1+1', '-2+3', '@SUM(1,1)', '\t=1+1', '\r=1+1', '=cmd|\' /C calc\'!A0', '=1,2', '"=quoted"', "'=already", ' =leading space',
           'plain', 'with, comma', 'with "quote"', 'two\nlines', 'ends with =', 'a-b', 'x+y', 'user@example.com', '0', '12', '1.5']


_API = []


def _cell_by_the_server(value):
    """One cell as the server writes it: its own rule, then the csv module."""
    if not _API:
        import importlib.util
        spec = importlib.util.spec_from_file_location('api_csv_guard', _CGI / 'api.py')
        mod = importlib.util.module_from_spec(spec)           # type: ignore[arg-type]
        spec.loader.exec_module(mod)                            # type: ignore[union-attr]
        _API.append(mod)
    buf = io.StringIO()
    csv.writer(buf, lineterminator='').writerow([_API[0]._csv_safe(value)])
    return buf.getvalue()


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheCellHelper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        body = srcpin.js_function((_JS / 'app.js').read_text(), '_csvCell')
        script = body + '\nconst cases = JSON.parse(process.argv[1]);\nconsole.log(JSON.stringify(cases.map(c => _csvCell(c)).concat([_csvCell(undefined), _csvCell(null)])));\n'
        cls.cells = staticmethod(lambda cases: json.loads(subprocess.run([_NODE, '-e', script, json.dumps(cases)], capture_output=True, text=True, check=True).stdout))

    def test_a_cell_the_server_would_quote_is_quoted_the_same_way(self):
        got = self.cells(HOSTILE)
        for value, cell in zip(HOSTILE, got):
            self.assertEqual(cell, _cell_by_the_server(value), repr(value))

    def test_a_formula_is_text_in_the_file(self):
        got = dict(zip(HOSTILE, self.cells(HOSTILE)))
        for value in ('=HYPERLINK("http://attacker.example","x")', '+1+1', '-2+3', '@SUM(1,1)', '\t=1+1', '\r=1+1'):
            parsed = list(csv.reader(io.StringIO(got[value])))[0][0]
            self.assertEqual(parsed, "'" + value, repr(value))
        for value in ('plain', 'a-b', 'x+y', 'user@example.com', 'ends with =', '0', '12'):
            self.assertEqual(got[value], value, 'a cell that does not start with one of the four is written as it is: %r' % value)

    def test_a_number_is_not_text_and_is_written_as_it_is_including_a_negative_one(self):
        got = self.cells([0, 5, -5, 1.5, -0.25, 1e21, -1e-7])
        self.assertEqual(got[:7], ['0', '5', '-5', '1.5', '-0.25', '1e+21', '-1e-7'], 'a negative number is a number: a leading minus is only a formula in text')

    def test_nothing_is_an_empty_cell(self):
        got = self.cells([])
        self.assertEqual(got, ['', ''], 'undefined and null')


class TestEveryClientBuilderUsesIt(unittest.TestCase):

    @staticmethod
    def builders():
        out = []
        for path in sorted(_JS.glob('*.js')):
            if path.name.startswith('i18n') or 'vendor' in str(path):
                continue
            src = path.read_text()
            for name in sorted(set(re.findall(r'\bfunction\s+([A-Za-z_$][\w$]*)\s*\(', src))):
                try:
                    body = srcpin.js_function(src, name)
                except Exception:
                    continue
                if 'text/csv' in body:
                    out.append((path.name, name, body))
        return out

    def test_the_population_is_the_two_builders_the_page_has(self):
        names = {(f, n) for f, n, _b in self.builders()}
        self.assertIn(('app.js', 'exportCsv'), names, 'control: the detector finds the table export')
        self.assertIn(('app-trends.js', 'exportMetricExplorerCsv'), names, 'control: and the metric explorer\'s')

    def test_each_of_them_writes_its_cells_through_the_helper(self):
        for fname, name, body in self.builders():
            self.assertIn('_csvCell', body, '%s in %s builds a CSV and does not write its cells through _csvCell' % (name, fname))


class TestEveryServerWriterIsGuardedOrWritesAHeading(unittest.TestCase):

    # (file, function, how the call starts): why the unguarded call is fine. Keyed by the call and not by the function, because a function that writes a heading and then rows has
    # a guarded call and an unguarded one, and an exemption for the function would hide the rows losing their guard. A heading is column names the code defines, never a value
    # from a host.
    EXEMPT = {
        ('api.py', '_csv_emit', 'w.writerow(header)'): 'the header row the caller passes: column names the code defines',
        ('api.py', '_fleet_query_bytes', 'w.writerow([label for _k, label in cols])'): 'the labels of the columns the query builds, from a table in the code',
        ('api.py', 'handle_patch_report_csv', "writer.writerow(['Host', 'Hostname', 'Group', 'OS'"): 'a literal list of column names',
    }

    @staticmethod
    def calls():
        out = []
        for path in sorted(_CGI.glob('*.py')):
            src = path.read_text()
            if 'writerow' not in src:
                continue
            tree = ast.parse(src)
            seen = set()
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('writerow', 'writerows') and node.lineno not in seen:
                        seen.add(node.lineno)
                        seg = ast.get_source_segment(src, node) or ''
                        out.append((path.name, fn.name, node.lineno, '_csv_safe' in seg, seg))
        return out

    def test_the_population_is_not_empty(self):
        calls = self.calls()
        self.assertGreaterEqual(len(calls), 7, 'control: the scan found the writers')
        self.assertGreaterEqual(sum(1 for c in calls if c[3]), 4, 'control: and the guarded ones')
        self.assertIn(('reports_handlers.py', '_fleet_report_csv_bytes', True), {(f, fn, ok) for f, fn, _l, ok, _s in calls}, 'control: a writer in a bound module is found and is guarded')

    def test_every_call_guards_its_cells_or_is_listed_with_its_reason(self):
        unguarded = [(f, fn, seg) for f, fn, _l, ok, seg in self.calls() if not ok]
        matched, unmatched = set(), []
        for f, fn, seg in unguarded:
            hit = [k for k in self.EXEMPT if k[0] == f and k[1] == fn and seg.startswith(k[2])]
            if hit:
                matched.add(hit[0])
            else:
                unmatched.append((f, fn, seg[:90]))
        self.assertEqual(unmatched, [], 'a csv writer call whose cells do not go through _csv_safe: a value from a host that starts with = runs as a formula')
        self.assertEqual(sorted(set(self.EXEMPT) - matched), [], 'an exemption that no longer applies: delete it, the list only shrinks')


if __name__ == '__main__':
    unittest.main()
