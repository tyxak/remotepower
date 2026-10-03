"""The size table in docs/internals.md has to stay near the code.

The page quoted three different sizes for the same thing: ~113,000 lines of server
Python in the intro, ~132,000 in the table, and api.py at ~67k in one bullet and
~74,000 in the table. Nobody re-counts when a file grows, so each number was true
on the day it was written and then drifted apart.

The prose copies are gone and the table is the only place the numbers live. This
asks the code for each one and fails when the document is more than 6% away. The
slack is on purpose: the figures are written with "~", and a release that adds a
handler or two should not fail a documentation test. A table that has fallen 6%
behind is out of date and should be refreshed.

Narrow by design, like test_v702_doc_counts: only counts that can be derived from
the tree without judgement.
"""
import importlib.util
import inspect
import os
import pathlib
import re
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_DOC = _ROOT / 'docs' / 'internals.md'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v710ic-'))
sys.path.insert(0, str(_CGI))

TOLERANCE = 0.06


def within(claimed, actual, tolerance=TOLERANCE):
    """True when `claimed` is no more than `tolerance` away from `actual`."""
    return abs(claimed - actual) <= tolerance * actual


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _lines(paths):
    return sum(len(p.read_text(encoding='utf-8', errors='replace').splitlines()) for p in paths)


def _numbers(cell):
    """Every integer in a table cell or sentence ('~501 exact, ~428 pattern' -> [501, 428])."""
    return [int(n.replace(',', '')) for n in re.findall(r'\d[\d,]*', cell)]


def _table():
    """{row label: cell text} for the 'By the numbers' table."""
    text = _DOC.read_text(encoding='utf-8')
    block = text[text.index('By the numbers'):]
    block = block[:block.index('\n---')]
    rows = {}
    for line in block.splitlines():
        m = re.match(r'\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$', line)
        if m and not set(m.group(1)) <= set('-: ') and m.group(1) != 'Thing':
            rows[m.group(1)] = m.group(2)
    return rows


@unittest.skipUnless(_DOC.exists(), 'docs/internals.md is not in this tree')
class TestInternalsSizeTableIsCurrent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rows = _table()
        cls.api = _load('api_v710ic', _CGI / 'api.py')
        cls.scheduler = _load('scheduler_v710ic', _CGI / 'scheduler.py')
        cls.request_models = _load('request_models_v710ic', _CGI / 'request_models.py')

    def _row(self, prefix):
        hits = [v for k, v in self.rows.items() if k.startswith(prefix)]
        self.assertEqual(len(hits), 1, f'no unique "{prefix}" row in the table: {sorted(self.rows)}')
        return hits[0]

    def _check(self, prefix, actuals):
        claimed = _numbers(self._row(prefix))
        self.assertEqual(len(claimed), len(actuals), f'{prefix}: expected {len(actuals)} figure(s) in {claimed}')
        off = [(c, a) for c, a in zip(claimed, actuals) if not within(c, a)]
        self.assertEqual(off, [], f'docs/internals.md "{prefix}" says {claimed}; the code measures {actuals}. '
                                  f'Update the table (the figures are written with "~", so round them).')

    def test_the_table_was_parsed(self):
        """Control: an empty parse would make every assertion below vacuous."""
        self.assertGreaterEqual(len(self.rows), 9, sorted(self.rows))

    def test_server_python_lines(self):
        self._check('Server Python', [_lines(sorted(_CGI.glob('*.py')))])

    def test_api_module_lines(self):
        self._check('The main API module', [_lines([_CGI / 'api.py'])])

    def test_sibling_modules(self):
        self._check('Focused sibling modules', [len([p for p in _CGI.glob('*.py') if p.name != 'api.py'])])

    def test_routes(self):
        self._check('HTTP routes', [len(self.api._build_exact_routes()), len(self.api._dispatcher_routes())])

    def test_handlers(self):
        n = sum(len(re.findall(r'^\s*(?:async )?def handle_\w+', p.read_text(errors='replace'), re.M))
                for p in _CGI.glob('*.py'))
        self._check('Request handlers', [n])

    def test_request_models(self):
        from pydantic import BaseModel
        mod = self.request_models
        n = len([c for _n, c in inspect.getmembers(mod, inspect.isclass)
                 if issubclass(c, BaseModel) and c is not BaseModel and c.__module__ == mod.__name__])
        self._check('Typed request-body models', [n])

    def test_maintenance_sweeps(self):
        self._check('Background maintenance sweeps', [len(self.scheduler.CADENCE)])

    def test_frontend_js_files(self):
        self._check('Frontend JS files', [len(list(_JS.glob('*.js')))])

    def test_the_frontend_paragraph(self):
        """index.html, app.js and the supporting modules, quoted in 'The frontend' section."""
        text = _DOC.read_text(encoding='utf-8')
        m = re.search(r'one `index\.html` \(~([\d,]+) lines\), one main `app\.js` \(~([\d,]+)\s+lines\), '
                      r'and ~(\d+) supporting JS modules', text)
        self.assertTrue(m, 'the frontend sentence changed shape; update this pattern with it')
        claimed = [int(g.replace(',', '')) for g in m.groups()]
        actual = [_lines([_ROOT / 'server/html/index.html']), _lines([_JS / 'app.js']),
                  len(list(_JS.glob('*.js'))) - 1]
        off = [(c, a) for c, a in zip(claimed, actual) if not within(c, a)]
        self.assertEqual(off, [], f'frontend paragraph says {claimed}; the tree measures {actual}')

    def test_the_comparison_can_say_no(self):
        """Control on the rule itself: a figure 20% off must fail, and one 3% off must pass."""
        self.assertFalse(within(700, 870))
        self.assertTrue(within(857, 870))
        self.assertFalse(within(1.07 * 870, 870))


if __name__ == '__main__':
    unittest.main()
