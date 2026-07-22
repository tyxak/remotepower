"""A page whose renderer lives in a LAZY module must register that module.

`_LAZY_PAGE_MODULES` in app.js maps page → the JS files to fetch before the page
is shown. `showPage()` then calls the page's loader directly. If the loader
lives in a lazy module the page never declared, that call is a straight
`ReferenceError` — and because `showPage` is one long `if` chain, everything
after the throwing line is skipped too.

That shipped: the Security Advisory page called `advScopeChanged()` (defined in
app-checks.js) with no `advisory:` entry, so navigating to it threw and left the
page inert. This is the same "touch two registries" shape as FLEET_EVENTS and
the scheduler CADENCE tuple — the code looks complete in review because both
halves exist, just not wired to each other.
"""

import re
import unittest
from pathlib import Path

_JS = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js'
_APP = _JS / 'app.js'


def _lazy_map():
    """{page: [file, …]} parsed out of the _LAZY_PAGE_MODULES literal."""
    src = _APP.read_text(encoding='utf-8')
    i = src.index('const _LAZY_PAGE_MODULES = {')
    block = src[i:src.index('\n};', i)]
    out = {}
    for page, files in re.findall(r"^\s*'?([\w-]+)'?:\s*\[([^\]]*)\]", block, re.M):
        out[page] = re.findall(r"'([^']+)'", files)
    return out


def _lazy_files():
    return {f for files in _lazy_map().values() for f in files}


def _defined_in(file_path):
    """Top-level function names declared in a script."""
    return set(re.findall(r'^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)',
                          file_path.read_text(encoding='utf-8'), re.M))


def _showpage_calls():
    """[(page, fn), …] for every `if (name === 'page') fn(...)` in showPage.

    Covers the braced form too (`{ loadProtectChecks(); loadGuardVault(); }`),
    which is where a second, unregistered call is easiest to miss.
    """
    src = _APP.read_text(encoding='utf-8')
    i = src.index('function showPage(')
    body = src[i:i + 12000]
    out = []
    for page, tail in re.findall(
            r"if\s*\(name\s*===\s*'([\w-]+)'\)\s*(\{[^}]*\}|[^\n]*)", body):
        for fn in re.findall(r'([A-Za-z_$][\w$]*)\s*\(', tail):
            if fn not in ('if', 'for', 'while', 'return', 'typeof'):
                out.append((page, fn))
    return out


class TestLazyPageModulesAreRegistered(unittest.TestCase):
    def setUp(self):
        self.lazy_map = _lazy_map()
        self.lazy_files = _lazy_files()
        self.owner = {}          # fn -> lazy file that defines it
        for f in sorted(self.lazy_files):
            path = _JS / f
            if path.exists():
                for fn in _defined_in(path):
                    self.owner.setdefault(fn, f)
        self.calls = _showpage_calls()

    def test_the_parsers_actually_find_things(self):
        """A guardrail that matches nothing passes forever."""
        self.assertGreater(len(self.lazy_map), 10)
        self.assertGreater(len(self.calls), 30)
        self.assertGreater(len(self.owner), 50)
        self.assertIn(('scans', 'loadScans'), self.calls)
        self.assertIn('app-checks.js', self.lazy_files)

    def test_every_lazy_module_file_exists(self):
        missing = sorted(f for f in self.lazy_files if not (_JS / f).exists())
        self.assertEqual(missing, [], f'_LAZY_PAGE_MODULES names missing files: {missing}')

    def test_showpage_never_calls_an_unregistered_lazy_function(self):
        app_fns = _defined_in(_APP)
        bad = []
        for page, fn in self.calls:
            if fn in app_fns:
                continue                      # eager: always available
            home = self.owner.get(fn)
            if home and home not in self.lazy_map.get(page, []):
                bad.append(f'page {page!r} calls {fn}() from {home}, which it '
                           f'does not list in _LAZY_PAGE_MODULES '
                           f'(has: {self.lazy_map.get(page, [])})')
        self.assertEqual(bad, [], 'ReferenceError on navigation:\n  ' + '\n  '.join(bad))

    def test_the_advisory_regression_stays_fixed(self):
        self.assertIn('app-checks.js', self.lazy_map.get('advisory', []))
        self.assertIn('advScopeChanged', self.owner)

    def test_a_missing_handler_is_not_swallowed_silently(self):
        """Both delegated dispatchers must try a lazy load and then say
        something — a silent `return` is what made a whole page look dead."""
        src = _APP.read_text(encoding='utf-8')
        self.assertEqual(src.count("console.warn('[rp] no handler for"), 3)
        i = src.index("const fn = window[btnEl.dataset.actionBtn];")
        self.assertIn('_loadAllLazyJs', src[i:i + 600],
                      'data-action-btn must recover like data-action does')


if __name__ == '__main__':
    unittest.main()
