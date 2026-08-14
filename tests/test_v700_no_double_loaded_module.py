#!/usr/bin/env python3
"""A JS module must not be BOTH eagerly loaded and in the lazy-load map.

These are classic scripts sharing one global scope, so loading a file twice
re-executes its top level, and a second `const` at top level is a SyntaxError:

    Uncaught SyntaxError: Identifier '_SELF_STATE_ICO' has already been declared

Everything the file declared on the first pass still exists, so the page mostly
works and the only evidence is a console error. That is exactly how it happened:
the Autonomy page's renderer was added to `app-self.js`, and `app-self.js` was
then added to the lazy map for that page — except app-self.js is EAGER on
purpose (app-backups.js calls into it from a different page, so it cannot be
keyed on navigation), and index.html already ships it as a deferred script.

Source review did not catch it. A browser did, immediately.

The rule is mechanical and cheap to check, so it should not depend on anyone
remembering which modules are eager: any file named in a `<script src>` in a
served HTML surface must not also appear in app.js's lazy-module map.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / 'server' / 'html'
_APP = _HTML / 'static' / 'js' / 'app.js'


def _eager_modules():
    """Every static/js file pulled in by a <script src> in a served page."""
    out = set()
    for page in sorted(_HTML.glob('*.html')):
        for m in re.finditer(r'<script[^>]+src="static/js/([A-Za-z0-9_.-]+\.js)',
                             page.read_text(encoding='utf-8')):
            out.add(m.group(1))
    return out


def _lazy_map():
    """page -> [module, …] from app.js's lazy-module table."""
    src = _APP.read_text(encoding='utf-8')
    m = re.search(r'const _PAGE_JS\s*=\s*\{(.*?)\n\};', src, re.S) or \
        re.search(r'_PAGE_JS\s*=\s*\{(.*?)\n\};', src, re.S)
    if not m:
        # Fall back to any object literal whose values are app-*.js lists.
        pairs = re.findall(r"^\s*([a-z][\w]*):\s*\[([^\]]*\.js[^\]]*)\],",
                           src, re.M)
    else:
        pairs = re.findall(r"^\s*([a-z][\w]*):\s*\[([^\]]*)\],", m.group(1), re.M)
    out = {}
    for page, body in pairs:
        mods = re.findall(r"'([A-Za-z0-9_.-]+\.js)'", body)
        if mods:
            out.setdefault(page, []).extend(mods)
    return out


class TestTheScanWorks(unittest.TestCase):
    """The assertion below is 'the overlap is empty', which a broken parse
    produces just as happily."""

    def test_it_finds_eager_scripts(self):
        eager = _eager_modules()
        self.assertGreater(len(eager), 5, f'parsed almost no eager scripts: {eager}')
        self.assertIn('app.js', eager)

    def test_it_finds_the_lazy_map(self):
        lazy = _lazy_map()
        self.assertGreater(len(lazy), 5, f'parsed almost no lazy pages: {lazy}')
        flat = {m for mods in lazy.values() for m in mods}
        self.assertTrue(any(m.startswith('app-') for m in flat), flat)

    def test_app_self_is_eager(self):
        """The specific file this rule was written for. If it ever stops being
        eager the overlap check below still holds, but this pins the premise."""
        self.assertIn('app-self.js', _eager_modules())


class TestNoModuleIsLoadedTwice(unittest.TestCase):

    def test_no_eager_module_is_also_lazy(self):
        eager = _eager_modules()
        lazy = _lazy_map()
        clashes = sorted({(page, mod) for page, mods in lazy.items()
                          for mod in mods if mod in eager})
        self.assertEqual(
            clashes, [],
            'these modules are loaded eagerly by a served page AND listed in '
            'app.js\'s lazy map, so navigating to that page re-executes their '
            'top level and every top-level const throws '
            '"already been declared":\n'
            + '\n'.join(f'  page {p!r} -> {m}' for p, m in clashes)
            + '\nPut the renderer in a lazy module, or drop the lazy entry — '
              'an eager module is already there when the page opens.')


if __name__ == '__main__':
    unittest.main()
