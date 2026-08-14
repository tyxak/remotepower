#!/usr/bin/env python3
"""Eager code must not read a lazy module's top-level bindings.

These are classic scripts sharing one global scope, so a lazy module's
`let _alertsCache = []` is simply absent until that module loads. Eager code
touching it does not degrade — it throws `ReferenceError` and takes down
whatever was running.

That shipped. Making app-alerts.js lazy left `openCommandPalette` reading
`_alertsCache`, so the command palette — reachable from every page with Ctrl-K —
threw on every page until the operator happened to visit Alerts. The full gate
caught it; review did not, because the check I ran by hand enumerated FUNCTION
names and never looked at variables.

WHY FUNCTIONS ARE DIFFERENT FROM VARIABLES, and why this file cares mostly about
the second:

* A `data-action="someLazyFn"` is safe — the dispatcher loads the remaining
  modules and replays the click when the handler is missing.
* A page-scoped call like `if (name === 'alerts') loadAlerts()` is safe —
  `showPage` awaits that page's modules first.
* A bare variable read has no such net. Nothing catches it, and it throws.

So a reference to a lazy module's function is reported only when it is a DIRECT
call from eager code with no guard, while any reference to a lazy module's
variable is reported unless it is guarded with `typeof`.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_APP = (_JS / 'app.js').read_text(encoding='utf-8')

# NO name-level exemption list. There was one, and the fail-demo showed it was
# worthless: exempting `_alertsCache` by NAME meant the scan skipped every read
# of it, including the unguarded one that caused the outage. Restoring the
# original bug left the gate green.
#
# The guard is STRUCTURAL instead: a read is safe when the function containing
# it also contains `typeof <name>`. That covers the real pattern — an accessor
# that checks once and then uses the binding freely — and cannot be satisfied by
# adding a name to a list.


def _lazy_modules():
    """Files in app.js's lazy maps and NOT boot-loaded by a served page."""
    out = set()
    for marker, end in (('_LAZY_PAGE_MODULES = {', '};'),
                        ('_LAZY_NON_PAGE_MODULES = [', '];')):
        if marker not in _APP:
            continue
        blk = _APP[_APP.index(marker):]
        out |= set(re.findall(r"'([a-z-]+\.js)'", blk[:blk.index(end)]))
    return {f for f in out if f'static/js/{f}?' not in _HTML}


def _top_level_bindings(src):
    """Names a module puts into the shared global scope."""
    names = set(re.findall(r'^(?:let|const|var)\s+([A-Za-z_$][\w$]*)', src, re.M))
    fns = set(re.findall(r'^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)', src, re.M))
    return names, fns


def _code_lines(src):
    """(lineno, text) for lines that are not comments."""
    out = []
    for i, line in enumerate(src.split('\n'), 1):
        t = line.strip()
        if t.startswith('//') or t.startswith('*') or t.startswith('/*'):
            continue
        out.append((i, line))
    return out


def _guarded_at(src, name, lineno):
    """Is the read on `lineno` inside a function that typeof-guards `name`?

    Scoped deliberately. A `typeof` anywhere in the file excusing a read
    anywhere else would repeat the name-list mistake with extra steps.
    """
    lines = src.split('\n')
    start = 0
    for i in range(min(lineno, len(lines)) - 1, -1, -1):
        t = lines[i].lstrip()
        if t.startswith('function ') or t.startswith('async function '):
            start = i
            break
    end = len(lines)
    for i in range(lineno, len(lines)):
        t = lines[i]
        if t.startswith('function ') or t.startswith('async function '):
            end = i
            break
    return f'typeof {name}' in '\n'.join(lines[start:end])


class TestTheScanWorks(unittest.TestCase):
    """The assertion below is "this list is empty", which a scan that finds no
    lazy modules produces just as happily."""

    def test_there_are_lazy_modules(self):
        lz = _lazy_modules()
        self.assertGreaterEqual(len(lz), 2, f'only found {lz}')
        self.assertIn('app-alerts.js', lz)

    def test_it_finds_their_bindings(self):
        v, f = _top_level_bindings((_JS / 'app-alerts.js').read_text(encoding='utf-8'))
        self.assertIn('_alertsCache', v)
        self.assertIn('loadAlerts', f)

    def test_it_would_catch_an_unguarded_read(self):
        """Positive control on the matcher itself."""
        pat = re.compile(r'(?<![\w$.])_alertsCache(?![\w$])')
        self.assertTrue(pat.search('for (const a of (_alertsCache || [])) {'))
        self.assertFalse(pat.search('this._alertsCache = 1;'))


class TestNoEagerReadOfALazyBinding(unittest.TestCase):

    def test_no_unguarded_variable_reads(self):
        bad = []
        for mod in sorted(_lazy_modules()):
            src = (_JS / mod).read_text(encoding='utf-8')
            variables, _fns = _top_level_bindings(src)
            for name in sorted(variables):
                pat = re.compile(r'(?<![\w$.])' + re.escape(name) + r'(?![\w$])')
                for ln, line in _code_lines(_APP):
                    if not pat.search(line):
                        continue
                    if _guarded_at(_APP, name, ln):
                        continue
                    bad.append(f'{name} ({mod}) at app.js:{ln}: {line.strip()[:70]}')
                    break
        self.assertEqual(
            sorted(bad), [],
            "eager code reads a LAZY module's top-level variable. That binding "
            'does not exist until the module loads, so this throws '
            'ReferenceError rather than degrading — it took down the whole '
            'command palette once:\n' + '\n'.join('  ' + b for b in sorted(bad)))

    def test_the_guard_detection_is_scoped_not_global(self):
        """A `typeof` anywhere in the file must NOT excuse a read elsewhere —
        that is the same mistake the name list made, one level down."""
        src = ('function safe() {\n'
               '  if (typeof _x !== "undefined") return _x;\n'
               '}\n'
               'function unsafe() {\n'
               '  return _x.length;\n'
               '}\n')
        self.assertTrue(_guarded_at(src, '_x', 2))
        self.assertFalse(_guarded_at(src, '_x', 5),
                         'a typeof in a DIFFERENT function was accepted')


if __name__ == '__main__':
    unittest.main()
