#!/usr/bin/env python3
"""Shrink-only ratchet on fixed-size source windows in the test suite.

THE PATTERN THIS BOUNDS
-----------------------
A test that pins a region of api.py / app.js by slicing a fixed number of
characters from an anchor:

    i = js.index('function showPage(')
    self.assertIn('page-devices', js[i:i + N])     # N a literal, e.g. 5600

The window is a guess about how long the code around the anchor happens to be.
Add an event to a registry above the assertion target and the region silently
grows past the window — so the pin either fails for a reason unrelated to what
it tests, or, worse, keeps passing while no longer covering the thing it names.

tests/srcpin.py exists precisely to kill this: `py_function`, `js_function` and
`balanced_block` extract the ENCLOSING CONSTRUCT, so they cannot truncate.
CLAUDE.md's v6.2.3 note says the fixed windows "were all migrated to srcpin"
and that new pins must use it. That did not hold — several test_v642_* files
carry windows written after the migration, and `git log -S widen -- tests/`
shows the churn is ongoing, with a commit the day before this ratchet landed.
Documentation asked; it did not enforce. This enforces.

WHY THE ASSERTNOTIN CASE IS THE SHARP EDGE
------------------------------------------
    self.assertNotIn('badthing', src[i:i + N])

If the region shifts or shrinks past the target, this passes while asserting
nothing at all — a member of the false-green family CLAUDE.md documents three
of, with an extra failure mode bolted on. Those are listed separately below so
they can be converted first.

DELIBERATELY NARROW so it stays worth having: only a NUMERIC literal of 1000+
in an `[x:x + N]` slice trips it. Smaller windows are usually tight enough to
fail loudly rather than silently, and a gate that flags borderline cases gets
switched off — taking the real signal with it.

WHAT IS LEFT, AND WHY IT IS NOT ZERO
------------------------------------
91 windows were converted down to 16 in one pass. The remainder are NOT
oversights — every one was examined and left deliberately, in three classes:

  * NOT PYTHON OR JAVASCRIPT. srcpin's brace scanner understands `//` and
    `/* */` comments only, so on a shell script a `#` comment containing an
    apostrophe opens a phantom string and the scan runs past the closing
    brace — measured at 9,278 chars returned for a 672-char bash function.
    Converting those would replace a fixed window with a silently OVER-broad
    one, which is worse. Same for HTML elements (html_page only extracts
    `<div id="page-X" class="page">` sections, not arbitrary modals) and
    Makefile recipes (no delimiters to balance).
  * ANCHORED ON A BARE STATEMENT INSIDE A HUGE FUNCTION. A window anchored on
    `if 'containers' in body:` sits inside handle_heartbeat — 137,824 chars.
    Extracting the enclosing construct is technically a conversion and
    practically an assertion over the whole file.
  * PROXIMITY WINDOWS. `src[i - 120:i + 120]` asserts that two things are NEAR
    each other; that is the actual contract, and srcpin cannot express it.

So the honest floor is somewhere near 16, not 0. Lower the ceiling when a
window genuinely converts; do not chase the number.
"""
import ast
import io
import re
import tokenize
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent

# `[i:i + 4000]`, `[start:start+12000]`, `[a : a + 2200]` — an anchored window
# whose length is a hardcoded guess. A variable length (`[i:i + span]`) is fine:
# it is not a magic number and usually IS computed from the content.
_WINDOW = re.compile(r'\[\s*[A-Za-z_][A-Za-z_0-9]*\s*:\s*[A-Za-z_][A-Za-z_0-9]*\s*\+\s*(\d+)\s*\]')

MIN_WIDTH = 1000

# Current count. LOWER THIS as windows are converted; never raise it. Adding a
# new fixed window is not a "bump the number" situation — use srcpin instead.
WINDOW_CEILING = 15


def _code_only(path):
    """The file's lines with comments and string literals blanked out.

    Without this the scan counts its own documentation: srcpin.py's module
    docstring quotes the very pattern it exists to replace, and this file's
    docstring has to show the shape too. A gate that reports things that are
    not the problem is a gate someone eventually switches off — and it takes
    the real findings with it. Blanking is per-character so column offsets (and
    therefore line content around a real match) are preserved.
    """
    src = path.read_text()
    rows = [list(line) for line in src.splitlines()]
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type not in (tokenize.COMMENT, tokenize.STRING):
                continue
            (sr, sc), (er, ec) = tok.start, tok.end
            for r in range(sr, min(er, len(rows)) + 1):
                if r - 1 >= len(rows):
                    break
                row = rows[r - 1]
                a = sc if r == sr else 0
                b = ec if r == er else len(row)
                for c in range(a, min(b, len(row))):
                    row[c] = ' '
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass  # unparseable: fall back to the raw text rather than skipping
    return [''.join(r) for r in rows]


def _windows():
    """(path, lineno, width, has_assertnotin_nearby) for every fixed window."""
    found = []
    for path in sorted(TESTS.glob('*.py')):
        code = _code_only(path)
        raw = path.read_text().splitlines()
        for n, line in enumerate(code, start=1):
            for m in _WINDOW.finditer(line):
                width = int(m.group(1))
                if width < MIN_WIDTH:
                    continue
                nearby = '\n'.join(raw[n - 1:n + 30])
                found.append((path.name, n, width, 'assertNotIn' in nearby))
    return found


class TestFixedSourceWindowRatchet(unittest.TestCase):
    def test_no_new_fixed_source_windows(self):
        found = _windows()
        n = len(found)
        if n > WINDOW_CEILING:
            worst = '\n'.join(f'    {f}:{ln}  [{w} chars]'
                              for f, ln, w, _ in sorted(found, key=lambda r: -r[2])[:10])
            self.fail(
                f'{n} fixed source windows in tests/ (ceiling {WINDOW_CEILING}).\n'
                f'A fixed [i:i + N] window is a guess about how long the '
                f'surrounding code is; it silently stops covering its target '
                f'when the region grows. Use tests/srcpin.py instead:\n'
                f"    from srcpin import py_function, js_function, balanced_block\n"
                f"    body = js_function(client_js(), '_renderHomeActivity')\n"
                f'Widest windows currently present:\n{worst}')

    def test_ceiling_tracks_the_real_count(self):
        """Shrink-only: converting windows must be matched by lowering the
        ceiling, or the ratchet loosens and quietly stops nudging. Same shape
        as tests/test_api_module_ratchet.py's slack check, which is the idiom
        this repo already trusts. Buffer of 3 tolerates an in-flight batch."""
        n = len(_windows())
        self.assertGreaterEqual(
            WINDOW_CEILING, n,
            'ceiling below the real count — a fixed window was added')
        self.assertLessEqual(
            WINDOW_CEILING - n, 3,
            f'ceiling ({WINDOW_CEILING}) is {WINDOW_CEILING - n} above the real '
            f'count ({n}) — you converted windows but did not tighten the '
            f'ratchet. Lower WINDOW_CEILING to {n}.')


def _file_prefix_windows():
    """`somefile.read_text()[:N]` — the OTHER shape of the same mistake.

    Found the hard way. This ratchet originally matched only `[x:x + N]`, so it
    did not see `CHANGELOG.md.read_text()[:2000]` — and the very commit that
    introduced the ratchet added three CHANGELOG entries, pushed the version
    header past character 2000, and broke that assertion in 21 files at once.
    Same failure mode exactly: content grows above the target, the fixed count
    stops reaching it.

    AST-based and deliberately narrow — it fires only on a slice of a
    `read_text()` result (directly, or through a variable assigned from one in
    the same file), never on ordinary truncation like `proc.stdout[:1000]` in
    an error message. Bound a file read by its CONTENT (find the header, split
    on the marker), never by a character count.
    """
    hits = []
    for path in sorted(TESTS.glob('*.py')):
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue

        def _is_read_text(node):
            return (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'read_text')

        # names bound to a read_text() result anywhere in this file
        from_read = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _is_read_text(node.value):
                from_read.update(t.id for t in node.targets if isinstance(t, ast.Name))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Subscript) or not isinstance(node.slice, ast.Slice):
                continue
            sl = node.slice
            if sl.lower is not None or sl.step is not None:
                continue
            if not (isinstance(sl.upper, ast.Constant) and isinstance(sl.upper.value, int)):
                continue
            if sl.upper.value < MIN_WIDTH:
                continue
            v = node.value
            if _is_read_text(v) or (isinstance(v, ast.Name) and v.id in from_read):
                hits.append((path.name, node.lineno, sl.upper.value))
    return hits


class TestNoFixedPrefixOfAFileRead(unittest.TestCase):
    """Ceiling ZERO — every instance was removed when this class was written,
    so there is no baseline to grandfather and no reason to ever add one."""

    def test_no_file_read_is_pinned_by_character_count(self):
        hits = _file_prefix_windows()
        listing = '\n'.join(f'    {f}:{ln}  [:{w}]' for f, ln, w in hits)
        self.assertEqual(
            hits, [],
            f'{len(hits)} assertion(s) slice a file read by a fixed character '
            f'count:\n{listing}\n'
            f'Content above the target grows and pushes it out of the window — '
            f'this exact shape broke 21 files at once when three CHANGELOG '
            f'entries were added. Bound it by CONTENT instead, e.g.\n'
            f'    cl = (_ROOT / "CHANGELOG.md").read_text()\n'
            f'    newest = cl[cl.index("\\n## v"):]')


class TestVacuouslyPassingWindows(unittest.TestCase):
    """A fixed window feeding assertNotIn is the dangerous subset: when it
    drifts off target it does not fail, it silently proves nothing. Tracked on
    its own ceiling so this class can be driven to zero first."""

    ASSERTNOTIN_CEILING = 5

    def test_assertnotin_windows_do_not_grow(self):
        risky = [r for r in _windows() if r[3]]
        n = len(risky)
        if n > self.ASSERTNOTIN_CEILING:
            listing = '\n'.join(f'    {f}:{ln}' for f, ln, _, _ in risky)
            self.fail(
                f'{n} fixed windows feed an assertNotIn (ceiling '
                f'{self.ASSERTNOTIN_CEILING}). If such a window drifts past its '
                f'target the assertion passes while checking nothing — convert '
                f'these to srcpin FIRST:\n{listing}')
        self.assertLessEqual(
            self.ASSERTNOTIN_CEILING - n, 3,
            f'ceiling ({self.ASSERTNOTIN_CEILING}) is above the real count '
            f'({n}) — lower it to {n}.')


if __name__ == '__main__':
    unittest.main()
