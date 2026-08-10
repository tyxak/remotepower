"""Anchor-based source extraction for tests — replaces fixed-window slices.

The recurring failure mode this kills: a test pins `js[start:start+5600]`
around a function, then an unrelated event/feature lengthens the code above
the assertion target and the window silently truncates — so every event
addition bumped windows across three+ test files (see the widening-history
comments that used to live in test_v223/v248/v225). Extract the enclosing
construct instead:

    from srcpin import js_function, py_function, balanced_block
    body = js_function(client_js(), '_renderHomeActivity')

The extractors are deliberately dumb scanners (quote/comment aware brace
counting) — good enough for this repo's code style; they raise ValueError
loudly rather than returning a truncated region.

PYTHON AND JAVASCRIPT ONLY — do NOT point these at shell, HTML or Makefiles.
`_scan_balanced` knows `//` and `/* */` comments and treats `'` as a string
delimiter. In a shell script a `#` comment is not skipped, so an apostrophe in
prose ("isn't") opens a phantom string and brace tracking is lost. Measured on
install.sh's `transport_state()`: the real body is 672 chars and
`balanced_block(src, 'transport_state()', '{', '}')` returns 9,278 — it runs
past the closing brace through eight other functions. That failure is SILENT
and over-broad, which is worse than the fixed window it would replace. Windows
over shell scripts, HTML elements and Makefile recipes are therefore left as
fixed slices on purpose (see tests/test_srcpin_ratchet.py for the remaining
set). `js_function` is safe by luck here — a bash `name()` matches none of its
definition anchors, so it raises rather than mis-extracting.
"""

import re


def _scan_balanced(src, open_idx, open_ch='{', close_ch='}'):
    """Return the index just past the delimiter that balances
    src[open_idx] (which must be open_ch). Skips string literals
    ('', "", ``), // line comments and /* */ block comments."""
    if src[open_idx] != open_ch:
        raise ValueError(f'expected {open_ch!r} at {open_idx}, '
                         f'found {src[open_idx]!r}')
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c in ('"', "'", '`'):
            quote = c
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == quote:
                    break
                i += 1
        elif c == '/' and i + 1 < n and src[i + 1] == '/':
            i = src.find('\n', i)
            if i < 0:
                break
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            i = src.find('*/', i + 2)
            if i < 0:
                break
            i += 1
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError(f'unbalanced {open_ch}...{close_ch} from {open_idx}')


def balanced_block(src, anchor, open_ch='{', close_ch='}', start=0):
    """Source from `anchor` through the delimiter balancing the first
    open_ch after it. E.g. balanced_block(js, 'const FLEET_EVENTS = new Set(',
    '(', ')') yields the whole Set literal regardless of how many events
    are ever added to it."""
    a = src.find(anchor, start)
    if a < 0:
        raise ValueError(f'anchor not found: {anchor!r}')
    o = src.find(open_ch, a + len(anchor) - 1)
    if o < 0:
        raise ValueError(f'no {open_ch!r} after anchor {anchor!r}')
    return src[a:_scan_balanced(src, o, open_ch, close_ch)]


def js_function(src, name, start=0):
    """The full text of `function <name>(...) {...}` (or a
    `const <name> = (...) => {...}` / `async function <name>` form),
    brace-balanced — never a fixed window."""
    # Definition forms only — a bare '<name>(' would anchor on a CALL site.
    for anchor in (f'function {name}(', f'async function {name}(',
                   f'const {name} = ', f'let {name} = '):
        a = src.find(anchor, start)
        if a >= 0:
            break
    else:
        raise ValueError(f'JS function not found: {name}')
    # v6.3.0: the body brace is the first '{' AFTER the parameter list — a
    # default object parameter (`function toast(msg, type, opts = {})`) puts
    # a '{' inside the params, which the old "first brace" scan mistook for
    # the body (returning just the signature). Balance the parens first
    # whenever a '(' precedes the first '{'.
    o_paren = src.find('(', a)
    o = src.find('{', a)
    if o_paren != -1 and (o == -1 or o_paren < o):
        params_end = _scan_balanced(src, o_paren, '(', ')')
        o = src.find('{', params_end)
    if o < 0:
        raise ValueError(f'no body brace for {name}')
    return src[a:_scan_balanced(src, o)]


def py_function(src, name, start=0):
    """The full text of a top-level or method `def <name>(...)` block,
    by indentation (includes decorators directly above it)."""
    import re
    m = re.search(rf'^([ \t]*)def {re.escape(name)}\(', src[start:], re.M)
    if not m:
        raise ValueError(f'python def not found: {name}')
    indent = m.group(1)
    body_start = start + m.start()
    lines = src[body_start:].split('\n')
    out = [lines[0]]
    for line in lines[1:]:
        if line.strip() and not line.startswith(indent + ' ') \
                and not line.startswith(indent + '\t') \
                and not line.strip().startswith('#'):
            break
        out.append(line)
    # trim trailing blank lines
    while out and not out[-1].strip():
        out.pop()
    return '\n'.join(out)


def html_page(html, page_id, start=0):
    """The markup of one `<div id="page-X" class="page">` section.

    Bounded by the NEXT `id="page-` occurrence, not a hardcoded neighbour —
    a test that pins "the next page id" breaks the day someone inserts a page
    between the two, which is exactly the fixed-window fragility srcpin
    exists to kill (see the v6.2.3 source-window migration).
    """
    anchor = 'id="page-%s"' % page_id
    i = html.index(anchor, start)
    m = re.search(r'id="page-[a-z0-9-]+"', html[i + len(anchor):])
    end = i + len(anchor) + m.start() if m else len(html)
    return html[i:end]
