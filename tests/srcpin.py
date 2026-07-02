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
"""


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
    o = src.find('{', a)
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
