"""Find `.style.display = <expr>` writes that cannot show the element they point at.

`el.style.display = ''` removes only the inline property. When a class on the element sets
`display: none` (the `d-none` and `hidden` utilities, or one of the `isl-*` classes the CSP
migration lifted out of `style="display:none"`), the class keeps the element hidden, so a form
that "shows" it that way never shows it. Issue #41 (the maintenance window form) was this: picking
"Recurring (cron)" wrote '' to a row that carried `d-none`.

The scan reads the shipped source. Its population is every write in static/js/*.js whose
right-hand side can be the empty string, resolved to the markup it targets:

  * `document.getElementById('x').style.display = ...`
  * `const el = document.getElementById('x'); ... el.style.display = ...` (within 40 lines)
  * `document.querySelectorAll('.cls').forEach(el => el.style.display = ...)` and the
    `for (const el of ...)` form

Anything else (rows and cells built at run time, selectors with a placeholder in them) is
counted as unresolved and listed, so a change in that number is visible rather than silent.

The first version of this check (test_v232) matched only a literal `= ''` and so saw 4 of the 31
writes that can be blank; the 11 broken elements were all written as `cond ? '' : 'none'`.
"""
import functools
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "server" / "html" / "index.html"
CSS = ROOT / "server" / "html" / "static" / "css" / "styles.css"
JS_DIR = ROOT / "server" / "html" / "static" / "js"

# Utility classes that hide an element. Others come from the stylesheet (hiding_classes()).
UTILITY_HIDERS = frozenset(("d-none", "hidden"))

# A write of '' at markup that carries a hiding class, and still right. (file, target) -> why.
# A listed entry that stops matching fails the gate, so the list only shrinks.
ALLOW = {
    ('app.js', '.settings-section'):
        "The settings search hides the sections that do not match and hands the rest back with ''. "
        "The two sections that carry a hiding class (tenants-section, pii-card) are shown by their "
        "own switches, which '' must not override.",
}

# A write that can be '' whose target the scan cannot find in markup, because the rows and cells
# are built at run time. (file, right-hand side) -> why. Same rule: it must still match.
UNRESOLVED_OK = {
    ('app.js', "hide ? 'none' : ''"):
        "Table column picker: header cells of tables built by the page renderers; none carries a hiding class.",
    ('app.js', "hideIdx.has(i) ? 'none' : ''"):
        "Table column picker: body cells of those tables.",
    ('app.js', "row.dataset.q?.toLowerCase().includes(q) ? '' : 'none'"):
        "Listening-ports rows in the host drawer (a <tr> without a class); a filter, so '' means "
        "'no filter hides this row'.",
}


_CODE_STOP = re.compile(r"""['"`/{}]""")
_STR_STOP = {"'": re.compile(r"""['\\\n]"""),
             '"': re.compile(r'''["\\\n]'''),
             '`': re.compile(r"""[`\\$\n]""")}


@functools.lru_cache(maxsize=None)
def strip_js_comments(src):
    """The source with `//` and `/* */` comments blanked (newlines kept, so line numbers hold).

    A small state machine that steps over strings and the `${...}` of a template literal. It does
    not parse regular-expression literals; a quote inside one only confuses the rest of its own
    line, because the quote states end at a newline.
    """
    out = []
    i, n = 0, len(src)
    state = None            # None (code) | "'" | '"' | '`'
    stack = []              # brace depth to return to at the `}` that closes a `${`
    brace = 0
    while i < n:
        m = (_CODE_STOP if state is None else _STR_STOP[state]).search(src, i)
        if not m:
            out.append(src[i:])
            break
        j = m.start()
        out.append(src[i:j])
        c = src[j]
        i = j
        if state is None:
            if src.startswith('//', i):
                j = src.find('\n', i)
                j = n if j < 0 else j
                out.append(' ' * (j - i))
                i = j
                continue
            if src.startswith('/*', i):
                j = src.find('*/', i + 2)
                j = n if j < 0 else j + 2
                out.append(re.sub(r'[^\n]', ' ', src[i:j]))
                i = j
                continue
            if c in '\'"`':
                state = c
            elif c == '{':
                brace += 1
            elif c == '}':
                brace -= 1
                if stack and brace == stack[-1]:
                    stack.pop()
                    state = '`'
            out.append(c)
            i += 1
            continue
        if c == '\\':
            out.append(src[i:i + 2])
            i += 2
            continue
        if state == '`' and c == '$':
            if src.startswith('${', i):
                stack.append(brace)
                brace += 1
                state = None
                out.append('${')
                i += 2
            else:
                out.append(c)
                i += 1
            continue
        if c == state or (c == '\n' and state != '`'):
            state = None
        out.append(c)
        i += 1
    return ''.join(out)


def strip_css_comments(css):
    return re.sub(r'/\*.*?\*/', '', css, flags=re.S)


def top_level_rules(css):
    """(selector list, body) for every rule that is not inside an at-rule (`@media print` and
    the like do not hide anything on screen)."""
    css = strip_css_comments(css)
    out = []
    i, n = 0, len(css)
    start = 0
    while i < n:
        j = css.find('{', i)
        if j < 0:
            break
        prelude = css[start:j].strip()
        depth, k = 1, j + 1
        while k < n and depth:
            if css[k] == '{':
                depth += 1
            elif css[k] == '}':
                depth -= 1
            k += 1
        if not prelude.startswith('@'):
            out.append((prelude, css[j + 1:k - 1]))
        start = i = k
    return out


def split_selector_list(prelude):
    """The selectors of a rule, split at the commas that are not inside `:is(...)` and friends."""
    parts, depth, cur = [], 0, []
    for ch in prelude:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append(''.join(cur))
    return parts


@functools.lru_cache(maxsize=None)
def _hiding_classes(css):
    found: set = set(UTILITY_HIDERS)
    for prelude, body in top_level_rules(css):
        if not re.search(r'(?<![\w-])display\s*:\s*none\b', body):
            continue
        for sel in split_selector_list(prelude):
            m = re.fullmatch(r'\s*\.([A-Za-z_][\w-]*)\s*', sel)
            if m:
                found.add(m.group(1))
    return frozenset(found)


def hiding_classes(css):
    """Classes whose own rule, outside any at-rule, is `display: none`."""
    return set(_hiding_classes(css))


_TAG = re.compile(r'<[A-Za-z][^<>]*>')
_CLASS_ATTR = re.compile(r'''\bclass\s*=\s*(["'])(.*?)\1''', re.S)
_ID_ATTR = re.compile(r'''\bid\s*=\s*(["'])([\w-]+)\1''')


@functools.lru_cache(maxsize=None)
def _elements_of(text):
    out = []
    for m in _TAG.finditer(text):
        tag = m.group(0)
        cm = _CLASS_ATTR.search(tag)
        im = _ID_ATTR.search(tag)
        if not cm and not im:
            continue
        toks = frozenset()
        if cm:
            toks = frozenset(t for t in re.split(r'\s+', re.sub(r'\$\{[^}]*\}', ' ', cm.group(2))) if t)
        out.append((im.group(2) if im else '', toks))
    return tuple(out)


def markup_elements(sources):
    """[(id or '', set of class tokens)] for every opening tag in the given texts.

    Reads index.html and the JS files alike, because the JS builds a good deal of markup in
    template strings. A class attribute holding a `${...}` keeps its literal tokens.
    """
    out = []
    for text in sources:
        out.extend(_elements_of(text))
    return out


_WRITE = re.compile(r'(?P<recv>[^\n;]*?)\.style\.display\s*=(?!=)\s*(?P<rhs>[^;\n]*)')
_GET_ID = re.compile(r'''getElementById\(\s*['"]([\w-]+)['"]\s*\)\s*\??$''')
_BLANK = re.compile(r"""(?<![\w])(?:''|"")""")


def can_be_blank(rhs):
    """True when the right-hand side can evaluate to the empty string."""
    return bool(_BLANK.search(rhs))


def _bind(lines, idx, name):
    """What the identifier `name` points at, looking back up to 40 lines from line `idx`:
    ('id', x) | ('sel', selector) | None."""
    nm = re.escape(name)
    for back in range(idx, max(-1, idx - 41), -1):
        line = lines[back]
        m = re.search(r'''(?:const|let|var)\s+%s\s*=\s*[^;]*?getElementById\(\s*['"]([\w-]+)['"]\s*\)''' % nm, line)
        if m:
            return ('id', m.group(1))
        m = re.search(r'''querySelector(?:All)?\(\s*(['"`])(.+?)\1\s*\)\s*\.forEach\(\s*\(?\s*%s\b''' % nm, line)
        if m:
            return ('sel', m.group(2))
        m = re.search(r'''for\s*\(\s*(?:const|let|var)\s+%s\s+of\s+[^)]*?querySelectorAll\(\s*(['"`])(.+?)\1''' % nm, line)
        if m:
            return ('sel', m.group(2))
    return None


@functools.lru_cache(maxsize=None)
def _writes_of(text):
    lines = strip_js_comments(text).splitlines()
    out = []
    for idx, line in enumerate(lines):
        if '.style.display' not in line:
            continue
        for m in _WRITE.finditer(line):
            rhs = m.group('rhs').strip()
            if not rhs and idx + 1 < len(lines):
                rhs = lines[idx + 1].split(';')[0].strip()
            recv = m.group('recv').rstrip()
            target = None
            g = _GET_ID.search(recv)
            if g:
                target = ('id', g.group(1))
            else:
                v = re.search(r'([A-Za-z_$][\w$]*)\s*\??$', recv)
                if v:
                    target = _bind(lines, idx, v.group(1))
            out.append((idx + 1, rhs, target))
    return tuple(out)


def display_writes(js_by_file):
    """Every `.style.display = rhs` in code: [dict(file, line, rhs, target)].

    `target` is ('id', x), ('sel', selector) or None when the receiver cannot be resolved.
    """
    out = []
    for fname, text in js_by_file.items():
        for line, rhs, target in _writes_of(text):
            out.append({'file': fname, 'line': line, 'rhs': rhs, 'target': target})
    return out


def _selector_hits(selector, elements):
    """The markup elements a selector names: by id when it has a complete one, else by every class.

    A `${...}` placeholder is dropped first, so `#log-lines-${id} .log-line` still resolves by
    `.log-line`; an id left incomplete by a placeholder is not used.
    """
    sel = re.sub(r'\$\{[^}]*\}', '', selector)
    ids = [i for i in re.findall(r'#([\w-]+)', sel) if not i.endswith('-')]
    cls = re.findall(r'\.([A-Za-z_][\w-]*)', sel)
    if ids:
        return [(i, c) for i, c in elements if i == ids[-1]]
    if cls:
        return [(i, c) for i, c in elements if all(k in c for k in cls)]
    return None


def scan(js_by_file, html_text, css_text, js_templates=None):
    """The whole census. Returns a dict:

      writes        all `.style.display =` writes in code
      blank         those that can be the empty string
      resolved      blank writes whose target is in the markup
      unresolved    blank writes whose target is not (rows and cells built at run time)
      violations    resolved writes whose target carries a hiding class: [(file, line, what, classes)]
    """
    hiders = hiding_classes(css_text)
    elements = markup_elements([html_text] + list((js_templates if js_templates is not None else js_by_file).values()))
    writes = display_writes(js_by_file)
    blank = [w for w in writes if can_be_blank(w['rhs'])]
    resolved, unresolved, violations = [], [], []
    for w in blank:
        target = w['target']
        hits = None
        who = ''
        if target and target[0] == 'id':
            who = '#' + target[1]
            hits = [(i, c) for i, c in elements if i == target[1]]
        elif target and target[0] == 'sel':
            who = target[1]
            hits = _selector_hits(target[1], elements)
        if not hits:
            unresolved.append(w)
            continue
        resolved.append(w)
        bad = sorted({t for _, c in hits for t in c if t in hiders})
        if bad:
            violations.append((w['file'], w['line'], who, bad))
    return {'writes': writes, 'blank': blank, 'resolved': resolved,
            'unresolved': unresolved, 'violations': violations}


def shipped_sources():
    js = {p.name: p.read_text() for p in sorted(JS_DIR.glob('*.js'))}
    return js, HTML.read_text(), CSS.read_text()
