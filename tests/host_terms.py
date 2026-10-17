"""Scanners behind the host-terminology gate (tests/test_v740_host_terminology.py).

Every managed machine is a "host" wherever a person reads it. "Device" survives only where it is the
right word: a peripheral, a disk, the reader's own hardware, an OAuth grant, or a name in the API.

The scanners return the places where the old word is left in prose. They do not decide what to do
about it, and they never touch a file. Each one reads a different surface, because the word hides
differently in each:

  html_prose(html)      visible text and the title / placeholder / aria-label / alt attributes
  js_literals(source)   string and template literals of a script (a small tokenizer, not a regex)
  py_prose(source)      string constants of a Python module that read as sentences
  md_prose(markdown)    prose of a Markdown file, with code, links and file names left out
"""
import ast
import html.parser
import re

# Spans where "device" is the right word. The list is the contract: widen it only for a sense that
# is not a RemotePower host, and say which sense in a comment.
PROTECT = re.compile(
    # peripherals and storage: a disk, a RAID member, a USB stick
    r"\bUSB [Dd]evices?\b"
    r"|(?i:\bblock[- ]devices?\b)"
    r"|\b[Ss]torage [Dd]evices?\b"
    r"|\b[Mm]obile [Dd]evices?\b"
    r"|\bRAID [Dd]evices?\b"
    r"|\b[Rr]aw devices?\b"
    r"|\b[Ww]hole-disk [Dd]evices?\b"
    r"|\b[Dd]evices? \((?:one per line, )?whole-disk[^)]*\)"
    r"|\b[Mm]ember devices \((?:one per line, )?whole-disk[^)]*\)"
    r"|\bdevices?\b(?= (?:must be|is not)[^.]{0,40}/dev)"
    r"|\bbtrfs device\b"
    r"|\bdevice-mapper\b"
    r"|\bAdvanced Micro Devices\b"
    r"|\bwidth=device-width\b"
    r"|\bdevice[- ]motion\b"
    r"|\bNo space left on device\b"
    r"|\{severity, title, body, device\}"           # the JSON field a generic webhook posts
    r"|\{device\}"                                   # the template variable of a log-rule message
    # code: URL fragments, paths, file names, JSON keys, enum values, key=value and attributes
    r"|#device/"
    r"|(?<!\w)(?:/api)?/devices?\b"
    r"|\bdevices?\.(?:json|py|js|md|html|csv|txt)\b"
    r"|\bbody\.device\b"
    r"|\\?[\"']devices?\\?[\"']\s*:"
    r"|(?<=[|(])devices?(?=[|)])"
    r"|(?<=\|)devices?\b"
    r"|\bdevices?="
    r"|[\w-]+=[\"']?devices?(?=[\"'\s>]|$)"
    # the reader's own hardware, an authenticator, an OAuth grant, a WireGuard peer
    r"|\bbrowsers? ?(?:/|or|and) ?devices?\b"
    r"|\b(?:synced|follows? you) across devices\b"
    r"|\b[Rr]emember me on this device\b"
    r"|\bper-device client configs\b"
    r"|\b[Dd]evice (?:code|flow|authori[sz]ation|grant)\b"
    r"|\b(?:security key|passkey|authenticator|WebAuthn)[^.]{0,30}\bdevices?\b"
    r"|\bClick to dial on a device\b"
    r"|\bOn touch devices\b"
    r"|\bfrom any device or network\b"
    r"|\bagainst the current device set\b"
    # a third party's own word for its entities: Syncthing and ESPHome call them devices
    r"|\bdevices connected\b"
    r"|\bESPHome dashboard device list\b"
)
WORD = re.compile(r"\b(?:DEVICES?|[Dd]evices?)\b")
# a token that is a path, an identifier, a file name or an attribute, not a sentence
TECH_TOKEN = re.compile(
    r"^['\"(\[]*(?:[/~.]|#|\$)|://|[_=@<>{}]|\.(?:md|py|js|json|html|sh|txt|conf|service|yml|yaml|toml|csv)\b")
_TOKEN = re.compile(r"\S+")


def leftover(text):
    """The "device" words in prose that are not a protected sense. Empty means the text is fine."""
    if not WORD.search(text):
        return []
    spans = [(m.start(), m.end()) for m in PROTECT.finditer(text)]
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if WORD.search(tok) and TECH_TOKEN.search(tok):
            spans.append((m.start(), m.end()))
    out = []
    for m in WORD.finditer(text):
        if not any(a <= m.start() and m.end() <= b for a, b in spans):
            lo, hi = max(0, m.start() - 30), min(len(text), m.end() + 30)
            out.append(text[lo:hi].replace('\n', ' '))
    return out


def looks_like_code(text):
    """A plain string that is a selector, a class list, a path, a key or a format, not prose."""
    t = text.strip()
    if not t:
        return True
    if re.match(r'^[#./\[$@]', t):
        return True
    toks = t.split()
    if len(toks) == 1 and re.fullmatch(r'[A-Za-z0-9_.:/?-]+', t) and (t[0].islower() or '-' in t or '_' in t):
        return True
    ident = r'[a-z0-9]+(?:[-_:][a-z0-9]+)+'
    if all(re.fullmatch(ident, k) or k in {'btn', 'active', 'hidden', 'row', 'card', 'tag', 'chip', 'pill'} for k in toks):
        return True
    if '=>' in t or '${' in t or re.search(r'[{};]\s*$', t) or 'function' in t:
        return True
    if re.search(r'\w\[[\w-]+[~|^$*]?=', t):
        return True
    if re.search(r'\b(?:startswith|endswith)\(|\(\?[:=!<]', t):      # a route test, a regular expression
        return True
    if re.search(r'[\w)\]]\.device\b|\bdevice\.\w', t) and ' ' not in t:
        return True
    if re.search(r'\b(CREATE|ALTER|DROP|SELECT|INSERT|UPDATE|DELETE|TRIGGER|POLICY|INDEX|TABLE|WHERE|FROM)\b', t) \
            and re.search(r'\b(TABLE|FROM|WHERE|INTO|SET|POLICY|INDEX)\b', t):
        return True
    return False


# ── HTML ───────────────────────────────────────────────────────────────────────

_ATTRS = ('title', 'placeholder', 'aria-label', 'alt', 'data-tip', 'data-combo-placeholder')
_SKIP = {'script', 'style', 'code', 'pre', 'kbd', 'samp', 'textarea', 'svg'}


class _Prose(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.items = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self.depth += 1
        for k, v in attrs:
            if k in _ATTRS and v:
                self.items.append((self.getpos()[0], k, v))

    def handle_startendtag(self, tag, attrs):
        for k, v in attrs:
            if k in _ATTRS and v:
                self.items.append((self.getpos()[0], k, v))

    def handle_endtag(self, tag):
        if tag in _SKIP and self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if not self.depth and data.strip():
            self.items.append((self.getpos()[0], 'text', data))


def html_prose(source):
    """(line, kind, text) for every visible text node and prose attribute of an HTML page."""
    p = _Prose()
    p.feed(source)
    p.close()
    return p.items


# ── JavaScript ─────────────────────────────────────────────────────────────────

_REGEX_AFTER = re.compile(r'[(,=:\[!&|?{};+\-*%<>~^]$|^$|\b(?:return|typeof|case|in|of|delete|void|throw|new|else|do)$')
_ESC = {'n': '\n', 't': '\t', 'r': '\r', '\\': '\\', "'": "'", '"': '"', '`': '`', '$': '$'}


def js_literals(src):
    """(line, text) for every string literal and static part of a template literal.

    A small state machine rather than a regex: it steps over comments, over regular-expression
    literals (a slash after an operator) and into the `${...}` of a template, which is where a
    quote-pairing regex loses its place and reports half the file as one string.
    """
    out = []
    n, i, line = len(src), 0, 1
    prev = ''          # last significant token, to tell a division from a regex

    def read_string(i, q):
        buf, ln = [], line
        i += 1
        while i < n and src[i] != q:
            c = src[i]
            if c == '\\' and i + 1 < n:
                nx = src[i + 1]
                buf.append(_ESC.get(nx, nx))
                if nx == '\n':
                    ln += 1
                i += 2
                continue
            if c == '\n':
                ln += 1
            buf.append(c)
            i += 1
        return i + 1, ''.join(buf), ln

    stack = []         # template-literal nesting: brace depth at each open `${`
    brace = 0
    while i < n:
        c = src[i]
        if c == '\n':
            line += 1
            i += 1
            continue
        if c in ' \t\r':
            i += 1
            continue
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            line += src.count('\n', i, j)
            i = j
            continue
        if c in '\'"':
            start = line
            i, text, ln = read_string(i, c)
            out.append((start, text))
            line = ln
            prev = 'str'
            continue
        if c == '`' or (c == '}' and stack and brace == stack[-1]):
            if c == '}':
                stack.pop()
            start, buf = line, []
            i += 1
            closed = False
            while i < n:
                d = src[i]
                if d == '\\' and i + 1 < n:
                    buf.append(_ESC.get(src[i + 1], src[i + 1]))
                    if src[i + 1] == '\n':
                        line += 1
                    i += 2
                    continue
                if d == '`':
                    i += 1
                    closed = True
                    break
                if d == '$' and src.startswith('${', i):
                    out.append((start, ''.join(buf)))
                    stack.append(brace)
                    i += 2
                    buf = None
                    prev = '{'          # an expression starts here, so a slash may open a regex
                    break
                if d == '\n':
                    line += 1
                buf.append(d)
                i += 1
            if buf is not None:
                out.append((start, ''.join(buf)))
            if buf is not None:
                prev = 'str'
            if not closed and buf is not None:
                break
            continue
        if c == '{':
            brace += 1
        elif c == '}':
            brace -= 1
        if c == '/':
            # division or a regular expression literal?
            if _REGEX_AFTER.search(prev) and prev != 'str':
                j = i + 1
                in_class = False
                while j < n and src[j] != '\n':
                    if src[j] == '\\':
                        j += 2
                        continue
                    if src[j] == '[':
                        in_class = True
                    elif src[j] == ']':
                        in_class = False
                    elif src[j] == '/' and not in_class:
                        break
                    j += 1
                i = j + 1
                while i < n and (src[i].isalpha()):
                    i += 1
                prev = 'str'
                continue
        m = re.match(r'[A-Za-z_$][\w$]*|\d[\w.]*|\S', src[i:i + 64])
        tok = m.group(0)
        prev = tok if (tok.isidentifier() or len(tok) == 1) else tok
        i += len(tok)
    return out


def literal_prose(text):
    """What a person reads in a literal: markup stripped, attribute prose kept. None if it is code."""
    if '<' in text and re.search(r'<[A-Za-z/!]', text):
        parts = [m.group(3) or m.group(4) or '' for m in re.finditer(
            r"""(?<![\w-])(title|placeholder|aria-label|alt)=("([^"]*)"|'([^']*)')""", text)]
        body = re.sub(r'<(?:script|style|code|pre|kbd|samp)\b.*?</(?:script|style|code|pre|kbd|samp)\s*>', ' ', text, flags=re.S | re.I)
        body = re.sub(r'<[^<>]*>?', ' ', body)
        return ' '.join([body] + parts)
    if looks_like_code(text):
        return None
    return text


# ── Python ─────────────────────────────────────────────────────────────────────

# Calls whose string arguments are names, not sentences: XML element names are an export schema.
_NAME_CALLS = {'SubElement', 'Element'}
_ACCESS = {'get', 'pop', 'setdefault', 'startswith', 'endswith', 'split', 'join', 'replace', 'strip', 'lstrip',
           'rstrip', 'format', 'encode', 'decode', 'count', 'index', 'find'}


def py_prose(src, seen=None):
    """(line, text) for string constants that read as sentences and mention a device.

    Docstrings, dict keys, comparisons, subscripts, SQL, paths and XML element names are left out.
    Audit and log calls stay in: an operator reads those lines. `seen`, if given, is a dict that
    receives the number of string constants looked at, so a caller can tell a clean module from an
    empty population.
    """
    tree = ast.parse(src)
    out = []
    stack = []

    def walk(node):
        stack.append(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if seen is not None:
                seen['strings'] = seen.get('strings', 0) + 1
            if WORD.search(node.value):
                parent = stack[-2] if len(stack) >= 2 else None
                doc = False
                if len(stack) >= 3 and isinstance(parent, ast.Expr) and isinstance(
                        stack[-3], (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    doc = bool(stack[-3].body) and stack[-3].body[0] is parent
                named = False
                for anc in stack:
                    if isinstance(anc, ast.Call):
                        f = anc.func
                        if (f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '')) in _NAME_CALLS:
                            named = True
                key = isinstance(parent, ast.Dict) and node in parent.keys
                access = isinstance(parent, (ast.Compare, ast.Subscript)) or (
                    isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute)
                    and parent.func.attr in _ACCESS)
                if not doc and not named and not key and not access and not looks_like_code(node.value):
                    out.append((node.lineno, node.value))
        for child in ast.iter_child_nodes(node):
            walk(child)
        stack.pop()

    walk(tree)
    return out


# ── Markdown ───────────────────────────────────────────────────────────────────

_FENCE = re.compile(r'^\s*(`{3,}|~{3,})')
_NOT_PROSE = re.compile(r'(`+)(?:(?!\1).)+?\1|\]\([^)\s]*(?:\s+"[^"]*")?\)|<https?://[^>\s]+>|https?://[^\s)>\]]+|<[A-Za-z/!][^>]*>')
_REF = re.compile(r'^\s*\[[^\]]+\]:\s*\S+')


def md_prose(text):
    """(line, text) for the prose of a Markdown file: no fenced code, code spans, link targets or URLs."""
    out, fence = [], ''
    for no, line in enumerate(text.split('\n'), 1):
        m = _FENCE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = ''
            continue
        if m:
            fence = m.group(1)
            continue
        if _REF.match(line):
            continue
        out.append((no, _NOT_PROSE.sub(' ', line)))
    return out
