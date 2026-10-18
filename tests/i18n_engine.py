"""Facts about the i18n engine that a test has to read from its source.

Restating them in a test lets the two drift: the text-node cap was once
hardcoded in three places, nine descriptions sat just above it, and every key
was present while nothing translated.
"""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

I18N_JS = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js' / 'i18n.js'

# The six languages the product ships besides English; `LANGS` in i18n.js is the authority.
LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')

# The head of a DICT entry: the English key (either quote style: the curated block is single-quoted and
# the machine-written catalog is double-quoted; matching one reported thousands of phantom gaps twice),
# a colon and the opening brace. The object itself may sit on the same line or on the lines below.
_ENTRY_HEAD = re.compile(r"""^\s{4}(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*:\s*(\{)""", re.M)
# Strings are taken whole, so a brace or a colon inside a translation (`{ticket_id}`, `Note:`) is never
# read as structure. Everything else in an entry is a bare word or one of { } : ,
_TOKEN = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[{}:,]|[A-Za-z_]\w*""")


def _languages(text, brace_at):
    """The language keys of the object literal whose `{` is at text[brace_at]."""
    langs, prev, depth = set(), None, 0
    for m in _TOKEN.finditer(text, brace_at):
        tok = m.group(0)
        if tok == '{':
            depth += 1
        elif tok == '}':
            depth -= 1
            if depth == 0:
                break
        elif tok == ':' and prev is not None and prev.strip('\'"') in LANGS:
            langs.add(prev.strip('\'"'))
        prev = tok
    return langs


def dict_rows(src=None):
    """{English key: set of language codes} for every entry of DICT.

    The key is read as the browser would see it (quotes and backslashes unescaped). The languages
    come from a scan that takes each string whole, so a translation that holds a brace cannot end the
    entry early, and an entry written over several lines is read to its closing brace. The control is
    V8: tests/test_v740_dict_parse.py compares this with the dictionary as the engine evaluates it.
    """
    text = src if src is not None else I18N_JS.read_text(encoding='utf-8')
    start = text.index('var DICT = {')
    stop = text.index('\n  };', start)
    rows = {}
    for m in _ENTRY_HEAD.finditer(text, start, stop):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        key = raw.replace("\\'", "'").replace('\\"', '"').replace('\\\\', '\\')
        rows[key] = _languages(text, m.start(3))
    return rows


_ENGINE_RUN = r'''
const store = {};
global.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
const stub = () => ({ setAttribute(){}, getAttribute(){ return null; }, hasAttribute(){ return false; },
  querySelectorAll(){ return []; }, addEventListener(){}, appendChild(){}, dataset: {},
  classList: { contains(){ return false; } }, value: '', style: {} });
global.document = { readyState: 'complete', documentElement: stub(), body: null, createElement: stub,
  createTreeWalker: null, getElementById(){ return null; }, querySelectorAll(){ return []; }, addEventListener(){} };
global.window = global;
global.fetch = () => ({ catch(){} });
require(process.argv[2]);
const strings = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const lang of window.RPi18n.langs) {
  if (lang === 'en') continue;
  window.RPi18n.setLang(lang, false);
  out[lang] = strings.filter(s => window.RPi18n.t(s) === s);
}
console.log(JSON.stringify(out));
'''


def unchanged_by_engine(strings, src_path=None):
    """{lang: [strings the real engine hands back unchanged]}; None when node is not installed.

    `RPi18n.t()` is the lookup `translateTextNode` makes for a text node, so a string that comes back
    unchanged is one the person reads in English. i18n.js is a browser script that hangs RPi18n off
    `window`; the shim is the smallest DOM that lets it reach that line (it never renders, so there is
    no tree walker, and what runs is the dictionary lookup). The strings travel on stdin, not in a
    scratch file: a suite-wide scan for fixtures that write DATA_DIR files cannot tell such a name
    from a storage key.
    """
    node = shutil.which('node')
    if not node:
        return None
    work = Path(tempfile.mkdtemp(prefix='rp-i18n-'))
    try:
        (work / 'run.js').write_text(_ENGINE_RUN, encoding='utf-8')
        r = subprocess.run([node, str(work / 'run.js'), str(src_path or I18N_JS)],
                           input=json.dumps(sorted(set(strings))), capture_output=True, text=True, timeout=120)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if r.returncode != 0:
        raise AssertionError('node could not load i18n.js: ' + r.stderr[-800:])
    return json.loads(r.stdout)


def text_node_cap(src=None):
    """The longest text node `translateTextNode` will translate.

    A node above it is skipped before the dictionary is consulted, so a string
    that long cannot be translated even with a complete DICT entry.
    """
    text = src if src is not None else I18N_JS.read_text(encoding='utf-8')
    m = re.search(r'trimmed\.length\s*>\s*(\d+)', text)
    assert m, 'the text-node length cap is no longer in translateTextNode'
    return int(m.group(1))
