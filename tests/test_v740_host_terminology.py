#!/usr/bin/env python3
"""v7.4.0: a managed machine is a "host" wherever a person reads it.

The product said "device" in some places and "host" in others, and the two meant the same thing.
This gate keeps it that way once the words agree. It reads every surface where a person meets
text and fails on "device" in prose, unless the sentence uses the word for something that is not
a RemotePower host: a peripheral, a disk, the reader's own phone, a name in the API.

Each scanner is shown to see the old word before it is trusted (TestScannersSeeTheWord), and each
surface must examine a population of real size (TestPopulationIsNotEmpty): a scanner that reads
nothing reports success, which is how two earlier gates here went green for years.

Not covered, on purpose: code comments and docstrings (developer text), API paths, JSON keys,
CSS classes and storage names (identifiers, not words), CHANGELOG.md and the earlier release notes
(history), and the SQL and storage internals.
"""
import functools
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required   # noqa: E402
import host_terms as H   # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / 'server' / 'html'
JS = HTML / 'static' / 'js'

# Release notes and reviews that describe an earlier version in that version's words.
HISTORY = {'v7.1.0.md', 'v7.2.0.md', 'v7.3.0.md'}

# Exceptions: (file, regular expression the leftover context must match) -> why the word stays.
# Every entry must still match something, so the list can only shrink.
ALLOW = {
    ('docs/keyboard-shortcuts.md', r'when that page was called Devices'):
        'explains why the shortcut is still `g d`',
    ('server/html/static/js/app.js', r'agent hosts devices roster'):
        'search keywords: typing the old word still finds the page',
    ('server/html/static/js/app.js', r'search hosts devices ad-hoc'):
        'search keywords: typing the old word still finds the page',
    ('server/html/static/js/app.js', r'metrics device cpu memory'):
        'search keywords: typing the old word still finds the page',
    ('server/cgi-bin/integrations.py', r'Devices'):
        'Syncthing calls its peers devices, and the tile shows its number',
    ('client/remotepower-agent.py', r'unknown device'):
        'a USB peripheral with no vendor or product name',
}

# Translations that may keep the word because the English key names something that is not a host.
# Matched on the English key; every entry must still match, so the list can only shrink.
ALLOW_TRANSLATION = {
    r'^The KMIP key server': 'the translation says appliance (a machine that boots from the key server)',
    r'^Each row is one log file or command': 'the translation says router, whose Arabic name contains the word',
    r'^the affected host.s recent journal': 'the translation says "outside the machine" for an AI provider that is not local',
    r'^Vulnerability scans run on a scanner satellite': 'the translation says "the machine being scanned"',
}

# The old word in a translation, per language (the Chinese word for a fleet contains it).
STEMS = {
    'zh': re.compile(r'设备(?!群)'),
    'hi': re.compile(r'डिवाइस|\bdevices?\b', re.I),
    'es': re.compile(r'dispositivos?', re.I),
    'ar': re.compile(r'جهاز|أجهزة|الجهاز|الأجهزة|لجهاز|بجهاز'),
    'de': re.compile(r'Gerät|Geräte', re.I),
    'fr': re.compile(r'appareils?|périphériques?', re.I),
}


def _rel(path):
    return path.relative_to(ROOT).as_posix()


def _py_files():
    out = sorted(p for p in (ROOT / 'server' / 'cgi-bin').glob('*.py')
                 if p.name not in {'storage.py', 'storage_pg.py'})            # SQL and store internals
    out += sorted(p for p in (ROOT / 'server').glob('*/*.py') if p.parent.name not in {'cgi-bin', 'html'})
    out += [ROOT / 'client' / n for n in ('remotepower-agent.py', 'remotepower-agent-win.py', 'remotepower-agent-mac.py',
                                          'remotepower-satellite.py', 'remotepower-scanner.py')]
    out += sorted((ROOT / 'mcp').glob('*.py')) + sorted((ROOT / 'packaging').glob('*.py'))
    return [p for p in out if p.exists()]


def _doc_files():
    out = [p for p in sorted((ROOT / 'docs').glob('*.md')) if p.name not in HISTORY]
    return out + [p for p in (ROOT / 'README.md', ROOT / 'SECURITY.md') if p.exists()]


def _script_files():
    files = [ROOT / n for n in ('install.sh', 'install-server.sh', 'install-client.sh', 'deploy-server.sh',
                                'docker-compose.yml')]
    files += sorted((ROOT / 'docker').glob('*.sh')) + sorted((ROOT / 'docker').glob('*.yml'))
    files += sorted((ROOT / 'packaging').glob('*.sh')) + sorted((ROOT / 'packaging').glob('*.service'))
    # The Windows and macOS installers and the agent's unit file sat outside this list, and "Add device" survived in
    # the Windows one (the dashboard button is Add host).
    files += [ROOT / 'client' / n for n in ('install-windows.ps1', 'install-macos.sh', 'remotepower-agent.service')]
    return [p for p in files if p.exists()]


def _without_comments(line):
    s = line.lstrip()
    if s.startswith('#'):
        return ''
    return re.sub(r'\s#\s.*$', '', line)


# What i18n.js needs at load time so the dictionaries can be read out of it.
_STUBS = """
var window = globalThis, self = globalThis;
var document = { addEventListener: function () {}, querySelectorAll: function () { return []; },
                 documentElement: {}, readyState: 'loading', createTreeWalker: function () {} };
var localStorage = { getItem: function () { return null; }, setItem: function () {} };
var navigator = { language: 'en' };
var MutationObserver = function () { this.observe = function () {}; };
var NodeFilter = { SHOW_TEXT: 4 };
"""


def _dict_entries():
    """(key, {lang: text}) for DICT and HTMLDICT, evaluated rather than parsed so quoting cannot mislead."""
    ctx = MiniRacer()
    ctx.eval(_STUBS)
    src = (JS / 'i18n.js').read_text(encoding='utf-8')
    for name in ('DICT', 'HTMLDICT'):
        marker = f'var {name} = {{'
        if marker not in src:
            raise AssertionError(f'{marker} not found in i18n.js')
        src = src.replace(marker, f'var {name} = globalThis.__{name} = {{', 1)
    try:
        ctx.eval(src)
    except Exception:
        pass                                     # the engine below the tables needs a page; the tables do not
    d = json.loads(ctx.eval('JSON.stringify({DICT: globalThis.__DICT, HTMLDICT: globalThis.__HTMLDICT})'))
    out = []
    for table in ('DICT', 'HTMLDICT'):
        for k, v in (d.get(table) or {}).items():
            if isinstance(v, dict):
                out.append((k, v))
    return out


def _dict_keys():
    """Every English source string of the dictionaries, read from the file (no V8 needed)."""
    text = (JS / 'i18n.js').read_text(encoding='utf-8')
    keys = []
    for m in re.finditer(r"""^\s*(?:'((?:[^'\\]|\\.)+)'|"((?:[^"\\]|\\.)+)"):\s*\{""", text, re.M):
        keys.append(m.group(1) or m.group(2))
    return keys


def _unallowed(found):
    """Drop the listed exceptions; returns (remaining, matched_allow_keys)."""
    used, rest = set(), []
    for path, line, ctx in found:
        for (apath, rx), _why in ALLOW.items():
            if apath == path and re.search(rx, ctx):
                used.add((apath, rx))
                break
        else:
            rest.append((path, line, ctx))
    return rest, used


def _fmt(items, limit=25):
    shown = [f'{p}:{ln}: …{c}…' for p, ln, c in items[:limit]]
    more = f'\n  … and {len(items) - limit} more' if len(items) > limit else ''
    return '\n  ' + '\n  '.join(shown) + more


class TestScannersSeeTheWord(unittest.TestCase):
    """A scanner nobody has watched fail is indistinguishable from one that cannot."""

    def test_leftover_finds_a_plain_use_and_spares_the_protected_senses(self):
        self.assertTrue(H.leftover('Select a device to continue'))
        self.assertTrue(H.leftover('3 DEVICES offline'))
        for fine in ('USB device connected', 'block device /dev/sda', 'GET /api/devices', 'see devices.json',
                     'the device-mapper target', 'Remember me on this device', 'device_id', 'passkey on this device',
                     'width=device-width', 'No space left on device', 'Device code flow'):
            self.assertEqual(H.leftover(fine), [], fine)

    def test_html_scanner(self):
        page = ('<div><button title="Add a device">Go</button><p>Pick a device</p>'
                '<code>device</code><script>var device = 1</script><span>Hosts</span></div>')
        hits = [(k, t) for _ln, k, t in H.html_prose(page) for _h in H.leftover(t)]
        self.assertEqual(sorted(k for k, _t in hits), ['text', 'title'])

    def test_js_scanner_follows_templates_and_regexes(self):
        src = ("const a = toast('Pick a device');\n"
               "const b = `<b>${x ? `inner ${y}` : ''}</b> a device`;\n"
               "const c = ${'x'} ; const r = /device\\/x/.test(q) ? 'fine' : 'ok';\n"
               "const d = `${/^https?:\\/\\//.test(u) ? 'link' : 'none'} done`;\n"
               "// a device in a comment\n"
               "/* a device in a block comment */\n"
               "const e = 'last';\n")
        texts = [t for _ln, t in H.js_literals(src)]
        flagged = [t for t in texts if (H.literal_prose(t) or '') and H.leftover(H.literal_prose(t))]
        self.assertIn('Pick a device', flagged)
        self.assertTrue(any('a device' in t for t in flagged))
        self.assertNotIn('last', flagged)
        self.assertFalse(any('comment' in t for t in texts), 'comments must not be read as strings')
        self.assertIn('last', texts, 'the tokenizer lost its place after a template and a regex')

    def test_python_scanner(self):
        src = ('"""A docstring about a device."""\n'
               'def f():\n'
               '    respond(400, {"error": "device not found"})\n'
               '    audit_log("x", "removed a device")\n'
               '    SubElement(root, "Device")\n'
               '    q = d.get("device")\n'
               '    return {"device": 1}\n')
        got = [t for _ln, t in H.py_prose(src)]
        self.assertEqual(sorted(got), ['device not found', 'removed a device'])

    def test_markdown_scanner(self):
        text = ('Pick a device.\n\n`device` stays.\n\n```\na device in code\n```\n\n'
                '[a device](devices.md) and https://x.example/devices\n')
        hits = [(ln, h) for ln, t in H.md_prose(text) for h in H.leftover(t)]
        self.assertEqual([ln for ln, _h in hits], [1, 9])


class TestPopulationIsNotEmpty(unittest.TestCase):
    """Duration and size are the smoke alarm: a gate that looks at nothing passes."""

    def test_html(self):
        n = sum(len(H.html_prose(p.read_text(encoding='utf-8'))) for p in HTML.glob('*.html'))
        self.assertGreater(n, 5000, 'the HTML scan examined almost nothing')

    def test_javascript(self):
        n = sum(len(H.js_literals(p.read_text(encoding='utf-8'))) for p in JS.glob('*.js') if p.name != 'i18n.js')
        self.assertGreater(n, 30000, 'the JavaScript scan examined almost nothing')

    def test_python(self):
        seen = {}
        files = _py_files()
        for p in files:
            H.py_prose(p.read_text(encoding='utf-8'), seen)
        self.assertGreater(len(files), 100)
        self.assertGreater(seen.get('strings', 0), 50000, 'the Python scan examined almost nothing')

    def test_documents(self):
        files = _doc_files()
        n = sum(len(H.md_prose(p.read_text(encoding='utf-8'))) for p in files)
        self.assertGreater(len(files), 100)
        self.assertGreater(n, 15000, 'the document scan examined almost nothing')

    def test_the_exception_list_is_not_stale(self):
        found = _everything()
        _rest, used = _unallowed(found)
        stale = sorted(set(ALLOW) - used)
        self.assertEqual(stale, [], 'these exceptions no longer match anything; delete them: ' + repr(stale))


@functools.lru_cache(maxsize=None)
def _everything_cached():
    """Every leftover on every surface as (file, line, context)."""
    found = []
    for p in sorted(HTML.glob('*.html')):
        for ln, _kind, text in H.html_prose(p.read_text(encoding='utf-8')):
            found += [(_rel(p), ln, c) for c in H.leftover(text)]
    for p in sorted(JS.glob('*.js')):
        if p.name == 'i18n.js':
            continue
        for ln, text in H.js_literals(p.read_text(encoding='utf-8')):
            prose = H.literal_prose(text)
            if prose:
                found += [(_rel(p), ln, c) for c in H.leftover(prose)]
    for p in _py_files():
        for ln, text in H.py_prose(p.read_text(encoding='utf-8')):
            found += [(_rel(p), ln, c) for c in H.leftover(text)]
    for p in _doc_files():
        for ln, text in H.md_prose(p.read_text(encoding='utf-8')):
            found += [(_rel(p), ln, c) for c in H.leftover(text)]
    for p in _script_files():
        for no, line in enumerate(p.read_text(encoding='utf-8').split('\n'), 1):
            found += [(_rel(p), no, c) for c in H.leftover(_without_comments(line))]
    for key in _dict_keys():
        found += [('server/html/static/js/i18n.js', 0, c) for c in H.leftover(key)]
    return found


def _everything():
    return list(_everything_cached())


class TestNoDeviceInProse(unittest.TestCase):
    def test_every_surface(self):
        found = _everything()
        rest, _used = _unallowed(found)
        self.assertEqual(rest, [], '"device" is left in prose. Say "host", or add the sentence to ALLOW with a '
                                   'reason if the word is the right one there:' + _fmt(rest))


@unittest.skipUnless(_HAVE_V8 or browser_required.required(), 'py_mini_racer (V8) not installed')
class TestTranslationsFollowTheEnglish(unittest.TestCase):
    """A key that says "host" must not carry a translation that still says "device".

    The six languages each have a word for a device and a different one for a host. Translations
    written when the English said "device" keep their old word unless somebody reads them again, and
    a French user then sees "hôte" in one sentence and "appareil" in the next for the same machine.
    """

    @classmethod
    def setUpClass(cls):
        if not _HAVE_V8:
            raise AssertionError('RP_BROWSER_REQUIRE is set and py_mini_racer is not installed')
        cls.entries = _dict_entries()

    def test_the_tables_were_read(self):
        self.assertGreater(len(self.entries), 8000, 'the dictionaries came back almost empty')
        host_keyed = [k for k, _v in self.entries if re.search(r'\bhosts?\b', k, re.I)]
        self.assertGreater(len(host_keyed), 800)

    def test_no_translation_keeps_the_old_word(self):
        found, used = [], set()
        for key, vals in self.entries:
            if re.search(r'\bdevices?\b', key, re.I):
                continue
            plain = re.sub(r'(?i)hostnames?|host[- ]?keys?|host[- ]?firewall|host header|localhost|hosting|self-hosted',
                           '', key)
            if not re.search(r'\bhosts?\b', plain, re.I):
                continue
            for lang, rx in STEMS.items():
                val = vals.get(lang)
                if val and rx.search(val):
                    allowed = [a for a in ALLOW_TRANSLATION if re.search(a, key)]
                    if allowed:
                        used.update(allowed)
                    else:
                        found.append(('server/html/static/js/i18n.js', 0, f'[{lang}] {key[:90]}'))
        self.assertEqual(found, [], 'a translation still says "device" where the English says "host":' + _fmt(found))
        self.assertEqual(sorted(set(ALLOW_TRANSLATION) - used), [],
                         'these translation exceptions no longer match anything; delete them')

    def test_the_check_sees_a_translation_that_kept_the_old_word(self):
        sample = {'zh': '重启设备', 'de': 'Gerät neu starten', 'fr': 'Redémarrer l’hôte'}
        hit = [lang for lang, rx in STEMS.items() if sample.get(lang) and rx.search(sample[lang])]
        self.assertEqual(sorted(hit), ['de', 'zh'])
        self.assertIsNone(STEMS['zh'].search('整个设备群'), 'the Chinese word for a fleet must not count')


if __name__ == '__main__':
    unittest.main()
