#!/usr/bin/env python3
"""Server-provided labels are invisible to every markup-based i18n gate.

`tests/test_v430_i18n_gate.py` extracts from `index.html` and `app*.js`. A
label that lives as a Python dict VALUE and is sent to the browser in a JSON
response is not markup, so no extraction sees it. CLAUDE.md records the shape
already: 24 autonomy action labels shipped English-only with that gate fully
green.

Measured at v7.0.2, before this file existed:

    EVENT_REGISTRY.label                0/214 translated
    CHANNEL_KIND_DEFS.label             8/83
    _AI_PROMPT_LABELS                   1/70
    _MITIGATE_PLAYBOOKS label+fix_label 7/26
    CHECK_BASELINE_CATALOG cat/name/desc 1/12, 0/79, 0/79

EVENT_REGISTRY.label is the whole Settings -> Notifications table — 214 rows of
English in every one of the six other languages.

No JS change was needed to fix it. The engine translates any TEXT NODE whose
trimmed text is a DICT key, and a MutationObserver re-runs over JS-injected
nodes, so a DICT entry for the English string is the entire fix. This file
proves that end to end rather than assuming it: `test_every_label_round_trips_
through_the_real_engine` loads i18n.js in node and asks the engine itself.

THE ONE THING THAT BLOCKS THE ROUND TRIP IS LENGTH. `translateTextNode` skips a
text node longer than its own cap, so a label above it cannot be translated no
matter what DICT holds. Nine baseline-check descriptions (up to 392 chars) sat
above the old 200-char cap and were untranslatable for that reason alone; the
cap is 400 now. `test_no_label_exceeds_the_engines_text_node_cap` reads the cap
out of i18n.js so the two cannot drift apart again.

Not in the population, on purpose:
  * `EVENT_REGISTRY[...]['title']` and `tags` — webhook/push/email decoration.
    They never become a DOM text node, so DICT cannot reach them; translating
    them needs a different mechanism and would be a different gate.
  * `_MITIGATE_PLAYBOOKS[...]['diagnostic']` / `['fix']` — shell commands.
"""
import ast
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'
_CHECKS = _ROOT / 'server' / 'cgi-bin' / 'checks.py'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
_NODE = shutil.which('node')

# Mirrors test_v430_i18n_gate.LANGS: every language the UI ships besides English.
_LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')


# ── the dictionary ───────────────────────────────────────────────────────────
def _dict_keys():
    """Every DICT key in i18n.js.

    Both quote styles, because the file mixes them: the curated chrome block is
    single-quoted and the machine-written catalog is double-quoted. CLAUDE.md
    records two separate sessions that reported thousands of phantom gaps by
    matching one style, or by using a character class that excluded the quote.
    `test_the_dictionary_parse_is_not_lying` is the control for this function.
    """
    src = _I18N.read_text(encoding='utf-8')
    start = src.index('var DICT = {')
    body = src[start:src.index('\n  };', start)]
    keys = set()
    for m in re.finditer(
            r"""^\s{4}(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*:\s*\{""",
            body, re.M):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        keys.add(raw.replace("\\'", "'").replace('\\"', '"').replace('\\\\', '\\'))
    return keys


def _engine_text_node_cap():
    """The engine's own maximum translatable text-node length, read from source.

    Hardcoding it here would let the two drift, which is exactly how nine
    descriptions became untranslatable while every key was present.
    """
    m = re.search(r'trimmed\.length\s*>\s*(\d+)', _I18N.read_text(encoding='utf-8'))
    assert m, 'the text-node length cap is no longer in translateTextNode'
    return int(m.group(1))


# ── the population, derived from the registries themselves ───────────────────
def _top_level_value(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
    raise AssertionError(f'{name} is no longer a top-level assignment')


def _literal(node):
    """Evaluate a literal, treating `dict(...)` calls as dict displays.

    EVENT_REGISTRY entries are written `dict(label=..., kind=...)`, which
    `ast.literal_eval` refuses.
    """
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'dict'):
        out = {}
        for kw in node.keywords:
            try:
                out[kw.arg] = _literal(kw.value)
            except Exception:
                out[kw.arg] = None
        return out
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _registries():
    """{registry name: [user-facing English strings]} straight from the source.

    Derived, never a maintained list: a registry that gains a row is in the
    population the moment it lands. A hand-kept copy of these strings would go
    stale the same way the markup gate's caps did.
    """
    api = ast.parse(_API.read_text(encoding='utf-8'))
    chk = ast.parse(_CHECKS.read_text(encoding='utf-8'))
    out = {}

    ev = _top_level_value(api, 'EVENT_REGISTRY')
    out['EVENT_REGISTRY.label'] = [
        (_literal(v) or {}).get('label') for v in ev.values]

    kinds = _top_level_value(api, 'CHANNEL_KIND_DEFS')
    out['CHANNEL_KIND_DEFS.label'] = [
        (_literal(e) or (None, None))[1] for e in kinds.elts]

    ai = _top_level_value(api, '_AI_PROMPT_LABELS')
    out['_AI_PROMPT_LABELS'] = [_literal(v) for v in ai.values]

    pb = [_literal(v) or {} for v in _top_level_value(api, '_MITIGATE_PLAYBOOKS').values]
    out['_MITIGATE_PLAYBOOKS.label'] = [p.get('label') for p in pb]
    out['_MITIGATE_PLAYBOOKS.fix_label'] = [p.get('fix_label') for p in pb]

    cat = [_literal(e) or {} for e in _top_level_value(chk, 'CHECK_BASELINE_CATALOG').elts]
    out['CHECK_BASELINE_CATALOG.cat'] = [c.get('cat') for c in cat]
    out['CHECK_BASELINE_CATALOG.name'] = [c.get('name') for c in cat]
    out['CHECK_BASELINE_CATALOG.desc'] = [c.get('desc') for c in cat]

    return {k: sorted({s for s in v if isinstance(s, str) and s.strip()})
            for k, v in out.items()}


# Minimum size per registry. A derivation that silently returned nothing would
# make every assertion below pass over an empty set — the failure mode this
# project keeps rediscovering. Deliberately well under the real counts (215 /
# 83 / 70 / 21 / 79 at the time of writing) so ordinary growth or a removed row
# does not fail here; a broken parse falls off a cliff, it does not drift.
_FLOOR = {
    'EVENT_REGISTRY.label': 150,
    'CHANNEL_KIND_DEFS.label': 60,
    '_AI_PROMPT_LABELS': 50,
    '_MITIGATE_PLAYBOOKS.label': 15,
    '_MITIGATE_PLAYBOOKS.fix_label': 5,
    'CHECK_BASELINE_CATALOG.cat': 8,
    'CHECK_BASELINE_CATALOG.name': 60,
    'CHECK_BASELINE_CATALOG.desc': 60,
}


def _untranslated(strings, keys):
    return sorted(s for s in strings if s not in keys)


class TestServerLabelsAreTranslated(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.registries = _registries()
        cls.keys = _dict_keys()
        cls.cap = _engine_text_node_cap()

    def test_the_dictionary_parse_is_not_lying(self):
        """Positive control for _dict_keys.

        Every assertion in this file is 'is this string a DICT key?'. A parse
        that returned nothing, or that dropped one of the two quote styles,
        would report the whole product as untranslated — an instrument error
        wearing a finding's clothes, and the exact one CLAUDE.md says was walked
        into twice.
        """
        self.assertGreater(len(self.keys), 4000,
                           'DICT parse found almost nothing')
        # One key from each quote style block.
        self.assertIn('Dashboard', self.keys)
        self.assertIn('Device went offline', self.keys)
        self.assertNotIn('zzz not a key in any dictionary', self.keys)

    def test_population_is_derived_and_nonempty(self):
        got = {k: len(v) for k, v in self.registries.items()}
        short = {k: (n, _FLOOR[k]) for k, n in got.items() if n < _FLOOR[k]}
        self.assertEqual(short, {},
                         'a registry derivation collapsed (found, floor): '
                         + json.dumps(short))
        self.assertEqual(sorted(got), sorted(_FLOOR),
                         'a registry was added or removed without updating the '
                         f'floor map: {sorted(got)}')

    def test_every_registry_label_has_a_dict_entry(self):
        missing = {}
        for name, strings in self.registries.items():
            gap = _untranslated(strings, self.keys)
            if gap:
                missing[name] = gap
        self.assertEqual(missing, {}, '\n'.join([
            'these server-provided labels reach the browser with no DICT '
            'entry, so they render English in all six other languages:',
            json.dumps(missing, indent=2, ensure_ascii=False),
            '',
            'The fix is normally a DICT entry in i18n.js for the English '
            'string and no JS change at all: the engine translates any text '
            'node matching a DICT key, and a MutationObserver covers the '
            'nodes these labels are rendered into.',
            '',
            'Never invent a translation you are unsure of — English falls back '
            'gracefully and a wrong translation does not.']))

    def test_every_dict_entry_carries_all_six_languages(self):
        """A half-filled entry renders English for the missing languages, which
        looks identical to having no entry at all."""
        src = _I18N.read_text(encoding='utf-8')
        start = src.index('var DICT = {')
        body = src[start:src.index('\n  };', start)]
        rows = {}
        for m in re.finditer(
                r"""^\s{4}(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*:\s*\{([^}]*)\}""",
                body, re.M):
            raw = m.group(1) if m.group(1) is not None else m.group(2)
            key = raw.replace("\\'", "'").replace('\\"', '"').replace('\\\\', '\\')
            rows[key] = set(re.findall(r'["\']?(\w+)["\']?\s*:', m.group(3)))
        partial = {}
        for strings in self.registries.values():
            for s in strings:
                langs = rows.get(s)
                if langs is not None and not set(_LANGS) <= langs:
                    partial[s] = sorted(set(_LANGS) - langs)
        self.assertEqual(partial, {}, 'server labels missing languages: '
                         + json.dumps(partial, indent=2, ensure_ascii=False))

    def test_no_label_exceeds_the_engines_text_node_cap(self):
        """Presence in DICT is not sufficient — the engine has to look.

        translateTextNode returns early on a text node longer than its cap, so
        a longer label is untranslatable with a perfectly good DICT entry and
        nothing anywhere reports it. Nine CHECK_BASELINE_CATALOG descriptions
        were in that state.
        """
        over = {}
        for name, strings in self.registries.items():
            for s in strings:
                if len(s) > self.cap:
                    over.setdefault(name, []).append((len(s), s[:80] + '…'))
        self.assertEqual(over, {}, '\n'.join([
            f'these labels are longer than the engine cap ({self.cap} chars), '
            'so a DICT entry for them would never be applied:',
            json.dumps(over, indent=2, ensure_ascii=False),
            '',
            'Either shorten the label or raise the cap in translateTextNode '
            '(i18n.js) — and if you raise it, raise the extraction caps in '
            'test_v430_i18n_gate.py with it.']))

    def test_the_gate_catches_an_untranslated_string(self):
        """Control on the RULE. Inject a string no dictionary will ever hold
        and require the checker to name it; otherwise a checker that always
        returned [] would make every assertion above pass.
        """
        fake = 'Sentinel label that no dictionary will ever carry'
        self.assertNotIn(fake, self.keys)
        self.assertEqual(_untranslated([fake], self.keys), [fake])
        # And the length rule, the other half of the gate.
        self.assertGreater(len('x' * (self.cap + 1)), self.cap)


@unittest.skipUnless(_NODE, 'node not installed')
class TestLabelsRoundTripThroughTheRealEngine(unittest.TestCase):
    """Ask i18n.js itself, rather than asserting a key is present and hoping.

    `RPi18n.setLang(lang)` + `RPi18n.t(s)` is the exact lookup translateTextNode
    performs, so a string that comes back unchanged is a string the operator
    reads in English.
    """

    @classmethod
    def setUpClass(cls):
        strings = sorted({s for v in _registries().values() for s in v})
        cls.count = len(strings)
        work = pathlib.Path(tempfile.mkdtemp(prefix='rp-i18n-'))
        # i18n.js is a browser IIFE that hangs RPi18n off `window`. The shim is
        # the smallest DOM that lets it reach that line: it never renders, so
        # createTreeWalker is absent on purpose and translateTextNodes returns
        # early. What is under test is the dictionary lookup.
        (work / 'run.js').write_text('''
const store = {};
global.localStorage = { getItem: k => (k in store ? store[k] : null),
                        setItem: (k, v) => { store[k] = String(v); } };
const stub = () => ({
  setAttribute(){}, getAttribute(){ return null; }, hasAttribute(){ return false; },
  querySelectorAll(){ return []; }, addEventListener(){}, appendChild(){},
  dataset: {}, classList: { contains(){ return false; } }, value: '', style: {},
});
global.document = { readyState: 'complete', documentElement: stub(), body: null,
                    createElement: stub, createTreeWalker: null,
                    getElementById(){ return null; }, querySelectorAll(){ return []; },
                    addEventListener(){} };
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
''', encoding='utf-8')
        # The label list rides stdin rather than a scratch strings.json:
        # a suite-wide scan for fixtures that write DATA_DIR as files cannot
        # tell that name apart from a storage key.
        r = subprocess.run([_NODE, str(work / 'run.js'), str(_I18N)],
                           input=json.dumps(strings),
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise AssertionError('node could not load i18n.js: '
                                 + r.stderr[-800:])
        cls.untranslated = json.loads(r.stdout)

    def test_the_harness_actually_ran(self):
        """Positive control. An empty result set would satisfy every
        'nothing untranslated' assertion below without testing anything."""
        self.assertGreater(self.count, 400, 'population collapsed')
        self.assertEqual(sorted(self.untranslated), sorted(_LANGS),
                         'the engine reported a different language set than '
                         'this gate checks')

    def test_every_label_round_trips_through_the_real_engine(self):
        gaps = {lang: v for lang, v in self.untranslated.items() if v}
        self.assertEqual(gaps, {}, 'the real engine returns these unchanged: '
                         + json.dumps({k: v[:10] for k, v in gaps.items()},
                                      indent=2, ensure_ascii=False))

    def test_a_string_with_no_entry_is_reported(self):
        """Control on the harness: prove it can say no.

        `t()` falls back to the English source, so a broken lookup and a
        perfect one produce the same output for a translated string. Only an
        UNtranslated one separates them.
        """
        self.assertNotIn('Device went offline', self.untranslated['de'])
        # Re-run with a string that is certainly absent.
        r = subprocess.run(
            [_NODE, '-e', '''
const store={};global.localStorage={getItem:()=>null,setItem:()=>{}};
const stub=()=>({setAttribute(){},getAttribute(){return null},hasAttribute(){return false},
querySelectorAll(){return[]},addEventListener(){},appendChild(){},dataset:{},
classList:{contains(){return false}},value:'',style:{}});
global.document={readyState:'complete',documentElement:stub(),body:null,createElement:stub,
createTreeWalker:null,getElementById(){return null},querySelectorAll(){return[]},addEventListener(){}};
global.window=global;global.fetch=()=>({catch(){}});
require(process.argv[1]);
window.RPi18n.setLang('de', false);
console.log(window.RPi18n.t('Sentinel label that no dictionary will ever carry'));
''', str(_I18N)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertEqual(r.stdout.strip(),
                         'Sentinel label that no dictionary will ever carry',
                         'the harness cannot distinguish a missing entry from '
                         'a present one')


if __name__ == '__main__':
    unittest.main()
