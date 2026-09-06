#!/usr/bin/env python3
"""Which server-side constants hold user-facing text — derived, not listed.

`tests/test_v702_server_labels_i18n.py` fixed the class CLAUDE.md had already
recorded: a label that is a Python dict VALUE is not markup, so no extraction
based on `index.html` and `app*.js` can see it. It named five registries.

A named list is the same hole one level up. At v7.0.3, three more registries
were carrying English-only text into the browser with nothing looking at them:

    ACME_DNS_CREDENTIAL_FIELDS  label + hint   5/37 translated
    APP_CATALOG                 description    0/5
    DEFAULT_RATE_CARD           name           1/3

The ACME field labels and hints are the whole Settings -> DNS credential pane,
for eleven providers.

So this file derives the population. Discovery is deliberately WIDE — it
includes `name`, because `DEFAULT_RATE_CARD` uses that key for a human label
while `ACME_DNS_CREDENTIAL_FIELDS` uses it for an environment variable. Which
keys of a given registry are actually translatable is then stated per registry,
so the wide scan cannot start demanding a translation of `CF_Token`.

Two kinds of string stay English on purpose, because translating them would be
worse than leaving them:
  * identifiers the operator copies — environment variable names, DNSBL zone
    operators, product names;
  * example DATA — a sample URL, a list of literal endpoint values.
"""
import ast
import importlib.util
import pathlib
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'

# Wide, for DISCOVERY only. What is translatable is decided per registry below.
_LABELISH_KEYS = {'label', 'hint', 'desc', 'description', 'summary',
                  'fix_label', 'cat', 'name', 'title', 'text'}

# Enough label-ish strings to be a registry rather than an incidental literal.
_MIN_STRINGS = 3

# Registries an existing gate measures. Value: the gate that owns it.
_COVERED_ELSEWHERE = {
    'EVENT_REGISTRY': 'test_v702_server_labels_i18n.py',
    'CHANNEL_KIND_DEFS': 'test_v702_server_labels_i18n.py',
    '_AI_PROMPT_LABELS': 'test_v702_server_labels_i18n.py',
    '_MITIGATE_PLAYBOOKS': 'test_v702_server_labels_i18n.py',
    'CHECK_BASELINE_CATALOG': 'test_v702_server_labels_i18n.py',
    'ACTION_CLASSES': 'test_v700_action_labels_translated.py',
}

# Registries this file measures: name -> the keys whose values are PROSE.
_COVERED_HERE = {
    'ACME_DNS_CREDENTIAL_FIELDS': {'label', 'hint'},   # `name` is an env var
    'APP_CATALOG': {'description'},                    # `name` is a product
    'DEFAULT_RATE_CARD': {'name'},                     # `name` IS the label
    'RESOURCE_DEFS': {'label', 'name'},
}

# Constants whose strings must NOT be translated at all, each with its reason.
_EXEMPT = {
    'DEFAULT_DNSBLS': 'DNSBL zone operators (Spamhaus, SORBS, SpamCop) — '
                      'proper nouns an operator matches against a log line',
}

# Individual strings inside a covered registry that stay English, with reasons.
_UNTRANSLATED_STRINGS = {
    'e.g. https://auth.acme-dns.io':
        'an example URL the operator copies, not prose',
    'ovh-eu / ovh-ca / ovh-us / kimsufi-eu / soyoustart-eu (default: ovh-eu).':
        'the literal endpoint values OVH accepts',
}


def _dict_keys():
    """Reuse the v7.0.2 gate's parser rather than writing a second one.

    CLAUDE.md records two sessions that reported thousands of phantom gaps by
    writing a fresh i18n.js parser. That one has its own control test.
    """
    spec = importlib.util.spec_from_file_location(
        '_server_labels_gate',
        _ROOT / 'tests' / 'test_v702_server_labels_i18n.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._dict_keys()


def _strings_under(node, wanted, out, key=None):
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            kn = k.value if isinstance(k, ast.Constant) else None
            _strings_under(v, wanted, out, kn if isinstance(kn, str) else key)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for e in node.elts:
            _strings_under(e, wanted, out, key)
    elif isinstance(node, ast.Call):
        for kw in node.keywords:
            _strings_under(kw.value, wanted, out, kw.arg)
        for a in node.args:
            _strings_under(a, wanted, out, key)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        if key in wanted and node.value.strip():
            out.append(node.value)


def _constant_nodes():
    for f in sorted(_CGI.glob('*.py')):
        try:
            tree = ast.parse(f.read_text(encoding='utf-8'))
        except SyntaxError:                                # pragma: no cover
            continue
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        yield f.name, target.id, node.value


def label_bearing_constants(keys=None):
    """{constant name: sorted label-ish strings} across server/cgi-bin."""
    found = {}
    for _fname, name, value in _constant_nodes():
        out = []
        _strings_under(value, keys or _LABELISH_KEYS, out)
        if len(set(out)) >= _MIN_STRINGS:
            found.setdefault(name, set()).update(out)
    return {k: sorted(v) for k, v in found.items()}


def prose_strings(constant, keys):
    """The strings of one constant under the keys that hold prose."""
    out = []
    for _fname, name, value in _constant_nodes():
        if name == constant:
            _strings_under(value, keys, out)
    return sorted(set(out))


class TestThePopulationIsDerived(unittest.TestCase):

    def test_every_label_bearing_constant_is_covered_or_exempt(self):
        known = set(_COVERED_ELSEWHERE) | set(_COVERED_HERE) | set(_EXEMPT)
        unknown = sorted(set(label_bearing_constants()) - known)
        self.assertEqual(
            unknown, [],
            "these server constants carry user-facing text that no i18n gate "
            "measures. Add DICT entries and a _COVERED_HERE entry naming which "
            "keys hold prose, or exempt them with the reason they stay "
            f"English: {unknown}")

    def test_the_scan_finds_the_registries_we_know_about(self):
        """The control. A scan that finds nothing passes the check above —
        which is how a named list of five went unquestioned for a release."""
        found = label_bearing_constants()
        for known in ('EVENT_REGISTRY', 'CHECK_BASELINE_CATALOG',
                      'ACME_DNS_CREDENTIAL_FIELDS', 'APP_CATALOG',
                      'DEFAULT_RATE_CARD', 'DEFAULT_DNSBLS'):
            self.assertIn(known, found,
                          f"the scan no longer sees {known} — the scan is "
                          "broken, not the code")
        self.assertGreaterEqual(len(found), 9, sorted(found))

    def test_discovery_is_wider_than_what_it_demands(self):
        """`name` must be in DISCOVERY (DEFAULT_RATE_CARD's labels live there)
        and must not be demanded of ACME, where it is an environment variable
        the operator types exactly. Narrow either way and this gate is wrong in
        one of the two directions."""
        self.assertIn('name', _LABELISH_KEYS)
        self.assertNotIn('name', _COVERED_HERE['ACME_DNS_CREDENTIAL_FIELDS'])
        acme_all = label_bearing_constants()['ACME_DNS_CREDENTIAL_FIELDS']
        self.assertIn('CF_Token', acme_all, "discovery should SEE the env var")
        acme_prose = prose_strings('ACME_DNS_CREDENTIAL_FIELDS',
                                   _COVERED_HERE['ACME_DNS_CREDENTIAL_FIELDS'])
        self.assertNotIn('CF_Token', acme_prose,
                         "and must not DEMAND a translation of it")
        self.assertIn('API Token (recommended)', acme_prose)


class TestTheNewlyCoveredRegistriesAreTranslated(unittest.TestCase):

    def test_every_prose_string_has_a_dictionary_entry(self):
        keys = _dict_keys()
        self.assertGreater(len(keys), 1000, "the DICT parse collapsed")
        missing = {}
        for const, prose_keys in _COVERED_HERE.items():
            gaps = [s for s in prose_strings(const, prose_keys)
                    if s not in keys and s not in _UNTRANSLATED_STRINGS]
            if gaps:
                missing[const] = gaps
        self.assertEqual(
            missing, {},
            "server-provided text with no DICT entry — it renders as a bare "
            "text node, so an entry for the English string is the whole fix")

    def test_the_exempt_strings_are_still_there(self):
        """An exemption for a string that no longer exists is dead weight that
        makes the list look considered when it is stale."""
        every = {s for v in label_bearing_constants().values() for s in v}
        for s in _UNTRANSLATED_STRINGS:
            self.assertIn(s, every,
                          f"exempted string no longer in any registry: {s!r}")


if __name__ == '__main__':
    unittest.main()
