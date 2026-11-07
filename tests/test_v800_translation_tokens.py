#!/usr/bin/env python3
"""A translation keeps what must not change: identifiers, placeholders, addresses and numbers (8.0.0).

Nobody here reads all six languages, and a gate that only asks "is there a translation, and does it differ from the English" cannot see a
translation that dropped `container_alert_log_lines`, turned `<slug>` into a word or changed 27 January into 28 January. This reads the
dictionary and checks that what a person would copy, type or compare is still there, spelled the same, in every language.

Two populations, because the second has honest exceptions and the first has none:
  * the WHOLE dictionary (every entry written with a double-quoted key and all six languages): names with an underscore
    (`oidc_issuer`), `<placeholders>` and `%s` / `{name}` fields. 287 + 69 + 2 of these were checked when the gate was written and
    none was missing, so the allow-list for this class is empty and a new miss fails the build.
  * the strings the sweep and the tenth round added (NEW_STRINGS): also addresses, paths, numbers and acronyms. A language may use its own word
    for a feature (2-Step Verification, an uninterruptible power supply, "1 hour" in words), so each of those is listed with its reason, and a
    listed exception that stops applying fails the gate, so the list can only shrink.

Entries written in the single-quoted style (`'Tenant': { fr: ... }`) are not read: the count of what is read is held, so the gate cannot go
quiet by reading nothing.
"""
import json
import pathlib
import re
import sys
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import test_new_strings_i18n as _new  # noqa: E402

_I18N = _new._I18N
LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')

_URL = re.compile(r'https?://[^\s,;)…]+')
_ANGLE = re.compile(r'<[A-Za-z_]+>')
_IDENT = re.compile(r'(?<![\w/.-])[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?![\w])')
_PATH = re.compile(r'(?<![\w)])/[a-z][\w./-]+')
_FMT = re.compile(r'%[sd]|\{[a-z_]+\}')
_NUM = re.compile(r'(?<![\w.])\d+(?:[.,]\d+)*(?![\w])')
_ACR = re.compile(r'\b[A-Z]{3,}\b')
_CLASSES = (('url', _URL), ('angle', _ANGLE), ('ident', _IDENT), ('path', _PATH), ('fmt', _FMT), ('num', _NUM), ('acr', _ACR))

STRICT = ('ident', 'angle', 'fmt')                 # the whole dictionary, no exceptions
NEW_ONLY = ('url', 'path', 'num', 'acr')           # the new strings, with the reasons below

# (the start of the English text, the token) -> (the languages that do not keep it, why that is right)
LOCALIZED = {
    ('A switch, printer, camera or UPS.', 'UPS'): ({'es', 'de', 'fr'}, 'the word is SAI, USV and onduleur there'),
    ('The URL must start with http:// or https://', 'URL'): ({'ar'}, 'the word is the Arabic for address there'),
    ('0 sends none. A number from 1 to 10', '0'): ({'ar'}, 'the Arabic starts the sentence with the word for zero'),
    ('Google asks for an app password here', '2'): ({'zh', 'es', 'ar', 'de', 'fr'}, '2-Step Verification is the name each language gives the feature'),
}

_LINE = re.compile(r'^    "((?:[^"\\]|\\.)*)": (\{.*\}),?$', re.M)


def _js(text):
    """A JavaScript double-quoted string body or object literal as JSON: the only escape JSON lacks is \\' ."""
    return text.replace("\\'", "'")


def entries():
    """(English key, {language: text}) for every double-quoted dictionary line that holds all six languages."""
    for m in _LINE.finditer(_I18N):
        try:
            key = json.loads('"%s"' % _js(m.group(1)))
            tr = json.loads(_js(m.group(2)))
        except ValueError:
            continue
        if all(isinstance(tr.get(lang), str) and tr[lang] for lang in LANGS):
            yield key, tr


def tokens(text, classes):
    """[(class, token)] of what in `text` has to survive translation."""
    out = []
    for name, rx in _CLASSES:
        if name in classes:
            out += [(name, m.group(0).rstrip('.,:;')) for m in rx.finditer(text)]
    return out


def holds(text, name, tok):
    """Whether `text` holds the token as a whole: 27 is not in 2027, and a name is not the tail of a longer one."""
    if name == 'num':
        return re.search(r'(?<!\d)' + re.escape(tok) + r'(?!\d)', text) is not None
    if name in ('ident', 'acr'):
        return re.search(r'(?<![A-Za-z0-9_])' + re.escape(tok) + r'(?![A-Za-z0-9_])', text) is not None
    return tok in text


def missing(english, tr, classes):
    """[(class, token, language)] for every token of `english` that a language's text does not hold."""
    return [(name, tok, lang) for name, tok in tokens(english, classes) for lang in LANGS if not holds(tr.get(lang, ''), name, tok)]


class TestTranslationsKeepTheirTokens(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.all = list(entries())

    def test_the_population_is_the_dictionary_and_not_a_corner_of_it(self):
        self.assertGreater(len(self.all), 8000, 'the reader found few entries: its pattern no longer matches the dictionary')
        counted = {name: sum(1 for k, _ in self.all for kind, _tok in tokens(k, STRICT) if kind == name) for name in STRICT}
        self.assertGreater(counted['ident'], 250, counted)
        self.assertGreater(counted['angle'], 60, counted)
        self.assertGreater(counted['fmt'], 0, counted)

    def test_identifiers_placeholders_and_fields_are_in_every_language(self):
        bad = [(k[:80], name, tok, lang) for k, tr in self.all for name, tok, lang in missing(k, tr, STRICT)]
        self.assertEqual(bad, [], 'a translation dropped or changed a name, a <placeholder> or a %s field (language, token above)')

    def test_the_new_strings_keep_their_addresses_paths_and_numbers(self):
        lookup = dict(self.all)
        absent = [s[:60] for s in _new.NEW_STRINGS if s not in lookup]
        self.assertEqual(absent, [], 'a new string has no entry the reader can use')
        bad = {}
        for s in _new.NEW_STRINGS:
            for _, tok, lang in missing(s, lookup[s], NEW_ONLY):
                bad.setdefault((s, tok), set()).add(lang)
        unexplained = {}
        for (s, tok), langs in bad.items():
            allowed = next((v[0] for (start, t), v in LOCALIZED.items() if t == tok and s.startswith(start)), set())
            if langs - allowed:
                unexplained[(s[:70], tok)] = sorted(langs - allowed)
        self.assertEqual(unexplained, {}, 'a language lost an address, a path, a number or an acronym of the English (listed with the languages)')

    def test_every_listed_exception_still_applies_and_names_a_real_string(self):
        lookup = dict(self.all)
        for (start, tok), (langs, why) in LOCALIZED.items():
            hits = [s for s in _new.NEW_STRINGS if s.startswith(start)]
            self.assertEqual(len(hits), 1, 'the exception for %r matches %d new strings' % (start, len(hits)))
            kind = 'acr' if tok.isupper() else 'num'
            absent = {lang for lang in LANGS if not holds(lookup[hits[0]][lang], kind, tok)}
            self.assertEqual(absent, langs, 'the exception for %r (%s) lists %s, the text lacks it in %s: change the list' % (start, why, sorted(langs), sorted(absent)))

    # ── the controls: the check has to be able to say no, and the reader has to see what it should ──
    def test_the_check_says_no_to_a_dropped_name_a_changed_number_and_a_lost_placeholder(self):
        en = 'Set container_alert_log_lines to 5 at https://x.example/app/<slug>/ and say %s'
        good = {lang: 'container_alert_log_lines 5 https://x.example/app/<slug>/ %s' for lang in LANGS}
        self.assertEqual(missing(en, good, STRICT + NEW_ONLY), [])
        bad = dict(good, de='Wert 5 https://x.example/app/<slug>/ %s', fr='container_alert_log_lines 6 https://x.example/app/<slug>/ %s',
                   es='container_alert_log_lines 5 https://x.example/app/slug/ %s', zh='container_alert_log_lines 5 https://x.example/app/<slug>/')
        found = {(name, lang) for name, _, lang in missing(en, bad, STRICT + NEW_ONLY)}
        # the Spanish text lost the angle brackets, so the address that holds <slug> is lost with them
        self.assertEqual(found, {('ident', 'de'), ('num', 'fr'), ('angle', 'es'), ('url', 'es'), ('fmt', 'zh')})

    def test_a_number_is_held_as_a_whole_and_a_name_as_a_whole(self):
        self.assertFalse(holds('Ende 2027', 'num', '27'), '27 is not in 2027')
        self.assertTrue(holds('am 27. Januar 2026', 'num', '27'))
        self.assertTrue(holds('0.25 Stunden', 'num', '0.25'))
        self.assertFalse(holds('my_oidc_issuer', 'ident', 'oidc_issuer'))
        self.assertTrue(holds('Feld oidc_issuer.', 'ident', 'oidc_issuer'))
        self.assertFalse(holds('SMTPS', 'acr', 'SMTP'))

    def test_the_reader_finds_each_kind_of_token(self):
        t = tokens('The issuer is https://a.example/application/o/<slug>/ and the key is oidc_issuer, in 3 of 10 hosts at /api/mcp (%s) {name} on SMTP', STRICT + NEW_ONLY)
        kinds = {name for name, _ in t}
        self.assertEqual(kinds, {'url', 'angle', 'ident', 'path', 'fmt', 'num', 'acr'})
        self.assertIn(('url', 'https://a.example/application/o/<slug>/'), t)
        self.assertIn(('num', '10'), t)

    def test_a_single_quoted_entry_is_not_read_and_is_not_counted_as_read(self):
        sample = "    'Tenant': { fr: 'Locataire', de: 'Mandant' },\n"
        self.assertIsNone(_LINE.search(sample))


if __name__ == '__main__':
    unittest.main()
