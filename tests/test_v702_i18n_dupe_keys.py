#!/usr/bin/env python3
"""A duplicate key in i18n.js silently discards a translation.

JavaScript keeps the LAST definition of a repeated object key. So a duplicate
does not error, does not warn, and does not render: an operator who fixes a
translation by editing the first occurrence sees no change and has no way to
tell why.

Fifty-two of them had accumulated, in two shapes:

  31  a language repeated INSIDE one entry —
      `{ fr: "…", de: "…", fr: "…" }` — where 18 pairs had genuinely different
      French text, so someone's wording edit had been dead since it landed
  21  the same English key defined on two separate LINES, discarding an entire
      six-language set; 20 of those pairs differed, e.g. `Swap` had zh "Swap"
      on the dead entry and zh "交换空间" on the live one

The per-entry completeness check added earlier this release could not see any of
this: it asks whether all six languages are PRESENT, and a duplicate is present
twice.

Pure Python and dependency-free on purpose. eslint's no-dupe-keys found these,
but eslint is not in the CI dep list, and a gate that only runs where someone
happens to have installed a linter is the class of gate this codebase keeps
finding switched off.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
_LANGS = ('fr', 'de', 'zh', 'hi', 'es', 'ar')


def _entry_lines():
    """(line number, dictionary, key, text) for every single-line entry.

    The dictionary matters: DICT is keyed by plain text and HTMLDICT by
    normalised innerHTML, and they are SEPARATE objects — the same English
    string legitimately appears in both, which is not a JavaScript duplicate.
    A first version of this compared across the whole file and reported 50-odd
    of those as bugs.
    """
    out, which = [], None
    for n, ln in enumerate(_I18N.read_text().splitlines(), 1):
        if re.match(r'\s*var (DICT|HTMLDICT)\s*=', ln):
            which = re.match(r'\s*var (DICT|HTMLDICT)\s*=', ln).group(1)
            continue
        st = ln.strip()
        if which is None or not st.startswith(('"', "'")) or ': {' not in st:
            continue
        m = re.match(r'''(["'])(.*?)\1\s*:''', st)
        if m:
            out.append((n, which, m.group(2), st))
    return out


class TestTheScannerWorks(unittest.TestCase):

    def test_it_finds_entries_at_all(self):
        """Positive control — an empty population passes every check below."""
        self.assertGreater(len(_entry_lines()), 3000)

    def test_it_would_catch_a_planted_duplicate(self):
        line = '''"X": { fr: "a", de: "b", fr: "c", zh: "d", hi: "e", es: "f", ar: "g" },'''
        dupes = [lg for lg in _LANGS
                 if len(re.findall(rf'(?<![\w"\']){lg}["\']?\s*:', line)) > 1]
        self.assertEqual(dupes, ['fr'])


class TestNoDuplicateKeys(unittest.TestCase):

    def test_no_language_is_repeated_inside_an_entry(self):
        bad = []
        for n, _d, key, text in _entry_lines():
            for lg in _LANGS:
                if len(re.findall(rf'(?<![\w"\']){lg}["\']?\s*:', text)) > 1:
                    bad.append(f'i18n.js:{n} "{key[:44]}" repeats {lg}')
        self.assertEqual(bad, [],
                         'JavaScript keeps the LAST one, so the other '
                         'translation never renders:\n  ' + '\n  '.join(bad))

    def test_no_english_key_is_defined_twice(self):
        seen, bad = {}, []
        for n, which, key, _text in _entry_lines():
            if (which, key) in seen:
                bad.append(f'{which} "{key[:52]}" at line '
                           f'{seen[(which, key)]} and {n}')
            else:
                seen[(which, key)] = n
        self.assertEqual(bad, [],
                         'the earlier definition is dead — delete it, keeping '
                         'the later one, which is what renders today:\n  '
                         + '\n  '.join(bad))

    def test_every_entry_still_has_all_six_languages(self):
        """Guards the FIX, not the bug: de-duplicating by deleting text is one
        slip away from deleting a language."""
        bad = []
        for n, _d, key, text in _entry_lines():
            for lg in _LANGS:
                if not re.search(rf'["\']?{lg}["\']?\s*:', text):
                    bad.append(f'i18n.js:{n} "{key[:44]}" missing {lg}')
        self.assertEqual(bad, [], '\n  '.join(bad))


if __name__ == '__main__':
    unittest.main()
