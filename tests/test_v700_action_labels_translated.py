#!/usr/bin/env python3
"""Every autonomy action label must carry all six translations.

The 24 labels in `ACTION_CLASSES` are server-provided strings rendered beside
each machine name in the allow-list. The translation engine handles them as
ordinary text nodes, so a DICT entry is the whole fix — but the i18n gate scans
STATIC markup and `app*.js` literals, and a label that only exists as a Python
dict value is invisible to it. All 24 shipped English-only and the gate was
green.

That is the same shape as the rest of this release's findings: the rule is
followed everywhere the gate looks.

WHY ALL SIX AND NOT A BACKLOG. CLAUDE.md's rule is never to fabricate a
translation, because English fallback is graceful and a wrong translation is
worse — which is why the attribute backlog exists for strings that are example
DATA (cron lines, log paths, PEM blocks). These are none of those: they are short
imperative phrases about a well-defined technical action, and the machine name
sits next to each one in a `<code>` element, so the reader has the unambiguous
identifier regardless.
"""
import importlib.util
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'

_spec = importlib.util.spec_from_file_location('autonomy_i18n', _CGI / 'autonomy.py')
autonomy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(autonomy)

_LANGS = ('fr', 'de', 'zh', 'hi', 'es', 'ar')


def _dict_entry(label):
    """The DICT value block for `label`, or None.

    Language keys in DICT are UNQUOTED (`fr:`) while HTMLDICT quotes them
    (`"fr":`). CLAUDE.md records that exact trap — a pattern that assumes one
    form reports thousands of false gaps in the other. Accept both.
    """
    src = _I18N.read_text(encoding='utf-8')
    m = re.search(r'"' + re.escape(label) + r'":\s*\{([^{}]*)\}', src)
    return m.group(1) if m else None


class TestTheProbeWorks(unittest.TestCase):

    def test_it_finds_a_known_entry(self):
        """Control: a label already known to be translated must be found, or
        every assertion below is measuring a broken regex."""
        body = _dict_entry('Autonomy')
        self.assertIsNotNone(body, 'the DICT lookup found nothing for "Autonomy"')
        for lang in _LANGS:
            self.assertRegex(body, rf'(?:"{lang}"|{lang})\s*:')

    def test_it_reports_a_missing_entry_as_missing(self):
        self.assertIsNone(_dict_entry('This String Is Not In DICT At All'))

    def test_there_are_labels_to_check(self):
        self.assertGreater(len(autonomy.ACTION_CLASSES), 20)


class TestEveryLabelIsTranslated(unittest.TestCase):

    def test_all_of_them_are_in_dict(self):
        missing = sorted(spec['label'] for spec in autonomy.ACTION_CLASSES.values()
                         if _dict_entry(spec['label']) is None)
        self.assertEqual(
            missing, [],
            'these action labels render in the allow-list with no DICT entry, '
            'so they stay English in every language. The i18n gate cannot see '
            'them: they are Python dict values, not markup.\n'
            + '\n'.join('  ' + m for m in missing))

    def test_each_carries_all_six_languages(self):
        bad = {}
        for spec in autonomy.ACTION_CLASSES.values():
            body = _dict_entry(spec['label'])
            if body is None:
                continue
            absent = [l for l in _LANGS
                      if not re.search(rf'(?:"{l}"|{l})\s*:', body)]
            if absent:
                bad[spec['label']] = absent
        self.assertEqual(bad, {},
                         'action labels with an incomplete language set: '
                         + repr(bad))

    def test_no_translation_is_just_the_english(self):
        """A copied English string is worse than no entry: the fallback would
        have produced the same text, and the entry claims it was translated.
        Latin-script cognates are legitimate in fr/de/es, so this only fails
        when a value is byte-identical to the English in a language that could
        not plausibly share it."""
        for spec in autonomy.ACTION_CLASSES.values():
            en = spec['label']
            body = _dict_entry(en) or ''
            for lang in ('zh', 'hi', 'ar'):
                m = re.search(rf'(?:"{lang}"|{lang})\s*:\s*"([^"]*)"', body)
                if m:
                    self.assertNotEqual(
                        m.group(1), en,
                        f'{lang} for {en!r} is the untranslated English')


if __name__ == '__main__':
    unittest.main()
