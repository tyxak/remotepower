#!/usr/bin/env python3
"""Every string that the password history and maximum age work put on screen has all six languages in the dictionary.

The key is the English text exactly as it is written in index.html, a script or the server. The coverage gates in test_v430_i18n_gate see
only some kinds of text, so this lists the strings and holds three things for each: it is a key with zh, hi, es, ar, de and fr; the real
engine, run under node, hands back a translation and not the English; and the sentence is still written that way where it is shown (a
reworded sentence would otherwise drop out of the dictionary unnoticed).

The translations are machine-written. A person who reads one of the six languages should read them before a release.
"""
import pathlib
import shutil
import sys
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from i18n_engine import LANGS, dict_rows, unchanged_by_engine  # noqa: E402

_ROOT = _HERE.parent
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_JS = '\n'.join(p.read_text(encoding='utf-8') for p in sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')))
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(encoding='utf-8')

# where each sentence is shown: 'html' (index.html), 'js' (a script builds it) or 'py' (the server answers with it)
STRINGS = {
    # the Settings fields
    "Applied to new users and password changes. The length and character rules never invalidate a password someone already has; the maximum age does, at that person's next sign-in. Every rule is off until you set it.": 'html',
    "Passwords remembered (0 = off, at most 24). At 3, a new password cannot be the one in use now or either of the two before it": 'html',
    "Maximum password age in days (0 = off, at most 3650). A local password older than this has to be changed at the next sign-in. Accounts that sign in through LDAP, OIDC or SAML are not affected": 'html',
    # the banner that says why a change is asked for (the second is the default-password banner, which had no translation)
    '\u26a0 Your password has expired.': 'js',
    '\u26a0 This account is using the default password.': 'js',
    'Change it now': 'js',
    '\u2014 click here.': 'js',
    # what the server says when a change is refused
    'This password was used recently. Choose one you have not used before.': 'py',
    'The password changed while this request was running. Try again.': 'py',
    'Too many password changes. Wait a minute and try again.': 'py',
    'The value must be a whole number within the range this setting allows.': 'py',
}

# the hint that said "existing passwords are never invalidated", which is no longer true once a maximum age is set
GONE = 'Applied to new users and password changes (existing passwords are never invalidated). Opt-in — leave length at 0 to keep the current behaviour.'


class TestSixLanguages(unittest.TestCase):

    def test_every_string_is_a_key_with_all_six_languages(self):
        rows = dict_rows()
        missing = {s: sorted(set(LANGS) - rows.get(s, set())) for s in STRINGS if set(LANGS) - rows.get(s, set())}
        self.assertEqual(missing, {}, 'strings without a complete translation')

    def test_the_real_engine_translates_every_string_in_every_language(self):
        if not shutil.which('node'):
            self.skipTest('node is not installed')
        left = unchanged_by_engine(list(STRINGS))
        self.assertEqual({k: v for k, v in left.items() if v}, {}, 'the engine hands these back in English')

    def test_the_old_hint_is_gone_from_the_page_and_the_dictionary(self):
        self.assertTrue(GONE not in dict_rows(), 'the old key is still in the dictionary')
        self.assertTrue(GONE not in _HTML, 'the old sentence is still in the page')

    def test_every_string_is_still_written_that_way(self):
        for s, where in STRINGS.items():
            if where == 'html':
                self.assertTrue(('>' + s + '<') in _HTML, f'not in index.html as a text node: {s}')
            elif where == 'js':
                # a script holds it inside a longer string (the banner is one string with markup) or on its own
                esc = s.replace('\u26a0', '\\u26a0').replace('\u2014', '\\u2014')
                self.assertTrue(s in _JS or esc in _JS, f'not in a script: {s}')
            else:
                self.assertTrue(f"'{s}'" in _API, f'not in api.py as a message: {s}')


if __name__ == '__main__':
    unittest.main()
