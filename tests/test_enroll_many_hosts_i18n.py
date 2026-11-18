#!/usr/bin/env python3
"""Every string the "Hosts that can use it" work put on screen has all six languages in the dictionary.

The key is the English text exactly as it is written in index.html or a script. The coverage gates in test_v430_i18n_gate see only some
kinds of text (the wizard's sentences and the list's words are not among them), so this lists the strings and holds three things for
each: it is a key with zh, hi, es, ar, de and fr; the real engine, run under node, hands back a translation and not the English; and the
sentence is still written that way in the page or a script (a reworded sentence would otherwise drop out of the dictionary unnoticed).

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

# where each sentence is drawn: 'html' (index.html) or 'js' (a script builds it)
STRINGS = {
    # the field and its notice, in the Enroll dialog and in the wizard's Settings step
    'Hosts that can use it': 'both',
    'Anyone who holds this command can enroll that many hosts until it expires. A copy can also stay in the shell history of each host and in the log of any proxy in front of this server, so revoke it when the rollout is done.': 'both',
    'Enter a whole number of hosts from 1 to 1000': 'js',
    # what the dialog says under a command that works for more than one host
    'This token works for the number of hosts you set, and expires in 24h. Downloads the agent from this server, verifies its checksum, enrols, and the host appears by its hostname.': 'js',
    'Save as docker-compose.yml on each host, then: docker compose up -d — the token works for the number of hosts you set and expires in 24h.': 'js',
    'The command works for as many hosts as you set, and stops working after the time you chose or when you revoke it.': 'js',
    # the dialog's text that no longer says "one-time" (the sentence was reworded, so the key moved)
    'Mints a token and hands you a one-line command for': 'html',
    'No install needed — run the agent as a container. This mints an enrollment token and a ready-to-run': 'html',
    # the list of open install commands
    '— install commands that are still open —': 'html',
    'Commands that can still enroll hosts. Revoke one to stop it working.': 'html',
    'No install commands are open.': 'js',
    'used': 'js',
    'of': 'js',
    'Revoke this install command? It stops working at once, for hosts that have not enrolled with it yet.': 'js',
    'Install command revoked': 'js',
    'Could not revoke the install command': 'js',
}

# the two sentences that said "one-time" and were reworded
GONE = (
    'Mints a one-time token and hands you a one-line command for',
    'No install needed — run the agent as a container. This mints a one-time enrollment token and a ready-to-run',
)


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

    def test_the_two_sentences_that_said_one_time_are_gone_from_the_dictionary_and_the_page(self):
        rows = dict_rows()
        for old in GONE:
            self.assertTrue(old not in rows, 'the old key is still in the dictionary')
            self.assertTrue(old not in _HTML, 'the old sentence is still in the page')

    def test_every_string_is_still_written_that_way(self):
        for s, where in STRINGS.items():
            if where in ('html', 'both'):
                # a text node of the page starts right after a tag (a sentence with inline markup is cut at the tag, so it may end with a space)
                self.assertTrue(('>' + s) in _HTML, f'not in index.html as a text node: {s}')
            if where in ('js', 'both'):
                # a script holds it as a quoted string
                self.assertTrue(f"'{s}'" in _JS or f'"{s}"' in _JS, f'not in a script: {s}')

    def test_a_translation_is_a_translation_and_not_a_copy_of_the_english(self):
        rows = dict_rows()
        text = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text(encoding='utf-8')
        self.assertTrue(all(s in rows for s in STRINGS))
        # the numbers a sentence carries survive translation (1000 is the limit the field and the server share)
        i = text.index('"Enter a whole number of hosts from 1 to 1000"')
        line = text[i:text.index('\n', i)]
        self.assertGreaterEqual(line.count('1000'), 7, 'a language dropped the limit from the message: ' + line[:200])


if __name__ == '__main__':
    unittest.main()
