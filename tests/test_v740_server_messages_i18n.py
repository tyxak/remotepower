"""Every error message the server sends is translated, or listed as not yet.

The server answers a refused request with {'error': '<sentence>'}, and the dashboard shows that
sentence as it arrives: api() toasts it, a form prints it under the field. The translator matches a
whole text node against the dictionary, so the sentence has to be a dictionary key, spelled the way
the server spells it. At 7.4.0 the server sent 991 distinct literal sentences and the dictionary held
7 of them, so a person who chose German read English every time something was refused.

The population is read from the source: each respond(<status>, {'error': '<literal>'}) in any server
module (tests/server_messages.py), so a message is counted the moment a handler is written. The gate
asks four things:

  * a message is a dictionary key with all six languages, or it is in
    tests/data/server_message_i18n_backlog.txt. That list only shrinks: a new message has to arrive
    translated, and a listed message that has been translated (or deleted) has to come off it;
  * the real engine, run in node, returns something other than the English for every translated
    message in every language;
  * a message longer than the engine's text-node cap could never be matched, so none may be;
  * the number of messages built with an f-string does not grow.

Recorded, not hidden: an f-string message (f'unknown provider {provider!r}') puts the variable inside
the text node, so no dictionary key can equal it. A message that needs a variable should send the
fixed sentence and carry the variable in a field of its own. And some `error` values are not literals
in a respond() at all (a validator's result, str(e)); this scan cannot see those.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import LANGS, dict_rows, text_node_cap, unchanged_by_engine  # noqa: E402
from server_messages import census, fstring_census, fstring_sites_of, sites_of  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BACKLOG = ROOT / 'tests' / 'data' / 'server_message_i18n_backlog.txt'

# respond() calls whose 'error' is an f-string. It is a ratchet in both directions: lower it in the
# same commit that removes one, so it can never creep back up unseen.
F_STRING_SITES = 305

# Messages whose translation is the English itself in a language (a protocol name, a loan word). The
# engine hands them back unchanged and that is correct. An entry that stops being identical is stale.
SAME_IN_LANGUAGE = {}


# ── the rules, as functions the controls can call ────────────────────────────
def distinct_messages(sites):
    return sorted({site[3] for site in sites})


def read_backlog(path=BACKLOG):
    return [ln for ln in path.read_text(encoding='utf-8').split('\n') if ln and not ln.startswith('#')]


def untranslated(messages, keys):
    return [m for m in messages if m not in keys]


def arrived_untranslated(messages, keys, backlog):
    """Messages with no dictionary entry that the backlog does not account for."""
    listed = set(backlog)
    return [m for m in untranslated(messages, keys) if m not in listed]


def stale_backlog(messages, keys, backlog):
    """(listed but translated now, listed but no longer sent by the server)."""
    present = set(messages)
    return [m for m in backlog if m in keys], [m for m in backlog if m not in present]


def missing_languages(messages, rows):
    return {m: sorted(set(LANGS) - rows[m]) for m in messages if m in rows and not set(LANGS) <= rows[m]}


def _show(items, limit=40):
    shown = '\n'.join('  ' + repr(i) for i in items[:limit])
    return shown + (f'\n  ... and {len(items) - limit} more' if len(items) > limit else '')


class TestThePopulationWasRead(unittest.TestCase):
    """A gate over an empty set passes whatever the code does; prove it is looking at something."""

    @classmethod
    def setUpClass(cls):
        cls.sites = census()
        cls.messages = distinct_messages(cls.sites)
        cls.rows = dict_rows()

    def test_the_messages_were_read(self):
        self.assertGreater(len(self.sites), 2000, 'the scan of respond() calls came back almost empty')
        self.assertGreater(len(self.messages), 900)

    def test_the_known_messages_are_in_it(self):
        # One that every handler family sends, and one with the wording the census gate pins.
        self.assertIn('Method not allowed', self.messages)
        self.assertIn('Host not found', self.messages)

    def test_the_dictionary_was_read(self):
        self.assertGreater(len(self.rows), 8000)
        self.assertIn('Dashboard', self.rows, 'the single-quoted block was not read')
        self.assertIn('Host offline', self.rows, 'the double-quoted catalog was not read')
        self.assertNotIn('zzz not a key in any dictionary', self.rows)

    def test_a_message_fits_on_one_line_of_the_backlog(self):
        bad = [m for m in self.messages if '\n' in m or '\r' in m or m.startswith('#') or not m.strip()]
        self.assertEqual(bad, [], 'the backlog file holds one message per line:\n' + _show(bad))


class TestEveryMessageIsTranslatedOrListed(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.messages = distinct_messages(census())
        cls.rows = dict_rows()
        cls.keys = set(cls.rows)
        cls.backlog = read_backlog()

    def test_a_new_message_arrives_translated(self):
        new = arrived_untranslated(self.messages, self.keys, self.backlog)
        self.assertEqual(new, [], '\n'.join([
            f'{len(new)} error message(s) the server sends have no dictionary entry:',
            _show(new), '',
            'Add an entry to DICT in server/html/static/js/i18n.js, spelled exactly as the server spells',
            'it, with all six languages. The engine needs no other change: it translates any text node',
            'that matches a key. Do not add the message to the backlog; the list only shrinks.',
            'Never write a translation you are unsure of: English falls back well and a wrong one does not.']))

    def test_the_backlog_only_shrinks(self):
        done, gone = stale_backlog(self.messages, self.keys, self.backlog)
        self.assertEqual(done, [], 'these are translated now; delete them from '
                         'tests/data/server_message_i18n_backlog.txt:\n' + _show(done))
        self.assertEqual(gone, [], 'the server no longer sends these; delete them from '
                         'tests/data/server_message_i18n_backlog.txt:\n' + _show(gone))

    def test_the_backlog_is_sorted_and_has_no_duplicates(self):
        self.assertEqual(self.backlog, sorted(set(self.backlog)),
                         'keep the backlog sorted with one line per message, so a diff shows what changed')

    def test_every_translated_message_has_all_six_languages(self):
        partial = missing_languages(self.messages, self.rows)
        self.assertEqual(partial, {}, 'a half-filled entry shows English for the missing languages, '
                         'which looks the same as no entry at all:\n' + _show(sorted(partial.items())))

    def test_no_message_is_longer_than_the_engine_reads(self):
        cap = text_node_cap()
        over = [m for m in self.messages if len(m.strip()) > cap]
        short = [m for m in self.messages if len(m.strip()) < 2]
        self.assertEqual(over, [], f'a text node over {cap} characters is never looked up:\n' + _show(over))
        self.assertEqual(short, [], 'a text node under 2 characters is never looked up:\n' + _show(short))

    def test_the_rule_names_a_message_nobody_translated(self):
        """Control: a checker that always answered [] would pass every test above."""
        fake = 'Sentinel error that no dictionary will ever carry'
        self.assertNotIn(fake, self.keys)
        self.assertEqual(arrived_untranslated([fake], self.keys, []), [fake])
        self.assertEqual(arrived_untranslated([fake], self.keys, [fake]), [], 'a listed message is accounted for')
        self.assertEqual(stale_backlog([], {'a'}, ['a', 'b']), (['a'], ['a', 'b']))
        self.assertEqual(missing_languages(['x'], {'x': {'de', 'fr'}}), {'x': ['ar', 'es', 'hi', 'zh']})

    def test_the_census_sees_a_message_a_new_handler_adds(self):
        src = "def h():\n    respond(400, {'error': 'A brand new refusal'})\n    respond(200, {'ok': True})\n"
        self.assertEqual(sites_of(src, 'x.py'), [('x.py', 2, 400, 'A brand new refusal')])


@unittest.skipUnless(unchanged_by_engine([]) is not None, 'node not installed')
class TestTranslationsReachThePage(unittest.TestCase):
    """Ask i18n.js itself, rather than asserting that a key exists and hoping."""

    @classmethod
    def setUpClass(cls):
        rows = dict_rows()
        cls.translated = [m for m in distinct_messages(census()) if m in rows]
        got = unchanged_by_engine(cls.translated)
        assert got is not None, 'node vanished between the skip check and the run'
        cls.unchanged = got

    def test_the_engine_ran_over_a_real_population(self):
        self.assertGreater(len(self.translated), 100, 'almost nothing to check; the scan or the dictionary came back empty')
        self.assertEqual(sorted(self.unchanged), sorted(LANGS), 'the engine reported a different set of languages')

    def test_every_translated_message_changes_in_every_language(self):
        gaps = {lang: [m for m in v if m not in SAME_IN_LANGUAGE.get(lang, ())] for lang, v in self.unchanged.items()}
        gaps = {lang: v for lang, v in gaps.items() if v}
        self.assertEqual(gaps, {}, 'the real engine returns these unchanged, so the person reads English:\n'
                         + '\n'.join(f'[{lang}]\n{_show(v, 10)}' for lang, v in gaps.items()))

    def test_the_same_in_language_list_is_not_stale(self):
        for lang, listed in SAME_IN_LANGUAGE.items():
            now = set(listed) & set(self.unchanged[lang])
            self.assertEqual(now, set(listed), f'{lang}: these differ from the English now, so they no longer '
                             f'need listing: {sorted(set(listed) - now)}')

    def test_an_untranslated_string_is_reported(self):
        """Control: t() falls back to the English, so a broken lookup and a perfect one look the same for a
        translated string. Only a string with no entry separates them."""
        fake = 'Sentinel error that no dictionary will ever carry'
        got = unchanged_by_engine([fake])
        assert got is not None
        self.assertTrue(all(got[lang] == [fake] for lang in LANGS), got)


class TestFormattedMessagesDoNotGrow(unittest.TestCase):

    def test_the_count_of_f_string_messages(self):
        n = len(fstring_census())
        self.assertGreater(n, 200, 'the scan for f-string messages came back almost empty')
        self.assertLessEqual(n, F_STRING_SITES, f'{n - F_STRING_SITES} new error message(s) are built with an '
                             'f-string. A dictionary key cannot match text with a variable inside. Send the fixed '
                             'sentence as the error and put the variable in its own field.')
        self.assertGreaterEqual(n, F_STRING_SITES, f'{F_STRING_SITES - n} f-string message(s) are gone: lower '
                                'F_STRING_SITES in tests/test_v740_server_messages_i18n.py to ' + str(n))

    def test_the_scan_sees_an_f_string_message(self):
        src = "def h():\n    respond(404, {'error': f'unknown provider {provider!r}'})\n"
        self.assertEqual(fstring_sites_of(src, 'x.py'), [('x.py', 2, 404, 'unknown provider {}')])
        self.assertEqual(fstring_sites_of("respond(404, {'error': 'plain'})", 'x.py'), [])


if __name__ == '__main__':
    unittest.main()
