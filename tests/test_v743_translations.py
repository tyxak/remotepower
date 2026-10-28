#!/usr/bin/env python3
"""7.4.3: the text the release added to the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes dead
with no error, and the six languages quietly read English again. This lists the English text 7.4.3 put
on a page and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (HTML and JavaScript are read as text, the
    server's own strings through the parser);
  * the literal parts a person types or reads as syntax (HEAD, GET, the product name) survive.

What a translation SAYS is not tested here: those six languages were written without a native reader
and are flagged as owed one in the release notes. The helpers are the 7.4.2 ones, so the two releases
read their strings the same way.

Self-skips without node, like the other engine checks.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import LANGS, text_node_cap, unchanged_by_engine  # noqa: E402
from test_v742_translations import rendered_in, translations  # noqa: E402

INDEX = "server/html/index.html"
APP = "server/html/static/js/app.js"

# (English text as the page shows it, the file that renders it)
NEW = (
    # Monitors: the HTTP form
    ("Leave this empty and any answer below 400 counts as up. Enter a code and only that code counts, so an "
     "app behind a login can be watched for 401.", INDEX),
    ("Auto sends HEAD, and tries GET once when HEAD is answered with 404, 405 or 501. A body or JSON check "
     "always sends GET.", INDEX),
    # Maintenance windows: what a window holds back
    ("While the window is active", INDEX),
    ("Hold notifications only", INDEX),
    ("Raise no alerts at all", INDEX),
    ("Notifications are always held back. With Raise no alerts at all, covered events are also kept out of "
     "the Alerts inbox, Needs attention and the stopped-containers count, and each one is still listed in "
     "the suppression log below.", INDEX),
    ("An alert that was open before the window starts stays open and closes when the problem clears. A problem "
     "that begins inside the window and is still there at the end shows in Needs attention again, but no alert "
     "is raised for it later.", INDEX),
    ("no alerts", APP),
    ("Covered events are kept out of the Alerts inbox and Needs attention as well as out of notifications. "
     "An alert that was already open stays open.", APP),
)

# Text that must come through a translation as it is written.
LITERALS = (
    ("HEAD", ("Auto sends HEAD",)),
    ("GET", ("Auto sends HEAD",)),
)


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(NEW), 9)
        self.assertEqual(len({s for s, _ in NEW}), len(NEW), "a string is listed twice")

    def test_the_real_engine_translates_each_in_every_language(self):
        out = unchanged_by_engine([s for s, _ in NEW])
        if out is None:
            self.skipTest("node is not installed")
        self.assertEqual(sorted(out), sorted(LANGS))
        for lang in LANGS:
            self.assertEqual(out[lang], [], f"{lang}: these read in English")

    def test_the_engine_check_can_fail(self):
        """The control: a sentence nobody translated must come back as unchanged in every language."""
        text = "A sentence that 7.4.3 never put in the dictionary."
        out = unchanged_by_engine([text])
        if out is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            self.assertEqual(out[lang], [text], lang)

    def test_no_translation_is_the_english_again(self):
        got = translations([s for s, _ in NEW])
        if got is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            for s, _ in NEW:
                self.assertNotEqual(got[lang][s], s, f"{lang}: {s[:50]}")
                self.assertTrue(got[lang][s].strip(), f"{lang}: empty for {s[:50]}")

    def test_each_string_fits_the_text_node_cap(self):
        cap = text_node_cap()
        for s, _ in NEW:
            self.assertLessEqual(len(s), cap, s[:50])

    def test_each_string_is_still_where_it_is_rendered(self):
        for s, rel in NEW:
            with self.subTest(s=s[:60]):
                self.assertTrue(rendered_in(s, rel),
                                f"{rel} no longer holds this text, so its translations never apply")

    def test_the_source_check_can_fail(self):
        self.assertFalse(rendered_in("A sentence nobody put on this page.", INDEX))

    def test_literal_text_survives_translation(self):
        got = translations([s for s, _ in NEW])
        if got is None:
            self.skipTest("node is not installed")
        for lit, starts in LITERALS:
            for s, _ in NEW:
                if lit in s and s.startswith(starts):
                    for lang in LANGS:
                        self.assertIn(lit, got[lang][s], f"{lang}: {lit!r} was translated in {s[:40]}")


if __name__ == "__main__":
    unittest.main()
