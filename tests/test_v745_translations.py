#!/usr/bin/env python3
"""7.4.5: the text the release added to the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes dead
with no error, and the six languages quietly read English again. This lists the English text 7.4.5 put
on a page and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (JavaScript is read as text);
  * the part a person reads as syntax (the address that follows a colon) is not in the string, so the
    sentence in front of it can be translated whole.

What a translation SAYS is not tested here: those six languages were written without a native reader
and are flagged as owed one in the release notes. The helpers are the 7.4.2 ones, so the releases read
their strings the same way.

Self-skips without node, like the other engine checks.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import LANGS, text_node_cap, unchanged_by_engine  # noqa: E402
from test_v742_translations import rendered_in, translations  # noqa: E402

APP = "server/html/static/js/app.js"

# (English text as the page shows it, the file that renders it)
NEW = (
    ("assumed internal", APP),
    ("Treat as internal", APP),
    ("Not internal", APP),
    ("Marked internal, but it has a public address:", APP),
    ("Marked internal, but its agent does not report its addresses. Update the agent.", APP),
    ("Services that listen on every address are graded world-reachable.", APP),
    ("This host is treated as internal: services that listen on every address are graded assumed internal.", APP),
    ("No longer treated as internal", APP),
    ("Treated as internal", APP),
    ("Marked internal. It does not hold yet: see the note beside the host.", APP),
)


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(NEW), 10)
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
        text = "A sentence that 7.4.5 never put in the dictionary."
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
        self.assertFalse(rendered_in("A sentence nobody put on this page.", APP))

    def test_a_sentence_that_ends_in_an_address_does_not_hold_the_address(self):
        """The address follows in its own element. A string with an address in it would match no text
        node, and the sentence would read in English for everyone."""
        for s, _ in NEW:
            self.assertNotRegex(s, r"\d+\.\d+\.\d+\.\d+")
        self.assertIn("<code>${escHtml((hs.public || []).join(', '))}</code>", (Path(__file__).resolve().parent.parent / APP).read_text())


if __name__ == "__main__":
    unittest.main()
