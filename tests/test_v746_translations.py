#!/usr/bin/env python3
"""7.4.6: the text the release added to the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes dead
with no error, and the six languages quietly read English again. This lists the English text 7.4.6 put
on a page and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (JavaScript and HTML are read as text);
  * no string holds a number or a version, which the page prints in an element of its own.

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
CVE = "server/html/static/js/app-cve.js"
PAGE = "server/html/index.html"

# (English text as the page shows it, the file that renders it)
NEW = (
    # #57: the tiles that count the fix statuses and filter the host table
    ("Fixable now", PAGE),
    ("Newer release only", PAGE),
    ("No fix yet", PAGE),
    ("Not checked", PAGE),
    ("Fixable now means an update for the host's own release clears it. The counts leave out accepted risks.", PAGE),
    # #57: what a finding says about its fix
    ("Fixed in a newer release", CVE),
    ("No fix yet", CVE),
    # #57: the alert option in Settings
    ("Only CVEs an update can fix, or that are known to be exploited", APP),
    ("A finding that no update for this host's release clears stays on the CVE page and raises no alert. "
     "One on the known-exploited list always alerts.", APP),
)


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def strings(self):
        return sorted({s for s, _ in NEW})

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(self.strings()), 8)

    def test_the_real_engine_translates_each_in_every_language(self):
        out = unchanged_by_engine(self.strings())
        if out is None:
            self.skipTest("node is not installed")
        self.assertEqual(sorted(out), sorted(LANGS))
        for lang in LANGS:
            self.assertEqual(out[lang], [], f"{lang}: these read in English")

    def test_the_engine_check_can_fail(self):
        """The control: a sentence nobody translated must come back as unchanged in every language."""
        text = "A sentence that 7.4.6 never put in the dictionary."
        out = unchanged_by_engine([text])
        if out is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            self.assertEqual(out[lang], [text], lang)

    def test_no_translation_is_the_english_again(self):
        got = translations(self.strings())
        if got is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            for s in self.strings():
                self.assertNotEqual(got[lang][s], s, f"{lang}: {s[:50]}")
                self.assertTrue(got[lang][s].strip(), f"{lang}: empty for {s[:50]}")

    def test_each_string_fits_the_text_node_cap(self):
        cap = text_node_cap()
        for s in self.strings():
            self.assertLessEqual(len(s), cap, s[:50])

    def test_each_string_is_still_where_it_is_rendered(self):
        for s, rel in NEW:
            with self.subTest(s=s[:60]):
                self.assertTrue(rendered_in(s, rel),
                                f"{rel} no longer holds this text, so its translations never apply")

    def test_the_source_check_can_fail(self):
        self.assertFalse(rendered_in("A sentence nobody put on this page.", PAGE))

    def test_no_string_holds_a_number_or_a_version(self):
        """The count and the version are printed in their own elements, so the label can be translated whole."""
        for s in self.strings():
            self.assertNotRegex(s, r"\d")


if __name__ == "__main__":
    unittest.main()
