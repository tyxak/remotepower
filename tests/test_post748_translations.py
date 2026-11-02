#!/usr/bin/env python3
"""After 7.4.8: the text the work for #54 and Discussion #30 put on the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes dead
with no error, and the six languages quietly read English again. This lists the English text this work put
on a page and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (JavaScript and HTML are read as text);
  * no string holds a number or a version, which the page prints in an element of its own.

What a translation SAYS is not tested here: the six languages were written without a native reader and are
flagged as owed one. The helpers are the 7.4.2 ones, so the releases read their strings the same way.

Self-skips without node, like the other engine checks.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import LANGS, text_node_cap, unchanged_by_engine  # noqa: E402
from test_v742_translations import rendered_in, translations  # noqa: E402

POWER = "server/html/static/js/app-power.js"
APP = "server/html/static/js/app.js"
MODE = "server/cgi-bin/upgrade_mode.py"
MODE_ROUTE = "server/cgi-bin/upgrade_mode_handlers.py"

# (English text as the page shows it, the file that renders it)
NEW = (
    # #54: a drivetemp sensor whose disk the agent could not name, on the Thermal page
    ("disk not identified", POWER),
    # Discussion #30: the upgrade mode in the Patch Report dialog, the table and the bulk actions
    ("Upgrade mode", APP),
    ("Standard \u2014 apt-get upgrade, as before", APP),
    ("Extended \u2014 also installs the new packages an update needs", APP),
    ("Standard runs apt-get upgrade, which keeps back an update that needs a package that is not installed yet, such as a new "
     "kernel image. Extended runs apt-get upgrade --with-new-pkgs, which installs those packages as well and removes nothing. "
     "The mode applies to the patch button, auto-patch, scheduled upgrades and rollouts.", APP),
    ("Packages apt keeps back:", APP),
    ("The next upgrade installs them.", APP),
    ("The standard upgrade leaves them. Switch to Extended to install them.", APP),
    ("Extended", APP),
    ("Upgrade mode: Standard (apt hosts)", APP),
    ("Upgrade mode: Extended (apt hosts)", APP),
    ("Upgrade mode saved", APP),
    ("Could not save the upgrade mode", APP),
    # Discussion #30: what the server says when it refuses
    ('The upgrade mode must be "standard" or "extended"', MODE_ROUTE),
    ("The upgrade mode applies to Linux hosts that use apt", MODE),
    ("The upgrade mode applies to hosts that use apt, and this host uses another package manager", MODE),
)


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def strings(self):
        return sorted({s for s, _ in NEW})

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(self.strings()), 16)
        self.assertEqual(len({s for s, _ in NEW}), len(NEW), "a string is listed twice")

    def test_the_real_engine_translates_each_in_every_language(self):
        out = unchanged_by_engine(self.strings())
        if out is None:
            self.skipTest("node is not installed")
        self.assertEqual(sorted(out), sorted(LANGS))
        for lang in LANGS:
            self.assertEqual(out[lang], [], f"{lang}: these read in English")

    def test_the_engine_check_can_fail(self):
        """The control: a sentence nobody translated must come back as unchanged in every language."""
        text = "A sentence that this work never put in the dictionary."
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
        self.assertFalse(rendered_in("A sentence nobody put on this page.", POWER))

    def test_no_string_holds_a_number_or_a_version(self):
        for s in self.strings():
            self.assertNotRegex(s, r"\d")


if __name__ == "__main__":
    unittest.main()
