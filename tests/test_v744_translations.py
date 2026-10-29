#!/usr/bin/env python3
"""7.4.4: the text the release added to the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes dead
with no error, and the six languages quietly read English again. This lists the English text 7.4.4 put
on a page and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (HTML and JavaScript are read as text);
  * the literal parts a person reads as syntax (the unit, the names of the drive types) survive.

What a translation SAYS is not tested here: those six languages were written without a native reader
and are flagged as owed one in the release notes. The server's own sentences are held by
test_v740_server_messages_i18n. The helpers are the 7.4.2 ones, so the releases read their strings the
same way.

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
    ("Drive temperature",
     INDEX),
    ("How warm a drive may get, in °C, before an alert. A hard disk, a SATA SSD and an NVMe drive run at different temperatures, so each type has a pair of its own, and the last pair is for any other drive. The most specific line wins: a drive's own line (on its host's Hardware tab, against its serial number), then the host's (under Metric thresholds), then these. Every line is off at 0, and nothing alerts until one is set.",
     INDEX),
    ("Hard disk warn °C",
     INDEX),
    ("Hard disk crit °C",
     INDEX),
    ("SATA SSD warn °C",
     INDEX),
    ("SATA SSD crit °C",
     INDEX),
    ("NVMe warn °C",
     INDEX),
    ("NVMe crit °C",
     INDEX),
    ("Any other drive warn °C",
     INDEX),
    ("Any other drive crit °C",
     INDEX),
    ("How warm a drive on this host may get, in °C. The first box of each row is the warning line and the second the critical line. Leave a box blank to follow the fleet setting under Settings, Alert parameters, shown in grey. A drive can have lines of its own on the Hardware tab, and those win over these.",
     INDEX),
    ("Hard disks",
     INDEX),
    ("SATA SSDs",
     INDEX),
    ("NVMe drives",
     INDEX),
    ("Any other drive",
     INDEX),
    ("Warn and Crit are the temperature in °C at which this drive raises a warning or a critical alert. An empty box uses the host's line, or the fleet's, shown in grey. Nothing alerts until a line is set.",
     APP),
    ("Warn °C",
     APP),
    ("Crit °C",
     APP),
    ("Save names and lines",
     APP),
    ("Disk names and lines saved",
     APP),
)

# Text that must come through a translation as it is written: the unit, and the names of the drive types.
LITERALS = (
    ("°C", ("How warm", "Hard disk warn", "Hard disk crit", "SATA SSD warn", "SATA SSD crit", "NVMe warn",
            "NVMe crit", "Any other drive warn", "Any other drive crit", "Warn", "Crit")),
    ("NVMe", ("NVMe", "How warm")),
    ("SATA", ("SATA SSD", "How warm")),
)


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(NEW), 20)
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
        text = "A sentence that 7.4.4 never put in the dictionary."
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
                # A drive type and a unit are the same word in every language; only the sentence around them moves.
                if s in ("NVMe warn °C", "NVMe crit °C") and lang in ("hi", "zh"):
                    continue
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
        checked = 0
        for lit, starts in LITERALS:
            for s, _ in NEW:
                if lit in s and s.startswith(starts):
                    for lang in LANGS:
                        checked += 1
                        self.assertIn(lit, got[lang][s], f"{lang}: {lit!r} was translated in {s[:40]}")
        self.assertGreater(checked, 100, "the check looked at nothing")


if __name__ == "__main__":
    unittest.main()
