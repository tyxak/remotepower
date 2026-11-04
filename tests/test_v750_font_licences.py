#!/usr/bin/env python3
"""7.5.0: every vendored font family has its licence text beside the files.

Inter and JetBrains Mono were vendored under the SIL Open Font License 1.1 with the licence named only in the vendoring record; B612
(7.4.9) was the first to ship the text. The two texts are the LICENSE files of `@fontsource/inter@5.3.0` and
`@fontsource/jetbrains-mono@5.3.0` (the tarballs' sha512 matched the registry before anything was unpacked), and they are pinned here.
"""
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / "server" / "html" / "static" / "vendor" / "fonts"
RECORD = (ROOT / "server" / "html" / "static" / "vendor" / "VENDORED.md").read_text()

# file -> (sha256, the copyright holder the text must name)
PINS = {
    "inter-OFL.txt": ("3b0a5fca3d17942cde889069889dedbbbd075e9b599968c82a95f4d944e9b345", "The Inter Project Authors"),
    "jetbrains-mono-OFL.txt": ("403581b69dac5cff4079205e01c6b467e56af449ecbd7247693ddb1baafa005b", "The JetBrains Mono Project Authors"),
    "b612-OFL.txt": ("32927731ab48cd86ac01dd213d2db646c91665e8eb3e6a2de7e8b8c98ab415ed", "The B612 Project Authors"),
}


class TestLicenceTexts(unittest.TestCase):

    def test_each_text_is_the_one_that_was_checked(self):
        for name, (sha, _holder) in PINS.items():
            self.assertEqual(hashlib.sha256((FONTS / name).read_bytes()).hexdigest(), sha, name)

    def test_each_names_its_authors_and_is_the_ofl_1_1(self):
        for name, (_sha, holder) in PINS.items():
            text = (FONTS / name).read_text()
            self.assertIn(holder, text, name)
            self.assertIn("SIL Open Font License, Version 1.1", text, name)
            self.assertIn("SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007", text, name)
            self.assertIn("PERMISSION & CONDITIONS", text, name)

    def test_every_family_the_stylesheet_loads_has_a_text(self):
        css = (FONTS / "inter-jetbrains.css").read_text()
        families = {m.lower() for m in re.findall(r"font-family:\s*['\"]?([A-Za-z0-9 ]+?)['\"]?\s*;", css)}
        self.assertTrue(families, "the stylesheet names no font family: the check below would measure nothing")
        for fam in families:
            key = fam.replace(" ", "-")
            self.assertTrue(any(key.startswith(n.split("-OFL")[0]) or n.split("-OFL")[0].startswith(key) for n in PINS),
                            f"{fam} has no licence text beside the files")
        self.assertIn("inter", {f.split()[0] for f in families})
        self.assertIn("jetbrains", {f.split()[0] for f in families})

    def test_the_record_names_the_files(self):
        for name in PINS:
            self.assertIn(name, RECORD, name)

    def test_the_font_directory_holds_no_unlisted_text(self):
        extra = {p.name for p in FONTS.glob("*.txt")} - set(PINS)
        self.assertEqual(extra, set(), "a licence file nobody pinned")


if __name__ == "__main__":
    unittest.main()
