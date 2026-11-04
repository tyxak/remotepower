#!/usr/bin/env python3
"""7.4.9: the B612 files are the ones that were checked, and nothing else of the package came with them.

The Typeface option loads B612, a font Airbus and ENAC drew for aircraft cockpit screens, under the SIL Open Font License 1.1. The
two files come from the npm package `@fontsource/b612@5.3.0`. Before anything was unpacked, the tarball's sha512 and sha1 were
compared with the registry's `dist` entry; the files were then read with fontTools, and the name table of each says the same as the
package: family B612, copyright "The B612 Project Authors", the licence address, version 1.008, embedding allowed.

This module holds what can be held without a font library (the CI image has none): the bytes are pinned, each file has the header
of a WOFF2 file with TrueType outlines, the licence text sits beside the files and is unchanged, nothing else of the package was
added (a new face needs its own @font-face rule and its own line in the record), and `VENDORED.md` says where all of it came from.

The pins are checks on a file, not on the idea. A newer B612 comes with new hashes here and a new entry in the record.
"""
import hashlib
import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

_ROOT = Path(__file__).resolve().parent.parent
_FONTS = _ROOT / "server" / "html" / "static" / "vendor" / "fonts"
_FILES = _FONTS / "files"
_RECORD = (_ROOT / "server" / "html" / "static" / "vendor" / "VENDORED.md").read_text()

# name -> (sha256, size in bytes), as they came out of @fontsource/b612@5.3.0
PINS = {
    "b612-latin-400-normal.woff2": ("a96e47feaec40f5b53b6c8e941e87ba7732d7935d47f2a554223585f36c6785d", 21160),
    "b612-latin-700-normal.woff2": ("95f39db174588831100e7e32a0329d4f91952a6c28f2fd91f207951e3a8c6788", 13244),
}
LICENCE = "b612-OFL.txt"
LICENCE_SHA256 = "32927731ab48cd86ac01dd213d2db646c91665e8eb3e6a2de7e8b8c98ab415ed"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def woff2_problem(data):
    """None when the bytes are a WOFF2 file of TrueType outlines whose declared length is the file's length, else the reason."""
    if len(data) < 48:
        return "shorter than the 48-byte header"
    signature, flavor, length, tables = struct.unpack(">4sIIH", data[:14])
    if signature != b"wOF2":
        return "not a WOFF2 file"
    if flavor != 0x00010000:
        return "not TrueType outlines"
    if length != len(data):
        return "the declared length is not the length of the file"
    if not 1 <= tables <= 64:
        return "an implausible number of tables"
    return None


class TestTheFilesAreTheOnesThatWereChecked(unittest.TestCase):

    def test_each_file_has_the_pinned_bytes(self):
        for name, (want, size) in PINS.items():
            data = (_FILES / name).read_bytes()
            self.assertEqual(len(data), size, name)
            self.assertEqual(sha256(data), want, f"{name} is not the file from @fontsource/b612@5.3.0")

    def test_each_file_is_a_woff2_font(self):
        for name in PINS:
            self.assertIsNone(woff2_problem((_FILES / name).read_bytes()), name)

    def test_nothing_else_of_the_package_came_along(self):
        # The package's italic files and .woff copies are not taken: the browser slants the regular face, and every browser that
        # runs this interface reads WOFF2. A face added later needs its @font-face rule and a line in the record.
        found = sorted(p.name for p in _FILES.glob("b612-*"))
        self.assertEqual(found, sorted(PINS), "a B612 file was added or removed without its pin")
        self.assertEqual(sorted(p.name for p in _FONTS.glob("b612*")), [LICENCE], "the font folder holds something unexpected")

    def test_the_population_is_not_empty(self):
        # a scan over nothing passes: the two faces are what the option loads
        self.assertEqual(len(PINS), 2)
        self.assertEqual(sorted(PINS), ["b612-latin-400-normal.woff2", "b612-latin-700-normal.woff2"])


class TestTheLicenceTravelsWithTheFont(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.raw = (_FONTS / LICENCE).read_bytes()
        cls.text = cls.raw.decode("utf-8")

    def test_it_is_the_text_that_came_with_the_package(self):
        self.assertEqual(sha256(self.raw), LICENCE_SHA256)

    def test_it_names_the_authors_and_the_licence(self):
        self.assertTrue(self.text.startswith("Copyright 2012 The B612 Project Authors"), self.text[:80])
        self.assertIn("SIL OPEN FONT LICENSE Version 1.1", self.text)
        self.assertIn("PERMISSION & CONDITIONS", self.text)

    def test_it_reserves_no_font_name(self):
        # the font is used unmodified; a reserved name would only matter for a changed copy, and the copyright line has none
        self.assertNotRegex(self.text.split("\n", 1)[0], r"(?i)reserved font name")


class TestTheRecordSaysWhereItCameFrom(unittest.TestCase):

    def test_the_record_names_the_package_the_files_and_the_licence(self):
        self.assertIn("@fontsource/b612", _RECORD)
        self.assertRegex(_RECORD, r"@fontsource/b612@5\.3\.0")
        for name in PINS:
            self.assertIn(name, _RECORD, name)
        self.assertIn("b612-OFL.txt", _RECORD)
        self.assertIn("SIL Open Font License 1.1", _RECORD)

    def test_the_record_says_the_registry_hashes_were_compared(self):
        self.assertRegex(_RECORD, r"sha512 and sha1\s+matched the registry")

    def test_the_table_row_lists_b612(self):
        rows = [line for line in _RECORD.splitlines() if line.startswith("| `fonts/`")]
        self.assertEqual(len(rows), 1, rows)
        self.assertIn("B612", rows[0])
        self.assertIn("@fontsource/b612", rows[0])
        self.assertIn("5.3.0", rows[0])


class TestTheHeaderCheckSeesWhatItIsFor(unittest.TestCase):
    """Each way a file can be wrong, as bytes of its own; a check that cannot be failed proves nothing."""

    GOOD = b"wOF2" + struct.pack(">I", 0x00010000) + struct.pack(">I", 64) + struct.pack(">H", 12) + b"\0" * 50

    def test_the_good_header_passes(self):
        self.assertEqual(len(self.GOOD), 64)
        self.assertIsNone(woff2_problem(self.GOOD))

    def test_a_woff1_file_is_refused(self):
        self.assertEqual(woff2_problem(b"wOFF" + self.GOOD[4:]), "not a WOFF2 file")

    def test_cff_outlines_are_refused(self):
        bad = self.GOOD[:4] + struct.pack(">I", 0x4F54544F) + self.GOOD[8:]
        self.assertEqual(woff2_problem(bad), "not TrueType outlines")

    def test_a_truncated_file_is_refused(self):
        self.assertEqual(woff2_problem(self.GOOD[:40]), "shorter than the 48-byte header")
        self.assertEqual(woff2_problem(self.GOOD[:60]), "the declared length is not the length of the file")

    def test_a_html_error_page_saved_as_a_font_is_refused(self):
        self.assertEqual(woff2_problem(b"<!doctype html><title>404</title>" + b" " * 40), "not a WOFF2 file")

    def test_no_tables_is_refused(self):
        bad = self.GOOD[:12] + struct.pack(">H", 0) + self.GOOD[14:]
        self.assertEqual(woff2_problem(bad), "an implausible number of tables")

    def test_a_changed_byte_changes_the_hash(self):
        # bytes of its own: reading the real file here would let a corrupted file flip back to the pinned one
        data = bytearray(bytes(range(256)) * 4)
        before = sha256(bytes(data))
        data[len(data) // 2] ^= 1
        self.assertNotEqual(sha256(bytes(data)), before)

    def test_the_record_pattern_would_miss_a_dropped_line(self):
        self.assertIsNone(re.search(r"sha512 and sha1\s+matched the registry", "the files came from npm"))


if __name__ == "__main__":
    unittest.main()
