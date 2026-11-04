#!/usr/bin/env python3
"""7.4.9: the batch bar says what it does. Reboot and shut down act on the hosts you selected, not on all of them.

The bar above the host list appears when hosts are ticked: "3 selected", then the buttons. Two of them read "Shut down all" and
"Reboot all", and both act on the selection only (`batchAction` returns at once with nothing selected and posts the selected ids).
A label that says "all" next to a count that says "3 selected" reads as the whole fleet, on the two buttons whose mistake costs most.
They say "Shut down selected" and "Reboot selected" now.

The bar is read from the page, so a button added later gets the same check: no action button of the bar may promise "all". The one
button that is allowed the word, "Select all matching filters", is about choosing, and is named here so the exception is visible.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()
_APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
_I18N = (_ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()

ALLOWED_ALL = {"Select all matching filters"}


def bar(html):
    m = re.search(r'<div id="batch-bar" class="batch-bar">(.*?)\n        </div>', html, re.S)
    assert m, "the batch bar was not found"
    return m.group(1)


def buttons(bar_html):
    """[(attributes, visible label)] for every button of the bar: the text after the last tag, comments and icons removed."""
    bar_html = re.sub(r"<!--.*?-->", "", bar_html, flags=re.S)
    out = []
    for attrs, inner in re.findall(r"<button([^>]*)>(.*?)</button>", bar_html, re.S):
        label = re.sub(r"<svg.*?</svg>", "", inner, flags=re.S)
        label = re.sub(r"<[^>]+>", "", label)
        out.append((attrs, " ".join(label.split())))
    return out


class TestTheBarSaysSelected(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.buttons = buttons(bar(_HTML))

    def test_the_bar_was_read(self):
        # a scan over nothing passes: the bar has about a dozen buttons
        self.assertGreater(len(self.buttons), 8, self.buttons)
        labels = [label for _a, label in self.buttons]
        for known in ("Upgrade packages", "Update agent", "Run script", "Clear"):
            self.assertIn(known, labels)

    def test_shut_down_and_reboot_name_the_selection(self):
        by_arg = {}
        for attrs, label in self.buttons:
            m = re.search(r'data-action="batchAction"\s+data-arg="(\w+)"', attrs)
            if m:
                by_arg[m.group(1)] = label
        self.assertEqual(by_arg["shutdown"], "Shut down selected")
        self.assertEqual(by_arg["reboot"], "Reboot selected")
        self.assertEqual(sorted(by_arg), ["reboot", "shutdown", "update", "upgrade"])

    def test_no_action_button_promises_all(self):
        promising = [label for _a, label in self.buttons if re.search(r"\ball\b", label, re.I) and label not in ALLOWED_ALL]
        self.assertEqual(promising, [], "these buttons act on the selection, and 'all' reads as the whole fleet")

    def test_the_exception_is_the_one_that_chooses(self):
        self.assertIn("Select all matching filters", [label for _a, label in self.buttons])


class TestTheScanSeesWhatItIsFor(unittest.TestCase):

    def test_a_button_that_says_all_is_found(self):
        html = '<button class="x" data-action="batchAction" data-arg="reboot"><svg><path/></svg> Reboot all</button>' \
               '<button class="y">Clear</button>'
        found = [label for _a, label in buttons(html) if re.search(r"\ball\b", label, re.I) and label not in ALLOWED_ALL]
        self.assertEqual(found, ["Reboot all"])

    def test_the_label_is_what_a_person_reads(self):
        html = '<button data-action="batchAction" data-arg="x"><svg viewBox="0 0 1 1"><use href="#a"/></svg> Reboot\n   selected </button>'
        self.assertEqual(buttons(html)[0][1], "Reboot selected")


class TestTheButtonsReallyActOnTheSelection(unittest.TestCase):
    """The label is only true while the handler is."""

    @classmethod
    def setUpClass(cls):
        cls.body = srcpin.js_function(_APP, "batchAction")

    def test_nothing_selected_does_nothing(self):
        self.assertIn("if (!selectedDevices.size) return;", self.body)

    def test_the_ids_posted_are_the_selected_ones(self):
        self.assertIn("device_ids: [...selectedDevices]", self.body)
        self.assertNotIn("devices.map(", self.body)

    def test_the_confirmation_names_the_selected_hosts(self):
        self.assertIn("[...selectedDevices].map(id =>", self.body)


class TestTheTranslations(unittest.TestCase):

    def entry(self, key):
        m = re.search(r'^\s+"%s": \{ (.+?) \},$' % re.escape(key), _I18N, re.M)
        return m.group(1) if m else None

    def test_the_new_labels_have_all_six_languages(self):
        for key in ("Reboot selected", "Shut down selected"):
            body = self.entry(key)
            self.assertIsNotNone(body, key)
            langs = re.findall(r'"(zh|hi|es|ar|de|fr)": "[^"]+"', body)
            self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"], key)

    def test_the_old_labels_are_gone_from_the_dictionary(self):
        # an entry nothing displays any more is a translation someone maintains for nothing, and a way for "all" to come back
        for key in ("Reboot all", "Shut down all"):
            self.assertIsNone(self.entry(key), key)

    def test_the_old_labels_are_gone_from_the_page(self):
        self.assertNotIn("Reboot all", _HTML)
        self.assertNotIn("Shut down all", _HTML)


if __name__ == "__main__":
    unittest.main()
