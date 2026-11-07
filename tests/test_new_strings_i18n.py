#!/usr/bin/env python3
"""Every visible string the sidebar sweep added has all six languages in the dictionary.

The key is the English text exactly as it is written in index.html or a script, so a reworded sentence drops out of the dictionary
without any other test noticing: this lists the strings by the sentence and checks each is a key with zh, hi, es, ar, de and fr.
Add a string here when you add one to the interface (the gates in test_v430_i18n_gate only see some kinds of text).
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_I18N = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text(encoding='utf-8')
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_JS = '\n'.join(p.read_text(encoding='utf-8') for p in sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')))

NEW_STRINGS = [
    # the OpenSCAP card of Compliance
    "Scores a host against an OpenSCAP profile and lists the rules it fails. It needs the OpenSCAP scanner and the SCAP Security Guide content on the host.",
    "About profiles and content",
    # the picker of Cron, File manager and App Catalog
    "Recent hosts",
    # the Pentest page
    "New scan",
    # Fleet Query
    "Criteria set in this group",
    "Identity",
    "Resources",
    "Clear criteria",
    # My Account > Appearance > Page sections
    "Page sections",
    "Tabs",
    "One long page",
    "Pages with many cards, such as Server Status and Compliance, show one group at a time under tabs. Choose one long page to see every card at once. It applies to this browser only.",
    # the tab labels of the pages that gained tabs (a label the dictionary already had is not listed)
    "Clients and keys",          # KMIP
    "Decisions",                 # Autonomy
    "Servers and sessions",      # SSH Gateway
    "Noise",                     # Tuning
    "Silenced",
    "Needs triage",              # Tickets
    "My tickets",
    "Schedules",                 # Pentest
    "Catalog and SLA",           # Patches
    "Map",                       # Network
    "Dependencies",
    "Discovery",
    "Watches",
    "Frameworks",                # Compliance
    "Baseline and scans",
    "Personal data",
    "Traffic",                   # Server Status
    "Diagnostics",
    "Data and upkeep",
    "Container images",         # CVEs
    # the fleet heat map: Group by and Colour by, its blocks, legends and notes (a label the dictionary already had is not listed)
    "No grouping",
    "Host type",
    "Worst finding",
    "Colour by",
    "Nothing open",
    "None",
    "Not reported",
    "No group",
    "No site",
    "No agent",
    "Under 5 minutes",
    "Under an hour",
    "Under a day",
    "A day or more",
    "Never or no agent",
    "worst open finding per host — red critical, amber warning",
    "pending updates per host — green none, red the most",
    "time since each host last checked in — green recent, red long ago",
]


def entry_languages(text):
    """The languages of the DICT entry whose key is exactly `text`, or None when there is none."""
    import json
    m = re.search(r'^    ' + re.escape(json.dumps(text, ensure_ascii=False)) + r': \{(.*)\},?$', _I18N, re.M)
    if not m:
        return None
    return set(re.findall(r'"(zh|hi|es|ar|de|fr)": "[^"]+"', m.group(1)))


class TestNewStringsAreTranslated(unittest.TestCase):

    def test_each_string_has_all_six_languages(self):
        missing = {s[:60]: entry_languages(s) for s in NEW_STRINGS if entry_languages(s) != {'zh', 'hi', 'es', 'ar', 'de', 'fr'}}
        self.assertEqual(missing, {})

    def test_each_string_is_still_in_the_interface(self):
        # a string nobody shows any more is a dictionary entry to delete, and a reworded one has left its translation behind
        gone = [s[:60] for s in NEW_STRINGS if s not in _HTML and s not in _JS]
        self.assertEqual(gone, [])

    def test_the_check_sees_a_missing_entry_and_a_partial_one(self):
        self.assertIsNone(entry_languages('A sentence nobody wrote'))
        self.assertEqual(entry_languages('About profiles and content'), {'zh', 'hi', 'es', 'ar', 'de', 'fr'})


if __name__ == '__main__':
    unittest.main()
