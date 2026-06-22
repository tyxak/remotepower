#!/usr/bin/env python3
"""v4.3.0: i18n coverage gate for the app chrome.

The translation strategy is deliberate: a curated DICT covers the app's
*chrome* (sidebar nav, page titles) and everything else falls back to
English. The gap was process, not strategy — nothing failed when a new page
shipped with untranslated chrome, so coverage silently decayed with every
release. This gate makes the curated set self-enforcing: every sidebar nav
label and every page title in index.html must have a DICT entry carrying all
four non-English languages.
"""
import html as _html
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
INDEX = (_ROOT / "server" / "html" / "index.html").read_text()
I18N = (_ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()

LANGS = ('zh', 'hi', 'es', 'ar')


def _dict_entries():
    """Parse DICT keys → set of language codes present, from i18n.js."""
    m = re.search(r'var DICT = \{(.*?)\n  \};', I18N, re.S)
    assert m, "DICT block not found in i18n.js"
    entries = {}
    for em in re.finditer(r"'((?:[^'\\]|\\.)+)':\s*\{([^}]*)\}", m.group(1)):
        key = em.group(1).replace("\\'", "'")
        langs = set(re.findall(r'(\w+):', em.group(2)))
        entries[key] = langs
    return entries


def _htmldict_entries():
    """Parse HTMLDICT keys → set of language codes present, from i18n.js.

    HTMLDICT is the separate object that translates whole `.page-subtitle`
    innerHTML strings (keys are the normalized English HTML, double-quoted).
    Each line is one entry: `    "<en html>": { "zh": ..., "hi": ..., ... },`
    """
    m = re.search(r'var HTMLDICT = \{(.*?)\n  \};', I18N, re.S)
    assert m, "HTMLDICT block not found in i18n.js"
    entries = {}
    for em in re.finditer(r'^\s{4}"((?:[^"\\]|\\.)*)":\s*\{([^}]*)\}', m.group(1), re.M):
        # Unescape the JS string-literal key into the runtime innerHTML it matches.
        key = em.group(1).replace('\\"', '"').replace('\\\\', '\\')
        langs = set(re.findall(r'"(\w+)":', em.group(2)))
        entries[key] = langs
    return entries


def _nav_labels():
    """Visible label of every sidebar .nav-btn. The label is the bare
    `<span>` (no attributes); badges/stars are attributed spans — dropped."""
    labels = set()
    for bm in re.finditer(r'<button class="nav-btn[^"]*"[^>]*>(.*?)</button>', INDEX, re.S):
        body = re.sub(r'<svg\b.*?</svg>', '', bm.group(1), flags=re.S)
        body = re.sub(r'<span [^>]+>.*?</span>', '', body, flags=re.S)
        body = re.sub(r'<[^>]+>', '', body)
        text = _html.unescape(re.sub(r'\s+', ' ', body)).strip()
        if text:
            labels.add(text)
    return labels


def _page_titles():
    """First text node of every .page-title (badge spans excluded)."""
    titles = set()
    for tm in re.finditer(r'<(?:h1|div)[^>]*class="page-title[^"]*"[^>]*>(.*?)</(?:h1|div)>',
                          INDEX, re.S):
        body = tm.group(1)
        first = body.split('<', 1)[0]
        text = _html.unescape(re.sub(r'\s+', ' ', first)).strip()
        if not text:
            stripped = re.sub(r'<[^>]+>', '', re.sub(r'<span [^>]+>.*?</span>', '',
                                                     body, flags=re.S))
            text = _html.unescape(re.sub(r'\s+', ' ', stripped)).strip()
        if text:
            titles.add(text)
    return titles


def _page_subtitles():
    """Normalized innerHTML of every `.page-subtitle` element in index.html.

    The runtime keys HTMLDICT by `_normWS(el.innerHTML)` — whitespace runs
    collapsed to a single space and trimmed — so mirror that here.
    """
    subs = set()
    for sm in re.finditer(
            r'<(\w+)[^>]*class="[^"]*\bpage-subtitle\b[^"]*"[^>]*>(.*?)</\1>',
            INDEX, re.S):
        text = re.sub(r'\s+', ' ', sm.group(2)).strip()
        if text:
            subs.add(text)
    return subs


class TestChromeTranslationCoverage(unittest.TestCase):
    def setUp(self):
        self.dict_entries = _dict_entries()

    def test_dict_parses_and_is_nontrivial(self):
        self.assertGreater(len(self.dict_entries), 40)

    def test_every_nav_label_is_in_dict(self):
        labels = _nav_labels()
        self.assertGreater(len(labels), 20, "nav extraction looks broken")
        missing = sorted(l for l in labels if l not in self.dict_entries)
        self.assertEqual(missing, [],
                         "sidebar nav labels with no DICT entry (new page shipped "
                         f"without chrome translation?): {missing}")

    def test_every_page_title_is_in_dict(self):
        titles = _page_titles()
        self.assertGreater(len(titles), 20, "page-title extraction looks broken")
        missing = sorted(t for t in titles if t not in self.dict_entries)
        self.assertEqual(missing, [],
                         f"page titles with no DICT entry: {missing}")

    def test_dict_entries_carry_all_four_languages(self):
        incomplete = {k: sorted(set(LANGS) - langs)
                      for k, langs in self.dict_entries.items()
                      if not set(LANGS) <= langs}
        self.assertEqual(incomplete, {},
                         f"DICT entries missing languages: {incomplete}")


class TestSubtitleTranslationCoverage(unittest.TestCase):
    """Every `.page-subtitle` must have a translation entry in DICT or
    HTMLDICT carrying all four non-English languages, or it renders
    English-only in zh/hi/es/ar. The original v4.3.0 gate only checked
    page-*titles*; leaf-page subtitles slipped through (the gap this closes)."""

    def setUp(self):
        self.dict_entries = _dict_entries()
        self.htmldict_entries = _htmldict_entries()

    def test_htmldict_parses_and_is_nontrivial(self):
        self.assertGreater(len(self.htmldict_entries), 60,
                           "HTMLDICT extraction looks broken")

    def test_every_page_subtitle_is_translated(self):
        subs = _page_subtitles()
        self.assertGreater(len(subs), 60, "page-subtitle extraction looks broken")
        # A subtitle is covered if its normalized innerHTML is a key in either
        # table (text-node DICT or whole-subtitle HTMLDICT).
        keys = set(self.dict_entries) | set(self.htmldict_entries)
        missing = sorted(s for s in subs if s not in keys)
        self.assertEqual(missing, [],
                         "page subtitles with no DICT/HTMLDICT entry (new page "
                         f"shipped without a subtitle translation?): {missing}")

    def test_htmldict_entries_carry_all_four_languages(self):
        incomplete = {k: sorted(set(LANGS) - langs)
                      for k, langs in self.htmldict_entries.items()
                      if not set(LANGS) <= langs}
        self.assertEqual(incomplete, {},
                         f"HTMLDICT entries missing languages: {incomplete}")


if __name__ == '__main__':
    unittest.main()
