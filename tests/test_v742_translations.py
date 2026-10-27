#!/usr/bin/env python3
"""7.4.2: the text the release added to the pages is translated, and stays tied to the page.

The i18n engine looks a text node up by its exact English text, so a translation is only as good as
the link between the key and the text on the page: change one word on the page and the key goes
dead with no error, the six languages quietly read English again. This lists the English text 7.4.2
put on a page (the Tuning card and its row, the Memory block of the SNMP tab, the integrations
section of the host card and its longer trend) and holds three things for each string:

  * the real engine, run under node, hands back a translation in all six languages;
  * the string is still in the file that renders it (HTML and JavaScript are read as text, the
    server's own strings through the parser);
  * the literal parts a person types or reads as syntax (`image:`, the product name, the arrow in
    a menu path) survive translation.

What a translation SAYS is not tested here: those six languages were written without a native
reader and are flagged as owed one in the release notes.

Self-skips without node, like the other engine checks.
"""
import ast
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import I18N_JS, LANGS, text_node_cap, unchanged_by_engine  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INDEX = "server/html/index.html"
APP = "server/html/static/js/app.js"
TUNING = "server/html/static/js/app-tuning.js"
ATTN = "server/cgi-bin/attention_handlers.py"

# (English text as the page shows it, the file that renders it)
NEW = (
    # Monitoring -> Tuning: the exclude list card and its row in the list of everything silenced
    ("Container exclude list", INDEX),
    ("Containers that match an entry raise no stopped or restart alert, and stay out of Needs attention "
     "and the stopped-containers widget.", INDEX),
    ("One entry per line, up to 200 entries of 128 characters. An entry matches part of a container's name. "
     "Start it with image: to match part of the image instead, which suits helper containers that exit by "
     "design and get a random name each run.", INDEX),
    ("Save exclude list", INDEX),
    ("Only an administrator can change this list.", TUNING),
    ("Container exclusion", TUNING),
    ("Containers whose name contains this raise no stopped or restart alert and are left out of "
     "Needs attention", ATTN),
    ("Containers whose image contains this raise no stopped or restart alert and are left out of "
     "Needs attention", ATTN),
    ("Every active suppression in one place, from all eight mechanisms — alert mutes, Needs-attention ignores "
     "and class rules, accepted-risk CVEs, exposure mutes, active maintenance windows, quiet hours and the "
     "container exclude list. Read-only: each row links to the page that can lift it.", INDEX),
    # The SNMP tab: the Memory block
    ("includes cache and buffers", APP),
    ("In use", APP),
    ("Cache and buffers", APP),
    ("Host reports", APP),
    ("The host counts its cache and buffers as used. RemotePower alerts on the share without them.", APP),
    # The host card: the integrations section and the longer trend
    ("Integrations on this host", APP),
    ("Homelab software integrations are hidden on this instance.", APP),
    ("No integrations are bound to this host. To bind one, open it under Settings → Integrations and fill "
     "in Runs on host.", APP),
    ("hourly average", APP),
)

# Text that must come through a translation as it is written.
LITERALS = (
    ("image:", ("One entry per line", "Containers whose image", "Start it with")),
    ("RemotePower", ("The host counts its cache", "Every active")),
)

# What a translation of a menu path may use as its arrow: Arabic reads right to left.
ARROWS = ("→", "←")

_READ = r'''
const store = {};
global.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
const stub = () => ({ setAttribute(){}, getAttribute(){ return null; }, hasAttribute(){ return false; },
  querySelectorAll(){ return []; }, addEventListener(){}, appendChild(){}, dataset: {},
  classList: { contains(){ return false; } }, value: '', style: {} });
global.document = { readyState: 'complete', documentElement: stub(), body: null, createElement: stub,
  createTreeWalker: null, getElementById(){ return null; }, querySelectorAll(){ return []; }, addEventListener(){} };
global.window = global;
global.fetch = () => ({ catch(){} });
require(process.argv[2]);
const strings = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const lang of window.RPi18n.langs) {
  if (lang === 'en') continue;
  window.RPi18n.setLang(lang, false);
  out[lang] = Object.fromEntries(strings.map(s => [s, window.RPi18n.t(s)]));
}
console.log(JSON.stringify(out));
'''


def translations(strings):
    """{lang: {english: what the engine returns}}, or None without node."""
    node = shutil.which("node")
    if not node:
        return None
    work = Path(tempfile.mkdtemp(prefix="rp-i18n-"))
    try:
        (work / "read.js").write_text(_READ, encoding="utf-8")
        r = subprocess.run([node, str(work / "read.js"), str(I18N_JS)], input=json.dumps(sorted(set(strings))),
                           capture_output=True, text=True, timeout=120)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if r.returncode != 0:
        raise AssertionError("node could not load i18n.js: " + r.stderr[-800:])
    return json.loads(r.stdout)


def _squash(text):
    return re.sub(r"\s+", " ", html.unescape(text))


def rendered_in(string, rel):
    """Is `string` in the file that is meant to render it?"""
    p = ROOT / rel
    if rel.endswith(".py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and string in n.value
                   for n in ast.walk(tree))
    return _squash(string) in _squash(p.read_text(encoding="utf-8"))


class TestTheNewStringsAreTranslated(unittest.TestCase):

    def test_the_list_was_found(self):
        """The control on the population: a list that shrank to nothing would pass every test below."""
        self.assertGreaterEqual(len(NEW), 18)
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
        out = unchanged_by_engine(["A sentence that 7.4.2 never put in the dictionary."])
        if out is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            self.assertEqual(out[lang], ["A sentence that 7.4.2 never put in the dictionary."], lang)

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
        self.assertFalse(rendered_in("A sentence nobody put in this module.", ATTN))

    def test_literal_text_survives_translation(self):
        got = translations([s for s, _ in NEW])
        if got is None:
            self.skipTest("node is not installed")
        for lit, starts in LITERALS:
            for s, _ in NEW:
                if lit in s and s.startswith(starts):
                    for lang in LANGS:
                        self.assertIn(lit, got[lang][s], f"{lang}: {lit!r} was translated in {s[:40]}")

    def test_the_menu_path_keeps_its_arrow(self):
        path = next(s for s, _ in NEW if "Settings → Integrations" in s)
        got = translations([path])
        if got is None:
            self.skipTest("node is not installed")
        for lang in LANGS:
            self.assertTrue(any(a in got[lang][path] for a in ARROWS), f"{lang}: no arrow in the menu path")


if __name__ == "__main__":
    unittest.main()
