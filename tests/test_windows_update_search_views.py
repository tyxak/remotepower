"""What the host's pages say about its Windows Update search and the definition updates it leaves out.

The server stores a state of the last search (when it ran, whether it worked and, if not, one word for why) and counts the Defender
definition updates apart. The page functions that print them run under node, taken out of the real scripts with stubs for what they call:

  * the line under the pills of the Packages card and of the host's patch report, for a search that worked, one that failed with
    a date for the count, one that failed before any search worked, and one that asked a WSUS server;
  * the word for why is one of the fixed set, whatever the server sends, and nothing in the line is markup the host chose;
  * the pill for the definition updates is there when there are some and not when there are none;
  * every phrase the page prints is a key of the dictionary in all six languages, and the real engine translates it.
"""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import i18n_engine  # noqa: E402
import srcpin  # noqa: E402

_APP = (_JS / "app.js").read_text(encoding="utf-8")


def node(script):
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def preamble():
    return "\n".join([
        re.search(r"^function escHtml\(.*$", _APP, re.M).group(0),
        re.search(r"^function escAttr\(.*$", _APP, re.M).group(0),
        srcpin.js_function(_APP, "_wuSearchLine"),
        # the time helpers stand in for the page's: the text they print is the argument, so a test can read which time was shown
        "const timeAgoHtml = ts => '<time>ago:' + ts + '</time>';",
        "const _fmtAbsDate = ts => 'date:' + ts;",
    ])


def line(state, cls=None):
    return node(preamble() + "\nconsole.log(JSON.stringify({html: _wuSearchLine(%s, %s)}));" % (json.dumps(state), json.dumps(cls)))["html"]


def card(sysinfo):
    """The Packages card of the drawer, run as the page runs it, with the stubs it needs."""
    fn = srcpin.js_function(_APP, "_loadAuditSection")
    script = preamble() + "\nasync " + fn + """
const out = {body: '', badge: ''};
const els = {'audit-body-packages': {set innerHTML(v) { out.body = v; }}, 'audit-badge-packages': {set textContent(v) { out.badge = v; }}};
const document = {getElementById: id => els[id]};
let _drawerDeviceId = 'h1', _drawerDeviceName = 'host one';
const _skeletonBlock = () => '';
const api = async () => ({sysinfo: %s});
_loadAuditSection('packages').then(() => console.log(JSON.stringify(out)));
""" % json.dumps(sysinfo)
    return node(script)


class TestTheLine(unittest.TestCase):
    def test_a_search_that_worked(self):
        html = line({"at": 1700000000, "ok": True, "source": "windows-update-agent", "error_class": "", "ok_at": 1700000000})
        self.assertIn("<span class=\"hint\">Last search</span> <time>ago:1700000000</time>, <span class=\"c-green\">ok</span>", html)
        self.assertNotIn("WSUS", html)
        self.assertNotIn("c-amber", html)

    def test_a_failed_search_says_why_and_when_the_count_is_from(self):
        html = line({"at": 1700000500, "ok": False, "error_class": "access", "ok_at": 1699000000, "source": "windows-update-agent"})
        self.assertIn("c-amber", html)
        self.assertIn("<span>Last search failed</span> (<span>access</span>)", html)
        self.assertIn("<span>the count is from</span> date:1699000000", html)

    def test_a_failed_search_before_any_worked_says_so(self):
        html = line({"at": 1700000500, "ok": False, "error_class": "network", "ok_at": 0})
        self.assertIn("<span>no search has worked yet</span>", html)
        self.assertNotIn("the count is from", html)

    def test_a_host_that_asks_a_wsus_server_says_so(self):
        for ok in (True, False):
            html = line({"at": 1700000500, "ok": ok, "error_class": "" if ok else "service", "ok_at": 1, "source": "wsus"})
            self.assertIn("· WSUS", html)

    def test_the_word_for_why_is_one_of_the_fixed_set(self):
        for cls in ("timeout", "access", "service", "network", "unknown"):
            self.assertIn(f"(<span>{cls}</span>)", line({"at": 1, "ok": False, "error_class": cls, "ok_at": 1}))
        for hostile in ("<img src=x onerror=alert(1)>", "Access is denied C:\\Users\\x", "", None, 5, ["access"]):
            html = line({"at": 1, "ok": False, "error_class": hostile, "ok_at": 1})
            self.assertIn("(<span>unknown</span>)", html)
            self.assertNotIn("<img", html)
            self.assertNotIn("Users", html)

    def test_nothing_the_host_chose_becomes_markup(self):
        html = line({"at": 1, "ok": False, "error_class": "access", "ok_at": "<b>x</b>", "source": "<script>x</script>"})
        self.assertNotIn("<b>x</b>", html)
        self.assertNotIn("<script>", html)

    def test_a_host_with_no_state_gets_no_line(self):
        for state in (None, {}, {"ok": "yes"}, "x", 5, [], {"at": 1}):
            self.assertEqual(line(state), "", state)

    def test_the_class_the_page_gives_the_line_is_used(self):
        self.assertIn('class="fs-12 mb-8"', line({"at": 1, "ok": True}, "mb-8"))
        self.assertIn('class="fs-12 c-amber mb-8"', line({"at": 1, "ok": False, "error_class": "access", "ok_at": 1}, "mb-8"))


class TestThePackagesCard(unittest.TestCase):
    PKG = {"manager": "windows-update", "upgradable": 3, "definition_updates": 2}

    def test_the_definition_updates_have_a_pill_beside_the_count(self):
        out = card({"packages": self.PKG, "pkg_scan_ts": 1700000000})
        self.assertIn('<div class="label">Definition updates</div><div class="value" title="Defender definition updates are counted here '
                      'and left out of the pending updates.">2</div>', out["body"])
        self.assertIn('<div class="label">Upgradable</div><div class="value isl-635 c-amber">3</div>', out["body"])
        self.assertEqual(out["badge"], "3 upgradable")

    def test_a_host_without_any_has_no_pill(self):
        for pkg in ({"manager": "apt", "upgradable": 3}, dict(self.PKG, definition_updates=0), dict(self.PKG, definition_updates="2"),
                    dict(self.PKG, definition_updates=-1), dict(self.PKG, definition_updates=None)):
            self.assertNotIn("Definition updates", card({"packages": pkg})["body"], pkg)

    def test_the_search_line_is_under_the_pills_and_above_the_button(self):
        body = card({"packages": self.PKG, "wu_search": {"at": 1700000500, "ok": False, "error_class": "timeout", "ok_at": 1699000000}})["body"]
        self.assertLess(body.index("</div>\n          <div class=\"fs-12 c-amber"), body.index("Scan now"))
        self.assertIn("Last search failed", body)

    def test_a_host_without_a_state_shows_the_card_as_before(self):
        body = card({"packages": {"manager": "apt", "upgradable": 0}, "pkg_scan_ts": 1700000000})["body"]
        self.assertNotIn("Last search", body)
        self.assertIn("Scan now", body)


class TestThePatchReport(unittest.TestCase):
    """The patch report of one host (Patching -> Patches -> Detail), run as the page runs it."""

    def report(self, data):
        fn = srcpin.js_function(_APP, "openDevicePatchReport")
        script = preamble() + "\nasync " + fn + """
const out = {body: '', title: ''};
const els = {'device-patch-title': {set textContent(v) { out.title = v; }}, 'device-patch-body': {set innerHTML(v) { out.body = v; }}};
const document = {getElementById: id => els[id]};
const _skeletonBlock = () => '';
const openModal = () => {};
const _errorState = () => { out.error = true; };
const _upgradeModeBlock = () => '';
const _patchPlanButton = () => '';
const _fmtAbsTs = ts => 'ts:' + ts;
const api = async () => (%s);
openDevicePatchReport('h1', 'host one').then(() => console.log(JSON.stringify(out)));
""" % json.dumps(data)
        return node(script)

    BASE = {"patch_status": "patches_available", "upgradable": 3, "os": "Windows 11", "pkg_manager": "windows-update", "version": "8.0.1",
            "online": True, "patch_history": []}

    def test_the_line_is_in_the_report_of_a_host_whose_search_failed(self):
        body = self.report(dict(self.BASE, wu_search={"at": 1700000500, "ok": False, "error_class": "access", "ok_at": 1699000000}))["body"]
        self.assertIn("<span>Last search failed</span> (<span>access</span>)", body)
        self.assertIn("<span>the count is from</span> date:1699000000", body)

    def test_and_when_it_worked(self):
        body = self.report(dict(self.BASE, wu_search={"at": 1700000500, "ok": True, "ok_at": 1700000500}))["body"]
        self.assertIn("Last search</span> <time>ago:1700000500</time>, <span class=\"c-green\">ok</span>", body)

    def test_a_host_with_no_state_has_none(self):
        for data in (self.BASE, dict(self.BASE, wu_search=None)):
            self.assertNotIn("Last search", self.report(data)["body"])


class TestTheWords(unittest.TestCase):
    PHRASES = [
        "Definition updates",
        "Defender definition updates are counted here and left out of the pending updates.",
        "Last search", "ok", "Last search failed", "the count is from", "no search has worked yet",
        "timeout", "access", "service", "network", "unknown",
    ]

    def test_every_phrase_is_a_key_with_all_six_languages(self):
        rows = i18n_engine.dict_rows()
        missing = {p: sorted(set(i18n_engine.LANGS) - rows.get(p, set())) for p in self.PHRASES if set(i18n_engine.LANGS) - rows.get(p, set())}
        self.assertEqual(missing, {})

    def test_the_phrases_are_the_ones_the_page_prints(self):
        page = srcpin.js_function(_APP, "_wuSearchLine") + srcpin.js_function(_APP, "_loadAuditSection")
        for p in self.PHRASES:
            if p in ("timeout", "access", "service", "network", "unknown", "Definition updates"):
                continue
            self.assertIn(p, page, p)
        for p in ("timeout", "access", "service", "network"):
            self.assertIn(f"'{p}'", page)

    # The French word for a service is "service": the engine hands it back as it is, and that is the translation.
    SAME_IN_LANGUAGE = {"fr": {"service"}}

    def test_the_real_engine_translates_each(self):
        unchanged = i18n_engine.unchanged_by_engine(self.PHRASES)
        if unchanged is None:
            self.skipTest("node is not installed")
        left = {lang: sorted(set(found) - self.SAME_IN_LANGUAGE.get(lang, set())) for lang, found in unchanged.items()}
        self.assertEqual({lang: found for lang, found in left.items() if found}, {})
        for lang, words in self.SAME_IN_LANGUAGE.items():
            self.assertEqual(sorted(words & set(unchanged[lang])), sorted(words), "an exemption that is not one any more")


if __name__ == "__main__":
    unittest.main()
