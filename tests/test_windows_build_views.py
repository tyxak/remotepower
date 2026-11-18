"""What the pages say about the build of a Windows host.

The server sends the Hosts list a label for a Windows host that reported its build (`os_detail`: "Windows 11 Pro 23H2 (build 22631.3593)"), and the
pages print it in place of the agent's shorter text. The function that decides runs under node, taken out of the real script; the rendered pages
are measured in test_windows_host_e2e. Here:

  * the label is used when there is one, and the text the agent sends otherwise;
  * the new phrases of the Fleet Query page and the pill label are in the dictionary in all six languages, and the real engine translates them;
  * the Fleet Query page has the control and its criterion reaches the server as `win_build`.
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
_HTML = (ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")


def os_text(d):
    script = re.search(r"^function _osText\(.*$", _APP, re.M).group(0) + "\nconsole.log(JSON.stringify({v: _osText(%s)}));" % json.dumps(d)
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["v"]


class TestTheTextOfTheOs(unittest.TestCase):
    def test_the_label_is_used_when_the_host_reported_its_build(self):
        self.assertEqual(os_text({"os": "Windows 11 (Build 22631)", "os_detail": "Windows 11 Pro 23H2 (build 22631.3593)"}),
                         "Windows 11 Pro 23H2 (build 22631.3593)")

    def test_the_text_of_the_agent_is_used_otherwise(self):
        for d in ({"os": "Ubuntu 24.04"}, {"os": "Ubuntu 24.04", "os_detail": ""}, {"os": "Ubuntu 24.04", "os_detail": None}):
            self.assertEqual(os_text(d), "Ubuntu 24.04")

    def test_a_host_with_neither_has_an_empty_text(self):
        for d in ({}, None, {"os": None}):
            self.assertEqual(os_text(d), "")


class TestThePages(unittest.TestCase):
    def test_the_hosts_list_prints_it_in_the_table_the_cards_the_search_and_the_sort(self):
        # four places print or compare the OS text of a host; each takes it from the one function
        for fragment, times in (("_osText(d).toLowerCase().includes(deviceSearchTerm)", 1), ("os:        _osText(d),", 1),
                                ("${escHtml(_osText(d) || '—')}", 2), ('title="${escAttr(_osText(d))}"', 1)):    # the cards and the table cell
            self.assertEqual(_APP.count(fragment), times, fragment)

    def test_the_drawer_has_an_os_pill(self):
        fn = srcpin.js_function(_APP, "_loadAuditSection")
        self.assertIn("['OS',        (_drawerDeviceData && _drawerDeviceData.os_detail) || null],", fn)

    def test_the_fleet_query_page_has_the_control_and_sends_the_criterion(self):
        self.assertEqual(_HTML.count('id="fq-winbuild"'), 1)
        block = re.search(r"const _FQ_FIELDS = \{(.*?)\n\};", _APP, re.S).group(1)
        self.assertEqual(dict(re.findall(r"(\w+):\s*'(fq-[\w-]+)'", block)).get("win_build"), "fq-winbuild")


class TestTheWords(unittest.TestCase):
    PHRASES = ["Windows build contains", "e.g. 23H2 / 22631.3593", "OS"]

    def test_every_phrase_is_a_key_with_all_six_languages(self):
        rows = i18n_engine.dict_rows()
        missing = {p: sorted(set(i18n_engine.LANGS) - rows.get(p, set())) for p in self.PHRASES if set(i18n_engine.LANGS) - rows.get(p, set())}
        self.assertEqual(missing, {})

    def test_the_phrases_are_the_ones_the_page_has(self):
        self.assertIn('<label class="form-label">Windows build contains</label>', _HTML)
        self.assertIn('placeholder="e.g. 23H2 / 22631.3593" aria-label="Windows build contains"', _HTML)

    # "OS" is the same word in French and Hindi, and the dictionary says so
    SAME_IN_LANGUAGE = {"fr": {"OS"}, "hi": {"OS"}}

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
