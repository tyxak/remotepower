"""The Problems page (#56) is registered everywhere a page has to be, and everything it shows is translated.

A new page is registered in six places and a missing one fails somewhere far from the page (a dead nav button, a
page that renders empty, a lazy module loaded twice). This holds them in one place, without a browser, next to the
browser test in test_problems_e2e.py.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "server" / "html"
JS = HTML / "static" / "js"

LANGS = ("fr", "de", "zh", "hi", "es", "ar")
STATES = ("failing", "resolved_but_failing", "waiting_for_report", "host_clear", "resolved", "recovered")


def between(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i + len(start))]


class _Sources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = (HTML / "index.html").read_text()
        cls.app = (JS / "app.js").read_text()
        cls.mod = (JS / "app-problems.js").read_text()
        cls.i18n = (JS / "i18n.js").read_text()
        cls.shell = between(cls.index, 'id="page-problems"', "<!-- ── Needs Attention page")


class TestRegistered(_Sources):
    def test_the_nav_button_is_in_the_monitoring_group_in_its_alphabetical_place(self):
        """Needs Attention stays first (test_v642_pages) and the rest of the group is alphabetical
        (test_v643_nav_ordering): Problems sits between Network Metrics and Services."""
        group = self.index[self.index.index('id="sbg-monitoring"'):]
        group = group[:group.index('class="sidebar-group-items"', 40)]
        pages = re.findall(r'data-page="(\w+)"', group)
        self.assertEqual(pages[0], "attention")
        self.assertEqual(pages[pages.index("problems") - 1], "netmetrics")
        self.assertEqual(pages[pages.index("problems") + 1], "services")

    def test_the_page_shell_exists_once(self):
        self.assertEqual(self.index.count('id="page-problems"'), 1)
        self.assertIn('class="page-title">Problems<', self.shell)

    def test_the_module_is_lazy_loaded_and_dispatched_and_refreshed(self):
        self.assertIn("problems: ['app-problems.js']", self.app)
        self.assertIn("if (name === 'problems') loadProblems();", self.app)
        self.assertRegex(self.app, r"problems:\s*\{ fn: 'loadProblems',\s*every: 60 \}")

    def test_the_module_is_not_also_loaded_at_boot(self):
        self.assertNotIn("app-problems.js", self.index, "a lazy module that is also a <script> loads twice")

    def test_every_action_the_page_uses_is_defined(self):
        actions = set(re.findall(r'data-action="(\w+)"', self.shell)) | set(re.findall(r'data-action="(\w+)"', self.mod))
        self.assertTrue({"setProblemsState", "loadProblems", "resolveProblem", "showPage"} <= actions, actions)
        for name in actions:
            self.assertTrue(re.search(rf"function {name}\b", self.mod + self.app), f"data-action {name} has no function")

    def test_the_sort_columns_of_the_header_are_the_keys_the_table_sorts_on(self):
        header = set(re.findall(r'data-col="(\w+)"', between(self.shell, 'id="problems-thead"', "</thead>")))
        sorted_on = set(re.findall(r"^\s{4}(\w+):", between(self.mod, "tableCtl.sortRows('problems'", "}));"), re.M))
        self.assertEqual(header, sorted_on)

    def test_the_headers_are_wired_before_the_data_arrives(self):
        load = between(self.mod, "async function loadProblems()", "const data = await")
        self.assertIn("tableCtl.wireSortOnly('problems-thead', 'problems', renderProblems)", load)

    def test_the_page_names_every_state_the_server_can_return_and_no_other(self):
        in_js = set(re.findall(r"^\s{2}(\w+):\s+\{label:", self.mod, re.M))
        self.assertEqual(in_js, set(STATES))
        options = set(re.findall(r'<option value="(\w+)"', between(self.shell, 'id="problems-filter-state"', "</select>")))
        self.assertEqual(options, set(STATES) | {"active", "all"})

    def test_a_state_reads_the_same_in_the_tile_the_select_and_the_pill(self):
        labels = dict(re.findall(r"^\s{2}(\w+):\s+\{label: '([^']+)'", self.mod, re.M))
        tiles = re.findall(r'data-arg="(\w+)"[^>]*><div><div class="stat-value[^"]*" id="problems-n-\w+">0</div><div class="stat-label">([^<]+)<', self.shell)
        self.assertEqual(len(tiles), 4)
        for state, label in tiles:
            self.assertEqual(label, labels[state], state)
        for state, label in re.findall(r'<option value="(\w+)"[^>]*>([^<]+)<', between(self.shell, 'id="problems-filter-state"', "</select>")):
            if state in labels:
                self.assertEqual(label, labels[state], state)

    def test_what_the_server_returns_is_what_the_page_reads(self):
        """The row fields the page reads must be fields problems.py puts on a row."""
        src = (ROOT / "server" / "cgi-bin" / "problems.py").read_text()
        for field in ("key", "device_id", "device", "family", "title", "severity", "state", "updated", "sources", "alerts",
                      "attention", "checks", "open_ids"):
            self.assertIn(f'"{field}"', src, f"problems.py has no {field!r} on a row")
            self.assertRegex(self.mod, rf"\br\.{field}\b", f"the page never reads row.{field}")


class TestTheAlertsPageBadge(_Sources):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alerts = (JS / "app-alerts.js").read_text()

    def test_a_resolved_alert_the_host_disagrees_with_gets_a_pill_beside_resolved_by(self):
        row = between(self.alerts, "const byWho = a.resolved_by", "copyAlertLink")
        self.assertIn("a.still_failing === 'resolved_but_failing'", row)
        self.assertIn("a.still_failing === 'waiting_for_report'", row)
        self.assertIn("Still failing", row)
        self.assertIn("Waiting for the host", row)
        self.assertLess(row.index("resolved by"), row.index("${stillFailing}"))

    def test_both_pills_are_translated(self):
        for key in ("Still failing", "Waiting for the host", "The last report from the host still shows this problem",
                    "The host has not reported since this was resolved"):
            i = self.i18n.index(json.dumps(key) + ":")
            line = self.i18n[i:self.i18n.index("\n", i)]
            for lang in LANGS:
                self.assertIn(f'"{lang}": "', line, f"{key!r} has no {lang}")


class TestTranslated(_Sources):
    def entry(self, key):
        needle = json.dumps(key, ensure_ascii=False) + ":"
        i = self.i18n.index(needle)
        return self.i18n[i:self.i18n.index("\n", i)]

    def test_every_label_of_the_page_has_all_six_languages(self):
        keys = ["Problems", "Problem", "Where", "Needs you", "All states", "Recovered", "Resolved, still failing",
                "Resolved, waiting for the host", "Host reports it clear", "Alerts, Needs Attention and Checks",
                "No problems match.", "Filter problems by state", "Filter problems by where they show",
                "Filter by host, problem or kind…", "Filter by host, problem or kind", "Could not resolve the alerts",
                "Could not load problems.",
                "More problems match than are listed. Narrow the filters to see the rest.",
                "One list of what is wrong, each problem once: alerts, Needs Attention and checks joined, with whether the host still reports it"]
        for k in keys:
            line = self.entry(k)
            for lang in LANGS:
                self.assertIn(f'"{lang}": "', line, f"{k!r} has no {lang}")

    def test_the_words_of_the_page_are_in_the_markup_the_dictionary_is_keyed_on(self):
        for text in ("Needs you", "All states", "No problems match.", "Filter problems by state",
                     "One list of what is wrong, each problem once"):
            self.assertIn(text, self.index + self.mod)

    def test_the_subtitle_is_keyed_three_ways_as_the_other_pages_are(self):
        sub = "Everything wrong with the fleet, each problem once."
        self.assertGreaterEqual(self.i18n.count(sub), 3, "DICT, HTMLDICT plain and HTMLDICT with the docs link")
        link = [ln for ln in self.i18n.splitlines() if ln.lstrip().startswith(f'"{sub}') and 'docs/problems.md' in ln.split('": {')[0]]
        self.assertEqual(len(link), 1)
        for lang in LANGS:
            self.assertIn(f'"{lang}": "', link[0])

    def test_nothing_of_the_page_is_an_inline_handler_or_inline_style(self):
        self.assertNotRegex(self.shell, r'\son\w+="')
        self.assertNotRegex(self.shell, r'\sstyle="')
        self.assertNotRegex(self.mod, r'\son(click|change|input)="')
        self.assertNotRegex(self.mod, r'style="')


if __name__ == "__main__":
    unittest.main()
