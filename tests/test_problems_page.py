"""The Problems page (#56) is registered everywhere a page has to be, and everything it shows is translated.

A new page is registered in six places and a missing one fails somewhere far from the page (a dead nav button, a
page that renders empty, a lazy module loaded twice). This holds them in one place, without a browser, next to the
browser test in test_problems_e2e.py.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402
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
        cls.modal = between(cls.index, 'id="problem-history-modal"', 'id="slo-edit-modal"')


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
        self.assertIn("if (name === 'problems') enterProblems();", self.app)
        self.assertRegex(self.app, r"problems:\s*\{ fn: 'loadProblems',\s*every: 60 \}")

    def test_the_module_is_not_also_loaded_at_boot(self):
        self.assertNotIn("app-problems.js", self.index, "a lazy module that is also a <script> loads twice")

    def test_every_action_the_page_uses_is_defined(self):
        actions = (set(re.findall(r'data-action="(\w+)"', self.shell)) | set(re.findall(r'data-action="(\w+)"', self.modal))
                   | set(re.findall(r'data-action="(\w+)"', self.mod)) | set(re.findall(r"item\('(\w+)'", self.mod)))
        self.assertTrue({"setProblemsState", "setProblemsView", "loadProblems", "resolveProblem", "showPage", "openProblemHistory",
                         "muteProblem", "snoozeProblem", "ignoreProblem", "fixProblem", "disableProblemChecks",
                         "rowMoreMenu", "closeModal"} <= actions, actions)
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
        self.assertIn("a.problem_state === 'resolved_but_failing'", row)
        self.assertIn("a.problem_state === 'waiting_for_report'", row)
        self.assertIn("Still failing", row)
        self.assertIn("Waiting for the host", row)
        self.assertLess(row.index("resolved by"), row.index("${stillFailing}"))

    def test_an_open_alert_nothing_lists_any_more_is_tagged_beside_its_title(self):
        self.assertIn("a.problem_state === 'host_clear'", self.alerts)
        self.assertIn(">No longer listed</span>", self.alerts)
        title = between(self.alerts, "_escapeHtml(a.title || a.event || '')", "${_alertEscalationBadge(a)}")
        self.assertIn("${unlistedTag}", title)

    def test_the_old_field_name_is_gone(self):
        self.assertNotIn("still_failing", self.alerts)

    def test_every_pill_and_its_tooltip_is_translated(self):
        for key in ("Still failing", "Waiting for the host", "The last report from the host still shows this problem",
                    "The host has not reported since this was resolved", "No longer listed",
                    "Needs attention and Checks no longer list this problem. It may have cleared on the host, or an item may have been hidden or switched off."):
            i = self.i18n.index(json.dumps(key) + ":")
            line = self.i18n[i:self.i18n.index("\n", i)]
            for lang in LANGS:
                self.assertIn(f'"{lang}": "', line, f"{key!r} has no {lang}")


class TestTheViewsAndTheActions(_Sources):
    def test_the_four_views_are_a_segmented_control_over_one_list(self):
        seg = between(self.shell, 'id="problems-views"', "</div>")
        self.assertEqual(re.findall(r'data-action="setProblemsView" data-arg="(\w*)"', seg), ["", "alert", "attention", "check"])
        for n in ("all", "alert", "attention", "check"):
            self.assertIn(f'id="problems-view-n-{n}"', seg)

    def test_the_old_source_select_is_gone_and_the_view_reaches_the_query(self):
        self.assertNotIn("problems-filter-source", self.index + self.mod)
        query = between(self.mod, "function _problemsQuery()", "return p.toString();")
        self.assertIn("p.set('source', _problemsView)", query)

    def test_the_counts_of_the_views_are_filled_from_the_active_problems(self):
        tiles = between(self.mod, "function _renderProblemTiles", "function _markProblemViews")
        self.assertIn("counts.active_sources", tiles)
        self.assertIn("'problems-view-n-all', counts && counts.active", tiles)

    def test_the_history_modal_is_at_body_level_and_has_the_ids_the_page_fills(self):
        self.assertEqual(self.index.count('id="problem-history-modal"'), 1)
        self.assertNotIn('id="problem-history-modal"', self.shell, "an overlay inside .container is sealed under the sidebar")
        for i in ("problem-history-sub", "problem-history-body"):
            self.assertIn(f'id="{i}"', self.modal)
            self.assertIn(f"'{i}'", self.mod)

    def test_the_write_actions_are_offered_to_administrators_only_and_fix_is_not(self):
        menu = between(self.mod, "function _problemActionsHtml", "function renderProblems")
        admin = between(menu, "if (isAdmin) {", "if (r.fix")
        for name in ("muteProblem", "snoozeProblem", "ignoreProblem", "disableProblemChecks"):
            self.assertIn(name, admin)
        self.assertNotIn("fixProblem", admin)
        self.assertIn("if (isAdmin && (r.open_ids || []).length)", menu)       # Resolve

    def test_the_page_calls_only_endpoints_the_other_pages_already_call(self):
        """The actions are the other pages' actions with the other pages' permissions: no route of its own writes."""
        calls = set(re.findall(r"api\('(GET|POST|DELETE)', '(/[a-z/-]+)", self.mod))
        self.assertEqual(calls, {
            ("GET", "/problems"), ("GET", "/problems/history"), ("POST", "/alerts/bulk-resolve"),
            ("POST", "/alert-mutes"), ("DELETE", "/alert-mutes/"), ("POST", "/ignored"),
            ("POST", "/ignored/remove"), ("POST", "/checks/toggle")})
        elsewhere = "\n".join((JS / f).read_text() for f in ("app.js", "app-alerts.js", "app-checks.js"))
        for method, path in calls - {("GET", "/problems"), ("GET", "/problems/history")}:
            self.assertIn(f"api('{method}', '{path}", elsewhere, f"{method} {path} is not an endpoint another page calls")

    def test_a_state_reads_the_same_everywhere(self):
        self.assertIn("'Alert open, no longer listed'", self.mod)
        self.assertNotIn("Host reports it clear", self.index + self.mod + self.i18n)


class TestTranslated(_Sources):
    def entry(self, key):
        needle = json.dumps(key, ensure_ascii=False) + ":"
        i = self.i18n.index(needle)
        return self.i18n[i:self.i18n.index("\n", i)]

    def test_every_label_of_the_page_has_all_six_languages(self):
        keys = ["Problems", "Problem", "Where", "Needs you", "All states", "Recovered", "Resolved, still failing",
                "Resolved, waiting for the host", "Alert open, no longer listed", "All problems",
                "Views of the problems list", "Snooze 24 h", "Disable check", "Raised",
                "Nothing is recorded for this problem.", "Mute these alerts on this host",
                "Switch off these checks on this host?", "Switch off", "Checks switched off", "Everything that happened to this problem", "More actions for this problem",
                "No problems match.", "Filter problems by state", "Filter problems by where they show",
                "Filter by host, problem or kind…", "Filter by host, problem or kind", "Could not resolve the alerts",
                "Could not load problems.",
                "More problems match than are listed. Narrow the filters to see the rest.",
                "Alert resolved, still failing", "Alert resolved, waiting for the host",
                "The alert for this problem was resolved, and the last report from the host still shows the problem.",
                "The alert for this problem was resolved. The host has not reported since, so this may clear on its next report.",
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


class TestTheOtherPagesSayTheSameThing(_Sources):
    """Alerts, Needs Attention and Checks are three views of the one list (#56). Each carries a bar that links the four
    pages, and Needs Attention and Checks put the state of the problem beside the item or the check."""

    PAGES = (("alerts", 'id="page-alerts"', 'id="alerts-inbox-card"'),
             ("attention", 'id="page-attention"', 'data-action="loadAttentionPage"'),
             ("checks", 'id="page-checks"', 'id="checks-filter-status"'))

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.checks = (JS / "app-checks.js").read_text()

    def test_each_page_has_the_bar_before_its_controls_and_marks_its_own_button(self):
        for page, start, stop in self.PAGES:
            group = between(between(self.index, start, stop), 'class="segmented problem-views', "</div>")
            buttons = re.findall(r'<button data-action="showPage" data-arg="(\w+)"( class="active" aria-current="page")?>([^<]+)</button>', group)
            self.assertEqual([b[0] for b in buttons], ["problems", "alerts", "attention", "checks"], page)
            self.assertEqual([b[2] for b in buttons], ["All problems", "Alerts", "Needs Attention", "Checks"], page)
            self.assertEqual([b[0] for b in buttons if b[1]], [page], f"{page} must mark its own button and no other")

    def test_every_button_of_the_bar_opens_a_page_the_sidebar_has(self):
        pages = set(re.findall(r'data-page="(\w+)"', self.index))
        self.assertLessEqual({"problems", "alerts", "attention", "checks"}, pages)

    def test_the_bar_says_what_it_is_to_a_screen_reader_in_a_string_that_is_translated(self):
        self.assertEqual(self.index.count('aria-label="Views of the problems list"'), 4)   # the page itself and the three
        self.assertIn('"Views of the problems list":', self.i18n)

    def test_needs_attention_and_checks_ask_for_the_state_and_nothing_else_does(self):
        page = between(self.app, "async function loadAttentionPage()", "_fillAttentionFilterOptions();")
        self.assertIn("api('GET', '/attention?problems=1')", page)
        self.assertIn("api('GET', '/checks?problems=1')", between(self.checks, "async function loadChecks()", "if (!data || data.error)"))
        everything = "\n".join(f.read_text() for f in sorted(JS.glob("app*.js")))
        asked = re.findall(r"api\('GET', '(/\w+\?problems=1)'", everything)
        self.assertEqual(sorted(asked), ["/attention?problems=1", "/checks?problems=1"],
                         "the dashboard card or another reader would pay for a state it does not show")

    def test_the_tag_sits_beside_the_summary_and_beside_the_status(self):
        na = between(self.app, "function _registerAttentionTable()", "emptyMsg: 'Nothing needs attention right now.'")
        self.assertIn("${escHtml(i.summary || '')}${problemTagHtml(i.problem)}", na)
        self.assertIn("${r.status}</span>${problemTagHtml(r.problem)}", self.checks)
        self.assertIn("problem: c.problem || null", self.checks)

    def test_arriving_at_the_page_starts_at_every_problem(self):
        self.assertIn("if (name === 'problems') enterProblems();", self.app)
        enter = between(self.mod, "function enterProblems()", "function setProblemsState")
        self.assertIn("_problemsView = ''", enter)
        self.assertIn("loadProblems()", enter)
        self.assertRegex(self.app, r"problems:\s*\{ fn: 'loadProblems',\s*every: 60 \}")   # the refresh keeps the view


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestTheTag(_Sources):
    def tags(self, problems):
        body = srcpin.js_function(self.app, "problemTagHtml")
        script = body + "\nconsole.log(JSON.stringify(" + json.dumps(problems) + ".map(p => problemTagHtml(p))));"
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_only_a_problem_someone_resolved_and_the_host_has_not_cleared_gets_a_tag(self):
        states = list(STATES) + [None]
        got = dict(zip(states, self.tags([({"state": s} if s else None) for s in states])))
        self.assertEqual({s for s, tag in got.items() if tag}, {"resolved_but_failing", "waiting_for_report"})
        self.assertIn("Alert resolved, still failing", got["resolved_but_failing"])
        self.assertIn("chk-critical", got["resolved_but_failing"])
        self.assertIn("Alert resolved, waiting for the host", got["waiting_for_report"])
        self.assertIn("chk-warning", got["waiting_for_report"])

    def test_the_tag_carries_a_tooltip_and_no_inline_style_or_handler(self):
        for tag in self.tags([{"state": "resolved_but_failing"}, {"state": "waiting_for_report"}]):
            self.assertIn(' title="', tag)
            self.assertNotRegex(tag, r'\sstyle="|\son\w+="')


if __name__ == "__main__":
    unittest.main()
