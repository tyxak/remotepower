#!/usr/bin/env python3
"""8.0.0: the security review is part of the release.

It exists, it is indexed where a reader looks, its counts agree with its own table and with every other place that quotes them, each test it names is in the
tree, it says what it did not run, and it counted the route table it read.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DOC = "docs/security-review-8.0.0.md"
HEADLINE = "one High issue, nine Medium issues, seven Low or hardening items and one informational item"
REVIEWED_ROUTES = 995          # what the route tables held when the review was written: 981 at 7.5.0 and the 14 routes 8.0.0 added


def raw():
    return (_ROOT / DOC).read_text()


def text():
    return re.sub(r"\s+", " ", raw())


class TestTheSecurityReview(unittest.TestCase):

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-8.0.0.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_leaves_open_and_what_it_did_not_run(self):
        t = text()
        for heading in ("## Open", "## Not found", "## Known and unchanged", "## The release gate", "## Not run for this review"):
            self.assertIn(heading, t, heading)
        self.assertIn("A live probe of a running installation", t)

    def test_the_table_agrees_with_the_headline(self):
        self.assertIn(HEADLINE, text())
        rows = re.findall(r"^\| (S\d+) \| ([^|]+) \|", raw(), re.M)
        self.assertEqual([r[0] for r in rows], ["S%d" % i for i in range(1, 19)])

        def kind(severity):
            severity = severity.strip()
            return {"High": "high", "Medium": "medium", "Info": "info"}.get(severity) or ("low" if severity.startswith("Low") else "other")
        kinds = [kind(r[1]) for r in rows]
        self.assertEqual((kinds.count("high"), kinds.count("medium"), kinds.count("low"), kinds.count("info"), kinds.count("other")), (1, 9, 7, 1, 0), kinds)
        body = raw()
        open_part = body[body.index("\n## Open"):body.index("\n## Not found")]
        self.assertIn("Nothing rated Medium or higher is open", open_part)
        self.assertEqual(re.findall(r"(?i)\b(medium|high|critical)\b", open_part.replace("Nothing rated Medium or higher is open", "")), [],
                         "the Open section lists something rated Medium or higher")

    def test_every_row_names_a_test_that_exists(self):
        body = raw()
        section = body[body.index("## Fixed in 8.0.0"):body.index("\n## Open")]
        named = set()
        for row in re.findall(r"^\| S\d+ \|.*\| ([^|]+) \|$", section, re.M):
            named |= {n.strip() for n in row.split(",") if n.strip()}
        self.assertGreaterEqual(len(named), 14, named)
        for name in sorted(named):
            self.assertTrue((_ROOT / "tests" / ("%s.py" % name)).exists(), name)

    def test_the_other_places_quote_the_same_counts(self):
        for rel in ("docs/v8.0.0.md", "README.md", "server/html/index.html"):
            self.assertIn(HEADLINE.lower(), re.sub(r"\s+", " ", (_ROOT / rel).read_text()).lower(), rel)
        for rel in ("docs/security.md", "docs/README.md"):
            body = re.sub(r"\s+", " ", (_ROOT / rel).read_text()).lower()
            for needle in ("nine medium", "one informational"):
                self.assertIn(needle, body, (rel, needle))
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        section = changelog[changelog.index("## v8.0.0 — "):changelog.index("## v7.5.0 — ")]
        self.assertIn(HEADLINE.lower(), re.sub(r"\s+", " ", section).lower())

    def test_the_route_count_the_review_quotes_is_the_one_it_counted(self):
        """The review says 981 entries at 7.5.0 and 14 added. 995 is the count when it was written, from the real route tables (the exact table and the
        dispatcher chain). The table grows with the next version's work, so what is held is that the review still says what it counted and that the live
        table has not shrunk below it."""
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800-routes-"))
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        spec = importlib.util.spec_from_file_location("api_v800_review_routes", _ROOT / "server" / "cgi-bin" / "api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        live = len(set(str(r) for r in list(api._build_exact_routes().keys()) + api._dispatcher_routes()))
        self.assertIn("Fourteen routes were added", text())
        self.assertIn("held 981 entries at 7.5.0 and holds %d now" % REVIEWED_ROUTES, text())
        self.assertGreaterEqual(live, REVIEWED_ROUTES, "the route tables hold fewer entries than the 8.0.0 review counted")

    def test_no_placeholder_is_left(self):
        for stub in ("@@", "TBD-"):
            self.assertNotIn(stub, raw(), stub)

    def test_it_reveals_no_command_for_the_attack_and_no_infrastructure(self):
        for rel in (DOC, "docs/v8.0.0.md"):
            body = (_ROOT / rel).read_text()
            for needle in ("curl", "X-Token", "wget", "nc -", "tvipper", "jaove", "/home/", "10.0.0.", "ssh -i"):
                self.assertNotIn(needle, body, (rel, needle))

    def test_it_keeps_clear_of_the_words_the_house_style_drops(self):
        for rel in (DOC, "docs/v8.0.0.md"):
            body = (_ROOT / rel).read_text().lower()
            for word in ("genuine", "verbatim", "deliberate"):
                self.assertNotIn(word, body, (rel, word))

    def test_the_card_links_the_review(self):
        html = (_ROOT / "server" / "html" / "index.html").read_text()
        card = html[html.index("What's new — v8.0.0"):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-8.0.0.md", card)


if __name__ == "__main__":
    unittest.main()
