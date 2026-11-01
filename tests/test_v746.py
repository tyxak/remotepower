#!/usr/bin/env python3
"""v7.4.6 "F1xableMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: four reports from the same Docker
install (#55 to #58). #55, a host can be marked internal, was built as v7.4.5 and
folded into this release before it shipped; its proofs stay in tests/test_v745*.py.
The behaviour of the other three lives in their own test files, each guard watched
failing before it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.6"
CODENAME = "F1xableMatters"
PREVIOUS = "7.4.5"     # the entry under it in CHANGELOG.md: the folded version


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """The strict pins moved to tests/test_v747.py. What stays true of 7.4.6 while it is inside the windows."""

    def test_version_doc_exists_and_is_titled(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} \u2014 "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary", "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index(f"\n## v{PREVIOUS}")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_names_a_newer_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_it_is_still_in_the_kept_windows(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md") if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertIn(f"v{V}", vers)
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        self.assertIn(V, re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M))
        html = _html()
        self.assertIn(V, re.findall(r"What's new \u2014 v(\d+\.\d+\.\d+)", html))
        head = html[:html.index(f"What's new \u2014 v{V}")]
        self.assertIn(CODENAME.lower(), head[head.rindex('data-keywords="'):].lower())

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.5.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(), f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheFoldedVersion(unittest.TestCase):
    """7.4.5 never shipped on its own. Nothing a reader sees may announce it as a release, and the
    entry that records what it built says where it went."""

    def test_the_changelog_keeps_its_entry_as_a_folded_one(self):
        heads = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v7.4.5 ")]
        self.assertEqual(len(heads), 1, heads)
        self.assertIn("Int3rnalMatters", heads[0])
        self.assertTrue(heads[0].endswith("folded into v7.4.6 (no standalone release)"), heads[0])

    def test_the_notes_carry_what_it_built(self):
        self.assertFalse((_ROOT / "docs/v7.4.5.md").exists())
        self.assertIn("## A host can count as internal", (_ROOT / f"docs/v{V}.md").read_text())

    def test_no_surface_announces_a_release_that_never_shipped(self):
        readme = (_ROOT / "README.md").read_text()
        self.assertNotIn('**v7.4.5 "', readme)
        self.assertNotIn("What's new \u2014 v7.4.5", _html())
        self.assertNotIn("(v7.4.5.md)", (_ROOT / "docs/README.md").read_text())

    def test_its_codename_stays_searchable(self):
        html = _html()
        head = html[:html.index(f"What's new \u2014 v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn("int3rnalmatters", kw.lower())


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it names what it
    found, it says what it did not run, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.6.md"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.6.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("The first, a switch that marks a host as internal, was reviewed on its own", text)
        self.assertIn("were not run this time", text)           # the nginx scanners and nuclei
        self.assertIn("## Known and unchanged", text)
        self.assertIn("a live probe of the maintainer's own instance", text)
        self.assertIn("(`make ci-parity`)", text)

    def test_it_names_its_two_findings_and_the_summary_has_two_rows(self):
        text = self.text()
        self.assertIn("**two** issues", text)
        self.assertIn("turned on for the string \"false\"", text)
        self.assertIn("Five readers raised on a stored row that is not a whole map", text)
        rows = re.findall(r"^\| ([1-9]) \|", self.raw(), re.M)
        self.assertEqual(rows, ["1", "2"])

    def test_it_ran_the_scans_and_the_checks_it_says_it_did(self):
        text = self.text()
        for needle in ("bandit", "semgrep", "gitleaks", "pip-audit", "CodeQL", "A scan against the live OSV",
                       "The agent's sockets", "Hostile input to what is new", "Mutation checks", "PostgreSQL"):
            self.assertIn(needle, text, needle)

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())
        self.assertNotIn("TBD-", self.raw())

    def test_it_reveals_no_command_for_the_attack(self):
        text = self.raw()
        for needle in ("curl", "X-Token", "wget", "nc -"):
            self.assertNotIn(needle, text, needle)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.6 \u2014 "):body.index("## v7.4.5 \u2014 ")]
        section = body[body.index("### Security"):][:700]
        self.assertIn("two issues", re.sub(r"\s+", " ", section))
        notes = re.sub(r"\s+", " ", (_ROOT / "docs/v7.4.6.md").read_text())
        self.assertIn("It found two more issues, both low", notes)

    def test_the_card_links_its_review_and_the_index_of_the_others(self):
        html = _html()
        card = html[html.index("What's new \u2014 v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.6.md", card)
        self.assertIn("docs/security.md", card)         # the review of the internal-host switch left the window at v7.4.8
        self.assertNotIn("docs/security-review-7.4.5.md", card)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.4.6.md", "security-review-7.4.7.md", "security-review-7.4.8.md"])

    def test_the_review_that_left_the_window_is_gone_everywhere(self):
        for gone in ("7.4.3", "7.4.4", "7.4.5"):
            self.assertFalse((_ROOT / f"docs/security-review-{gone}.md").exists(), gone)
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
                self.assertNotIn(f"security-review-{gone}.md", (_ROOT / rel).read_text(), (gone, rel))

    def test_the_kept_reviews_do_not_send_a_reader_to_the_one_that_left(self):
        self.assertNotIn("7.4.3 review", self.text())


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of #55 are listed in tests/test_v745.py."""

    FILES = (
        "tests/test_v746_peer_direction.py",    # #58: the agent leaves out what the host accepted, the server's rule, the heartbeat contract
        "tests/test_v746_cve_fix_status.py",    # #57: the scan per release, the alert option and the re-alert, the report and the readers
        "tests/test_v746_cve_fix_page.py",      # #57: the page counts a finding as the server does, and the demo data keeps the contract
        "tests/test_v746_cve_fix_e2e.py",       # #57: the tiles, the filter, the host view and the Settings option, in a browser
        "tests/test_v746_translations.py",      # #57: the text the release added, in six languages
        "tests/test_v746_resolve_refresh.py",   # #56: resolving an alert by hand makes its host report; the three agents read it
        "tests/test_v746_drive_lines_thermal.py",  # #54: the Thermal page and the risk score hold a drive to its own lines
        "tests/test_v746_thermal_e2e.py",       # #54: the sensor table paints a drive by its own state, in a browser
        "tests/test_v746_security.py",          # the review: who may ask a host to report, a strict switch, hostile records and stores
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
