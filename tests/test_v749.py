#!/usr/bin/env python3
"""v7.4.9 "Ch0iceMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape
checks. Headline: the choices a person makes on a host. A host runs its upgrades in a Standard or an Extended
mode (Discussion #30), a drivetemp sensor follows the lines of the disk it reads (#54), and an update Ubuntu is
still phasing in is not counted as pending. The behaviour lives in their own test files, each guard watched
failing before it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.9"
CODENAME = "Ch0iceMatters"
PREVIOUS = "7.4.8"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):

    def test_server_version(self):
        self.assertEqual(_server_version(), V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        self.assertTrue(m.group(1).startswith(V + "-"), m.group(1))
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_every_static_page_carries_the_same_stamp(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_readme_badge(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_header_is_newest(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{V} — "{CODENAME}"'), first)

    def test_version_doc_exists_and_is_titled(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index(f"\n## v{PREVIOUS}")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_codename(self):
        """gen-wiki.py's Home line hardcodes the codename — bump it or the
        wiki ships the previous release's name."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn(CODENAME, p.read_text())

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertIn(f"v{V}", vers)

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], V, "the new release leads")

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], V, "the new release leads")
        # The sneaky non-visible surface: the doc-search keyword attribute. A
        # visible-text rename never touches it, so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md", "v7.4.6.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_dropped_release_stays_searchable(self):
        """v7.4.6 left the three kept cards. Its search keywords moved to the
        'Older releases' card, so doc search still finds it by its codename."""
        html = _html()
        older = html[html.index('older versions history'):]
        kw = older[:older.index('"')]
        self.assertIn("f1xablematters", kw.lower())
        self.assertIn("spec1ficmatters", kw.lower(), "the releases before it are still found")

    def test_the_older_releases_card_says_where_it_starts(self):
        """The card names the newest release it stands for."""
        html = _html()
        i = html.index("<strong>Older releases</strong>")
        label = html[i:html.index("</summary>", i)]
        self.assertIn("v7.4.6 and earlier", label)


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it says what it did not run,
    its counts agree with its own table and with every other place that quotes them, and the kept reviews are the last three."""

    DOC = "docs/security-review-7.4.9.md"
    HEADLINE = "three High issues, sixteen Medium ones and ten Low or hardening items"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.9.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_leaves_open_and_what_it_did_not_run(self):
        text = self.text()
        for heading in ("## Open", "## Not found", "## Known and unchanged", "## Not run for this review"):
            self.assertIn(heading, text, heading)
        self.assertIn("A live probe of a running installation", text)

    def test_the_table_agrees_with_the_headline(self):
        self.assertIn(self.HEADLINE, self.text())
        rows = re.findall(r"^\| (S\d+) \| ([^|]+) \|", self.raw(), re.M)
        self.assertEqual([r[0] for r in rows], [f"S{i}" for i in range(1, 30)])

        def kind(severity):
            severity = severity.strip()
            if severity.startswith("**High**"):
                return "high"
            if severity == "Medium" or severity.startswith("High with signed commands"):
                return "medium"
            return "low"
        kinds = [kind(r[1]) for r in rows]
        self.assertEqual(kinds.count("high"), 3)
        self.assertEqual(kinds.count("medium"), 16, "sixteen Medium rows, all fixed")
        self.assertEqual(kinds.count("low"), 10)
        raw = self.raw()
        open_part = raw[raw.index("\n## Open"):raw.index("\n## Not found")]
        self.assertIn("Nothing rated Medium or higher is open", open_part)
        self.assertEqual(re.findall(r"(?i)\b(medium|high|critical)\b", open_part.replace("Nothing rated Medium or higher is open", "")), [],
                         "the Open section lists something rated Medium or higher")

    def test_the_other_places_quote_the_same_counts(self):
        for rel in ("docs/v7.4.9.md", "README.md", "server/html/index.html"):
            body = re.sub(r"\s+", " ", (_ROOT / rel).read_text())
            for needle in ("three High", "sixteen Medium", "ten Low"):
                self.assertIn(needle, body, (rel, needle))
        for rel in ("docs/security.md", "docs/README.md"):
            body = re.sub(r"\s+", " ", (_ROOT / rel).read_text()).lower()
            for needle in ("three high", "sixteen medium", "ten low"):
                self.assertIn(needle, body, (rel, needle))
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        section = changelog[changelog.index("## v7.4.9 \u2014 "):changelog.index("## v7.4.8 \u2014 ")]
        self.assertIn(self.HEADLINE, re.sub(r"\s+", " ", section))

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())
        self.assertNotIn("TBD-", self.raw())

    def test_it_reveals_no_command_for_the_attack_and_no_infrastructure(self):
        for rel in (self.DOC, "docs/v7.4.9.md"):
            text = (_ROOT / rel).read_text()
            for needle in ("curl", "X-Token", "wget", "nc -", "tvipper", "jaove", "/home/", "10.0.0.", "ssh -i"):
                self.assertNotIn(needle, text, (rel, needle))

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new \u2014 v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.9.md", card)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.4.7.md", "security-review-7.4.8.md", "security-review-7.4.9.md"])


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of 7.4.8 are listed in tests/test_v748.py."""

    FILES = (
        "tests/test_upgrade_mode.py",            # Discussion #30: Standard or Extended, at every place that queues an upgrade
        "tests/test_upgrade_mode_pages.py",      # the dialog block and its save, run as they are in app.js
        "tests/test_upgrade_mode_e2e.py",        # the dialog, the table badge and the bulk action in a browser
        "tests/test_apt_phased.py",              # real apt output: an update Ubuntu is phasing in is not pending
        "tests/test_drivetemp_disk_lines.py",    # #54: a drivetemp sensor is held to the lines of its disk
        "tests/test_drivetemp_disk_e2e.py",      # #54: the Thermal page and the drawer, in a browser
        "tests/test_prometheus_slo_junk.py",     # a junk number in the SLO store does not fail the scrape
        "tests/test_post748_translations.py",    # the new strings are translated and still on their pages
        "tests/test_v749_container_user.py",     # the Docker image starts its app server and daemons as www-data, not root
        "tests/test_v749_actions_pinned.py",     # every GitHub Action is pinned to a commit; Dependabot waits a week
        "tests/test_v749_ws_upgrade_map.py",     # the WebSocket proxies upgrade only for WebSocket (real nginx)
        "tests/test_v749_acme_cmd_scrub.py",     # a DNS provider token does not reach the command-output history
        "tests/test_v749_cron_names.py",         # a maintenance window written with a day name opens; an unreadable field is refused
        "tests/test_v749_ai_redaction.py",       # every AI call is redacted before it leaves the server; no adapter is called directly
        "tests/test_v749_services_config_verbs.py",  # a read-only role cannot rewrite service and log-watch rules by changing the verb
        "tests/test_tenant_instance_gate.py",    # (extended) instance-wide operations, session revoke, links, schedules and rollouts stay in the tenant
        "tests/test_v749_hostile_input.py",      # a non-ASCII token, a lone surrogate, Infinity and unhashable elements are refused, not a 500
        "tests/test_v749_logout.py",             # Sign out ends the session on the server
        "tests/test_v749_ui_polish.py",          # the measured spacing, wrapping, focus and mirroring rules and the two text bugs
        # the agent security pass: each file carries its own fail-demo
        "tests/test_v749_agent_ca_pin.py",
        "tests/test_v749_agent_container_update.py",
        "tests/test_v749_agent_guard_quarantine.py",
        "tests/test_v749_agent_hostcfg_userfiles.py",
        "tests/test_v749_agent_restore_drill.py",
        "tests/test_v749_agent_satellite_body.py",
        "tests/test_v749_agent_threat_regex.py",
        "tests/test_v749_agent_win_quoting.py",
        "tests/test_v749_scap_report_link.py",   # the SCAP report opens from a one-minute link that keeps its own sandbox
        "tests/test_v749_signals.py",            # the Advisory LUKS finding, the digest flags and the RAG GPU key, with the agent's own shapes
        "tests/test_v749_seeder.py",             # the demo hosts carry the upgrade mode, kept-back packages and named drive sensors
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
