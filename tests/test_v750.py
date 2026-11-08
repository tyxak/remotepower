#!/usr/bin/env python3
"""v7.5.0 "Wh0leMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape
checks. Headline: finishing what was started. A rule the code applied in most places and missed in one or two (four-eyes
approval on every command, a sign-in before a restore), data the agents send that no page used, and statements in the guides
and the interface that the code did not keep. The behaviour lives in their own test files, each guard watched failing before
it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.5.0"
CODENAME = "Wh0leMatters"
PREVIOUS = "7.4.9"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """The strict pins moved to tests/test_v800.py. What stays true of 7.5.0 while it is inside the windows."""

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
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md",
                        "v7.4.6.md", "v7.4.7.md", "v7.4.8.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_folded_version_stays_in_the_changelog_as_one(self):
        """7.4.9 never stood alone: its entry says so, and 7.5.0 says it carries it."""
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn('## v7.4.9 \u2014 "Ch0iceMatters" \u2014 folded into v7.5.0 (no standalone release)', changelog)
        top = changelog[changelog.index(f"## v{V}"):changelog.index("\n## v7.4.9")]
        self.assertIn("everything from 7.4.1\nto 7.4.9", top)


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it says what it did not run,
    its counts agree with its own table and with every other place that quotes them, and the kept reviews are the last three."""

    DOC = "docs/security-review-7.5.0.md"
    HEADLINE = "fifteen Medium issues, twenty-one Low or hardening items and three informational ones"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.5.0.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_leaves_open_and_what_it_did_not_run(self):
        text = self.text()
        for heading in ("## Open", "## Not found", "## Known and unchanged", "## Not run for this review"):
            self.assertIn(heading, text, heading)
        self.assertIn("A live probe of a running installation", text)

    def test_the_table_agrees_with_the_headline(self):
        self.assertIn(self.HEADLINE, self.text())
        rows = re.findall(r"^\| (S\d+) \| ([^|]+) \|", self.raw(), re.M)
        self.assertEqual([r[0] for r in rows], [f"S{i}" for i in range(1, 40)])

        def kind(severity):
            severity = severity.strip()
            if severity == "Medium" or severity.startswith("High with"):
                return "medium"
            if severity.startswith("Low"):
                return "low"
            if severity == "Info":
                return "info"
            return "other"
        kinds = [kind(r[1]) for r in rows]
        self.assertEqual(kinds.count("medium"), 15, "fifteen Medium rows, all fixed")
        self.assertEqual(kinds.count("low"), 21)
        self.assertEqual(kinds.count("info"), 3)
        self.assertEqual(kinds.count("other"), 0, [r for r in rows if kind(r[1]) == "other"])
        raw = self.raw()
        open_part = raw[raw.index("\n## Open"):raw.index("\n## Not found")]
        self.assertIn("Nothing rated Medium or higher is open", open_part)
        self.assertEqual(re.findall(r"(?i)\b(medium|high|critical)\b", open_part.replace("Nothing rated Medium or higher is open", "")), [],
                         "the Open section lists something rated Medium or higher")

    def test_every_row_names_a_test_that_exists(self):
        """The 'Held by' column is a promise: each file it names is in the tree."""
        raw = self.raw()
        section = raw[raw.index("## Fixed in 7.5.0"):raw.index("\n## Open")]
        named = set()
        for row in re.findall(r"^\| S\d+ \|.*\| ([^|]+) \|$", section, re.M):
            named |= {n.strip() for n in row.split(",") if n.strip()}
        self.assertGreater(len(named), 20, named)
        for name in sorted(named):
            self.assertTrue((_ROOT / "tests" / f"{name}.py").exists(), name)

    def test_the_other_places_quote_the_same_counts(self):
        for rel in ("docs/v7.5.0.md", "README.md", "server/html/index.html"):
            body = re.sub(r"\s+", " ", (_ROOT / rel).read_text())
            for needle in ("fifteen Medium", "twenty-one Low", "three informational"):
                self.assertIn(needle, body, (rel, needle))
        for rel in ("docs/security.md", "docs/README.md"):
            body = re.sub(r"\s+", " ", (_ROOT / rel).read_text()).lower()
            for needle in ("fifteen medium", "twenty-one low", "three informational"):
                self.assertIn(needle, body, (rel, needle))
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        section = changelog[changelog.index("## v7.5.0 \u2014 "):changelog.index("## v7.4.9 \u2014 ")]
        self.assertIn(self.HEADLINE, re.sub(r"\s+", " ", section))

    REVIEWED_ROUTES = 981          # what the route tables held at the 7.5.0 tag, which is the code the review read

    def test_the_route_count_the_review_quotes_is_the_one_it_counted(self):
        """The review says no route was added and that the table has 981 entries before and after. 981 is the count at the 7.5.0 tag, counted from
        the real route tables (the exact table and the dispatcher chain), and the review is a record of that release: the table grows with the next
        version's work (8.0.0 added five), so what is held is that the review still says what it counted and that the live table has not shrunk below
        it. A route that went missing since the review is worth a look; a route that arrived is in the CHANGELOG of its own version."""
        import importlib.util
        import os
        import sys
        import tempfile
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-routes-"))
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        spec = importlib.util.spec_from_file_location("api_v750_routes", _ROOT / "server" / "cgi-bin" / "api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        live = len(set(str(r) for r in list(api._build_exact_routes().keys()) + api._dispatcher_routes()))
        self.assertIn("No route was added", self.text())
        self.assertIn(f"has {self.REVIEWED_ROUTES} entries before and after", self.text())
        self.assertGreaterEqual(live, self.REVIEWED_ROUTES, "the route tables hold fewer entries than the 7.5.0 review counted")

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())
        self.assertNotIn("TBD-", self.raw())

    def test_it_reveals_no_command_for_the_attack_and_no_infrastructure(self):
        for rel in (self.DOC, "docs/v7.5.0.md"):
            text = (_ROOT / rel).read_text()
            for needle in ("curl", "X-Token", "wget", "nc -", "tvipper", "jaove", "/home/", "10.0.0.", "ssh -i"):
                self.assertNotIn(needle, text, (rel, needle))

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new \u2014 v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.5.0.md", card)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.4.9.md", "security-review-7.5.0.md", "security-review-8.0.0.md"])


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of 7.4.9 are listed in tests/test_v749.py."""

    FILES = (
        "tests/test_v750_accounts_signals.py",
        "tests/test_v750_advisory_hardware.py",
        "tests/test_v750_agent_canary_channel.py",
        "tests/test_v750_agent_enroll_env.py",
        "tests/test_v750_agent_hostcfg_files.py",
        "tests/test_v750_agent_installers.py",
        "tests/test_v750_agent_listening_ports.py",
        "tests/test_v750_agent_mac_brew_owner.py",
        "tests/test_v750_agent_probes_signed.py",
        "tests/test_v750_agent_repo_secrets.py",
        "tests/test_v750_agent_scanner_local_runner.py",
        "tests/test_v750_agent_server_data.py",
        "tests/test_v750_agent_update_write.py",
        "tests/test_v750_ai_flags.py",
        "tests/test_v750_ai_local_providers.py",
        "tests/test_v750_ansible_playbooks.py",
        "tests/test_v750_backup_checks.py",
        "tests/test_v750_bughunt_lows.py",
        "tests/test_v750_bughunt_lows2.py",
        "tests/test_v750_bughunt_mediums.py",
        "tests/test_v750_canary_paths_server.py",
        "tests/test_v750_cert_files.py",
        "tests/test_v750_command_approval.py",
        "tests/test_v750_compliance_patching.py",
        "tests/test_v750_compliance_time_sync.py",
        "tests/test_v750_defender_realtime.py",
        "tests/test_v750_docker_df_alone.py",
        "tests/test_v750_encryption_security_facets.py",
        "tests/test_v750_entrypoint_links.py",
        "tests/test_v750_font_licences.py",
        "tests/test_v750_governance_gated_kinds.py",
        "tests/test_v750_image_cves.py",
        "tests/test_v750_inapp_text_matches_code.py",
        "tests/test_v750_maintenance_fixes.py",
        "tests/test_v750_mcp_reads.py",
        "tests/test_v750_openapi_methodless.py",
        "tests/test_v750_openapi_security_schemes.py",
        "tests/test_v750_password_keeps_session.py",
        "tests/test_v750_posture_alerts.py",
        "tests/test_v750_provisioning_default.py",
        "tests/test_v750_query_health_fields.py",
        "tests/test_v750_rag_hardware_inventory.py",
        "tests/test_v750_rag_zfs_docker.py",
        "tests/test_v750_reliability_unit_flapping.py",
        "tests/test_v750_repo_credentials.py",
        "tests/test_v750_report_hardware_exposure.py",
        "tests/test_v750_restore_step_up.py",
        "tests/test_v750_risk_factors.py",
        "tests/test_v750_satellite_probes.py",
        "tests/test_v750_satellite_setup.py",
        "tests/test_v750_services_watched_shape.py",
        "tests/test_v750_signal_readers.py",
        "tests/test_v750_stored_not_shown_e2e.py",
        "tests/test_v750_ui_mediums_e2e.py",
        "tests/test_v749_upgrade_mode_drawer.py",
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
