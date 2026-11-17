#!/usr/bin/env python3
"""v8.0.1 "L0gMatters": release pins.

Loosened at the v8.0.2 bump: the strict version pins live in tests/test_v802.py now; this file keeps the shape checks and the list of guards the release carries.
Headline: what Threat Intel tells you and what it does about it. Clear empties the table even with the Edge blocklist on, a service
that does not answer is not counted against the daily limits, each service has limits of its own, a Request log lists what was sent to
AbuseIPDB and SniffCat and what the hosts' sensors sent, an address a ban engine already banned can be blocked without a score, and
an address carries up to three samples of what it asked for (a report ends with them only if the operator says so). The behaviour lives in the test files of each change, each
guard watched failing before it was trusted; what is here is that the release is versioned, documented and carries them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "8.0.1"
CODENAME = "L0gMatters"
PREVIOUS = "8.0.0"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v8.0.2 bump. The STRICT pins for the current release live in tests/test_v802.py; what stays here is the shape: the
    surfaces must still agree with each other, whatever version they carry, and 8.0.1 is inside the kept windows."""

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{_server_version()}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{_server_version()} \u2014 "'), first)

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

    def test_the_changelog_entry_says_it_is_a_pre_release_on_dev(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f'## v{V} \u2014 "{CODENAME}" \u2014 2026-11-16 (pre-release on dev; no standalone release)', changelog)

    def test_gen_wiki_names_a_newer_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_it_is_still_in_the_kept_windows(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md") if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertIn(f"v{V}", vers)
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], _server_version(), "the new release leads")
        self.assertIn(V, bullets)
        html = _html()
        cards = re.findall(r"What's new \u2014 v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertIn(V, cards)
        head = html[:html.index(f"What's new \u2014 v{V}")]
        self.assertIn(CODENAME.lower(), head[head.rindex('data-keywords="'):].lower())

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md",
                        "v7.4.6.md", "v7.4.7.md", "v7.4.8.md", "v7.4.9.md", "v7.5.0.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(), f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it was committed. This pins that
    they ship."""

    FILES = (
        "tests/test_v730_ipintel_clear.py",         # Clear takes every address off the table; the list keeps what it reads (43 tests)
        "tests/test_v730_ipintel_clear_page.py",    # its dialog, its answer and their six languages
        "tests/test_v801_provider_down.py",         # a service that does not answer is not charged to the daily limits, and the blocklist's downloads too
        "tests/test_v801_request_log.py",           # every request to AbuseIPDB and SniffCat is a line; no key, header or body
        "tests/test_v801_request_log_page.py",      # the card, escaped, hidden for anyone else, six languages, the seeded rows
        "tests/test_v801_service_limits.py",        # lookups, reports and downloads per day for each service; today's counts repaired once
        "tests/test_v801_intake_log.py",            # what the hosts' sensors sent is a line of the same log; the agent's own log lines
        "tests/test_v801_block_confirmed.py",       # a ban engine's decision blocks, behind a proxy at the edge, with every protection kept
        "tests/test_v801_threatintel_e2e.py",       # the card, the checkbox and the blocks table, in a browser
        "tests/test_v801_evidence_samples.py",      # CrowdSec names the server could not class (the hub's names frozen) and the sample vocabulary: a path cut to a safe alphabet, rebuilt by the server
        "tests/test_v801_agent_samples.py",         # the agent's samples: each log, the bouncer's AppSec line, the refused requests a ban is about, nothing written to disk
        "tests/test_v801_sample_reports.py",        # the setting, the intake, the page (escaped), examples in a report (off by default), nothing in the AI corpus
        "tests/test_v801_attack_classes.py",        # probing and a service's login have kinds: the families, what a report says, what ignoring means, every source, the page and the guides
        "tests/test_v801_agent_request_kinds.py",   # the agent's finer request kinds: the four patterns match what the one matched, and the server knows every kind
        "tests/test_v801_edge_samples.py",          # samples and real times from Cloudflare and the honeypot: the tiers, what is never asked for, the request log's category ids
        "tests/test_v801_uninstall_mark.py",        # the "agent uninstalled" mark follows the command: stamped by the heartbeat that delivers it, carried by the Hosts list
        "tests/test_v801_pkg_versions.py",          # RPM and Alpine versions in their own order, held to 116 recorded OSV answers
        "tests/test_v801_cve_matching.py",          # what a scan asks OSV and does with the answer, replayed from the recording; the worker; the host view
        "tests/test_v801_agent_package_sources.py", # the agent's package list: source package, epoch, what counts as installed, the Alpine database
        "tests/test_v801_notify_dest_health.py",    # a destination that keeps failing is reported once, through the others, and closed when it delivers
        "tests/test_v801_deb_source_matching.py",   # Debian and Ubuntu by source package against two recordings: the rule, the ceilings, Ubuntu Pro, the detail stage
        "tests/test_v801_cve_readers.py",           # campaigns, both MCP tools, the assistant, the SBOM and the "clean" texts read what a scan writes
        "tests/test_v801_derivatives.py",           # Mint, Zorin, elementary, Devuan and LMDE are scanned under the release they are built on
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
