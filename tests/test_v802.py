#!/usr/bin/env python3
"""v8.0.2 "C0verMatters": release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape checks.
Headline: what was missing from pages you already use: hosts and operating systems a page could not reach (one enrolment token for many hosts,
the software on Windows and macOS hosts) and the settings and numbers a page did not have. The behaviour lives in the test files of each change,
each guard watched failing before it was trusted; what is here is that the release is versioned, documented and carries them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "8.0.2"
CODENAME = "C0verMatters"
PREVIOUS = "8.0.1"     # the entry under it in CHANGELOG.md


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
                 if l.startswith("## ")][0]
        self.assertTrue(first.startswith(f'## v{V} — "{CODENAME}"'), first)

    def test_the_previous_release_is_a_shipped_one(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn('## v8.0.1 — "L0gMatters" — 2026-11-16', changelog)
        self.assertLess(changelog.index(f"## v{V}"), changelog.index(f"\n## v{PREVIOUS}"))

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
        """gen-wiki.py's Home line hardcodes the codename: bump it or the wiki ships the previous release's name."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        text = p.read_text()
        self.assertIn(CODENAME, text)
        self.assertNotIn("L0gMatters", text)

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(vers, ["v8.0.0", "v8.0.1", "v8.0.2"], f"keep exactly 3 version docs: {vers}")

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
        self.assertEqual(cards, [V, "8.0.1", "8.0.0"], f"cap the cards at 3: {cards}")
        # The non-visible surface: the doc-search keyword attribute. A visible-text rename never touches it,
        # so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md",
                        "v7.4.6.md", "v7.4.7.md", "v7.4.8.md", "v7.4.9.md", "v7.5.0.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_dropped_release_stays_searchable(self):
        """v7.5.0 left the three kept cards. Its search keywords moved to the 'Older releases' card, so doc search still
        finds it by its codename, and the releases before it are still found."""
        html = _html()
        older = html[html.index("older versions history"):]
        kw = older[:older.index('"')].lower()
        self.assertIn("wh0lematters", kw)
        self.assertIn("ch0icematters", kw, "the releases before it are still found")
        self.assertIn("hon3stmatters", kw)
        self.assertIn("0ncematters", kw, "the releases before it are still found")
        self.assertIn("f1xablematters", kw)
        self.assertIn("spec1ficmatters", kw)

    def test_the_older_releases_card_says_where_it_starts(self):
        """The card names the newest release it stands for."""
        html = _html()
        i = html.index("<strong>Older releases</strong>")
        label = html[i:html.index("</summary>", i)]
        self.assertIn("v7.5.0 and earlier", label)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it was committed. This pins that
    they ship."""

    FILES = (
        "tests/test_v802.py",    # the release pins themselves
        "tests/test_scroll_cap_focus_rings_e2e.py",    # the keyboard focus ring of every control in the lists that scroll stays inside their edge (four lists, both engines measured by hand)
        "tests/test_v800_host_purge.py",               # the addresses a sensor queued for a host leave with it
        # Enrolment and sign-in
        "tests/test_enroll_token_many_hosts.py",              # max_uses: 1 to 1000, a use taken under the lock and given back for a refused host, racing requests, the list, revoke and the audit line
        "tests/test_enroll_many_hosts_e2e.py",                # the Enroll dialog and the Add a host wizard in a browser: the field, the notice, the open commands, the next opening
        "tests/test_enroll_many_hosts_i18n.py",               # every string of that work in all six languages
        "tests/test_enrol_dialog_opens_afresh.py",            # the dialog opens at one host each time, whatever an earlier opening left behind
        "tests/test_enrol_list_draws_text.py",                # a token's label is drawn as text, never as markup, in the source and in a browser
        "tests/test_install_link_is_not_logged.py",           # the install link's token stays out of nginx's access log, in both shipped snippets
        "tests/test_token_wording.py",                        # no shipped text says a token works once or for one host without saying what changes that
        "tests/test_password_history_max_age.py",             # passwords remembered and a maximum age through the real routes: the fourth change back to the first at 3, expiry and its clearing, who is not aged, the audit lines, the export
        "tests/test_password_policy_settings_e2e.py",         # the two Settings fields and the expired-password banner in a browser, in English, German and Arabic
        "tests/test_password_policy_i18n.py",                 # every string of that work in all six languages
        "tests/test_long_password.py",                        # a password over 72 bytes is refused with a message, and the five places that hash a password handle one
        "tests/test_session_gates_allow_logout.py",           # every gate that holds a session behind a step lets it sign out
        # Security
        "tests/test_tenant_password_reset_and_export.py",     # a tenant administrator cannot set another tenant's password or download the export of every tenant
        "tests/test_downloads_check_the_status.py",           # a download that saves the answer without its status saves the error: the class is held at zero
        "tests/test_platform_only_markup.py",                 # what the page hides from everyone but the platform operator is what the server refuses them, in both directions
        "tests/test_export_buttons_tenant_e2e.py",            # the export buttons pressed in a browser as a tenant administrator and as the platform operator
        "tests/test_v802_key_scope_confirmations.py",         # an API key with a host scope lists, approves, rejects and clears only the confirmations of its own hosts
        "tests/test_v802_key_scope_inbound_tokens.py",        # the same key manages only the inbound tokens pinned to its own hosts
        # Software
        "tests/test_software_inventory_server.py",            # the ingest of Windows and macOS lists, the policy, the search, the SBOM and the order of versions
        "tests/test_software_inventory_agents.py",            # the two agents against a stand-in registry, application bundles in a temporary folder and a script in place of Homebrew
        "tests/test_software_inventory_views.py",             # what each page and guide says about the software of a Windows or macOS host, run under node
        "tests/test_software_inventory_nothing_queued.py",    # install, uninstall and hold answer 400 with the reason when no host takes the command
        "tests/test_software_inventory_e2e.py",               # the pages that show such a host's software, in a browser over the demo, in three languages
        "tests/test_software_violations_lock.py",             # the violations store is written under its lock when twelve hosts send their lists together
        "tests/test_host_written_store_locks.py",             # no store a host writes is read and saved without its lock (the class, found by syntax tree)
        # Patching, reports and the Data Explorer
        "tests/test_mean_time_to_patch.py",                   # the sweep files each completed patch; the mttp field, the five-patch minimum, scope and tenant
        "tests/test_mean_time_to_patch_ui.py",                # the card's words and the function that draws it, under node
        "tests/test_mean_time_to_patch_e2e.py",               # the card at three widths in a browser
        "tests/test_patch_age_split.py",                      # a request reads the small aging store and not the completed patches; a failed read of the host store empties nothing
        "tests/test_fleet_read_failed_prunes.py",             # a failed read of the host store is not an empty fleet: four sweeps keep what they hold, and every function with that shape is found by syntax tree
        "tests/test_data_explorer_hardware.py",               # the hardware entity: its rows, the queries, the serial number checked role by role
        "tests/test_data_explorer_hardware_ui.py",            # the line under the entity select that says what a row is
        "tests/test_data_explorer_hardware_e2e.py",           # the entity in the Data Explorer page, in a browser on the demo
        "tests/test_query_value_types.py",                    # a value is read against the field it meets: every operator against text, number, flag and empty cells
        "tests/test_data_explorer_value_ui.py",               # the page sends the text as typed
        "tests/test_software_metering_cost.py",               # the cost of a licence: exact amounts, hostile costs, who sees money
        "tests/test_software_metering_cost_ui.py",            # the metering table and its rule editor under node
        "tests/test_software_metering_cost_e2e.py",           # the columns, the total, the CSV and a refused cost, in a browser
        # Notifications and settings
        "tests/test_failing_destination_mark.py",             # the Failing mark through the real route after real failed deliveries, role by role; an edit clears it
        "tests/test_failing_destination_mark_ui.py",          # what the mark says and how it is drawn
        "tests/test_failing_destination_mark_e2e.py",         # the mark on the right card in a browser, in three languages
        "tests/test_declarative_destination_credentials.py",  # a settings document applied back keeps every destination credential; an unchanged import changes nothing
        # Interface (these four keep the test_v801 name they were written under)
        "tests/test_v801_date_prefs.py",                      # date order and clock under node with real ICU: seven languages, four orders, three clocks, a change of time zone
        "tests/test_v801_date_prefs_e2e.py",                  # My Account's two selects and a chosen order on the audit log, in a browser
        "tests/test_v801_smart_group_preview.py",             # the preview route: the saved group's own matcher, tenant and key scope, who may ask, nothing written
        "tests/test_v801_smart_group_preview_e2e.py",         # the editor's button in a browser, and focus staying on it
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
