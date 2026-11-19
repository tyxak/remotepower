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


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it says what is open and what was not run, its counts agree with the places that
    quote them, it says which findings are new in this release, and the kept reviews are the last three."""

    DOC = "docs/security-review-8.0.2.md"

    def text(self):
        return re.sub(r"\s+", " ", (_ROOT / self.DOC).read_text())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md", "docs/v8.0.2.md"):
            self.assertIn("security-review-8.0.2.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_is_open_and_what_it_did_not_run(self):
        text = self.text()
        for heading in ("## Open", "## Known and unchanged", "## Not found", "## Not run for this review"):
            self.assertIn(heading, text, heading)
        raw = (_ROOT / self.DOC).read_text()
        open_part = raw[raw.index("\n## Open"):raw.index("\n## Known and unchanged")]
        self.assertEqual(re.findall(r"(?i)\b(medium|high|critical)\b", open_part), [], "the Open section lists something rated Medium or higher")

    def test_the_counts_agree_with_the_places_that_quote_them(self):
        text = self.text()
        self.assertIn("fourteen High issues, twenty-three Medium issues and twelve Low issues in the first run", text)
        self.assertIn("seven Medium and two Low issues more in the second", text)
        index = re.sub(r"\s+", " ", (_ROOT / "docs/README.md").read_text())
        self.assertIn("Fourteen high, thirty medium and fourteen low findings", index)
        rows = re.findall(r"^\| (?:API surface|Pages|Threat Intel|Agents|Vulnerability pages|Stores|The second run) \| (\d+) / (\d+) / (\d+) \|", (_ROOT / self.DOC).read_text(), re.M)
        self.assertEqual(len(rows), 7)
        self.assertEqual([sum(int(r[i]) for r in rows) for i in range(3)], [14, 30, 14])

    def test_it_says_which_findings_are_in_8_0_0_and_which_are_new(self):
        text = self.text()
        self.assertIn("In 8.0.0", text)
        self.assertIn("In code new in 8.0.2", text)

    def test_it_reveals_no_command_for_the_attack_and_no_infrastructure(self):
        text = (_ROOT / self.DOC).read_text()
        for needle in ("curl", "X-Token", "wget", "nc -", "tvipper", "jaove", "/home/", "10.0.0.", "ssh -i", "genuine", "verbatim", "deliberately"):
            self.assertNotIn(needle, text, needle)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.5.0.md", "security-review-8.0.0.md", "security-review-8.0.2.md"])


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it was committed. This pins that
    they ship."""

    FILES = (
        "tests/test_v802.py",    # the release pins themselves
        "tests/test_scroll_cap_focus_rings_e2e.py",    # the keyboard focus ring of every control in the lists that scroll stays inside their edge (four lists, both engines measured by hand)
        "tests/test_v800_host_purge.py",               # the addresses a sensor queued for a host leave with it, and the four stores the seed leaves empty
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
        # Found by the review of this release and by running every reproduction again on the final tree
        "tests/test_v802_agent_log_attribution.py",                  # the nginx error log names the host that sent a request, not an address written into the message
        "tests/test_v802_audit_line_holds_no_destination.py",        # the audit line of a destination test names the host and not its address
        "tests/test_v802_command_queue_writers_lock.py",             # the four writers that saved a snapshot of the command queue take its lock
        "tests/test_v802_config_key_coverage.py",                    # RP_CONFIG_KEY seals the settings, each revision and the failed-delivery queue, addresses and header values included
        "tests/test_v802_cve_flow_accepted_risks.py",                # the vulnerability pages of one organisation: accepted risks
        "tests/test_v802_cve_flow_campaigns.py",                     # the vulnerability pages of one organisation: campaigns
        "tests/test_v802_cve_flow_false_clear.py",                   # the vulnerability pages of one organisation: false clear
        "tests/test_v802_cve_flow_home_cost.py",                     # the vulnerability pages of one organisation: home cost
        "tests/test_v802_cve_flow_host_tenant.py",                   # the vulnerability pages of one organisation: host tenant
        "tests/test_v802_cve_flow_patch_report.py",                  # the vulnerability pages of one organisation: patch report
        "tests/test_v802_cve_flow_policy_flap.py",                   # the vulnerability pages of one organisation: policy flap
        "tests/test_v802_cve_flow_sbom_cost.py",                     # the vulnerability pages of one organisation: sbom cost
        "tests/test_v802_cve_flow_scan_cost.py",                     # the vulnerability pages of one organisation: scan cost
        "tests/test_v802_cve_flow_scan_runs.py",                     # the vulnerability pages of one organisation: scan runs
        "tests/test_v802_cve_flow_scan_scope.py",                    # the vulnerability pages of one organisation: scan scope
        "tests/test_v802_edge_list_sources.py",                      # with tenants a tenant host does not put addresses in the operator Cloudflare list
        "tests/test_v802_hidden_text_cleaners.py",                   # six cleaners of host and administrator text take out characters that reorder or hide text
        "tests/test_v802_iac_collection_requested_only.py",          # a host answer to an infrastructure-as-code request is kept once and only if it was asked for
        "tests/test_v802_ip_intel_scoped_key.py",                    # a key or role with a host scope is not the platform operator on the Threat Intel page
        "tests/test_v802_ipintel_evidence_scope.py",                 # a caller reads the evidence the hosts they see collected, not the sum of every host
        "tests/test_v802_key_scope_dispatch_objects.py",             # what a scoped key starts (auto-patch policies, rollouts, rules, maintenance windows) keeps to its scope
        "tests/test_v802_key_scope_identity_routes.py",              # a scoped key creates and changes keys, roles and accounts inside its scope only
        "tests/test_v802_key_scope_smart_groups.py",                 # a scoped key cannot make, change or delete a smart group outside its scope
        "tests/test_v802_key_scope_whole_installation.py",           # the routes that act on the whole installation refuse a scoped key
        "tests/test_v802_mac_scan_budget.py",                        # the application folders of macOS and Windows are walked on one budget
        "tests/test_v802_never_block_not_an_oracle.py",              # a tenant cannot read that an address is another tenant host or sign-in source
        "tests/test_v802_never_block_spellings_and_order.py",        # the IPv4-mapped spelling is protected, and the ban route asks for the permission first
        "tests/test_v802_notify_dest_identity.py",                   # a destination that delivers again closes only its own failing alert
        "tests/test_v802_notify_dest_secret.py",                     # the alert about a failing destination holds no secret path
        "tests/test_v802_notify_redirects.py",                       # a destination that answers every delivery with a redirect is a failing destination
        "tests/test_v802_osv_answer_without_names.py",               # an advisory with no usable name is an unreadable answer, not nothing found
        "tests/test_v802_password_reset_asks_for_step_up.py",        # setting another account password asks for a fresh sign-in, which a key cannot give
        "tests/test_v802_redaction_linear.py",                       # the secret redaction takes time in proportion to the text
        "tests/test_v802_revoked_session_stays_revoked.py",          # a revoked session is not written back by another request
        "tests/test_v802_sample_token_segments.py",                  # a path segment that is a capability link is shown and sent as ~token~
        "tests/test_v802_scan_links.py",                             # the secrets and personal data scans do not go into a folder that is a link
        "tests/test_v802_scim_asks_for_step_up.py",                  # switching SCIM on or setting its token asks for a fresh sign-in
        "tests/test_v802_shapes_of_unlisted_fields.py",              # wrong-typed values in fields the shape registry did not list are repaired on read
        "tests/test_v802_sign_in_sources.py",                        # where people signed in from is kept in a store of its own
        "tests/test_v802_software_list_cut_server.py",               # a cut software list is not a compliant one
        "tests/test_v802_sso_trust_asks_for_step_up.py",             # turning on single sign-on or LDAP, or changing what they trust, asks for a fresh sign-in
        "tests/test_v802_store_write_locks.py",                      # every store several requests write is saved inside its lock, found by syntax tree
        "tests/test_v802_threat_intake_shares.py",                   # each host has a share of the day lookups and reports
        "tests/test_v802_threat_intel_tenant_scope.py",              # the settings, the day counts and the queue of Threat Intel are the platform operator
        "tests/test_v802_threat_protected_sign_ins.py",              # an address someone signed in from is protected whichever way they signed in
        "tests/test_v802_threat_sensor_forged_logs.py",              # a request cannot name the address nginx error log is read as
        "tests/test_v802_threat_sensor_hostile_logs.py",             # a request body cannot write a transaction into the ModSecurity audit log or stop the sensor
        "tests/test_v802_win_startup_links.py",                      # the startup folders of Windows are listed without following a link
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
        # Windows hosts: definition updates, build, shares and TPM
        "tests/test_windows_update_search.py",        # Defender definition updates are left out of the pending count (the agent's rule and the server's held to one answer), the state of each search, the count a failed search keeps
        "tests/test_windows_update_search_views.py",  # the Packages card and the patch report say when the search ran and whether it worked, under node
        "tests/test_windows_build.py",                # the build, revision, display version and edition from the registry, the family from the build number, the installation type
        "tests/test_windows_build_views.py",          # what the Hosts list, the drawer and Fleet Query say about the build
        "tests/test_windows_shares_tpm.py",           # the shares and the TPM: the probes, the cleaning, the Data Explorer, Fleet Query, tenants
        "tests/test_windows_shares_tpm_views.py",     # what the host drawer and Fleet Query say about the shares and the TPM
        "tests/test_windows_host_e2e.py",             # the three Windows host items in a browser over the demo, in three languages
        "tests/test_windows_inventory_review.py",     # what the review of the Windows items found, closed at the cause, among it the repair of a row that a SQL backend reads on its own
        "tests/test_agent_duplicate_definitions.py",  # a name defined twice at the top level of a program is held at zero over every program the product ships
        # Windows hosts: registry check, event log rules, persistence
        "tests/test_registry_check.py",               # the registry value check: its rules held in the agent and on the server, a stand-in registry that fails on a write, the six conditions against every state, the six baselines
        "tests/test_win_event_rules.py",              # log rules on the Windows event log: the eight events as wevtutil prints them, the cursor, the limits, hostile names, the chain to the alert
        "tests/test_win_persistence.py",              # what starts by itself on a Windows host: the inventory, the log of changes, one alert, a place that is cut or unread, the chain to the page
        "tests/test_win_security_e2e.py",             # the registry check dialog, the ready-made Windows rules and the Persistence section, in a browser
        "tests/test_entity_update_one.py",            # one row of an entity store read, changed and written as one step, on JSON and SQLite
        # Linux hosts
        "tests/test_pkg_refresh.py",                  # Check for updates now: the agent's functions with fake package managers, the server handlers, the lock watchdog, the version gate, the setting
        "tests/test_agent_capabilities.py",           # what the agent can see: the builder over fake directories, the cleaning of every wrong value, the heartbeat, the page's answer
        "tests/test_agent_state_rendered_e2e.py",     # the refresh state and What this agent can see, in a browser
        # Vulnerabilities
        "tests/test_cve_package_coverage.py",         # each package a host listed is checked, or has one reason it was not
        "tests/test_cve_package_coverage_page.py",    # the page says which packages a scan checked and why not the others
        "tests/test_cve_coverage_readers.py",         # every text that can say no CVEs says what it did not look at
        "tests/test_cve_coverage_page_review.py",     # the scripts of the coverage work run under node, the Home tile and the renamed options included
        "tests/test_cve_kernel_state.py",             # a finding against the kernel is matched against the running kernel; reboot to apply, counting and alerting
        "tests/test_cve_kernel_state_page.py",        # the page says which kernel a host runs and which findings only need a reboot
        "tests/test_cve_kernel_rpm_units.py",         # an RPM kernel is several packages, and what a scan says of it does not depend on the order of the list
        "tests/test_cve_kernel_reboot_scope.py",      # only a finding of the running kernel can read reboot to apply
        "tests/test_cve_coverage_kernel_e2e.py",      # the CVE page over the demo, in a browser: the coverage line, the six tiles, the kernel line
        # Demo
        "tests/test_demo_seed_coverage.py",           # the demo seed gives the first half of the release something to show, in the shape the server writes
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
