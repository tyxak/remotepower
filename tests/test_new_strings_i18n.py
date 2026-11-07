#!/usr/bin/env python3
"""Every visible string the sidebar sweep added has all six languages in the dictionary.

The key is the English text exactly as it is written in index.html or a script, so a reworded sentence drops out of the dictionary
without any other test noticing: this lists the strings by the sentence and checks each is a key with zh, hi, es, ar, de and fr.
Add a string here when you add one to the interface (the gates in test_v430_i18n_gate only see some kinds of text).
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_I18N = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text(encoding='utf-8')
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_JS = '\n'.join(p.read_text(encoding='utf-8') for p in sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')))

NEW_STRINGS = [
    # the OpenSCAP card of Compliance
    "Scores a host against an OpenSCAP profile and lists the rules it fails. It needs the OpenSCAP scanner and the SCAP Security Guide content on the host.",
    "About profiles and content",
    # the picker of Cron, File manager and App Catalog
    "Recent hosts",
    # the Pentest page
    "New scan",
    # Fleet Query
    "Criteria set in this group",
    "Identity",
    "Resources",
    "Clear criteria",
    # My Account > Appearance > Page sections
    "Page sections",
    "Tabs",
    "One long page",
    "Pages with many cards, such as Server Status and Compliance, show one group at a time under tabs. Choose one long page to see every card at once. It applies to this browser only.",
    # the tab labels of the pages that gained tabs (a label the dictionary already had is not listed)
    "Clients and keys",          # KMIP
    "Decisions",                 # Autonomy
    "Servers and sessions",      # SSH Gateway
    "Noise",                     # Tuning
    "Silenced",
    "Needs triage",              # Tickets
    "My tickets",
    "Schedules",                 # Pentest
    "Catalog and SLA",           # Patches
    "Map",                       # Network
    "Dependencies",
    "Discovery",
    "Watches",
    "Frameworks",                # Compliance
    "Baseline and scans",
    "Personal data",
    "Traffic",                   # Server Status
    "Diagnostics",
    "Data and upkeep",
    "Container images",         # CVEs
    # the fleet heat map: Group by and Colour by, its blocks, legends and notes (a label the dictionary already had is not listed)
    "No grouping",
    "Host type",
    "Worst finding",
    "Colour by",
    "Nothing open",
    "None",
    "Not reported",
    "No group",
    "No site",
    "No agent",
    "Under 5 minutes",
    "Under an hour",
    "Under a day",
    "A day or more",
    "Never or no agent",
    "worst open finding per host — red critical, amber warning",
    "pending updates per host — green none, red the most",
    "time since each host last checked in — green recent, red long ago",
    # Home layouts: the switcher, the manager in the Customize panel and its messages
    "Layouts",
    "My layout",
    "Dashboard layout",
    "Showing now",
    "Use",
    "Use this layout",
    "Rename this layout",
    "Delete this layout",
    "Name of the new layout",
    "Start from",
    "A copy of this layout",
    "An empty layout",
    "Fleet overview",
    "Create layout",
    "Copy wall display link",
    "Copy a link that opens the wall display",
    "Keep more than one arrangement of this page, for example one for security and one for patching, and switch between them from the top of the page. Your current layout stays as it is.",
    "Opens the page as a wall display and shows each layout in turn, 30 seconds each.",
    "Give the layout a name",
    "A layout with that name already exists",
    "You can keep up to 8 layouts: delete one first",
    "There is no room for another layout: delete one first",
    "There is no room for that name: delete a layout first",
    "Layout created",
    "Layout deleted",
    "Wall display link copied",
    "Name for this layout:",
    "Delete this layout?",
    "Copy this wall display link:",
    "This layout is full: take a widget out or delete a layout first",
    "Reset this layout to the default widgets?",
    # the wizards (Add a host, Add a notification destination) and the step-by-step mode of four long forms (a label the dictionary already had is not listed)
    "Steps",
    "Back",
    "Review",
    "Continue",
    "Finish",
    "Yes",
    "Step by step",
    "Guide me",
    "Not sure which one to use?",
    "Something went wrong. Try again.",
    "This field is needed",
    "Add a host",
    "What kind of host is it?",
    "Linux or macOS",
    "One command, run as root.",
    "One command in an elevated PowerShell.",
    "Docker host",
    "Runs the agent as a container. Nothing to install.",
    "Interactive install (PIN)",
    "The installer asks for a six-digit PIN. You get it on the next screens.",
    "Cannot run the agent",
    "A switch, printer, camera or UPS. Added by address and checked without an agent.",
    "Could not create a PIN. Try again.",
    "What should the host get when it joins?",
    "Tags (optional)",
    "Comma-separated. The group and tags are applied when the host enrolls. You can change them later.",
    "Only from these networks (optional)",
    "Addresses or networks the install may connect from, such as 10.0.0.0/24. Leave empty to allow any address.",
    "Valid for",
    "Could not create the install command. Try again.",
    "Run this on the host",
    "Run the client installer on the target host and enter this PIN when prompted.",
    "The PIN works once and expires after 10 minutes.",
    "Run on the target host as root.",
    "Run in an elevated PowerShell (Win+X → Terminal (Admin)). Needs Python 3.8+.",
    "Save as docker-compose.yml on the host, then run docker compose up -d.",
    "The command works once and stops working after the time you chose.",
    "Waiting for the host to check in…",
    "Checked in",
    "No host has checked in after 5 minutes. Check the installer output on the target, that it can reach this server, and that the token has not been used already.",
    "The host has joined",
    "Nothing has checked in yet",
    "Keep this window open, or close it: the host shows up on the Hosts page when it checks in.",
    "Open host",
    "Add another host",
    "Add a notification destination",
    "Connection",
    "Where should alerts go?",
    "Chat",
    "Push",
    "On-call",
    "Anything else",
    "Needs the application token and your user or group key from pushover.net.",
    "App token",
    "User or group key",
    "Needs an access token that may write issues in the repository.",
    "Access token",
    "Needs the integration key of a PagerDuty service (Events API v2).",
    "Integration key",
    "Needs an API key from an Opsgenie API integration. Use the EU address if your account is in the EU.",
    "Opens a ticket when an alert is acknowledged. Needs an account that may create tickets.",
    "Account (email or username)",
    "API token or password",
    "Project key",
    "Issue type (optional)",
    "The bot token is part of the address. The chat ID is the chat the bot writes to.",
    "Chat ID",
    "The access token is sent as a bearer header.",
    "Optional: each message is signed with a secret so the receiver can check where it came from.",
    "Signing secret (optional)",
    "The topic name is part of the address. Pick one nobody else will guess.",
    "The URL must start with http:// or https://",
    "Send a message to check that it arrives.",
    "Send a test message",
    "The service accepted the test message. Check that it arrived in the place you chose.",
    "Not delivered",
    "The service refused it. The address or the key is usually wrong, or has been revoked.",
    "The service had a problem on its side. Try again in a minute.",
    "Held back",
    "Tests are held back during maintenance windows and quiet hours. Try again later.",
    "Check the address and that this server can reach it.",
    "The test could not be run. Try again.",
    "What should it receive?",
    "Not tested",
    "It was not tested. A wrong address fails without a sign until the first alert needs it.",
    "Turn it on",
    "Notification destination added",
    "Saved, but switched off. Turn it on under Settings, Notifications.",
    "Safety",
    # Settings > Branding: the default typeface
    "Default typeface",
    "No default (System font)",
    "People get the default typeface until they choose their own in My Account.",
    # the Threat Intel widget on Home
    "addresses seen in the last 24 hours",
    "Reported in 24 hours",
    "Blocked now",
    "Sources in trouble",
    "Threat Intel is off.",
    "Open Threat Intel →",
    # Threat Intel: a firewall whose Suricata sends its own messages and no alerts
    "No alerts sent",
    "Suricata is running, but no alerts arrive, only its own messages. If you expect alerts, tick Enable syslog alerts in its settings (OPNsense: Services → Intrusion Detection → Settings).",
    # 8.0.0: the Apprise destination in the notification wizard
    "The key is part of the address. Set up the services behind it in Apprise itself.",
    # 8.0.0: log lines in an unhealthy container's alert
    "Log lines in an unhealthy container's alert",
    "0 sends none. A number from 1 to 10 sends that many of the container's last log lines with the notification. Obvious passwords and tokens are masked, but a log can hold other private text, and the lines go wherever the notification goes (chat, e-mail, webhooks). They are not kept in the Alerts list.",
    "Only an administrator can change this.",
    "Enter a whole number from 0 to 10.",
    # 8.0.0: the SMTP, IMAP, SSH banner and NTP monitor types
    "SMTP handshake (no mail sent)",
    "IMAP handshake (no login)",
    "SSH banner (no login)",
    "NTP clock offset",
    "Connection security",
    "None (plain connection)",
    "TLS from the start (port 465 or 993)",
    "Checks that the server answers and, with STARTTLS or TLS, that the encrypted session works. No mail is sent and no password is used. The port is 25 for SMTP and 143 for IMAP when you leave it out.",
    "Largest allowed clock offset (ms)",
    "An NTP server that answers and is synchronised is up. Set a limit to turn a clock that is further from this server's own than that into a failure. The port is 123 when you leave it out.",
    # 8.0.0: the Add an integration wizard
    "Add an integration",
    "Type a service name",
    "What do you want to connect?",
    "Media",
    "Downloads",
    "Requests",
    "Proxies",
    "Orchestration",
    "Your own",
    "Choose a service",
    "No service matches.",
    "Check the TLS certificate",
    "Turn it off for a service with a self-signed certificate on your network.",
    "Optional",
    "Check that this server can reach it and that the key works.",
    "Test the connection",
    "Reachable",
    "Not reachable",
    "The service answered.",
    "Check the address and the key, and that this server can reach it.",
    "Testing…",
    "It was not tested. A wrong address shows up as a red tile at the first check.",
    "The test did not pass. You can still add it and fix it from its card.",
    "Add it",
    "Integration added",
    "The service answered and reports a problem. That is what its tile will show.",
]


def entry_languages(text):
    """The languages of the DICT entry whose key is exactly `text`, or None when there is none."""
    import json
    m = re.search(r'^    ' + re.escape(json.dumps(text, ensure_ascii=False)) + r': \{(.*)\},?$', _I18N, re.M)
    if not m:
        return None
    return set(re.findall(r'"(zh|hi|es|ar|de|fr)": "[^"]+"', m.group(1)))


class TestNewStringsAreTranslated(unittest.TestCase):

    def test_each_string_has_all_six_languages(self):
        missing = {s[:60]: entry_languages(s) for s in NEW_STRINGS if entry_languages(s) != {'zh', 'hi', 'es', 'ar', 'de', 'fr'}}
        self.assertEqual(missing, {})

    def test_each_string_is_still_in_the_interface(self):
        # a string nobody shows any more is a dictionary entry to delete, and a reworded one has left its translation behind
        gone = [s[:60] for s in NEW_STRINGS if s not in _HTML and s not in _JS]
        self.assertEqual(gone, [])

    def test_the_check_sees_a_missing_entry_and_a_partial_one(self):
        self.assertIsNone(entry_languages('A sentence nobody wrote'))
        self.assertEqual(entry_languages('About profiles and content'), {'zh', 'hi', 'es', 'ar', 'de', 'fr'})


if __name__ == '__main__':
    unittest.main()
