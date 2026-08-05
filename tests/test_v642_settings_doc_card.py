"""v6.4.2: the in-app Settings doc card described a product that no longer exists.

It listed eight "tabs" — Account, Webhooks, SMTP, LDAP, Service watch, Log rules,
Server functions, Backup — against fourteen real Settings panes, none of which
are called those things. It also promised **password resets** twice, a feature
this codebase does not have anywhere.

That is the documentation twin of the UI-text-that-lies class: an operator
reading the in-app help was sent looking for controls that are not there.

The pin below is structural rather than a fixed word list, so the card fails the
build when a pane is ADDED and nobody updates it — which is how it drifted.

Run: python3 -m pytest tests/test_v642_settings_doc_card.py -q
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / "server/html/index.html").read_text()

# Pane slug -> the phrase the card is allowed to use for it. A slug is not a
# label ("notifs" is "Notifications"), so the map is explicit rather than fuzzy.
_PANE_LABEL = {
    "install": "getting started",
    "general": "general",
    "notifs": "notifications",
    "dashboard": "dashboard",
    "alertparams": "alert parameters",
    "mailbox": "mailbox",
    "ignored": "ignored items",
    "integrations": "integrations",
    "proxmox": "virtualization",
    "ai": "ai assistant",
    "security": "security",
    "tickets": "tickets",
    "backups": "backups",
    "advanced": "advanced",
}


def _card():
    i = _HTML.index('<summary><strong>Settings page</strong>')
    start = _HTML.rindex("<details", 0, i)
    return _HTML[start:_HTML.index("</details>", start)]


class TestSettingsDocCard(unittest.TestCase):
    def test_every_real_pane_is_described(self):
        """The drift direction that actually happened: panes were added and the
        card was not touched."""
        panes = set(re.findall(r'id="settings-pane-([a-z0-9-]+)"', _HTML))
        card = _card().lower()
        missing = sorted(p for p in panes
                         if _PANE_LABEL.get(p, p) not in card)
        self.assertEqual(missing, [],
                         f"Settings panes the in-app doc card does not mention: {missing}. "
                         "Add them to the card AND to _PANE_LABEL here.")

    def test_the_label_map_has_not_gone_stale_either(self):
        """A guard that names panes which no longer exist is its own kind of
        lie — it would pass while describing a removed pane."""
        panes = set(re.findall(r'id="settings-pane-([a-z0-9-]+)"', _HTML))
        gone = sorted(set(_PANE_LABEL) - panes)
        self.assertEqual(gone, [], f"_PANE_LABEL names panes that no longer exist: {gone}")

    def test_it_does_not_promise_password_resets(self):
        """There is no reset flow anywhere in the product."""
        card = _card().lower()
        self.assertNotIn("password reset", card)
        self.assertNotIn("password resets", card)

    def test_no_password_reset_feature_exists_to_document(self):
        """Pins WHY the sentence had to go, so nobody re-adds it from memory."""
        hits = []
        for p in (_ROOT / "server" / "cgi-bin").glob("*.py"):
            if re.search(r"forgot.?password|password_reset|reset-password", p.read_text(), re.I):
                hits.append(p.name)
        self.assertEqual(hits, [], f"a reset flow now exists in {hits} — document it")

    def test_it_does_not_invent_tabs(self):
        """The old card listed Account / Webhooks / SMTP / LDAP / Service watch /
        Log rules / Server functions / Backup as Settings TABS. None is one."""
        card = _card()
        for phantom in ("<strong>Account</strong>", "<strong>Webhooks</strong>",
                        "<strong>LDAP</strong>", "<strong>Service watch</strong>",
                        "<strong>Log rules</strong>", "<strong>Server functions</strong>"):
            self.assertNotIn(phantom, card, f"{phantom} is not a Settings pane")

    def test_it_points_at_a_doc_that_exists(self):
        m = re.search(r'href="(docs/[a-z0-9\-]+\.md)"', _card())
        self.assertIsNotNone(m, "the card has no Documentation link")
        self.assertTrue((_ROOT / m.group(1)).exists(), f"{m.group(1)} does not exist")


if __name__ == "__main__":
    unittest.main(verbosity=2)
