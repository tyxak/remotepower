"""7.4.0: the tabbed pages' markup. Every card belongs to a tab that has a button and every button
has a card; the bar is a labelled <nav> whose current button says so (the cards are several
siblings, not one tabpanel, so it is not the ARIA tab widget). The browser half is
test_v740_page_tabs_e2e.py."""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / 'server/html/index.html').read_text()
PAGES = ('ipintel', 'account', 'sites', 'reports')


def _page_source(name):
    a = _HTML.index(f'<div id="page-{name}" class="page')
    m = re.search(r'<div id="page-[a-z0-9-]+" class="page', _HTML[a + 10:])
    return _HTML[a:a + 10 + m.start()]


class TestMarkup(unittest.TestCase):
    def test_every_card_has_a_button_and_every_button_a_card(self):
        for name in PAGES:
            src = _page_source(name)
            buttons = set(re.findall(r'data-pg-tab-btn="([a-z]+)"', src))
            cards = set(re.findall(r'<div class="[^"]*" data-pg-tab="([a-z]+)"', src))
            self.assertGreaterEqual(len(buttons), 2, name)
            self.assertEqual(buttons, cards, name)
            self.assertIn('<nav class="pg-tabs" aria-labelledby=', src, name)
            self.assertNotIn('role="tab"', src[src.index('pg-tabs'):src.index('pg-tabs') + 900], name)
            for b in buttons:
                self.assertIn(f'data-arg="{name}:{b}"', src, (name, b))




if __name__ == '__main__':
    unittest.main()
