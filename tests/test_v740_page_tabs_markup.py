"""7.4.0: the tabbed pages' markup. Every card belongs to a tab that has a button and every button
has a card; the bar is a labelled <nav> whose current button says so (the cards are several
siblings, not one tabpanel, so it is not the ARIA tab widget). The browser half is
test_v740_page_tabs_e2e.py (the four pages of 7.4.0) and test_page_sections_e2e.py (every page).

Page sections: the population is every page that has a strip, read from index.html, so a page that
gains one is held to the same rules. A card that two tabs share lists both names, separated by a space.
The strip names its page, its default tab is one of its buttons, and the title it is labelled by exists."""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / 'server/html/index.html').read_text()
PAGES = tuple(sorted(set(re.findall(r'<nav class="pg-tabs"[^>]*\bdata-pg="([a-z0-9-]+)"', _HTML))))
OLD_PAGES = ('ipintel', 'account', 'sites', 'reports')


def _page_source(name):
    a = _HTML.index(f'<div id="page-{name}" class="page')
    m = re.search(r'<div id="page-[a-z0-9-]+" class="page', _HTML[a + 10:])
    return _HTML[a:a + 10 + m.start()]


def card_tabs(src):
    """Every tab name a tagged element of the page source belongs to."""
    out = set()
    for value in re.findall(r'<[a-z]+[^>]*\bdata-pg-tab="([a-z ]+)"', src):
        out.update(value.split())
    return out


class TestMarkup(unittest.TestCase):
    def test_the_population_has_the_old_pages_and_is_not_empty(self):
        self.assertTrue(set(OLD_PAGES) <= set(PAGES), PAGES)
        self.assertGreaterEqual(len(PAGES), 5, PAGES)

    def test_every_card_has_a_button_and_every_button_a_card(self):
        for name in PAGES:
            src = _page_source(name)
            buttons = set(re.findall(r'data-pg-tab-btn="([a-z]+)"', src))
            cards = card_tabs(src)
            self.assertGreaterEqual(len(buttons), 2, name)
            self.assertEqual(buttons, cards, name)
            self.assertIn('<nav class="pg-tabs" aria-labelledby=', src, name)
            self.assertNotIn('role="tab"', src[src.index('pg-tabs'):src.index('pg-tabs') + 900], name)
            for b in buttons:
                self.assertIn(f'data-arg="{name}:{b}"', src, (name, b))

    def test_the_strip_names_its_page_its_default_and_its_title(self):
        for name in PAGES:
            src = _page_source(name)
            m = re.search(r'<nav class="pg-tabs" aria-labelledby="([a-z0-9-]+)" data-pg="([a-z0-9-]+)" data-default="([a-z]+)"', src)
            self.assertIsNotNone(m, name)
            label_id, pg, default = m.groups()
            self.assertEqual(pg, name)
            self.assertIn(f'data-pg-tab-btn="{default}"', src, (name, 'default'))
            self.assertIn(f'id="{label_id}"', src, (name, 'the title the strip is labelled by'))
            self.assertEqual(src.count('<nav class="pg-tabs"'), 1, f'{name}: one strip per page')

    def test_the_check_reads_a_shared_card(self):
        self.assertEqual(card_tabs('<div class="dash-card" data-pg-tab="scans schedules"></div><div data-pg-tab="targets">'),
                         {'scans', 'schedules', 'targets'})


if __name__ == '__main__':
    unittest.main()
