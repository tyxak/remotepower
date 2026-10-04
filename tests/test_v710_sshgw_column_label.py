"""The opt-in column on the SSH gateway page is called "Allow SSH", not "Gateway".

"Gateway" names the whole feature, so as a column header it read as a place, and
people looked for a setting that was not there. The checkbox under it is the
per-server permission.
"""
import re
import unittest
from pathlib import Path

_HTML = Path(__file__).resolve().parent.parent / 'server' / 'html'


class TestColumnLabel(unittest.TestCase):
    def test_servers_table_header_says_what_the_checkbox_does(self):
        html = (_HTML / 'index.html').read_text()
        card = html[html.index('id="sshgw-dev-thead"'):]
        card = card[:card.index('</thead>')]
        self.assertRegex(card, r'<th scope="col" data-col="enabled">Allow SSH</th>')
        self.assertNotRegex(card, r'>Gateway<')

    def test_the_label_is_translated_in_all_six_languages(self):
        js = (_HTML / 'static' / 'js' / 'i18n.js').read_text()
        m = re.search(r'"Allow SSH":\s*\{([^}]*)\}', js)
        self.assertIsNotNone(m, 'Allow SSH has no DICT entry')
        for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr'):
            self.assertRegex(m.group(1), r'"%s":\s*"[^"]+"' % lang, lang)


if __name__ == '__main__':
    unittest.main()
