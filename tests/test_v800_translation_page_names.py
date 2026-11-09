#!/usr/bin/env python3
"""8.0.0: a text that names the Settings page uses the word the menu uses, in every language.

"enable it in Settings → Security" sends the reader to a page by its name. In Spanish 48 of the 87 texts that did said Ajustes while the menu says Configuración, so the reader looked for a
page that is not there; Hindi wrote the English word in 8 texts where the menu has सेटिंग्स, and one French text said réglages for Paramètres. The population is every DICT entry whose English
text names the page (in Settings, under Settings, Settings →, Settings,), and the word to look for is the translation of the key `Settings`, the one the menu button is drawn from. A text that
names another product's Settings page (Pi-hole, Fastmail, Tailscale) is exempt, with the reason.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
NODE = shutil.which('node')
LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')
NAMES_THE_PAGE = re.compile(r'\b(?:in|under|from|on|to|of|at) Settings\b|Settings →|Settings,|Settings ›')

# the start of the English key -> whose menu it names
EXEMPT = {
    'Pi-hole v6 API (app password under Settings': "Pi-hole's own Settings menu, which the text quotes in English",
    'Create an app password with SMTP access under Settings': "the mail provider's own Settings menu",
    'Tailscale API. Reports the hosts of your tailnet': "the Tailscale admin console's Settings menu",
}

_EXTRACT = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[1], 'utf8');
const m = /^\s*var DICT = \{/m.exec(src);
let i = m.index + m[0].length - 1, depth = 0, q = null, end = -1;
for (let j = i; j < src.length; j++) {
  const c = src[j];
  if (q) { if (c === '\\') j++; else if (c === q) q = null; continue; }
  if (c === '"' || c === "'" || c === '`') { q = c; continue; }
  if (c === '/' && src[j + 1] === '/') { j = src.indexOf('\n', j); if (j < 0) break; continue; }
  if (c === '/' && src[j + 1] === '*') { j = src.indexOf('*/', j) + 1; continue; }
  if (c === '{') depth++;
  else if (c === '}') { depth--; if (depth === 0) { end = j; break; } }
}
process.stdout.write(JSON.stringify(vm.runInNewContext('(' + src.slice(i, end + 1) + ')', {}, {timeout: 20000})));
"""


def load_dict():
    out = subprocess.run([NODE, '-e', _EXTRACT, str(JS)], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise AssertionError('node could not evaluate DICT: ' + out.stderr[-500:])
    return json.loads(out.stdout)


def exempt(key):
    return any(key.startswith(p) for p in EXEMPT)


def without_the_menu_word(entries, labels):
    """[(language, key)] for each text that names the page and does not carry the language's menu word (compared without regard to case)."""
    return [(lang, k) for k, e in entries.items() if NAMES_THE_PAGE.search(k) and not exempt(k) for lang in LANGS if labels[lang].lower() not in (e.get(lang) or '').lower()]


@unittest.skipUnless(NODE, 'node is not installed')
class TestPageNames(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dict = load_dict()
        cls.labels = {lang: cls.dict['Settings'][lang] for lang in LANGS}

    def test_the_scan_sees_a_text_that_names_the_page_another_way(self):
        planted = {'enable it in Settings → Security': {'es': 'actívelo en Ajustes → Seguridad', 'de': 'in Einstellungen → Sicherheit aktivieren', 'fr': 'activez-le dans Paramètres → Sécurité',
                                                       'zh': '在 设置 → 安全 中启用', 'hi': 'सेटिंग्स → सुरक्षा में सक्षम करें', 'ar': 'فعّله في الإعدادات ← الأمان'}}
        self.assertEqual(without_the_menu_word(planted, self.labels), [('es', 'enable it in Settings → Security')])
        planted['x Settings → y'] = {'es': 'Configuración'}
        self.assertEqual(sorted(without_the_menu_word({'a in Settings first': {}}, self.labels)), sorted((l, 'a in Settings first') for l in LANGS), 'control: a missing translation is a miss')

    def test_the_menu_has_a_word_for_the_page_in_every_language(self):
        self.assertEqual(sorted(self.labels), sorted(LANGS))
        self.assertTrue(all(self.labels[lang] and self.labels[lang] != 'Settings' for lang in LANGS), self.labels)

    def test_the_population_is_every_text_that_names_the_page(self):
        names = [k for k in self.dict if NAMES_THE_PAGE.search(k)]
        self.assertGreater(len(names), 80, 'entries that name the Settings page (87 at 8.0.0)')
        self.assertGreater(len([k for k in names if not exempt(k)]), 80)

    def test_every_text_that_names_the_page_uses_the_menu_word(self):
        miss = without_the_menu_word(self.dict, self.labels)
        self.assertEqual(miss, [], '%d texts name the Settings page and do not use the menu word:\n%s' % (len(miss), '\n'.join('  %s %r (the menu says %r)' % (l, k[:70], self.labels[l]) for l, k in miss)))

    def test_an_exemption_names_a_text_that_still_needs_it(self):
        for prefix in EXEMPT:
            keys = [k for k in self.dict if k.startswith(prefix)]
            self.assertTrue(keys, '%r matches no entry: delete the exemption' % prefix)
            self.assertTrue(any(NAMES_THE_PAGE.search(k) for k in keys), '%r no longer names a Settings page' % prefix)
            self.assertTrue(any(self.labels[l].lower() not in (self.dict[keys[0]].get(l) or '').lower() for l in LANGS), '%r now carries the menu word in every language: delete the exemption' % prefix)


if __name__ == '__main__':
    unittest.main()
