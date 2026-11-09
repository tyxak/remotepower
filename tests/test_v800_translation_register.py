#!/usr/bin/env python3
"""8.0.0: the translations address the reader in the register the product uses.

German, French and Spanish write to the reader formally (Sie, vous, usted) and Chinese with 您. Of the 632 entries 8.0.0 added, 26 had slipped into the informal form (du, tu, tú,
你): the SSH gateway wizard, the branding card and a few hints, and a read of all of them found 16 more in informal imperatives (Versuche es erneut, Installe-le, Inténtalo). A reader of the German page saw Sie in one box and dein in the next. The population is every entry of DICT, read
by evaluating the object literal with node as the browser does; the rule is that no entry carries an informal pronoun or possessive, except the few listed here with the reason
(a command called du, a verb that looks like the pronoun, a quoted system prompt).
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
NODE = shutil.which('node')

_EXTRACT = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[1], 'utf8');
function literal(name) {
  const m = new RegExp('^\\s*var ' + name + ' = \\{', 'm').exec(src);
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
  return vm.runInNewContext('(' + src.slice(i, end + 1) + ')', {}, {timeout: 20000});
}
process.stdout.write(JSON.stringify({DICT: literal('DICT'), HTMLDICT: literal('HTMLDICT')}));
"""

INFORMAL = {
    # the informal imperatives are listed by phrase, the ones a read of the 8.0.0 entries found: no pattern tells an imperative from a third-person description in French and Spanish
    # (`ejecuta` is both), so this list names forms that can only be an instruction and cannot promise there are no others
    'de': re.compile(r'\b(du|dich|dir|dein|deine|deinen|deinem|deiner|deines|euch|euer|eure|euren|eurem|eurer)\b|\bVersuche es\b|\bInstalliere (?:ihn|die|das|es)\b|\bprüfe dann\b'),
    'fr': re.compile(r"\b(tu|toi|ton|ta|tes)\b|\bt'|-toi\b|-tu\b|\bRéessaie\b|\bInstalle(?:-(?:le|la|les)| la)\b|\bdéfinis RP_|\bvérifie à nouveau\b"),
    # only forms that cannot be a third-person description: the possessive and the pronoun, the verbs in -as/-es of the second person, and the informal imperative with a
    # clitic, listed by word because the formal one of another verb class has the same ending (déjalo is informal, ábralo is formal)
    'es': re.compile(r'\b(tu|tus|tú|puedes|quieres|necesitas|tienes|desactivas|hayas|cambies|conéctate|asegúrate|'
                     r'(?:déj|guárd|cópi|pég|cámbi|actív|desactív|revís|instál|desbloqué|iníci|edít|ejecút|pruéb|compruéb|actualíz|confírm|aplíc|búsc|cré|ús|bórr|mír|quít|habilít|intént|analíz|despliég|configúr|'
                     r'deshabilít|reiníci|modifíc|ajúst|cárg|enví)al[oa]s?|(?:ábr|resuélv|vuélv|elíg|escríb|añád)el[oa]s?|Instala la)\b', re.I),
    'zh': re.compile('你'),
}

# (language, the start of the English key) -> why the match is not the informal pronoun
EXEMPT = {
    ('de', 'Disk-usage scanning needs the du tool'): 'du is the name of a command',
    ('fr', ': a link that was carrying observed traffic'): "s'est tu is the verb se taire (went silent)",
    ('fr', 'Each AI feature uses a system prompt to set tone'): 'ton is the noun (the tone of the answer)',
    ('fr', 'edge carried traffic before and went silent'): "s'est tu is the verb se taire (went silent)",
    ('zh', 'A small block of background ("you are an assistant'): 'a quotation of the system prompt, which says 你是',
}


def load_dict():
    out = subprocess.run([NODE, '-e', _EXTRACT, str(JS)], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise AssertionError('node could not evaluate DICT: ' + out.stderr[-500:])
    import json
    both = json.loads(out.stdout)
    merged = dict(both['DICT'])
    merged.update({'[html] ' + k: v for k, v in both['HTMLDICT'].items()})      # the page subtitles are keyed by their markup
    return merged


def informal(entries):
    """[(language, key, matched word)] for each entry that carries an informal pronoun or possessive."""
    found = []
    for key, e in entries.items():
        for lang, rx in INFORMAL.items():
            m = rx.search(e.get(lang, '') or '')
            if m:
                found.append((lang, key, m.group(0)))
    return found


@unittest.skipUnless(NODE, 'node is not installed')
class TestRegister(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dict = load_dict()

    def test_the_scan_sees_a_planted_informal_entry(self):
        planted = {'Where do your users reach the gateway?': {'de': 'Wo erreichen deine Benutzer das Gateway?', 'fr': 'Où tes utilisateurs joignent-ils la passerelle ?',
                                                              'es': '¿Dónde llegan tus usuarios a la pasarela?', 'zh': '你的用户在哪里访问网关？'}}
        self.assertEqual(sorted(l for l, _, _ in informal(planted)), ['de', 'es', 'fr', 'zh'])
        imperative = {'a': {'de': 'Installiere ihn und prüfe dann erneut.', 'fr': 'Installe-le, puis réessaie.', 'es': 'Instala la biblioteca.'},
                      'b': {'de': 'Versuche es erneut.', 'fr': 'Réessaie.', 'es': 'Analízalos con bash. Inténtalo de nuevo.'}}
        self.assertEqual(sorted((l, k) for l, k, _ in informal(imperative)), [('de', 'a'), ('de', 'b'), ('es', 'a'), ('es', 'b'), ('fr', 'a'), ('fr', 'b')], 'control: the informal imperatives are seen')
        formal_imperative = {'a': {'de': 'Installieren Sie ihn und prüfen Sie dann erneut.', 'fr': 'Installez-le, puis réessayez.', 'es': 'Instale la biblioteca. Inténtelo de nuevo.'}}
        self.assertEqual(informal(formal_imperative), [], 'control: the formal imperatives pass')
        formal = {'x': {'de': 'Wo erreichen Ihre Benutzer das Gateway?', 'fr': 'Où vos utilisateurs joignent-ils la passerelle ?', 'es': '¿Dónde llegan sus usuarios?', 'zh': '您的用户'}}
        self.assertEqual(informal(formal), [], 'control: the formal forms pass')

    def test_the_population_is_the_whole_dictionary_and_the_formal_form_is_the_norm(self):
        self.assertGreater(len(self.dict), 10500, 'the whole of DICT and the whole of HTMLDICT')
        self.assertTrue(any(k.startswith('[html] ') for k in self.dict), 'control: the page subtitles are read too')
        formal = {'de': re.compile(r'\b(Sie|Ihre|Ihren|Ihrem|Ihrer|Ihr)\b'), 'fr': re.compile(r'\b(vous|votre|vos)\b')}
        for lang, rx in formal.items():
            n = sum(1 for e in self.dict.values() if rx.search(e.get(lang, '') or ''))
            self.assertGreater(n, 250, '%s: the formal address is how this product writes (%d entries)' % (lang, n))

    def test_no_entry_addresses_the_reader_informally(self):
        found = [f for f in informal(self.dict) if (f[0], next((p for (l, p) in EXEMPT if l == f[0] and f[1].startswith(p)), None)) not in {(l, p) for (l, p) in EXEMPT}]
        self.assertEqual(found, [], '%d informal forms; the register of this product is Sie, vous, usted and 您:\n%s' % (len(found), '\n'.join('  %s: %s -> %s' % (l, k[:70], w) for l, k, w in found)))

    def test_an_exemption_names_an_entry_that_still_matches(self):
        hits = {(l, k) for l, k, _ in informal(self.dict)}
        for lang, prefix in EXEMPT:
            self.assertTrue(any(l == lang and k.startswith(prefix) for l, k in hits), '%s %r no longer matches: delete the exemption' % (lang, prefix))


if __name__ == '__main__':
    unittest.main()
