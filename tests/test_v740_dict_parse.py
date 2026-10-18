"""The dictionary reader the i18n gates share, checked against the engine's own reading.

Three gates ask "does this string have an entry in all six languages?" through
tests/i18n_engine.py: dict_rows(). A reader that is wrong reports gaps that are not there, or hides
ones that are, and every gate that trusts it follows. Two readers in this suite had exactly that
fault: one cut an entry at the first `}` (so a translation holding `{ticket_id}` looked half empty),
and one read only the first line of an entry written over several lines (seven entries looked to
have a single language). Neither showed until a new entry happened to hit it.

The control is the engine: node evaluates the DICT object literal as the browser does, and every
key's languages must equal what dict_rows() found.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import I18N_JS, LANGS, _languages, dict_rows  # noqa: E402

_NODE = shutil.which('node')

_EVAL = r'''
const src = require('fs').readFileSync(process.argv[2], 'utf8');
const head = 'var DICT = ';
const at = src.indexOf(head + '{');
const end = src.indexOf('\n  };', at);
const dict = (new Function('return ' + src.slice(at + head.length, end + 4)))();
const out = {};
for (const k of Object.keys(dict)) out[k] = Object.keys(dict[k] || {});
process.stdout.write(JSON.stringify(out));
'''


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheReaderAgreesWithTheEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        assert _NODE, 'node vanished between the skip check and the run'
        work = Path(tempfile.mkdtemp(prefix='rp-dictparse-'))
        try:
            (work / 'eval.js').write_text(_EVAL, encoding='utf-8')
            r = subprocess.run([_NODE, str(work / 'eval.js'), str(I18N_JS)], capture_output=True, text=True, timeout=120)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if r.returncode != 0:
            raise AssertionError('node could not evaluate DICT: ' + r.stderr[-600:])
        cls.engine = {k: set(v) & set(LANGS) for k, v in json.loads(r.stdout).items()}
        cls.rows = dict_rows()

    def test_the_engine_was_read(self):
        self.assertGreater(len(self.engine), 8000, 'node returned almost nothing')

    def test_the_same_keys(self):
        self.assertEqual(sorted(set(self.engine) - set(self.rows))[:5], [], 'keys the reader missed')
        self.assertEqual(sorted(set(self.rows) - set(self.engine))[:5], [], 'keys the reader invented')

    def test_the_same_languages_for_every_key(self):
        differ = {k: (sorted(self.rows[k]), sorted(v)) for k, v in self.engine.items()
                  if k in self.rows and self.rows[k] != v}
        self.assertEqual(differ, {}, 'the reader and the engine disagree about the languages of '
                         f'{len(differ)} entries, for example: {list(differ.items())[:3]}')


class TestTheReaderOnShapesThatBrokeOthers(unittest.TestCase):

    def _rows(self, entries):
        return dict_rows('  var DICT = {\n' + entries + '\n  };\n')

    def test_a_brace_inside_a_translation_does_not_end_the_entry(self):
        rows = self._rows('    "Hi {ticket_id}": { "zh": "您好 {ticket_id}", "hi": "नमस्ते", "es": "Hola", '
                          '"ar": "مرحبًا", "de": "Guten Tag", "fr": "Bonjour" },')
        self.assertEqual(rows['Hi {ticket_id}'], set(LANGS))

    def test_an_unbalanced_brace_inside_a_translation_does_not_end_the_entry(self):
        """Balanced braces survive any depth count; a lone one only survives a scan that takes strings whole."""
        rows = self._rows('    "Open": { "zh": "x", "hi": "a", "es": "} cierra", "ar": "c", "de": "d", "fr": "e" },\n'
                          '    "Next": { "zh": "z" },')
        self.assertEqual(rows['Open'], set(LANGS))
        self.assertEqual(rows['Next'], {'zh'})

    def test_a_key_that_is_not_a_language_is_ignored(self):
        rows = self._rows('    "Extra": { "zh": "a", "note": "b", "fr": "c" },')
        self.assertEqual(rows['Extra'], {'zh', 'fr'})

    def test_a_colon_inside_a_translation_is_not_a_language(self):
        rows = self._rows('    "Note": { "zh": "注意：de: x", "hi": "a", "es": "b", "ar": "c", "de": "d", "fr": "e" },')
        self.assertEqual(rows['Note'], set(LANGS))
        rows = self._rows('    "Odd": { "zh": "x", "hi": "y", "es": "fr: not a key", "ar": "z" },')
        self.assertEqual(rows['Odd'], {'zh', 'hi', 'es', 'ar'})

    def test_an_entry_written_over_several_lines_is_read_to_its_end(self):
        rows = self._rows("    'Long key':\n      {fr: \"a\",\n        de: 'b',  zh: 'c',\n"
                          "        hi: 'd', es: 'e',\n        ar: 'f'},")
        self.assertEqual(rows['Long key'], set(LANGS))

    def test_a_missing_language_is_reported(self):
        rows = self._rows('    "Half": { "zh": "a", "fr": "b" },')
        self.assertEqual(rows['Half'], {'zh', 'fr'})

    def test_one_entry_does_not_borrow_from_the_next(self):
        rows = self._rows('    "One": { "zh": "a" },\n    "Two": { "hi": "b", "es": "c" },')
        self.assertEqual(rows['One'], {'zh'})
        self.assertEqual(rows['Two'], {'hi', 'es'})

    def test_both_quote_styles_are_keys(self):
        rows = self._rows("    'It\\'s': { fr: 'a' },\n    \"Say \\\"hi\\\"\": { \"fr\": \"b\" },")
        self.assertEqual(set(rows), {"It's", 'Say "hi"'})

    def test_languages_of_a_bare_object(self):
        self.assertEqual(_languages('{ zh: "a", fr: \'b\' }', 0), {'zh', 'fr'})


if __name__ == '__main__':
    unittest.main()
