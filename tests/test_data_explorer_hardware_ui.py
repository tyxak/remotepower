#!/usr/bin/env python3
"""The Data Explorer's line under the entity select: what one row of the hardware entity is.

The entity list and the field lists of the page are built from `GET /api/query/fields`, so the hardware entity and its fields appear with no change to the
page. What the page gained is one sentence under the entity select that says what a row is, for the entities that have one (hardware, so far). The sentence is
a whole text node, so the translation of the page reaches it, and it has all six languages. The real `qeEntityChanged` runs under node over a small stand-in for
the document, so what is held is what the function does: it writes the sentence for hardware, nothing for an entity without one, and never reads a name
from the prototype chain.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text(encoding='utf-8')
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_NODE = shutil.which('node')


def _hints():
    """The sentences of `_QE_ENTITY_HINTS`, read from the source of app.js."""
    block = srcpin.balanced_block(_APP, 'const _QE_ENTITY_HINTS = ', '{', '}')
    return {m.group(1): json.loads(m.group(2)) for m in re.finditer(r'^\s*(\w+):\s*("(?:[^"\\]|\\.)*"),?\s*$', block, re.M)}


class TestTheLineIsThere(unittest.TestCase):

    def test_the_markup_has_the_line_between_the_selects_and_the_conditions(self):
        i_sel = _HTML.index('id="qe-entity"')
        i_hint = _HTML.index('id="qe-entity-hint"')
        i_cond = _HTML.index('id="qe-conditions"')
        self.assertTrue(i_sel < i_hint < i_cond)

    def test_hardware_is_the_entity_with_a_sentence_and_the_sentence_says_what_a_row_is(self):
        hints = _hints()
        self.assertEqual(sorted(hints), ['hardware'])
        self.assertIn('One row for each host', hints['hardware'])
        self.assertIn('empty cells', hints['hardware'])
        self.assertIn('Hardware tab', hints['hardware'], 'it says who sees the serial numbers')

    def test_every_sentence_has_all_six_languages(self):
        rows = dict_rows()
        missing = {k: sorted(set(LANGS) - rows.get(v, set())) for k, v in _hints().items() if set(LANGS) - rows.get(v, set())}
        self.assertEqual(missing, {}, 'sentences of the Data Explorer that are not in the dictionary in every language')
        self.assertGreater(len(_hints()), 0, 'control: the sentences were read')


_STUB = r'''
class El { constructor() { this.textContent = ''; this.value = ''; this.innerHTML = ''; } }
const els = {};
const document = { getElementById: id => els[id] || null };
let added = 0;
function escAttr(s) { return String(s); }
function escHtml(s) { return String(s); }
function _qeCurrentFields() { return ['device_id']; }
function qeAddCondition() { added++; }
'''


def _run(cases):
    body = srcpin.js_function(_APP, 'qeEntityChanged')
    consts = srcpin.balanced_block(_APP, 'const _QE_ENTITY_HINTS = ', '{', '}') + ';\n'
    script = (_STUB + consts + body + '\n'
              'const cases = ' + json.dumps(cases) + ';\n'
              'const out = [];\n'
              'for (const c of cases) {\n'
              '  for (const k of Object.keys(els)) delete els[k];\n'
              '  if (!c.drop || !c.drop.includes("hint")) els["qe-entity-hint"] = new El();\n'
              '  els["qe-entity"] = Object.assign(new El(), {value: c.entity});\n'
              '  els["qe-sort"] = new El(); els["qe-conditions"] = new El();\n'
              '  let err = null;\n'
              '  try { qeEntityChanged(); } catch (e) { err = e.message; }\n'
              '  out.push({err, hint: els["qe-entity-hint"] ? els["qe-entity-hint"].textContent : null, sort: els["qe-sort"].innerHTML});\n'
              '}\n'
              'console.log(JSON.stringify(out));\n')
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-qe-hint-'))
    try:
        f = d / 'qe.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheFunctionWritesIt(unittest.TestCase):

    def test_hardware_gets_its_sentence_and_the_others_get_none(self):
        got = _run([{'entity': 'hardware'}, {'entity': 'devices'}, {'entity': ''}])
        self.assertEqual(got[0]['hint'], _hints()['hardware'])
        self.assertEqual([g['hint'] for g in got[1:]], ['', ''])
        self.assertTrue(all(g['err'] is None for g in got), got)
        self.assertIn('device_id', got[0]['sort'], 'the rest of the function still ran')

    def test_a_name_from_the_prototype_chain_is_not_an_entity(self):
        got = _run([{'entity': n} for n in ('constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf')])
        self.assertEqual([g['hint'] for g in got], [''] * 5, got)

    def test_a_page_without_the_line_is_left_alone(self):
        got = _run([{'entity': 'hardware', 'drop': ['hint']}])
        self.assertIsNone(got[0]['err'])
        self.assertIn('device_id', got[0]['sort'])


if __name__ == '__main__':
    unittest.main()
