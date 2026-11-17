#!/usr/bin/env python3
"""The Data Explorer page sends what was typed, as it was typed.

`_qeBuildWhere` made a number of any box text that parsed as one, to give the numeric operators something to compare. The text fields of the hardware entity hold digits that
a person types alone (a processor model 7302, a memory speed 2933, a disk model, a serial number), and `contains` and `eq` with a number found nothing; `007` became 7 and `1.50`
became 1.5 before it left the page. The page cannot know the kind of the field. The engine does (`query_engine` reads each value against each cell: tests/test_query_value_types.py),
so the page sends the text, trimmed, and nothing else. The real function runs under node over a stand-in for the document.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')

_STUB = r'''
class Box { constructor(v) { this.value = v; } }
class Row {
  constructor(field, op, value) { this.parts = {'.qe-cond-field': new Box(field), '.qe-cond-op': new Box(op), '.qe-cond-value': new Box(value)}; }
  querySelector(sel) { return this.parts[sel] || null; }
}
let rows = [];
const document = { querySelectorAll: sel => (sel === '#qe-conditions .qe-cond-row' ? rows : []) };
'''


def build(*conditions):
    """_qeBuildWhere() for rows of (field, op, value), run by node."""
    script = (_STUB + srcpin.js_function(_APP, '_qeBuildWhere') + '\n'
              'rows = ' + json.dumps([list(c) for c in conditions]) + '.map(c => new Row(c[0], c[1], c[2]));\n'
              'console.log(JSON.stringify(_qeBuildWhere()));\n')
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-qe-where-'))
    try:
        f = d / 'where.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheTextIsSentAsTyped(unittest.TestCase):

    def test_digits_alone_are_text(self):
        self.assertEqual(build(('cpu_model', 'contains', '7302')), {'field': 'cpu_model', 'op': 'contains', 'value': '7302'})
        self.assertEqual(build(('memory_speed', 'eq', '2933')), {'field': 'memory_speed', 'op': 'eq', 'value': '2933'})

    def test_what_a_number_would_have_lost_is_kept(self):
        for typed in ('007', '1.50', '1e3', '0x1F', ' 42 ', '00123', '1_000', '+5', '.5', '5.'):
            got = build(('serial', 'eq', typed))
            self.assertEqual(got['value'], typed.strip(), typed)
            self.assertIsInstance(got['value'], str, typed)

    def test_a_word_that_a_number_parse_would_turn_into_nothing_is_kept(self):
        """Number('Infinity') is a number, and JSON has no way to write it: it went out as null."""
        for typed in ('Infinity', '-Infinity', 'NaN', 'e5'):
            self.assertEqual(build(('serial', 'eq', typed))['value'], typed)

    def test_every_operator_sends_the_text_and_the_numeric_ones_too(self):
        for op in ('eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'contains'):
            self.assertEqual(build(('cpu_count', op, '16')), {'field': 'cpu_count', 'op': op, 'value': '16'}, op)

    def test_in_is_a_list_of_the_trimmed_pieces_and_exists_has_no_value(self):
        self.assertEqual(build(('cpu_count', 'in', '4, 8 ,16,,')), {'field': 'cpu_count', 'op': 'in', 'value': ['4', '8', '16']})
        self.assertEqual(build(('cpu_model', 'exists', 'ignored')), {'field': 'cpu_model', 'op': 'exists'})

    def test_two_rows_are_an_and_and_none_is_nothing(self):
        got = build(('a', 'eq', '1'), ('b', 'contains', 'x'))
        self.assertEqual(got, {'and': [{'field': 'a', 'op': 'eq', 'value': '1'}, {'field': 'b', 'op': 'contains', 'value': 'x'}]})
        self.assertIsNone(build())

    def test_an_empty_box_is_an_empty_text(self):
        self.assertEqual(build(('serial', 'eq', '')), {'field': 'serial', 'op': 'eq', 'value': ''})

    def test_the_source_no_longer_guesses_a_number(self):
        body = srcpin.js_function(_APP, '_qeBuildWhere')
        self.assertNotIn('Number(', body)
        self.assertNotIn('isNaN', body)


if __name__ == '__main__':
    unittest.main()
