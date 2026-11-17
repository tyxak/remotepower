#!/usr/bin/env python3
"""A value of one kind meets a cell of another: the query engine reads the value against the cell.

The Data Explorer page sent what a person typed, and made a number of it when it parsed as one. A text cell that holds digits (a processor model "7302", a memory speed "2933",
a disk model, a serial number) was then asked `contains 7302` or `eq 2933` with a number, which the engine answered with nothing: `contains` wanted text on both sides and `eq`
compared "2933" with 2933. The page cannot know the kind of a cell, and the engine can: it sees each cell. So the page sends what was typed, as text, and the engine reads it
against the cell:

  * a text cell and a number: the text of the number (`contains 7302`, `eq 2933`, `in [99]`);
  * a number cell and text that is only a decimal number: the number (`eq "8"`, `gt "10"`, `in ["4", "8"]`);
  * a flag cell and the words true and false, whatever their case;
  * everything else still finds nothing, and nothing raises: a word against a number cell, a number against a flag, a list, a map, null, a number too long for the engine, "nan", "inf".

The text cell is never read as a number (a text cell `gt 100` finds nothing, "2933 MT/s" is not equal to 2933 though it contains it), and `contains` on a number cell finds nothing.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import query_engine as qe  # noqa: E402

FIELDS = {k: (lambda r, k=k: r.get(k)) for k in ('name', 'cpu_model', 'memory_speed', 'serial', 'cpu_count', 'ratio', 'monitored')}
ROWS = [
    {'name': 'a', 'cpu_model': 'AMD EPYC 7302 16-Core Processor', 'memory_speed': '2933', 'serial': '00123', 'cpu_count': 16, 'ratio': 1.5, 'monitored': True},
    {'name': 'b', 'cpu_model': 'Intel Xeon Gold 6130', 'memory_speed': '2933 MT/s', 'serial': '99', 'cpu_count': 8, 'ratio': 2, 'monitored': False},
    {'name': 'c', 'cpu_model': '', 'memory_speed': '', 'serial': '', 'cpu_count': None, 'ratio': None, 'monitored': None},
]


def names(field, op, value):
    return [r['name'] for r in qe.run(ROWS, {'field': field, 'op': op, 'value': value}, FIELDS)]


class TestANumberMeetsTextCell(unittest.TestCase):

    def test_contains_reads_a_number_as_its_text(self):
        self.assertEqual(names('cpu_model', 'contains', 7302), ['a'])
        self.assertEqual(names('cpu_model', 'contains', '7302'), ['a'])
        self.assertEqual(names('cpu_model', 'contains', 6130), ['b'])
        self.assertEqual(names('memory_speed', 'contains', 2933), ['a', 'b'])
        self.assertEqual(names('cpu_model', 'contains', 'xeon'), ['b'], 'and text is as it was: case-insensitive')

    def test_eq_and_ne_read_a_number_as_its_text(self):
        self.assertEqual(names('memory_speed', 'eq', 2933), ['a'], 'b holds "2933 MT/s", which is not equal to 2933')
        self.assertEqual(names('memory_speed', 'eq', '2933'), ['a'])
        self.assertEqual(names('memory_speed', 'eq', 2933.0), ['a'], 'a float that is whole is written without its point')
        self.assertEqual(names('memory_speed', 'ne', 2933), ['b', 'c'])
        self.assertEqual(names('serial', 'eq', 99), ['b'])
        self.assertEqual(names('serial', 'eq', 123), [], 'the serial is "00123": text is compared as written, and the zeros are part of it')
        self.assertEqual(names('serial', 'eq', '00123'), ['a'])

    def test_in_reads_each_number_of_the_list_as_its_text(self):
        self.assertEqual(names('serial', 'in', [99]), ['b'])
        self.assertEqual(names('serial', 'in', ['99', '00123']), ['a', 'b'])
        self.assertEqual(names('serial', 'in', [123, 99, None]), ['b'])

    def test_a_text_cell_is_not_read_as_a_number(self):
        self.assertEqual(names('memory_speed', 'gt', 100), [], 'a text cell has no magnitude')
        self.assertEqual(names('memory_speed', 'lte', '5000'), [])
        self.assertEqual(names('serial', 'gte', 0), [])
        self.assertEqual(names('memory_speed', 'eq', '2933 MT'), [], 'and equal means equal')


class TestTextMeetsANumberCell(unittest.TestCase):

    def test_eq_ne_and_in_read_text_that_is_a_number_as_the_number(self):
        self.assertEqual(names('cpu_count', 'eq', '8'), ['b'])
        self.assertEqual(names('cpu_count', 'eq', 8), ['b'])
        self.assertEqual(names('cpu_count', 'eq', ' 8 '), ['b'])
        self.assertEqual(names('cpu_count', 'eq', '8.0'), ['b'])
        self.assertEqual(names('cpu_count', 'eq', '1.6e1'), ['a'])
        self.assertEqual(names('cpu_count', 'ne', '8'), ['a', 'c'])
        self.assertEqual(names('cpu_count', 'in', ['8', '16']), ['a', 'b'])
        self.assertEqual(names('cpu_count', 'in', ['4', 'x']), [])
        self.assertEqual(names('ratio', 'eq', '1.5'), ['a'])
        self.assertEqual(names('ratio', 'eq', '2'), ['b'], 'an integer cell and a float written the same way')
        self.assertEqual(names('ratio', 'eq', 2.0), ['b'])

    def test_the_order_operators_read_text_that_is_a_number_as_the_number(self):
        self.assertEqual(names('cpu_count', 'gt', '10'), ['a'])
        self.assertEqual(names('cpu_count', 'gte', '16.0'), ['a'])
        self.assertEqual(names('cpu_count', 'lt', '9'), ['b'])
        self.assertEqual(names('cpu_count', 'lte', '8'), ['b'])
        self.assertEqual(names('ratio', 'gt', '1.75'), ['b'])
        self.assertEqual(names('cpu_count', 'gt', 10), ['a'], 'a number is as it was')

    def test_a_word_finds_nothing_in_a_number_cell_and_nothing_raises(self):
        for op in ('eq', 'gt', 'gte', 'lt', 'lte', 'contains'):
            self.assertEqual(names('cpu_count', op, 'many'), [], op)
        self.assertEqual(names('cpu_count', 'ne', 'many'), ['a', 'b', 'c'], 'it is not equal to any of them, as before')
        self.assertEqual(names('cpu_count', 'contains', 1), [], 'a number cell is not searched as text')
        self.assertEqual(names('cpu_count', 'contains', '1'), [])

    def test_an_empty_cell_never_meets_a_value(self):
        for op in ('eq', 'gt', 'gte', 'lt', 'lte', 'contains'):
            self.assertNotIn('c', names('cpu_count', op, '0'), op)
        self.assertNotIn('c', names('cpu_count', 'in', ['0']))
        self.assertIn('c', names('cpu_count', 'ne', '0'))


class TestAFlagCell(unittest.TestCase):

    def test_the_words_true_and_false_in_any_case_meet_a_flag(self):
        self.assertEqual(names('monitored', 'eq', 'true'), ['a'])
        self.assertEqual(names('monitored', 'eq', 'True'), ['a'])
        self.assertEqual(names('monitored', 'eq', ' TRUE '), ['a'])
        self.assertEqual(names('monitored', 'eq', 'false'), ['b'])
        self.assertEqual(names('monitored', 'ne', 'true'), ['b', 'c'])
        self.assertEqual(names('monitored', 'in', ['false', 'x']), ['b'])
        self.assertEqual(names('monitored', 'eq', True), ['a'], 'and a flag is as it was')
        self.assertEqual(names('monitored', 'eq', False), ['b'])

    def test_any_other_word_finds_nothing(self):
        for word in ('yes', 'no', 'on', 'off', '', 'truee', 't', 'null', '1x'):
            self.assertEqual(names('monitored', 'eq', word), [], repr(word))


class TestHostileValues(unittest.TestCase):

    VALUES = ['9' * 5000, '1e999', '-1e999', 'nan', 'NaN', 'inf', '-inf', 'Infinity', '-', '.', 'e5', '1e', '１２', '٣', '1_000', '0x10', '', ' ', None, True, False, [], [1], {}, {'a': 1},
              float('inf'), -float('inf'), 10 ** 400, 1e308, '\x00', '8\x00', '8\n9']

    def test_nothing_raises_whatever_the_value_and_the_operator(self):
        for field in ('cpu_model', 'cpu_count', 'ratio', 'monitored', 'serial'):
            for op in ('eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'contains', 'in', 'exists'):
                for value in self.VALUES:
                    with self.subTest(field=field, op=op, value=repr(value)[:30]):
                        try:
                            qe.run(ROWS, {'field': field, 'op': op, 'value': value}, FIELDS)
                        except Exception as e:                       # noqa: BLE001
                            self.fail(f'{type(e).__name__}: {e}')

    def test_a_number_the_engine_cannot_hold_is_not_a_number(self):
        for text in ('1e999', '-1e999', 'nan', 'inf', '9' * 5000, '１２', '٣'):
            self.assertEqual(names('cpu_count', 'eq', text), [], text)
            self.assertEqual(names('cpu_count', 'gt', text), [], text)
            self.assertEqual(names('cpu_count', 'lt', text), [], text)

    def test_a_flag_is_not_a_number_and_a_number_is_not_a_flag(self):
        self.assertEqual(names('monitored', 'gt', 0), [], 'a flag has no magnitude, as before')
        self.assertEqual(names('cpu_count', 'eq', 'true'), [])
        self.assertEqual(names('cpu_count', 'eq', True), [], 'a number cell does not equal a flag value')

    def test_an_in_that_is_not_a_list_finds_nothing(self):
        for value in ('8', 8, None, {'a': 8}, True):
            self.assertEqual(names('cpu_count', 'in', value), [], repr(value))

    def test_exists_is_as_it_was(self):
        self.assertEqual([r['name'] for r in qe.run(ROWS, {'field': 'cpu_count', 'op': 'exists'}, FIELDS)], ['a', 'b'])
        self.assertEqual([r['name'] for r in qe.run(ROWS, {'field': 'memory_speed', 'op': 'exists'}, FIELDS)], ['a', 'b'])

    def test_a_predicate_still_needs_its_value(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'field': 'cpu_count', 'op': 'eq'}, FIELDS)


class TestTheNumberAWordIsWrittenAs(unittest.TestCase):
    """The text a number is compared as: 2933 and 2933.0 are "2933", 1.5 is "1.5", and nothing is written in an exponent that a person would not have typed."""

    def test_whole_floats_have_no_point_and_the_rest_keep_theirs(self):
        text = qe._number_text
        self.assertEqual((text(2933), text(2933.0), text(-7), text(1.5), text(0.1), text(0)), ('2933', '2933', '-7', '1.5', '0.1', '0'))
        self.assertEqual(text(123456789012345.0), '123456789012345')
        self.assertEqual(text(1e15), repr(1e15), 'from 1e15 up a float is written as Python writes it')


if __name__ == '__main__':
    unittest.main()
