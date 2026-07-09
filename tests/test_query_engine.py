"""v6.1.1 — ad-hoc fleet query engine, the pure predicate-tree module.

query_engine.py has zero I/O (mirrors integrations.py's "pure function,
unit-tested without the server" style) — these tests exercise the predicate
validator and evaluator directly, no api.py / storage involved.
"""
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import query_engine as qe  # noqa: E402

FIELDS = {
    'cpu': lambda r: r.get('cpu'),
    'name': lambda r: r.get('name'),
    'group': lambda r: r.get('group'),
    'tags': lambda r: r.get('tags'),
}

ROWS = [
    {'cpu': 95, 'name': 'web-1', 'group': 'prod', 'tags': ['edge']},
    {'cpu': 40, 'name': 'web-2', 'group': 'prod', 'tags': []},
    {'cpu': None, 'name': 'db-1', 'group': 'staging', 'tags': ['db']},
]


class TestValidatePredicate(unittest.TestCase):
    def test_leaf_ok(self):
        qe.validate_predicate({'field': 'cpu', 'op': 'gt', 'value': 50}, FIELDS)

    def test_and_or_not_ok(self):
        qe.validate_predicate({'and': [
            {'field': 'cpu', 'op': 'gt', 'value': 50},
            {'not': {'field': 'group', 'op': 'eq', 'value': 'staging'}},
        ]}, FIELDS)
        qe.validate_predicate({'or': [
            {'field': 'name', 'op': 'contains', 'value': 'web'},
            {'field': 'group', 'op': 'eq', 'value': 'staging'},
        ]}, FIELDS)

    def test_unknown_field_rejected(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'field': 'ssh_password', 'op': 'eq', 'value': 'x'}, FIELDS)

    def test_unknown_op_rejected(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'field': 'cpu', 'op': 'DROP TABLE', 'value': 1}, FIELDS)

    def test_missing_value_rejected_except_exists(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'field': 'cpu', 'op': 'gt'}, FIELDS)
        qe.validate_predicate({'field': 'cpu', 'op': 'exists'}, FIELDS)   # no value required

    def test_empty_and_or_rejected(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'and': []}, FIELDS)
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'or': []}, FIELDS)

    def test_non_dict_node_rejected(self):
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate('field=cpu', FIELDS)
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate({'and': ['not-a-node']}, FIELDS)

    def test_depth_cap(self):
        node = {'field': 'cpu', 'op': 'eq', 'value': 1}
        for _ in range(qe.MAX_PREDICATE_DEPTH + 2):
            node = {'not': node}
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate(node, FIELDS)

    def test_node_count_cap(self):
        node = {'and': [{'field': 'cpu', 'op': 'eq', 'value': i}
                        for i in range(qe.MAX_PREDICATE_NODES + 5)]}
        with self.assertRaises(qe.QueryError):
            qe.validate_predicate(node, FIELDS)


class TestRun(unittest.TestCase):
    def test_eq_ne(self):
        self.assertEqual(len(qe.run(ROWS, {'field': 'group', 'op': 'eq', 'value': 'prod'}, FIELDS)), 2)
        self.assertEqual(len(qe.run(ROWS, {'field': 'group', 'op': 'ne', 'value': 'prod'}, FIELDS)), 1)

    def test_numeric_ops_and_none_never_matches(self):
        gt = qe.run(ROWS, {'field': 'cpu', 'op': 'gt', 'value': 50}, FIELDS)
        self.assertEqual([r['name'] for r in gt], ['web-1'])
        # db-1's cpu is None -- must never satisfy a numeric comparison either way
        self.assertFalse(qe.run([ROWS[2]], {'field': 'cpu', 'op': 'gt', 'value': -1000}, FIELDS))
        self.assertFalse(qe.run([ROWS[2]], {'field': 'cpu', 'op': 'lt', 'value': 1000}, FIELDS))

    def test_contains_case_insensitive(self):
        r = qe.run(ROWS, {'field': 'name', 'op': 'contains', 'value': 'WEB'}, FIELDS)
        self.assertEqual({x['name'] for x in r}, {'web-1', 'web-2'})

    def test_in_op(self):
        r = qe.run(ROWS, {'field': 'group', 'op': 'in', 'value': ['prod', 'edge']}, FIELDS)
        self.assertEqual({x['name'] for x in r}, {'web-1', 'web-2'})

    def test_exists_op(self):
        r = qe.run(ROWS, {'field': 'cpu', 'op': 'exists'}, FIELDS)
        self.assertEqual({x['name'] for x in r}, {'web-1', 'web-2'})   # db-1's cpu is None

    def test_and_combinator(self):
        r = qe.run(ROWS, {'and': [
            {'field': 'group', 'op': 'eq', 'value': 'prod'},
            {'field': 'cpu', 'op': 'gt', 'value': 50},
        ]}, FIELDS)
        self.assertEqual([x['name'] for x in r], ['web-1'])

    def test_or_combinator(self):
        r = qe.run(ROWS, {'or': [
            {'field': 'group', 'op': 'eq', 'value': 'staging'},
            {'field': 'cpu', 'op': 'gt', 'value': 90},
        ]}, FIELDS)
        self.assertEqual({x['name'] for x in r}, {'web-1', 'db-1'})

    def test_not_combinator(self):
        r = qe.run(ROWS, {'not': {'field': 'group', 'op': 'eq', 'value': 'prod'}}, FIELDS)
        self.assertEqual([x['name'] for x in r], ['db-1'])

    def test_bool_excluded_from_numeric_ops(self):
        # bools are ints in Python (True == 1) -- a numeric op must not treat
        # a boolean field as satisfying a magnitude comparison.
        rows = [{'cpu': True}]
        fields = {'cpu': lambda r: r.get('cpu')}
        self.assertFalse(qe.run(rows, {'field': 'cpu', 'op': 'gt', 'value': 0}, fields))


if __name__ == '__main__':
    unittest.main()
