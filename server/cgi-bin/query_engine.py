"""RemotePower ad-hoc fleet query engine (v6.1.1).

A small, WHITELISTED predicate tree over registered entities -- NOT a raw-SQL passthrough. A raw-SQL surface would be a direct RLS-bypass
risk: a query issued outside the normal per-request tenant-scoped connection
(see storage_pg.set_request_tenant / api._rls_narrow) could read across
tenants. Every entity's rows are instead fetched through the SAME
load()-backed path every other handler uses, so whatever RBAC/tenancy
scoping already applies to that data stays applied here (see the per-entity
loaders in api.py, e.g. _qe_devices_rows).

Predicate node shapes:
    {"field": "cpu_pct", "op": "gt", "value": 80}
    {"and": [<node>, <node>, ...]}
    {"or":  [<node>, <node>, ...]}
    {"not": <node>}

Ops: eq, ne, gt, gte, lt, lte, contains (case-insensitive substring),
in (value is a list), exists (field is present and not None/empty string).

A value is read against the cell it meets, because the kind of a cell is known where the row is and the kind of a value is not known where it is typed (the Data Explorer
page sends the text of a box as it is). A text cell and a number are compared as text (`contains 7302` finds "AMD EPYC 7302", `eq 2933` finds "2933"); a number cell and text that
is only a decimal number are compared as numbers (`eq "8"`, `gt "10"`); a flag cell and the words true and false are compared as the flag. Anything else still finds nothing: a
word against a number cell, a number against a flag, and a text cell is never read as a number.

See docs/feature-buildout-scoping-internal.md #2 for the design rationale
(why a predicate tree instead of SQL, why load()-backed instead of a second
SQL-pushdown execution path for v1).
"""

import math
import re

MAX_PREDICATE_DEPTH = 6
MAX_PREDICATE_NODES = 100

# Text that is only a decimal number, as a person types one: ASCII digits, an optional sign, a point and an exponent. Not "nan", "inf", "0x10", "1_000" or a digit of another script
# (float() reads some of those), and not longer than a number a person types.
_DECIMAL = re.compile(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?')
_WHOLE = re.compile(r'[+-]?[0-9]{1,18}')
_MAX_NUMBER_TEXT = 64


def _num(v):
    """A number cell: a number that is not a flag (a boolean is an int in Python, and a flag has no magnitude)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    return None


def _typed_number(v):
    """The number a value stands for: a number, or text that is only a decimal number. None for anything else, and for a number the engine cannot hold (an exponent that overflows)."""
    n = _num(v)
    if n is not None:
        return n
    if not isinstance(v, str) or len(v) > _MAX_NUMBER_TEXT:
        return None
    t = v.strip()
    if _WHOLE.fullmatch(t):
        return int(t)
    if not _DECIMAL.fullmatch(t):
        return None
    try:
        f = float(t)
    except (ValueError, OverflowError):
        return None
    return f if math.isfinite(f) else None


def _number_text(n):
    """The text of a number as a person would have typed it: 2933 and 2933.0 are "2933", 1.5 is "1.5"."""
    if isinstance(n, float) and math.isfinite(n) and n == int(n) and abs(n) < 1e15:
        return str(int(n))
    return str(n) if isinstance(n, int) else repr(n)


def _flag(word):
    """True or False for the words true and false in any case, None for any other text."""
    if not isinstance(word, str):
        return None
    return {'true': True, 'false': False}.get(word.strip().lower())


def _same(a, b):
    """Whether a cell equals a value: the same thing, or the same thing written two ways (see the note at the top)."""
    if a == b:
        return True
    if isinstance(a, bool):
        return _flag(b) is a
    if isinstance(a, str):
        return _num(b) is not None and a == _number_text(b)
    na = _num(a)
    if na is not None:
        nb = _typed_number(b) if isinstance(b, str) else None
        return nb is not None and na == nb
    return False


def _contains(a, b):
    """Case-insensitive substring of a text cell. The value is text, or a number read as its text; a number cell is not searched."""
    if not isinstance(a, str):
        return False
    needle = b if isinstance(b, str) else (_number_text(b) if _num(b) is not None else None)
    return needle is not None and needle.lower() in a.lower()


def _cmp(a, b, op):
    na, nb = _num(a), _typed_number(b)
    if na is None or nb is None:
        return False
    return op(na, nb)


_OPS = {
    'eq':  _same,
    'ne':  lambda a, b: not _same(a, b),
    'gt':  lambda a, b: _cmp(a, b, lambda x, y: x > y),
    'gte': lambda a, b: _cmp(a, b, lambda x, y: x >= y),
    'lt':  lambda a, b: _cmp(a, b, lambda x, y: x < y),
    'lte': lambda a, b: _cmp(a, b, lambda x, y: x <= y),
    'contains': _contains,
    'in':  lambda a, b: isinstance(b, list) and any(_same(a, x) for x in b),
    'exists': lambda a, b: a is not None and a != '',
}


class QueryError(Exception):
    """A malformed predicate / unknown field / unknown op — always a 400 to
    the caller, never a 500 (see api.handle_query)."""


def validate_predicate(node, fields, depth=0, count=None):
    """Raise QueryError if `node` isn't a well-formed predicate over `fields`
    (the entity's {name: extractor} allowlist — see api._QE_ENTITIES).
    `count` is a mutable [int] node counter shared across the recursion so
    the TOTAL predicate size is capped, not just nesting depth (a wide,
    shallow predicate with 10,000 leaf conditions is as much a cost risk as
    a deep one)."""
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_PREDICATE_NODES:
        raise QueryError(f'predicate has more than {MAX_PREDICATE_NODES} nodes')
    if depth > MAX_PREDICATE_DEPTH:
        raise QueryError(f'predicate nested deeper than {MAX_PREDICATE_DEPTH}')
    if not isinstance(node, dict):
        raise QueryError('predicate node must be an object')
    if 'and' in node or 'or' in node:
        key = 'and' if 'and' in node else 'or'
        kids = node[key]
        if not isinstance(kids, list) or not kids:
            raise QueryError(f'"{key}" must be a non-empty list of predicate nodes')
        for k in kids:
            validate_predicate(k, fields, depth + 1, count)
        return
    if 'not' in node:
        validate_predicate(node['not'], fields, depth + 1, count)
        return
    field = node.get('field')
    op = node.get('op')
    if field not in fields:
        raise QueryError(f'unknown field: {field!r}')
    if op not in _OPS:
        raise QueryError(f'unknown op: {op!r} (choose from {sorted(_OPS)})')
    if op != 'exists' and 'value' not in node:
        raise QueryError(f'op {op!r} requires a "value"')


def _eval(node, row, fields):
    if 'and' in node:
        return all(_eval(k, row, fields) for k in node['and'])
    if 'or' in node:
        return any(_eval(k, row, fields) for k in node['or'])
    if 'not' in node:
        return not _eval(node['not'], row, fields)
    extractor = fields[node['field']]
    return _OPS[node['op']](extractor(row), node.get('value'))


def run(rows, predicate, fields):
    """Filter `rows` (list of entity dicts) by `predicate`, evaluated via the
    per-field extractor functions in `fields`. Assumes
    validate_predicate(predicate, fields) already passed — this does not
    re-validate, so a malformed predicate here is a programming error, not a
    user-input path (api.handle_query validates before calling this)."""
    return [r for r in rows if _eval(predicate, r, fields)]
