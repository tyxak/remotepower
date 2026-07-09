"""RemotePower ad-hoc fleet query engine (v6.1.1).

A small, WHITELISTED predicate tree over registered entities -- deliberately
NOT a raw-SQL passthrough. A raw-SQL surface would be a direct RLS-bypass
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

See docs/feature-buildout-scoping-internal.md #2 for the design rationale
(why a predicate tree instead of SQL, why load()-backed instead of a second
SQL-pushdown execution path for v1).
"""

MAX_PREDICATE_DEPTH = 6
MAX_PREDICATE_NODES = 100


def _num(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    return None


def _cmp(a, b, op):
    na, nb = _num(a), _num(b)
    if na is None or nb is None:
        return False
    return op(na, nb)


_OPS = {
    'eq':  lambda a, b: a == b,
    'ne':  lambda a, b: a != b,
    'gt':  lambda a, b: _cmp(a, b, lambda x, y: x > y),
    'gte': lambda a, b: _cmp(a, b, lambda x, y: x >= y),
    'lt':  lambda a, b: _cmp(a, b, lambda x, y: x < y),
    'lte': lambda a, b: _cmp(a, b, lambda x, y: x <= y),
    'contains': lambda a, b: isinstance(a, str) and isinstance(b, str) and b.lower() in a.lower(),
    'in':  lambda a, b: isinstance(b, list) and a in b,
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
