#!/usr/bin/env python3
"""8.0.0: every `A.<name>` a bound handler module uses is a name api.py defines.

A handler module reaches the rest of the server through `A`, a proxy whose lookup raises AttributeError for a name api.py does not have. Python does not check that when the
module loads, so a misspelt helper fails only when its branch runs, and ruff cannot see it (F821 reads names, not attributes of a proxy). The population is every handler module
that uses `A`, parsed by syntax tree; the control cases plant a bad name and see it.
"""

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-boundnames-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

CGI = _TESTS.parent / 'server' / 'cgi-bin'


def names_used(source):
    """The set of attribute names read from a name `A` anywhere in the source."""
    out = set()
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == 'A':
            out.add(n.attr)
    return out


def population():
    """{module file: names it reads from A} for every *_handlers.py that uses A at all."""
    return {p.name: names_used(p.read_text()) for p in sorted(CGI.glob('*_handlers.py')) if names_used(p.read_text())}


class TestTheScan(unittest.TestCase):

    def test_it_sees_a_name_that_is_not_there(self):
        self.assertEqual(names_used('def f():\n    return A._no_such_helper(1) + A.respond(2)\n'), {'_no_such_helper', 'respond'})
        self.assertEqual(names_used('def f(a):\n    return a.x.y\n'), set(), 'control: another name is not the proxy')

    def test_the_population_is_not_empty(self):
        pop = population()
        self.assertGreaterEqual(len(pop), 40, sorted(pop))
        self.assertGreaterEqual(sum(len(v) for v in pop.values()), 1000)
        self.assertIn('traffic_handlers.py', pop, 'control: a module added in 8.0.0')
        self.assertIn('respond', pop['traffic_handlers.py'])


class TestEveryNameResolves(unittest.TestCase):

    def test_each_name_is_defined_in_api(self):
        api_names = set(vars(_fresh_api()))
        pop = population()
        missing = {f: sorted(n for n in names if n not in api_names) for f, names in pop.items()}
        missing = {f: v for f, v in missing.items() if v}
        total = sum(len(v) for v in pop.values())
        self.assertEqual(missing, {}, '%d names in %d modules; these do not resolve: %s' % (total, len(pop), missing))


if __name__ == '__main__':
    unittest.main()
