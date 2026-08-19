#!/usr/bin/env python3
"""`(body.get('x') or [])[:50]` turns a malformed request into a 500.

Slicing a dict raises KeyError — a slice object is just a key the dict does not
have. The idiom is used ~66 times across the server and is fine on stored data
whose shape the product controls; on a REQUEST field it is not, because a JSON
body can hold any type. Five sites read a caller-supplied list that way.

Strings are the quieter half: `"abc"[:50]` succeeds and yields a list of
characters downstream, so a string field would have been iterated per-character
instead of rejected. `sanitize.as_list` returns empty for anything that is not
a list, which makes both cases a 400-shaped empty rather than a 500 or a wrong
answer.

Found while fixing the RAG posture readers — the same slice on
`platform_health.wifi` would have taken down the whole corpus build for any
device still carrying the pre-v7.0.2 shape.

Worth recording how the population was measured, because the first attempt was
wrong: a "is there an isinstance nearby?" grep called four of the nine sites
guarded. They were — on the ELEMENT (`if not isinstance(a, dict): continue`),
which runs after the slice has already raised. The AST rule below asks the
question the bug actually turns on, and found them.
"""
import ast
import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
import sanitize  # noqa: E402


class TestTheHelper(unittest.TestCase):

    def test_a_dict_becomes_empty_instead_of_raising(self):
        self.assertEqual(sanitize.as_list({'a': 1}, 50), [])

    def test_a_string_becomes_empty_not_a_list_of_characters(self):
        self.assertEqual(sanitize.as_list('abc', 50), [])

    def test_an_int_and_none_become_empty(self):
        self.assertEqual(sanitize.as_list(7, 50), [])
        self.assertEqual(sanitize.as_list(None, 50), [])

    def test_a_real_list_is_passed_through_and_capped(self):
        """The control — a guard that emptied everything would pass the rest."""
        self.assertEqual(sanitize.as_list(['a', 'b'], 50), ['a', 'b'])
        self.assertEqual(sanitize.as_list(list(range(100)), 3), [0, 1, 2])
        self.assertEqual(sanitize.as_list(['a']), ['a'])

    def test_the_old_idiom_really_does_raise(self):
        """Stated as a fact, so the reason this file exists cannot quietly
        stop being true."""
        with self.assertRaises(KeyError):
            ({'a': 1} or [])[:50]


class TestNoRequestFieldIsSlicedRaw(unittest.TestCase):
    """AST, not grep: fires only on `(<root>.get(...) or [])[slice]` where the
    root is a request-body name. Stored-data reads keep the idiom — the shape
    there is the product's own, and the seeder gate covers it."""

    ROOTS = {'body', 'sel', 'selector', 'payload', 'req'}

    def _offenders(self, path):
        out = []

        class V(ast.NodeVisitor):
            def visit_Subscript(inner, node):
                inner.generic_visit(node)
                if not isinstance(node.slice, ast.Slice):
                    return
                v = node.value
                if not (isinstance(v, ast.BoolOp) and isinstance(v.op, ast.Or)
                        and isinstance(v.values[-1], ast.List)
                        and not v.values[-1].elts):
                    return
                call = v.values[0]
                if not (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == 'get'
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id in self.ROOTS):
                    return
                out.append(f'{path.name}:{node.lineno}: {ast.unparse(node)[:80]}')
        V().visit(ast.parse(path.read_text()))
        return out

    def test_the_scanner_finds_the_shape_it_looks_for(self):
        """A positive control. Without it a broken visitor reports zero
        offenders and reads as a clean codebase."""
        import tempfile
        p = pathlib.Path(tempfile.mkdtemp()) / 'x.py'
        p.write_text("out = [i for i in (body.get('ids') or [])[:500]]\n")
        self.assertEqual(len(self._offenders(p)), 1)

    def test_no_offenders_remain(self):
        bad = []
        for f in sorted(_CGI.glob('*.py')):
            bad += self._offenders(f)
        self.assertEqual(bad, [], 'use sanitize.as_list(x, N) — slicing a '
                                  'request field raises KeyError on a dict:\n  '
                         + '\n  '.join(bad))


class TestTheFixedSitesUseIt(unittest.TestCase):

    def test_each_one_calls_as_list(self):
        for rel, needle in (
                ('api.py', "as_list(sel.get('ids'), 500)"),
                ('cve_handlers.py', "A.as_list(body.get('cve_ids'), 500)"),
                ('tickets_handlers.py',
                 "A.as_list(body.get('affected_devices'), 50)"),
                ('provisioning_handlers.py',
                 "A.as_list(selector.get('ids'), 500)"),
                ('provisioning_handlers.py',
                 "A.as_list(sel.get('ids'), 500)")):
            self.assertIn(needle, (_CGI / rel).read_text(), rel)


class TestTheRagWifiSliceIsGuarded(unittest.TestCase):
    """The site that found the class. A device still carrying the pre-v7.0.2
    wifi dict must skip one line, not take the corpus build down."""

    def test_a_legacy_dict_does_not_raise(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rag_slice', _CGI / 'rag_index.py')
        rag = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rag)
        docs = rag.build_live_state_corpus(
            [{'id': 'd1', 'name': 'web01', 'sysinfo': {'platform_health': {
                'wifi': {'ssid': 'lab', 'signal_dbm': -55}}}}],
            {}, now=1_700_000_000)
        self.assertIsInstance(docs, list)


if __name__ == '__main__':
    unittest.main()
