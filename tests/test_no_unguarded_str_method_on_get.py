"""`(body.get('x') or '').strip()` is a 500 waiting for a non-string.

`_read_valid` hands the handler the ORIGINAL body, not the pydantic model's
coerced copy (the model is an additive pre-check by design), so a client that
sends `{"name": 5}` or `{"url": ["a"]}` reaches the handler's own extraction. The
idiom `(value.get('k') or '').strip()` only copes with a string: for an int, list
or dict it raises AttributeError, the dispatcher answers `500 Internal server
error`, and the real fault is a client one.

Found by sending every route a body whose every key holds an integer: POST
/api/roles, /api/webhook/test and /api/proxmox/snapshot answered 500. A
mechanical pass then wrapped 234 such calls across 28 modules in `str(...)`,
which is the same value for a string and a harmless one for anything else.

This holds the class at zero. The scan is AST-based, so a docstring or a comment
quoting the pattern does not count, and its control feeds it a snippet that has
to be flagged.
"""
import ast
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "split", "rsplit",
            "startswith", "endswith", "replace", "encode", "title", "casefold",
            "splitlines", "partition", "rpartition", "removeprefix", "removesuffix"}


def _is_get(n):
    return isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"


def offenders(src):
    """(line, snippet) for every str-method call whose receiver is `x.get(..) or ''`
    or `x.get(.., '')` with no str() around it."""
    out = []
    for n in ast.walk(ast.parse(src)):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in _METHODS):
            continue
        v = n.func.value
        bare = (isinstance(v, ast.BoolOp) and isinstance(v.op, ast.Or) and len(v.values) == 2
                and isinstance(v.values[1], ast.Constant) and v.values[1].value == ""
                and _is_get(v.values[0]))
        bare = bare or (_is_get(v) and len(v.args) == 2 and not v.keywords
                        and isinstance(v.args[1], ast.Constant) and v.args[1].value == "")
        if bare:
            out.append((n.lineno, ast.unparse(n)[:80]))
    return out


class TestNoUnguardedStrMethodOnGet(unittest.TestCase):
    def test_the_scan_sees_the_pattern(self):
        snippet = ("def f(body):\n"
                   "    a = (body.get('a') or '').strip()\n"
                   "    b = body.get('b', '').lower()\n"
                   "    c = str(body.get('c') or '').strip()\n"
                   "    return a, b, c\n")
        self.assertEqual([ln for ln, _ in offenders(snippet)], [2, 3],
                         "the scan must flag the two bare forms and not the str()-wrapped one")

    def test_no_server_module_has_one(self):
        files = sorted(CGI.glob("*.py"))
        self.assertGreater(len(files), 80, "the module list is empty or truncated")
        found = {}
        for p in files:
            hits = offenders(p.read_text())
            if hits:
                found[p.name] = hits
        self.assertEqual(
            found, {},
            "wrap the value in str(...): a request body is not trusted to hold a string:\n"
            + "\n".join(f"  {f}:{ln}  {s}" for f, hs in found.items() for ln, s in hs))


if __name__ == "__main__":
    unittest.main()
