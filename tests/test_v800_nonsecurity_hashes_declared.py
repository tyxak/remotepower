#!/usr/bin/env python3
"""8.0.0: every use of md5 or sha1 in the server says whether it is a security hash.

The server's own non-security uses (a cache key, a breach-corpus index, a log-line fingerprint, a short id) pass `usedforsecurity=False`, which says so to the reader, keeps CodeQL's weak-hash query quiet
and lets the call work on a Python built for FIPS, where an undeclared md5 raises. `image_autoupdate.fingerprint` was the one that did not, found by ruff's S324 during a pass over the security rules. The
only other uses are SNMPv3's, where HMAC-MD5-96 and HMAC-SHA-96 are the protocol's authentication and cannot be declared away (server/cgi-bin/snmp.py).

Read off the syntax tree of every server module: a reference to `hashlib.md5` or `hashlib.sha1` that is not a call with `usedforsecurity=False` must be in the one reviewed file.
"""
import ast
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
_PROTOCOL_MANDATED = {"snmp.py"}          # SNMPv3 USM authentication: the algorithms are the protocol's


def _undeclared(tree):
    """Line numbers of hashlib.md5 / hashlib.sha1 used without usedforsecurity=False, and the number of declared calls."""
    declared_calls, calls_of = set(), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("md5", "sha1") and ast.unparse(n.func.value) == "hashlib":
            calls_of.add(id(n.func))
            if any(k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant) and k.value.value is False for k in n.keywords):
                declared_calls.add(id(n.func))
    bad = []
    declared = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr in ("md5", "sha1") and ast.unparse(n.value) == "hashlib":
            if id(n) in declared_calls:
                declared += 1
            else:
                bad.append(n.lineno)
    return bad, declared


class TestNonSecurityHashesAreDeclared(unittest.TestCase):
    def test_every_use_outside_the_protocol_module_declares_itself(self):
        offenders, declared = [], 0
        for p in sorted(_CGI.glob("*.py")):
            bad, n = _undeclared(ast.parse(p.read_text(encoding="utf-8")))
            declared += n
            if bad and p.name not in _PROTOCOL_MANDATED:
                offenders += [f"{p.name}:{ln}" for ln in bad]
        # Control: the declared calls are what the rule protects; none found would mean the walk looks at nothing.
        self.assertGreaterEqual(declared, 5, f"only {declared} declared md5/sha1 calls found: the detector is broken")
        self.assertEqual(offenders, [], "md5 or sha1 without usedforsecurity=False (add it if the hash is not a security control): " + ", ".join(offenders))

    def test_the_protocol_module_is_still_the_only_exception(self):
        """A stale exemption would hide a future use: the file must still hold an undeclared use."""
        bad, _ = _undeclared(ast.parse((_CGI / "snmp.py").read_text(encoding="utf-8")))
        self.assertTrue(bad, "snmp.py no longer uses an undeclared md5/sha1: remove it from _PROTOCOL_MANDATED")

    def test_the_detector_tells_declared_from_undeclared(self):
        undeclared = ["import hashlib\nhashlib.sha1(b'x')\n", "import hashlib\nhashlib.md5(b'x', usedforsecurity=True)\n", "import hashlib\nTABLE = {'a': hashlib.md5}\n"]
        declared = ["import hashlib\nhashlib.sha1(b'x', usedforsecurity=False)\n", "import hashlib\nhashlib.sha256(b'x')\n"]
        for src in undeclared:
            with self.subTest(undeclared=src):
                self.assertTrue(_undeclared(ast.parse(src))[0])
        for src in declared:
            with self.subTest(declared=src):
                self.assertFalse(_undeclared(ast.parse(src))[0])


if __name__ == "__main__":
    unittest.main()
