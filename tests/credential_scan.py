#!/usr/bin/env python3
"""The syntax-tree scans the credential ratchets share.

A ratchet over "every place that hands out access" is only as good as its list of places, so the list is read from the source and not
kept by hand: a function that starts to write one of the stores, or to set a user's password hash or role, is in the population the
moment it is written. A name in a comment or a docstring is not a call, which is why the scans read the tree.
"""
import ast
import functools
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_WRITERS = ('_LockedUpdate', 'save', 'locked_update', '_locked_update')


def _name(node):
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def _mentions(node, wanted):
    return any(_name(n) == wanted for n in ast.walk(node))


@functools.lru_cache(maxsize=8)
def _functions_of(cgi, signature):
    """Every function of api.py and of the other modules of the directory, parsed once per state of the files: a test that reads the tree
    several times pays for the parse once, and a changed file (the signature is the modification time and size of each) is read again."""
    found = []
    for path in [cgi / 'api.py'] + sorted(p for p in cgi.glob('*.py') if p.name != 'api.py'):
        for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append((path, fn))
    return tuple(found)


def functions():
    """(path, function node) for every function of api.py and of the other modules of server/cgi-bin."""
    cgi = Path(CGI)
    signature = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in sorted(cgi.glob('*.py')))
    return iter(_functions_of(cgi, signature))


def calls_of(fn):
    return {_name(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)} - {None}


def writes_store(fn, store):
    """Whether the function writes the store: `with _LockedUpdate(STORE)`, `save(STORE, ...)` or the lower-case form of the first."""
    return any(isinstance(n, ast.Call) and _name(n.func) in _WRITERS and any(_mentions(a, store) for a in n.args) for n in ast.walk(fn))


def store_writers(*stores):
    """{function name: calls it makes} for every function that writes one of the stores."""
    found = {}
    for _path, fn in functions():
        if any(writes_store(fn, s) for s in stores):
            found[fn.name] = calls_of(fn)
    return found


def bare_saves(store):
    """The functions that write the store with a bare `save(STORE, ...)`: a read, a change and a write with no lock held across the three,
    which loses what another request wrote in between."""
    return sorted({fn.name for _path, fn in functions()
                   if any(isinstance(n, ast.Call) and _name(n.func) == 'save' and any(_mentions(a, store) for a in n.args) for n in ast.walk(fn))})


def users_store_writers_of_credentials():
    """{function name: calls it makes} for every function that writes the users store and sets a user's password hash or role: a subscript
    store (`rec['role'] = ...`), a user record written out as a dict that holds a password hash, or a call of `_set_password`. A dict with
    a `role` key alone is not one (the sign-in answers with one)."""
    found = {}
    for path, fn in functions():
        if path.name == 'api.py' or path.name.endswith('_handlers.py'):
            if not writes_store(fn, 'USERS_FILE'):
                continue
            sets = '_set_password' in calls_of(fn)
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign):
                    sets = sets or any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                       and t.slice.value in ('role', 'password_hash') for t in n.targets)
                if isinstance(n, ast.Dict):
                    sets = sets or any(isinstance(k, ast.Constant) and k.value == 'password_hash' for k in n.keys)
            if sets:
                found[fn.name] = calls_of(fn)
    return found
