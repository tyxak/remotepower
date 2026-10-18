"""The error messages the server sends, read from its source.

Shared by the tests that look at them: test_v740_server_message_census.py (one spelling, one status) and
test_v740_server_messages_i18n.py (translated, or listed as not yet). A message is the literal in
`respond(<status>, {'error': '<literal>'})`, in any server module. A message built with an f-string is
counted separately: the dictionary matches whole text nodes, so a message with a variable inside has no
entry to match.
"""
import ast
import functools
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
SKIP = {'storage.py', 'storage_pg.py'}          # store internals raise, they do not answer a request


def _respond_calls(source):
    for n in ast.walk(ast.parse(source)):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if (f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '')) != 'respond' or len(n.args) < 2:
            continue
        status, body = n.args[0], n.args[1]
        if not (isinstance(status, ast.Constant) and isinstance(status.value, int) and isinstance(body, ast.Dict)):
            continue
        for k, v in zip(body.keys, body.values):
            if isinstance(k, ast.Constant) and k.value == 'error':
                yield n.lineno, status.value, v


def sites_of(source, name='<source>'):
    """(file, line, status, message) for each respond(<int>, {'error': '<literal>'}) in `source`."""
    return [(name, line, status, v.value) for line, status, v in _respond_calls(source)
            if isinstance(v, ast.Constant) and isinstance(v.value, str)]


def fstring_sites_of(source, name='<source>'):
    """(file, line, status, template) for each respond(<int>, {'error': f'...'}); a variable reads as {}."""
    out = []
    for line, status, v in _respond_calls(source):
        if isinstance(v, ast.JoinedStr):
            parts = [x.value if isinstance(x, ast.Constant) else '{}' for x in v.values]
            out.append((name, line, status, ''.join(parts)))
    return out


def key_of(message):
    return message.strip().rstrip('.').lower()


def _modules():
    return [p for p in sorted(CGI.glob('*.py')) if p.name not in SKIP]


@functools.lru_cache(maxsize=None)
def _census():
    sites = []
    for p in _modules():
        sites += sites_of(p.read_text(encoding='utf-8'), p.name)
    return tuple(sites)


@functools.lru_cache(maxsize=None)
def _fstrings():
    sites = []
    for p in _modules():
        sites += fstring_sites_of(p.read_text(encoding='utf-8'), p.name)
    return tuple(sites)


def census():
    return list(_census())


def fstring_census():
    return list(_fstrings())
