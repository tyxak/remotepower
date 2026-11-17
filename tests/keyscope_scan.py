"""The syntax-tree scan the key-scope ratchets share.

An API key can carry a device scope, and the scope confines even an administrator's key. A handler that reads hosts, or rows that
belong to hosts, has to answer over the hosts of the caller, which it does by calling a helper that folds the caller's scope
(`_confined_host_ids`, `_scope_filter_devices` or a helper built on them). A name in a comment or a docstring is not a call, so
the scan reads the syntax tree and not the text.
"""
import ast
import textwrap


def facts(src, reads=("DEVICES_FILE",), words=()):
    """(calls, reads_it): the names a function calls, and whether its body names one of `reads` (a store constant, as a name or as
    the attribute of `A.`) or holds one of `words` as a string constant (a key of a stored row, such as "members")."""
    calls, reads_it = set(), False
    for node in ast.walk(ast.parse(textwrap.dedent(src))):
        if isinstance(node, ast.Call):
            fn = node.func
            calls.add(fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "")
        if isinstance(node, ast.Name) and node.id in reads or isinstance(node, ast.Attribute) and node.attr in reads:
            reads_it = True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in words:
            reads_it = True
    return calls, reads_it


def unconfined(sources, aware, reads=("DEVICES_FILE",), words=()):
    """The names of the functions that read hosts (or a row of a host) and call none of the helpers in `aware`."""
    out = []
    for name, src in sorted(sources.items()):
        calls, reads_it = facts(src, reads, words)
        if reads_it and not calls & set(aware):
            out.append(name)
    return out
