#!/usr/bin/env python3
"""Copy the app catalog of the server (server/cgi-bin/app_catalog.py) into the Linux agent (8.0.0).

The agent recognises the apps its host runs with the same catalog and the same matcher the server uses on what an older agent reported, so that the two cannot
disagree about what counts as Jellyfin. The agent is a single file with no imports from the server, so the code is copied. It is not copied by hand: this writes the
block between the two marker lines of the agent, and `--check` (which tests/test_v800_app_discovery.py runs) fails when the agent's block is not what this would write.

What is copied is the part of the module between its two marker lines ("shared with the Linux agent from the next line on" and "end of what the agent shares"). Every name
that part defines is prefixed with `_ac_` (`discover` is `_ac_discover`, `_repo` is `_ac_repo`, `APPS` is `_ac_APPS`), so nothing of it can be mistaken for the agent's own.
Nothing is rewritten otherwise.

    python3 tools/sync-app-catalog.py           write the block
    python3 tools/sync-app-catalog.py --check   exit 1 when the block is out of date
"""
import ast
import io
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'server' / 'cgi-bin' / 'app_catalog.py'
BEGIN = '# BEGIN app_catalog: generated from server/cgi-bin/app_catalog.py by tools/sync-app-catalog.py, do not edit by hand'
END = '# END app_catalog'
FROM = '# ── shared with the Linux agent from the next line on'
UNTIL = '# ── end of what the agent shares'
TARGET = ROOT / 'client' / 'remotepower-agent.py'
ANCHOR = 'def get_containers():'


def _defined_names(src):
    names = set()
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def _new(name):
    return '_ac_' + name.lstrip('_')


def render():
    """The text of the block, markers included."""
    src = SOURCE.read_text()
    body = src[src.index('\n', src.index(FROM)) + 1: src.index(UNTIL)]
    names = _defined_names(body)
    starts = [0]
    for line in body.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    edits, prev = [], None
    for tok in tokenize.generate_tokens(io.StringIO(body).readline):
        if tok.type == tokenize.NAME and tok.string in names and not (prev is not None and prev.type == tokenize.OP and prev.string == '.'):
            edits.append((starts[tok.start[0] - 1] + tok.start[1], starts[tok.end[0] - 1] + tok.end[1], _new(tok.string)))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev = tok
    for a, b, new in reversed(edits):
        body = body[:a] + new + body[b:]
    return '%s\n# the apps this host runs, recognised from its listening sockets, its containers and its services\n%s\n%s\n' % (BEGIN, body.strip('\n'), END)


def splice(source, block):
    """`source` with the block between its markers replaced, or put in front of the anchor when the markers are not there yet."""
    if BEGIN in source:
        start = source.index(BEGIN)
        end = source.index(END, start) + len(END) + 1
        return source[:start] + block + source[end:]
    assert source.count(ANCHOR) == 1, ANCHOR
    return source.replace(ANCHOR, block + '\n\n' + ANCHOR)


def main(argv):
    block = render()
    text = TARGET.read_text()
    new = splice(text, block)
    if '--check' in argv:
        if new != text:
            sys.stderr.write('out of date: %s (run tools/sync-app-catalog.py)\n' % TARGET.name)
            return 1
        return 0
    if new != text:
        TARGET.write_text(new)
    sys.stdout.write('updated: %s\n' % (TARGET.name if new != text else 'nothing, the block was current'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
