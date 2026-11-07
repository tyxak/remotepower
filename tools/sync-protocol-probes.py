#!/usr/bin/env python3
"""Copy the protocol probes of the server (server/cgi-bin/protocol_probes.py) into the Linux agent and the satellite (8.0.0).

A host's agent and a satellite run the smtp, imap, ssh and ntp monitors with the same code the server runs, so that a monitor gives the same
answer wherever it is probed from. Both clients are single files with no imports from the server, so the code is copied. It is not copied by
hand: this writes the block between the two marker lines of each client, and `--check` (which tests/test_v800_client_protocol_probes.py runs)
fails when a client's block is not what this would write.

The copy is the module's own text with two changes that keep it out of the client's namespace: every name the module defines is prefixed with
`_pp_` (`smtp_probe` is `_pp_smtp_probe`, `_clean` is `_pp_clean`), and the four modules it uses are imported under `_pp_` names
(`import socket as _pp_socket`). Nothing is rewritten otherwise.

    python3 tools/sync-protocol-probes.py           write the blocks
    python3 tools/sync-protocol-probes.py --check   exit 1 when a block is out of date
"""
import io
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'server' / 'cgi-bin' / 'protocol_probes.py'
BEGIN = '# BEGIN protocol_probes: generated from server/cgi-bin/protocol_probes.py by tools/sync-protocol-probes.py, do not edit by hand'
END = '# END protocol_probes'
MODULES = ('socket', 'ssl', 'struct', 'time')
# each client, and the line the block goes in front of the first time it is written
TARGETS = {
    ROOT / 'client' / 'remotepower-agent.py': 'def _probe_run_one(spec):',
    ROOT / 'client' / 'remotepower-satellite.py': 'def _probe_run_one(spec):',
}


def _defined_names(src):
    """The names the module defines at its top level: functions, classes and assignments."""
    import ast
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
    return '_pp_' + name.lstrip('_')


def render():
    """The text of the block, markers included."""
    src = SOURCE.read_text()
    names = _defined_names(src)
    body = src[src.index('DEFAULT_PORTS = '):]          # after the docstring and the imports
    starts = [0]
    for line in body.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    edits, prev = [], None
    for tok in tokenize.generate_tokens(io.StringIO(body).readline):
        if tok.type == tokenize.NAME and not (prev is not None and prev.type == tokenize.OP and prev.string == '.'):
            new = _new(tok.string) if tok.string in names else ('_pp_' + tok.string if tok.string in MODULES else None)
            if new:
                edits.append((starts[tok.start[0] - 1] + tok.start[1], starts[tok.end[0] - 1] + tok.end[1], new))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev = tok
    for a, b, new in reversed(edits):
        body = body[:a] + new + body[b:]
    header = ''.join('import %s as _pp_%s\n' % (m, m) for m in MODULES)
    return '%s\n# the probes run from this client: tcp, http and ping above, and the four below\n%s%s\n%s\n' % (BEGIN, header, body.rstrip('\n'), END)


def splice(source, block, anchor):
    """`source` with the block between its markers replaced, or put in front of `anchor` when the markers are not there yet."""
    if BEGIN in source:
        start = source.index(BEGIN)
        end = source.index(END, start) + len(END) + 1
        return source[:start] + block + source[end:]
    assert source.count(anchor) == 1, anchor
    return source.replace(anchor, block + '\n\n' + anchor)


def main(argv):
    block = render()
    stale = []
    for path, anchor in TARGETS.items():
        text = path.read_text()
        new = splice(text, block, anchor)
        if new != text:
            stale.append(path.name)
            if '--check' not in argv:
                path.write_text(new)
    if '--check' in argv:
        if stale:
            sys.stderr.write('out of date: %s (run tools/sync-protocol-probes.py)\n' % ', '.join(stale))
            return 1
        return 0
    sys.stdout.write('updated: %s\n' % (', '.join(stale) or 'nothing, the blocks were current'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
