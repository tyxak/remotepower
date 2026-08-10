#!/usr/bin/env python3
"""Generate the ruff exemption list for api.py's runtime-bound handler names.

WHY THIS EXISTS
---------------
CLAUDE.md names `ruff check --select F821` as THE mechanical detector for the
project's first false-green class — the undefined name that killed the agent's
`apply_host_config` while every substring assertion in its test passed.

On the agent that detector works. On the server it had gone completely dead:

    $ ruff check --select F821 server/cgi-bin/api.py
    Found 238 errors.

Every one of those 238 is a false positive. api.py loads 30 `*_handlers.py`
bound modules and re-imports their exports into its own globals at runtime:

    for _tk_name in ('handle_tickets', '_ticket_sla', ...):
        globals()[_tk_name] = getattr(tickets_handlers_mod, _tk_name)

Static analysis cannot see that, so every call site of those 513 names reads as
undefined. A detector whose output is 100% noise is not a detector — nobody
reads it, and a REAL undefined name in the largest file in the project would sit
in that list unnoticed. (CLAUDE.md records the exemption as "~88 false
positives"; it had grown to 238 without anyone noticing, which is the point.)

This script extracts those names straight from the bind blocks — the same source
of truth the runtime uses — and writes them as a ruff `builtins` list, so the
F821 check on api.py reports only names that are genuinely undefined.

    python3 tools/gen_ruff_builtins.py            # rewrite the config
    python3 tools/gen_ruff_builtins.py --check    # exit 1 if it is stale

SCOPE NOTE: ruff's `builtins` is a global setting, not per-file, which is why
this lives in its own config applied ONLY to the api.py pass (see the Makefile
`lint` target). Exempting 513 names repo-wide would re-blind the check
everywhere else — the opposite of the goal.

tests/test_ruff_f821_gate.py fails if the committed config drifts from the live
bind lists, so a new carve cannot silently re-blind the check.
"""
import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / 'server' / 'cgi-bin' / 'api.py'
CONFIG = ROOT / 'tools' / 'ruff-api-builtins.toml'

HEADER = """\
# GENERATED — do not edit by hand. Rewrite with:
#     python3 tools/gen_ruff_builtins.py
#
# The names api.py binds at runtime from its 30 *_handlers.py bound modules.
# Declaring them as builtins is what lets `ruff check --select F821` report a
# REAL undefined name in api.py instead of 238 false positives. Applied ONLY to
# the api.py pass (ruff's `builtins` is global, not per-file) — see the Makefile
# `lint` target and tools/gen_ruff_builtins.py for the full rationale.
#
# tests/test_ruff_f821_gate.py pins this list == the live bind lists.
"""


def bound_names(api_src):
    """Every name api.py re-imports from a bound handler module.

    Matches the loader idiom exactly:

        for _xx_name in ('a', 'b', ...):
            globals()[_xx_name] = getattr(xx_handlers_mod, _xx_name)

    Reads the bind blocks rather than the handler modules' own top-level defs:
    the tuple in api.py is what actually lands in api's globals, so a name a
    module defines but api.py does not list is genuinely undefined here and
    SHOULD keep failing F821.
    """
    names = set()
    for node in ast.walk(ast.parse(api_src)):
        if not isinstance(node, ast.For) or not isinstance(node.iter, (ast.Tuple, ast.List)):
            continue
        dumped = ast.dump(node)
        if 'globals' not in dumped or 'getattr' not in dumped:
            continue
        names.update(
            el.value for el in node.iter.elts
            if isinstance(el, ast.Constant) and isinstance(el.value, str)
        )
    return names


def render(names):
    body = '\n'.join(f'    "{n}",' for n in sorted(names))
    return f'{HEADER}\nbuiltins = [\n{body}\n]\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--check', action='store_true',
                    help='exit 1 if the committed config is stale (no rewrite)')
    args = ap.parse_args()

    names = bound_names(API.read_text())
    if not names:
        sys.exit('error: found no bind blocks in api.py — has the loader idiom changed?')
    rendered = render(names)

    if args.check:
        current = CONFIG.read_text() if CONFIG.exists() else ''
        if current != rendered:
            sys.exit(f'{CONFIG.relative_to(ROOT)} is STALE — run: '
                     f'python3 tools/gen_ruff_builtins.py')
        print(f'{CONFIG.relative_to(ROOT)} is current ({len(names)} bound names)')
        return

    CONFIG.write_text(rendered)
    print(f'wrote {CONFIG.relative_to(ROOT)} ({len(names)} bound names '
          f'from {API.relative_to(ROOT)})')


if __name__ == '__main__':
    main()
