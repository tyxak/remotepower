#!/usr/bin/env python3
"""new-handler-module.py — scaffold a server/cgi-bin/<name>_handlers.py bound
module so a NEW handler subsystem lands in its own file by default, instead of
being appended to the api.py monolith (which then needs a periodic split as
housekeeping).

    tools/new-handler-module.py snmp "SNMP trap intake + polling cadence"

Writes server/cgi-bin/snmp_handlers.py with the _ApiNamespace/bind() boilerplate
(the same shape as dmarc_handlers/rack_ipam_handlers/tls_ct_handlers) and PRINTS
the exact wiring block to paste into api.py next to the other loaders (search for
`rack_ipam_handlers_mod.bind`). You then:

  1. write your handler functions in the new module (reach every api global as
     A.<name> — a dynamic lookup that keeps the suite's monkeypatching working);
  2. paste the printed wiring block into api.py and fill the name tuple;
  3. add routes to the route table / dispatcher as usual (they resolve to the
     re-imported names).

tests/apisrc.py auto-globs *_handlers.py, so source-pin tests need no change.
Constants stay in api.py (read via A.); pure logic goes in a sibling module
(imported directly, like dmarc_monitor / tls_monitor).

stdlib-only. Never touches git or api.py — it only writes the new file and
prints the paste-in block, so it is safe to re-run (refuses to clobber).
"""
import re
import sys
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'

TEMPLATE = '''"""RemotePower — {desc}

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {{name!r}}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ── handlers ─────────────────────────────────────────────────────────────────
# def handle_{name}_example():
#     """GET /api/{name}/example."""
#     A.require_auth()
#     A.respond(200, {{'ok': True}})
'''

WIRING = '''
# ── paste this next to the other *_handlers loaders in api.py ────────────────
# (search api.py for `rack_ipam_handlers_mod.bind` and add below it)

# {desc}
_{abbr}_spec = _tk_ilu.spec_from_file_location(
    '{name}_handlers', Path(__file__).parent / '{name}_handlers.py')
{name}_handlers_mod = _tk_ilu.module_from_spec(_{abbr}_spec)
_{abbr}_spec.loader.exec_module({name}_handlers_mod)
{name}_handlers_mod.bind(globals())
for _{abbr}_name in (
        # 'handle_{name}_example', '_{name}_helper', 'run_{name}_if_due', …
):
    globals()[_{abbr}_name] = getattr({name}_handlers_mod, _{abbr}_name)
del _{abbr}_name
'''


def main(argv):
    if len(argv) < 2 or argv[1] in ('-h', '--help'):
        print(__doc__)
        return 0
    name = argv[1].strip().lower()
    desc = (argv[2] if len(argv) > 2 else f'{name} handlers').strip()
    if not re.fullmatch(r'[a-z][a-z0-9_]*', name):
        print(f'error: module name {name!r} must be lower snake_case '
              '([a-z][a-z0-9_]*)', file=sys.stderr)
        return 2
    if name.endswith('_handlers'):
        name = name[:-len('_handlers')]
    dest = CGI / f'{name}_handlers.py'
    if dest.exists():
        print(f'error: {dest} already exists — refusing to clobber',
              file=sys.stderr)
        return 1
    # a short unique abbr for the loader locals (_dm_/_ri_ style): initials or
    # first two letters, kept simple.
    abbr = (name[0] + (name.split('_')[-1][0] if '_' in name else name[1:2])) or name[:2]
    dest.write_text(TEMPLATE.format(name=name, desc=desc))
    print(f'wrote {dest.relative_to(CGI.parent.parent)}')
    print(WIRING.format(name=name, desc=desc, abbr=abbr))
    print('Then: add routes, run the subsystem tests, and the FULL serial gate '
          '(both backends). tests/apisrc.py auto-includes the new module.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
