#!/usr/bin/env python3
"""Plants and reads stores of a seeded data directory through the product's own storage layer, for the browser modules.

A browser module seeds a data directory with the demo seeder and then needs a few stores changed before the stack starts: a destination that is failing, a rule, the completed
patches of a few hosts. Writing the JSON file of a store by hand works on the JSON backend only. Under SQLite and Postgres a store is a table and the file is not what the server
reads, and `tests/test_no_raw_store_io_in_tests.py` holds the number of tests that do it at a ceiling. These go through `api.save`, `api.load` and `api._LockedUpdate` instead, by
the name of the store's constant in api.py (`'NOTIFY_HEALTH_FILE'`).

The work is done in a child process that imports api.py over that one directory, so the process of the test keeps its own api and its own data directory, and nothing it reads or
writes here is cached in it.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

_CHILD = r'''
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['RP_ROOT'], 'server', 'cgi-bin'))
import api
op, attr = sys.argv[1], sys.argv[2]
path = getattr(api, attr)
if op == 'load':
    sys.stdout.write(json.dumps(api.load(path)))
elif op == 'update':
    changes = json.loads(sys.stdin.read())
    with api._LockedUpdate(path) as store:
        store.update(changes)
else:
    api.save(path, json.loads(sys.stdin.read()))
'''


def _child(data_dir, op, attr, payload=None):
    env = dict(os.environ, RP_DATA_DIR=str(data_dir), RP_ROOT=str(_ROOT))
    env.pop('RP_STORAGE_BACKEND', None)         # the browser modules run on the JSON backend and skip on the others
    proc = subprocess.run([sys.executable, '-c', _CHILD, op, attr], input=None if payload is None else json.dumps(payload), capture_output=True, text=True, env=env,
                          cwd=str(_ROOT), timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f'e2e_plant {op} {attr} failed: {proc.stderr[-600:]}')
    return proc.stdout


def load(data_dir, attr):
    """The store `api.<attr>` of the data directory, as the server would read it."""
    return json.loads(_child(data_dir, 'load', attr))


def save(data_dir, attr, value):
    """Replace the store `api.<attr>` of the data directory."""
    _child(data_dir, 'save', attr, value)


def update(data_dir, attr, changes):
    """Set these top-level keys of the store `api.<attr>` and leave the others as they are, under the store's lock."""
    _child(data_dir, 'update', attr, changes)
