#!/usr/bin/env python3
"""The real application in a process of its own, for tests of who may do what.

A test that stubs the token check or the role gate passes a handler that has no gate at all. `run()` starts a driver in a subprocess that
imports `wsgi` from server/cgi-bin on a data directory of its own and sends requests through Flask's test client, so the route table, the
gates that run before a handler, the token check (sessions in the token store, keys with a stored hash) and the handler are the ones a
client reaches. Only the password hashes of the seeded accounts are made at the lowest bcrypt cost, so that seeding is quick.

The driver is a piece of source that runs after `PRELUDE`, and it fills `out`, which `run()` returns (parsed from the last line the driver
prints). What the prelude sets up:

    accounts (password in PW[name], session token in SESS[name])
      admin   administrator of the default tenant (the operator of the installation)
      vera    viewer, default tenant            olga  custom role ops (patch, command; every host)
      rita    custom role ro-prod (no actions; hosts of the group prod)
      alice   administrator of the tenant acme  vic   viewer of acme          bob  administrator of the tenant globex
    hosts     web1 (group prod), db1 (group dev), acme1 (group prod, tenant acme)
    tenants   acme and globex, and `tenancy_enforced` on

and the helpers `put(attr, obj)`, `get(attr)`, `add_user(name, role, tenant=None)`, `session(name, stepped_up=False)`,
`add_key(secret, user, role='admin', scope=None, tenant='default', **extra)` and `call(method, path, token=None, body=None, headers=None)`,
which answers `[status, body]`.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'

PRELUDE = r'''
import hashlib, json, os, sys, time
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
client = wsgi.application.test_client()
now = int(time.time())
out = {}
PW, SESS = {}, {}


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


def get(attr):
    api._invalidate_load_cache(getattr(api, attr))
    return api.load(getattr(api, attr))


def _hash(pw):
    if api._BCRYPT:
        import bcrypt
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(4)).decode()
    return api.hash_password(pw)


def add_user(name, role, tenant=None):
    PW[name] = 'Start-%s-Passw0rd!1' % name
    rec = {'password_hash': _hash(PW[name]), 'created': now - 1000, 'role': role, 'password_changed_at': now - 1000}
    if tenant:
        rec['tenant_id'] = tenant
    users = get('USERS_FILE')
    users[name] = rec
    put('USERS_FILE', users)


def session(name, stepped_up=False):
    """A session of the account, as the sign-in leaves it (and, when asked, one that has just re-entered its password)."""
    raw = 'sess-%s-%s' % (name, hashlib.sha256(name.encode()).hexdigest()[:20])
    row = {'user': name, 'created': now, 'ttl': 86400, 'last_seen': now, 'ip': '198.51.100.1'}
    if stepped_up:
        row['step_up_at'] = now
    tokens = get('TOKENS_FILE')
    tokens[api._token_hash(raw)] = row
    put('TOKENS_FILE', tokens)
    SESS[name] = raw
    return raw


def add_key(secret, user, role='admin', scope=None, tenant='default', **extra):
    kid = hashlib.sha256(secret.encode()).hexdigest()[:16]
    rec = {'name': secret, 'key_hash': api._apikey_hash(secret), 'user': user, 'role': role, 'active': True, 'created': now,
           'rate_limit': 0, 'expires_at': None, 'tenant_id': tenant}
    if scope:
        rec['scope'] = scope
    rec.update(extra)
    keys = get('APIKEYS_FILE')
    keys[kid] = rec
    put('APIKEYS_FILE', keys)
    return kid


def call(method, path, token=None, body=None, headers=None, ip='203.0.113.5'):
    h = dict(headers or {})
    if token:
        h['X-Token'] = token
    kw = {}
    if body is not None:
        kw['data'] = json.dumps(body)
        h['Content-Type'] = 'application/json'
    api._LOAD_CACHE.clear()
    r = client.open(path, method=method, headers=h, environ_overrides={'REMOTE_ADDR': ip}, **kw)
    raw = r.get_data(as_text=True)
    try:
        js = json.loads(raw) if raw else None
    except ValueError:
        js = None
    return [r.status_code, js]


put('CONFIG_FILE', {'tenancy_enforced': True})
put('TENANTS_FILE', {'acme': {'name': 'Acme', 'status': 'active', 'created': 1}, 'globex': {'name': 'Globex', 'status': 'active', 'created': 1}})
put('ROLES_FILE', {'roles': [
    {'name': 'ops', 'permissions': ['patch', 'command'], 'scope': {'type': 'all'}},
    {'name': 'ro-all', 'permissions': [], 'scope': {'type': 'all'}},
    {'name': 'ro-prod', 'permissions': [], 'scope': {'type': 'groups', 'values': ['prod']}},
]})
put('USERS_FILE', {})
put('TOKENS_FILE', {})
put('APIKEYS_FILE', {})
for _n, _r, _t in (('admin', 'admin', None), ('vera', 'viewer', None), ('olga', 'ops', None), ('rita', 'ro-prod', None),
                   ('alice', 'admin', 'acme'), ('vic', 'viewer', 'acme'), ('bob', 'admin', 'globex')):
    add_user(_n, _r, _t)
    session(_n)
put('DEVICES_FILE', {
    'web1': {'name': 'web-one', 'hostname': 'web-one', 'group': 'prod', 'os': 'Debian 12', 'last_seen': now, 'monitored': True},
    'db1': {'name': 'db-one', 'hostname': 'db-one', 'group': 'dev', 'os': 'Debian 12', 'last_seen': now, 'monitored': True},
    'acme1': {'name': 'acme-one', 'hostname': 'acme-one', 'group': 'prod', 'os': 'Debian 12', 'last_seen': now, 'monitored': True,
              'tenant': 'acme'}})
api._LOAD_CACHE.clear()
'''

_EPILOGUE = '\nprint("\\n" + json.dumps(out))\n'


def run(driver, cgi=None, timeout=600):
    """Run `driver` after the prelude in a process of its own and return what it put in `out`."""
    work = Path(tempfile.mkdtemp(prefix='rp-realstack-'))
    try:
        data = work / 'data'
        data.mkdir()
        script = work / 'driver.py'
        script.write_text(PRELUDE + driver + _EPILOGUE, encoding='utf-8')
        # the storage backend of the gate that runs this (JSON, SQLite or Postgres) is the one the driver uses
        env = dict(os.environ, RP_DATA_DIR=str(data), PYTHONDONTWRITEBYTECODE='1')
        proc = subprocess.run([sys.executable, str(script), str(cgi or CGI)], capture_output=True, text=True, env=env, timeout=timeout)
        if proc.returncode != 0:
            raise AssertionError('the driver failed:\n' + proc.stderr[-2500:])
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(work, ignore_errors=True)
