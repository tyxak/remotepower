#!/usr/bin/env python3
"""Fixtures for the tests of what the stores keep, who may read it and what leaves the box.

A test module that uses this sets RP_DATA_DIR before it imports anything (the data directory of the whole suite may be the one it gets), then:

    os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-x-'))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import stores_support as S
    setUpModule, tearDownModule = S.set_up_module, S.tear_down_module

`set_up_module` moves every store of api.py (and DATA_DIR itself) into a directory of the module's own, so the module cannot read or write what another module left, and
`tear_down_module` puts everything back and removes the directory (it is on tmpfs). The routes are the real ones: the WSGI application, a real sign-in, the real session store.
Stores are written through `api.save`, never as files, so the SQL backends see them.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-stores-support-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import wsgi  # noqa: E402  (imports api)

api = wsgi.api
ROOT_PW = 'Root-Passw0rd!x1'
_STATE = {}


def set_up_module():
    data_dir = api.DATA_DIR
    moved = {n: v for n, v in vars(api).items() if n.isupper() and isinstance(v, Path) and v.parent == data_dir}
    tmp = Path(tempfile.mkdtemp(prefix='rp-stores-run-'))
    for n, v in moved.items():
        setattr(api, n, tmp / v.name)
    api.DATA_DIR = tmp
    saved = {n: getattr(api, n) for n in ('_run_detached', '_ip_ratelimit', 'hash_password', '_external_scheduler_active')}
    api._run_detached = lambda *a, **k: None
    api._external_scheduler_active = lambda: True               # the sweeps of main() are not what these tests look at, and they cost most of a request
    api._ip_ratelimit = lambda *a, **k: True                     # twenty sign-ins a minute is for people; these are tests
    if api._BCRYPT:
        import bcrypt
        api.hash_password = lambda plain: bcrypt.hashpw(plain.encode(), bcrypt.gensalt(4)).decode()      # the scheme as it is, at the lowest cost
    _STATE.update(tmp=tmp, moved=moved, data_dir=data_dir, saved=saved)


def tear_down_module():
    if not _STATE:
        return
    try:
        import storage
        storage.close_connection()
    except Exception:
        pass
    for n, v in _STATE['moved'].items():
        setattr(api, n, v)
    api.DATA_DIR = _STATE['data_dir']
    for n, v in _STATE['saved'].items():
        setattr(api, n, v)
    api._LOAD_CACHE.clear()
    api._RCTX.environ = None
    shutil.rmtree(_STATE['tmp'], ignore_errors=True)
    _STATE.clear()


def environ(method, path, body=b'', headers=None, query='', remote='127.0.0.1'):
    env = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': query, 'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
           'SERVER_PROTOCOL': 'HTTP/1.1', 'REMOTE_ADDR': remote, 'wsgi.input': io.BytesIO(body), 'wsgi.errors': io.BytesIO(),
           'wsgi.version': (1, 0), 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False,
           'wsgi.run_once': False}
    if body:
        env['CONTENT_LENGTH'] = str(len(body))
        env['CONTENT_TYPE'] = 'application/json'
    for k, v in (headers or {}).items():
        env['HTTP_' + k.upper().replace('-', '_')] = v
    return env


def call(verb, path, body=None, token=None, raw=False, query='', headers=None):
    """One request through the WSGI application: (status, parsed body), or (status, bytes) with raw=True."""
    payload = json.dumps(body).encode() if body is not None else b''
    h = dict(headers or {})
    if token:
        h['X-Token'] = token
    cap = {}

    def start(status, hdrs):
        cap['status'] = int(status.split()[0])
        cap['headers'] = hdrs

    out = b''.join(wsgi.application(environ(verb, path, payload, h, query=query), start))
    api._LOAD_CACHE.clear()
    if raw:
        return cap['status'], out
    try:
        return cap['status'], (json.loads(out) if out else None)
    except ValueError:
        return cap['status'], out


class Case(unittest.TestCase):
    """A fresh set of stores for each test, an administrator signed in as `self.admin`."""

    STORES = ('USERS_FILE', 'TOKENS_FILE', 'CONFIG_FILE', 'AUDIT_LOG_FILE', 'RATELIMIT_FILE', 'TENANTS_FILE', 'DEVICES_FILE', 'APIKEYS_FILE', 'ROLES_FILE',
              'CMDS_FILE', 'CONFIG_REVS_FILE', 'WEBHOOK_DLQ_FILE', 'WEBHOOK_LOG_FILE')

    def setUp(self):
        for n in self.STORES:
            f = getattr(api, n, None)
            if f is not None:
                api.save(f, {})
        api.save(api.CONFIG_FILE, {'backup': {'enabled': False}})
        api._LOAD_CACHE.clear()
        self.now = int(time.time())
        self.add_user('root', 'admin', ROOT_PW)
        self.admin = self.sign_in('root', ROOT_PW)

    def add_user(self, name, role, password, **extra):
        rec = {'password_hash': api.hash_password(password), 'role': role, 'created': self.now, 'password_changed_at': self.now, 'tenant_id': 'default'}
        rec.update(extra)
        users = api.load(api.USERS_FILE) or {}
        users[name] = rec
        api.save(api.USERS_FILE, users)
        api._LOAD_CACHE.clear()

    def sign_in(self, name, password):
        st, d = call('POST', '/api/login', {'username': name, 'password': password})
        self.assertEqual(st, 200, d)
        self.assertTrue(isinstance(d, dict) and d.get('ok'), (name, d))
        return d['token']

    def seed_device(self, dev_id, **extra):
        devs = api.load(api.DEVICES_FILE) or {}
        d = {'name': dev_id, 'os': 'Linux', 'last_seen': int(time.time()), 'enrolled': int(time.time()), 'token_hash': 'x' * 64, 'group': '', 'tags': [],
             'sysinfo': {}, 'version': '8.0.2'}
        d.update(extra)
        devs[dev_id] = d
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        return d

    def set_cfg(self, **kw):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update(kw)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()


def timed(fn, *a, **k):
    t0 = time.time()
    out = fn(*a, **k)
    return out, time.time() - t0
