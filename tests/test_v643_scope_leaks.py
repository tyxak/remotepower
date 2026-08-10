#!/usr/bin/env python3
"""Fleet-AGGREGATE endpoints must respect role scope and tenant isolation.

Three endpoints served the whole fleet to any authenticated session. None was
introduced by v6.4.3 — all three were live in production — and all three share
one shape: a handler that authenticates the caller and then never asks WHICH
DEVICES that caller may see.

    GET /api/metrics          per-device telemetry for every host, incl. names
    GET /api/schedule.ics     every tenant's jobs + maintenance windows
    GET /api/racks/{id}/elevation   another tenant's device ids and hostnames

CLAUDE.md already names this class: a tenant admin resolves to
`_caller_scope() == None`, so any gate shaped `if scope is not None:` passes
them, and an endpoint under a prefix other than /api/devices/<id>/ gets no
cover from `_enforce_device_scope`. `_scope_filter_devices` folds in BOTH role
scope and tenancy and no-ops for an unscoped admin on a single-tenant install,
which is why it is the right filter and why applying it is safe.

/api/metrics is the sharpest of the three, for a reason worth keeping: it
accepts EITHER a status token (a machine scrape, legitimately instance-wide)
OR a session. Its code carried a comment reasoning that scope filtering is
"wrong for a scrape — a metrics endpoint is not a logged-in operator with a
role scope". True of the scrape, false of the session branch the same endpoint
also serves. The sibling handle_prometheus_sd already drew that distinction.

Filtering ctx['devices'] alone is NOT sufficient there and the tests below
prove it: prometheus_export._dev_labels falls back to `name = dev_id`, so any
device-keyed store left unfiltered still emits `device="dev-x"` — the
identifier leaks with the hostname merely missing.
"""
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643scope-'))

_spec = importlib.util.spec_from_file_location('api_v643_scope', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

FOREIGN_NAME = 'globex-secret-payroll-01'
FOREIGN_ID = 'dev-globex'


def _seed():
    """Two tenants, one device each, tenancy ON."""
    now = int(time.time())
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg['tenancy_enforced'] = True
    api.save(api.CONFIG_FILE, cfg)
    api.save(api.TENANTS_FILE, {
        api.DEFAULT_TENANT: {'name': 'Primary', 'builtin': True, 'status': 'active'},
        'acme': {'name': 'Acme', 'status': 'active'},
        'globex': {'name': 'Globex', 'status': 'active'}})
    api.save(api.DEVICES_FILE, {
        'dev-acme': {'name': 'acme-db-01', 'tenant': 'acme', 'last_seen': now,
                     'monitored': True, 'sysinfo': {'mem_percent': 40}},
        FOREIGN_ID: {'name': FOREIGN_NAME, 'tenant': 'globex', 'last_seen': now,
                     'monitored': True, 'sysinfo': {'mem_percent': 91}}})
    return now


def _token(user, role, tenant, now):
    users = api.load(api.USERS_FILE) or {}
    users[user] = {'role': role, 'tenant_id': tenant,
                   'password_hash': api.hash_password('x')}
    api.save(api.USERS_FILE, users)
    tok = api.make_token()
    toks = api.load(api.TOKENS_FILE) or {}
    toks[api._token_hash(tok)] = {'user': user, 'role': role, 'created': now,
                                  'expires': now + 86400, 'last_seen': now}
    api.save(api.TOKENS_FILE, toks)
    return tok


def _capture(fn, environ):
    """Run a handler that writes to stdout, return what it wrote."""
    api._RCTX.environ = environ
    raw = io.BytesIO()
    buf = io.TextIOWrapper(raw, encoding='utf-8', write_through=True)
    old = sys.stdout
    sys.stdout = buf
    try:
        fn()
    except (SystemExit, api.HTTPError):
        pass
    finally:
        try:
            buf.flush()
        except Exception:
            pass
        sys.stdout = old
    return raw.getvalue().decode('utf-8', 'replace')


class TestFleetAggregatesRespectScope(unittest.TestCase):
    def setUp(self):
        self.now = _seed()

    def _env(self, tok, path, qs=''):
        return {'HTTP_X_TOKEN': tok, 'REQUEST_METHOD': 'GET', 'PATH_INFO': path,
                'QUERY_STRING': qs, 'REMOTE_ADDR': '127.0.0.1'}

    def test_metrics_hides_other_tenants_from_a_session(self):
        """The reported HIGH: a tenant VIEWER — the lowest-privilege role —
        received 11 series naming another tenant's host."""
        for role in ('viewer', 'admin'):
            with self.subTest(role=role):
                tok = _token(f'acme-{role}', role, 'acme', self.now)
                out = _capture(api.handle_prometheus_metrics,
                               self._env(tok, '/api/metrics'))
                self.assertIn('dev-acme', out, 'own device missing — over-filtered')
                self.assertNotIn(FOREIGN_ID, out)
                self.assertNotIn(FOREIGN_NAME, out)

    def test_metrics_status_token_scrape_is_still_instance_wide(self):
        """The other half of the contract. A machine scrape has no operator and
        must keep seeing everything, or this fix silently breaks monitoring."""
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['status_token'] = 'scrape-tok'
        api.save(api.CONFIG_FILE, cfg)
        out = _capture(api.handle_prometheus_metrics,
                       {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/api/metrics',
                        'QUERY_STRING': 'token=scrape-tok', 'REMOTE_ADDR': '127.0.0.1'})
        self.assertIn('dev-acme', out)
        self.assertIn(FOREIGN_ID, out, 'the scrape lost its instance-wide view')

    def test_metrics_leaks_no_id_even_without_a_name(self):
        """_dev_labels falls back to `name = dev_id`, so filtering only the
        device roster would still emit `device="dev-globex"`. Drop the foreign
        device's NAME and assert the id is still absent — this is the assertion
        that catches a half-fix."""
        devs = api.load(api.DEVICES_FILE)
        devs[FOREIGN_ID].pop('name', None)
        api.save(api.DEVICES_FILE, devs)
        tok = _token('acme-v2', 'viewer', 'acme', self.now)
        out = _capture(api.handle_prometheus_metrics, self._env(tok, '/api/metrics'))
        self.assertNotIn(FOREIGN_ID, out)

    def test_schedule_ics_hides_other_tenants(self):
        # NB: the real store shape — `run_at` + `command` for a job, ISO
        # start/end for a window. An invented shape renders NO events at all
        # and every assertion below passes vacuously, which is exactly what
        # happened on the first draft of this test.
        api.save(api.SCHEDULE_FILE, {'jobs': [
            {'id': 'j1', 'device_id': FOREIGN_ID, 'device_name': FOREIGN_NAME,
             'command': 'reboot', 'run_at': self.now + 3600, 'recurring': False},
            {'id': 'j2', 'device_id': 'dev-acme', 'device_name': 'acme-db-01',
             'command': 'reboot', 'run_at': self.now + 7200, 'recurring': False}]})
        api.save(api.MAINT_FILE, {'windows': [
            {'id': 'w1', 'scope': 'device', 'target': FOREIGN_ID,
             'reason': 'globex payroll migration',
             'start': '2026-09-01T00:00:00Z', 'end': '2026-09-01T04:00:00Z'}]})
        tok = _token('acme-ics', 'viewer', 'acme', self.now)
        out = _capture(api.handle_schedule_ics, self._env(tok, '/api/schedule.ics'))
        self.assertNotIn(FOREIGN_ID, out)
        self.assertNotIn(FOREIGN_NAME, out)
        self.assertNotIn('globex payroll migration', out)
        self.assertIn('acme-db-01', out, 'own job missing — over-filtered')

    def test_rack_elevation_hides_other_tenants(self):
        api.save(api.RACKS_FILE, {'rack1': {'name': 'R1', 'height_u': 42}})
        cmdb = api._cmdb_load() or {}
        cmdb['dev-acme'] = {'rack_id': 'rack1', 'rack_unit': 5, 'rack_height_u': 1}
        cmdb[FOREIGN_ID] = {'rack_id': 'rack1', 'rack_unit': 20, 'rack_height_u': 2}
        api.save(api.CMDB_FILE, cmdb)
        tok = _token('acme-rack', 'viewer', 'acme', self.now)
        api._RCTX.environ = self._env(tok, '/api/racks/rack1/elevation')
        try:
            api.handle_rack_elevation('rack1')
            body = None
        except api.HTTPError as e:
            body = e.body
        self.assertIsInstance(body, dict)
        ids = [a.get('device_id') for a in (body.get('assets') or [])]
        self.assertIn('dev-acme', ids)
        self.assertNotIn(FOREIGN_ID, ids)


class TestTheseTestsWouldHaveCaughtIt(unittest.TestCase):
    """A regression test for a leak is only worth having if it fails on the
    pre-fix code. These pin the CONTROL rather than re-asserting the fix: the
    filter must be reachable and must actually narrow."""

    def test_scope_filter_narrows_for_a_tenant_caller(self):
        now = _seed()
        tok = _token('acme-ctl', 'admin', 'acme', now)
        api._RCTX.environ = {'HTTP_X_TOKEN': tok, 'REQUEST_METHOD': 'GET',
                             'PATH_INFO': '/api/metrics', 'QUERY_STRING': '',
                             'REMOTE_ADDR': '127.0.0.1'}
        api.verify_token(tok)
        visible = set(api._scope_filter_devices(api.load(api.DEVICES_FILE) or {}))
        self.assertEqual(visible, {'dev-acme'},
                         'the filter itself is not narrowing — every assertion '
                         'above would pass vacuously')

    def test_the_metrics_ctx_accepts_a_visible_set(self):
        self.assertIn('visible', api._build_metrics_ctx.__code__.co_varnames)


if __name__ == '__main__':
    unittest.main()
