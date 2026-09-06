#!/usr/bin/env python3
"""The CVE accepted-risk list reached across tenants in four directions.

`CVE_IGNORE_FILE` is keyed by vulnerability id alone and every handler was gated
on `require_admin_auth()`, which a TENANT admin passes. So a tenant admin could:

  * mark a finding accepted on another tenant's host — `scope` was validated for
    SHAPE (`_validate_id`) and never scope-blocked;
  * write `scope: "global"`, silencing that CVE on every tenant's hosts and
    overwriting whatever record another tenant had under the same key;
  * delete another tenant's accepted-risk record;
  * list every tenant's records, which carry device ids in `scope`.

Thirteen places carried their own copy of `scope in ('global', dev_id)`. That is
the whole rule with one tenant and not the whole rule with several, so the
predicate is now one shared function — `checks.cve_ignore_applies`, pure, with
the api.py wrapper resolving the device's tenant.

Records written before this release carry no tenant and keep their old meaning.
An upgrade that silently un-suppressed findings an operator had already accepted
would be a worse bug than the one being fixed, so that direction is asserted
too, along with the single-tenant install where none of this applies.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v703-cve-'))
for _k, _v in (('REQUEST_METHOD', 'POST'), ('PATH_INFO', '/'),
               ('CONTENT_LENGTH', '0')):
    os.environ.setdefault(_k, _v)
_spec = importlib.util.spec_from_file_location('api_v703_cve', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import checks


class TestThePurePredicate(unittest.TestCase):
    """No fixtures, no store — the rule itself."""

    def test_a_record_with_no_tenant_keeps_its_old_meaning(self):
        self.assertTrue(checks.cve_ignore_applies({'scope': 'global'}, 'd1'))
        self.assertTrue(checks.cve_ignore_applies({'scope': 'd1'}, 'd1'))
        self.assertFalse(checks.cve_ignore_applies({'scope': 'd2'}, 'd1'))

    def test_a_tenant_owned_record_stops_at_its_tenant(self):
        rec = {'scope': 'global', 'tenant': 't1'}
        self.assertTrue(checks.cve_ignore_applies(rec, 'd1', 't1'))
        self.assertFalse(checks.cve_ignore_applies(rec, 'd1', 't2'))

    def test_an_unknown_device_tenant_errs_toward_showing_the_finding(self):
        rec = {'scope': 'global', 'tenant': 't1'}
        self.assertFalse(checks.cve_ignore_applies(rec, 'd1', None))

    def test_a_malformed_record_suppresses_nothing(self):
        for junk in (None, 'x', 42, []):
            self.assertFalse(checks.cve_ignore_applies(junk, 'd1'))


class _HandlerCase(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-cve-case-'))
        self._saved = {}
        for name in ('CVE_IGNORE_FILE', 'DEVICES_FILE', 'CONFIG_FILE',
                     'TENANTS_FILE'):
            self._saved[name] = getattr(api, name)
            # The basename IS the storage key on SQLite/Postgres.
            setattr(api, name, self.tmp / Path(str(self._saved[name])).name)
        self._real = {n: getattr(api, n) for n in
                      ('_tenant_gate', '_caller_scope', 'require_admin_auth',
                       'require_auth', 'audit_log', 'method', '_read_valid',
                       'respond')}
        api._invalidate_load_cache(None)
        api.save(api.TENANTS_FILE, {'t1': {'id': 't1'}, 't2': {'id': 't2'}})
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api.save(api.DEVICES_FILE, {
            'devA': {'id': 'devA', 'name': 'a', 'tenant': 't1'},
            'devB': {'id': 'devB', 'name': 'b', 'tenant': 't2'}})
        api._invalidate_load_cache(None)
        self.gate = 't1'
        api._tenant_gate = lambda: self.gate
        api._caller_scope = lambda: None
        api.require_admin_auth = lambda *a, **k: 'admin1'
        api.require_auth = lambda **k: 'admin1'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)
        for name, value in self._real.items():
            setattr(api, name, value)
        api._invalidate_load_cache(None)

    def call(self, fn, *args, body=None):
        api._read_valid = lambda model: dict(body or {})
        cap = {}
        real = api.respond

        def fake(status, payload):
            cap['status'], cap['body'] = status, payload
            raise api.HTTPError(status, payload)

        api.respond = fake
        try:
            fn(*args)
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.respond = real
        return cap.get('status'), cap.get('body')

    def store(self):
        api._invalidate_load_cache(None)
        return api.load(api.CVE_IGNORE_FILE) or {}


class TestCrossTenantReachIsClosed(_HandlerCase):

    def test_cannot_accept_a_risk_on_another_tenants_host(self):
        status, _ = self.call(api.handle_cve_ignore_add,
                              body={'vuln_id': 'CVE-1', 'scope': 'devB'})
        self.assertEqual(status, 403)
        self.assertNotIn('CVE-1', self.store())

    def test_a_global_record_is_stamped_with_the_writers_tenant(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        self.assertEqual(self.store()['CVE-2'].get('tenant'), 't1')

    def test_a_global_record_does_not_suppress_on_another_tenants_host(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        rec = self.store()['CVE-2']
        self.assertTrue(api.cve_ignore_applies(rec, 'devA'))
        self.assertFalse(api.cve_ignore_applies(rec, 'devB'))

    def test_another_tenant_cannot_list_it(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        self.gate = 't2'
        api._invalidate_load_cache(None)
        api.method = lambda: 'GET'
        _status, body = self.call(api.handle_cve_ignore_list)
        self.assertEqual(body.get('ignores'), [])

    def test_another_tenant_cannot_delete_it_and_gets_a_404(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        self.gate = 't2'
        api._invalidate_load_cache(None)
        api.method = lambda: 'DELETE'
        status, _ = self.call(api.handle_cve_ignore_delete, 'CVE-2')
        self.assertEqual(status, 404, 'a 403 would confirm the record exists')
        self.assertIn('CVE-2', self.store())

    def test_cannot_overwrite_a_record_it_cannot_see(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        self.gate = 't2'
        api._invalidate_load_cache(None)
        status, _ = self.call(api.handle_cve_ignore_add,
                              body={'vuln_id': 'CVE-2', 'scope': 'global'})
        self.assertEqual(status, 404)
        self.assertEqual(self.store()['CVE-2'].get('tenant'), 't1')


class TestTheOrdinaryCasesStillWork(_HandlerCase):
    """The other direction. Refusing everything would pass the class above."""

    def test_a_tenant_admin_can_still_accept_a_risk_on_its_own_host(self):
        status, _ = self.call(api.handle_cve_ignore_add,
                              body={'vuln_id': 'CVE-3', 'scope': 'devA'})
        self.assertEqual(status, 200)
        self.assertEqual(self.store()['CVE-3']['scope'], 'devA')

    def test_its_own_global_record_still_suppresses_on_its_own_hosts(self):
        self.call(api.handle_cve_ignore_add,
                  body={'vuln_id': 'CVE-2', 'scope': 'global'})
        api.method = lambda: 'GET'
        _status, body = self.call(api.handle_cve_ignore_list)
        self.assertEqual([r['vuln_id'] for r in body['ignores']], ['CVE-2'])

    def test_a_pre_upgrade_record_keeps_working_everywhere(self):
        """Records already on disk carry no tenant. Un-suppressing a finding an
        operator has accepted would be a worse bug than the one being fixed."""
        api.save(api.CVE_IGNORE_FILE,
                 {'CVE-OLD': {'scope': 'global', 'reason': 'accepted'}})
        api._invalidate_load_cache(None)
        rec = self.store()['CVE-OLD']
        self.assertTrue(api.cve_ignore_applies(rec, 'devA'))
        self.assertTrue(api.cve_ignore_applies(rec, 'devB'))
        api.method = lambda: 'GET'
        _status, body = self.call(api.handle_cve_ignore_list)
        self.assertEqual(len(body['ignores']), 1)

    def test_a_single_tenant_install_is_untouched(self):
        self.gate = None
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(None)
        status, _ = self.call(api.handle_cve_ignore_add,
                              body={'vuln_id': 'CVE-4', 'scope': 'global'})
        self.assertEqual(status, 200)
        rec = self.store()['CVE-4']
        self.assertNotIn('tenant', rec, 'nothing to stamp with tenancy off')
        self.assertTrue(api.cve_ignore_applies(rec, 'devA'))
        self.assertTrue(api.cve_ignore_applies(rec, 'devB'))


class TestNoInlineCopiesOfTheRuleRemain(unittest.TestCase):
    """One shared helper, because six copies of three lines is how the sixth
    site gets missed — the reason `safe_opener.py` exists."""

    _FILES = ('api.py', 'cve_handlers.py', 'cve_scanner.py',
              'prometheus_export.py', 'reports_handlers.py',
              'advisory_handlers.py', 'attention_handlers.py',
              'posture_signals.py')

    def test_no_handwritten_scope_comparison_survives(self):
        offenders = []
        for name in self._FILES:
            path = _CGI / name
            if not path.exists():
                continue
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if 'cve_ignore_applies' in line or line.lstrip().startswith('#'):
                    continue
                if ("scope') == 'global'" in line
                        or "scope') in ('global'" in line):
                    offenders.append(f'{name}:{i}')
        self.assertEqual(
            offenders, [],
            'an inline copy of the accepted-risk rule — use '
            f'cve_ignore_applies so tenancy cannot be forgotten: {offenders}')

    def test_the_detector_would_catch_an_inline_copy(self):
        """The control: the check above passes trivially if the pattern never
        matches anything."""
        sample = "        if ig and ig.get('scope') in ('global', dev_id):"
        self.assertTrue("scope') in ('global'" in sample)


if __name__ == '__main__':
    unittest.main()
