#!/usr/bin/env python3
"""GET /api/config handed the platform operator's credentials to tenant admins.

`handle_config_get` withholds its secret-bearing keys from non-admins and has
done for several releases — healthchecks_url, siem_url, audit_forward_url,
otlp_endpoint, metrics_push.url and the webhook URLs, each because a URL with
basic-auth userinfo is a reusable credential. The gate was:

    _cfg_is_admin = bool(_resolve_role(_cfg_role).get('admin'))

which is a ROLE check, and under tenancy that is the wrong question. Those
integrations are INSTANCE-wide and belong to the platform operator; they are not
tenant property. A tenant admin has role == 'admin', so an operator of the
smallest tenant on the box received the host's SIEM endpoint, its audit-forward
destination and its OTLP collector, credentials and all.

This is the same one fact that has produced cross-tenant findings here in four
different shapes: a tenant admin passes every role check by construction, so a
role check can never be a tenancy check.

The single-tenant install is untouched, and that is asserted rather than
assumed — with tenancy off the branch is never taken and every admin keeps the
access it has today.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cfgsec-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

SIEM = 'https://siemuser:S1EMtoken@siem.internal/ingest'
OTLP = 'https://otlpuser:0TLPtoken@otlp.internal/v1'
PUSH = 'https://pushuser:PUSHtoken@pushgw.internal/metrics'
SECRETS = ('S1EMtoken', '0TLPtoken', 'PUSHtoken')


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-cs-'))
        self._saved = {}
        for name in ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE',
                     'AUDIT_LOG_FILE'):
            self._saved[name] = getattr(api, name)
            setattr(api, name, self.d / f'{name.lower()}.json')
        api.save(api.TENANTS_FILE, {
            'default': {'name': 'Default', 'status': 'active', 'builtin': True},
            'tenantB': {'name': 'B', 'status': 'active'}})
        api.save(api.USERS_FILE, {
            'platform': {'role': 'admin', 'tenant_id': 'default'},
            'badmin':   {'role': 'admin', 'tenant_id': 'tenantB'},
            'watcher':  {'role': 'viewer', 'tenant_id': 'tenantB'}})
        self._cfg = {'tenancy_enforced': True, 'siem_url': SIEM,
                     'otlp_endpoint': OTLP,
                     'metrics_push': {'url': PUSH, 'enabled': True}}
        api.save(api.CONFIG_FILE, self._cfg)
        self._rvt, self._rgt, self._rm = (
            api.verify_token, api.get_token_from_request, api.method)
        api.get_token_from_request = lambda: 'tok'
        api.method = lambda: 'GET'
        self._who, self._role = 'badmin', 'admin'
        api.verify_token = lambda t: (self._who, self._role)

    def tearDown(self):
        api.verify_token, api.get_token_from_request = self._rvt, self._rgt
        api.method = self._rm
        for k, v in self._saved.items():
            setattr(api, k, v)

    def get(self):
        try:
            api.handle_config_get()
        except api.HTTPError as e:
            return e.body
        return None

    def as_user(self, who, role='admin'):
        self._who, self._role = who, role

    def tenancy(self, on):
        cfg = dict(self._cfg)
        cfg['tenancy_enforced'] = on
        api.save(api.CONFIG_FILE, cfg)


class TestInstanceSecretsAreForThePlatformOperator(_Base):

    def test_platform_operator_still_receives_them(self):
        """POSITIVE CONTROL. Withholding from everyone would satisfy the
        assertions below while breaking the Settings editor for the one role
        that is supposed to manage these."""
        self.as_user('platform')
        body = self.get()
        self.assertEqual(body.get('siem_url'), SIEM)
        self.assertEqual(body.get('otlp_endpoint'), OTLP)

    def test_tenant_admin_gets_no_instance_credentials(self):
        self.as_user('badmin')
        blob = repr(self.get())
        for s in SECRETS:
            self.assertNotIn(s, blob,
                             f'{s} reached a tenant admin via GET /api/config')

    def test_tenant_admin_still_learns_they_are_configured(self):
        self.as_user('badmin')
        body = self.get()
        self.assertTrue(body.get('siem_url_set'),
                        'hiding the value must not hide that one is set')

    def test_viewer_gets_nothing_either(self):
        """Unchanged behaviour, asserted so a future refactor of this gate
        cannot quietly widen it."""
        self.as_user('watcher', 'viewer')
        blob = repr(self.get())
        for s in SECRETS:
            self.assertNotIn(s, blob)


class TestSingleTenantInstallIsUnaffected(_Base):

    def test_admin_keeps_full_access_when_tenancy_is_off(self):
        self.tenancy(False)
        self.as_user('badmin')          # no longer meaningful: tenancy is off
        body = self.get()
        self.assertEqual(body.get('siem_url'), SIEM,
                         'the common single-tenant install must be untouched')
        self.assertEqual(body.get('otlp_endpoint'), OTLP)


if __name__ == '__main__':
    unittest.main()
