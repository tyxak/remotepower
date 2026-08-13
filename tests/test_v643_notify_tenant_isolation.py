#!/usr/bin/env python3
"""A personal notification subscription must not stream another tenant's events.

`_deliver_user_notifications` filtered on RBAC device scope and nothing else,
and that filter is skipped for every FULL-FLEET role:

    rscope = _user_notify_scope(username, users)
    if rscope is not None and not _device_in_scope(rscope, dev):

`_user_notify_scope` returns None for an admin role AND for any role whose scope
type is 'all' — which is a plain viewer, auditor, mcp or finance user. So on a
tenanted install the guard did nothing for essentially everybody, and any
account could point a personal webhook at a host it controls and receive every
tenant's device events.

It is a quiet channel: `POST /api/my/notify-prefs` is deliberately open to any
authenticated user (self-scoped), and the webhook URL is write-only — masked to
a boolean on read — so an operator auditing the install sees a subscription
exists and cannot see where it points.

Two properties are asserted, and the second matters as much as the first: a
cross-tenant subscriber gets NOTHING, and a same-tenant subscriber still gets
DELIVERED. Without that positive control this file would pass just as happily if
delivery broke altogether, which is the failure mode the v6.4.3 release exists to
close.

The fixtures deliberately do NOT stub `_resolve_role` (the pre-existing suite
does, which is precisely why it never exercised tenancy), and they DO populate
TENANTS_FILE — `_user_tenant` falls back to 'default' for a tenant that is not
registered, which would silently turn every "tenant admin" in a fixture into a
platform operator and make the whole file vacuous.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-notify-tenant-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-nt-'))
        self._saved = {}
        for name in ('USERS_FILE', 'DEVICES_FILE', 'TENANTS_FILE',
                     'USER_NOTIFY_FILE', 'CONFIG_FILE'):
            self._saved[name] = getattr(api, name)
            setattr(api, name, self.d / f'{name.lower()}.json')

        api.save(api.TENANTS_FILE, {
            'default': {'name': 'Default', 'status': 'active', 'builtin': True},
            'tenantA': {'name': 'A', 'status': 'active'},
            'tenantB': {'name': 'B', 'status': 'active'},
        })
        api.save(api.USERS_FILE, {
            # lowest-privilege account in the OTHER tenant
            'bview':  {'role': 'viewer', 'tenant_id': 'tenantB'},
            # a tenant admin is also confined — admin != platform operator
            'badmin': {'role': 'admin',  'tenant_id': 'tenantB'},
            # same tenant as the device: the positive control
            'aview':  {'role': 'viewer', 'tenant_id': 'tenantA'},
            # admin in the BUILT-IN default tenant == platform operator
            'root':   {'role': 'admin',  'tenant_id': 'default'},
        })
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'tenantA-prod-db', 'tenant': 'tenantA'},
        })
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})

    def tearDown(self):
        for name, val in self._saved.items():
            setattr(api, name, val)

    def _subscribe(self, user):
        store = api.load(api.USER_NOTIFY_FILE) or {}
        store[user] = {'enabled': True,
                       'webhook_url': f'https://attacker.invalid/{user}'}
        api.save(api.USER_NOTIFY_FILE, store)

    def _capture(self):
        sent = []
        real = api._dispatch_one_webhook
        api._dispatch_one_webhook = (
            lambda ev, dest, p, m, t, pr, allow_digest=True:
            sent.append({'dest': dest['id'], 'event': ev,
                         'name': p.get('device_name')}))
        self.addCleanup(lambda: setattr(api, '_dispatch_one_webhook', real))
        return sent

    def _fire(self):
        api._deliver_user_notifications(
            'device_offline',
            {'device_id': 'devA', 'device_name': 'tenantA-prod-db'},
            'tenantA-prod-db is offline', {'smtp_host': ''})


class TestPersonalSubscriptionsAreTenantScoped(_Base):

    def test_same_tenant_subscriber_is_delivered(self):
        """POSITIVE CONTROL. Every other test here asserts an absence, and an
        absence proves nothing if delivery is simply broken."""
        sent = self._capture()
        self._subscribe('aview')
        self._fire()
        self.assertEqual([s['dest'] for s in sent], ['user:aview'],
                         'a same-tenant subscriber must still be delivered — '
                         'without this the cross-tenant assertions are vacuous')

    def test_cross_tenant_viewer_receives_nothing(self):
        sent = self._capture()
        self._subscribe('bview')
        self._fire()
        self.assertEqual(sent, [],
                         "a tenant-B viewer received tenant A's device event: "
                         f'{sent}')

    def test_cross_tenant_admin_receives_nothing(self):
        """A tenant admin is not a platform operator — being 'admin' inside
        tenant B must not confer sight of tenant A."""
        sent = self._capture()
        self._subscribe('badmin')
        self._fire()
        self.assertEqual(sent, [],
                         "a tenant-B ADMIN received tenant A's device event: "
                         f'{sent}')

    def test_platform_operator_still_sees_every_tenant(self):
        """The gate must not break the superadmin: an admin in the built-in
        default tenant is the platform operator and does see the whole estate."""
        sent = self._capture()
        self._subscribe('root')
        self._fire()
        self.assertEqual([s['dest'] for s in sent], ['user:root'],
                         'the platform operator must keep full visibility')

    def test_untenanted_install_is_unaffected(self):
        """With tenancy off, the gate must be a no-op — the common install."""
        api.save(api.CONFIG_FILE, {'tenancy_enforced': False})
        sent = self._capture()
        self._subscribe('bview')
        self._fire()
        self.assertEqual([s['dest'] for s in sent], ['user:bview'],
                         'tenancy off must not change delivery')


if __name__ == '__main__':
    unittest.main()
