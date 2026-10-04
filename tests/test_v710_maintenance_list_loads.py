"""GET /api/maintenance resolves a window's owner once, and the owner lookup copies nothing.

For every window the list counts how many devices it covers, and `_window_applies` re-resolved the window's
owner tenant for every (window, device) pair: `_window_owner_tenant` -> `_user_tenant`, which loaded the users
store and the tenants store with load(), a full deep copy each time. Six windows on a 2,000-device fleet made
24,012 load() calls and 0.4 s for a 2 KB answer. The same pair-wise call is made by the status-page projection
and the SLA report. The owner is a property of the window, so the list resolves it once per window and
passes it in, and `_user_tenant` reads the two stores without copying them.

This runs the real handler and counts load() calls, and checks the tenant rules the lookup feeds, because a
faster owner lookup that put a window on the wrong tenant would silence another tenant's alerting.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-mnt-')
    spec = importlib.util.spec_from_file_location('api_v710_mnt', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        api.save(api.USERS_FILE, {'ua': {'tenant_id': 'tenantA', 'role': 'admin'},
                                  'ub': {'tenant_id': 'tenantB', 'role': 'admin'},
                                  'root': {'role': 'admin'},
                                  'stray': {'tenant_id': 'not-in-the-registry', 'role': 'admin'}})
        api.save(api.TENANTS_FILE, {'tenantA': {'name': 'A', 'status': 'active'},
                                    'tenantB': {'name': 'B', 'status': 'active'}})
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        api.require_auth = lambda *a, **k: ('root', 'admin')
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'], self.cap['d'] = s, d
            raise api.HTTPError(s, d)
        api.respond = _respond

    def seed(self, n_devices, windows):
        devices = {}
        for i in range(n_devices):
            tenant = 'tenantA' if i % 2 == 0 else 'tenantB'
            devices['d%04d' % i] = {'name': 'h%d' % i, 'tenant': tenant, 'group': 'prod', 'token': 't'}
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api.save(self.api.MAINT_FILE, {'windows': windows})
        self.api._LOAD_CACHE.clear()

    def window(self, wid, author, **kw):
        return dict({'id': wid, 'scope': 'global', 'reason': 'patching', 'created_by': author}, **kw)

    def listing(self):
        """({window id: covers}, {store file name: load() calls}) for one real GET /api/maintenance."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        self.cap.clear()
        try:
            api.handle_maintenance_list()
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.load = real
        self.assertEqual(200, self.cap.get('s'), self.cap)
        return {w['id']: w['covers'] for w in self.cap['d']['windows']}, calls


class TestTheListDoesNotResolveTheOwnerPerDevice(_Base):

    def test_load_calls_do_not_grow_with_the_number_of_devices(self):
        windows = [self.window('w%d' % i, 'ua') for i in range(3)]
        self.seed(10, windows)
        _, small = self.listing()
        self.seed(300, windows)
        covers, big = self.listing()
        self.assertEqual(3, len(covers), 'control: all three windows should be listed')
        self.assertTrue(all(n > 0 for n in covers.values()), 'control: the windows should cover something: %r' % covers)
        self.assertEqual(small, big, 'load() calls grew with the fleet: %r -> %r' % (small, big))
        self.assertLessEqual(big.get('users.json', 0), 1)
        self.assertLessEqual(big.get('tenants.json', 0), 1)

    def test_the_owner_lookup_copies_nothing(self):
        api = self.api
        calls = []
        real = api.load
        api.load = lambda path, *a, **k: (calls.append(Path(str(path)).name), real(path, *a, **k))[1]
        try:
            for _ in range(50):
                api._user_tenant('ua')
        finally:
            api.load = real
        self.assertEqual([], calls, '_user_tenant called load() %d times for 50 lookups' % len(calls))


class TestTheOwnerRulesAreUnchanged(_Base):

    def test_user_tenant_answers(self):
        api = self.api
        self.assertEqual('tenantA', api._user_tenant('ua'))
        self.assertEqual('tenantB', api._user_tenant('ub'))
        self.assertEqual(api.DEFAULT_TENANT, api._user_tenant('root'), 'a user with no tenant is in the default tenant')
        self.assertEqual(api.DEFAULT_TENANT, api._user_tenant('stray'), 'a tenant id that is not registered falls back')
        self.assertEqual(api.DEFAULT_TENANT, api._user_tenant('nobody'))

    def _as(self, tenant):
        self.api.save(self.api.CONFIG_FILE, {'tenancy_enforced': True})
        self.api.verify_token = lambda tok=None: ('alice', 'admin')
        self.api._caller_effective_tenant = lambda u, _t=tenant: _t
        self.api._caller_scope = lambda: None
        self.api._LOAD_CACHE.clear()

    def test_a_window_covers_only_the_hosts_of_the_tenant_that_wrote_it(self):
        """Seen as tenant A: its own window and the instance-wide one are listed, each covering A's five hosts."""
        self._as('tenantA')
        self.seed(10, [self.window('wa', 'ua'), self.window('wb', 'ub'), self.window('wr', 'root'),
                       {'id': 'wi', 'scope': 'global', 'reason': 'everyone'}])
        covers, _ = self.listing()
        self.assertEqual({'wa': 5, 'wi': 5}, covers,
                         "tenant A's window must cover tenant A's five hosts, and tenant B's and the default tenant's must not be listed")

    def test_an_explicit_owner_stamp_still_wins_over_the_author(self):
        """The author `ua` is in tenant A, but the stamp says B: the window is B's."""
        self._as('tenantB')
        self.seed(10, [self.window('ws', 'ua', tenant_gate='tenantB')])
        covers, _ = self.listing()
        self.assertEqual({'ws': 5}, covers)
        self._as('tenantA')
        covers, _ = self.listing()
        self.assertEqual({}, covers, 'tenant A must not see a window stamped for tenant B')


if __name__ == '__main__':
    unittest.main()
