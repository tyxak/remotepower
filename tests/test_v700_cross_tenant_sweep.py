#!/usr/bin/env python3
"""Five cross-tenant leaks found in one hunt, and why they share a shape.

A tenant admin's role IS `admin`, so `require_admin_auth()` passes them, and
`_caller_scope()` returns None, so every gate written as `if scope is not None:`
passes them too. That single fact is why these five handlers — in five
different subsystems, written at five different times — were all open:

  inbound webhooks   a token could be PINNED to another tenant's device, and
                     the ingest path honours the pin unconditionally, so every
                     alert / syslog line / flow record POSTed to it landed on
                     that host
  DNS providers      returned the whole fleet roster, ids and hostnames, as
                     "import from agent" candidates
  CVE campaigns      carried no tenant field at all: readable AND deletable by
                     any admin of any tenant
  tickets            `affected_devices` accepted foreign ids and the detail
                     view resolved them to HOSTNAMES — a name oracle
  network tunnels    a tenant admin could assert a relationship between two
                     hosts they do not own, and read the pair back

Each fix routes the device set through `_scope_filter_devices`, which folds in
BOTH role scope and the tenant filter and no-ops for an unscoped superadmin.
Every class below therefore carries a superadmin control: these handlers must
keep working for the operator who legitimately sees everything, and a fix that
merely broke them would satisfy the negative assertions perfectly.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-xtenant-'))

import importlib.util  # noqa: E402

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api'] = api
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        api._LOAD_CACHE.clear()
        api.save(api.TENANTS_FILE, {'tenants': [
            {'id': 'tenantA', 'name': 'A'}, {'id': 'tenantB', 'name': 'B'}]})
        api.save(api.TUNNELS_FILE, {})
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'A-host', 'tenant': 'tenantA', 'last_seen': 1},
            'devB': {'name': 'SECRET-B-host', 'tenant': 'tenantB', 'last_seen': 1},
            'devB2': {'name': 'SECRET-B-two', 'tenant': 'tenantB', 'last_seen': 1},
        })
        self._real = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', '_tenant_gate',
                       '_caller_scope', 'respond', 'audit_log', 'method',
                       'get_json_body', 'get_json_obj', '_read_valid')}
        api.audit_log = lambda *a, **k: None
        self.captured = []

        def _respond(status, data=None, *a, **k):
            self.captured.append((status, data))
            raise api.HTTPError(status, data)
        api.respond = _respond
        self.as_tenant_admin()

    def tearDown(self):
        for n, f in self._real.items():
            setattr(api, n, f)

    def as_tenant_admin(self):
        api.require_auth = lambda *a, **k: ('alice', 'admin')
        api.require_admin_auth = lambda *a, **k: 'alice'
        api._tenant_gate = lambda *a, **k: 'tenantA'
        api._caller_scope = lambda *a, **k: None

    def as_superadmin(self):
        api.require_auth = lambda *a, **k: ('root', 'admin')
        api.require_admin_auth = lambda *a, **k: 'root'
        api._tenant_gate = lambda *a, **k: None
        api._caller_scope = lambda *a, **k: None

    def call(self, fn, *args, body=None, verb='POST'):
        self.captured = []
        api.method = lambda: verb
        api.get_json_body = lambda: (body or {})
        api.get_json_obj = lambda: (body or {})
        api._read_valid = lambda *a, **k: (body or {})
        api._LOAD_CACHE.clear()
        try:
            fn(*args)
        except (api.HTTPError, SystemExit):
            pass
        return self.captured[-1] if self.captured else (None, None)


class TestTheFixtureSeparatesTheTenants(_Base):
    """Every assertion in this file is a refusal or an absence, which a
    fixture that simply cannot see anything satisfies just as well."""

    def test_the_tenant_admin_sees_only_its_own_device(self):
        visible = api._scope_filter_devices(api.load(api.DEVICES_FILE) or {})
        self.assertEqual(sorted(visible), ['devA'])

    def test_the_superadmin_sees_all_three(self):
        self.as_superadmin()
        visible = api._scope_filter_devices(api.load(api.DEVICES_FILE) or {})
        self.assertEqual(sorted(visible), ['devA', 'devB', 'devB2'])


class TestInboundWebhookPin(_Base):

    def test_cannot_pin_a_token_to_a_foreign_device(self):
        st, data = self.call(api.handle_inbound_webhooks_create,
                             body={'label': 'x', 'scope_device_id': 'devB'})
        # _scope_block_device answers 403 here; the point is that the pin is
        # refused and not stored, not which of the two codes it picks.
        self.assertEqual(st, 403, f'expected a refusal, got {st} {data}')

    def test_a_superadmin_still_can(self):
        self.as_superadmin()
        st, _ = self.call(api.handle_inbound_webhooks_create,
                          body={'label': 'x', 'scope_device_id': 'devB'})
        self.assertEqual(st, 200)

    def test_pinning_an_own_device_still_works(self):
        st, _ = self.call(api.handle_inbound_webhooks_create,
                          body={'label': 'mine', 'scope_device_id': 'devA'})
        self.assertEqual(st, 200)


class TestDnsProviderRoster(_Base):

    def test_the_agent_device_list_is_scoped(self):
        api.save(api.ACME_STATE_FILE, {})
        st, data = self.call(api.handle_dns_providers, verb='GET')
        self.assertEqual(st, 200)
        ids = [d['id'] for d in data.get('agent_devices', [])]
        self.assertEqual(ids, ['devA'],
                         'the picker hands over the whole fleet, ids and names')

    def test_a_superadmin_sees_the_whole_fleet(self):
        self.as_superadmin()
        api.save(api.ACME_STATE_FILE, {})
        st, data = self.call(api.handle_dns_providers, verb='GET')
        self.assertEqual(st, 200)
        self.assertEqual(sorted(d['id'] for d in data['agent_devices']),
                         ['devA', 'devB', 'devB2'])


class TestCveCampaignTenancy(_Base):

    def _seed_foreign(self):
        api.save(api.CVE_CAMPAIGNS_FILE, {'campaigns': [
            {'id': 'camp_x', 'name': 'B-private', 'tenant': 'tenantB',
             'owner': 'bob', 'cve_ids': [], 'severities': [], 'kev_only': False,
             'target_date': '', 'created_at': 1, 'completed_at': None,
             'samples': []}]})

    def test_a_foreign_campaign_is_not_listed(self):
        self._seed_foreign()
        st, data = self.call(api.handle_cve_campaigns, verb='GET')
        self.assertEqual(st, 200)
        self.assertEqual([c['name'] for c in data['campaigns']], [])

    def test_a_foreign_campaign_cannot_be_deleted(self):
        self._seed_foreign()
        st, _ = self.call(api.handle_cve_campaign, 'camp_x', verb='DELETE')
        self.assertEqual(st, 404)
        left = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')
        self.assertEqual([c['id'] for c in left], ['camp_x'],
                         'another tenant’s remediation plan was deleted')

    def test_a_new_campaign_is_stamped(self):
        api.save(api.CVE_CAMPAIGNS_FILE, {'campaigns': []})
        st, _ = self.call(api.handle_cve_campaigns, body={'name': 'mine'})
        self.assertEqual(st, 200)
        camps = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')
        self.assertEqual(camps[0]['tenant'], 'tenantA',
                         'unstamped, so the next release cannot tell who owns it')

    def test_the_owning_tenant_still_sees_and_deletes_its_own(self):
        """Positive control — the filter must be about ownership, not a blanket
        refusal that would pass every assertion above."""
        self._seed_foreign()
        api._tenant_gate = lambda *a, **k: 'tenantB'
        st, data = self.call(api.handle_cve_campaigns, verb='GET')
        self.assertEqual([c['name'] for c in data['campaigns']], ['B-private'])
        st, _ = self.call(api.handle_cve_campaign, 'camp_x', verb='DELETE')
        self.assertEqual(st, 200)


class TestTicketDeviceNameOracle(_Base):

    def _seed(self):
        """One ticket naming BOTH an own and a foreign device.

        The first draft named only the foreign one and asserted its hostname was
        absent — which passed with the fix reverted, because an empty resolved
        list satisfies "absent" perfectly. Carrying a device that MUST resolve
        turns the same call into a two-sided measurement.
        """
        api.save(api.TICKETS_FILE, {'tickets': [
            {'id': 'tk1', 'number': 1, 'subject': 's', 'status': 'open',
             'affected_devices': ['devA', 'devB'], 'created_at': 1,
             'updated_at': 1, 'comments': [], 'priority': 'normal'}]})

    def _resolved(self):
        self._seed()
        st, data = self.call(api.handle_ticket_get, 'tk1', verb='GET')
        self.assertEqual(st, 200, f'the ticket did not load ({st}) — every '
                                  'assertion here would be vacuous')
        # The payload nests under `ticket`; reading the top level returned an
        # empty list, which made the negative assertion pass with the fix
        # reverted. Hence the positive control above.
        tk = (data or {}).get('ticket') or {}
        return {d['id']: d['name'] for d in tk.get('affected_devices_resolved', [])}

    def test_an_own_device_still_resolves_to_its_name(self):
        self.assertEqual(self._resolved().get('devA'), 'A-host')

    def test_a_foreign_device_does_not_resolve_to_its_hostname(self):
        got = self._resolved()
        self.assertEqual(got.get('devB'), 'devB',
                         'a foreign id must fall back to the id, as it already '
                         f'did for a deleted device; got {got.get("devB")!r}')

    def test_a_superadmin_sees_both_names(self):
        self.as_superadmin()
        got = self._resolved()
        self.assertEqual(got.get('devB'), 'SECRET-B-host')


class TestNetworkTunnels(_Base):

    def test_cannot_link_two_foreign_hosts(self):
        st, data = self.call(api.handle_tunnel_add,
                             body={'endpoints': ['devB', 'devB2']})
        self.assertEqual(st, 400, f'got {st} {data}')

    def test_a_foreign_tunnel_is_not_listed(self):
        self.as_superadmin()
        self.call(api.handle_tunnel_add, body={'endpoints': ['devB', 'devB2']})
        self.as_tenant_admin()
        st, data = self.call(api.handle_tunnels_list, verb='GET')
        self.assertEqual(st, 200)
        self.assertEqual(data, [], f'leaked device ids: {data}')

    def test_a_superadmin_creates_and_reads_it_back(self):
        """The positive control for BOTH assertions above: the create must
        still work, or 'not listed' proves only that nothing exists."""
        self.as_superadmin()
        st, _ = self.call(api.handle_tunnel_add,
                          body={'endpoints': ['devB', 'devB2']})
        self.assertIn(st, (200, 201), 'superadmin can no longer create a tunnel')
        st, data = self.call(api.handle_tunnels_list, verb='GET')
        self.assertEqual(st, 200)
        self.assertEqual([t['endpoints'] for t in data], [['devB', 'devB2']])


if __name__ == '__main__':
    unittest.main()
