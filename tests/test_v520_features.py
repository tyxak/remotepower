"""v5.2.0 "AccessMatters" — WG Access (road-warrior WireGuard VPN) tests.

Covers the pure wg_access module (validation / allocation / AllowedIPs / sync-spec
/ wg-dump parsing / status), the api.py event-registry wiring (every registry, per
CLAUDE.md "Adding a webhook/alert event"), the auto-resolve REAL path (recover
event closes the open alert — built via _record_alert, not a hand-built dict, per
the webhook §7 lesson), per-client coalescing, and the store/meta helpers.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import wg_access as W  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v520_feat", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestWgAccessPure(unittest.TestCase):
    def test_validators(self):
        self.assertTrue(W.valid_pubkey('A' * 43 + '='))
        self.assertFalse(W.valid_pubkey('A' * 43))          # no padding
        self.assertFalse(W.valid_pubkey('!' * 43 + '='))    # bad chars
        self.assertTrue(W.valid_iface('rp-wg0'))
        self.assertTrue(W.valid_iface('rp-wg12'))
        self.assertFalse(W.valid_iface('eth0'))
        self.assertFalse(W.valid_iface('rp-wg0; rm -rf'))
        self.assertTrue(W.valid_name('jakob-pixel'))
        self.assertFalse(W.valid_name('bad/name'))   # slash not allowed
        self.assertFalse(W.valid_name(''))
        self.assertTrue(W.valid_port(51820))
        self.assertFalse(W.valid_port(0))
        self.assertFalse(W.valid_port(99999))
        self.assertTrue(W.valid_cidr('10.0.0.0/24'))
        self.assertTrue(W.valid_host_ip('1.2.3.4'))
        self.assertFalse(W.valid_host_ip('1.2.3.4/32'))

    def test_allocation(self):
        self.assertEqual(W.next_iface(['rp-wg0', 'rp-wg2']), 'rp-wg1')
        self.assertEqual(W.next_iface([]), 'rp-wg0')
        self.assertEqual(W.next_port([51820, 51821]), 51822)
        self.assertEqual(W.next_pool(['10.97.0.0/24']), '10.97.1.0/24')
        self.assertEqual(W.hub_ip('10.97.3.0/24'), '10.97.3.1')
        self.assertEqual(W.alloc_client_ip('10.97.3.0/24', []), '10.97.3.2')
        self.assertEqual(W.alloc_client_ip('10.97.3.0/24', ['10.97.3.2']), '10.97.3.3')

    def test_allowed_ips_modes(self):
        dash = {'pool': '10.97.3.0/24', 'allow_internet': False}
        self.assertEqual(W.client_allowed_ips(dash, []), '10.97.3.1/32')
        self.assertIn('192.168.1.5/32', W.client_allowed_ips(dash, ['192.168.1.5/32']))
        full = {'pool': '10.97.3.0/24', 'allow_internet': True}
        self.assertEqual(W.client_allowed_ips(full, []), '0.0.0.0/0')

    def test_needs_forwarding(self):
        self.assertFalse(W.needs_forwarding({'allow_internet': False}, []))
        self.assertTrue(W.needs_forwarding({'allow_internet': True}, []))
        self.assertTrue(W.needs_forwarding({'allow_internet': False}, ['10.0.0.1/32']))

    def test_build_sync_spec_filters_bad_peers(self):
        t = {'iface': 'rp-wg0', 'listen_port': 51820, 'pool': '10.97.3.0/24',
             'allow_internet': False}
        clients = [
            {'pubkey': 'A' * 43 + '=', 'address': '10.97.3.2'},
            {'pubkey': 'bad', 'address': '10.97.3.3'},          # dropped
            {'pubkey': 'B' * 43 + '=', 'address': 'not-an-ip'},  # dropped
        ]
        spec = W.build_sync_spec(t, clients, ['192.168.1.5/32'])
        self.assertEqual(spec['iface'], 'rp-wg0')
        self.assertEqual(spec['address'], '10.97.3.1/24')
        self.assertEqual(len(spec['peers']), 1)
        self.assertEqual(spec['peers'][0]['allowed_ips'], '10.97.3.2/32')

    def test_parse_wg_dump(self):
        pub = 'A' * 43 + '='
        dump = ('rp-wg0\tprivhash\t51820\toff\n'
                f'{pub}\t(none)\t1.2.3.4:5000\t10.97.3.2/32\t1700000000\t1024\t2048\t0')
        out = W.parse_wg_dump(dump)
        self.assertIn(pub, out)
        self.assertEqual(out[pub]['endpoint'], '1.2.3.4')     # port stripped
        self.assertEqual(out[pub]['rx_bytes'], 1024)
        self.assertEqual(out[pub]['tx_bytes'], 2048)

    def test_client_status(self):
        now = 1_000_000
        self.assertEqual(W.client_status(0, now), 'offline')
        self.assertEqual(W.client_status(now - 10, now), 'connected')
        self.assertEqual(W.client_status(now - 600, now), 'idle')
        self.assertEqual(W.client_status(now - 99999, now), 'offline')


class TestEventRegistry(unittest.TestCase):
    EVENTS = ('vpn_client_connected', 'vpn_client_disconnected', 'vpn_handshake_stale')

    def test_in_webhook_events(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        for ev in self.EVENTS:
            self.assertIn(ev, names)

    def test_alert_rules(self):
        self.assertIn('vpn_client_disconnected', api._ALERT_RULES)
        self.assertIn('vpn_handshake_stale', api._ALERT_RULES)

    def test_recover_mapping(self):
        self.assertEqual(api._ALERT_RECOVER.get('vpn_client_connected'),
                         'vpn_client_disconnected')
        self.assertIn('vpn_handshake_stale',
                      api._ALERT_RECOVER_EXTRA.get('vpn_client_connected', ()))

    def test_channel_kind(self):
        kinds = {k[0] for k in api.CHANNEL_KINDS}
        self.assertIn('vpn', kinds)
        for ev in self.EVENTS:
            self.assertEqual(api.EVENT_KIND_MAP.get(ev), 'vpn')

    def test_identity_field(self):
        self.assertIn('client_id', api._ALERT_IDENTITY_FIELDS)

    def test_titles_no_placeholder(self):
        for ev in self.EVENTS:
            self.assertNotIn('?', api._webhook_title(ev) or '?')
            self.assertNotIn('?', api._alert_title(ev, {'client_name': 'x'}) or '?')


class TestAutoResolveRealPath(unittest.TestCase):
    """Recover event must close the open alert via the REAL _record_alert path
    (the match key client_id must actually be stored on the alert)."""

    def _open(self):
        store = api.load(api.ALERTS_FILE) or {}
        return [a for a in store.get('alerts', []) if not a.get('resolved_at')]

    def test_connected_resolves_disconnected(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('vpn_client_disconnected',
                          {'client_id': 'wgc_1', 'client_name': 'laptop',
                           'tunnel_id': 'wgt_1', 'tunnel_name': 'HQ'})
        opened = self._open()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]['payload'].get('client_id'), 'wgc_1')
        api._auto_resolve_alerts('vpn_client_connected', {'client_id': 'wgc_1'})
        self.assertEqual(len(self._open()), 0)

    def test_connected_resolves_handshake_stale(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('vpn_handshake_stale',
                          {'client_id': 'wgc_2', 'tunnel_id': 'wgt_1'})
        self.assertEqual(len(self._open()), 1)
        api._auto_resolve_alerts('vpn_client_connected', {'client_id': 'wgc_2'})
        self.assertEqual(len(self._open()), 0)

    def test_per_client_coalescing(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('vpn_client_disconnected', {'client_id': 'wgc_3'})
        api._record_alert('vpn_client_disconnected', {'client_id': 'wgc_3'})
        opened = self._open()
        self.assertEqual(len(opened), 1)               # coalesced, not stacked
        self.assertEqual(int(opened[0].get('count') or 1), 2)


class _Responded(Exception):
    def __init__(self, status, data):
        self.status, self.data = status, data


class TestHandlers(unittest.TestCase):
    """Exercise the actual request handlers (catches runtime errors the pure-unit
    tests miss — e.g. the missing local `import ipaddress` in tunnel stats)."""

    def setUp(self):
        self._orig = {k: getattr(api, k) for k in
                      ('respond', 'require_admin_or_auditor_auth', 'require_admin_auth',
                       '_get_client_ip')}
        api.respond = lambda s, d: (_ for _ in ()).throw(_Responded(s, d))
        api.require_admin_or_auditor_auth = lambda: 'admin'
        api.require_admin_auth = lambda: 'admin'
        api._get_client_ip = lambda: '127.0.0.1'
        api.save(api.DEVICES_FILE, {
            'd1': {'hostname': 'web1', 'site': 'HQ', 'ip': '192.168.1.10'}})
        api.save(api.VPN_FILE, {'tunnels': [{
            'id': 'wgt_test', 'name': 't', 'iface': 'rp-wg0', 'listen_port': 51820,
            'pool': '10.97.0.0/24', 'endpoint': 'vpn.example.com:51820', 'dns': '',
            'hub_pubkey': '', 'allow_internet': False, 'reach_scope_type': 'site',
            'reach_scope_value': 'HQ', 'enabled': True, 'expires_at': None,
            'clients': []}]})

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def test_tunnel_stats_ok(self):
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_tunnel_stats('wgt_test')
        self.assertEqual(cm.exception.status, 200)
        st = cm.exception.data['stats']
        self.assertEqual(st['reach_count'], 1)
        self.assertEqual(st['reach_devices'][0]['ip'], '192.168.1.10')

    def test_clients_list_ok(self):
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_clients_list('wgt_test')
        self.assertEqual(cm.exception.status, 200)


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for h in ('handle_vpn_tunnels_list', 'handle_vpn_tunnel_create',
                  'handle_vpn_tunnel_update', 'handle_vpn_tunnel_delete',
                  'handle_vpn_tunnel_stats', 'handle_vpn_clients_list',
                  'handle_vpn_client_create', 'handle_vpn_client_update',
                  'handle_vpn_client_delete', 'handle_vpn_client_stats',
                  'run_vpn_stats_if_due'):
            self.assertTrue(hasattr(api, h), h)

    def test_store_empty_shape(self):
        api.save(api.VPN_FILE, {})
        d = api._vpn_load()
        self.assertIsInstance(d.get('tunnels'), list)

    def test_meta_shapes(self):
        t = {'id': 'wgt_x', 'name': 'HQ', 'iface': 'rp-wg0', 'listen_port': 51820,
             'pool': '10.97.0.0/24', 'allow_internet': False,
             'reach_scope_type': 'none', 'clients': [
                 {'id': 'wgc_x', 'name': 'l', 'pubkey': 'A' * 43 + '=',
                  'address': '10.97.0.2', 'last_handshake': 0}]}
        m = api._vpn_tunnel_meta(t, with_clients=True)
        self.assertEqual(m['client_count'], 1)
        self.assertIn('clients', m)
        self.assertEqual(m['clients'][0]['status'], 'offline')
        # no private material in meta
        self.assertNotIn('privkey', m)

    def test_ensure_hub_key_no_helper(self):
        # A tunnel created before the helper exists has hub_pubkey='' and stays
        # that way when the helper is absent (so client-create refuses rather than
        # emitting a config with an empty PublicKey).
        api.save(api.VPN_FILE, {'tunnels': [
            {'id': 'wgt_nokey', 'name': 'T', 'iface': 'rp-wg0',
             'listen_port': 51820, 'pool': '10.97.0.0/24', 'hub_pubkey': '',
             'clients': []}]})
        if not api._wg_helper_available():
            self.assertEqual(api._vpn_ensure_hub_key('wgt_nokey'), '')
        # An already-keyed tunnel returns its key unchanged.
        api.save(api.VPN_FILE, {'tunnels': [
            {'id': 'wgt_keyed', 'hub_pubkey': 'K' * 43 + '=', 'clients': []}]})
        self.assertEqual(api._vpn_ensure_hub_key('wgt_keyed'), 'K' * 43 + '=')

    def test_reach_resolution(self):
        # Reach resolves from the CURRENT fleet via the RBAC device matcher.
        api.save(api.DEVICES_FILE, {
            'd1': {'hostname': 'web1', 'site': 'HQ', 'tags': ['prod'], 'ip': '192.168.1.10'},
            'd2': {'hostname': 'web2', 'site': 'HQ', 'tags': ['dev'],  'ip': '192.168.1.11'},
            'd3': {'hostname': 'box',  'site': 'DR', 'tags': ['prod'], 'ip': ''},          # no IP → excluded
        })
        none_t = {'reach_scope_type': 'none'}
        self.assertEqual(api._vpn_reach_cidrs(none_t), [])
        site_t = {'reach_scope_type': 'site', 'reach_scope_value': 'HQ'}
        self.assertEqual(api._vpn_reach_cidrs(site_t),
                         ['192.168.1.10/32', '192.168.1.11/32'])
        tag_t = {'reach_scope_type': 'tag', 'reach_scope_value': 'prod'}
        # d3 is tag=prod but has no IP → only d1
        self.assertEqual(api._vpn_reach_cidrs(tag_t), ['192.168.1.10/32'])
        all_t = {'reach_scope_type': 'all'}
        self.assertEqual(api._vpn_reach_cidrs(all_t),
                         ['192.168.1.10/32', '192.168.1.11/32'])
        devs = api._vpn_reach_devices(site_t)
        self.assertEqual({d['name'] for d in devs}, {'web1', 'web2'})

    def test_direct_mode_toggle(self):
        # Direct mode (CAP_NET_ADMIN worker) runs the helper without sudo so it
        # works under NoNewPrivileges; default (fcgiwrap) uses sudo.
        old = os.environ.get('RP_WG_DIRECT')
        try:
            os.environ['RP_WG_DIRECT'] = '1'
            self.assertTrue(api._wg_direct())
            os.environ['RP_WG_DIRECT'] = '0'
            self.assertFalse(api._wg_direct())
            os.environ.pop('RP_WG_DIRECT', None)
            self.assertFalse(api._wg_direct())
        finally:
            if old is None:
                os.environ.pop('RP_WG_DIRECT', None)
            else:
                os.environ['RP_WG_DIRECT'] = old

    def test_helper_absent_is_graceful(self):
        # In CI the helper isn't installed → available False, sync is a no-op.
        self.assertIn(api._wg_helper_available(), (True, False))
        self.assertFalse(api._vpn_sync_tunnel(
            {'iface': 'rp-wg0', 'pool': '10.97.0.0/24', 'clients': []})
            if not api._wg_helper_available() else False)


if __name__ == '__main__':
    unittest.main()
