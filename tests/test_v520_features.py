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

    def test_valid_psk(self):
        # #86: identical format to a pubkey (same regex, distinct name).
        self.assertTrue(W.valid_psk('A' * 43 + '='))
        self.assertFalse(W.valid_psk('A' * 43))
        self.assertFalse(W.valid_psk(None))
        self.assertFalse(W.valid_psk(''))

    def test_build_sync_spec_includes_valid_psk(self):
        t = {'iface': 'rp-wg0', 'listen_port': 51820, 'pool': '10.97.3.0/24',
             'allow_internet': False}
        psk = 'B' * 43 + '='
        clients = [{'pubkey': 'A' * 43 + '=', 'address': '10.97.3.2',
                    'preshared_key': psk}]
        spec = W.build_sync_spec(t, clients, [])
        self.assertEqual(spec['peers'][0]['preshared_key'], psk)

    def test_build_sync_spec_drops_malformed_psk_keeps_peer(self):
        t = {'iface': 'rp-wg0', 'listen_port': 51820, 'pool': '10.97.3.0/24',
             'allow_internet': False}
        clients = [{'pubkey': 'A' * 43 + '=', 'address': '10.97.3.2',
                    'preshared_key': 'not-a-real-psk'}]
        spec = W.build_sync_spec(t, clients, [])
        self.assertEqual(len(spec['peers']), 1)   # peer kept, pubkey-only
        self.assertNotIn('preshared_key', spec['peers'][0])

    def test_build_sync_spec_no_psk_field_when_absent(self):
        t = {'iface': 'rp-wg0', 'listen_port': 51820, 'pool': '10.97.3.0/24',
             'allow_internet': False}
        clients = [{'pubkey': 'A' * 43 + '=', 'address': '10.97.3.2'}]
        spec = W.build_sync_spec(t, clients, [])
        self.assertNotIn('preshared_key', spec['peers'][0])

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
                       '_get_client_ip', 'method', 'get_json_obj')}
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
            'clients': [{'id': 'wgc_test', 'name': 'laptop', 'pubkey': 'x', 'address': '10.97.0.2',
                        'enabled': True, 'expires_at': None, 'created_by': 'admin',
                        'created_at': 0, 'last_handshake': 0, 'rx_bytes': 0, 'tx_bytes': 0,
                        'endpoint': ''}]}]})

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

    # ── #86: preshared key generated + encrypted on client create ──────────
    def _give_hub_key(self):
        store = api.load(api.VPN_FILE)
        store['tunnels'][0]['hub_pubkey'] = 'H' * 43 + '='
        api.save(api.VPN_FILE, store)

    def test_client_create_generates_and_encrypts_psk(self):
        self._give_hub_key()
        old_key = os.environ.get('RP_CONFIG_KEY')
        try:
            os.environ['RP_CONFIG_KEY'] = 'test-master-key-for-vpn-psk'
            api.method = lambda: 'POST'
            api.get_json_obj = lambda: {'name': 'phone', 'pubkey': 'Q' * 43 + '='}
            with self.assertRaises(_Responded) as cm:
                api.handle_vpn_client_create('wgt_test')
            self.assertEqual(cm.exception.status, 200)
            self.assertTrue(cm.exception.data['preshared_key'])
            self.assertTrue(cm.exception.data['psk_encrypted'])
            new_id = cm.exception.data['id']
            store = api.load(api.VPN_FILE)
            new_client = next(c for c in store['tunnels'][0]['clients'] if c['id'] == new_id)
            self.assertTrue(new_client.get('psk_enc', '').startswith('enc:'))
            self.assertNotEqual(new_client['psk_enc'], cm.exception.data['preshared_key'])
            self.assertEqual(api._cfg_dec(new_client['psk_enc']), cm.exception.data['preshared_key'])
        finally:
            if old_key is None:
                os.environ.pop('RP_CONFIG_KEY', None)
            else:
                os.environ['RP_CONFIG_KEY'] = old_key

    def test_client_create_flags_unencrypted_when_no_master_key(self):
        self._give_hub_key()
        old_key = os.environ.get('RP_CONFIG_KEY')
        try:
            os.environ.pop('RP_CONFIG_KEY', None)
            api.method = lambda: 'POST'
            api.get_json_obj = lambda: {'name': 'tablet', 'pubkey': 'R' * 43 + '='}
            with self.assertRaises(_Responded) as cm:
                api.handle_vpn_client_create('wgt_test')
            self.assertTrue(cm.exception.data['preshared_key'])   # still generated
            self.assertFalse(cm.exception.data['psk_encrypted'])  # but flagged plaintext
        finally:
            if old_key is not None:
                os.environ['RP_CONFIG_KEY'] = old_key

    def test_client_create_can_opt_out_of_psk(self):
        self._give_hub_key()
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'no-psk', 'pubkey': 'S' * 43 + '=', 'psk': False}
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_client_create('wgt_test')
        self.assertIsNone(cm.exception.data['preshared_key'])

    def test_client_meta_never_leaks_psk(self):
        self._give_hub_key()
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'watch', 'pubkey': 'T' * 43 + '='}
        with self.assertRaises(_Responded):
            api.handle_vpn_client_create('wgt_test')
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_clients_list('wgt_test')
        for c in cm.exception.data['clients']:
            self.assertNotIn('psk_enc', c)
            self.assertNotIn('preshared_key', c)
        watch = next(c for c in cm.exception.data['clients'] if c['name'] == 'watch')
        self.assertTrue(watch['psk_configured'])

    # ── #87: per-peer RX/TX history ──────────────────────────────────────
    def test_client_history_ok(self):
        api.save(api.VPN_STATS_HIST_FILE,
                 {'wgc_test': [{'ts': 100, 'rx_bytes': 10, 'tx_bytes': 5},
                               {'ts': 200, 'rx_bytes': 30, 'tx_bytes': 15}]})
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_client_history('wgt_test', 'wgc_test')
        self.assertEqual(cm.exception.status, 200)
        self.assertEqual(cm.exception.data['samples'],
                         [{'ts': 100, 'rx_bytes': 10, 'tx_bytes': 5},
                          {'ts': 200, 'rx_bytes': 30, 'tx_bytes': 15}])

    def test_client_history_empty_when_no_samples_yet(self):
        api.save(api.VPN_STATS_HIST_FILE, {})
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_client_history('wgt_test', 'wgc_test')
        self.assertEqual(cm.exception.status, 200)
        self.assertEqual(cm.exception.data['samples'], [])

    def test_client_history_unknown_client_404(self):
        api.save(api.VPN_STATS_HIST_FILE, {})
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_client_history('wgt_test', 'wgc_nope')
        self.assertEqual(cm.exception.status, 404)

    # ── #88: default tunnel-scope template ───────────────────────────────
    def test_default_template_empty_when_unset(self):
        api.method = lambda: 'GET'
        api.save(api.CONFIG_FILE, {})
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_default_template()
        self.assertEqual(cm.exception.status, 200)
        self.assertEqual(cm.exception.data['template'], {})

    def test_default_template_save_and_reload(self):
        api.method = lambda: 'POST'
        api.save(api.CONFIG_FILE, {})
        api.get_json_obj = lambda: {'allow_internet': False, 'reach_scope_type': 'site',
                                    'reach_scope_value': 'HQ', 'dns': '10.0.0.1'}
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_default_template()
        self.assertEqual(cm.exception.status, 200)
        self.assertEqual(cm.exception.data['template']['reach_scope_value'], 'HQ')
        self.assertEqual(api.load(api.CONFIG_FILE)['vpn_default_template']['dns'], '10.0.0.1')
        api.method = lambda: 'GET'
        with self.assertRaises(_Responded) as cm2:
            api.handle_vpn_default_template()
        self.assertEqual(cm2.exception.data['template']['reach_scope_type'], 'site')

    def test_default_template_rejects_invalid_scope(self):
        api.method = lambda: 'POST'
        api.save(api.CONFIG_FILE, {})
        api.get_json_obj = lambda: {'reach_scope_type': 'bogus'}
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_default_template()
        self.assertEqual(cm.exception.status, 400)

    def test_default_template_requires_scope_value_when_scoped(self):
        api.method = lambda: 'POST'
        api.save(api.CONFIG_FILE, {})
        api.get_json_obj = lambda: {'reach_scope_type': 'site', 'reach_scope_value': ''}
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_default_template()
        self.assertEqual(cm.exception.status, 400)

    # ── v6.1.1 (#7 stateless-audit follow-up): _wg_last_err thread-local fix ──
    def test_wg_last_err_not_a_bare_module_global(self):
        # It used to be, correct under CGI (fresh process per request), wrong
        # under gunicorn's persistent threaded workers.
        self.assertFalse(hasattr(api.vpn_handlers_mod, '_wg_last_err'))

    def test_wg_last_err_cleared_by_begin_request(self):
        api._RCTX.wg_last_err = 'stale error from an unrelated earlier request'
        api._begin_request()   # simulates the next request landing on this thread
        self.assertEqual(api._RCTX.wg_last_err, '')

    def test_stale_wg_last_err_does_not_leak_into_a_later_requests_400(self):
        # End-to-end: a value left behind by an earlier request on the same
        # reused thread must NOT surface in a later, unrelated request's error
        # detail once _begin_request() has run between them.
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'phone', 'pubkey': 'Q' * 43 + '='}
        api._RCTX.wg_last_err = 'stale error from an unrelated earlier request'
        api._begin_request()
        with self.assertRaises(_Responded) as cm:
            api.handle_vpn_client_create('wgt_test')   # hub_pubkey is '' in setUp
        self.assertEqual(cm.exception.status, 400)
        self.assertNotIn('stale error from an unrelated earlier request',
                         cm.exception.data['error'])


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for h in ('handle_vpn_tunnels_list', 'handle_vpn_tunnel_create',
                  'handle_vpn_tunnel_update', 'handle_vpn_tunnel_delete',
                  'handle_vpn_tunnel_stats', 'handle_vpn_clients_list',
                  'handle_vpn_client_create', 'handle_vpn_client_update',
                  'handle_vpn_client_delete', 'handle_vpn_client_stats',
                  'handle_vpn_client_history', 'run_vpn_stats_if_due'):
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

    def test_disabled_tunnel_is_torn_down_not_synced(self):
        # A disabled tunnel must be brought DOWN, not synced up — otherwise
        # disabling a tunnel to cut off access silently re-installs every peer.
        calls = []
        orig_run = api._wg_run
        orig_avail = api._wg_helper_available
        try:
            api._wg_helper_available = lambda: True
            api._wg_run = lambda argv, **kw: (calls.append(argv[0]), (0, '{}', ''))[1]
            self.assertTrue(api._vpn_sync_tunnel(
                {'iface': 'rp-wg0', 'pool': '10.97.0.0/24',
                 'enabled': False, 'clients': []}))
            self.assertEqual(calls, ['down'])
            calls.clear()
            api._vpn_sync_tunnel(
                {'iface': 'rp-wg0', 'pool': '10.97.0.0/24',
                 'enabled': True, 'reach_scope_type': 'none',
                 'allow_internet': False, 'clients': []})
            self.assertEqual(calls, ['sync'])
        finally:
            api._wg_run = orig_run
            api._wg_helper_available = orig_avail

    # ── #86: preshared key encrypted at rest + wired into the sync spec ─────
    def test_sync_decrypts_psk_onto_the_spec(self):
        old_key = os.environ.get('RP_CONFIG_KEY')
        calls = []
        orig_run = api._wg_run
        orig_avail = api._wg_helper_available
        try:
            os.environ['RP_CONFIG_KEY'] = 'test-master-key-for-vpn-psk'
            psk_plain = 'P' * 43 + '='
            psk_enc = api._cfg_enc(psk_plain)
            self.assertTrue(psk_enc.startswith('enc:'))   # actually encrypted, not fell-open
            api._wg_helper_available = lambda: True
            api._wg_run = lambda argv, **kw: (calls.append(kw.get('stdin')), (0, '{}', ''))[1]
            tunnel = {'iface': 'rp-wg0', 'pool': '10.97.0.0/24', 'enabled': True,
                      'reach_scope_type': 'none', 'allow_internet': False,
                      'clients': [{'pubkey': 'A' * 43 + '=', 'address': '10.97.0.2',
                                   'enabled': True, 'psk_enc': psk_enc}]}
            api._vpn_sync_tunnel(tunnel)
            self.assertEqual(len(calls), 1)
            import json as _json
            spec = _json.loads(calls[0])
            self.assertEqual(spec['peers'][0]['preshared_key'], psk_plain)
            # the stored client record itself was never mutated with plaintext
            self.assertEqual(tunnel['clients'][0]['psk_enc'], psk_enc)
            self.assertNotIn('preshared_key', tunnel['clients'][0])
        finally:
            api._wg_run = orig_run
            api._wg_helper_available = orig_avail
            if old_key is None:
                os.environ.pop('RP_CONFIG_KEY', None)
            else:
                os.environ['RP_CONFIG_KEY'] = old_key

    def test_sync_skips_psk_field_when_client_has_none(self):
        calls = []
        orig_run = api._wg_run
        orig_avail = api._wg_helper_available
        try:
            api._wg_helper_available = lambda: True
            api._wg_run = lambda argv, **kw: (calls.append(kw.get('stdin')), (0, '{}', ''))[1]
            tunnel = {'iface': 'rp-wg0', 'pool': '10.97.0.0/24', 'enabled': True,
                      'reach_scope_type': 'none', 'allow_internet': False,
                      'clients': [{'pubkey': 'A' * 43 + '=', 'address': '10.97.0.2',
                                   'enabled': True}]}
            api._vpn_sync_tunnel(tunnel)
            import json as _json
            spec = _json.loads(calls[0])
            self.assertNotIn('preshared_key', spec['peers'][0])
        finally:
            api._wg_run = orig_run
            api._wg_helper_available = orig_avail


class TestStatsCadenceHistory(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #87 — run_vpn_stats_if_due
    appends one history sample per client per poll (capped, rolling window),
    not just overwriting the current rx/tx snapshot on the client record."""

    def setUp(self):
        self._orig = {k: getattr(api, k) for k in
                      ('_wg_helper_available', '_wg_run', 'audit_log', 'fire_webhook')}
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api._wg_helper_available = lambda: True
        api.save(api.CONFIG_FILE, {})
        api.save(api.VPN_STATS_HIST_FILE, {})
        self.tunnel = {
            'id': 'wgt_h', 'name': 't', 'iface': 'rp-wg0', 'listen_port': 51820,
            'pool': '10.97.0.0/24', 'endpoint': '', 'dns': '', 'hub_pubkey': 'hub',
            'allow_internet': False, 'reach_scope_type': 'none', 'reach_scope_value': '',
            'enabled': True, 'expires_at': None,
            'clients': [{'id': 'wgc_h', 'name': 'laptop',
                        'pubkey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                        'address': '10.97.0.2', 'enabled': True, 'expires_at': None,
                        'created_by': 'admin', 'created_at': 0, 'last_handshake': 0,
                        'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''}]}
        api.save(api.VPN_FILE, {'tunnels': [self.tunnel]})

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _fake_dump(self, rx, tx, handshake=123456):
        pub = self.tunnel['clients'][0]['pubkey']
        # wg show <iface> dump: line 0 = interface, then tab-separated peer rows.
        return ('iface-priv\tiface-pub\t51820\toff\n'
                f'{pub}\t(none)\t203.0.113.5:51820\t10.97.0.2/32\t{handshake}\t{rx}\t{tx}\t0')

    def test_appends_one_sample_per_poll(self):
        api._wg_run = lambda argv, **kw: (0, self._fake_dump(100, 50), '') \
            if argv[0] == 'show' else (0, '{}', '')
        api.run_vpn_stats_if_due()
        hist = api.load(api.VPN_STATS_HIST_FILE)
        self.assertEqual(len(hist.get('wgc_h', [])), 1)
        self.assertEqual(hist['wgc_h'][0]['rx_bytes'], 100)
        self.assertEqual(hist['wgc_h'][0]['tx_bytes'], 50)
        # The client record's live snapshot is also updated, same as before.
        client = api.load(api.VPN_FILE)['tunnels'][0]['clients'][0]
        self.assertEqual(client['rx_bytes'], 100)

    def test_second_poll_appends_not_overwrites(self):
        api._wg_run = lambda argv, **kw: (0, self._fake_dump(100, 50), '') \
            if argv[0] == 'show' else (0, '{}', '')
        api.run_vpn_stats_if_due()
        # Force the cadence gate open again (bypassing the interval).
        cfg = api.load(api.CONFIG_FILE)
        cfg['last_vpn_stats_run'] = 0
        api.save(api.CONFIG_FILE, cfg)
        api._wg_run = lambda argv, **kw: (0, self._fake_dump(300, 150), '') \
            if argv[0] == 'show' else (0, '{}', '')
        api.run_vpn_stats_if_due()
        hist = api.load(api.VPN_STATS_HIST_FILE)['wgc_h']
        self.assertEqual(len(hist), 2)
        self.assertEqual([s['rx_bytes'] for s in hist], [100, 300])

    def test_history_capped_to_max_samples(self):
        api._wg_run = lambda argv, **kw: (0, self._fake_dump(1, 1), '') \
            if argv[0] == 'show' else (0, '{}', '')
        # Seed a full-but-one history directly (avoid N real cadence calls).
        api.save(api.VPN_STATS_HIST_FILE, {'wgc_h': [
            {'ts': i, 'rx_bytes': i, 'tx_bytes': i}
            for i in range(api.VPN_STATS_HIST_MAX_SAMPLES - 1)]})
        api.run_vpn_stats_if_due()
        hist = api.load(api.VPN_STATS_HIST_FILE)['wgc_h']
        self.assertEqual(len(hist), api.VPN_STATS_HIST_MAX_SAMPLES)
        api.save(api.CONFIG_FILE, {**api.load(api.CONFIG_FILE), 'last_vpn_stats_run': 0})
        api.run_vpn_stats_if_due()
        hist2 = api.load(api.VPN_STATS_HIST_FILE)['wgc_h']
        self.assertEqual(len(hist2), api.VPN_STATS_HIST_MAX_SAMPLES)   # still capped, not growing


if __name__ == '__main__':
    unittest.main()
