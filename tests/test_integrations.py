#!/usr/bin/env python3
"""Tests for the v4.7.0 homelab software integrations subsystem.

Two layers:
  * the pure connector module (integrations.py) — every connector parsed against
    canned API JSON via a fake HTTP client (no network);
  * the api.py wiring — config redaction, secret preservation, SSRF rejection,
    poll→persist→alert transitions, and the event-registry registration.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402


class FakeClient(I.HTTPClient):
    """Canned-response client: routes is {path_without_query: (status, payload)}.
    payload may be a dict/list (JSON-encoded) or a raw string. A 3-tuple adds
    response headers."""
    def __init__(self, base='http://x', routes=None):
        super().__init__(base)
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path))
        key = path.split('?')[0]
        v = self.routes.get(key)
        if v is None:
            return I.Resp(404, '')
        if len(v) == 3:
            st, payload, hdrs = v
        else:
            st, payload = v
            hdrs = {}
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return I.Resp(st, text, hdrs)


class TestConnectorRegistry(unittest.TestCase):
    def test_all_waves_present(self):
        types = set(I.CONNECTORS)
        expected = {
            'pihole', 'adguard', 'truenas', 'unifi', 'homeassistant',   # A
            'pbs', 'kubernetes', 'vcenter', 'unraid',                   # B
            'traefik', 'npm', 'caddy',                                  # C
            'uptimekuma', 'netdata', 'grafana',                        # D
            'jellyfin', 'plex', 'nextcloud',                           # E
            'sabnzbd', 'nzbget', 'qbittorrent', 'transmission',        # F
            'deluge', 'servarr', 'bazarr', 'overseerr',                # F
        }
        self.assertTrue(expected.issubset(types), expected - types)

    def test_catalog_shape(self):
        for c in I.list_connectors():
            self.assertIn('type', c)
            self.assertIn('label', c)
            self.assertIn('category', c)
            self.assertIsInstance(c['fields'], list)
            for f in c['fields']:
                self.assertIn(f['key'], ('secret', 'username', 'slug'))
                self.assertIn(f['kind'], (I.TEXT, I.PASSWORD))

    def test_secret_field_naming_redactable(self):
        # The primary credential must be named 'secret' (or be the non-secret
        # 'username'/'slug') so the config scrubber redacts it.
        for c in I.CONNECTORS.values():
            for f in c['fields']:
                if f['kind'] == I.PASSWORD:
                    self.assertIn(f['key'], ('secret', 'username'), c['type'])


class TestPollInstanceSafety(unittest.TestCase):
    def test_unknown_type(self):
        r = I.poll_instance({'type': 'nope'}, FakeClient())
        self.assertEqual(r['status'], I.UNKNOWN)

    def test_unreachable_is_critical(self):
        r = I.poll_instance({'type': 'servarr', 'secret': 'k'}, FakeClient(routes={}))
        self.assertEqual(r['status'], I.CRIT)

    def test_never_raises_on_parser_bug(self):
        # A connector that gets garbage JSON must degrade, not raise.
        c = FakeClient(routes={'/api/v3/system/status': (200, 'not json')})
        r = I.poll_instance({'type': 'servarr', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.CRIT)


class TestConnectors(unittest.TestCase):
    def test_servarr_health_levels(self):
        base = {'/api/v3/system/status': (200, {'appName': 'Sonarr', 'version': '4.0'})}
        # healthy
        c = FakeClient(routes={**base, '/api/v3/health': (200, [])})
        self.assertEqual(I.poll_instance({'type': 'servarr', 'secret': 'k'}, c)['status'], I.OK)
        # warning
        c = FakeClient(routes={**base, '/api/v3/health': (200, [{'type': 'warning', 'message': 'x'}])})
        self.assertEqual(I.poll_instance({'type': 'servarr', 'secret': 'k'}, c)['status'], I.WARN)
        # error → critical
        c = FakeClient(routes={**base, '/api/v3/health': (200, [{'type': 'error', 'message': 'indexer down'}])})
        r = I.poll_instance({'type': 'servarr', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.CRIT)
        self.assertIn('indexer down', r['detail'])

    def test_truenas_pool_degraded(self):
        c = FakeClient(routes={
            '/api/v2.0/system/info': (200, {'version': 'SCALE-24'}),
            '/api/v2.0/pool': (200, [{'name': 'tank', 'status': 'ONLINE'},
                                     {'name': 'cold', 'status': 'DEGRADED'}]),
            '/api/v2.0/alert/list': (200, []),
        })
        r = I.poll_instance({'type': 'truenas', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.CRIT)
        self.assertEqual(r['metrics']['pools_bad'], 1)

    def test_pihole_v6_session(self):
        c = FakeClient(routes={
            '/api/auth': (200, {'session': {'sid': 's', 'valid': True}}),
            '/api/stats/summary': (200, {'queries': {'total': 500, 'blocked': 50, 'percent_blocked': 10.0},
                                         'gravity': {'domains_being_blocked': 1000}}),
            '/api/info/version': (200, {'version': {'core': {'local': {'version': 'v6.0'}}}}),
        })
        r = I.poll_instance({'type': 'pihole', 'secret': 'pw'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['version'], 'v6.0')

    def test_adguard_protection_off_warns(self):
        c = FakeClient(routes={
            '/control/status': (200, {'running': True, 'protection_enabled': False, 'version': '0.107'}),
            '/control/stats': (200, {'num_dns_queries': 100, 'num_blocked_filtering': 5}),
        })
        r = I.poll_instance({'type': 'adguard', 'username': 'a', 'secret': 'b'}, c)
        self.assertEqual(r['status'], I.WARN)

    def test_transmission_409_handshake(self):
        # First POST returns 409 + session id; connector retries with the header.
        routes = {'/transmission/rpc': (409, '', {'X-Transmission-Session-Id': 'sess'})}
        c = FakeClient(routes=routes)

        # patch the route to succeed on the retry by swapping after first call
        orig = c.request
        state = {'n': 0}
        def req(method, path, headers=None, params=None, body=None):
            state['n'] += 1
            if path == '/transmission/rpc' and state['n'] >= 2:
                return I.Resp(200, json.dumps({'arguments': {'torrentCount': 3, 'activeTorrentCount': 1,
                                                             'downloadSpeed': 2048}}))
            return orig(method, path, headers, params, body)
        c.request = req
        r = I.poll_instance({'type': 'transmission'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics']['torrents'], 3)

    def test_kubernetes_notready_critical(self):
        c = FakeClient(routes={
            '/api/v1/nodes': (200, {'items': [
                {'metadata': {'name': 'n1'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}},
                {'metadata': {'name': 'n2'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'False'}]}},
            ]}),
            '/api/v1/pods': (200, {'items': []}),
        })
        r = I.poll_instance({'type': 'kubernetes', 'secret': 't'}, c)
        self.assertEqual(r['status'], I.CRIT)
        self.assertEqual(r['metrics']['nodes_notready'], 1)

    def test_overseerr_update_warns(self):
        c = FakeClient(routes={
            '/api/v1/status': (200, {'version': '1.33', 'updateAvailable': True}),
            '/api/v1/request/count': (200, {'pending': 4}),
        })
        r = I.poll_instance({'type': 'overseerr', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.WARN)
        self.assertEqual(r['metrics']['pending_requests'], 4)


# ── api.py wiring ──────────────────────────────────────────────────────────────
def _load_api():
    os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
    spec = importlib.util.spec_from_file_location('api_integ', _CGI / 'api.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestRichTiles(unittest.TestCase):
    """v4.7.0 rich tiles: format_stats + the widget/page wiring."""

    def test_format_stats_shapes(self):
        s = dict((x['label'], x['value']) for x in I.format_stats(
            'pihole', {'queries_today': 12300, 'blocked_pct': 18.4, 'domains_blocked': 990}))
        self.assertEqual(s['Queries'], '12.3k')
        self.assertEqual(s['Blocked'], '18%')

    def test_format_stats_rate_rolls_to_mbs(self):
        s = dict((x['label'], x['value']) for x in I.format_stats(
            'qbittorrent', {'torrents': 5, 'download_kbs': 2150}))
        self.assertEqual(s['Torrents'], '5')
        self.assertEqual(s['Down'], '2.1 MB/s')          # >1000 KB/s → MB/s
        slow = dict((x['label'], x['value']) for x in I.format_stats(
            'qbittorrent', {'download_kbs': 300}))
        self.assertEqual(slow['Down'], '300 KB/s')

    def test_format_stats_flag_and_missing(self):
        s = I.format_stats('nextcloud', {'users': 12, 'update_available': True})
        self.assertIn({'label': 'Update', 'value': 'yes'}, s)
        self.assertEqual(I.format_stats('plex', {}), [])      # absent metric skipped
        self.assertEqual(I.format_stats('nope', {'x': 1}), [])  # unknown type

    def test_every_connector_has_a_stat_spec(self):
        # Each registered connector should expose at least one headline chip.
        for t in I.CONNECTORS:
            self.assertIn(t, I._STATS, f'{t} has no stat-chip spec')
            self.assertTrue(I._STATS[t])

    def test_page_and_widget_wired(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        i18n = (_ROOT / 'server/html/static/js/i18n.js').read_text()
        # dedicated page + nav
        self.assertIn('data-page="integrations"', html)
        self.assertIn('id="page-integrations"', html)
        self.assertIn('id="integrations-page-tiles"', html)
        # shared tile renderer + loaders + activity route
        self.assertIn('function _integrationTiles(', js)
        self.assertIn('function loadIntegrationsPage(', js)
        self.assertIn("if (name === 'integrations') loadIntegrationsPage();", js)
        # the widget carries the lg tile grid (server provides items+stats)
        self.assertIn('integ-tiles-mini', js)
        # i18n gate: nav label + page title need a DICT entry
        self.assertIn("'Integrations':", i18n)

    def test_server_emits_items_and_stats(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("roll['items'] = items", src)          # widget per-integration tiles
        self.assertIn("safe['last_stats'] = integrations_mod.format_stats", src)  # list endpoint


class TestApiWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    def test_events_registered_everywhere(self):
        api = self.api
        for ev in ('integration_down', 'integration_recovered'):
            self.assertIn(ev, api.WEBHOOK_EVENT_NAMES, ev)
        self.assertIn('integration_down', api._ALERT_RULES)
        self.assertEqual(api._ALERT_RECOVER['integration_recovered'], 'integration_down')
        kinds = {k[0] for k in api.CHANNEL_KINDS}
        self.assertIn('integration', kinds)

    def test_routes_registered(self):
        routes = self.api._build_exact_routes()
        self.assertIn(('GET', '/api/integrations'), routes)
        self.assertIn(('POST', '/api/integrations'), routes)
        self.assertIn(('POST', '/api/integrations/test'), routes)
        self.assertIn(('GET', '/api/integrations/status'), routes)

    def test_cadence_hook_present(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("_safe(run_integrations_if_due, 'run_integrations_if_due')", src)

    def test_redact_drops_secret(self):
        safe = self.api._redact_integration({'id': 'x', 'type': 'pihole', 'secret': 'topsecret', 'url': 'http://p'})
        self.assertNotIn('secret', safe)
        self.assertTrue(safe['secret_set'])
        self.assertEqual(safe['url'], 'http://p')

    def test_config_scrubber_removes_integration_secret(self):
        # Defence-in-depth: the recursive config scrubber also nukes 'secret'.
        cfg = {'integrations': [{'id': 'x', 'type': 'pihole', 'secret': 'leak'}]}
        self.api._scrub_config_secrets(cfg)
        self.assertNotIn('secret', cfg['integrations'][0])

    def test_persist_alert_transitions(self):
        api = self.api
        cfg = api.load(api.CONFIG_FILE)
        cfg['integrations'] = [{'id': 'i1', 'type': 'truenas'}]   # a polled instance is configured
        api.save(api.CONFIG_FILE, cfg)
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, p: fired.append((ev, p))
        try:
            api._persist_integration_results([{'id': 'i1', 'label': 'TrueNAS', 'type': 'truenas',
                                               'status': 'critical', 'detail': 'pool DEGRADED',
                                               'checked': 1, 'metrics': {}}])
            self.assertEqual(fired[0][0], 'integration_down')
            self.assertEqual(fired[0][1]['severity'], 'high')
            fired.clear()
            api._persist_integration_results([{'id': 'i1', 'label': 'TrueNAS', 'type': 'truenas',
                                               'status': 'ok', 'detail': 'healthy', 'checked': 2, 'metrics': {}}])
            self.assertEqual(fired[0][0], 'integration_recovered')
            fired.clear()
            # steady state — no duplicate
            api._persist_integration_results([{'id': 'i1', 'label': 'TrueNAS', 'type': 'truenas',
                                               'status': 'ok', 'detail': 'healthy', 'checked': 3, 'metrics': {}}])
            self.assertEqual(fired, [])
        finally:
            api.fire_webhook = orig

    def test_ssrf_client_blocks_metadata(self):
        # No network: the pre-flight DNS check rejects the cloud-metadata IP.
        client = self.api._SSRFIntegrationClient('http://169.254.169.254', verify_tls=False)
        with self.assertRaises(I.IntegrationError):
            client.request('GET', '/latest/meta-data/')


class TestSecurityFixes(unittest.TestCase):
    """Regression tests for the v4.7.0 security review findings."""

    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    def test_integration_down_reaches_inbox(self):
        # Finding 1 (HIGH): integration_down must get a non-None severity, or it
        # fires a webhook but never lands in the Alerts inbox.
        self.assertEqual(self.api._alert_severity('integration_down', {'severity': 'high'}), 'high')
        self.assertEqual(self.api._alert_severity('integration_down', {'severity': 'medium'}), 'medium')
        self.assertEqual(self.api._alert_severity('integration_down', {}), 'medium')      # default
        self.assertIsNotNone(self.api._alert_severity('integration_down', {'severity': 'x'}))

    def test_integration_down_title_has_label(self):
        t = self.api._alert_title('integration_down', {'label': 'TrueNAS', 'detail': 'pool DEGRADED'})
        self.assertIn('TrueNAS', t)
        self.assertNotIn('integration_down', t)   # not the bare event name

    def test_no_ctrl_strips_crlf(self):
        # Finding 5: credential fields are stripped of control chars before they
        # reach an HTTP header.
        self.assertEqual(self.api._no_ctrl('tok\r\nX-Evil: 1'), 'tokX-Evil: 1')
        self.assertEqual(self.api._no_ctrl('a\x00b\x1fc\x7fd'), 'abcd')

    def test_poll_budget_constants(self):
        # Finding 2: a per-cycle wall-clock budget + bounded per-call timeout exist.
        self.assertLessEqual(self.api._INTEGRATIONS_POLL_BUDGET_S, 30)
        self.assertLessEqual(self.api._INTEGRATION_HTTP_TIMEOUT_S, 10)
        src = (_CGI / 'api.py').read_text()
        self.assertIn('time.monotonic() > budget', src)

    def test_persist_keeps_configured_but_unpolled(self):
        # Finding 6: an integration that exists in config but wasn't polled this
        # cycle keeps its history (don't purge based on the polled batch).
        api = self.api
        cfg = api.load(api.CONFIG_FILE)
        cfg['integrations'] = [{'id': 'keep', 'type': 'pihole'}, {'id': 'gone', 'type': 'pihole'}]
        api.save(api.CONFIG_FILE, cfg)
        # seed history for both
        api._persist_integration_results([
            {'id': 'keep', 'label': 'k', 'type': 'pihole', 'status': 'ok', 'detail': '', 'checked': 1, 'metrics': {}},
            {'id': 'gone', 'label': 'g', 'type': 'pihole', 'status': 'ok', 'detail': '', 'checked': 1, 'metrics': {}},
        ])
        # next cycle polls only 'keep' (budget skipped 'gone') — 'gone' still configured
        api._persist_integration_results([
            {'id': 'keep', 'label': 'k', 'type': 'pihole', 'status': 'ok', 'detail': '', 'checked': 2, 'metrics': {}},
        ])
        latest = (api.load(api.INTEG_STATE_FILE) or {}).get('latest') or {}
        self.assertIn('gone', latest, 'configured-but-unpolled integration was wrongly purged')
        # remove 'gone' from config → now it should be purged
        cfg = api.load(api.CONFIG_FILE)
        cfg['integrations'] = [{'id': 'keep', 'type': 'pihole'}]
        api.save(api.CONFIG_FILE, cfg)
        api._persist_integration_results([
            {'id': 'keep', 'label': 'k', 'type': 'pihole', 'status': 'ok', 'detail': '', 'checked': 3, 'metrics': {}},
        ])
        latest = (api.load(api.INTEG_STATE_FILE) or {}).get('latest') or {}
        self.assertNotIn('gone', latest, 'removed integration should be purged')

    def test_url_gated_behind_admin(self):
        # The raw url (which could embed creds) is admin-only; viewers get url_set.
        inst = {'id': 'x', 'type': 'pihole', 'url': 'https://user:pass@pi.lan', 'secret': 's'}
        adm = self.api._redact_integration(inst, admin=True)
        self.assertEqual(adm['url'], 'https://user:pass@pi.lan')
        self.assertNotIn('secret', adm)
        viewer = self.api._redact_integration(inst, admin=False)
        self.assertNotIn('url', viewer)
        self.assertTrue(viewer['url_set'])
        self.assertNotIn('secret', viewer)

    def test_show_homelab_in_payloads(self):
        # The instance-wide flag round-trips through the integrations list response.
        src = (_CGI / 'api.py').read_text()
        self.assertIn("'show_homelab': cfg.get('show_homelab', True) is not False", src)
        # gated widget exists in the server allowlist
        self.assertIn('integrations', self.api.DASHBOARD_WIDGETS)


if __name__ == '__main__':
    unittest.main()
