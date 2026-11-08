#!/usr/bin/env python3
"""8.0.0: three connectors for the networks that carry remote access: Tailscale, Headscale and Cloudflare Tunnel.

Pure layer, run against canned API JSON through a fake client (no network, no account): the shapes are the vendors' documented ones, not
a recording of a real tailnet or account, and that is said here so nobody reads these as a measurement of the real services.

What is held: the verdicts (a key that has run out is red, one that ends soon is amber, a host that is only offline is neither: phones and
laptops come and go and a standing amber tile is the one that gets ignored), that an abandoned host with an old key does not keep a tile red
for ever, that a shared-in host is not this tailnet's to keep alive, that the token goes in a header and never in the path or the query,
that a tailnet name is quoted into the path, that a malformed answer is a tile and not a traceback, and the small facts the page needs
(a stat-chip spec whose keys the connector really returns, a default address for the two SaaS APIs).
"""
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402

NEW = ('tailscale', 'headscale', 'cloudflare_tunnel')
ACCOUNT = 'a' * 32


def iso(days=0, seconds=0):
    return (datetime.now(timezone.utc) + timedelta(days=days, seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


class FakeClient(I.HTTPClient):
    def __init__(self, routes=None):
        super().__init__('https://api.example')
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        bare = path.split('?')[0]
        self.calls.append({'method': method, 'path': bare, 'headers': dict(headers or {}), 'params': dict(params or {}), 'full': path})
        v = self.routes.get(bare)
        if v is None:
            return I.Resp(404, '')
        st, payload = v
        return I.Resp(st, payload if isinstance(payload, str) else json.dumps(payload))


def ts_device(**kw):
    d = {'name': 'h.tail.ts.net', 'connectedToControl': True, 'lastSeen': iso(seconds=-30), 'expires': iso(days=90),
         'keyExpiryDisabled': False, 'updateAvailable': False, 'authorized': True, 'isExternal': False}
    d.update(kw)
    return d


def poll(kind, routes, **inst):
    base = {'type': kind, 'secret': 'tok'}
    base.update(inst)
    return I.poll_instance(base, FakeClient(routes))


TS = '/api/v2/tailnet/-/devices'
HS = '/api/v1/node'
CF = '/client/v4/accounts/%s/cfd_tunnel' % ACCOUNT


class TestRegistry(unittest.TestCase):
    def test_registered_with_chips_the_connector_really_returns(self):
        samples = {
            'tailscale': poll('tailscale', {TS: (200, {'devices': [ts_device()]})}),
            'headscale': poll('headscale', {HS: (200, {'nodes': [{'online': True, 'lastSeen': iso(), 'expiry': iso(days=60)}]})}),
            'cloudflare_tunnel': poll('cloudflare_tunnel', {CF: (200, {'success': True, 'result': [{'status': 'healthy', 'connections': [{}]}]})},
                                      slug=ACCOUNT),
        }
        for t in NEW:
            self.assertIn(t, I.CONNECTORS, t)
            chips = I._STATS.get(t)
            self.assertTrue(chips, '%s has no stat-chip spec' % t)
            for key, _label, _kind in chips:
                self.assertIn(key, samples[t]['metrics'], '%s: the chip %r is a number the connector never returns' % (t, key))

    def test_unreachable_is_critical_for_each(self):
        for t in NEW:
            self.assertEqual(poll(t, {}, slug=ACCOUNT)['status'], I.CRIT, t)

    def test_the_two_saas_apis_have_an_address_to_start_from(self):
        cat = {c['type']: c for c in I.list_connectors()}
        self.assertEqual(cat['tailscale']['default_url'], 'https://api.tailscale.com')
        self.assertEqual(cat['cloudflare_tunnel']['default_url'], 'https://api.cloudflare.com')
        self.assertEqual(cat['headscale']['default_url'], '', 'Headscale runs where you put it: there is no address to start from')
        for c in cat.values():
            self.assertIn('default_url', c)

    def test_the_notes_say_what_the_connector_reports(self):
        for t in NEW:
            self.assertGreater(len(I.CONNECTORS[t]['notes']), 40, t)


class TestTheClock(unittest.TestCase):
    def test_a_timestamp_is_read_with_fractions_offsets_and_the_zero_time(self):
        self.assertEqual(I._iso_epoch('2026-11-07T10:00:00Z'), 1794045600)
        self.assertEqual(I._iso_epoch('2026-11-07T11:00:00+01:00'), 1794045600)
        self.assertEqual(I._iso_epoch('2026-11-07T10:00:00.123456789Z'), 1794045600)
        self.assertEqual(I._iso_epoch('2026-11-07T10:00:00'), 1794045600, 'no offset is read as UTC')

    def test_nothing_that_is_not_a_date_is_a_date(self):
        for bad in (None, '', 5, 1.5, [], {}, 'never', '0001-01-01T00:00:00Z', '2026-13-45T99:00:00Z', 'x' * 40):
            with self.subTest(bad=repr(bad)[:30]):
                self.assertEqual(I._iso_epoch(bad), 0)


class TestTailscale(unittest.TestCase):
    def go(self, devices, **inst):
        return poll('tailscale', {TS: (200, {'devices': devices})}, **inst)

    def test_a_quiet_tailnet_is_ok(self):
        r = self.go([ts_device(), ts_device()])
        self.assertEqual(r['status'], I.OK)
        self.assertEqual((r['metrics']['devices'], r['metrics']['online'], r['metrics']['offline']), (2, 2, 0))
        self.assertIn('2 hosts, 2 online', r['detail'])

    def test_a_host_that_is_only_offline_is_not_a_warning(self):
        r = self.go([ts_device(), ts_device(connectedToControl=False, lastSeen=iso(days=-3))])
        self.assertEqual(r['status'], I.OK)
        self.assertEqual((r['metrics']['online'], r['metrics']['offline']), (1, 1))

    def test_a_key_that_ends_soon_is_amber(self):
        r = self.go([ts_device(expires=iso(days=10))])
        self.assertEqual(r['status'], I.WARN)
        self.assertEqual(r['metrics']['keys_expiring'], 1)

    def test_a_key_that_ends_in_two_months_is_not(self):
        self.assertEqual(self.go([ts_device(expires=iso(days=60))])['status'], I.OK)

    def test_a_key_that_has_run_out_on_a_host_seen_lately_is_red(self):
        r = self.go([ts_device(expires=iso(days=-1), connectedToControl=False, lastSeen=iso(days=-3))])
        self.assertEqual(r['status'], I.CRIT)
        self.assertEqual(r['metrics']['keys_expired'], 1)
        self.assertIn('run out', r['detail'])

    def test_an_abandoned_host_with_an_old_key_does_not_keep_the_tile_red(self):
        r = self.go([ts_device(expires=iso(days=-200), connectedToControl=False, lastSeen=iso(days=-200))])
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics']['keys_expired'], 0)

    def test_a_host_whose_key_never_expires_is_left_alone(self):
        r = self.go([ts_device(expires=iso(days=-5), keyExpiryDisabled=True)])
        self.assertEqual(r['status'], I.OK)

    def test_a_host_shared_in_from_another_tailnet_is_not_counted(self):
        r = self.go([ts_device(), ts_device(isExternal=True, expires=iso(days=-1))])
        self.assertEqual((r['metrics']['devices'], r['status']), (1, I.OK))

    def test_a_host_waiting_for_approval_is_amber_and_counted_once(self):
        r = self.go([ts_device(authorized=False)])
        self.assertEqual((r['status'], r['metrics']['unapproved']), (I.WARN, 1))

    def test_updates_are_counted_and_are_not_a_warning(self):
        r = self.go([ts_device(updateAvailable=True), ts_device()])
        self.assertEqual((r['status'], r['metrics']['updates']), (I.OK, 1))

    def test_without_the_live_flag_a_host_seen_a_moment_ago_is_online(self):
        d = ts_device()
        del d['connectedToControl']
        self.assertEqual(self.go([d])['metrics']['online'], 1)
        old = ts_device(lastSeen=iso(days=-1))
        del old['connectedToControl']
        self.assertEqual(self.go([old])['metrics']['online'], 0)

    def test_the_token_is_a_header_and_never_in_the_path_or_the_query(self):
        c = FakeClient({TS: (200, {'devices': []})})
        I.poll_instance({'type': 'tailscale', 'secret': 'tskey-api-SECRET'}, c)
        call = c.calls[0]
        self.assertEqual(call['headers'].get('Authorization'), 'Bearer tskey-api-SECRET')
        self.assertNotIn('SECRET', call['full'])

    def test_the_tailnet_name_is_quoted_into_the_path(self):
        for slug, want in (('example.com', '/api/v2/tailnet/example.com/devices'), ('', TS), ('  ', TS),
                           ('a/b', '/api/v2/tailnet/a%2Fb/devices'), ('../x', '/api/v2/tailnet/..%2Fx/devices'),
                           ('a b?c=d', '/api/v2/tailnet/a%20b%3Fc%3Dd/devices')):
            with self.subTest(slug=slug):
                c = FakeClient({want: (200, {'devices': []})})
                r = I.poll_instance({'type': 'tailscale', 'secret': 't', 'slug': slug}, c)
                self.assertEqual(c.calls[0]['path'], want)
                self.assertEqual(r['status'], I.OK)

    def test_a_malformed_answer_is_a_tile_and_not_a_traceback(self):
        for payload in ({}, {'devices': None}, {'devices': 'x'}, {'devices': [None, 5, 'a', [], {}]}, [], 'text', None):
            with self.subTest(payload=repr(payload)[:40]):
                r = poll('tailscale', {TS: (200, payload)})
                self.assertIn(r['status'], (I.OK, I.CRIT))
                self.assertNotIn('Error', r['detail'].split(':')[0] if r['status'] == I.OK else '')

    def test_wrong_typed_fields_do_not_break_a_host(self):
        r = self.go([ts_device(expires=5, lastSeen=[], connectedToControl='yes', authorized='no', updateAvailable=1)])
        self.assertIn(r['status'], (I.OK, I.WARN))
        self.assertEqual(r['metrics']['devices'], 1)

    def test_a_refused_token_names_the_path_not_the_token(self):
        r = poll('tailscale', {TS: (401, {'message': 'bad token'})}, secret='tskey-api-SECRET')
        self.assertEqual(r['status'], I.CRIT)
        self.assertIn('401', r['detail'])
        self.assertNotIn('SECRET', r['detail'])


class TestHeadscale(unittest.TestCase):
    def go(self, nodes):
        return poll('headscale', {HS: (200, {'nodes': nodes})})

    def test_counts_and_verdicts(self):
        ok = {'online': True, 'lastSeen': iso(seconds=-5), 'expiry': iso(days=120)}
        self.assertEqual(self.go([ok, dict(ok, online=False)])['status'], I.OK)
        r = self.go([dict(ok, expiry=iso(days=3))])
        self.assertEqual((r['status'], r['metrics']['keys_expiring']), (I.WARN, 1))
        r = self.go([dict(ok, online=False, lastSeen=iso(days=-2), expiry=iso(days=-1))])
        self.assertEqual((r['status'], r['metrics']['keys_expired']), (I.CRIT, 1))

    def test_a_node_with_no_expiry_has_no_key_to_run_out(self):
        r = self.go([{'online': False, 'lastSeen': iso(days=-1), 'expiry': '0001-01-01T00:00:00Z'},
                     {'online': True, 'lastSeen': iso(), 'expiry': None}])
        self.assertEqual((r['status'], r['metrics']['keys_expired'], r['metrics']['keys_expiring']), (I.OK, 0, 0))

    def test_the_key_is_a_header(self):
        c = FakeClient({HS: (200, {'nodes': []})})
        I.poll_instance({'type': 'headscale', 'secret': 'hskey'}, c)
        self.assertEqual(c.calls[0]['headers'].get('Authorization'), 'Bearer hskey')

    def test_a_malformed_answer_is_a_tile(self):
        for payload in ({}, {'nodes': None}, {'nodes': [None, 'x']}, [], 'x'):
            r = poll('headscale', {HS: (200, payload)})
            self.assertIn(r['status'], (I.OK, I.CRIT), repr(payload))


class TestCloudflareTunnel(unittest.TestCase):
    def go(self, tunnels, **inst):
        return poll('cloudflare_tunnel', {CF: (200, {'success': True, 'result': tunnels})}, slug=ACCOUNT, **inst)

    def t(self, status, name='t', conns=1):
        return {'name': name, 'status': status, 'connections': [{} for _ in range(conns)]}

    def test_healthy_is_ok_and_counts_connections(self):
        r = self.go([self.t('healthy', conns=4), self.t('healthy', conns=2)])
        self.assertEqual(r['status'], I.OK)
        self.assertEqual((r['metrics']['tunnels'], r['metrics']['healthy'], r['metrics']['connections']), (2, 2, 6))

    def test_degraded_is_amber_and_down_is_red_and_names_the_tunnel(self):
        self.assertEqual(self.go([self.t('healthy'), self.t('degraded')])['status'], I.WARN)
        r = self.go([self.t('healthy'), self.t('down', name='home-lab', conns=0)])
        self.assertEqual(r['status'], I.CRIT)
        self.assertIn('home-lab', r['detail'])

    def test_down_outranks_degraded(self):
        self.assertEqual(self.go([self.t('degraded'), self.t('down')])['status'], I.CRIT)

    def test_a_tunnel_that_never_ran_is_not_a_problem(self):
        r = self.go([self.t('inactive', conns=0), self.t('healthy')])
        self.assertEqual((r['status'], r['metrics']['inactive']), (I.OK, 1))

    def test_an_unknown_status_is_not_counted_as_anything(self):
        r = self.go([self.t('banana')])
        self.assertEqual((r['status'], r['metrics']['tunnels']), (I.OK, 0))

    def test_the_account_id_is_checked_before_a_request_is_made(self):
        for bad in ('', 'short', 'z' * 32, ACCOUNT + 'a', '../' + 'a' * 29, ACCOUNT + '/x', None):
            with self.subTest(bad=repr(bad)):
                c = FakeClient({CF: (200, {'success': True, 'result': []})})
                r = I.poll_instance({'type': 'cloudflare_tunnel', 'secret': 't', 'slug': bad}, c)
                self.assertEqual(r['status'], I.CRIT)
                self.assertEqual(c.calls, [], 'a bad account ID must not reach the network')
                self.assertIn('account ID', r['detail'])

    def test_a_refusal_in_the_body_is_shown_in_words(self):
        r = poll('cloudflare_tunnel', {CF: (200, {'success': False, 'errors': [{'code': 10000, 'message': 'Authentication error'}]})}, slug=ACCOUNT)
        self.assertEqual(r['status'], I.CRIT)
        self.assertIn('Authentication error', r['detail'])

    def test_the_request_asks_for_live_tunnels_with_a_header_token(self):
        c = FakeClient({CF: (200, {'success': True, 'result': []})})
        I.poll_instance({'type': 'cloudflare_tunnel', 'secret': 'cf-SECRET', 'slug': ACCOUNT}, c)
        call = c.calls[0]
        self.assertEqual(call['headers'].get('Authorization'), 'Bearer cf-SECRET')
        self.assertEqual(call['params'].get('is_deleted'), 'false')
        self.assertNotIn('SECRET', call['full'])

    def test_a_malformed_answer_is_a_tile(self):
        for payload in ({}, {'success': True}, {'success': True, 'result': None}, {'success': True, 'result': [None, 5, 'x']}, [], 'x'):
            r = poll('cloudflare_tunnel', {CF: (200, payload)}, slug=ACCOUNT)
            self.assertIn(r['status'], (I.OK, I.CRIT), repr(payload))


class TestTheSummary(unittest.TestCase):
    def test_it_is_a_pure_function_of_its_rows_and_the_clock_it_is_given(self):
        now = 1_000_000
        rows = [{'online': True, 'last_seen': now, 'expires': now + 5 * 86400}]
        self.assertEqual(I._overlay_summary(rows, now=now)['status'], I.WARN)
        # six days later the key has run out and the host was seen within the month: red
        self.assertEqual(I._overlay_summary(rows, now=now + 6 * 86400)['status'], I.CRIT)
        self.assertEqual(I._overlay_summary([], now=now)['status'], I.OK)

    def test_the_boundaries_are_the_documented_ones(self):
        now = 2_000_000
        day = 86400
        seen = now - 60
        on_edge = [{'online': True, 'last_seen': seen, 'expires': now + I._OVERLAY_SOON_DAYS * day}]
        past_edge = [{'online': True, 'last_seen': seen, 'expires': now + I._OVERLAY_SOON_DAYS * day + 1}]
        self.assertEqual(I._overlay_summary(on_edge, now=now)['status'], I.WARN)
        self.assertEqual(I._overlay_summary(past_edge, now=now)['status'], I.OK)
        recent = [{'online': False, 'last_seen': now - I._OVERLAY_SEEN_DAYS * day, 'expires': now - 1}]
        stale = [{'online': False, 'last_seen': now - I._OVERLAY_SEEN_DAYS * day - 1, 'expires': now - 1}]
        self.assertEqual(I._overlay_summary(recent, now=now)['status'], I.CRIT)
        self.assertEqual(I._overlay_summary(stale, now=now)['status'], I.OK)


if __name__ == '__main__':
    unittest.main()
