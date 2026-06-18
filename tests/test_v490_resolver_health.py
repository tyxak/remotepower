"""v4.9.0 ResolutionMatters #3 — resolver health monitor.

Module logic with an injected fake resolver + fake clock (no real DNS), plus
api.py wiring (routes, webhook-event registration across every registry)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import dns.resolver  # noqa: E402
import dns_resolve as DR  # noqa: E402
import resolver_health as RH  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_v490_rh', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Rdata:
    def __init__(self, t):
        self._t = t

    def to_text(self):
        return self._t


class _Answer:
    def __init__(self, texts):
        self.rrset = [_Rdata(t) for t in texts] if texts is not None else None


class _FakeResolver:
    def __init__(self, ip, table):
        self.ip, self.table = ip, table

    def resolve(self, name, rtype, raise_on_no_answer=False):
        v = self.table.get((self.ip, name.rstrip('.'), rtype.upper()), [])
        if v == 'NXDOMAIN':
            raise dns.resolver.NXDOMAIN()
        if v == 'TIMEOUT':
            raise dns.exception.Timeout()
        return _Answer(v)


def _factory(table):
    return lambda ip, timeout: _FakeResolver(ip, table)


def _clock_seq(values):
    """A fake monotonic clock returning successive values (for latency timing)."""
    it = iter(values)
    return lambda: next(it)


class TestCheckTarget(unittest.TestCase):
    def test_all_healthy(self):
        table = {(ip, 'example.com', 'A'): ['93.184.216.34'] for _, ip in DR.PUBLIC_RESOLVERS}
        r = RH.check_target('example.com', 'A', _resolver_factory=_factory(table))
        self.assertTrue(r['healthy'])
        self.assertFalse(r['down'])
        self.assertEqual(r['ok_count'], r['total'])
        self.assertEqual(r['fail_count'], 0)

    def test_down_when_all_fail(self):
        table = {(ip, 'gone.example', 'A'): 'TIMEOUT' for _, ip in DR.PUBLIC_RESOLVERS}
        r = RH.check_target('gone.example', 'A', _resolver_factory=_factory(table))
        self.assertTrue(r['down'])
        self.assertFalse(r['healthy'])
        self.assertEqual(r['fail_count'], r['total'])
        self.assertEqual(r['ok_count'], 0)

    def test_nxdomain_counted_separately_not_down_if_one_ok(self):
        table = {(ip, 'host.example', 'A'): 'NXDOMAIN' for _, ip in DR.PUBLIC_RESOLVERS}
        first_ip = DR.PUBLIC_RESOLVERS[0][1]
        table[(first_ip, 'host.example', 'A')] = ['203.0.113.9']
        r = RH.check_target('host.example', 'A', _resolver_factory=_factory(table))
        self.assertEqual(r['nxdomain_count'], r['total'] - 1)
        self.assertEqual(r['ok_count'], 1)
        self.assertFalse(r['down'])          # one resolver still answers
        self.assertFalse(r['healthy'])       # but not all → not healthy

    def test_latency_mean_over_ok(self):
        table = {(ip, 'ex.com', 'A'): ['1.2.3.4'] for _, ip in DR.PUBLIC_RESOLVERS}
        # clock pairs: each resolve consumes start,end; deltas 10ms,20ms,30ms,40ms
        seq = []
        for i in range(len(DR.PUBLIC_RESOLVERS)):
            seq += [i, i + (i + 1) / 100.0]   # delta = (i+1)*10ms
        r = RH.check_target('ex.com', 'A', _resolver_factory=_factory(table),
                            _clock=_clock_seq(seq))
        self.assertGreater(r['latency_ms'], 0)
        self.assertGreaterEqual(r['max_latency_ms'], r['latency_ms'])


class TestScanFlapDampening(unittest.TestCase):
    def setUp(self):
        self._orig = RH.check_target

    def tearDown(self):
        RH.check_target = self._orig

    def test_unhealthy_fires_only_after_confirm(self):
        RH.check_target = lambda name, rtype: {
            'total': 4, 'ok_count': 0, 'nxdomain_count': 0, 'fail_count': 4,
            'latency_ms': 0, 'max_latency_ms': 0, 'healthy': False, 'down': True,
            'per_resolver': []}
        targets = {'rslv_a': {'name': 'down.example', 'type': 'A', 'label': ''}}
        results = {}
        # First scan: streak 1 < CONFIRM → no alert yet.
        pending, scanned = api._scan_resolver_health(targets, results)
        self.assertEqual(scanned, 1)
        self.assertEqual(pending, [])
        # Second scan (force due): streak hits CONFIRM → resolver_unhealthy.
        results['rslv_a']['checked_at'] = 0
        pending, _ = api._scan_resolver_health(targets, results)
        self.assertEqual([e for e, _ in pending], ['resolver_unhealthy'])
        self.assertTrue(results['rslv_a']['alerted'])

    def test_recovered_fires_when_back(self):
        targets = {'rslv_a': {'name': 'flap.example', 'type': 'A', 'label': ''}}
        results = {'rslv_a': {'alerted': True, 'down_streak': 5, 'checked_at': 0}}
        RH.check_target = lambda name, rtype: {
            'total': 4, 'ok_count': 4, 'nxdomain_count': 0, 'fail_count': 0,
            'latency_ms': 12, 'max_latency_ms': 20, 'healthy': True, 'down': False,
            'per_resolver': []}
        pending, _ = api._scan_resolver_health(targets, results)
        self.assertEqual([e for e, _ in pending], ['resolver_recovered'])
        self.assertFalse(results['rslv_a']['alerted'])


class TestAutoResolveRealPath(unittest.TestCase):
    """Exercise _record_alert -> _auto_resolve_alerts via the REAL payload
    whitelist (the existing integration test hand-builds the alert, which hid the
    bug where recover events couldn't find the open alert to close)."""

    def _open_ids(self):
        store = api.load(api.ALERTS_FILE) or {}
        return [a for a in store.get('alerts', [])
                if not a.get('resolved_at')]

    def test_resolver_recovered_resolves_open_alert(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('resolver_unhealthy',
                          {'target': 'mail.example.com', 'rtype': 'A', 'label': 'mx'})
        # The match key (target) must actually be stored on the alert.
        opened = self._open_ids()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]['payload'].get('target'), 'mail.example.com')
        api._auto_resolve_alerts('resolver_recovered', {'target': 'mail.example.com'})
        self.assertEqual(len(self._open_ids()), 0)   # now resolved

    def test_ip_blacklist_cleared_resolves_open_alert(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('ip_blacklisted',
                          {'ip': '203.0.113.7', 'label': '', 'listed_count': 2,
                           'blocklists': 'zen'})
        self.assertEqual(self._open_ids()[0]['payload'].get('ip'), '203.0.113.7')
        api._auto_resolve_alerts('ip_blacklist_cleared', {'ip': '203.0.113.7'})
        self.assertEqual(len(self._open_ids()), 0)

    def test_integration_recovered_resolves_open_alert(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('integration_down',
                          {'integration_id': 'pihole1', 'label': 'Pi-hole',
                           'severity': 'high', 'detail': 'unreachable'})
        self.assertEqual(self._open_ids()[0]['payload'].get('integration_id'), 'pihole1')
        api._auto_resolve_alerts('integration_recovered', {'integration_id': 'pihole1'})
        self.assertEqual(len(self._open_ids()), 0)


class TestApiWiring(unittest.TestCase):
    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/resolver-health/targets'), routes)
        self.assertIn(('POST', '/api/resolver-health/targets'), routes)
        self.assertIn(('POST', '/api/resolver-health/scan'), routes)

    def test_events_in_every_registry(self):
        events = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn('resolver_unhealthy', events)
        self.assertIn('resolver_recovered', events)
        self.assertIn('resolver_unhealthy', api._ALERT_RULES)          # severity → inbox
        self.assertEqual(api._ALERT_RECOVER.get('resolver_recovered'),
                         'resolver_unhealthy')
        kinds = {k[0] for k in api.CHANNEL_KINDS}
        self.assertIn('resolver', kinds)
        for ev in ('resolver_unhealthy', 'resolver_recovered'):
            self.assertNotIn('?', api._webhook_title(ev) or '?')

    def test_module_alias(self):
        self.assertIs(api.resolver_health_mod, RH)


if __name__ == '__main__':
    unittest.main()
