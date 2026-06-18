"""v4.9.0 ResolutionMatters — dns_resolve.py (live resolve/dig + propagation).

Pure-logic tests with an injected fake resolver factory — no real DNS."""
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
import dns_resolve as R  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_v490_resolve', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Rdata:
    def __init__(self, text):
        self._t = text

    def to_text(self):
        return self._t


class _Answer:
    def __init__(self, texts):
        self.rrset = [_Rdata(t) for t in texts] if texts is not None else None


class _FakeResolver:
    """Mimics dns.resolver.Resolver for one pinned nameserver IP. `table` maps
    (ip, name, TYPE) -> list[str] answers, or the str 'NXDOMAIN'/'TIMEOUT'."""
    def __init__(self, ip, table):
        self.ip = ip
        self.table = table

    def resolve(self, name, rtype, raise_on_no_answer=False):
        key = (self.ip, name.rstrip('.'), rtype.upper())
        val = self.table.get(key, [])
        if val == 'NXDOMAIN':
            raise dns.resolver.NXDOMAIN()
        if val == 'TIMEOUT':
            raise dns.exception.Timeout()
        return _Answer(val)


def _factory(table):
    return lambda ip, timeout: _FakeResolver(ip, table)


class TestValidation(unittest.TestCase):
    def test_valid_name(self):
        for ok in ('example.com', 'a.b.example.com', '_dmarc.example.com',
                   'example.com.', 'x-y.example.io'):
            self.assertTrue(R.valid_name(ok), ok)

    def test_invalid_name(self):
        for bad in ('', '   ', 'no spaces.com', '-bad.com', 'a..b.com',
                    'x' * 300 + '.com', 'http://example.com', 'a/b.com', None):
            self.assertFalse(R.valid_name(bad), repr(bad))

    def test_valid_type(self):
        self.assertTrue(R.valid_type('a'))
        self.assertTrue(R.valid_type('TXT'))
        self.assertFalse(R.valid_type('ANY'))
        self.assertFalse(R.valid_type(''))

    def test_blocked_ip(self):
        for bad in ('127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254',
                    '::1', 'not-an-ip', '0.0.0.0'):
            self.assertTrue(R._blocked_ip(bad), bad)
        for ok in ('1.1.1.1', '8.8.8.8', '93.184.216.34'):
            self.assertFalse(R._blocked_ip(ok), ok)


class TestResolvePublic(unittest.TestCase):
    def test_all_public_resolvers_queried(self):
        table = {(ip, 'example.com', 'A'): ['93.184.216.34']
                 for _, ip in R.PUBLIC_RESOLVERS}
        out = R.resolve_public('example.com', 'A', _resolver_factory=_factory(table))
        self.assertEqual(len(out), len(R.PUBLIC_RESOLVERS))
        self.assertTrue(all(r['answers'] == ['93.184.216.34'] for r in out))
        self.assertEqual({r['resolver'] for r in out},
                         {label for label, _ in R.PUBLIC_RESOLVERS})

    def test_nxdomain_and_timeout_surface_as_errors(self):
        table = {(ip, 'gone.example', 'A'): 'NXDOMAIN' for _, ip in R.PUBLIC_RESOLVERS}
        table[('1.1.1.1', 'gone.example', 'A')] = 'TIMEOUT'
        out = R.resolve_public('gone.example', 'A', _resolver_factory=_factory(table))
        errs = {r['ip']: r['error'] for r in out}
        self.assertEqual(errs['1.1.1.1'], 'timeout')
        self.assertEqual(errs['8.8.8.8'], 'NXDOMAIN')


class TestAuthoritative(unittest.TestCase):
    def _table(self):
        pub = R.PUBLIC_RESOLVERS[0][1]   # NS discovery uses the first public resolver
        return {
            (pub, 'example.com', 'NS'): ['ns1.example.com.', 'ns2.example.com.'],
            (pub, 'ns1.example.com', 'A'): ['93.184.216.34'],
            (pub, 'ns2.example.com', 'A'): ['10.0.0.9'],   # private → filtered out
            ('93.184.216.34', 'www.example.com', 'A'): ['198.51.100.50'],
        }

    def test_ns_discovery_filters_private_ips(self):
        nss = R.authoritative_ns('www.example.com', _resolver_factory=_factory(self._table()))
        self.assertEqual(nss, [{'ns': 'ns1.example.com', 'ip': '93.184.216.34'}])

    def test_walks_up_to_zone_for_subdomain(self):
        # NS only exists at example.com, but we query a deep subdomain.
        out = R.resolve_authoritative('www.example.com', 'A',
                                      _resolver_factory=_factory(self._table()))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['ns'], 'ns1.example.com')
        self.assertEqual(out[0]['answers'], ['198.51.100.50'])


class TestPropagation(unittest.TestCase):
    def test_counts_matching_resolvers(self):
        table = {}
        for i, (_, ip) in enumerate(R.PUBLIC_RESOLVERS):
            # first half already serve the new value, rest still serve the old
            table[(ip, 'host.example', 'A')] = ['203.0.113.99'] if i < 2 else ['203.0.113.1']
        res = R.propagation('host.example', 'A', expected='203.0.113.99',
                            _resolver_factory=_factory(table))
        self.assertEqual(res['total'], len(R.PUBLIC_RESOLVERS))
        self.assertEqual(res['propagated'], 2)
        self.assertEqual(sum(1 for r in res['resolvers'] if r['match']), 2)

    def test_no_expected_counts_any_answer(self):
        table = {(ip, 'host.example', 'TXT'): ['"v=spf1 -all"'] for _, ip in R.PUBLIC_RESOLVERS}
        table[(R.PUBLIC_RESOLVERS[0][1], 'host.example', 'TXT')] = 'NXDOMAIN'
        res = R.propagation('host.example', 'TXT', _resolver_factory=_factory(table))
        self.assertEqual(res['propagated'], len(R.PUBLIC_RESOLVERS) - 1)


class TestApiWiring(unittest.TestCase):
    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/dns/resolve'), routes)
        self.assertIn(('GET', '/api/dns/propagation'), routes)

    def test_handlers_admin_gated(self):
        # Both handlers must require admin auth — assert the source calls it.
        import inspect
        for fn in (api.handle_dns_resolve, api.handle_dns_propagation,
                   api._dns_resolve_args):
            src = inspect.getsource(fn)
            # _dns_resolve_args validates; the two handlers gate.
            if fn is not api._dns_resolve_args:
                self.assertIn('require_admin_auth', src, fn.__name__)

    def test_module_alias(self):
        self.assertIs(api.dns_resolve_mod, R)


if __name__ == '__main__':
    unittest.main()
