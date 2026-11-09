#!/usr/bin/env python3
"""8.0.0: the Traffic view names a remote address's country and organisation from the GeoLite2 files, and from a Threat Intel lookup when they name nothing.

The two columns were empty on an installation without GeoLite2 files, which reads as a broken page. Threat Intel keeps what AbuseIPDB said about an address it looked up
(a two-letter country and the network), so that is the second source, field by field: a file that names the country and not the network gets the network from the lookup.
A private address is never looked up and gets neither. What a lookup stored is text from a third party, so it is read as a country code (two letters) and a short name.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v800-where-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_v800_traffic import LAN, PUB, PUB2, _Server, device, row, sample  # noqa: E402


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


class _Where(_Server):

    def setUp(self):
        super().setUp()
        self.put({'web01': device()}, traffic_module_enabled=True)
        self.beat('web01', 'tok', traffic=sample([row(tx=900, rx=100), row(ip=PUB2, port=53, tx=5, rx=5, proc='unbound'), row(d='in', ip=LAN, port=22, proc='sshd', tx=3, rx=4)]))

    def verdicts(self, rows):
        self.api.save(self.api.IPINTEL_FILE, {'attackers': {ip: {'verdict': v} for ip, v in rows.items()}})
        self.api._LOAD_CACHE.clear()

    def geo(self, answer):
        """What the GeoLite2 files say, in place of the files."""
        self.api.geo_enrich = lambda ip: dict(answer.get(ip, {}))

    def remote(self, ip):
        return {e['ip']: e for e in self.fleet()['remotes']}[ip]

    def host_row(self, ip):
        return {r['ip']: r for r in self.host()['rows']}[ip]


class TestTheLookupIsTheSecondSource(_Where):

    def test_with_no_file_the_lookup_names_the_country_and_the_network(self):
        self.geo({})
        self.verdicts({PUB: {'score': 88, 'country': 'de', 'isp': 'Example Net GmbH'}})
        for view in (self.remote(PUB), self.host_row(PUB)):
            self.assertEqual((view['country_code'], view['org'], view['score']), ('DE', 'Example Net GmbH', 88))
            self.assertNotIn('country', view, 'a lookup names a code, and a name is not made up for it')

    def test_an_address_nobody_looked_up_has_neither(self):
        self.geo({})
        self.verdicts({PUB: {'score': 1, 'country': 'DE', 'isp': 'x'}})
        view = self.remote(PUB2)
        self.assertEqual({k for k in view if k in ('country', 'country_code', 'org', 'score')}, set())

    def test_the_files_win_field_by_field(self):
        self.geo({PUB: {'country': 'France', 'country_code': 'FR'}})
        self.verdicts({PUB: {'country': 'DE', 'isp': 'Example Net GmbH'}})
        view = self.remote(PUB)
        self.assertEqual((view['country'], view['country_code'], view['org']), ('France', 'FR', 'Example Net GmbH'), 'the country is the file\'s, the network is the lookup\'s')
        self.geo({PUB: {'country': 'France', 'country_code': 'FR', 'org': 'Mapped Org', 'asn': 64500}})
        view = self.remote(PUB)
        self.assertEqual((view['org'], view['asn']), ('Mapped Org', 64500))

    def test_a_private_address_is_never_looked_up(self):
        self.geo({LAN: {'country': 'Nowhere', 'country_code': 'NW', 'org': 'No Org'}})
        self.verdicts({LAN: {'country': 'DE', 'isp': 'Example'}})
        for view in (self.remote(LAN), self.host_row(LAN)):
            self.assertEqual(view['scope'] if 'scope' in view else 'private', 'private')
            self.assertEqual({k for k in view if k in ('country', 'country_code', 'org', 'score')}, set())

    def test_what_a_lookup_stored_is_read_as_a_code_and_a_short_name(self):
        self.geo({})
        for bad in ({'country': 'Germany', 'isp': ''}, {'country': 5, 'isp': 7}, {'country': 'D1', 'isp': None}, {'country': ['DE'], 'isp': {'a': 1}}, {'country': ' ', 'isp': '   '}):
            self.verdicts({PUB: dict({'score': 3}, **bad)})
            view = self.remote(PUB)
            self.assertEqual({k for k in view if k in ('country', 'country_code', 'org')}, set(), bad)
        self.verdicts({PUB: {'score': 3, 'country': 'DE', 'isp': 'N' * 500}})
        self.assertEqual(len(self.remote(PUB)['org']), 120)

    def test_a_store_that_is_damaged_does_not_stop_the_page(self):
        self.geo({})
        self.api.save(self.api.IPINTEL_FILE, {'attackers': {PUB: 'junk', PUB2: {'verdict': 'junk'}}})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.remote(PUB)['scope'] if 'scope' in self.remote(PUB) else 'public', 'public')
        self.assertEqual(self.fleet()['totals']['hosts'], 1)


class TestTheFlagForTheHint(_Where):

    def test_the_answer_says_whether_a_file_is_set_up(self):
        self.assertIs(self.fleet()['geo'], False)
        self.assertIs(self.host()['geo'], False)
        cfg = self.cfg()
        cfg['geoip_db_path'] = '/var/lib/GeoLite2-Country.mmdb'
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.assertIs(self.fleet()['geo'], True)
        self.assertIs(self.host()['geo'], True)


if __name__ == '__main__':
    unittest.main()
