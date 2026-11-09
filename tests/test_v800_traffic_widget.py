#!/usr/bin/env python3
"""8.0.0: the Traffic widget on Home: the numbers, who they are for, and that nothing leaks across hosts the caller cannot see.

The widget is small: how many of the Linux hosts with an agent report, what they sent and received per second at their last sample, their connections, the watch list
matches and the three busiest remote addresses. The page behind it (`/api/traffic/fleet`) answers the same questions in detail, so the widget reads the same store with the
same rules: the caller's own hosts, a host that stopped reporting is not added in, and the datum is `{on: False}` while the module is off. The Home page was flagged twice for
answering a tenant with the installation's figures (S10); this file asks as the operator, as a tenant administrator of each organisation and as a tenant viewer, with a marker
address in each organisation's host, and requires that the only addresses a caller gets are the ones its own hosts talk to.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v800-trwidget-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_v800_home_widgets_scope import _Home  # noqa: E402
from test_v800_traffic import LAN, PUB, PUB2, row, sample  # noqa: E402

ACME_ONLY, GLOBEX_ONLY, OPERATOR_ONLY = PUB, PUB2, '1.1.1.1'
JSON_ROOT = _TESTS.parent


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


class _TrafficHome(_Home):
    """web01 belongs to acme, web02 to globex, ops01 to the organisation that runs the installation; each talks to an address of its own."""

    def setUp(self):
        super().setUp()
        cfg = self.cfg()
        cfg['traffic_module_enabled'] = True
        cfg['traffic_watch'] = [{'kind': 'ip', 'value': ACME_ONLY, 'label': 'flagged'}]
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.beat('web01', 'tok', traffic=sample([row(ip=ACME_ONLY, tx=600, rx=60), row(d='in', ip=LAN, port=22, proc='sshd', tx=1, rx=1)]))
        self.beat('web02', 't2', traffic=sample([row(ip=GLOBEX_ONLY, tx=300, rx=30)]))
        self.beat('ops01', 't3', traffic=sample([row(ip=OPERATOR_ONLY, tx=1200, rx=120)]))

    def traffic(self, tok):
        return self.widgets(tok).get('traffic')

    def addresses(self, tok):
        return [r['ip'] for r in (self.traffic(tok) or {}).get('top', [])]


class TestTheNumbers(_TrafficHome):

    def test_what_the_operator_sees_is_every_host(self):
        w = self.traffic('op')
        self.assertEqual((w['on'], w['hosts'], w['total']), (True, 3, 3))
        self.assertEqual(self.addresses('op'), [OPERATOR_ONLY, ACME_ONLY, GLOBEX_ONLY], 'the busiest first: 1,320, 660 and 330 bytes')
        self.assertEqual((w['tx'], w['rx']), (round(600 / 60) + round(300 / 60) + round(1200 / 60) + round(1 / 60), round(60 / 60) + round(30 / 60) + round(120 / 60) + round(1 / 60)))

    def test_a_tenant_gets_the_addresses_of_its_own_hosts_and_no_others(self):
        for tok, mine, others in (('ta', {ACME_ONLY, LAN}, {GLOBEX_ONLY, OPERATOR_ONLY}), ('tb', {GLOBEX_ONLY}, {ACME_ONLY, LAN, OPERATOR_ONLY}), ('tv', {ACME_ONLY, LAN}, {GLOBEX_ONLY, OPERATOR_ONLY})):
            got = set(self.addresses(tok))
            self.assertEqual(got, mine, tok)
            self.assertFalse(got & others, tok)
            self.assertEqual(self.traffic(tok)['hosts'], 1, tok)
            self.assertEqual(self.traffic(tok)['total'], 1, tok)

    def test_the_figures_are_the_ones_the_page_adds_up_for_the_same_caller(self):
        for tok in ('op', 'ta', 'tb'):
            st, fleet = self.call(self.api.handle_traffic_fleet, token=tok)
            self.assertEqual(st, 200)
            reporting = [h for h in fleet['hosts'] if h['state'] == 'reporting']
            w = self.traffic(tok)
            self.assertEqual((w['hosts'], w['tx'], w['rx'], w['conns']), (len(reporting), sum(h['tx_rate'] for h in reporting), sum(h['rx_rate'] for h in reporting), sum(h['conns'] for h in reporting)), tok)
            self.assertEqual([r['ip'] for r in w['top']], [e['ip'] for e in fleet['remotes'][:3]], tok)

    def test_the_watch_list_matches_are_counted_for_the_hosts_of_the_caller(self):
        self.assertEqual((self.traffic('op')['hits'], self.traffic('ta')['hits'], self.traffic('tb')['hits']), (1, 1, 0))

    def test_at_most_three_addresses_are_listed(self):
        self.beat('ops01', 't3', traffic=sample([row(ip='9.9.9.%d' % n, tx=10 * n, rx=1) for n in range(1, 9)] + [row(ip=OPERATOR_ONLY, tx=5000, rx=1)]))
        self.assertEqual(len(self.addresses('op')), 3)
        self.assertEqual(self.addresses('op')[0], OPERATOR_ONLY)

    def test_a_host_that_stopped_reporting_is_not_added_in(self):
        rec = self.stored('web01')
        rec['at'] -= 3 * 3600
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        w = self.traffic('ta')
        self.assertEqual((w['hosts'], w['total'], w['top']), (0, 1, []))

    def test_the_agentless_and_the_decommissioned_are_not_hosts_of_the_widget(self):
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['web01']['decommissioned'] = True
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.traffic('ta')['total'], 0)


class TestWhatTheLookupAdds(_TrafficHome):

    def test_the_busiest_addresses_carry_what_a_lookup_stored(self):
        self.api.geo_enrich = lambda ip: {}
        self.api.save(self.api.IPINTEL_FILE, {'attackers': {ACME_ONLY: {'verdict': {'score': 91, 'country': 'nl', 'isp': 'Example Net'}}}})
        self.api._LOAD_CACHE.clear()
        top = {r['ip']: r for r in self.traffic('ta')['top']}[ACME_ONLY]
        self.assertEqual((top['country_code'], top['org'], top['score']), ('NL', 'Example Net', 91))
        lan = {r['ip']: r for r in self.traffic('ta')['top']}[LAN]
        self.assertEqual(lan['scope'], 'private')
        self.assertEqual({k for k in lan if k in ('country', 'country_code', 'org', 'score')}, set(), 'a private address is never looked up')


class TestOffAndBroken(_TrafficHome):

    def test_the_module_off_says_off_and_the_page_answers_404(self):
        cfg = self.cfg()
        cfg['traffic_module_enabled'] = False
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.traffic('op'), {'on': False})
        st, body = self.call(self.api.handle_traffic_fleet, token='op')
        self.assertEqual((st, body.get('module_disabled')), (404, 'traffic'))

    def test_a_store_of_the_wrong_shape_gives_the_numbers_it_can(self):
        self.api.save(self.api.TRAFFIC_FILE, {'web01': 'junk', 'web02': ['x'], 'ops01': {'sample': 5, 'at': 'now'}})
        self.api._LOAD_CACHE.clear()
        w = self.traffic('op')
        self.assertEqual((w['on'], w['hosts'], w['top']), (True, 0, []))

    def test_a_read_that_fails_gives_an_empty_datum_and_not_an_error(self):
        real = self.api._load_ro

        def broken(path, *a, **k):
            if path == self.api.TRAFFIC_FILE:
                raise RuntimeError('store unreadable')
            return real(path, *a, **k)
        self.api._load_ro = broken
        self.assertEqual(self.api.traffic_widget({'web01': {'name': 'web01'}}, int(time.time())), {})

    def test_no_hosts_at_all_is_an_empty_widget(self):
        self.assertEqual(self.api.traffic_widget({}, int(time.time()))['hosts'], 0)
        self.assertEqual(self.api.traffic_widget(None, int(time.time()))['total'], 0)


class TestOnTheHomePayload(_TrafficHome):

    def test_it_is_built_when_the_widget_is_on_and_not_when_it_is_not(self):
        visible = {'web01': self.api.load(self.api.DEVICES_FILE)['web01']}
        now = int(time.time())
        on = self.api._dashboard_extra_widgets(visible, {}, now, want={'traffic'})
        self.assertEqual(on['traffic']['on'], True)
        off = self.api._dashboard_extra_widgets(visible, {}, now, want={'vpn'})
        self.assertNotIn('traffic', off, 'a widget nobody displays costs no read of the traffic store')
        self.assertIn('traffic', self.api._dashboard_extra_widgets(visible, {}, now, want=None))

    def test_the_key_is_in_both_lists_in_the_same_place(self):
        src = (JSON_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text().split('const DASH_WIDGETS = [', 1)[1].split('];', 1)[0]
        client = __import__('re').findall(r"key:\s*'([a-z]+)'", src)
        self.assertEqual(client, list(self.api.DASHBOARD_WIDGETS))
        self.assertEqual(client.index('traffic'), client.index('threatintel') + 1)

    def test_the_security_layout_has_it(self):
        src = (JSON_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-dashsets.js').read_text()
        security = src.split("id: 'security'", 1)[1].split("id: 'patching'", 1)[0]
        self.assertIn("'traffic'", security)


if __name__ == '__main__':
    unittest.main()
