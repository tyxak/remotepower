"""The Threat Intel widget on Home: the numbers, who they are for, and that nothing leaks across hosts the caller cannot see.

The widget is small on purpose: how many addresses Threat Intel saw in the last day, how many it reported in that day, how many
blocks are in force, and how many hosts have a log source in trouble. The page it links to answers the same questions in detail,
so the widget takes its numbers from the same store and the same rules: the caller's own hosts, the instance's edge feeds for
the operator only, and a firewall's source row that has been quiet for a day read as quiet.

The datum is only counts, and the page behind it (`/api/ip-intel`) is open to every signed-in role with the same scoping, so the
widget widens no one's read access (the VPN widget, whose page is admin-only, withholds its datum; this one has no such page).
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v800-tiwidget-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402

from test_ip_intel import _Case  # noqa: E402

DAY = 86400
A1, A2, A3, A4, A5, A6 = ('203.0.113.%d' % n for n in (10, 11, 12, 13, 14, 15))


class _Widget(_Case):
    def setUp(self):
        super().setUp()
        self.now = int(time.time())
        n = self.now
        ipintel_store.write(self.api, {
            'attackers': {
                A1: {'last_seen': n - 100, 'devices': {'d1': {'count': 5}}, 'reported': {'abuseipdb': n - 50}},
                A2: {'last_seen': n - 200, 'devices': {'d1': {'count': 5}}, 'reported': {'abuseipdb': n - 3 * DAY}},
                A3: {'last_seen': n - 5 * DAY, 'devices': {'d3': {'count': 5}}, 'reported': {}},
                A4: {'last_seen': n - 10, 'devices': {'dX': {'count': 5}}, 'reported': {'abuseipdb': n - 5}},
                A5: {'last_seen': n - 10, 'devices': {'edge:trap': {'count': 5}}, 'reported': {}},
                A6: {'last_seen': n - 10, 'devices': {'d3': {'count': 2}, 'dX': {'count': 2}}},
            },
            'blocks': {'d1': {A1: {'until': n + 3600}, A2: {'until': n - 10}},
                       'dX': {A4: {'until': n + 3600}}},
            'sensors': {
                'd1': {'at': n - 30, 'sources': [{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok'},
                                                 {'kind': 'ids', 'path': '/var/log/suricata/eve.json', 'state': 'denied'}]},
                'd3': {'at': n - 2 * DAY, 'sources': [{'kind': 'ids', 'path': 'syslog', 'state': 'unparsed'}]},
                'dX': {'at': n - 30, 'sources': [{'kind': 'web', 'path': '/var/log/x.log', 'state': 'error'}]},
            },
            'edge': {'cf': {'state': 'refused'}, 'trap': {'state': 'ok'}},
        })
        self.visible = {'d1': {'name': 'web01'}, 'd3': {'name': 'edge'}}

    def as_role(self, role):
        self.api.verify_token = lambda _t=None: ('alice', role)

    def widget(self, role='admin', visible=None):
        self.as_role(role)
        self.api._LOAD_CACHE.clear()
        return self.api.ip_intel_widget(self.visible if visible is None else visible, self.now)


class TestTheNumbers(_Widget):
    def setUp(self):
        super().setUp()
        self.policy(lookup_enabled=True, edge_enabled=True)

    def test_what_the_operator_sees(self):
        # seen in a day: A1 and A2 (d1), A5 (the honeypot, the operator's), A6 (d3). A3 is five days old, A4 is a host not in the view.
        # reported in a day: A1 only (A2 three days ago; A4 is not in the view). Blocks in force: A1 on d1 (A2's has run out; dX is not in the view).
        # Sources in trouble: d1 (eve.json refused), and the Cloudflare feed. d3's row is a day old and reads quiet; dX is not in the view.
        self.assertEqual(self.widget('admin'), {'on': True, 'seen': 4, 'reported': 1, 'blocked': 1, 'problems': 2})

    def test_a_viewer_gets_what_the_page_would_show_the_same_caller(self):
        # no honeypot address, no edge feed: those are the operator's
        self.assertEqual(self.widget('viewer'), {'on': True, 'seen': 3, 'reported': 1, 'blocked': 1, 'problems': 1})

    def test_an_administrator_of_one_tenant_is_not_the_operator(self):
        with mock.patch.object(self.api, '_tenancy_enforced', return_value=True), \
                mock.patch.object(self.api, '_caller_is_superadmin', return_value=False):
            self.assertEqual(self.widget('admin'), {'on': True, 'seen': 3, 'reported': 1, 'blocked': 1, 'problems': 1})
        with mock.patch.object(self.api, '_tenancy_enforced', return_value=True), \
                mock.patch.object(self.api, '_caller_is_superadmin', return_value=True):
            self.assertEqual(self.widget('admin')['seen'], 4, 'the platform operator on a multi-tenant install is the operator')

    def test_a_host_the_caller_cannot_see_is_in_none_of_the_numbers(self):
        w = self.widget('admin', visible={'d3': {}})
        # A6 (d3 and dX) and A5 (the honeypot) count; A1 and A2 are on d1, which is out of the view
        self.assertEqual((w['seen'], w['reported'], w['blocked']), (2, 0, 0))
        self.assertEqual(self.widget('admin', visible={}), {'on': True, 'seen': 1, 'reported': 0, 'blocked': 0, 'problems': 1})

    def test_a_firewall_row_that_has_been_quiet_for_a_day_is_not_a_problem(self):
        sensors = ipintel_store.read(self.api)['sensors']
        sensors['d3'] = {'at': self.now - 30, 'sources': [{'kind': 'ids', 'path': 'syslog', 'state': 'unparsed'}]}
        ipintel_store.update(self.api, sensors=sensors)
        self.assertEqual(self.widget('viewer')['problems'], 2, 'the same row, written a moment ago, is one (and d1\'s is the other)')

    def test_a_host_with_two_sources_in_trouble_is_counted_once(self):
        ipintel_store.update(self.api, sensors={'d1': {'at': self.now - 30, 'sources': [
            {'kind': 'web', 'path': '/a', 'state': 'denied'}, {'kind': 'err', 'path': '/b', 'state': 'missing'}]}})
        self.assertEqual(self.widget('viewer')['problems'], 1)

    def test_a_feed_that_is_off_or_waiting_is_not_a_problem(self):
        ipintel_store.update(self.api, edge={'cf': {'state': 'off'}, 'trap': {'state': 'waiting'}})
        self.assertEqual(self.widget('admin')['problems'], 1)

    def test_an_edge_feed_that_is_switched_off_is_not_looked_at(self):
        self.policy(edge_enabled=False)
        self.assertEqual(self.widget('admin')['problems'], 1)


class TestOffAndBroken(_Widget):
    def test_nothing_of_threat_intel_switched_on_says_off(self):
        self.policy(lookup_enabled=False, report_enabled=False, block_enabled=False, sensor_enabled=False,
                    appliance_enabled=False, edge_enabled=False)
        self.assertEqual(self.widget('admin'), {'on': False})

    def test_any_one_switch_is_enough(self):
        keys = ('lookup_enabled', 'report_enabled', 'block_enabled', 'sensor_enabled', 'appliance_enabled', 'edge_enabled')
        for key in keys:
            self.policy(**dict(dict.fromkeys(keys, False), **{key: True}))
            self.assertTrue(self.widget('viewer')['on'], key)

    def test_a_store_that_cannot_be_read_gives_an_empty_datum_not_an_error(self):
        self.policy(lookup_enabled=True)

        def boom():
            raise RuntimeError('store gone')
        with mock.patch.dict(self.api.ip_intel_widget.__globals__, {'_store_ro': boom}):
            self.assertEqual(self.widget('admin'), {})

    def test_a_row_of_the_wrong_kind_in_the_store_does_not_stop_it(self):
        self.policy(lookup_enabled=True)
        ipintel_store.update(self.api, attackers={A1: 'x', A2: {'devices': 'd1', 'last_seen': 'now'}, A3: {'devices': {'d1': 1}, 'last_seen': None,
                                                                                                          'reported': {'abuseipdb': 'soon'}}},
                             blocks={'d1': {A1: 'x', A2: {'until': 'never'}}}, sensors={'d1': {'at': 'x', 'sources': ['y', {'state': 5}]}})
        w = self.widget('viewer')
        self.assertEqual(w.get('on'), True, w)


class TestOnTheHomePayload(_Widget):
    def setUp(self):
        super().setUp()
        self.policy(lookup_enabled=True)

    def test_it_is_built_when_the_widget_is_on_and_not_when_it_is_not(self):
        self.as_role('viewer')
        on = self.api._dashboard_extra_widgets(self.visible, {}, self.now, want={'threatintel'})
        self.assertEqual(on['threatintel']['on'], True)
        off = self.api._dashboard_extra_widgets(self.visible, {}, self.now, want={'vpn'})
        self.assertNotIn('threatintel', off, 'a widget nobody displays costs no read of the store of addresses')
        everything = self.api._dashboard_extra_widgets(self.visible, {}, self.now, want=None)
        self.assertIn('threatintel', everything)

    def test_the_key_is_in_both_lists_in_the_same_place(self):
        client = __import__('re').findall(r"key:\s*'([a-z]+)'", (Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text().split('const DASH_WIDGETS = [', 1)[1].split('];', 1)[0])
        self.assertEqual(client, list(self.api.DASHBOARD_WIDGETS))
        self.assertEqual(client.index('threatintel'), client.index('helpdesk') + 1)

    def test_the_security_layout_has_it(self):
        src = (Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js' / 'app-dashsets.js').read_text()
        security = src.split("id: 'security'", 1)[1].split("id: 'patching'", 1)[0]
        self.assertIn("'threatintel'", security)


if __name__ == '__main__':
    unittest.main()
