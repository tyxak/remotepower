"""8.0.2: what a tenant is sent by Threat Intel is its own.

Threat Intel is one installation's: one table of addresses, one set of settings, one account at Cloudflare. A tenant's administrator or viewer is sent
the addresses its own hosts saw, and nothing that is the platform operator's.

  * `GET /api/ip-intel` sent the settings to any administrator (the never-block list holds the operator's own office and admin addresses, the Cloudflare
    account and zone ids, the Edge blocklist's name and entries, the extra log paths read on every host), and the day's lookup and report counts and the
    length of the whole queue to every role. The feeds, the list and the request log were already the operator's; the settings, the budget and the queue
    follow them now, and a tenant is told how many addresses wait from the hosts it can see.
  * The page shows the settings cards to the operator only.

The handler runs for real through `main()`, with the gates that run before it; only the session store is replaced.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-tenantscope-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ipintel_store  # noqa: E402
import srcpin  # noqa: E402
from request_harness import RequestCase  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
JS = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
T = int(time.time())

# what the operator has set; every value is a marker nobody else may be sent
OPERATOR = {
    'never_block': ['45.77.10.5', '203.0.113.0/24'], 'ignore_addresses': ['45.77.10.6'],
    'edge_account_id': 'a1' * 16, 'edge_zone_ids': ['b2' * 16], 'edge_workers': ['trap-sink-prod'],
    'edgelist_name': 'operator_blocklist', 'edgelist_always': ['45.77.10.7'], 'sensor_paths': ['/var/log/operator-private.log'],
    'sensor_enabled': True, 'limit_abuseipdb_lookups': 4321, 'daily_report_budget': 777,
}
MARKERS = ['45.77.10.5', '203.0.113.0/24', '45.77.10.6', 'a1' * 16, 'b2' * 16, 'trap-sink-prod', 'operator_blocklist', '45.77.10.7',
           '/var/log/operator-private.log', '4321', '777']
HOSTS = {
    'hD': {'id': 'hD', 'name': 'web-operator', 'os': 'Ubuntu 24.04', 'token': 'tokD', 'tenant': 'default', 'last_seen': T},
    'hA': {'id': 'hA', 'name': 'web-acme', 'os': 'Ubuntu 24.04', 'token': 'tokA', 'tenant': 'acme', 'last_seen': T},
    'hG': {'id': 'hG', 'name': 'web-globex', 'os': 'Ubuntu 24.04', 'token': 'tokG', 'tenant': 'globex', 'last_seen': T},
}


class _Tenants(RequestCase):
    def setUp(self):
        super().setUp()
        self.put(devices=HOSTS, tenancy_enforced=True, abuseipdb_api_key='a' * 80, ip_intel=dict(OPERATOR))

    def queue(self, *items):
        """Entries of the intake queue, as the sweep claims them: (device id, address)."""
        q = [{'ip': ip, 'device_id': dev, 'unit': 'threat-sensor', 'count': 5, 'window_s': 60, 'at': T} for dev, ip in items]
        # the sweep runs from main() when it is due, and would take these entries before the handler reads the length of the queue
        ipintel_store.update(self.api, queue=q, last_sweep=int(time.time()))
        self.api._LOAD_CACHE.clear()

    def get(self, token):
        status, body = self.request('/api/ip-intel', token=token)
        self.assertEqual(status, 200, body)
        return body


class TestTheInstancesSettingsAreTheOperators(_Tenants):
    def test_the_operator_is_sent_them(self):
        body = self.get('k')
        self.assertTrue(body['operator'])
        s = body['settings']
        for key in ('never_block', 'edge_account_id', 'edgelist_name', 'sensor_paths', 'limit_abuseipdb_lookups'):
            self.assertEqual(s[key], OPERATOR[key], key)
        self.assertEqual(body['budget'].get('day'), time.strftime('%Y-%m-%d', time.gmtime()))

    def test_a_tenants_administrator_is_sent_none_of_them(self):
        body = self.get('ta')
        self.assertTrue(body['is_admin'], 'the administrator of a tenant is still an administrator: of that tenant')
        self.assertFalse(body['operator'])
        self.assertEqual(body['settings'], {})
        self.assertEqual(body['budget'], {})
        text = json.dumps(body)
        for marker in MARKERS:
            self.assertNotIn(marker, text, 'the operator\'s value is in what a tenant\'s administrator was sent')

    def test_a_tenants_viewer_is_sent_none_of_them(self):
        body = self.get('tv')
        self.assertFalse(body['is_admin'] or body['operator'])
        self.assertEqual((body['settings'], body['budget']), ({}, {}))
        for marker in MARKERS:
            self.assertNotIn(marker, json.dumps(body))

    def test_every_instance_level_part_of_the_answer_is_the_operators(self):
        """The same answer as the three callers, key by key: what the operator is sent that a tenant is not is the whole instance-level set."""
        op, ta = self.get('k'), self.get('ta')
        for key in ('settings', 'budget', 'edge', 'edge_list', 'requests'):
            self.assertTrue(op.get(key) not in (None, {}), f'{key}: the operator is sent it')
        for key in ('settings', 'budget'):
            self.assertEqual(ta[key], {})
        for key in ('edge', 'edge_list', 'requests'):
            self.assertIsNone(ta[key])

    def test_the_queue_a_tenant_is_told_of_is_the_one_of_its_hosts(self):
        self.queue(('hA', '185.220.101.1'), ('hA', '185.220.101.2'), ('hG', '185.220.101.3'), ('hD', '185.220.101.4'))
        self.assertEqual(self.get('k')['queued'], 4)
        self.assertEqual(self.get('ta')['queued'], 2, 'acme\'s two, not the four of the installation')
        self.assertEqual(self.get('tb')['queued'], 1)
        self.assertEqual(self.get('tv')['queued'], 2)

    def test_with_one_organisation_nothing_changes(self):
        self.put(devices=HOSTS, abuseipdb_api_key='a' * 80, ip_intel=dict(OPERATOR))        # tenancy is off
        self.queue(('hA', '185.220.101.1'), ('hG', '185.220.101.3'))
        body = self.get('k')
        self.assertTrue(body['operator'])
        self.assertEqual(body['settings']['never_block'], OPERATOR['never_block'])
        self.assertEqual(body['queued'], 2)
        viewer = self.get('v')
        self.assertEqual((viewer['settings'], viewer['budget'], viewer['queued']), ({}, {}, 2),
                         'a viewer is sent no settings (as before) and no counts of the installation, and the queue of the hosts it sees')


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestThePageShowsTheSettingsToTheOperatorOnly(unittest.TestCase):
    CARDS = ('ipintel-settings-card', 'ipintel-sensor-card', 'ipintel-appliance-card', 'ipintel-limits-card', 'ipintel-lookup-card',
             'ipintel-edge-card', 'ipintel-edge-status-card', 'ipintel-edgelist-card')

    def run_page(self, answer):
        script = '''
const els = {};
const el = id => (els[id] = els[id] || {hidden: undefined, value: '', checked: false, textContent: '', innerHTML: '', dataset: {}, addEventListener() {}});
const document = {getElementById: el};
let _ipiData = null, _ipiAdmin = false, _ipiOperator = false, _ipiRowsAsked = 0, filled = false;
const tableCtl = {wireSortOnly() {}};
function _ipiWire() {} function _ipiRenderTiles() {} function pgTabsApply() {} function _ipiRenderAttackers() {} function _ipiRenderBlocks() {}
function _ipiRenderSources() {} function _ipiRenderEdge() {} function _ipiRenderEdgeList() {} function _ipiRenderRequests() {}
function _ipiFillSettings() { filled = true; }
async function api() { return %s; }
''' % json.dumps(answer)
        fn = 'async ' + srcpin.js_function(JS, 'loadIpIntel')
        probe = ('(async () => { await loadIpIntel(); console.log(JSON.stringify({hidden: Object.fromEntries(%s.map(i => [i, els[i].hidden])), '
                 "clear: els['ipintel-clear-btn'].hidden, filled})); })()") % json.dumps(list(self.CARDS))
        out = subprocess.run(['node', '-e', script + fn + '\n' + probe], capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_the_operator_sees_every_card(self):
        got = self.run_page({'ok': True, 'is_admin': True, 'operator': True, 'settings': {'x': 1}, 'budget': {}, 'edge': {'cf': {}}, 'edge_list': {'a': 1},
                             'attackers': [], 'blocks': [], 'sensors': []})
        self.assertEqual(got['hidden'], {c: False for c in self.CARDS})
        self.assertTrue(got['filled'])
        self.assertFalse(got['clear'])

    def test_a_tenants_administrator_sees_none_of_the_instances_cards_and_keeps_the_clear_button(self):
        got = self.run_page({'ok': True, 'is_admin': True, 'operator': False, 'settings': {}, 'budget': {}, 'edge': None, 'edge_list': None,
                             'attackers': [], 'blocks': [], 'sensors': []})
        self.assertEqual(got['hidden'], {c: True for c in self.CARDS})
        self.assertFalse(got['filled'], 'the settings form is not filled from an answer that holds none')
        self.assertFalse(got['clear'], 'what a tenant clears is its own sightings')

    def test_the_flag_decides_and_not_whether_the_answer_holds_data(self):
        """A tenant is never sent the feeds, but the page does not rely on that: an answer that holds them for a caller that is not the operator
        (a server that sent too much) still shows no card of the instance's."""
        got = self.run_page({'ok': True, 'is_admin': True, 'operator': False, 'settings': {'x': 1}, 'budget': {'day': 'x'}, 'edge': {'cf': {}},
                             'edge_list': {'a': 1}, 'requests': [], 'attackers': [], 'blocks': [], 'sensors': []})
        self.assertEqual(got['hidden'], {c: True for c in self.CARDS})
        self.assertFalse(got['filled'])

    def test_a_viewer_sees_none_of_it_and_no_clear_button(self):
        got = self.run_page({'ok': True, 'is_admin': False, 'operator': False, 'settings': {}, 'budget': {}, 'attackers': [], 'blocks': [], 'sensors': []})
        self.assertEqual(got['hidden'], {c: True for c in self.CARDS})
        self.assertTrue(got['clear'])


if __name__ == '__main__':
    unittest.main()
