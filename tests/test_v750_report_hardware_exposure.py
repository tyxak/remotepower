#!/usr/bin/env python3
"""v7.5.0 (data binding): the fleet report carries hardware health and exposure.

SMART-failed disks, over-temperature, a UPS on battery, a degraded pool and the
sockets reachable from the world were answerable in the Fleet Query, the
Needs-attention digest and the risk score, and absent from the document an
auditor or a customer is handed. The `posture` section was also a selectable
section that the CSV and the email wrote nothing for.

Driven through the real `_build_fleet_report`, the real CSV and email renderers,
and the real report.js under node, against one seeded store with a control for
each of the ways a host can fail to belong in a list.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v750-rep-'))

_NODE = shutil.which('node')


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v750-rep-api-')
    spec = importlib.util.spec_from_file_location('api_v750_rep', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ports(*specs):
    return [{'port': p, 'proto': proto, 'process': proc, 'scope': scope}
            for p, proto, proc, scope in specs]


class _Seeded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            # Everything wrong at once, one exposed port muted on the Exposure page.
            'd1': {'name': 'web01', 'last_seen': now, 'monitored': True, 'sysinfo': {
                'listening_ports': _ports((22, 'tcp', 'sshd', 'world'),
                                          (443, 'tcp', 'nginx', 'world'),
                                          (5432, 'tcp', 'postgres', 'lan')),
                'storage_health': [{'name': 'tank', 'state': 'DEGRADED'}],
                'firewall': {'active': False, 'backends': []}}},
            # Reported, and nothing is wrong.
            'd2': {'name': 'db01', 'last_seen': now, 'monitored': True, 'sysinfo': {
                'listening_ports': [],
                'storage_health': [{'name': 'md0', 'state': 'clean'},
                                   {'name': 'tank2', 'state': 'ONLINE'}],
                'firewall': {'active': True, 'backends': []}}},
            # Never reported any of it.
            'd3': {'name': 'old01', 'last_seen': now, 'monitored': True, 'sysinfo': {}},
            # Unmonitored: bad on every count, and not in the report.
            'd4': {'name': 'lab01', 'last_seen': now, 'monitored': False, 'sysinfo': {
                'listening_ports': _ports((23, 'tcp', 'telnetd', 'world')),
                'storage_health': [{'name': 'x', 'state': 'FAULTED'}]}},
        })
        api.save(api.HARDWARE_FILE, {
            'd1': {'_smart_failed': True, '_temp_high': True},
            'd2': {'_ups_on_battery': True},
            'd3': {},
            'd4': {'_smart_failed': True, '_temp_high': True, '_ups_on_battery': True},
        })
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['exposure_mutes'] = [{'device_id': 'd1', 'port': 443}]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: ('alice', 'admin')
        cls.rep = api._build_fleet_report()


class TestHardwareSection(_Seeded):

    def test_the_population_is_not_empty(self):
        """Control: an empty answer below cannot be a store that never loaded."""
        self.assertEqual(self.rep['devices']['total'], 4)
        self.assertGreater(self.rep['hardware']['reporting'], 0)

    def test_flags_are_counted_for_monitored_hosts_that_reported(self):
        hw = self.rep['hardware']
        self.assertEqual(hw['reporting'], 2)                 # d1, d2 (d3 empty, d4 unmonitored)
        self.assertEqual((hw['smart_failed'], hw['smart_failed_count']), (['web01'], 1))
        self.assertEqual((hw['temp_high'], hw['temp_high_count']), (['web01'], 1))
        self.assertEqual((hw['ups_on_battery'], hw['ups_on_battery_count']), (['db01'], 1))

    def test_storage_has_its_own_denominator(self):
        hw = self.rep['hardware']
        self.assertEqual(hw['storage_reporting'], 2)         # d1, d2; d3 sent none
        self.assertEqual((hw['storage_degraded'], hw['storage_degraded_count']),
                         (['web01'], 1))

    def test_a_healthy_pool_state_in_any_case_is_not_a_finding(self):
        """`clean` is mdadm's word, `ONLINE` ZFS's (upper case); both are healthy."""
        self.assertNotIn('db01', self.rep['hardware']['storage_degraded'])

    def test_the_unmonitored_host_is_not_in_any_list(self):
        for key in ('smart_failed', 'temp_high', 'ups_on_battery', 'storage_degraded'):
            self.assertNotIn('lab01', self.rep['hardware'][key])

    def test_lists_are_capped_and_counts_are_not(self):
        api = self.api
        now = int(time.time())
        many = {f'h{i}': {'name': f'host{i:02d}', 'last_seen': now, 'monitored': True,
                          'sysinfo': {}} for i in range(15)}
        old_dev, old_hw = api.load(api.DEVICES_FILE), api.load(api.HARDWARE_FILE)
        try:
            api.save(api.DEVICES_FILE, many)
            api.save(api.HARDWARE_FILE, {k: {'_smart_failed': True} for k in many})
            api._LOAD_CACHE.clear()
            hw = api._build_fleet_report()['hardware']
            self.assertEqual(hw['smart_failed_count'], 15)
            self.assertEqual(len(hw['smart_failed']), 10)
        finally:
            api.save(api.DEVICES_FILE, old_dev)
            api.save(api.HARDWARE_FILE, old_hw)
            api._LOAD_CACHE.clear()


class TestExposureSection(_Seeded):

    def test_world_sockets_are_counted_net_of_the_mutes(self):
        ex = self.rep['exposure']
        self.assertEqual(ex['reporting'], 2)                 # d1, d2 (d3 never sent ports)
        self.assertEqual((ex['world_hosts'], ex['world_hosts_count']), (['web01'], 1))
        self.assertEqual(ex['world_sockets'], 1)             # 22 counts, 443 is muted

    def test_the_mute_is_what_removed_443(self):
        api = self.api
        cfg = api.load(api.CONFIG_FILE)
        saved = cfg.get('exposure_mutes')
        try:
            cfg['exposure_mutes'] = []
            api.save(api.CONFIG_FILE, cfg)
            api._LOAD_CACHE.clear()
            ex = api._build_fleet_report()['exposure']
            self.assertEqual(ex['world_sockets'], 2)
        finally:
            cfg['exposure_mutes'] = saved
            api.save(api.CONFIG_FILE, cfg)
            api._LOAD_CACHE.clear()

    def test_the_top_list_names_the_ports(self):
        top = self.rep['exposure']['top']
        self.assertEqual(top, [{'device': 'web01', 'count': 1, 'ports': ['22/tcp sshd']}])

    def test_lan_scoped_and_unmonitored_sockets_are_not_exposure(self):
        text = json.dumps(self.rep['exposure'])
        self.assertNotIn('5432', text)
        self.assertNotIn('23/tcp', text)
        self.assertNotIn('lab01', text)

    def test_a_host_that_never_sent_ports_is_not_counted_as_clean(self):
        self.assertEqual(self.rep['exposure']['reporting'], 2)

    def _with_hosts(self, hosts):
        api = self.api
        old = api.load(api.DEVICES_FILE)
        try:
            api.save(api.DEVICES_FILE, hosts)
            api._LOAD_CACHE.clear()
            return api._build_fleet_report()['exposure']
        finally:
            api.save(api.DEVICES_FILE, old)
            api._LOAD_CACHE.clear()

    def test_the_top_list_is_ordered_by_socket_count_not_by_name(self):
        now = int(time.time())
        ex = self._with_hosts({
            'a': {'name': 'alpha', 'last_seen': now, 'monitored': True, 'sysinfo': {
                'listening_ports': _ports((80, 'tcp', 'nginx', 'world'))}},
            'z': {'name': 'zeta', 'last_seen': now, 'monitored': True, 'sysinfo': {
                'listening_ports': _ports((80, 'tcp', 'nginx', 'world'),
                                          (443, 'tcp', 'nginx', 'world'),
                                          (8080, 'tcp', 'java', 'world'))}}})
        self.assertEqual([t['device'] for t in ex['top']], ['zeta', 'alpha'])
        self.assertEqual(ex['world_sockets'], 4)

    def test_the_top_list_is_capped_and_the_count_is_not(self):
        now = int(time.time())
        hosts = {f'h{i}': {'name': f'host{i:02d}', 'last_seen': now, 'monitored': True,
                           'sysinfo': {'listening_ports': _ports((80, 'tcp', 'nginx', 'world'))}}
                 for i in range(14)}
        ex = self._with_hosts(hosts)
        self.assertEqual(ex['world_hosts_count'], 14)
        self.assertEqual(len(ex['top']), 10)
        self.assertEqual(len(ex['world_hosts']), 10)

    def test_the_same_port_on_two_processes_is_listed_once_per_label(self):
        now = int(time.time())
        ex = self._with_hosts({'a': {'name': 'alpha', 'last_seen': now, 'monitored': True,
                                     'sysinfo': {'listening_ports': _ports(
                                         (80, 'tcp', 'nginx', 'world'),
                                         (80, 'tcp', 'nginx', 'world'))}}})
        self.assertEqual(ex['top'][0]['ports'], ['80/tcp nginx'])
        self.assertEqual(ex['top'][0]['count'], 2)


class TestScope(_Seeded):

    def test_a_scoped_reader_gets_no_name_outside_the_scope(self):
        api = self.api
        real = api._scope_filter_devices
        api._scope_filter_devices = lambda d: {k: v for k, v in d.items() if k == 'd2'}
        try:
            rep = api._build_fleet_report()
        finally:
            api._scope_filter_devices = real
        blob = json.dumps({k: rep[k] for k in ('hardware', 'exposure', 'posture')})
        for name in ('web01', 'lab01', 'old01'):
            self.assertNotIn(name, blob)
        self.assertEqual(rep['hardware']['reporting'], 1)
        self.assertEqual(rep['exposure']['world_hosts_count'], 0)


class TestSectionsAreSelectableAndRendered(_Seeded):

    def test_both_names_are_report_sections(self):
        for k in ('hardware', 'exposure'):
            self.assertIn(k, self.api._REPORT_SECTIONS)

    def test_a_sectioned_report_keeps_only_what_was_asked(self):
        out = self.api._filter_report_sections(self.rep, ['hardware'])
        self.assertIn('hardware', out)
        self.assertNotIn('exposure', out)
        self.assertNotIn('posture', out)

    def test_csv_writes_posture_hardware_and_exposure_rows(self):
        csv = self.api._fleet_report_csv_bytes(self.rep).decode()
        for needle in ('Posture,Host firewall inactive,1',
                       'Posture,Host firewall inactive (hosts reporting),2',
                       'Hardware,SMART-failed disk,1',
                       'Hardware,UPS on battery,1',
                       'Hardware,Storage pool or array degraded,1',
                       'Hardware,Storage pool or array degraded (hosts reporting),2',
                       'Exposure,Hosts with a world-reachable port,1',
                       'Exposure,World-reachable sockets,1'):
            self.assertIn(needle, csv.replace('\r', ''))
        # Counts only: no host name in these rows.
        for line in csv.splitlines():
            if line.startswith(('Hardware,', 'Exposure,')):
                self.assertNotIn('web01', line)

    def test_a_row_is_left_out_when_no_host_reported_the_signal(self):
        rep = json.loads(json.dumps(self.rep))
        rep['posture']['ssh_reporting'] = 0
        csv = self.api._fleet_report_csv_bytes(rep).decode()
        self.assertNotIn('Weak SSH configuration', csv)

    def test_email_has_the_three_blocks(self):
        _subj, body = self.api._render_report_email(self.rep)
        self.assertIn('Host security posture', body)
        self.assertIn('Firewall inactive', body)
        self.assertIn('Hardware', body)
        self.assertIn('SMART-failed disk', body)
        self.assertIn('Exposure', body)
        self.assertIn('1 host, 1 socket', body)

    def test_a_report_without_the_sections_still_renders(self):
        """A saved definition with the boxes unticked must not raise (the 500 a
        missing key caused in 3.14)."""
        only = self.api._filter_report_sections(self.rep, ['patches'])
        _subj, body = self.api._render_report_email(only)
        csv = self.api._fleet_report_csv_bytes(only).decode()
        self.assertNotIn('SMART-failed', body)
        self.assertNotIn('Hardware,', csv)
        self.assertNotIn('Exposure,', csv)

    def test_the_ai_summary_sees_counts_and_no_names(self):
        ctx = self.api._report_summary_context(self.rep)
        self.assertEqual(ctx['hardware']['smart_failed_count'], 1)
        self.assertEqual(ctx['exposure']['world_sockets'], 1)
        self.assertEqual(ctx['posture']['firewall_off_count'], 1)
        self.assertNotIn('web01', json.dumps(ctx))

    def test_the_builder_labels_both_sections(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn("hardware: 'Hardware health'", js)
        self.assertIn("exposure: 'Network exposure'", js)


_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const rep = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const els = {};
function el(id) {
  if (!els[id]) els[id] = {innerHTML: '', textContent: '', addEventListener() {},
                           classList: {add() {}, remove() {}}};
  return els[id];
}
global.document = {
  readyState: 'complete',
  getElementById: el,
  querySelector: () => null,
  documentElement: {style: {setProperty() {}}},
  title: '',
  addEventListener() {},
};
global.localStorage = {getItem: () => 'tok'};
global.sessionStorage = {getItem: () => 'tok'};
global.window = {print() {}};
global.fetch = async (path) => ({
  ok: true,
  json: async () => (path.indexOf('baseline') >= 0 ? {} : rep),
});
(0, eval)(src);
setTimeout(() => {
  process.stdout.write(JSON.stringify({sections: els['pr-sections'] ? els['pr-sections'].innerHTML : null}));
}, 50);
"""


@unittest.skipUnless(_NODE, 'node not installed')
class TestThePrintedReportDrawsThem(_Seeded):
    """report.js, run for real against the server's own JSON."""

    def _render(self, rep):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / 'h.js'
            h.write_text(_HARNESS)
            j = Path(d) / 'rep.json'
            j.write_text(json.dumps(rep))
            r = subprocess.run([_NODE, str(h), str(_ROOT / 'server/html/static/js/report.js'),
                                str(j)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        return json.loads(r.stdout)['sections'] or ''

    def test_the_headings_and_figures_are_there(self):
        html = self._render(self.rep)
        self.assertIn('<h2>Hardware health</h2>', html)
        self.assertIn('SMART-failed disk', html)
        self.assertIn('<h2>Network exposure</h2>', html)
        self.assertIn('22/tcp sshd', html)
        # posture is drawn by the same builder as before
        self.assertIn('<h2>Host security posture</h2>', html)
        self.assertIn('Host firewall inactive', html)

    def test_a_row_with_no_reporting_hosts_is_left_out(self):
        rep = json.loads(json.dumps(self.rep))
        rep['hardware']['storage_reporting'] = 0
        html = self._render(rep)
        self.assertNotIn('Storage pool or array degraded', html)
        self.assertIn('SMART-failed disk', html)

    def test_nothing_exposed_still_prints(self):
        rep = json.loads(json.dumps(self.rep))
        rep['exposure'].update(world_hosts=[], world_hosts_count=0,
                               world_sockets=0, top=[])
        html = self._render(rep)
        self.assertIn('<h2>Network exposure</h2>', html)
        self.assertNotIn('Reachable ports', html)

    def test_no_host_reporting_ports_prints_no_exposure_heading(self):
        """Zero hosts reporting is "no data", not "nothing is exposed"."""
        rep = json.loads(json.dumps(self.rep))
        rep['exposure'].update(reporting=0, world_hosts=[], world_hosts_count=0,
                               world_sockets=0, top=[])
        self.assertNotIn('Network exposure', self._render(rep))

    def test_no_hardware_reporting_prints_no_empty_heading(self):
        rep = json.loads(json.dumps(self.rep))
        rep['hardware'].update(reporting=0, storage_reporting=0)
        self.assertNotIn('Hardware health', self._render(rep))

    def test_a_host_name_is_escaped(self):
        rep = json.loads(json.dumps(self.rep))
        rep['hardware']['smart_failed'] = ['<img src=x onerror=alert(1)>']
        rep['exposure']['top'][0]['device'] = '<script>alert(1)</script>'
        html = self._render(rep)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('<script>alert', html)
        self.assertIn('&lt;img src=x', html)


if __name__ == '__main__':
    unittest.main()
