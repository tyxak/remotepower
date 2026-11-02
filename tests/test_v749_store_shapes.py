#!/usr/bin/env python3
"""A store file holding a row of the wrong shape no longer fails the pages that read it (7.4.9, hostile-input sweep F6, F7, F8).

The sweep replaced one row, one list or the children of one node of each of 193 store files, one at a time, with null, a number,
a string, a list, a map, a 400-digit integer, NaN and Infinity, and requested every page that reads that file. 3,809 mutations in 110
stores answered 500 for everybody, and 1,810 periodic sweeps raised and stopped. One null in `alerts.json` took down the home page, the
problems page and the alert summary. The readers all assumed a shape that the loaders did not guarantee, and 202 endpoints could not be
fixed one at a time.

`server/cgi-bin/store_shapes.py` states the shape of each store once, and `api._load_uncached` checks it where the file is read. This
test holds:

* the registry accepts the demo data without changing a byte of it (a spec that disagreed with real data would delete real rows);
* every kind of spec repairs each wrong shape the way its docstring says, and the two stores where the obvious repair would fail
  open (the tenant registry, a smart group's rules) are repaired the other way;
* the product's own pages, started on the demo data in a process of their own, answer below 500 with a bad row in each of the stores
  the sweep named, and with NaN stored in the audit log. Run again with the repair switched off, several of them answer 500, which is
  what shows the test can see the old behaviour.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import store_shapes as S  # noqa: E402

SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'


def _seed(into):
    subprocess.run([sys.executable, str(SEEDER), '--data-dir', str(into), '--apply'], check=True, capture_output=True,
                   env=dict(os.environ, RP_DATA_DIR=str(into)))


class TestTheRegistryAgreesWithTheDemoData(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix='rp-shapes-'))
        _seed(cls.dir)

    def test_nothing_in_the_demo_data_is_repaired(self):
        checked = changed = 0
        for name in sorted(S.SHAPES):
            p = self.dir / name
            if not p.exists():
                continue
            doc = json.loads(p.read_text())
            before = copy.deepcopy(doc)
            checked += 1
            if S.normalize(name, doc) != before:
                changed += 1
                self.fail(f'{name}: the registry changes the demo data')
        self.assertGreater(checked, 60, 'the demo data holds too few of the registered stores to mean anything')
        self.assertEqual(changed, 0)

    def test_every_registered_store_is_one_the_product_uses(self):
        """A typo in a name would register a shape for a file that does not exist, and guard nothing."""
        code = ''.join(p.read_text() for p in (ROOT / 'server' / 'cgi-bin').glob('*.py') if p.name != 'store_shapes.py')
        self.assertEqual(sorted(n for n in S.SHAPES if f"'{n}'" not in code), [], 'a registered name that no code uses')


class TestTheRepairs(unittest.TestCase):

    def test_a_wrong_root_becomes_an_empty_container_of_the_right_kind(self):
        for junk in (None, 7, 'x', [1, 2], 10 ** 400):
            with self.subTest(junk=repr(junk)[:20]):
                self.assertEqual(S.normalize('devices.json', junk), {})
                self.assertEqual(S.normalize('alerts.json', junk), {})
        self.assertEqual(S.normalize('brute_force.json', [1]), {})

    def test_a_row_that_is_not_a_map_is_left_out(self):
        doc = {'a': {'name': 'ok'}, 'b': None, 'c': 7, 'd': 'x', 'e': [1]}
        self.assertEqual(S.normalize('sites.json', doc), {'a': {'name': 'ok'}})

    def test_a_list_keeps_only_the_maps_in_it(self):
        doc = {'alerts': [{'id': 1}, 'x', None, 7, {'id': 2}]}
        self.assertEqual(S.normalize('alerts.json', doc), {'alerts': [{'id': 1}, {'id': 2}]})
        self.assertEqual(S.normalize('alerts.json', {'alerts': None}), {'alerts': []})
        self.assertEqual(S.normalize('alerts.json', {}), {}, 'a missing key stays missing: readers already default it')

    def test_a_sub_container_of_the_wrong_kind_is_replaced(self):
        doc = {'pmx01': {'collected_at': 1, 'clamav': 7, 'rkhunter': {'ok': True}}}
        self.assertEqual(S.normalize('av_status.json', doc)['pmx01'], {'collected_at': 1, 'clamav': {}, 'rkhunter': {'ok': True}})

    def test_a_row_without_the_key_every_row_has_is_not_a_row(self):
        doc = {'tickets': [{'id': 't1'}, {'a': {'b': 1}}, {'id': 't2'}]}
        self.assertEqual([t['id'] for t in S.normalize('tickets.json', doc)['tickets']], ['t1', 't2'])

    def test_a_key_the_registry_does_not_list_is_not_touched(self):
        doc = {'pmx01': {'packages': [{'name': 'a'}], 'firewall': [{'name': 'domain', 'enabled': True}], 'anything': 7}}
        self.assertEqual(S.normalize('packages.json', copy.deepcopy(doc)), doc)

    def test_a_store_with_no_registered_shape_is_returned_as_it_is(self):
        junk = {'x': [None, 7]}
        self.assertIs(S.normalize('not_a_store.json', junk), junk)

    def test_a_host_record_keeps_the_fields_that_differ_by_platform(self):
        """`win_posture.firewall` is a list on Windows and `mac_posture.firewall` a map; the registry must not choose."""
        doc = {'h1': {'name': 'a', 'sysinfo': {'win_posture': {'firewall': [{'name': 'x', 'enabled': True}]},
                                               'mac_posture': {'firewall': {'on': True}}, 'proc_names': ['a', 7, 'b']},
                      'tags': ['a', None, 'b']}}
        out = S.normalize('devices.json', doc)
        self.assertEqual(out['h1']['sysinfo']['win_posture']['firewall'], [{'name': 'x', 'enabled': True}])
        self.assertEqual(out['h1']['sysinfo']['mac_posture']['firewall'], {'on': True})
        self.assertEqual(out['h1']['sysinfo']['proc_names'], ['a', '7', 'b'], 'a number is read as its text, so the name list stays a list of text')
        self.assertEqual(out['h1']['tags'], ['a', 'b'])

    # the two stores where emptying a bad value would grant something --------------------------------------------------------
    def test_a_damaged_tenant_row_stays_a_tenant(self):
        """A user whose tenant is missing from the registry belongs to the default tenant, which is the operator's. Leaving a
        damaged row out would move that tenant's users there."""
        doc = {'default': {'name': 'Default'}, 'tn_a': 'x', 'tn_b': None, 'tn_c': {'name': 'C'}}
        self.assertEqual(sorted(S.normalize('tenants.json', doc)), ['default', 'tn_a', 'tn_b', 'tn_c'])

    def test_a_smart_group_with_damaged_rules_is_gone_not_empty(self):
        """An empty rule set matches every host, so a window scoped to the group would cover the whole fleet."""
        doc = {'ok': {'rules': {'tag': 'web'}, 'members': ['h1']}, 'bad': {'rules': 'garbage', 'members': ['h1']},
               '_meta': {'x': 1}}
        out = S.normalize('smart_groups.json', doc)
        self.assertEqual(sorted(out), ['_meta', 'ok'])

    def test_the_repair_is_reported_once_on_stderr(self):
        import io
        import contextlib
        S._WARNED.discard('alerts.json')
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            S.normalize('alerts.json', {'alerts': ['x']})
            S.normalize('alerts.json', {'alerts': ['y']})
        self.assertEqual(buf.getvalue().count('alerts.json'), 1)


class TestTheLastRowsOfTheReplay(unittest.TestCase):
    """The rows the replay of the sweep's findings still broke after the first registry: a needed key of the wrong kind, a list that
    holds more than maps, a stamp that a sweep sorts by, and the sub-maps of the KMIP and patch-age stores."""

    def test_a_needed_key_of_the_wrong_kind_makes_the_row_unusable(self):
        doc = {'h1': {'services': [{'unit': 'a.service', 'active': 'active'}, {'unit': ['x']}, {'unit': None}, {'active': 'active'},
                                   {'unit': 'b.service', 'active': ['x']}]}}
        rows = S.normalize('services.json', doc)['h1']['services']
        self.assertEqual([r['unit'] for r in rows], ['a.service', 'b.service'], 'the readers index row["unit"] with no default')
        self.assertNotIn('active', rows[1], 'a wrong field on a row that stays is removed, so the reader default applies')
        tickets = S.normalize('tickets.json', {'tickets': [{'id': ['x']}, {'id': 't1'}, {'id': {'a': 1}}, {'id': 7}]})['tickets']
        self.assertEqual([t['id'] for t in tickets], ['t1', 7], 'an id that is a list or a map is no id; a number stays a number')

    def test_a_discovered_host_without_a_usable_address_is_left_out(self):
        doc = {'fw01': {'hosts': [{'ip': '10.0.0.5', 'mac': None, 'hostname': 'a'}, {'ip': None, 'mac': 'x'}, {'ip': ['1']}]}}
        hosts = S.normalize('discovery.json', doc)['fw01']['hosts']
        self.assertEqual([h['ip'] for h in hosts], ['10.0.0.5'])
        self.assertIsNone(hosts[0]['mac'], 'a missing MAC is null on the wire; the page shows it blank')

    def test_a_log_rule_is_a_map(self):
        doc = {'h1': {'name': 'a', 'log_watch': [{'unit': 'sshd', 'pattern': 'fail'}, 1, 'x', None, ['y']]}}
        self.assertEqual(S.normalize('devices.json', doc)['h1']['log_watch'], [{'unit': 'sshd', 'pattern': 'fail'}])
        prof = {'p1': {'log_watch': [{'path': '/var/log/syslog'}, '/var/log/x'], 'services_watched': ['nginx', 7, None, {'a': 1}]}}
        out = S.normalize('device_profiles.json', prof)['p1']
        self.assertEqual(out['log_watch'], [{'path': '/var/log/syslog'}])
        self.assertEqual(out['services_watched'], ['nginx', '7'])

    def test_a_stamp_a_sweep_sorts_by_is_a_number(self):
        for store in ('tls_results.json', 'ip_reputation_results.json', 'resolver_health_results.json'):
            with self.subTest(store=store):
                out = S.normalize(store, {'a': {'checked_at': None}, 'b': {'checked_at': 'x'}, 'c': {'checked_at': ['1']},
                                          'd': {'checked_at': '5'}, 'e': {'checked_at': 9}})
                self.assertEqual({k: v.get('checked_at') for k, v in out.items()}, {'a': None, 'b': None, 'c': None, 'd': 5, 'e': 9})
        tasks = S.normalize('tasks.json', {'tasks': [{'id': 'a', 'created_at': 'x', 'updated_at': ['1']}, {'id': 'b', 'created_at': 4}]})
        self.assertEqual(tasks['tasks'], [{'id': 'a'}, {'id': 'b', 'created_at': 4}])

    def test_the_kmip_store_keeps_its_maps_and_its_numbers(self):
        doc = {'clients': {'a': 7, 'b': {'not_after': 'x', 'name': 'ok'}, 'c': {'not_after': 5}}, 'ca': {'not_after': ['x']},
               '_cert_check': 5, 'daemon': {'last_state_fetch': 'soon'}}
        out = S.normalize('kmip.json', doc)
        self.assertEqual(out['clients'], {'b': {'name': 'ok'}, 'c': {'not_after': 5}})
        self.assertEqual((out['ca'], out['_cert_check'], out['daemon']), ({}, {}, {}))
        self.assertEqual(S.normalize('kmip.json', {'_cert_check': {'last_run': 3, 'alerted': 'x'}})['_cert_check'], {'last_run': 3, 'alerted': []})

    def test_the_patch_age_breaching_list_holds_host_ids(self):
        out = S.normalize('patch_age.json', {'_breaching': [{'a': 1}, 'h1', 7, None], 'h1': {'all_first': 1}})
        self.assertEqual(out['_breaching'], ['h1', '7'])

    def test_a_null_setting_is_read_as_not_set(self):
        out = S.normalize('config.json', {'monitor_interval': None, 'online_ttl': '90', 'patch_alert_threshold': [1], 'name': 'x'})
        self.assertEqual(out, {'online_ttl': 90, 'name': 'x'}, 'int(None) stopped the offline sweep on every request')

    def test_the_stamps_the_periodic_sweeps_convert_are_numbers(self):
        """Each of these is passed to int() by a sweep that runs from every request; one wrong value stopped the sweep, and with it
        the work it does (public IP check, the autonomy loop, the IP-intel block expiry), until someone found the file."""
        self.assertEqual(S.normalize('wan_state.json', {'checked': 'x', 'ip': '1.2.3.4'}), {'ip': '1.2.3.4'})
        self.assertEqual(S.normalize('autonomy_receipts.json', {'last_run': [1], 'receipts': []}), {'receipts': []})
        out = S.normalize('ip_intel.json', {'blocks': {'d': {'1.2.3.4': {'until': 'x', 'by': 'me'}, '1.2.3.5': 'junk'}, 'e': 'junk'},
                                            'budget': {'abuseipdb': [1], 'sniffcat': '4', 'day': 'x'}})
        self.assertEqual(out, {'blocks': {'d': {'1.2.3.4': {'by': 'me'}}}, 'budget': {'sniffcat': 4, 'day': 'x'}})

    def test_the_text_settings_a_string_method_is_called_on_are_text(self):
        out = S.normalize('config.json', {'audit_forward_mode': 7, 'smtp_tls': ['x'], 'siem_format': 'cef', 'issuer_name': None,
                                          'oidc_scopes': {'a': 1}, 'ldap_user_filter': 5,
                                          'ai': {'base_url': 7, 'embeddings': 'x'}})
        self.assertEqual(out, {'audit_forward_mode': '7', 'siem_format': 'cef', 'ldap_user_filter': '5',
                               'ai': {'base_url': '7', 'embeddings': {}}})

    # (store, a document with a text payload where a number belongs, and a number that must survive)
    NUMBER_FIELDS = (
        ('devices.json', lambda t, n: {'h': {'sysinfo': {
            'mounts': [{'percent': t, 'total_gb': t, 'used_gb': n}], 'disk_io': [{'busy_pct': t, 'read_mbs': t, 'write_mbs': n}],
            'firewall': {'backends': [{'rules': t}]}, 'firewall_fp': {'rules': t}, 'storage_health': [{'capacity': t}]}}}),
        ('hardware.json', lambda t, n: {'h': {
            'smart': [{'pending_sectors': t, 'power_on_hours': t, 'reallocated_sectors': n, 'temperature_c': t, 'wear_pct': t}],
            'gpus': [{'util_pct': t, 'power_w': n, 'mem_used_mb': t}], 'ups': [{'battery_pct': t, 'load_pct': t, 'power_w': n}]}}),
        ('drift_state.json', lambda t, n: {'h': {'files': {'/etc/x': {'drift_count': t, 'last_check': n}}}}),
        ('secret_findings.json', lambda t, n: {'h': {'findings': [{'line': t, 'fingerprint': 'f'}, {'line': n}]}}),
        ('scap.json', lambda t, n: {'h': {'fail': t, 'score': n}}),
        ('packages.json', lambda t, n: {'h': {'count': t, 'collected_at': n}}),
        ('speedtest.json', lambda t, n: {'h': [{'download_mbps': t, 'upload_mbps': t, 'ping_ms': n}]}),
        ('compose_stacks.json', lambda t, n: {'s-1': {'last_rc': t}}),
        ('ansible_playbooks.json', lambda t, n: {'playbooks': [{'last_rc': t}]}),
        ('automation_rules.json', lambda t, n: {'rules': [{'cooldown_seconds': t, 'fire_count': n}]}),
        ('inbound_webhooks.json', lambda t, n: {'tokens': [{'hit_count': t}]}),
        ('kmip_objects.json', lambda t, n: {'objects': {'o1': {'length': t}}}),
        ('netscan_schedules.json', lambda t, n: {'ns1': {'interval_minutes': t}}),
        ('patch_snapshots.json', lambda t, n: {'ps1': {'entry_count': t, 'created': n}}),
        ('webhook_dlq.json', lambda t, n: {'entries': [{'attempts': t}]}),
    )

    def test_a_number_stored_as_text_does_not_reach_a_page(self):
        """The web client review planted markup in every number of the stores (143,010 of them) and drove the pages: the fields
        below drew it unescaped. The agent channels keep only numbers there, so no host can store such a value, but a restore,
        an import or a hand edit can, and a number is not escaped where a page prints it. The loader reads such a field as
        absent. A number stays, and so does a number written as text."""
        payload = '" data-xq=1 x=""\'><img src=x onerror="alert(1)">'
        for store, make in self.NUMBER_FIELDS:
            with self.subTest(store=store):
                out = S.normalize(store, make(payload, 7))
                self.assertNotIn('data-xq', json.dumps(out), 'markup survived in a numeric field')
                self.assertEqual(S.normalize(store, make(7, 7)), make(7, 7), 'a number is left as it is')
                self.assertEqual(json.dumps(S.normalize(store, make('5', 7))), json.dumps(S.normalize(store, make(5, 7))),
                                 'a number written as text is read as that number')

    # The 7.4.9 sweep harness calls all 76 periodic sweeps with one stored node of the wrong shape at a time. These are the places
    # where a sweep still raised after the first registry: a stamp it converts with int(), a number it subtracts, a sort key, a
    # set element, a bucket it indexes. (store, a document holding a bad value, the document as it must be read)
    SWEEP_STAMPS = (
        ('alerts.json', {'alerts': [{'id': ['x'], 'resolved_at': 'x'}, {'id': 'a1'}]}, {'alerts': [{}, {'id': 'a1'}]}),
        ('ct_watch.json', {'a.example': {'last_check': 'x'}, 'b.example': 7}, {'a.example': {}}),
        ('cve_campaigns.json', {'campaigns': [], '_last_sample': [1]}, {'campaigns': []}),
        ('flow_deps.json', {'edges': {}, 'last_run': 'x'}, {'edges': {}}),
        ('incident_memory.json', {'outcomes': [], 'last_run': {'a': 1}}, {'outcomes': []}),
        ('integrations_state.json', {'latest': {'i1': {'checked': 'x', 'metrics': {}}}}, {'latest': {'i1': {'metrics': {}}}}),
        ('ip_intel.json', {'last_sweep': 'x'}, {}),
        ('ipam_state.json', {'last_run': 'x', 'conflicts': ['10.0.0.1', {'a': 1}, None]}, {'conflicts': ['10.0.0.1']}),
        ('mailflow_state.json', {'last_tick': [1]}, {}),
        ('netscan_schedules.json', {'ns1': {'interval_minutes': 'x', 'last_run': ['1']}}, {'ns1': {}}),
        ('proxmox_snapshot_cache.json', 7, {}),
        ('scan_schedules.json', {'s1': {'next_run': 'x', 'last_run': {'a': 1}, 'created': 5}}, {'s1': {'created': 5}}),
        ('self_backup_state.json', {'last_run': None, 'last_drill_at': 'x'}, {}),
        ('thermal_rollup.json', {'_meta': {'last_run': 'x'}, 'h1': {'hourly': [{'ts': 1}, {'ts': 'x'}, 5], 'last_ts': [1]}},
         {'_meta': {}, 'h1': {'hourly': [{'ts': 1}]}}),
        ('metrics_rollup.json', {'h1': {'daily': [{'ts': 1}, {'cpu': 5}], 'fivemin': 'x'}}, {'h1': {'daily': [{'ts': 1}], 'fivemin': []}}),
        ('vpn.json', {'tunnels': [{'expires_at': 'x', 'clients': [{'expires_at': [1]}, {'id': 'c'}]}]},
         {'tunnels': [{'clients': [{}, {'id': 'c'}]}]}),
    )

    def test_the_stamps_the_periodic_sweeps_subtract_and_sort_by_are_numbers(self):
        for store, bad, want in self.SWEEP_STAMPS:
            with self.subTest(store=store):
                self.assertEqual(S.normalize(store, copy.deepcopy(bad)), want)

    def test_a_saved_query_without_a_filter_keeps_its_null(self):
        """The product itself writes `where: null` for a fleet or metric query and for a predicate with no filter; the first
        registry repaired it on every read (23 times in the suite's own run). A filter of the wrong kind is removed."""
        out = S.normalize('query_templates.json', {'a': {'where': None}, 'b': {'where': {'x': 1}}, 'c': {'where': 'x'}, 'd': {'where': [1]}})
        self.assertEqual(out, {'a': {'where': None}, 'b': {'where': {'x': 1}}, 'c': {}, 'd': {}})

    def test_the_tls_scan_sorts_a_null_stamp(self):
        """The reader as well as the registry: a store written by something that skips the loader still reaches the sweep."""
        import importlib.util
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
        spec = importlib.util.spec_from_file_location('api_tls_sort', ROOT / 'server' / 'cgi-bin' / 'api.py')
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        keep = (mod._tls_targets, mod._tls_results, mod.TLS_SCAN_INTERVAL)
        mod._tls_targets = lambda: {'t1': {'host': 'a.example'}, 't2': {'host': 'b.example'}}
        mod._tls_results = lambda: {'t1': {'checked_at': None}, 't2': {'checked_at': 5}}
        mod.TLS_SCAN_INTERVAL = 10 ** 12          # nothing is due, so no probe is made: the sort is what is measured
        try:
            self.assertIsNone(mod.run_tls_scan_if_due())
        finally:
            mod._tls_targets, mod._tls_results, mod.TLS_SCAN_INTERVAL = keep


SCRIPT = r'''
import json, os, shutil, sys
src, dst, repo, switch = sys.argv[1:5]
shutil.copytree(src, dst, dirs_exist_ok=True)
os.environ['RP_DATA_DIR'] = dst
sys.stderr = open(os.devnull, 'w')
sys.path.insert(0, repo + '/server/cgi-bin')
import wsgi, api
if switch == 'off':
    api._shape_fix = lambda path, data, raw_text=None: data   # the old behaviour
client = wsgi.application.test_client()


def call(method, path, token=None, body=None):
    h = {'X-Forwarded-For': '10.9.9.9'}
    if token:
        h['X-Token'] = token
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h['Content-Type'] = 'application/json'
    r = client.open(path, method=method, data=data, headers=h, environ_overrides={'REMOTE_ADDR': '127.0.0.1'})
    return r.status_code, r.get_data()


users = api.load(api.USERS_FILE)
for v in users.values():
    if isinstance(v, dict):
        v['must_change_password'] = False
api.save(api.USERS_FILE, users)
tok = json.loads(call('POST', '/api/login', body={'username': 'alice', 'password': 'demo'})[1])['token']

PAGES = ['/api/home', '/api/alerts/summary', '/api/alerts', '/api/problems', '/api/fleet/health', '/api/attention',
         '/api/risk', '/api/compliance', '/api/devices', '/api/fleet/thermal', '/api/checks', '/api/patch-report',
         '/api/exposure', '/api/tickets', '/api/apikeys', '/api/fleet/events']
first = lambda d: next(iter(d))
CASES = {
    'a hardware row is a number':          ('hardware.json', lambda d: d.__setitem__(first(d), 7)),
    'alerts holds a string':               ('alerts.json', lambda d: d['alerts'].append('x')),
    'alerts is null':                      ('alerts.json', lambda d: d.__setitem__('alerts', None)),
    'alert mutes is null':                 ('alert_mutes.json', lambda d: d.__setitem__('mutes', None)),
    'fleet events is a number':            ('fleet_events.json', lambda d: d.__setitem__('events', 7)),
    'an api key row is null':              ('apikeys.json', lambda d: d.__setitem__(first(d), None)),
    'a scanner report is a number':        ('av_status.json', lambda d: d[first(d)].__setitem__('clamav', 7)),
    'a host row is null':                  ('devices.json', lambda d: d.__setitem__('ng01', None)),
    'a host\'s sysinfo is a number':       ('devices.json', lambda d: d['ng01'].__setitem__('sysinfo', 7)),
    'a user row is a number':              ('users.json', lambda d: d.__setitem__('bob', 7)),
    'a ticket is a string':                ('tickets.json', lambda d: d['tickets'].append('x')),
    'a package list holds null':           ('packages.json', lambda d: d[first(d)]['packages'].append(None)),
    'a thermal sample is null':            ('thermal_history.json', lambda d: d[first(d)]['samples'].append(None)),
    'the settings monitors is a number':   ('config.json', lambda d: d.__setitem__('monitors', 7)),
    'the settings root is a number':       ('config.json', lambda d: None),   # replaced below
}
out = {}
for name, (store, mut) in CASES.items():
    path = os.path.join(dst, store)
    orig = open(path, 'rb').read()
    doc = json.loads(orig)
    if name == 'the settings root is a number':
        doc = 7
    else:
        mut(doc)
    open(path, 'w').write(json.dumps(doc))
    api._LOAD_CACHE.clear()
    for c in ('fleet_checks_cache.json', 'attention_cache.json', 'fleet_risk_cache.json', 'fleet_reliability_cache.json'):
        try:
            os.unlink(os.path.join(dst, c))
        except FileNotFoundError:
            pass
    out[name] = {p: call('GET', p, tok)[0] for p in PAGES}
    open(path, 'wb').write(orig)
    api._LOAD_CACHE.clear()

# a stored NaN used to make every later write of that store raise: the audit trail stopped
path = os.path.join(dst, 'audit_log.json')
orig = open(path, 'rb').read()
doc = json.loads(orig)
doc['entries'][0]['ts'] = float('nan')
open(path, 'w').write(json.dumps(doc))
api._LOAD_CACHE.clear()
out['NaN in the audit log'] = {'/api/audit-log': call('GET', '/api/audit-log', tok)[0],
                              'login (writes the audit log)': call('POST', '/api/login', body={'username': 'alice', 'password': 'demo'})[0]}
print(json.dumps(out))
'''


class TestThePagesSurviveABadRow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.seed = Path(tempfile.mkdtemp(prefix='rp-shapes-seed-'))
        _seed(cls.seed)

    def run_pages(self, switch):
        dst = Path(tempfile.mkdtemp(prefix='rp-shapes-run-')) / 'data'
        r = subprocess.run([sys.executable, '-c', SCRIPT, str(self.seed), str(dst), str(ROOT), switch],
                           capture_output=True, text=True, timeout=900)
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_with_the_repair_every_page_answers_below_500_for_every_bad_row(self):
        got = self.run_pages('on')
        self.assertGreater(len(got), 12)
        bad = {case: {p: st for p, st in pages.items() if st >= 500 or st == 0} for case, pages in got.items()}
        self.assertEqual({c: v for c, v in bad.items() if v}, {})

    def test_control_with_the_repair_off_the_same_rows_do_break_pages(self):
        got = self.run_pages('off')
        broken = {c: [p for p, st in pages.items() if st >= 500] for c, pages in got.items()}
        self.assertTrue(broken['alerts holds a string'], 'the old behaviour is not visible: this test cannot fail')
        self.assertGreaterEqual(sum(1 for v in broken.values() if v), 6)


class TestANonFiniteNumberIsReadAsNothing(unittest.TestCase):

    def test_the_loader_reads_nan_and_infinity_as_null(self):
        import importlib.util
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
        spec = importlib.util.spec_from_file_location('api_nonfinite', ROOT / 'server' / 'cgi-bin' / 'api.py')
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(json.loads('{"a": NaN, "b": Infinity, "c": -Infinity, "d": 1}', parse_constant=mod._json_nonfinite),
                         {'a': None, 'b': None, 'c': None, 'd': 1})
        import inspect
        body = inspect.getsource(mod._load_uncached)
        self.assertEqual(body.count('json.loads('), 0, 'a store is parsed in _load_uncached without the number hooks')
        self.assertGreaterEqual(body.count('_json_loads('), 2, 'the store and its backup are both read through the hooks')
        self.assertIn('parse_constant=_json_nonfinite', inspect.getsource(mod._json_loads))
        self.assertEqual(mod._json_loads('{"a": %s, "b": 1e999, "c": 3}' % ('9' * 400)), {'a': None, 'b': None, 'c': 3},
                         'an integer of 400 digits and a float that overflows are read as null')


if __name__ == '__main__':
    unittest.main()
