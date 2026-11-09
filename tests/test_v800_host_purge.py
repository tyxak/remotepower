#!/usr/bin/env python3
"""8.0.0: deleting a host takes its own data with it, and what stays is listed with a reason.

`_purge_device` cleared the stores it knew by hand. In the demo instance, deleting each of the 18 hosts in turn left 66 of the 149 stores still naming the host that was just
deleted. Some are history and stay on purpose (an alert, a ticket, a time entry and the audit trail say what happened and to which host). The rest were the host's own data, the
schedules and mutes that name only it, and its place in groups, services, assignments and links. A runbook, a CMDB record and a webhook token for a host that no page can reach any
more are data nobody can delete, and a recurring job that names a host id is inherited by whatever enrolls under that id.

Population: every store file of the seeded demo instance, and every host of it. Each host is deleted with the real `_purge_device`, one after the other, and every store is read
back through the active backend (JSON, SQLite or Postgres, whichever the gate runs). A place that still names the deleted host is described as a pattern (store, how the id sits
there, path) and must be in KEEP with the reason it stays; a KEEP entry that no longer occurs fails too, so the list only shrinks. Controls: the scan finds planted residue, the
seed is large enough to mean something, every rule fires on the seed or is listed as one it cannot reach, and the rules have literal cases of their own.
"""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-hostpurge-'))
ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'
sys.path.insert(0, str(CGI))

import host_purge as HP  # noqa: E402
import store_shapes  # noqa: E402

SNAKE = re.compile(r'[a-z_]+')
GATE_BACKEND = os.environ.get('RP_STORAGE_BACKEND') or 'json'      # as the gate set it: read at import, before a test can change it

HISTORY = 'a record of what happened to the host; it keeps the id so the record still reads'
RECORD = 'a record people wrote; it keeps the id of the host it was about'
TEXT = 'text a person or the system wrote: the host is named in a sentence or a label, not referenced'
CONFIG = 'a setting an operator wrote; it matches no host once the host is gone, so nothing acts on it'
THIRD = "the third party's own name for it (a Proxmox node); it only happens to equal the host id in the demo"
OFF = 'switched off by the purge and kept, so what it was for stays visible'
MONITOR = "kept under the monitor's label, which names the host as text; the monitor stays, so its results stay with it"

# Where a deleted host is still named after the purge, and why that is right: (store, how the id sits there, path) -> reason.
KEEP = {
    ('alerts.json', 'value', 'alerts/[]/device_id'): 'alert history; the purge resolves the open ones (by "device-removed") and leaves the record',
    ('alerts.json', 'value', 'alerts/[]/payload/device_id'): 'alert history; the purge resolves the open ones (by "device-removed") and leaves the record',
    ('alerts.json', 'value', 'alerts/[]/payload/host_ids/[]'): 'an alert about several hosts is not the record of one of them',
    ('audit_log.json', 'token', 'entries/[]/detail'): 'the audit trail is append-only evidence and keeps the text it was written with',
    ('automation_rules.json', 'value', 'rules/[]/match/device_match/device_id'): OFF,
    ('autonomy_receipts.json', 'value', 'receipts/[]/blast_radius/device_id'): HISTORY,
    ('autonomy_receipts.json', 'value', 'receipts/[]/device_id'): HISTORY,
    ('batch_jobs.json', 'key', 'jobs/*/per_device/<HOST>'): 'a batch run is a record of what ran where and what each host answered',
    ('batch_jobs.json', 'value', 'jobs/*/targets/[]'): 'a batch run is a record of what ran where and what each host answered',
    ('calendar.json', 'token', 'events/[]/description'): TEXT,
    ('config.json', 'token', 'monitors/[]/label'): TEXT,
    ('config.json', 'value', 'custom_checks/[]/target'): CONFIG,
    ('config.json', 'value', 'drift/assignments/[]/scope_value'): CONFIG,
    ('config.json', 'value', 'monitors/[]/via_host'): CONFIG,
    ('config.json', 'value', 'proxmox_node'): THIRD,
    ('history.json', 'value', 'entries/[]/device_id'): 'command history: what ran on which host, and who ran it',
    ('image_updates.json', 'value', 'autoupdate/last_run/held/[]/device'): HISTORY,
    ('image_updates.json', 'value', 'autoupdate/last_run/held/[]/device_id'): HISTORY,
    ('image_updates.json', 'value', 'autoupdate/last_run/made_ids/[]'): HISTORY,
    ('image_updates.json', 'value', 'autoupdate/receipts/[]/device_id'): 'an update receipt; one that waited on an approval is closed as declined by the follow-up sweep',
    ('inbound_webhooks.json', 'value', 'tokens/[]/scope_device_id'): OFF,
    ('incident_memory.json', 'value', 'outcomes/[]/device_id'): 'what happened in past incidents, kept as precedent for the next one',
    ('kmip.json', 'token', 'clients/*/name'): TEXT,
    ('kmip_log.json', 'token', 'entries/[]/client'): TEXT,
    ('monitor_history.json', 'keytoken', '*'): MONITOR,
    ('pending_confirmations.json', 'value', 'confirmations/[]/device_id'): 'decisions stay as history; a pending one is declined by the purge',
    ('proxmox_backup_cache.json', 'value', 'node'): THIRD,
    ('remediations.json', 'value', '*/device_id'): 'a record of a fix that was tried and checked',
    ('rollouts.json', 'value', 'rollouts/[]/rings/[]/selector/ids/[]'): 'a rollout is a record of a plan; a ring skips a host that is gone when it is resolved',
    ('rollouts.json', 'value', 'rollouts/[]/rings_state/[]/dispatched_ids/[]'): HISTORY,
    ('satellite_monitors.json', 'keytoken', '*'): MONITOR,
    ('satellite_monitors.json', 'token', '*/by'): MONITOR,
    ('satellite_monitors.json', 'token', '*/label'): MONITOR,
    ('scans.json', 'value', '*/target_device_id'): 'a scan is a record of what was found, and where',
    ('sshgw_sessions.json', 'token', 'sessions/[]/target'): 'a gateway session is evidence of who connected to what',
    ('sshgw_sessions.json', 'value', 'sessions/[]/device_id'): 'a gateway session is evidence of who connected to what',
    ('tasks.json', 'value', 'tasks/[]/device_id'): RECORD,
    ('tickets.json', 'value', 'tickets/[]/affected_devices/[]'): RECORD,
    ('tickets.json', 'value', 'tickets/[]/device_id'): RECORD,
    ('time_entries.json', 'value', 'entries/[]/device_id'): RECORD,
    ('webhook_dlq.json', 'value', 'entries/[]/payload/device_id'): 'a failed delivery, kept as it was sent',
}

# Rules the seeded demo cannot exercise, with the reason; the literal cases below cover them.
NOT_IN_THE_SEED = {
    ('fleet_events.json', 1): 'the shape the purge used to look for (a top-level device_id); the seed writes events the way the server does',
    ('automation_rules.json', 0): 'the seeded rule that names a host is already switched off',
}


def pattern_of(path, host, ids):
    return '/'.join('<HOST>' if seg == host else '*' if seg in ids else seg for seg in path)


def scan(node, host, ids):
    """[(kind, pattern)] for every place `node` names `host`: as a key (key), as a whole value (value), inside a longer key or value (keytoken, token), or only as part of a word (substr)."""
    tok = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(host) + r'(?![A-Za-z0-9_])')
    out = []

    def walk(n, p):
        if isinstance(n, dict):
            for k, v in n.items():
                k = str(k)
                if k == host:
                    out.append(('key', pattern_of(p + ('<HOST>',), host, ids)))
                    walk(v, p + (k,))
                    continue
                if tok.search(k):
                    out.append(('keytoken', pattern_of(p + ('*',), host, ids)))
                elif host in k:
                    out.append(('substr', pattern_of(p + ('*',), host, ids)))
                walk(v, p + ((k if SNAKE.fullmatch(k) else '*'),))
        elif isinstance(n, list):
            for v in n:
                walk(v, p + ('[]',))
        elif isinstance(n, str):
            if n == host:
                out.append(('value', pattern_of(p, host, ids)))
            elif tok.search(n):
                out.append(('token', pattern_of(p, host, ids)))
            elif host in n:
                out.append(('substr', pattern_of(p, host, ids)))

    walk(node, ())
    return out


def load_api(data_dir):
    """A new api module over its own data directory. The module keeps DATA_DIR from the variable as it reads it, so the variable is put back straight after."""
    import importlib.util
    before = os.environ.get('RP_DATA_DIR')
    os.environ['RP_DATA_DIR'] = data_dir
    try:
        spec = importlib.util.spec_from_file_location('api_hostpurge', CGI / 'api.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if before is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = before
    return mod


_STATE = {}


def state():
    """The demo instance loaded into the active backend, with every host deleted in turn. Built on first use, once for the module, and only read afterwards."""
    if _STATE:
        return _STATE
    seed_dir = tempfile.mkdtemp(prefix='rp-hostpurge-seed-')
    data_dir = tempfile.mkdtemp(prefix='rp-hostpurge-data-')
    proc = subprocess.run([sys.executable, str(SEEDER), '--data-dir', seed_dir, '--apply', '--quiet'], capture_output=True, cwd=str(ROOT), timeout=900)
    assert proc.returncode == 0, 'the demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:]
    api = load_api(data_dir)
    rels = sorted(p.relative_to(seed_dir).as_posix() for p in Path(seed_dir).rglob('*.json'))
    for rel in rels:
        api.save(api.DATA_DIR / rel, json.loads((Path(seed_dir) / rel).read_text()))
    api._LOAD_CACHE.clear()
    hosts = sorted(api.load(api.DEVICES_FILE))
    ids = set(hosts)
    fired, residue, before_named, untouched = Counter(), Counter(), set(), []
    for i, host in enumerate(hosts):
        docs = {rel: api.load(api.DATA_DIR / rel) for rel in rels}
        for rel, doc in docs.items():
            if any(kind != 'substr' for kind, _pat in scan(doc, host, ids)):
                before_named.add(rel)
        for name, rules in HP.RULES.items():
            for j, rule in enumerate(rules):
                if HP.run(rule, docs.get(name) or {}, host, 0, True):       # a dry run changes nothing, so the loaded store is read as it is
                    fired[(name, j)] += 1
        dumps = {rel: json.dumps(doc, sort_keys=True) for rel, doc in docs.items()} if i == 0 else {}
        assert api._purge_device(host) is True, host
        api._LOAD_CACHE.clear()
        if i == 0:
            untouched = [rel for rel, text in dumps.items() if host not in text and json.dumps(api.load(api.DATA_DIR / rel), sort_keys=True) != text]
        for rel in rels:
            data = api.load(api.DATA_DIR / rel)
            for kind, pat in scan(data, host, ids):
                if kind != 'substr':
                    residue[(rel, kind, pat)] += 1
            if host in Path(rel).name and data:
                residue[(rel, 'file', '')] += 1
    _STATE.update(api=api, rels=rels, hosts=hosts, ids=ids, fired=fired, residue=residue, before_named=before_named, untouched=untouched, dirs=(seed_dir, data_dir))
    return _STATE


def tearDownModule():
    for d in _STATE.get('dirs', ()):
        shutil.rmtree(d, ignore_errors=True)       # the seed and the data of about 7 MB each are on tmpfs
    _STATE.clear()


class TestThePopulation(unittest.TestCase):

    def test_the_seed_is_large_enough_to_mean_something(self):
        s = state()
        self.assertGreaterEqual(len(s['hosts']), 15, s['hosts'])
        self.assertGreaterEqual(len(s['rels']), 120, 'store files seeded')
        self.assertGreaterEqual(len(s['before_named']), 70, 'stores that named a host before it was deleted (86 at 8.0.0): a scan over fewer measures little')

    def test_the_scan_finds_residue_it_is_shown(self):
        planted = {'rows': [{'device_id': 'h1', 'note': 'x'}], 'by': 'host:h1', 'h1': {}, 'text': 'moved off h1 today', 'word': 'sh1ne'}
        got = Counter(scan(planted, 'h1', {'h1'}))
        self.assertEqual(got[('value', 'rows/[]/device_id')], 1)
        self.assertEqual(got[('token', 'by')], 1)
        self.assertEqual(got[('key', '<HOST>')], 1)
        self.assertEqual(got[('token', 'text')], 1)
        self.assertEqual(got[('substr', 'word')], 1, 'a host id inside a longer word is a substring, not a reference')

    def test_every_rule_fires_on_the_seed_or_is_listed_as_unseeded(self):
        every = {(name, j) for name, rules in HP.RULES.items() for j in range(len(rules))}
        silent = {k for k in every if not state()['fired'][k]}
        self.assertEqual(sorted(silent - set(NOT_IN_THE_SEED)), [], 'rules no seeded host exercises: seed the data, or list the rule with the reason')
        self.assertEqual(sorted(set(NOT_IN_THE_SEED) - silent), [], 'listed as unseeded, and the seed now exercises them: take them off the list')

    def test_every_store_with_a_rule_is_a_store_the_server_knows(self):
        self.assertEqual([n for n in HP.RULES if n not in store_shapes.SHAPES], [])

    def test_it_ran_on_the_backend_the_gate_names(self):
        self.assertEqual(state()['api']._storage_backend(), GATE_BACKEND, 'a test that reads JSON in the SQLite gate measures the wrong backend')


class TestWhatIsLeft(unittest.TestCase):

    def test_what_still_names_a_deleted_host_is_listed_with_a_reason(self):
        unlisted = sorted(set(state()['residue']) - set(KEEP))
        self.assertEqual(unlisted, [], '%d places still name a deleted host and are not in KEEP: purge them (host_purge.RULES) or list them with the reason' % len(unlisted))

    def test_a_listed_place_still_occurs(self):
        gone = sorted(set(KEEP) - set(state()['residue']))
        self.assertEqual(gone, [], 'listed as staying, and nothing names a deleted host there any more: take them off the list')

    def test_every_listed_place_has_a_reason(self):
        self.assertEqual([k for k, why in KEEP.items() if len(why.split()) < 4], [])

    def test_the_stores_left_naming_a_host_are_a_fraction_of_what_named_one(self):
        s = state()
        left = {rel for (rel, _kind, _pat) in s['residue']}
        self.assertLess(len(left), len(s['before_named']) / 2, '%d of %d stores still name a deleted host' % (len(left), len(s['before_named'])))

    def test_the_documents_quote_the_number_the_test_counted(self):
        s = state()
        left = {rel for (rel, _kind, _pat) in s['residue']}
        review = re.sub(r'\s+', ' ', (ROOT / 'docs' / 'security-review-8.0.0.md').read_text())
        self.assertIn('%d of the %d stores of the demo instance still name a deleted host' % (len(left), len(s['rels'])), review)
        changelog = re.sub(r'\s+', ' ', (ROOT / 'CHANGELOG.md').read_text())
        self.assertIn('stores naming the host, and %d do now' % len(left), changelog)
        self.assertIn('left 66 of its %d stores naming the host' % len(s['rels']), changelog)

    def test_a_store_that_did_not_name_the_host_is_left_exactly_as_it_was(self):
        self.assertEqual(state()['untouched'], [], 'purging the first host changed stores that never named it')


class TestThroughTheRealPurge(unittest.TestCase):
    """The rules reach the stores through `_purge_device`, with the shapes the server's own producers write."""

    def setUp(self):
        self.api = state()['api']
        self.api.save(self.api.DEVICES_FILE, {i: {'id': i, 'name': i, 'token': 't-' + i} for i in ('zz1', 'zz2', 'zz3')})
        self.api._LOAD_CACHE.clear()

    def purge(self, host='zz1'):
        self.assertTrue(self.api._purge_device(host))
        self.api._LOAD_CACHE.clear()

    def test_the_events_the_server_records_go_with_the_host(self):
        api = self.api
        api.save(api.FLEET_EVENTS_FILE, {'events': []})
        api._record_fleet_event('drift_detected', {'device_id': 'zz1', 'device_name': 'one', 'path': '/etc/ssh/sshd_config'})
        api._record_fleet_event('drift_detected', {'device_id': 'zz2', 'device_name': 'two', 'path': '/etc/ssh/sshd_config'})
        api._LOAD_CACHE.clear()
        rows = api.load(api.FLEET_EVENTS_FILE)['events']
        self.assertEqual([r['payload']['device_id'] for r in rows], ['zz1', 'zz2'])
        self.assertNotIn('device_id', rows[0], 'the server keeps the host under `payload`, which is where the old filter never looked')
        self.purge()
        self.assertEqual([r['payload']['device_id'] for r in api.load(api.FLEET_EVENTS_FILE)['events']], ['zz2'])

    def test_a_pending_approval_for_the_host_is_declined_and_the_others_are_left(self):
        api, now = self.api, int(time.time())
        api.save(api.CONFIRMATIONS_FILE, {'confirmations': [
            {'id': 'c1', 'action': 'exec_command', 'device_id': 'zz1', 'status': 'pending', 'requested_at': now},
            {'id': 'c2', 'action': 'exec_command', 'device_id': 'zz1', 'status': 'approved', 'requested_at': now, 'decided_by': 'bob', 'decided_at': now},
            {'id': 'c3', 'action': 'exec_command', 'device_id': 'zz2', 'status': 'pending', 'requested_at': now}]})
        self.purge()
        rows = {c['id']: c for c in api.load(api.CONFIRMATIONS_FILE)['confirmations']}
        self.assertEqual((rows['c1']['status'], rows['c1']['decided_by'], rows['c1']['reject_note']), ('rejected', 'system', 'the host was deleted'))
        self.assertGreaterEqual(rows['c1']['decided_at'], now)
        self.assertEqual((rows['c2']['status'], rows['c2']['decided_by']), ('approved', 'bob'))
        self.assertEqual(rows['c3']['status'], 'pending')

    def test_a_webhook_token_and_an_automation_rule_for_the_host_are_switched_off_and_kept(self):
        api = self.api
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [
            {'id': 't1', 'label': 'a', 'token': 'rpwi_' + '0' * 32, 'kind': 'generic', 'scope_device_id': 'zz1', 'enabled': True},
            {'id': 't2', 'label': 'b', 'token': 'rpwi_' + '1' * 32, 'kind': 'generic', 'scope_device_id': 'zz2', 'enabled': True}]})
        api.save(api.RULES_FILE, {'rules': [
            {'id': 'r1', 'name': 'one', 'enabled': True, 'match': {'events': ['metric_warning'], 'device_match': {'device_id': 'zz1'}}},
            {'id': 'r2', 'name': 'two', 'enabled': True, 'match': {'events': ['metric_warning'], 'device_match': {'device_id': 'zz2'}}}]})
        self.purge()
        tokens = {t['id']: t for t in api.load(api.INBOUND_WEBHOOKS_FILE)['tokens']}
        self.assertEqual((tokens['t1']['enabled'], tokens['t1']['scope_device_id']), (False, 'zz1'), 'off, not widened to every host and not deleted')
        self.assertTrue(tokens['t2']['enabled'])
        rules = {r['id']: r for r in api.load(api.RULES_FILE)['rules']}
        self.assertEqual((rules['r1']['enabled'], rules['r1']['match']['device_match']['device_id']), (False, 'zz1'))
        self.assertTrue(rules['r2']['enabled'])

    def test_an_integration_that_ran_on_the_host_is_unbound_and_kept(self):
        api = self.api
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['integrations'] = [
            {'id': 'i1', 'type': 'prometheus_exporter', 'label': 'one', 'url': 'http://10.0.0.1:9100', 'enabled': True, 'device_id': 'zz1'},
            {'id': 'i2', 'type': 'prometheus_exporter', 'label': 'two', 'url': 'http://10.0.0.2:9100', 'enabled': True, 'device_id': 'zz2'}]
        api.save(api.CONFIG_FILE, cfg)
        self.purge()
        rows = {i['id']: i for i in api.load(api.CONFIG_FILE)['integrations']}
        self.assertEqual((rows['i1']['device_id'], rows['i1']['label'], rows['i1']['url'], rows['i1']['enabled']), ('', 'one', 'http://10.0.0.1:9100', True))
        self.assertEqual(rows['i2']['device_id'], 'zz2')

    def test_the_other_hosts_lose_their_link_to_it_and_keep_the_rest(self):
        api = self.api
        api.save(api.DEVICES_FILE, {
            'zz1': {'id': 'zz1', 'name': 'zz1', 'token': 't1'},
            'zz2': {'id': 'zz2', 'name': 'zz2', 'token': 't2', 'connected_to': 'zz1', 'depends_on': ['zz1', 'zz3']},
            'zz3': {'id': 'zz3', 'name': 'zz3', 'token': 't3', 'connected_to': 'zz2'}})
        self.purge()
        devs = api.load(api.DEVICES_FILE)
        self.assertEqual(sorted(devs), ['zz2', 'zz3'])
        self.assertEqual((devs['zz2']['connected_to'], devs['zz2']['depends_on']), ('', ['zz3']))
        self.assertEqual(devs['zz3']['connected_to'], 'zz2')


class TestAStoreTheHostWasNeverIn(unittest.TestCase):

    def test_the_purge_does_not_create_it(self):
        empty = tempfile.mkdtemp(prefix='rp-hostpurge-empty-')
        self.addCleanup(shutil.rmtree, empty, True)
        api = load_api(empty)
        names = [n for n in HP.STORES if n not in ('devices.json', 'config.json')]
        self.assertEqual([n for n in names if api.backend_exists(api.DATA_DIR / n)], [], 'control: the empty instance starts without them')
        api.save(api.DEVICES_FILE, {'zz1': {'id': 'zz1', 'name': 'zz1', 'token': 't1'}})
        self.assertTrue(api._purge_device('zz1'))
        self.assertEqual([n for n in names if api.backend_exists(api.DATA_DIR / n)], [], 'a store with nothing to clear is read, never locked or written')


class TestTheRules(unittest.TestCase):
    """Each kind of rule on a literal, including the shapes a damaged store holds."""

    def run_rule(self, rule, data, host='h1', now=7, dry=False):
        return HP.run(rule, data, host, now, dry)

    def test_pop_takes_the_hosts_entry_and_no_other(self):
        d = {'h1': 1, 'h2': 2, 'h10': 3}
        self.assertEqual(self.run_rule(HP.pop(), d), 1)
        self.assertEqual(d, {'h2': 2, 'h10': 3})

    def test_pop_follows_a_path_and_a_wildcard(self):
        d = {'blocks': {'h1': 1, 'h2': 2}, 'attackers': {'a': {'devices': {'h1': 1, 'h2': 2}}, 'b': {'devices': {'h2': 3}}, 'c': 'junk'}}
        self.assertEqual(self.run_rule(HP.pop('blocks'), d), 1)
        self.assertEqual(self.run_rule(HP.pop('attackers', '*', 'devices'), d), 1)
        self.assertEqual(d, {'blocks': {'h2': 2}, 'attackers': {'a': {'devices': {'h2': 2}}, 'b': {'devices': {'h2': 3}}, 'c': 'junk'}})

    def test_pop_prefix_needs_the_separator_so_a_longer_id_is_safe(self):
        d = {'h1:/repo': 1, 'h1:/other': 2, 'h10:/repo': 3, 'h2:h1': 4}
        self.assertEqual(self.run_rule(HP.pop_prefix(), d), 2)
        self.assertEqual(d, {'h10:/repo': 3, 'h2:h1': 4})

    def test_pop_edge_takes_either_end_and_only_whole_ids(self):
        d = {'edges': {'h1:h2': 1, 'h2:h1': 2, 'h2:h3': 3, 'h10:h2': 4}}
        self.assertEqual(self.run_rule(HP.pop_edge('edges'), d), 2)
        self.assertEqual(d, {'edges': {'h2:h3': 3, 'h10:h2': 4}})

    def test_drop_takes_the_records_of_a_list_by_a_plain_and_by_a_dotted_field(self):
        d = {'mutes': [{'device_id': 'h1'}, {'device_id': 'h2'}, 'junk', None, 5], 'rules': [{'m': {'d': {'id': 'h1'}}}, {'m': {'d': {'id': 'h2'}}}]}
        self.assertEqual(self.run_rule(HP.drop('mutes', field='device_id'), d), 1)
        self.assertEqual(self.run_rule(HP.drop('rules', field='m.d.id'), d), 1)
        self.assertEqual(d, {'mutes': [{'device_id': 'h2'}, 'junk', None, 5], 'rules': [{'m': {'d': {'id': 'h2'}}}]})

    def test_drop_takes_the_records_of_a_map_and_a_record_whose_list_holds_the_host(self):
        d = {'t1': {'endpoints': ['h1', 'h2']}, 't2': {'endpoints': ['h2', 'h3']}, 't3': {'endpoints': ['h3', 'h1']}, 'meta': 4}
        self.assertEqual(self.run_rule(HP.drop(field='endpoints'), d), 2)
        self.assertEqual(d, {'t2': {'endpoints': ['h2', 'h3']}, 'meta': 4})

    def test_drop_where_narrows_the_rule_to_the_records_that_match(self):
        d = {'windows': [{'scope': 'device', 'target': 'h1'}, {'scope': 'tag', 'target': 'h1'}, {'scope': 'device', 'target': 'h2'}]}
        self.assertEqual(self.run_rule(HP.drop('windows', field='target', where={'scope': 'device'}), d), 1)
        self.assertEqual(d['windows'], [{'scope': 'tag', 'target': 'h1'}, {'scope': 'device', 'target': 'h2'}])

    def test_unlist_takes_every_copy_and_leaves_the_rest(self):
        d = {'g': {'members': ['h1', 'h2', 'h1', 'h3']}, 'h': {'members': 'h1'}, 'k': 7}
        self.assertEqual(self.run_rule(HP.unlist('*', 'members'), d), 2)
        self.assertEqual(d, {'g': {'members': ['h2', 'h3']}, 'h': {'members': 'h1'}, 'k': 7})

    def test_put_switches_off_the_records_that_name_the_host_and_does_it_once(self):
        d = {'tokens': [{'scope_device_id': 'h1', 'enabled': True}, {'scope_device_id': 'h2', 'enabled': True}, {'scope_device_id': 'h1'}]}
        rule = HP.put('tokens', field='scope_device_id', to={'enabled': False})
        self.assertEqual(self.run_rule(rule, d), 2)
        self.assertEqual([t.get('enabled') for t in d['tokens']], [False, True, False])
        self.assertEqual(self.run_rule(rule, d), 0, 'a second delete of the same id changes nothing')

    def test_put_stamps_the_time_and_only_where_the_record_still_matches(self):
        d = {'c': [{'device_id': 'h1', 'status': 'pending'}, {'device_id': 'h1', 'status': 'approved'}, {'device_id': 'h2', 'status': 'pending'}]}
        rule = HP.put('c', field='device_id', where={'status': 'pending'}, to={'status': 'rejected', 'decided_at': HP.NOW})
        self.assertEqual(self.run_rule(rule, d, now=1234), 1)
        self.assertEqual(d['c'][0], {'device_id': 'h1', 'status': 'rejected', 'decided_at': 1234})
        self.assertEqual(d['c'][1]['status'], 'approved')
        self.assertEqual(d['c'][2]['status'], 'pending')
        self.assertEqual(self.run_rule(rule, d, now=9999), 0)
        self.assertEqual(d['c'][0]['decided_at'], 1234, 'the first decision is not restamped')

    def test_put_can_unbind_a_field_on_the_other_hosts_records(self):
        d = {'a': {'connected_to': 'h1'}, 'b': {'connected_to': 'h2'}, 'c': {}}
        self.assertEqual(self.run_rule(HP.put(field='connected_to', to={'connected_to': ''}), d), 1)
        self.assertEqual(d, {'a': {'connected_to': ''}, 'b': {'connected_to': 'h2'}, 'c': {}})

    def test_a_dry_run_changes_nothing_and_counts_what_a_real_run_changes(self):
        for rule, data in (
                (HP.pop(), {'h1': 1}), (HP.pop_prefix(), {'h1:x': 1}), (HP.pop_edge('e'), {'e': {'h1:h2': 1}}), (HP.drop('r', field='d'), {'r': [{'d': 'h1'}]}),
                (HP.unlist('l'), {'l': ['h1']}), (HP.put('r', field='d', to={'on': False}), {'r': [{'d': 'h1', 'on': True}]})):
            before = copy.deepcopy(data)
            dry = self.run_rule(rule, data, dry=True)
            self.assertEqual(data, before, rule.kind)
            self.assertEqual(self.run_rule(rule, data), dry, rule.kind)
            self.assertNotEqual(data, before, rule.kind)

    def test_a_store_of_the_wrong_kind_is_passed_over_without_an_error(self):
        for junk in (None, 5, 'text', [], {}, [None, 3], {'x': None}):
            for name in HP.STORES:
                HP.apply(name, copy.deepcopy(junk), 'h1', 1)

    def test_every_rule_is_well_formed(self):
        kinds = {'pop', 'pop_prefix', 'pop_edge', 'drop', 'unlist', 'put'}
        for name, rules in HP.RULES.items():
            self.assertTrue(name.endswith('.json'), name)
            self.assertTrue(rules, name)
            for rule in rules:
                self.assertIn(rule.kind, kinds, name)
                if rule.kind in ('drop', 'put'):
                    self.assertTrue(rule.field, '%s: a %s rule names the field that holds the host' % (name, rule.kind))
                else:
                    self.assertEqual(rule.field, '', name)
                self.assertEqual(bool(rule.to), rule.kind == 'put', name)


if __name__ == '__main__':
    unittest.main()
