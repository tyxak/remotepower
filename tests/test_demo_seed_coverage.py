#!/usr/bin/env python3
"""8.0.2: the demo seeder gives the first half of the release something to show, in the shape the server itself writes.

The rendered gates and the public demo measure the SEEDED instance, so a feature the seeder leaves out shows an empty state to all of them. Five features of the first half
of 8.0.2 had no seeded data. Each is read back here through the code that reads it (the real handlers, over a data directory the seeder wrote and that is loaded into the
backend the gate runs), and each seeded row is held to what the server's own producer writes:

  * the Enroll dialog's list of open install commands has one row, "Branch rollout", used 7 of 25: the real create handler and seven real enrolments write the same row;
  * the Patches page's mean time to patch has a figure for 30 days and another for 90, for the fleet and for a host with five pairs of its own: every pair goes through
    the sweep's own filing function, the real sweep run over the seed files nothing more, and no host shows as completed what it still shows as pending;
  * the Windows host and the Mac hold the lists their agents send, not the package list of an Ubuntu host: the real ingest stores the same entries from the same rows, the
    real evaluation files the same policy violations, and the CVE views say that nothing on them is checked;
  * software metering has three rules from software the hosts have: one short of licences with a cost, one with licences to spare and a cost, one with spare licences and none;
  * one destination, Apprise, is failing: the real fan-out, with only the network replaced by a failed name lookup, writes the same streak.

Every store the seed touches is held to the shape registry (`store_shapes.normalize` changes nothing), and the two hosts have no Ubuntu left in the seed. A check that passed over
an empty seed would pass for any reason, so the controls come first and the commit message lists the changes to the seeder that were made one at a time to see each check fail.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-demoseedcov-'))
ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
JS = ROOT / 'server' / 'html' / 'static' / 'js'
SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'
sys.path.insert(0, str(CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cve_scanner  # noqa: E402
import software_inventory as inventory  # noqa: E402
import srcpin  # noqa: E402
import store_shapes  # noqa: E402
import windows_host  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

NODE = shutil.which('node')
HOUR, DAY = 3600, 86400
WIN, MAC = 'wks01', 'mbp01'
TOKENS = {'k': ('alice', 'admin'), 'v': ('demo', 'viewer'), 'f': ('finn', 'finance')}      # the demo's own administrator and viewer, and a finance user
NEW_STORES = ('enrollment_tokens.json', 'patch_done.json', 'notify_health.json')
# the stores this work adds or changes (devices.json for the pending updates of the two hosts)
TOUCHED = NEW_STORES + ('packages.json', 'cve_findings.json', 'software_policy.json', 'software_violations.json', 'patch_age.json', 'config.json', 'devices.json')
# the touched stores the shape registry has no entry for: listed, so that an entry added later is a change this file notices
UNREGISTERED = ('enrollment_tokens.json', 'software_policy.json')

seed = None
UBUNTU = {}
if SEEDER.is_file():
    _spec = importlib.util.spec_from_file_location('seed_demo_coverage', SEEDER)
    seed = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(seed)
    UBUNTU = dict(seed._DEMO_INSTALLED_PACKAGES)         # name -> version of the package list the Ubuntu hosts of the demo carry


def load_api(data_dir):
    """A new api module over its own data directory. The module keeps DATA_DIR from the variable as it reads it, so the variable is put back straight after."""
    before = os.environ.get('RP_DATA_DIR')
    os.environ['RP_DATA_DIR'] = data_dir
    try:
        spec = importlib.util.spec_from_file_location('api_demoseedcov', CGI / 'api.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if before is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = before
    mod.verify_token = lambda token: TOKENS.get(token, (None, None))       # the session store only: the gates and the scope filters are the real ones
    return mod


_STATE = {}


def state():
    """The demo seeded into a directory by the command-line seeder (so a builder that is not in BUILDERS is not there), and loaded into the backend of the gate through the
    storage layer. Built on first use, once for the module, and only read afterwards. `raw` holds the documents as the seeder wrote them."""
    if _STATE:
        return _STATE
    seed_dir = tempfile.mkdtemp(prefix='rp-demoseedcov-seed-')
    data_dir = tempfile.mkdtemp(prefix='rp-demoseedcov-data-')
    _STATE['dirs'] = [seed_dir, data_dir]
    t0 = int(time.time())
    proc = subprocess.run([sys.executable, str(SEEDER), '--data-dir', seed_dir, '--apply', '--quiet'], capture_output=True, cwd=str(ROOT), timeout=900)
    assert proc.returncode == 0, 'the demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:]
    api = load_api(data_dir)
    raw = {p.name: json.loads(p.read_text()) for p in sorted(Path(seed_dir).glob('*.json'))}
    for name, doc in raw.items():
        api.save(api.DATA_DIR / name, copy.deepcopy(doc))
    api._LOAD_CACHE.clear()
    _STATE.update(api=api, raw=raw, seeded_at=t0)
    return _STATE


def scratch(stores=(), fire=False):
    """A new api over a data directory of its own, holding the named seeded stores, for the checks that write (a replay of the producer): the shared one is never written.
    Webhooks and the audit trail are replaced by a recorder (`api.told`), except with `fire`, which keeps the real fan-out and records each event it is asked for."""
    s = state()
    d = tempfile.mkdtemp(prefix='rp-demoseedcov-scratch-')
    s['dirs'].append(d)
    api = load_api(d)
    for name in stores:
        api.save(api.DATA_DIR / name, copy.deepcopy(s['raw'][name]))
    api._LOAD_CACHE.clear()
    api.audit_log = lambda *a, **k: None
    api._ip_ratelimit = lambda *a, **k: True
    api.told = []
    real = api.fire_webhook

    def fire_webhook(event, payload=None, *a, **k):
        api.told.append((event, dict(payload or {})))
        return real(event, payload, *a, **k) if fire else None
    api.fire_webhook = fire_webhook
    return api


def setUpModule():
    if not SEEDER.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    state()


def tearDownModule():
    for d in _STATE.get('dirs', ()):
        shutil.rmtree(d, ignore_errors=True)       # the seed, the data and the scratch directories are on tmpfs
    _STATE.clear()


def call(api, fn, *args, token='k', method='GET', query='', body=None):
    """A handler run as a request: (status, body). `token` None sends no credentials."""
    env = {'QUERY_STRING': query}
    if token:
        env['HTTP_AUTHORIZATION'] = 'Bearer ' + token
    return _run(api, lambda: fn(*args), body, method=method, env=env)


def ok(test, api, fn, *args, **kw):
    st, out = call(api, fn, *args, **kw)
    test.assertEqual(st, 200, out)
    return out


def node_json(script):
    d = Path(tempfile.mkdtemp(prefix='rp-demoseedcov-js-'))
    try:
        f = d / 'run.js'
        f.write_text(script)
        r = subprocess.run([NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class _Seeded(unittest.TestCase):

    @property
    def api(self):
        return state()['api']

    @property
    def raw(self):
        return state()['raw']

    def fresh(self):
        self.api._LOAD_CACHE.clear()


class TestTheSeedIsWorthMeasuring(_Seeded):
    """The controls of the file: every check below reads what the seeder wrote, so these say that it wrote it, and that the handlers read it."""

    def test_the_seed_wrote_the_three_new_stores_among_the_rest(self):
        self.assertLessEqual(set(NEW_STORES), set(self.raw))
        self.assertGreaterEqual(len(self.raw), 150, 'a seed of a few files would make everything below pass over nothing')

    def test_the_new_builders_are_where_apply_writes_from(self):
        self.assertLessEqual(set(NEW_STORES), set(seed.BUILDERS))

    def test_the_handlers_read_the_hosts_the_seeder_wrote(self):
        self.fresh()
        self.assertEqual(set(self.api.load(self.api.DEVICES_FILE)), set(self.raw['devices.json']))
        self.assertLessEqual({WIN, MAC}, set(self.raw['devices.json']))

    def test_the_two_callers_are_an_administrator_and_a_viewer(self):
        self.assertEqual(call(self.api, self.api.handle_enroll_token_list)[0], 200)
        self.assertNotEqual(call(self.api, self.api.handle_enroll_token_list, token='v')[0], 200, 'the list of open install commands is for administrators')

    def test_it_ran_on_the_backend_the_gate_names(self):
        self.assertEqual(self.api._storage_backend(), os.environ.get('RP_STORAGE_BACKEND') or 'json')


# ── 1. Enrolment, many hosts ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestTheOpenInstallCommand(_Seeded):

    def rows(self):
        self.fresh()
        return ok(self, self.api, self.api.handle_enroll_token_list)

    def test_the_list_returns_the_open_command_used_seven_of_twenty_five(self):
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual((r['label'], r['max_uses'], r['uses'], r['uses_left'], r['actor']), ('Branch rollout', 25, 7, 18, 'alice'))
        self.assertEqual('used %d of %d' % (r['uses'], r['max_uses']), 'used 7 of 25')
        self.assertEqual((r['default_group'], r['default_tags'], r['allowed_cidrs']), ('', [], []), 'nothing else is on the command')
        self.assertRegex(r['prefix'], r'^[A-Za-z0-9_-]{8}…$')
        self.assertTrue(DAY - 600 < r['remaining_seconds'] <= DAY, 'it expires a day ahead: %s' % r['remaining_seconds'])
        self.assertNotIn('token', r)

    def test_the_stored_row_has_the_fields_and_the_kinds_the_server_writes_for_a_command_seven_hosts_used(self):
        # the real create handler, then seven real enrolments through the real register handler
        api = scratch()
        st, made = call(api, api.handle_enroll_token_create, method='POST', body={'label': 'Branch rollout', 'expires_in': 30 * HOUR, 'max_uses': 25})
        self.assertEqual(st, 201, made)
        for i in range(7):
            st, out = call(api, api.handle_enroll_register, token=None, method='POST', body={'enrollment_token': made['token'], 'hostname': 'branch-%d' % i, 'name': 'branch-%d' % i})
            self.assertIn(st, (200, 201), out)
        api._LOAD_CACHE.clear()
        (key, produced), = api.load(api.ENROLL_TOKENS_FILE).items()
        self.assertEqual(key, hashlib.sha256(made['token'].encode()).hexdigest(), 'control: the server keys a command by the digest of its token')
        self.assertEqual(produced['prefix'], made['token'][:8])
        (seeded_key, seeded), = self.raw['enrollment_tokens.json'].items()
        self.assertRegex(seeded_key, r'^[0-9a-f]{64}$')
        self.assertEqual(set(seeded), set(produced), 'the seeded row holds the fields the server writes and no others')
        self.assertEqual({k: type(v) for k, v in seeded.items()}, {k: type(v) for k, v in produced.items()})
        for field in ('actor', 'default_group', 'default_tags', 'label', 'max_uses', 'uses'):
            self.assertEqual(seeded[field], produced[field], field)
        self.assertEqual(len(seeded['prefix']), len(produced['prefix']))
        self.assertEqual((api._enrol_token_counts(produced), self.api._enrol_token_counts(seeded)), ((7, 25), (7, 25)))

    def test_no_token_is_kept_and_the_key_cannot_be_worked_out_from_the_source(self):
        (key, row), = self.raw['enrollment_tokens.json'].items()
        self.assertNotIn('token', row)
        (again_key, again_row), = seed.build_enrollment_tokens().items()
        self.assertEqual(again_row['prefix'], row['prefix'], 'the prefix a person reads is the same on every run')
        self.assertNotEqual(again_key, key, 'the key is the digest of a token nobody holds, so it differs from run to run: no credential is written in the source')


# ── 2. Mean time to patch ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def mean(values):
    return sum(values) / len(values)


class TestTheMeanTimeToPatch(_Seeded):

    def report(self, days=None):
        self.fresh()
        return ok(self, self.api, self.api.handle_patch_report, query=('mttp_days=%d' % days) if days else '')['mttp']

    def pairs(self):
        return {h: e['done'] for h, e in self.raw['patch_done.json'].items()}

    def test_the_card_has_a_figure_for_thirty_days_and_another_for_ninety(self):
        m30, m90 = self.report(), self.report(90)
        self.assertEqual((m30['window_days'], m90['window_days']), (30, 90))
        for kind in ('all', 'sec'):
            a, b = m30['fleet'][kind], m90['fleet'][kind]
            self.assertFalse(a['hidden'], (kind, a))
            self.assertFalse(b['hidden'], (kind, b))
            self.assertGreaterEqual(a['n'], 5, kind)
            self.assertGreater(b['n'], a['n'], kind + ': the older pairs are what the longer window adds')
            for field in ('mean_h', 'median_h', 'p90_h'):
                self.assertIsInstance(a[field], float, (kind, field))
            self.assertNotEqual(a['mean_h'], b['mean_h'], kind + ': a different figure for 90 days')
            self.assertLessEqual(a['median_h'], a['p90_h'])
        self.assertGreaterEqual(m30['fleet']['all']['hosts'], 5, 'the pairs come from several hosts, not one')

    def test_the_figures_are_the_ones_the_pairs_come_to(self):
        done, now = self.raw['patch_done.json'], int(time.time())
        for days in (30, 90):
            m = self.report(days)
            for kind in ('all', 'sec'):
                hours = [(c - f) / HOUR for e in done.values() for f, c, k in e['done'] if k == kind and now - days * DAY <= c <= now]
                got = m['fleet'][kind]
                self.assertEqual(got['n'], len(hours), (days, kind))
                self.assertAlmostEqual(got['mean_h'], mean(hours), delta=0.05, msg=(days, kind))

    def test_a_host_has_five_pairs_of_its_own_so_a_per_host_figure_exists(self):
        m = self.report()
        own = {h: v['all'] for h, v in m['hosts'].items() if 'all' in v and not v['all']['hidden']}
        self.assertTrue(own, 'no host has five pairs of its own in 30 days: %s' % m['hosts'])
        host, stats = sorted(own.items())[0]
        self.assertGreaterEqual(stats['n'], 5)
        self.assertIsInstance(stats['mean_h'], float)
        self.assertTrue(any(v['all']['hidden'] for v in m['hosts'].values() if 'all' in v), 'control: other hosts have fewer than five and show no figure')

    def test_some_pairs_are_older_than_thirty_days_and_younger_than_ninety_and_some_are_security_only(self):
        now = int(time.time())
        rows = [(h, f, c, k) for h, ps in self.pairs().items() for f, c, k in ps]
        self.assertTrue([r for r in rows if 30 * DAY < now - r[2] < 90 * DAY], 'nothing for the 90-day window to add')
        self.assertGreaterEqual(len([r for r in rows if now - r[2] <= 30 * DAY and r[3] == 'all']), 5)
        self.assertGreaterEqual(len([r for r in rows if now - r[2] <= 30 * DAY and r[3] == 'sec']), 5)
        alls = {(h, f, c) for h, f, c, k in rows if k == 'all'}
        self.assertTrue([r for r in rows if r[3] == 'sec' and (r[0], r[1], r[2]) not in alls], 'every security pair cleared with an any-update pair: none is security only')

    def test_every_pair_is_one_the_sweeps_own_filing_function_would_file_in_this_order(self):
        api = self.api
        for host, ps in self.pairs().items():
            entry = {}
            for first, cleared, kind in ps:
                api._patch_done_add(entry, first, cleared, kind)
            self.assertEqual(entry['done'], ps, host)
            self.assertEqual(ps, sorted(ps, key=lambda p: (p[1], p[2] != 'all')), '%s: oldest first, any-update before security when one check cleared both' % host)
            self.assertTrue(all(isinstance(x, int) and not isinstance(x, bool) for p in ps for x in p[:2]), host)

    def test_the_episodes_of_a_host_are_apart_and_a_security_pair_lies_inside_an_any_update_pair(self):
        for host, ps in self.pairs().items():
            for kind in ('all', 'sec'):
                spans = sorted((f, c) for f, c, k in ps if k == kind)
                for (f1, c1), (f2, c2) in zip(spans, spans[1:]):
                    self.assertLess(c1, f2, '%s %s: one wait starts before the one before it was over' % (host, kind))
            alls = [(f, c) for f, c, k in ps if k == 'all']
            open_all = (self.raw['patch_age.json'].get(host) or {}).get('all_first')
            for f, c, k in ps:
                if k == 'sec':
                    inside = any(fa <= f and c <= ca for fa, ca in alls) or (open_all is not None and open_all <= f)
                    self.assertTrue(inside, '%s: a security update waited while no update of any kind was waiting' % host)

    def test_no_host_shows_as_completed_what_it_shows_as_pending(self):
        age, devices, done = self.raw['patch_age.json'], self.raw['devices.json'], self.raw['patch_done.json']
        pending = {'all_first': 'upgradable', 'sec_first': 'security_updates'}
        kinds = {'all_first': 'all', 'sec_first': 'sec'}
        stamps = sorted((h, k) for h, st in age.items() if not h.startswith('_') for k in st)
        self.assertIn(('tnas', 'all_first'), stamps, 'control: the seed has stamps')
        for host, key in stamps:
            self.assertGreater(devices[host]['sysinfo']['packages'][pending[key]], 0, '%s keeps a %s stamp but reports none of those updates pending' % (host, key))
            for f, c, k in done.get(host, {}).get('done', []):
                if k == kinds[key]:
                    self.assertLess(c, age[host][key], '%s: updates it shows as pending are also filed as completed' % host)
        # the security update tnas showed 10 days ago is applied: its stamp is a completed pair now, with the first-seen time the stamp had
        self.assertNotIn('sec_first', age['tnas'])
        story = [f for f, c, k in done['tnas']['done'] if k == 'sec' and c - f == 7 * DAY]
        self.assertEqual(len(story), 1)
        self.assertAlmostEqual(story[0], time.time() - 10 * DAY, delta=DAY * 0.05)

    def test_the_real_sweep_run_over_the_seed_files_nothing_more(self):
        api = scratch(['devices.json', 'config.json', 'patch_age.json', 'patch_done.json'])
        before = copy.deepcopy(api.load(api.PATCH_DONE_FILE))
        self.assertGreaterEqual(int(time.time()) - api.load(api.PATCH_AGE_FILE)['_last_run'], api.PATCH_SLA_INTERVAL, 'control: the sweep is due, as it is on the first request after a seed')
        api.run_patch_sla_if_due()
        api._LOAD_CACHE.clear()
        self.assertGreater(api.load(api.PATCH_AGE_FILE)['_last_run'], time.time() - 60, 'control: the sweep ran')
        self.assertEqual(api.load(api.PATCH_DONE_FILE), before, 'the sweep filed a pair of its own: the aging store and the hosts disagree')
        # the instrument sees one: put the spent stamp back, as the seed had it, and the same sweep files the pair of tnas
        age = api.load(api.PATCH_AGE_FILE)
        age['tnas']['sec_first'] = int(time.time()) - 10 * DAY
        age['_last_run'] = 0
        api.save(api.PATCH_AGE_FILE, age)
        api._LOAD_CACHE.clear()
        api.run_patch_sla_if_due()
        api._LOAD_CACHE.clear()
        after = api.load(api.PATCH_DONE_FILE)['tnas']['done']
        self.assertEqual(len(after), len(before['tnas']['done']) + 1)
        self.assertEqual(after[-1][2], 'sec')


# ── 3. The software of the Windows host and the Mac ─────────────────────────────────────────────────────────────────────────────────────────────────────

class TestTheListsOfTheTwoHosts(_Seeded):

    def entry(self, host):
        return self.raw['packages.json'][host]

    def test_the_windows_host_holds_the_list_its_agent_sends(self):
        e = self.entry(WIN)
        self.assertEqual((e['pkg_manager'], e['ecosystem'], e['os_id'], e['version_id'], e['skipped']), ('windows', '', '', '', 41))
        self.assertEqual(e['count'], len(e['packages']))
        self.assertGreaterEqual(len(e['packages']), 20)
        names = [p['name'] for p in e['packages']]
        for word in ('Microsoft 365', 'Google Chrome', 'Visual Studio Code', '7-Zip', 'OpenVPN', 'AnyDesk'):
            self.assertTrue([n for n in names if word in n], word)
        for p in e['packages']:
            self.assertEqual(p['manager'], 'windows')
            self.assertEqual(sorted(set(p) - {'publisher', 'installed'}), ['arch', 'manager', 'name', 'version'])
            self.assertRegex(p.get('installed', '2000-01-01'), r'^\d{4}-\d{2}-\d{2}$')
        self.assertTrue([p for p in e['packages'] if 'installed' not in p], 'a program whose key has no date')
        self.assertEqual(names, sorted(names, key=str.lower), 'the agent sends the list sorted by name')

    def test_the_mac_holds_applications_with_their_bundle_ids_and_some_homebrew_rows(self):
        e = self.entry(MAC)
        self.assertEqual((e['pkg_manager'], e['ecosystem'], e['os_id'], e['version_id']), ('macos', '', '', ''))
        apps = [p for p in e['packages'] if p['manager'] == 'macos']
        brew = [p for p in e['packages'] if p['manager'] == 'brew']
        self.assertGreaterEqual(len(apps), 15)
        self.assertGreaterEqual(len(brew), 3)
        self.assertTrue(all(re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+$', p['id']) for p in apps), 'a bundle identifier')
        self.assertTrue(all('id' not in p for p in brew), 'a Homebrew row has no identifier')
        self.assertEqual({p['manager'] for p in e['packages']}, {'macos', 'brew'})
        self.assertEqual(e['count'], len(e['packages']))

    def test_the_entries_are_what_the_real_ingest_stores_from_the_same_rows(self):
        api = scratch(['devices.json', 'config.json', 'software_policy.json'])
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {k: v for k, v in self.raw['software_violations.json'].items() if k not in (WIN, MAC)})
        api._LOAD_CACHE.clear()
        devices = self.raw['devices.json']
        for host, manager in ((WIN, 'windows'), (MAC, 'macos')):
            seeded = self.entry(host)
            body = {'device_id': host, 'token': devices[host]['token'], 'pkg_manager': manager, 'packages': copy.deepcopy(seeded['packages']), 'skipped': seeded['skipped']}
            st, out = call(api, api.handle_packages_submit, token=None, method='POST', body=body)
            self.assertEqual((st, out['ecosystem'], out['packages_stored']), (200, 'unsupported', len(seeded['packages'])), out)
            api._LOAD_CACHE.clear()
            stored = api.load(api.PACKAGES_FILE)[host]
            self.assertEqual({k: v for k, v in stored.items() if k != 'collected_at'}, {k: v for k, v in seeded.items() if k != 'collected_at'}, host)
            self.assertEqual(seeded['hash'], cve_scanner.packages_hash(seeded['packages']))
            self.assertEqual(inventory.clean_list(seeded['packages'], manager), seeded['packages'], 'the rows are already what the ingest keeps')
        # the policy that was judged as the Windows list landed, and the Mac's list, which breaks no rule
        self.assertEqual(api.load(api.SOFTWARE_VIOLATIONS_FILE).get(WIN, {}).get('violations'), self.raw['software_violations.json'][WIN]['violations'])
        self.assertNotIn(MAC, api.load(api.SOFTWARE_VIOLATIONS_FILE))

    def test_the_software_search_reads_both_lists(self):
        api = self.api
        self.fresh()
        out = ok(self, api, api.handle_inventory_search, query='q=google+chrome')
        got = {(r['device_id'], r['package']): r['version'] for r in out['results']}
        self.assertEqual(got[(WIN, 'Google Chrome')], '130.0.6723.92')
        self.assertEqual(got[(MAC, 'Google Chrome')], '131.0.6778.86')
        out = ok(self, api, api.handle_inventory_search, query='q=anydesk')
        self.assertEqual([r['device_id'] for r in out['results']], [WIN])
        # a dotted version is read as a number: Chrome 130 is below 131, and the Mac's is not
        out = ok(self, api, api.handle_inventory_search, query='q=google+chrome&op=lt&version=131.0')
        self.assertEqual([r['device_id'] for r in out['results']], [WIN])
        out = ok(self, api, api.handle_inventory_catalog, query='q=google+chrome')
        self.assertEqual([(r['package'], r['hosts']) for r in out['packages']], [('Google Chrome', 2)])

    def test_the_policy_page_has_the_rules_and_a_violation_of_the_windows_host(self):
        api = self.api
        self.fresh()
        rules = {r['id']: r for r in ok(self, api, api.handle_software_policy)['rules']}
        self.assertEqual((rules['banned:AnyDesk']['type'], rules['banned:AnyDesk']['package']), ('banned', 'AnyDesk'))
        self.assertEqual((rules['min_version:Google Chrome']['type'], rules['min_version:Google Chrome']['version']), ('min_version', '131.0'))
        self.assertGreaterEqual(len(rules), 6)
        out = ok(self, api, api.handle_software_policy_violations)
        win = [v for v in out['violations'] if v['device_id'] == WIN]
        self.assertEqual(sorted((v['type'], v['package'], v['found']) for v in win), [('banned', 'AnyDesk', '9.0.1'), ('min_version', 'Google Chrome', '130.0.6723.92')])
        self.assertTrue(all(v['device'] == 'design-win11' and v['manager'] == 'windows' for v in win), win)
        self.assertEqual([v for v in out['violations'] if v['device_id'] == MAC], [], 'the Mac is current and has no remote support tool')
        self.assertTrue([v for v in out['violations'] if v['device_id'] not in (WIN, MAC)], 'control: the Linux rows are still there')
        self.assertTrue(any('manager' not in v for v in out['violations'] if v['device_id'] != WIN), 'control: the Fix button stays for a Linux row')

    def test_the_seeded_violations_are_what_the_real_evaluation_files_for_the_list(self):
        api = scratch(['devices.json', 'config.json', 'software_policy.json'])
        for host, manager in ((WIN, 'windows'), (MAC, 'macos')):
            dev = self.raw['devices.json'][host]
            found = api._eval_software_policy(host, dev['name'], self.entry(host)['packages'], dev.get('tags') or [], host_manager=manager)
            self.assertEqual(found, self.raw['software_violations.json'].get(host, {}).get('violations', []), host)
        api._LOAD_CACHE.clear()
        row = api.load(api.SOFTWARE_VIOLATIONS_FILE)[WIN]
        self.assertEqual({k: v for k, v in row.items() if k != 'checked_at'}, {k: v for k, v in self.raw['software_violations.json'][WIN].items() if k != 'checked_at'})
        told = [t for t in api.told if t[0] == 'software_policy_violation' and t[1]['device_id'] == WIN]
        self.assertEqual(len(told), 2, 'the alert is raised once for each rule the Windows host breaks')

    def test_the_cve_page_says_the_two_hosts_are_not_checked(self):
        api = self.api
        self.fresh()
        report = ok(self, api, api.handle_cve_findings)
        rows = {d['device_id']: d for d in report['devices']}
        for host in (WIN, MAC):
            self.assertEqual((rows[host]['status'], rows[host]['ecosystem'], rows[host]['scanned_at']), ('no_matcher', 'unsupported', 0), host)
            self.assertEqual((rows[host]['counts']['critical'], rows[host]['counts']['high'], rows[host]['rollup']), (0, 0, 0), host)
            self.assertNotIn(host, self.raw['cve_findings.json'])
            view = ok(self, api, api.handle_cve_device, host)
            self.assertEqual((view['coverage'], view['findings'], view['rollup']), ('no_matcher', [], None), host)
            self.assertEqual(view['packages_count'], self.entry(host)['count'], host)
        self.assertEqual(rows['nc01']['status'], 'scanned', 'control: a Linux host is scanned')
        self.assertTrue([d for d in report['devices'] if d['device_id'] not in (WIN, MAC) and d['counts']['critical'] + d['counts']['high'] > 0], 'control: and the others have findings')

    def test_the_other_hosts_findings_are_the_ones_they_were(self):
        self.assertEqual(sorted(self.raw['cve_findings.json']), ['bk01', 'fw01', 'gt01', 'ha01', 'jf01', 'nc01', 'pi1', 'pmx01', 'pr01', 'tnas'])

    def test_the_two_hosts_have_no_ubuntu_left_in_the_seed(self):
        self.assertGreaterEqual(len(UBUNTU), 15, 'control: the Ubuntu list of the demo was read')
        for host in (WIN, MAC):
            e = self.entry(host)
            self.assertFalse({'sources', 'ubuntu_codename', 'debian_codename', 'version_codename'} & set(e), host)
            for p in e['packages']:
                self.assertFalse({'source', 'source_version', 'epoch'} & set(p), (host, p))
                self.assertNotIn('ubuntu', p['version'].lower(), (host, p))
                self.assertIsNone(re.search(r'-\d+ubuntu|~\d\d\.\d\d', p['version']), (host, p))
                self.assertNotEqual(UBUNTU.get(p['name']), p['version'], (host, p, 'a package of the Ubuntu list'))
                self.assertFalse(p['name'].startswith('libdemo'), (host, p))
            self.assertNotIn(host, self.raw['cve_findings.json'])
        # the policy: nothing of the rules written for the packages of a distribution is filed against them
        rules = {r['id'] for r in self.raw['software_policy.json']['rules']}
        for host, row in self.raw['software_violations.json'].items():
            if host in (WIN, MAC):
                self.assertTrue({v['rule_id'] for v in row['violations']} <= rules, host)
                self.assertEqual(row['manager'], 'windows' if host == WIN else 'macos')
        # the SBOM is made from the list: no Debian, Alpine or RPM address, and nothing says Ubuntu
        self.fresh()
        devices = self.api.load(self.api.DEVICES_FILE)
        for host in (WIN, MAC):
            doc = self.api._build_sbom_doc(host, devices[host], 'cyclonedx')
            purls = [c['purl'] for c in doc['components'] if c.get('purl')]
            self.assertEqual(len(purls), self.entry(host)['count'], host)
            self.assertFalse([u for u in purls if re.match(r'pkg:(deb|apk|rpm|alpm)/', u)], host)
            self.assertNotIn('ubuntu', json.dumps(doc).lower(), host)

    def test_the_pending_updates_of_the_two_hosts_are_what_their_agents_list(self):
        for host, manager in ((WIN, 'windows-update'), (MAC, 'brew')):
            pk = self.raw['devices.json'][host]['sysinfo']['packages']
            self.assertEqual(pk['manager'], manager)
            self.assertEqual(pk['upgradable'], len(pk['upgradable_names']), host)
            self.assertLessEqual(pk['security_updates'], pk['upgradable'])
        # the titles Windows Update offers (none is the name of a package of the Ubuntu list), and the outdated formulae of the list above for the Mac (a formula can share a
        # name with a Debian package, git for one, so the Mac's names are held to its own list)
        win_names = self.raw['devices.json'][WIN]['sysinfo']['packages']['upgradable_names']
        self.assertEqual(set(win_names) & set(UBUNTU), set(), 'pending updates named after Ubuntu packages')
        self.assertTrue(all(re.search(r'KB\d{6,7}', t) for t in win_names))
        # the agent counts a Defender definition update apart (`definition_updates`) and leaves it out of the list and of the count: the server's own rule, and a control that sees one
        self.assertTrue(windows_host.is_definition_update('Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1229.0)'))
        self.assertEqual([t for t in win_names if windows_host.is_definition_update(t)], [], 'a definition update among the pending updates')
        settled = copy.deepcopy(self.raw['devices.json'][WIN]['sysinfo']['packages'])
        windows_host.settle_update_packages(settled, settled)
        self.assertEqual((settled['upgradable'], settled['upgradable_names']), (len(win_names), win_names), 'the server would take a name out of the list it stores')
        brew = {p['name'] for p in self.entry(MAC)['packages'] if p['manager'] == 'brew'}
        self.assertLessEqual(set(self.raw['devices.json'][MAC]['sysinfo']['packages']['upgradable_names']), brew, 'an outdated formula the Mac has installed')
        # the third-party source each agent sends: winget for Windows, none for the Mac
        self.assertEqual(sorted(self.raw['devices.json'][WIN]['sysinfo']['packages'].get('third_party') or {}), ['winget'])
        self.assertNotIn('third_party', self.raw['devices.json'][MAC]['sysinfo']['packages'])
        api = self.api
        self.fresh()
        catalog = ok(self, api, api.handle_patch_catalog)
        self.assertEqual(catalog['devices_without_detail'], [])
        for host, name in ((WIN, 'design-win11'), (MAC, 'mette-macbook')):
            listed = {row['package'] for row in catalog['packages'] if name in row['devices']}
            self.assertEqual(listed, set(self.raw['devices.json'][host]['sysinfo']['packages']['upgradable_names']), '%s is in the Patch catalog under its own pending updates only' % name)


# ── 4. Software metering with licence costs ────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestSoftwareMetering(_Seeded):

    def report(self, token='k'):
        self.fresh()
        return ok(self, self.api, self.api.handle_inventory_metering, token=token)

    def test_three_rules_from_what_the_hosts_have_and_the_money_right_to_the_cent(self):
        out = self.report()
        rows = {r['name']: r for r in out['meters']}
        self.assertEqual(sorted(rows), ['Adobe Photoshop', 'Microsoft 365', 'Slack'])
        short, spare, free = rows['Adobe Photoshop'], rows['Microsoft 365'], rows['Slack']
        # one short of licences, with a cost: two installs against one licence
        self.assertEqual((short['installed'], short['owned'], short['shortfall'], short['over'], short['unit_cost'], short['shortfall_cost'], short['surplus_cost']),
                         (2, 1, 1, True, '19.99', '19.99', '0.00'))
        # one with licences to spare and a cost: two installs against five licences, three at 123.45
        self.assertEqual((spare['installed'], spare['owned'], spare['surplus'], spare['over'], spare['unit_cost'], spare['surplus_cost'], spare['shortfall_cost']),
                         (2, 5, 3, False, '123.45', '370.35', '0.00'))
        # one with licences to spare and no cost: a dash, never "0.00"
        self.assertEqual((free['installed'], free['owned'], free['surplus'], free['unit_cost'], free['surplus_cost'], free['shortfall_cost']), (2, 10, 8, None, None, None))
        self.assertEqual(out['currency'], 'EUR')
        self.assertEqual(out['totals'], {'shortfall': 1, 'surplus': 11, 'shortfall_cost': '19.99', 'surplus_cost': '370.35', 'rules_without_cost': 1})

    def test_each_rule_counts_hosts_the_seeded_lists_have(self):
        rows = {r['name']: r for r in self.report()['meters']}
        for name in ('Adobe Photoshop', 'Microsoft 365', 'Slack'):
            self.assertEqual(rows[name]['devices'], ['design-win11', 'mette-macbook'], name)
        self.assertEqual(rows['Microsoft 365']['aliases'], ['Microsoft Word', 'Microsoft Excel'], 'the Mac is counted through the aliases')
        rule = next(r for r in self.raw['config.json']['software_meters'] if r['name'] == 'Microsoft 365')
        needles = [rule['name'].lower()] + [a.lower() for a in rule['aliases']]
        own = {h for h, e in self.raw['packages.json'].items() if any(n in p['name'].lower() for p in e['packages'] for n in needles)}
        self.assertEqual(own, {WIN, MAC}, 'no other host has a package the rule would count')

    def test_the_stored_rules_are_what_the_settings_save_writes(self):
        api = scratch(['config.json'])
        stored = self.raw['config.json']['software_meters']
        st, out = call(api, api.handle_config_save, method='POST', body={'software_meters': copy.deepcopy(stored)})
        self.assertEqual(st, 200, out)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONFIG_FILE)['software_meters'], stored, 'the save would store the rules as they are seeded')
        self.assertEqual([r.get('unit_cost') for r in stored], ['19.99', '123.45', None])

    def test_a_viewer_reads_the_counts_and_no_money(self):
        out = self.report('v')
        self.assertIsNone(out['currency'])
        self.assertTrue(all(r['unit_cost'] is None and r['shortfall_cost'] is None and r['surplus_cost'] is None for r in out['meters']))
        self.assertEqual((out['totals']['shortfall'], out['totals']['surplus']), (1, 11))
        self.assertEqual(self.report('f')['currency'], 'EUR', 'control: finance reads the same money')


# ── 5. A failing notification destination ───────────────────────────────────────────────────────────────────────────────────────────────────────────

class _Network:
    """The opener the product asks for, with the one failure of the demo's Apprise address: its name does not resolve."""

    class _Ok:
        status = 200

        def read(self, *_a):
            return b'{}'

    def opener(self, *_a, **_k):
        return self

    def open(self, req, timeout=10):
        if req.full_url.split('/')[2] == 'apprise.lab':
            raise urllib.error.URLError('[Errno -2] Name or service not known')
        return self._Ok()


class TestTheFailingDestination(_Seeded):

    def config(self, token='k'):
        self.fresh()
        return ok(self, self.api, self.api.handle_config_get, token=token)

    def test_the_settings_list_marks_one_destination_failing_four_times_in_a_row_by_a_name_that_does_not_resolve(self):
        dests = {d['id']: d for d in self.config()['webhook_urls']}
        self.assertEqual(sorted(dests), ['wh_apprise_demo', 'wh_discord_demo', 'wh_pushover_demo'])
        self.assertEqual((dests['wh_apprise_demo']['fail_streak'], dests['wh_apprise_demo']['fail_class']), (4, 'dns'))
        for other in ('wh_discord_demo', 'wh_pushover_demo'):
            self.assertNotIn('fail_streak', dests[other], other)
            self.assertNotIn('fail_class', dests[other], other)

    def test_a_viewer_reads_the_list_with_no_streak(self):
        for d in self.config('v').get('webhook_urls') or []:
            self.assertNotIn('fail_streak', d)
            self.assertNotIn('fail_class', d)

    def test_the_store_holds_the_streak_and_no_address(self):
        (key, row), = self.raw['notify_health.json'].items()
        self.assertEqual(key, 'wh:wh_apprise_demo')
        self.assertEqual(sorted(row), ['alerted', 'error', 'fails', 'label', 'last', 'since'])
        text = json.dumps(self.raw['notify_health.json'])
        for leak in ('apprise.lab', 'discord.com', 'demo-not-a-real', '://', 'notify/', 'http'):
            self.assertNotIn(leak, text, leak)
        self.assertEqual(self.api._URL_IN_TEXT_RE.sub('[address]', row['error']), row['error'], 'what the server would have kept of the text: nothing in it was an address')
        self.assertEqual(self.api._notify_error_class(row['error']), 'dns')
        self.assertEqual(row['label'], 'Apprise — family chat')

    def test_the_streak_is_recent_and_the_alert_flag_is_set(self):
        (_, row), = self.raw['notify_health.json'].items()
        now = state()['seeded_at']
        self.assertTrue(now - 6 * HOUR < row['since'] < row['last'] < now, row)
        self.assertLess(now - row['last'], 30 * 60, 'the last failure was minutes ago')
        self.assertIs(row['alerted'], True)
        self.assertGreaterEqual(row['fails'], self.api.NOTIFY_FAIL_STREAK + 1)

    def test_the_row_is_the_one_the_real_fan_out_writes_when_only_the_network_is_replaced(self):
        api = scratch(fire=True)
        net = _Network()
        api._ssrf_safe_opener = net.opener
        api._url_targets_local_or_meta = lambda parsed, allow_loopback=True: False        # no name lookup in a test
        dests = copy.deepcopy(self.raw['config.json']['webhook_urls'])
        api.save(api.CONFIG_FILE, {'webhook_urls': dests, 'webhook_block_local': False})
        for _ in range(3):             # three events: the alert the third raises goes to the same destination, which fails it too, so the streak is four
            api.save(api.WEBHOOK_RATELIMIT_FILE, {})
            api._LOAD_CACHE.clear()
            api.fire_webhook('server_disk_low', {'name': 'server', 'percent': 97})
        api._LOAD_CACHE.clear()
        (key, produced), = api.load(api.NOTIFY_HEALTH_FILE).items()
        (seeded_key, seeded), = self.raw['notify_health.json'].items()
        dest = next(d for d in dests if d['id'] == 'wh_apprise_demo')
        self.assertEqual((seeded_key, key), (api._notify_dest_key(dest),) * 2)
        self.assertEqual(seeded['label'], api._notify_dest_label(dest))
        self.assertEqual(sorted(seeded), sorted(produced))
        for field in ('fails', 'error', 'label', 'alerted'):
            self.assertEqual(seeded[field], produced[field], field)
        self.assertTrue(isinstance(produced['since'], int) and produced['since'] <= produced['last'])
        self.assertEqual([e for e, _ in api.told].count('notify_dest_failing'), 1, 'control: the third failure raised the alert, once')


# ── the shapes, and what the pages draw ───────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestTheShapeRegistry(_Seeded):

    def test_the_registry_leaves_every_touched_store_exactly_as_it_was(self):
        for name in TOUCHED:
            doc = self.raw[name]
            self.assertEqual(store_shapes.normalize(name, copy.deepcopy(doc)), doc, name)

    def test_the_check_can_fail_a_wrong_kind_in_a_registered_store_is_repaired(self):
        damaged = {
            'patch_done.json': {'tnas': {'done': ['not a pair']}},
            'notify_health.json': {'wh:x': {'fails': 'four', 'since': None, 'last': 1, 'error': 5, 'label': 'x'}},
            'packages.json': {WIN: {'packages': ['one', 'two'], 'count': 'many'}},
            'software_violations.json': {WIN: {'violations': 'none'}},
            'cve_findings.json': {WIN: {'cut': 'x'}},
            'patch_age.json': {'tnas': {'all_first': 'soon'}},
        }
        for name, doc in damaged.items():
            with contextlib.redirect_stderr(io.StringIO()):          # the registry says on stderr that it left something out
                repaired = store_shapes.normalize(name, copy.deepcopy(doc))
            self.assertNotEqual(repaired, doc, name)

    def test_the_stores_the_registry_has_no_entry_for(self):
        self.assertEqual(sorted(n for n in TOUCHED if n not in store_shapes.SHAPES), sorted(UNREGISTERED),
                         'an entry was added, or one of the touched stores changed: the list of stores the registry does not hold needs the same change')


_DOM = r'''
class El {
  constructor(tag) { this.tag = tag; this.kids = []; this.className = ''; this._t = ''; this.attrs = {}; }
  set textContent(v) { this._t = String(v); this.kids = []; }
  get textContent() { return this._t + this.kids.map(k => k.textContent).join(''); }
  set innerHTML(v) { throw new Error('innerHTML was assigned'); }
  appendChild(c) { this.kids.push(c); return c; }
  append(...cs) { for (const c of cs) this.kids.push(typeof c === 'string' ? { textContent: c } : c); }
  replaceChildren(...cs) { this.kids = cs; this._t = ''; }
  setAttribute(k, v) { this.attrs[k] = v; }
}
'''


@unittest.skipUnless(NODE, 'node not installed')
class TestWhatThePagesDraw(_Seeded):
    """The real client functions, extracted from the page's scripts and run under node over what the real handlers answered for the seed."""

    def test_the_install_dialog_lists_branch_rollout_used_7_of_25(self):
        self.fresh()
        rows = ok(self, self.api, self.api.handle_enroll_token_list)
        script = (_DOM + 'const els = { "enroll-open-list": new El("div") };\n'
                  'const document = { createElement: t => new El(t), getElementById: id => els[id] || null };\n'
                  'const api = async () => %s;\nconst _fmtDuration = s => Math.round(s / 3600) + " hours";\n' % json.dumps(rows)
                  + (JS / 'app-enrol.js').read_text(encoding='utf-8')
                  + '\nenrolOpenList().then(() => console.log(JSON.stringify(els["enroll-open-list"].kids.map('
                    'r => r.kids.map(k => k.textContent.replace(/\\s+/g, " ").trim())))));\n')
        got = node_json(script)
        self.assertEqual(len(got), 1)
        main, used, left, revoke = got[0]
        self.assertIn('Branch rollout', main)
        self.assertEqual(used, 'used 7 of 25')
        self.assertTrue(left.startswith('Expires in 24 hours'), left)
        self.assertEqual(revoke, 'Revoke')

    def test_the_patches_card_shows_a_figure_for_thirty_days_and_another_for_ninety(self):
        self.fresh()
        mttp = {d: ok(self, self.api, self.api.handle_patch_report, query='' if d == 30 else 'mttp_days=%d' % d)['mttp'] for d in (30, 90)}
        js = (JS / 'app.js').read_text(encoding='utf-8')
        body = '\n'.join(srcpin.js_function(js, n) for n in ('_patchMttpQuery', '_mttpAmount', '_renderPatchMttp'))
        script = (_DOM + 'const els = {}; let windowValue = null;\n'
                  'const document = { createElement: t => new El(t), createTextNode: t => ({ textContent: String(t) }),\n'
                  '  getElementById: id => id === "patch-mttp-days" ? { value: windowValue } : (els[id] || null) };\n'
                  + body + '\nconst out = {};\n'
                  'for (const [days, m] of Object.entries(%s)) {\n'
                  '  for (const id of ["patch-mttp-num", "patch-mttp-unit", "patch-mttp-detail"]) els[id] = new El("span");\n'
                  '  _renderPatchMttp(m);\n'
                  '  out[days] = { num: els["patch-mttp-num"].textContent, unit: els["patch-mttp-unit"].textContent,\n'
                  '                lines: els["patch-mttp-detail"].kids.map(l => l.kids.map(k => k.textContent).join("")) };\n'
                  '}\nconsole.log(JSON.stringify(out));\n' % json.dumps(mttp))
        card = node_json(script)
        for days in ('30', '90'):
            self.assertRegex(card[days]['num'], r'^\d+(\.\d)?$', days)
            self.assertIn(card[days]['unit'], ('hours', 'days'))
            self.assertEqual(card[days]['lines'][0], 'Last %s days' % days)
            self.assertRegex(card[days]['lines'][1], r'^Median [\d.]+ (hours|days) · 90th percentile [\d.]+ (hours|days) · Samples \(n\) \d+$')
            self.assertRegex(card[days]['lines'][2], r'^Security updates [\d.]+ (hours|days) Samples \(n\) \d+$', 'the security line has a figure too, not "Not enough data"')
        self.assertNotEqual((card['30']['num'], card['30']['unit']), (card['90']['num'], card['90']['unit']))

    def test_the_settings_page_draws_the_red_mark_for_the_failing_destination_and_for_no_other(self):
        self.fresh()
        dests = ok(self, self.api, self.api.handle_config_get)['webhook_urls']
        app = (JS / 'app.js').read_text(encoding='utf-8')
        body = '\n'.join((srcpin.balanced_block(app, 'const _DEST_FAIL_CLASSES = ', '{', '}') + ';', srcpin.js_function(app, '_destFailingHtml')))
        script = 'function escHtml(s) { return String(s); }\n' + body + '\nconsole.log(JSON.stringify(%s.map(_destFailingHtml)));\n' % json.dumps(dests)
        out = node_json(script)
        ids = [d['id'] for d in dests]
        text = dict(zip(ids, (re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', h)).strip() for h in out)))
        self.assertEqual(text['wh_apprise_demo'], 'Failing Failed in a row 4 Last error Name lookup failed')
        self.assertEqual([i for i, t in text.items() if t], ['wh_apprise_demo'])
        self.assertIn('class="mon-status down"', out[ids.index('wh_apprise_demo')])


if __name__ == '__main__':
    unittest.main()
