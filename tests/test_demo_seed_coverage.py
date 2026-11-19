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

The second half of 8.0.2 (the Windows, Linux agent and vulnerability territories) is held the same way, in sections 6 to 13 below. Each row is read back through the real handlers and
page functions and held to what the real producer writes: the real agent function over a stand-in host for what an agent sends, the real heartbeat, log handler, apply handler and
ingest for what the server keeps, and the real scan over the seeded package lists for the account of what a scan checked.

  * the Windows host has its build, shares, TPM, Windows Update search and one Defender definition update counted apart;
  * it has two registry checks (one ok, one critical), a fleet-wide rule on failed logons with the twelve lines that fired it and one log alert, and a startup inventory with one
    alert and one feed entry for what changed in it;
  * three Linux hosts have a package-list refresh state (ok, failed, a container that cannot) and the Linux hosts of the 8.0.2 agent say what they can see;
  * every scan states which packages it checked, one host has packages that were not answered in full, the hypervisor runs a kernel and holds a newer one that fixes two findings
    (reboot to apply) and the NAS cannot say which kernel it runs;
  * the hosts that carry any of this run the agent that sends it, and no host carries what its platform or its agent cannot send.
"""
import contextlib
import copy
import hashlib
import importlib.machinery
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
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-demoseedcov-'))
ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
JS = ROOT / 'server' / 'html' / 'static' / 'js'
SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'
sys.path.insert(0, str(CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_capabilities  # noqa: E402
import checks  # noqa: E402
import cve_fixes  # noqa: E402
import cve_scanner  # noqa: E402
import persistence  # noqa: E402
import pkg_refresh  # noqa: E402
import software_inventory as inventory  # noqa: E402
import srcpin  # noqa: E402
import store_shapes  # noqa: E402
import win_event_samples as WE  # noqa: E402
import win_host_support as S  # noqa: E402
import windows_host  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

NODE = shutil.which('node')
HOUR, DAY = 3600, 86400
WIN, MAC = 'wks01', 'mbp01'
TOKENS = {'k': ('alice', 'admin'), 'v': ('demo', 'viewer'), 'f': ('finn', 'finance')}      # the demo's own administrator and viewer, and a finance user
NEW_STORES = ('enrollment_tokens.json', 'patch_done.json', 'notify_health.json')
SECOND_STORES = ('persistence.json',)            # the store the second half adds
# the stores this work adds or changes (devices.json for the pending updates of the two hosts; the second half also writes the log buffer and the rules of the Logs page, the
# inbox and the activity feed)
TOUCHED = NEW_STORES + SECOND_STORES + ('packages.json', 'cve_findings.json', 'software_policy.json', 'software_violations.json', 'patch_age.json', 'config.json', 'devices.json',
                                        'log_watch.json', 'log_rules_global.json', 'alerts.json', 'fleet_events.json')
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
    """A handler run as a request: (status, body). `token` None sends no credentials. A conditional GET answers by raising the 200 it would send (`_respond_with_etag`), which is
    read as the answer too."""
    env = {'QUERY_STRING': query}
    if token:
        env['HTTP_AUTHORIZATION'] = 'Bearer ' + token
    try:
        return _run(api, lambda: fn(*args), body, method=method, env=env)
    except api.HTTPError as e:
        return e.status, e.body


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
        self.assertEqual(self.api._notify_error_class(self.api._failure_reason(row['error'])), 'dns', 'what the server keeps of a failure is its kind: this text reads as a failed name lookup')
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


# ── 6. What the 8.0.2 agents report beyond the first half ─────────────────────────────────────────────────────────────────────────────────────────────

SECOND_HALF = (8, 0, 2)        # the first release whose agents send the build, shares, TPM and search state, the persistence inventory, the capabilities and the refresh state
_AGENTS = {}


def version_tuple(version):
    return tuple(int(part) for part in str(version).split('.')[:3])


def win_agent():
    """The Windows agent of this tree, loaded once."""
    if 'win' not in _AGENTS:
        _AGENTS['win'] = S.load_agent('rp_demoseedcov_win_agent')
    return _AGENTS['win']


def linux_agent():
    """The Linux agent of this tree, loaded once."""
    if 'linux' not in _AGENTS:
        loader = importlib.machinery.SourceFileLoader('rp_demoseedcov_linux_agent', str(ROOT / 'client' / 'remotepower-agent.py'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        _AGENTS['linux'] = mod
    return _AGENTS['linux']


def persistence_helpers():
    """The stand-ins of tests/test_win_persistence.py (a registry, a schtasks answer, startup folders in the form Windows has them), loaded when first needed."""
    if 'persistence' not in _AGENTS:
        import test_win_persistence
        _AGENTS['persistence'] = test_win_persistence
    return _AGENTS['persistence']


def linux_agent_hosts(devices):
    """The hosts that run a Linux agent: not agentless, and not Windows or macOS."""
    return {h: d for h, d in devices.items() if not d.get('agentless') and not re.search(r'windows|macos|mac os', str(d.get('os')), re.I)}


class _SecondHalf(_Seeded):
    """The seeded stores the second half writes, with the readers every class below needs."""

    @property
    def devices(self):
        return self.raw['devices.json']

    @property
    def win(self):
        return self.devices[WIN]['sysinfo']


class TestTheWindowsHostReportsWhatItsAgentSends(_SecondHalf):
    # The registry of a Windows 11 24H2 host as it stood after the October 2024 cumulative update. ProductName still says Windows 10, which is why the family comes from the build.
    WIN11 = dict(CurrentBuildNumber=('26100', S.SZ), CurrentBuild=('26100', S.SZ), UBR=(2033, S.DWORD), DisplayVersion=('24H2', S.SZ), ProductName=('Windows 10 Pro', S.SZ),
                 EditionID=('Professional', S.SZ), InstallationType=('Client', S.SZ))
    # what Get-SmbShare answers on the host: the three shares the system makes and the two an operator made
    SHARES = json.dumps([
        {'name': 'ADMIN$', 'path': 'C:\\Windows', 'description': 'Remote Admin', 'encrypted': False},
        {'name': 'C$', 'path': 'C:\\', 'description': 'Default share', 'encrypted': False},
        {'name': 'IPC$', 'path': '', 'description': 'Remote IPC', 'encrypted': False},
        {'name': 'Public', 'path': 'C:\\Users\\Public', 'description': '', 'encrypted': False},
        {'name': 'Scans', 'path': 'C:\\Scans', 'description': 'Scanner inbox', 'encrypted': True},
    ])
    TPM = json.dumps({'present': True, 'ready': True, 'enabled': True, 'spec': '2.0, 0, 1.59'})
    WINDOWS_ONLY = ('win_build', 'shares', 'tpm', 'wu_search')

    def test_the_build_is_what_the_agent_reads_from_a_registry_that_holds_these_values(self):
        fake = S.FakeWinreg({S.NT_KEY: S.nt_values(**self.WIN11)})
        with mock.patch.dict(sys.modules, {'winreg': fake}):
            read = windows_host.clean_win_build(win_agent().get_win_build())
        self.assertEqual(self.win['win_build'], read)
        self.assertFalse(fake.wrote, 'the agent asked for a right that writes')
        self.assertEqual((read['build'], read['ubr'], read['display_version'], read['edition']), ('26100', 2033, '24H2', 'Professional'))

    def test_the_hosts_list_and_the_data_explorer_say_windows_11_pro_from_the_build_and_not_from_the_product_name(self):
        self.fresh()
        rows = ok(self, self.api, self.api.handle_devices_list)
        rows = rows['devices'] if isinstance(rows, dict) else rows
        row = next(r for r in rows if r.get('id') == WIN)
        self.assertEqual(row['os_detail'], 'Windows 11 Pro 24H2 (build 26100.2033)')
        self.assertTrue(row['os_detail'].startswith(row['os']), 'the label of the build continues the host\'s own OS text')
        mine = {r['device_id']: r for r in self.api._qe_devices_rows()}
        got = {k: mine[WIN][k] for k in ('win_build', 'win_ubr', 'win_display_version', 'win_edition', 'win_product', 'win_family', 'shares_count', 'tpm_present', 'tpm_ready')}
        self.assertEqual(got, {'win_build': '26100', 'win_ubr': 2033, 'win_display_version': '24H2', 'win_edition': 'Professional', 'win_product': 'Windows 10 Pro',
                               'win_family': 'Windows 11', 'shares_count': 2, 'tpm_present': True, 'tpm_ready': True})
        self.assertNotEqual(got['win_product'], got['win_family'], 'the product name says Windows 10 and the family is read from the build number')
        for host in set(self.devices) - {WIN}:
            self.assertIsNone(mine[host]['win_build'], host)
            self.assertIsNone(mine[host]['shares_count'], host)

    def test_the_revision_is_below_the_cumulative_update_the_host_still_has_to_install(self):
        # 24H2 builds from Microsoft's release notes: KB5044284 is 26100.2033 (October 2024), KB5046617 is 26100.2314 (November 2024), KB5048667 is 26100.2605 (December 2024)
        built = {'KB5044284': 2033, 'KB5046617': 2314, 'KB5048667': 2605}
        pending = [n for n in self.win['packages']['upgradable_names'] if 'Cumulative Update' in n]
        self.assertEqual(len(pending), 1, pending)
        kb = re.search(r'KB\d+', pending[0]).group(0)
        self.assertIn(kb, built, 'the pending cumulative update is one this file knows the build of')
        self.assertLess(self.win['win_build']['ubr'], built[kb], 'a host at or past the build of an update does not list it as pending')
        self.assertEqual(self.win['win_build']['build'], '26100')
        self.assertIn('10.0.' + self.win['win_build']['build'], self.win['platform'], 'the platform line of the host names the build')

    def test_the_shares_and_the_tpm_are_what_the_agent_parses_from_the_answers_of_its_probes(self):
        agent = win_agent()
        self.assertEqual(self.win['shares'], windows_host.clean_shares(agent._parse_smb_shares(self.SHARES)))
        self.assertEqual(self.win['tpm'], windows_host.clean_tpm(agent._parse_tpm(self.TPM)))
        shares = self.win['shares']
        self.assertEqual((shares['count'], shares['admin_count'], [s['name'] for s in shares['items']]), (2, 3, ['Public', 'Scans']), 'the shares of the system are counted and not listed')
        self.assertEqual([s['encrypted'] for s in shares['items']], [False, True], 'one share is encrypted')
        self.assertEqual(windows_host.shares_count(self.win), 2)
        self.assertEqual((windows_host.tpm_flag(self.win, 'present'), windows_host.tpm_flag(self.win, 'ready')), (True, True))
        self.assertEqual(self.win['tpm']['spec'], '2.0')

    def test_the_state_of_the_search_is_the_one_the_server_makes_of_what_the_agent_sends(self):
        state, reported = self.win['wu_search'], self.win['pkg_scan_ts']
        sent = {'at': state['at'], 'ok': True, 'source': 'windows-update-agent', 'error_class': ''}
        self.assertEqual(state, windows_host.clean_search_state(sent, reported))
        self.assertEqual((state['ok'], state['ok_at'], state['fail_since'], state['error_class']), (True, state['at'], 0, ''))
        self.assertTrue(0 <= reported - state['at'] <= windows_host.AT_BEFORE, 'the search ran just before the package report that carries the count')
        status, text = windows_host.search_row(state, int(time.time()))
        self.assertEqual(status, 'ok', text)
        # the control: a search that failed is a state the instrument tells from this one
        failed = windows_host.clean_search_state({'at': state['at'], 'ok': False, 'source': 'wsus', 'error_class': 'network'}, reported, self.win)
        self.assertNotEqual(failed, state)
        self.assertEqual(failed['ok_at'], state['ok_at'], 'a failed search keeps the time of the last count that was taken')

    def test_the_definition_update_is_counted_apart_and_the_pending_count_is_what_it_was(self):
        packages = self.win['packages']
        self.assertEqual((packages['definition_updates'], packages['upgradable'], len(packages['upgradable_names'])), (1, 3, 3))
        self.assertEqual([n for n in packages['upgradable_names'] if windows_host.is_definition_update(n)], [])
        # what the server makes of the report of a current agent: nothing changes
        current = copy.deepcopy(packages)
        windows_host.settle_update_packages(current, {'definition_updates': 1})
        self.assertEqual(current, packages)
        # and of an older agent, which sends the definition update with the rest: the count comes down by one and is counted apart, to the same numbers
        older = copy.deepcopy(packages)
        older['upgradable'], older['upgradable_names'] = 4, packages['upgradable_names'] + ['Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1229.0)']
        older.pop('definition_updates')
        windows_host.settle_update_packages(older, {})
        self.assertEqual((older['upgradable'], older['definition_updates'], older['upgradable_names']), (3, 1, packages['upgradable_names']))
        # the patch report of the host says both, and its count is the one the first half gave
        self.fresh()
        report = ok(self, self.api, self.api.handle_patch_report_device, WIN)
        self.assertEqual((report['upgradable'], report['definition_updates'], report['patch_status']), (3, 1, 'patches_available'))
        self.assertEqual(report['wu_search'], self.win['wu_search'])
        sysinfo = ok(self, self.api, self.api.handle_sysinfo, WIN)['sysinfo']
        self.assertEqual(sysinfo['packages']['definition_updates'], 1)
        self.assertEqual((sysinfo['win_build'], sysinfo['shares'], sysinfo['tpm']), (self.win['win_build'], self.win['shares'], self.win['tpm']))

    def test_the_checks_page_has_the_row_of_the_search_for_the_one_host_that_sent_a_state(self):
        self.fresh()
        hosts = {h['device_id']: h for h in ok(self, self.api, self.api.handle_fleet_checks)['hosts']}
        row = next(c for c in hosts[WIN]['checks'] if c['key'] == 'win_update_search')
        self.assertEqual((row['name'], row['status']), ('Windows Update search', 'ok'))
        self.assertRegex(row['output'], r'^last search \d+ (minutes?|hours?|days?) ago, ok$')
        for host, entry in hosts.items():
            if host != WIN:
                self.assertFalse([c for c in entry['checks'] if c['key'] == 'win_update_search'], host)

    def test_a_real_heartbeat_keeps_what_was_seeded_as_it_is(self):
        api = scratch(['devices.json', 'config.json'])
        dev = api.load(api.DEVICES_FILE)[WIN]
        sysinfo = copy.deepcopy(dev['sysinfo'])
        sysinfo['wu_search'] = {'at': int(time.time()) - 25, 'ok': True, 'source': 'windows-update-agent', 'error_class': ''}      # the word of the agent: the server stamps the rest
        status, out = S.beat(api, WIN, dev['token'], sysinfo)
        self.assertEqual(status, 200, out)
        stored = api.load(api.DEVICES_FILE)[WIN]['sysinfo']
        for key in ('win_build', 'shares', 'tpm'):
            self.assertEqual(stored[key], self.win[key], key)
        self.assertEqual((stored['packages']['definition_updates'], stored['packages']['upgradable']), (1, 3))
        self.assertEqual({k: stored['wu_search'][k] for k in ('ok', 'source', 'error_class', 'fail_since')}, {'ok': True, 'source': 'windows-update-agent', 'error_class': '', 'fail_since': 0})

    def test_only_the_windows_host_has_any_of_it(self):
        for host, dev in self.devices.items():
            si = dev.get('sysinfo') or {}
            for key in self.WINDOWS_ONLY:
                self.assertEqual(key in si, host == WIN, (host, key))
            self.assertEqual('definition_updates' in (si.get('packages') or {}), host == WIN, host)
        self.assertEqual(sorted(self.raw['persistence.json']), [WIN])
        self.assertEqual(sorted(h for h, row in self.raw['log_watch.json'].items() if any(u.startswith('eventlog.') for u in row.get('units', {}))), [WIN])

    def test_nothing_that_was_added_to_the_windows_host_says_ubuntu(self):
        # the build string is the one the Windows agent sends for the kernel, and it is the build of the OS line
        self.assertEqual(self.win['kernel'], '10.0.26100')
        added = {k: self.win[k] for k in ('win_build', 'shares', 'tpm', 'wu_search', 'kernel')}
        added['definition_updates'] = self.win['packages']['definition_updates']
        added['checks'] = {k: v for k, v in self.win['custom_check_results'].items() if k != 'ck_00001'}
        added['persistence'] = self.raw['persistence.json'][WIN]
        added['lines'] = self.raw['log_watch.json'][WIN]
        added['alerts'] = [a for a in self.raw['alerts.json']['alerts'] if a['event'] in ('persistence_added', 'log_alert')]
        added['feed'] = [e for e in self.raw['fleet_events.json']['events'] if e['event'] == 'persistence_added']
        added['config'] = [c for c in self.raw['config.json']['custom_checks'] if c['type'] == 'registry']
        text = json.dumps(added)
        self.assertGreater(len(text), 3000, 'control: there is something to read')
        self.assertIsNone(re.search(r'ubuntu|debian|linux|systemd|dpkg|\.deb\b|/etc/|/var/|/usr/|\bapt\b', text, re.I), re.search(r'.{20}(ubuntu|debian|linux|systemd|dpkg|/etc/|/var/|/usr/|\bapt\b).{20}', text, re.I))

    def test_the_windows_host_runs_an_agent_that_sends_all_of_it(self):
        self.assertGreaterEqual(version_tuple(self.devices[WIN]['version']), SECOND_HALF)
        self.assertEqual(self.devices[WIN]['version'], seed.CURRENT_VERSION)


# ── 7. Registry checks ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestTheRegistryChecks(_SecondHalf):
    # the host: NTLM at level 5 as the first check wants, and ten cached logons where the second allows four (a number the registry keeps as text)
    TREE = {r'SYSTEM\CurrentControlSet\Control\Lsa': {'LmCompatibilityLevel': (5, S.DWORD)},
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon': {'CachedLogonsCount': ('10', S.SZ)}}

    def rows(self, config=None):
        return [c for c in (config or self.raw['config.json'])['custom_checks'] if c.get('type') == 'registry']

    def test_there_are_two_checks_for_the_windows_hosts_one_ok_and_one_critical(self):
        rows = self.rows()
        self.assertEqual(sorted(r['name'] for r in rows), ['Cached logons at most 4', 'NTLM level 5'])
        self.assertEqual({(r['target_kind'], r['target'], r['kind']) for r in rows}, {('tag', 'windows', 'protect')})
        self.assertEqual(sorted(r['id'] for r in rows), sorted(self.win['custom_check_results'].keys() - {'ck_00001'}))
        self.assertEqual(sorted(v['status'] for k, v in self.win['custom_check_results'].items() if k != 'ck_00001'), ['critical', 'ok'])

    def test_the_two_rows_are_what_the_apply_handler_writes_from_the_catalog(self):
        api = scratch(['config.json'])
        cfg = api.load(api.CONFIG_FILE)
        cfg['custom_checks'] = [c for c in cfg['custom_checks'] if c.get('type') != 'registry']
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        wanted = [t['id'] for t in checks.CHECK_BASELINE_CATALOG if t['type'] == 'registry' and t['name'] in {r['name'] for r in self.rows()}]
        self.assertEqual(len(wanted), 2, 'control: both names are templates of the catalog')
        st, out = call(api, api.handle_check_baselines_apply, method='POST', body={'ids': wanted, 'target_kind': 'tag', 'target': 'windows'})
        self.assertEqual((st, out.get('added')), (200, 2), out)
        api._LOAD_CACHE.clear()
        written = self.rows(api.load(api.CONFIG_FILE))
        strip = lambda rows: {r['name']: {k: v for k, v in r.items() if k != 'id'} for r in rows}
        self.assertEqual(strip(written), strip(self.rows()), 'the seeded rows are the rows the apply handler writes')
        # the handler walks a set of the ids it was given, so which of the two template gets the first number is not fixed: the numbers are the next two of the sequence, in either order
        self.assertEqual(sorted(r['id'] for r in written), ['ck_00005', 'ck_00006'])
        self.assertEqual(sorted(r['id'] for r in self.rows()), ['ck_00005', 'ck_00006'])

    def test_the_results_are_what_the_agent_writes_for_a_registry_that_holds_these_values(self):
        fake = S.FakeWinreg(self.TREE)
        for row in self.rows():
            status, output = win_agent()._eval_registry_check(row, wr=fake)
            self.assertEqual((status, output), (self.win['custom_check_results'][row['id']]['status'], self.win['custom_check_results'][row['id']]['output']), row['name'])
        self.assertFalse(fake.wrote, 'a registry check is read only')
        self.assertEqual(fake.leaked, [], 'every key it opened was closed')

    def test_the_checks_page_shows_both_for_the_windows_host_and_for_no_other(self):
        self.fresh()
        hosts = {h['device_id']: h for h in ok(self, self.api, self.api.handle_fleet_checks)['hosts']}
        mine = {c['name']: c for c in hosts[WIN]['checks'] if c.get('ctype') == 'registry'}
        self.assertEqual({n: (c['status'], c['output'], c['kind']) for n, c in mine.items()},
                         {'NTLM level 5': ('ok', 'LmCompatibilityLevel = 5', 'protect'),
                          'Cached logons at most 4': ('critical', 'CachedLogonsCount = 10, expected at most 4', 'protect')})
        self.assertEqual(hosts[WIN]['summary']['worst'], 'critical')
        for host, entry in hosts.items():
            if host != WIN:
                self.assertFalse([c for c in entry['checks'] if c.get('ctype') == 'registry'], '%s is not given a registry check' % host)

    def test_a_host_that_is_not_a_windows_one_is_not_asked_for_it(self):
        for row in self.rows():
            self.assertIn(row['type'], checks.WINDOWS_ONLY_CHECK_TYPES)
            for host, dev in self.devices.items():
                self.assertEqual(checks._custom_check_applies(row, host, dev), host == WIN, (row['name'], host))
        ids = {r['id'] for r in self.rows()}
        for host, dev in self.devices.items():
            self.assertEqual(ids & set((dev.get('sysinfo') or {}).get('custom_check_results') or {}), ids if host == WIN else set(), host)

    def test_the_add_check_dialogs_list_marks_the_two_templates_as_applied_and_no_other(self):
        self.fresh()
        catalog = ok(self, self.api, self.api.handle_check_baseline_catalog)['catalog']
        registry = [t for t in catalog if t['type'] == 'registry']
        self.assertEqual(len(registry), 6, 'the six ready-made baselines')
        applied = {t['name']: t['applied_count'] for t in registry}
        self.assertEqual(sorted(n for n, c in applied.items() if c), ['Cached logons at most 4', 'NTLM level 5'])
        for t in registry:
            if t['applied_count']:
                self.assertEqual([a['label'] for a in t['applied']], ['tag: windows'])


# ── 8. A rule on the Windows event log ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────

_TEMPLATES = []


def log_rule_templates():
    """LOG_RULE_TEMPLATES, evaluated out of the script the Add rule dialog ships."""
    if not _TEMPLATES:
        js = (JS / 'app-logs.js').read_text(encoding='utf-8')
        m = re.search(r'const LOG_RULE_TEMPLATES = (\[.*?\n\]);', js, re.S)
        assert m, 'LOG_RULE_TEMPLATES is not in app-logs.js'
        out = subprocess.run([NODE, '-e', 'console.log(JSON.stringify(eval(process.argv[1])))', m.group(1)], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        _TEMPLATES.extend(json.loads(out.stdout))
    return _TEMPLATES


UNIT = 'eventlog.Security.4625'


class TestTheEventLogRule(_SecondHalf):

    def rule(self):
        return next(r for r in self.raw['log_rules_global.json']['rules'] if r['unit'] == UNIT)

    def rows(self):
        return self.raw['log_watch.json'][WIN]['units'][UNIT]

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_rule_is_what_the_dialogs_template_saves_and_what_the_server_stores_for_it(self):
        t = next(t for t in log_rule_templates() if t['id'] == 'failed-logons')
        rule = self.rule()
        self.assertEqual({k: rule[k] for k in ('unit', 'pattern', 'threshold', 'severity', 'display_template')},
                         {'unit': t['unit'], 'pattern': t['pattern'], 'threshold': t['threshold'], 'severity': t['severity'], 'display_template': t['message']})
        self.assertEqual(rule['threshold'], 10)
        api = scratch(['config.json'])
        api.save(api.LOG_RULES_GLOBAL_FILE, {'rules': []})
        api._LOAD_CACHE.clear()
        st, out = call(api, api.handle_log_rules_global_add, method='POST',
                       body={'unit': t['unit'], 'pattern': t['pattern'], 'threshold': t['threshold'], 'severity': t['severity'], 'display_template': t['message']})
        self.assertEqual(st, 200, out)
        stored = out['rule']
        self.assertEqual(sorted(stored), sorted(rule), 'the seeded rule holds the fields the server stores, and no others')
        self.assertEqual({k: v for k, v in stored.items() if k not in ('id', 'created_at', 'created_by')}, {k: v for k, v in rule.items() if k not in ('id', 'created_at', 'created_by')})
        self.assertRegex(rule['id'], r'^[0-9a-f]{16}$')
        self.assertEqual(rule['created_by'], 'alice')

    def test_each_line_is_what_the_agent_writes_for_that_failed_logon(self):
        agent = win_agent()
        self.assertEqual(len(self.rows()), 12)
        for row in self.rows():
            m = re.match(r'\[4625\] failed logon rid=(\d+) source=(\S+) type=(\d) status=(0x\w+) substatus=(0x\w+) user="([^"]*)" domain="([^"]*)" workstation="([^"]*)"$', row['line'])
            self.assertTrue(m, row['line'])
            rid, source, kind, status, sub, user, domain, workstation = m.groups()
            xml = WE.failed_logon(rid=int(rid), user=user, domain=domain, workstation=workstation, ip=source, logon_type=kind, status=status, substatus=sub)
            self.assertEqual(agent._winevt_line(agent._winevt_parse(xml)[0]), row['line'])
        self.assertEqual([r['ts'] for r in self.rows()], sorted(r['ts'] for r in self.rows()), 'oldest first, as an agent reads them')
        self.assertEqual(len({r['line'] for r in self.rows()}), 12, 'a record id makes each line its own')

    def test_the_real_log_handler_given_these_lines_stores_them_and_raises_the_one_seeded_alert(self):
        api = scratch(['devices.json', 'log_rules_global.json'], fire=True)
        dev = api.load(api.DEVICES_FILE)[WIN]
        units = {UNIT: [{'message': r['line'], 'ts': r['ts'] * 1000} for r in self.rows()]}
        st, out = call(api, api.handle_log_submit, token=None, method='POST', body={'device_id': WIN, 'token': dev['token'], 'units': units})
        self.assertEqual((st, out.get('alerts_fired')), (200, 1), out)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.LOG_WATCH_FILE)[WIN]['units'][UNIT], self.rows(), 'the buffer is the one the handler writes')
        raised = [a for a in api.load(api.ALERTS_FILE)['alerts'] if a['event'] == 'log_alert']
        self.assertEqual(len(raised), 1)
        seeded = next(a for a in self.raw['alerts.json']['alerts'] if a['event'] == 'log_alert')
        for key in ('event', 'severity', 'title', 'device_id', 'device_name', 'payload', 'source', 'acknowledged_by', 'resolved_by'):
            self.assertEqual(raised[0][key], seeded[key], key)
        self.assertEqual(seeded['payload']['count'], len(self.rows()))
        self.assertGreaterEqual(seeded['payload']['count'], self.rule()['threshold'])
        # the handler records the same alert in the activity feed, with the first line of the sample
        fed = [e for e in api.load(api.FLEET_EVENTS_FILE)['events'] if e['event'] == 'log_alert']
        seeded_feed = [e for e in self.raw['fleet_events.json']['events'] if e['event'] == 'log_alert']
        self.assertEqual(([e['payload'] for e in fed], len(seeded_feed)), ([seeded_feed[0]['payload']], 1))
        self.assertEqual(seeded_feed[0]['payload']['sample'], seeded['payload']['sample'][:1])

    def test_eleven_lines_would_not_have_raised_it_the_rule_wants_ten_in_one_report(self):
        api = scratch(['devices.json', 'log_rules_global.json'], fire=True)
        dev = api.load(api.DEVICES_FILE)[WIN]
        units = {UNIT: [{'message': r['line'], 'ts': r['ts'] * 1000} for r in self.rows()[:9]]}
        st, out = call(api, api.handle_log_submit, token=None, method='POST', body={'device_id': WIN, 'token': dev['token'], 'units': units})
        self.assertEqual((st, out.get('alerts_fired')), (200, 0), 'nine failed logons are under the threshold of ten: the instrument sees a report that does not fire')

    def test_the_logs_page_reads_the_rule_the_unit_and_the_lines(self):
        self.fresh()
        rules = ok(self, self.api, self.api.handle_log_rules_global_list)['rules']
        mine = [r for r in rules if r['unit'] == UNIT]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]['threshold'], mine[0]['created_by']), (10, 'alice'))
        buf = ok(self, self.api, self.api.handle_log_device, WIN)
        self.assertEqual((sorted(buf['units']), len(buf['units'][UNIT])), ([UNIT], 12))
        found = ok(self, self.api, self.api.handle_log_search, query='q=failed+logon&device=' + WIN)
        self.assertEqual((found['count'], {r['unit'] for r in found['results']}), (12, {UNIT}), 'the search finds the twelve lines, in the one unit')

    def test_the_inbox_has_the_alert_and_it_is_the_only_one_of_its_kind(self):
        self.fresh()
        alerts = ok(self, self.api, self.api.handle_alerts_list)['alerts']
        mine = [a for a in alerts if a['event'] == 'log_alert' and a['device_id'] == WIN]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]['severity'], mine[0]['payload']['unit'], mine[0]['payload']['count']), ('medium', UNIT, 12))
        self.assertTrue(mine[0]['title'].startswith('Log alert on design-win11: design-win11: 12 failed logons in one report. Latest: [4625] failed logon rid='))
        self.assertFalse(mine[0].get('resolved_at') or mine[0].get('acknowledged_by'))
        feed = [e for e in ok(self, self.api, self.api.handle_fleet_events) if e['event'] == 'log_alert']
        self.assertEqual([(e['payload']['device_id'], e['payload']['count'], e['payload']['unit']) for e in feed], [(WIN, 12, UNIT)])
        self.assertEqual(len(feed[0]['payload']['sample']), 1, 'the feed keeps one line of the sample')


# ── 9. What starts by itself on the Windows host ──────────────────────────────────────────────────────────────────────────────────────────────────────

class TestThePersistenceInventory(_SecondHalf):

    def rec(self):
        return self.raw['persistence.json'][WIN]

    def snapshots(self):
        return seed._demo_persist_snapshot(False), seed._demo_persist_snapshot(True)

    def ingest(self, fire=True):
        """The real ingest, given the three inventories at the times the seeded record says they were taken."""
        api = scratch(['devices.json'], fire=fire)
        rec = self.rec()
        before, after = self.snapshots()
        for snap, at in ((before, rec['baseline']), (after, rec['alert_ts']), (after, rec['ts'])):
            api._persistence_ingest(WIN, 'design-win11', snap, at)
        api._LOAD_CACHE.clear()
        return api

    def test_the_row_is_what_the_real_ingest_writes_for_the_three_inventories(self):
        api = self.ingest()
        self.assertEqual(api._entity_read_one(api.PERSISTENCE_FILE, WIN, None), self.rec())
        rec = self.rec()
        self.assertLess(rec['baseline'], rec['alert_ts'])
        self.assertLess(rec['alert_ts'], rec['ts'])
        self.assertEqual([(e['op'], e['cat'], e['name']) for e in rec['log']],
                         [('added', 'run', 'WinSysHelper'), ('added', 'startup', 'Backup Sync.lnk'), ('removed', 'run', 'OneDriveSetup')])
        self.assertTrue(all(e['alerted'] for e in rec['log']), 'what was sent is marked, and a removal never alerts')
        self.assertEqual({e['ts'] for e in rec['log']}, {rec['alert_ts']}, 'all three came in one inventory')

    def test_the_first_inventory_raised_nothing_and_one_alert_went_out_for_what_changed_after_it(self):
        api = self.ingest()
        self.assertEqual([e for e, _ in api.told], ['persistence_added'])
        (_event, payload), = api.told
        seeded = next(a for a in self.raw['alerts.json']['alerts'] if a['event'] == 'persistence_added')
        self.assertEqual(payload, seeded['payload'])
        self.assertEqual((payload['count'], payload['detail']), (2, '2 new startup entries (1 Run key, 1 startup folder file)'))

    def test_the_alert_and_the_feed_entry_are_what_the_real_machinery_stores_for_that_payload(self):
        api = self.ingest()
        raised = [a for a in api.load(api.ALERTS_FILE)['alerts'] if a['event'] == 'persistence_added']
        seeded = [a for a in self.raw['alerts.json']['alerts'] if a['event'] == 'persistence_added']
        self.assertEqual((len(raised), len(seeded)), (1, 1))
        for key in ('event', 'severity', 'title', 'device_id', 'device_name', 'payload', 'source', 'acknowledged_by', 'resolved_by'):
            self.assertEqual(raised[0][key], seeded[0][key], key)
        fed = [e for e in api.load(api.FLEET_EVENTS_FILE)['events'] if e['event'] == 'persistence_added']
        seeded_feed = [e for e in self.raw['fleet_events.json']['events'] if e['event'] == 'persistence_added']
        self.assertEqual(([e['payload'] for e in fed], len(seeded_feed)), ([seeded_feed[0]['payload']], 1))
        self.assertEqual(seeded_feed[0]['payload']['sample'], [seeded[0]['payload']['sample'][0]], 'the feed keeps the first line of the sample')

    def test_the_inventory_is_what_the_agent_reads_from_a_host_that_looks_like_this(self):
        twp, P, agent = persistence_helpers(), persistence, win_agent()
        before, after = self.snapshots()
        for snapshot in (before, after):
            reg, run, env, done = self.host_for(snapshot)
            try:
                got = agent.collect_persistence(wr=reg, run=run, env=env, budget=60)
            finally:
                done()
            self.assertEqual(P.clean_snapshot(got), P.clean_snapshot(snapshot))
            self.assertEqual(reg.touched, [], 'the inventory reached for nothing a read does not need')
            self.assertTrue(reg.opened and all(access & ~(reg.KEY_READ | reg.KEY_WOW64_64KEY | reg.KEY_WOW64_32KEY) == 0 for _path, access in reg.opened),
                            'control: keys were opened, and each for reading only')

    def host_for(self, snapshot):
        """A host whose registry, schtasks answer and startup folders hold what `snapshot` says, in the form Windows has them: the stand-ins of tests/test_win_persistence.py."""
        twp = persistence_helpers()
        reg = twp.FakeRegistry()
        by_key = {}
        for loc, name, data in snapshot['run']['items']:
            key = twp.RUNONCE if loc.startswith('RunOnce') else twp.RUN
            by_key.setdefault((32 if loc.endswith('(32-bit)') else 64, key), []).append((name, data, twp.X if '%' in data else twp.S))
        for (view, key), values in by_key.items():
            reg.add(key, values, view=view)
        reg.add(twp.WINLOGON, [(name, data, twp.S) for _loc, name, data in snapshot['winlogon']['items']] + [('Background', '0 0 0', twp.S)])
        reg.add(twp.SERVICES, subkeys=['Spooler', 'WinDefend'])
        reg.add(twp.SERVICES + '\\Spooler', [('ImagePath', '%SystemRoot%\\System32\\spoolsv.exe', twp.X)])
        reg.add(twp.SERVICES + '\\WinDefend', [('ImagePath', '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2309.6-0\\MsMpEng.exe"', twp.S)])
        docs = []
        for folder, name, what in snapshot['tasks']['items']:
            uri = ('\\' + name) if folder == '\\' else folder + '\\' + name
            if what.startswith('"'):
                end = what.index('"', 1) + 1
                command, arguments = what[:end], what[end:].strip() or None
            else:
                command, arguments = what, None
            docs.append(twp.task_xml(uri, command, arguments))
        docs.append(twp.task_xml('\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', '%windir%\\system32\\defrag.exe', '-c -h -o -$'))     # Microsoft's own: not listed
        text = '\n'.join(docs)
        root = Path(tempfile.mkdtemp(prefix='rp-demoseedcov-fs-'))
        (root / 'ProgramData' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'StartUp').mkdir(parents=True)
        (root / 'Users' / 'Public').mkdir(parents=True)
        for loc, fname, data in snapshot['startup']['items']:
            folder = root / 'Users' / loc[len('User '):] / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            folder.mkdir(parents=True, exist_ok=True)
            (folder / fname).write_bytes(b'L' * int(data.split()[0]))
        env = {'programdata': str(root / 'ProgramData'), 'systemdrive': str(root), 'systemroot': 'C:\\Windows', 'windir': 'C:\\Windows', 'temp': 'C:\\Windows\\TEMP',
               'localappdata': 'C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local'}
        return reg, (lambda args, timeout: text), env, (lambda: shutil.rmtree(root, ignore_errors=True))

    def test_the_hosts_page_reads_the_inventory_and_the_log_through_the_real_handler(self):
        self.fresh()
        out = ok(self, self.api, self.api.handle_device_persistence, WIN)
        self.assertTrue(out['windows'])
        p = out['persistence']
        self.assertEqual({c: (len(v['items']), v['ok'], v['complete'], v['missed']) for c, v in p['inventory'].items()},
                         {'run': (4, True, True, 0), 'winlogon': (2, True, True, 0), 'services': (0, True, True, 0), 'tasks': (5, True, True, 0), 'startup': (1, True, True, 0)})
        self.assertEqual(sorted((c['op'], c['name']) for c in p['changes']), [('added', 'Backup Sync.lnk'), ('added', 'WinSysHelper'), ('removed', 'OneDriveSetup')])
        self.assertTrue(p['baseline'] < p['changes'][0]['ts'] < p['ts'])
        viewer = ok(self, self.api, self.api.handle_device_persistence, WIN, token='v')
        self.assertEqual(viewer['persistence']['changes'], p['changes'], 'any signed-in role may read it')
        for host in ('pmx01', MAC):
            other = ok(self, self.api, self.api.handle_device_persistence, host)
            self.assertEqual((other['windows'], other['persistence']), (False, None), host)

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_section_draws_each_change_and_each_place(self):
        self.fresh()
        p = ok(self, self.api, self.api.handle_device_persistence, WIN)['persistence']
        js = (JS / 'app-persistence.js').read_text(encoding='utf-8')
        body = '\n'.join((srcpin.balanced_block(js, 'const _PERS_CATS = ', '[', ']') + ';', srcpin.balanced_block(js, 'const _PERS_LABEL = ', '{', '}') + ';',
                          srcpin.js_function(js, '_persEntryHtml'), srcpin.js_function(js, '_persChangeHtml'), srcpin.js_function(js, '_persPlaceHtml')))
        script = ('const escHtml = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");\nconst timeAgoHtml = t => "<time>" + t + "</time>";\n' + body
                  + '\nconst p = %s;\nconsole.log(JSON.stringify({changes: p.changes.map(_persChangeHtml), places: _PERS_CATS.map(c => _persPlaceHtml(c, p.inventory[c]))}));\n' % json.dumps(p))
        got = node_json(script)
        text = lambda h: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', h)).strip()
        changes = sorted(text(h) for h in got['changes'])
        self.assertEqual(len(changes), 3, changes)
        self.assertTrue(changes[0].startswith('Added Run key WinSysHelper Run "C:\\Users\\Public\\Libraries\\syshelper.exe" -silent'), changes[0])
        self.assertTrue(changes[1].startswith('Added Startup folder Backup Sync.lnk User alice 1319 bytes'), changes[1])
        self.assertTrue(changes[2].startswith('Removed Run key OneDriveSetup Run (32-bit)'), changes[2])
        places = [text(h) for h in got['places']]
        self.assertEqual([t.split(' ')[0] for t in places if t], ['Run', 'Winlogon', 'Scheduled', 'Startup'], 'a place with nothing in it and nothing to say draws nothing')

    def test_the_inbox_and_the_activity_feed_show_the_change(self):
        self.fresh()
        alerts = ok(self, self.api, self.api.handle_alerts_list)['alerts']
        mine = [a for a in alerts if a['event'] == 'persistence_added']
        self.assertEqual([(a['severity'], a['title'], a['device_id']) for a in mine], [('medium', 'New startup entries on design-win11', WIN)])
        feed = [e for e in ok(self, self.api, self.api.handle_fleet_events) if e['event'] == 'persistence_added']
        self.assertEqual(len(feed), 1)
        self.assertEqual((feed[0]['payload']['device_id'], feed[0]['payload']['count']), (WIN, 2))
        self.assertTrue(feed[0]['payload']['detail'].startswith('2 new startup entries'))


# ── 10. The package lists of a Linux host: when they were refreshed and how it went ─────────────────────────────────────────────────────────────────────

class TestThePackageListRefresh(_SecondHalf):

    def records(self):
        return {h: d['sysinfo']['pkg_refresh'] for h, d in self.devices.items() if 'pkg_refresh' in (d.get('sysinfo') or {})}

    def test_three_hosts_have_a_record_and_each_is_one_the_server_keeps_as_it_is(self):
        recs = self.records()
        self.assertEqual(sorted(recs), ['ha01', 'jf01', 'ng01'])
        now = int(time.time())
        for host, rec in recs.items():
            self.assertEqual(pkg_refresh.clean(rec, now), rec, host)
            self.assertEqual(sorted(rec), ['at', 'error_class', 'source', 'status'], host)
        self.assertEqual({h: (r['status'], r['source'], r['error_class']) for h, r in recs.items()},
                         {'ng01': ('ok', 'apt', ''), 'jf01': ('failed', 'apt', 'network'), 'ha01': ('unsupported', '', 'container')})
        self.assertTrue(now - 20 * 60 < recs['ng01']['at'] < now - 5 * 60, 'refreshed about twelve minutes before the seed')
        self.assertTrue(now - 36 * 3600 < recs['jf01']['at'] < now - 18 * 3600, 'failed about a day ago')

    def test_the_hosts_that_have_one_are_hosts_the_server_would_send_the_command_to(self):
        self.fresh()
        devices = self.api.load(self.api.DEVICES_FILE)
        refused = {host: self.api._command_block_reason(dev, pkg_refresh.VERB) for host, dev in devices.items()}
        for host in self.records():
            self.assertIn(host, linux_agent_hosts(self.devices))
            self.assertIsNone(refused[host], '%s has a refresh record and the server would refuse the command for it: %s' % (host, refused[host]))
            self.assertGreaterEqual(version_tuple(self.devices[host]['version']), pkg_refresh.MIN_AGENT, host)
        # the controls: the server does refuse the command for an agent in audit mode, for an agent from before the command, and for the two hosts that are not Linux
        self.assertIn('audit', refused['bk01'][1].lower())
        self.assertIn('too old', refused['tnas'][1])
        self.assertTrue(refused[WIN] and refused[MAC])
        # and a host the server refuses has no record
        for host, why in refused.items():
            if why:
                self.assertNotIn(host, self.records(), host)
        # the hosts of the 8.0.2 agent that were never asked have none and are not refused: the card says Never
        self.assertEqual(sorted(h for h in linux_agent_hosts(self.devices) if refused[h] is None and h not in self.records()), ['fw01', 'gt01', 'pmx01'])

    def test_the_records_are_what_the_agent_writes(self):
        agent, recs = linux_agent(), self.records()
        tmp = Path(tempfile.mkdtemp(prefix='rp-demoseedcov-pm-'))
        self.addCleanup(shutil.rmtree, tmp, True)

        def manager(directory, name, output, rc):
            d = tmp / directory
            d.mkdir(exist_ok=True)
            f = d / name
            f.write_text("#!/bin/sh\ncat <<'RP_END'\n%s\nRP_END\nexit %d\n" % (output, rc))
            f.chmod(0o755)

            def which(n):
                p = d / n
                return str(p) if p.is_file() and os.access(p, os.X_OK) else None
            return which

        ok_apt = manager('ok', 'apt-get', 'Reading package lists... Done', 0)
        down = manager('down', 'apt-get', "Err:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n  Temporary failure resolving 'archive.ubuntu.com'\nReading package lists... Done", 100)
        with mock.patch.object(agent, 'IN_CONTAINER', False):
            made = {'ng01': agent._pkg_refresh_run(which=ok_apt), 'jf01': agent._pkg_refresh_run(which=down)}
        with mock.patch.object(agent, 'IN_CONTAINER', True):
            made['ha01'] = agent._pkg_refresh_run(which=ok_apt)
        for host, rec in recs.items():
            self.assertEqual({k: v for k, v in made[host].items() if k != 'at'}, {k: v for k, v in rec.items() if k != 'at'}, host)
            self.assertEqual(sorted(made[host]), sorted(rec), host)

    def test_the_host_that_refreshed_read_what_is_pending_after_it_and_the_container_agent_is_the_one_that_cannot(self):
        ng = self.devices['ng01']['sysinfo']
        self.assertGreaterEqual(ng['pkg_scan_ts'], ng['pkg_refresh']['at'], 'the agent reads the pending list again after a refresh that worked')
        self.assertLess(ng['pkg_scan_ts'] - ng['pkg_refresh']['at'], 300)
        for host, dev in linux_agent_hosts(self.devices).items():
            caps = dev['sysinfo'].get('capabilities') or {}
            self.assertEqual(caps.get('container') is True, host in self.records() and self.records()[host]['error_class'] == 'container', host)

    def test_the_real_reader_and_the_real_heartbeat_keep_the_record_as_it_is(self):
        self.fresh()
        for host, rec in self.records().items():
            self.assertEqual(ok(self, self.api, self.api.handle_sysinfo, host)['sysinfo']['pkg_refresh'], rec, host)
        api = scratch(['devices.json', 'config.json'])
        for host, rec in self.records().items():
            dev = api.load(api.DEVICES_FILE)[host]
            st, out = S.beat(api, host, dev['token'], copy.deepcopy(dev['sysinfo']))
            self.assertEqual(st, 200, out)
            self.assertEqual(api.load(api.DEVICES_FILE)[host]['sysinfo']['pkg_refresh'], rec, host)
        for host in (WIN, MAC):
            self.assertNotIn('pkg_refresh', self.devices[host]['sysinfo'], 'the command is for Linux hosts')
            self.assertEqual(call(self.api, self.api.handle_sysinfo, host)[0], 200)

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_packages_section_says_it_in_words(self):
        app = (JS / 'app.js').read_text(encoding='utf-8')
        body = '\n'.join((srcpin.balanced_block(app, 'const _PKG_REFRESH_STATUS = ', '{', '}') + ';', srcpin.balanced_block(app, 'const _PKG_REFRESH_CLASS = ', '{', '}') + ';',
                          srcpin.js_function(app, '_pkgRefreshPill')))
        recs = dict(self.records(), pmx01=None)
        script = ('const timeAgoHtml = t => "<time>" + t + "</time>";\n' + body + '\nconst recs = %s;\nconst out = {};\n'
                  'for (const [h, r] of Object.entries(recs)) out[h] = _pkgRefreshPill(r);\nconsole.log(JSON.stringify(out));\n' % json.dumps(recs))
        text = {h: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html)).strip() for h, html in node_json(script).items()}
        self.assertRegex(text['ng01'], r'^Lists refreshed \d+ Succeeded$')
        self.assertRegex(text['jf01'], r'^Lists refreshed \d+ Failed the repositories could not be reached$')
        self.assertRegex(text['ha01'], r'^Lists refreshed \d+ Not refreshed not available in a container$')
        self.assertEqual(text['pmx01'], 'Lists refreshed Never')


# ── 11. What the agent of a Linux host can see ──────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestWhatTheAgentCanSee(_SecondHalf):
    # the tool each firewall backend of the demo's hosts is run with
    FIREWALL_TOOL = {'nftables': 'nft', 'iptables': 'iptables', 'ufw': 'ufw'}

    def caps(self):
        return {h: d['sysinfo']['capabilities'] for h, d in self.devices.items() if 'capabilities' in (d.get('sysinfo') or {})}

    def present(self, host):
        return sorted(k for k, v in self.caps()[host]['tools'].items() if v)

    def answer(self, host):
        self.fresh()
        return ok(self, self.api, self.api.handle_device_capabilities, host)

    def test_the_hosts_that_report_are_the_linux_hosts_of_the_agent_that_sends_it_and_no_other(self):
        expected = {h for h, d in linux_agent_hosts(self.devices).items() if version_tuple(d['version']) >= SECOND_HALF}
        self.assertEqual(sorted(self.caps()), sorted(expected))
        self.assertGreaterEqual(len(expected), 4, 'control: there are hosts of the agent that sends it')
        older = set(linux_agent_hosts(self.devices)) - expected
        self.assertTrue(older, 'control: and hosts of an older one, whose card says the agent has not reported')
        for host in older | {WIN, MAC}:
            self.assertNotIn('capabilities', self.devices[host]['sysinfo'], host)
            self.assertEqual(self.answer(host)['reported'], False, host)

    def test_every_report_is_one_the_server_keeps_as_it_is_with_all_25_tools_as_true_or_false(self):
        for host, caps in self.caps().items():
            self.assertEqual(agent_capabilities.clean(copy.deepcopy(caps)), caps, host)
            self.assertEqual(list(caps['tools']), list(agent_capabilities.TOOL_KEYS), host)
            self.assertTrue(all(isinstance(v, bool) for v in caps['tools'].values()), host)
            self.assertEqual(caps['agent']['version'], self.devices[host]['version'], 'the report names the agent that sent it')

    def test_the_debian_family_host_has_seven_tools_and_the_page_says_what_the_others_are_for_and_how_to_get_them(self):
        self.assertEqual(self.present('jf01'), sorted(['ss', 'lsblk', 'ufw', 'journalctl', 'systemctl', 'apt', 'docker']))
        out = self.answer('jf01')
        self.assertEqual((out['root'], out['container'], out['distro'], out['family'], out['unavailable'], out['notices']), (True, False, 'ubuntu', 'apt', 0, []))
        missing = {t['name']: t for t in out['tools'] if t['status'] == 'missing'}
        self.assertEqual(out['missing'], len(missing))
        self.assertEqual(missing['smartctl']['hint'], 'apt install smartmontools')
        self.assertEqual(missing['smartctl']['feature'], 'Disk health (SMART)')
        self.assertTrue(missing['ipmitool']['optional'] and not missing['smartctl']['optional'])
        notneeded = {t['name'] for t in out['tools'] if t['status'] == 'not_needed'}
        self.assertTrue({'firewalld', 'iptables', 'nft', 'podman', 'dnf', 'zypper', 'apk', 'pacman'} <= notneeded, 'one firewall tool and one container tool are enough, and another distribution\'s package manager is not needed')

    def test_the_container_agent_is_not_root_sees_the_host_through_mapped_paths_and_cannot_install_anything(self):
        out = self.answer('ha01')
        self.assertEqual((out['root'], out['container'], out['mapped']), (False, True, ['/etc', '/proc', '/sys', '/var/lib', '/var/log']))
        self.assertEqual(sorted(out['notices']), sorted(agent_capabilities.NOTICES.values()), 'both sentences: not root, and a container')
        self.assertEqual(out['missing'], 0)
        self.assertGreater(out['unavailable'], 5)
        self.assertTrue(all(not t['hint'] for t in out['tools']), 'a container has nothing to install into')
        self.assertEqual(self.present('ha01'), sorted(['ss', 'smartctl', 'lsblk', 'apt']), 'the tools the agent image holds')

    def test_the_web_host_runs_fail2ban_whose_log_the_agent_cannot_open(self):
        out = self.answer('ng01')
        self.assertEqual([(l['kind'], l['path'], l['readable']) for l in out['logs']],
                         [('web', '/var/log/nginx/access.log', True), ('err', '/var/log/nginx/error.log', True), ('f2b', '/var/log/fail2ban.log', False)])
        self.assertIn('fail2ban-client', self.present('ng01'))
        self.assertTrue(all(p.startswith('/') for p in [l['path'] for l in out['logs']]), 'paths only')
        self.assertEqual(self.answer('jf01')['logs'], [])

    def test_what_each_host_has_agrees_with_what_the_rest_of_the_seed_says_it_runs(self):
        hardware, scap = self.raw['hardware.json'], self.raw['scap.json']
        for host, caps in self.caps().items():
            if caps['container']:
                continue                   # the agent of a container holds the tools of its image, not of the host
            tools, si, dev = caps['tools'], self.devices[host]['sysinfo'], self.devices[host]
            backend = (si.get('firewall_fp') or {}).get('backend')
            self.assertTrue(tools[self.FIREWALL_TOOL[backend]], '%s runs %s' % (host, backend))
            self.assertEqual(tools['docker'], bool(dev.get('compose_projects')), '%s docker' % host)
            self.assertEqual(tools['smartctl'], bool((hardware.get(host) or {}).get('smart')), '%s smartctl' % host)
            self.assertEqual(tools['dmidecode'], bool(((hardware.get(host) or {}).get('hardware') or {}).get('bios_vendor') or ((hardware.get(host) or {}).get('hardware') or {}).get('system')),
                             '%s dmidecode' % host)
            self.assertEqual(tools['sensors'], bool((((hardware.get(host) or {}).get('hardware')) or {}).get('temps')), '%s sensors' % host)
            self.assertEqual(tools['fail2ban-client'], (si.get('fail2ban') or {}).get('available') is True, '%s fail2ban' % host)
            self.assertEqual(tools['oscap'], host in scap, '%s oscap' % host)
            self.assertEqual(tools['journalctl'] and tools['systemctl'], caps['init'] == 'systemd', host)
            self.assertEqual(any(l['kind'] == 'f2b' for l in caps['logs']), tools['fail2ban-client'], '%s fail2ban log' % host)

    def test_the_tools_are_what_the_real_agent_finds_on_a_host_with_exactly_those_files(self):
        agent = linux_agent()
        names = dict(agent.CAPABILITY_TOOLS)
        for host, caps in self.caps().items():
            d = Path(tempfile.mkdtemp(prefix='rp-demoseedcov-bin-'))
            self.addCleanup(shutil.rmtree, d, True)
            for key, present in caps['tools'].items():
                if present:
                    f = d / names[key][0]
                    f.write_text('#!/bin/sh\n')
                    f.chmod(0o755)
            self.assertEqual(agent.collect_capabilities(tool_dirs=[str(d)])['tools'], caps['tools'], host)

    def test_the_real_heartbeat_keeps_each_report_as_it_is(self):
        api = scratch(['devices.json', 'config.json'])
        for host, caps in self.caps().items():
            dev = api.load(api.DEVICES_FILE)[host]
            st, out = S.beat(api, host, dev['token'], copy.deepcopy(dev['sysinfo']))
            self.assertEqual(st, 200, out)
            self.assertEqual(api.load(api.DEVICES_FILE)[host]['sysinfo']['capabilities'], caps, host)


# ── 12. What each scan checked, and the kernel a host runs ───────────────────────────────────────────────────────────────────────────────────────────────
#
# Two states are not seeded, because the demo cannot hold them without contradicting itself: a package that was "not checked, no source name" (every list of the demo names its source
# packages, which tests/test_v801_deb_source_matching.py requires), and a package-list refresh that had "no safe way" (it is the answer of an Arch host, and the demo has none). The
# packages a scan did not check say "no matcher" (the two application lists) and "not answered in full" (the kernel of the NAS), which is what each of those hosts would show.

KERNEL_HOST, NOT_REPORTED_HOST = 'pmx01', 'tnas'


class _Scans(_SecondHalf):

    @property
    def findings(self):
        return self.raw['cve_findings.json']

    def entry(self, host):
        return self.raw['packages.json'][host]

    def real_scan(self, host, advisories=None, truncated=()):
        """The scan the server makes of the seeded list of `host`, with a data source that answers no advisory for any package except the ones given (`advisories` is
        {(package, version): [OSV records]}) and cuts the answer for `truncated` packages. A question it was not set up for raises, so the scan cannot reach a network."""
        entry = self.entry(host)
        ecosystem, release = cve_scanner.entry_ecosystem(entry), cve_scanner.entry_release(entry)
        units, _block, _later, _left = cve_scanner.plan_host(entry['packages'], ecosystem, entry.get('sources') is True, release, entry.get('kernel'))
        prefetch, details = {}, {}
        for u in units:
            records = (advisories or {}).get((u['package'], u['version']), [])
            answer = {'vulns': [{'id': r['id'], 'modified': r['modified']} for r in records]}
            if u['package'] in truncated:
                answer['truncated'] = True
            prefetch[(ecosystem, u['name'], u['version'])] = answer
            for r in records:
                details[r['id']] = cve_scanner._detail_entry(r, ecosystem)

        def never(*_a, **_k):
            raise AssertionError('the scan asked the data source for something that was not set up')
        with mock.patch.object(cve_scanner, '_osv_querybatch', never), mock.patch.object(cve_scanner, '_osv_vuln_details', never):
            result = cve_scanner.scan_device(host, entry['packages'], ecosystem, Path(tempfile.mkdtemp(prefix='rp-demoseedcov-scan-')), osv_prefetch=prefetch,
                                             has_meta=entry.get('sources') is True, release=release, kernel=entry.get('kernel'), details=details)
        self.assertNotIn('error', result, result.get('error'))
        return result


def advisory(vid, summary, published, fixed='6.1.115-1'):
    """The record of the data source for a kernel finding, written so that a scan makes the seeded row of it: a medium rating of the distribution's own, one reference, the fix in
    the host's release."""
    return {'id': vid, 'summary': summary, 'published': published, 'modified': '2026-11-10T08:00:00.123456Z', 'severity': [{'type': 'Ubuntu', 'score': 'medium'}],
            'references': [{'url': 'https://nvd.nist.gov/vuln/detail/' + vid}],
            'affected': [{'package': {'ecosystem': 'Ubuntu:22.04:LTS', 'name': 'linux'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': fixed}]}]}]}


class TestWhatEachScanChecked(_Scans):

    def test_every_scanned_host_states_its_packages_and_the_account_adds_up(self):
        self.assertEqual(len(self.findings), 10)
        for host, rec in self.findings.items():
            covered = rec['covered']
            self.assertEqual(cve_fixes.covered_view(copy.deepcopy(covered)), {**{k: covered[k] for k in ('listed', 'checked', 'not_checked', 'reasons', 'packages')}, 'more': covered['more']}, host)
            self.assertEqual(covered['checked'] + covered['not_checked'], covered['listed'], host)
            self.assertEqual(sum(covered['reasons'].values()), covered['not_checked'], host)
            left_out = (rec.get('kernel') or {}).get('left_out', 0)
            self.assertEqual(covered['listed'], self.entry(host)['count'] - left_out, '%s: the packages of a kernel that does not run are left out of the account' % host)
            self.assertEqual(len(covered['packages']) + covered['more'], covered['not_checked'], host)
            self.assertIsInstance(rec['cut'], list, host)

    def test_a_real_scan_of_the_seeded_list_writes_the_same_account_for_every_host(self):
        for host, rec in self.findings.items():
            cut = tuple(rec['cut'])
            got = self.real_scan(host, truncated=cut)
            self.assertEqual(got['covered'], rec['covered'], host)
            self.assertEqual(got.get('kernel'), rec.get('kernel'), host)
            self.assertEqual(got['cut'], rec['cut'], host)

    def test_one_host_has_packages_the_data_source_did_not_answer_in_full_and_it_is_the_nas(self):
        rec = self.findings[NOT_REPORTED_HOST]
        self.assertEqual(rec['cut'], ['linux'])
        self.assertEqual((rec['covered']['not_checked'], rec['covered']['reasons']), (3, {'unanswered': 3}))
        self.assertEqual(sorted(p['name'] for p in rec['covered']['packages']), ['linux-headers-6.1.0-21-amd64', 'linux-headers-6.1.0-21-common', 'linux-image-6.1.0-21-amd64'])
        self.assertEqual(rec['findings'], [], 'nothing is listed one by one for it')
        self.assertGreater(rec['rollup']['total'], 0, 'what its scan counted is counted per package')
        others = {h: r['covered']['not_checked'] for h, r in self.findings.items() if h != NOT_REPORTED_HOST}
        self.assertEqual(set(others.values()), {0}, 'every other host was checked in full: the hosts list the source packages, so no host reads "no source name"')

    def test_the_cve_page_reads_it_fleet_wide_and_per_host(self):
        self.fresh()
        report = ok(self, self.api, self.api.handle_cve_findings)
        covered = report['summary']['covered']
        self.assertEqual(covered['hosts_unstated'], 0, 'every scanned host states what it checked')
        scanned = sum(self.entry(h)['count'] - (self.findings[h].get('kernel') or {}).get('left_out', 0) for h in self.findings)
        apps = sum(self.entry(h)['count'] for h in (WIN, MAC))
        self.assertEqual((covered['listed'], covered['not_checked'], covered['checked']), (scanned + apps, 3 + apps, scanned - 3))
        self.assertEqual(covered['reasons'], {'no_matcher': apps, 'unanswered': 3})
        most = {r['device_id']: (r['not_checked'], r['listed'], r['reasons']) for r in report['summary']['most_not_checked']}
        self.assertEqual(most[NOT_REPORTED_HOST], (3, 325, {'unanswered': 3}))
        self.assertEqual(sorted(most), sorted([NOT_REPORTED_HOST, WIN, MAC]))
        view = ok(self, self.api, self.api.handle_cve_device, NOT_REPORTED_HOST)
        self.assertEqual(view['covered']['not_checked'], 3)
        self.assertEqual(view['cut'], ['linux'])
        full = ok(self, self.api, self.api.handle_cve_device, 'nc01')
        self.assertEqual((full['covered']['not_checked'], full['covered']['checked'], full['cut']), (0, 190, []))

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_host_view_draws_the_rows_and_the_reason_in_words(self):
        self.fresh()
        view = ok(self, self.api, self.api.handle_cve_device, NOT_REPORTED_HOST)
        js = (JS / 'app-cve.js').read_text(encoding='utf-8')
        body = '\n'.join((srcpin.balanced_block(js, 'const _CVE_NOT_CHECKED = ', '{', '}') + ';', srcpin.js_function(js, '_cveCoveredHtml')))
        script = ('const escHtml = s => String(s); const _localeTag = () => "en";\n' + body + '\nconsole.log(JSON.stringify(_cveCoveredHtml(%s)));\n' % json.dumps(view['covered']))
        html = node_json(script)
        text = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html)).strip()
        self.assertIn('Packages checked: 322 / 325', text)
        self.assertIn('Not checked: 3', text)
        self.assertEqual(text.count('Not answered in full by the data source'), 4, 'the reason in the count table and on each of the three rows')
        for name in ('linux-image-6.1.0-21-amd64', 'linux-headers-6.1.0-21-amd64', 'linux-headers-6.1.0-21-common'):
            self.assertIn(name, text)


class TestTheKernelAHostRuns(_Scans):

    def kernel_findings(self):
        return [f for f in self.findings[KERNEL_HOST]['findings'] if f['fix_status'] == 'reboot']

    def test_the_hypervisor_runs_one_kernel_and_holds_a_newer_one_that_fixes_two_findings(self):
        rec = self.findings[KERNEL_HOST]
        self.assertEqual(rec['kernel'], {'running': '6.1.0-21-amd64', 'state': 'matched', 'package': 'linux-image-6.1.0-21-amd64', 'version': '6.1.90-1', 'left_out': 3,
                                         'newer': 'linux-image-6.1.0-27-amd64 6.1.115-1'})
        found = self.kernel_findings()
        self.assertEqual(sorted(f['vuln_id'] for f in found), ['CVE-2024-91001', 'CVE-2024-91002'])
        for f in found:
            self.assertEqual((f['package'], f['version'], f['fixed_version'], f['reboot_to'], f['severity']), ('linux', '6.1.90-1', '6.1.115-1', rec['kernel']['newer'], 'medium'))
            self.assertTrue(cve_fixes.kept(f) and cve_fixes.is_clearable(f) and not cve_fixes.is_fixable(f), 'something to do, and not something an update clears')
        self.assertEqual(cve_fixes.fix_key(found[0]), 'reboot')
        entry = self.entry(KERNEL_HOST)
        self.assertEqual(entry['kernel'], {'release': '6.1.0-21-amd64', 'images': [{'name': 'linux-image-6.1.0-21-amd64', 'version': '6.1.90-1', 'release': '6.1.0-21-amd64'},
                                                                                 {'name': 'linux-image-6.1.0-27-amd64', 'version': '6.1.115-1', 'release': '6.1.0-27-amd64'}]})
        self.assertEqual(cve_scanner.kernel_report(copy.deepcopy(entry['kernel'])), entry['kernel'], 'the report is the one the server keeps')

    def test_the_real_scan_of_the_seeded_list_makes_the_same_two_findings_and_the_same_kernel_block(self):
        records = [advisory('CVE-2024-91001', 'Use-after-free in the netfilter set handling.', '2024-09-18'), advisory('CVE-2024-91002', 'Out-of-bounds read in the USB audio driver.', '2024-10-02')]
        got = self.real_scan(KERNEL_HOST, advisories={('linux', '6.1.90-1'): records})
        seeded = {f['vuln_id']: f for f in self.kernel_findings()}
        self.assertEqual({f['vuln_id']: f for f in got['findings']}, seeded, 'the scan writes the seeded rows, key for key')
        self.assertEqual(got['kernel'], self.findings[KERNEL_HOST]['kernel'])
        self.assertEqual(got['covered'], self.findings[KERNEL_HOST]['covered'])
        # the control: with the newer kernel gone from the host the same advisories are findings an update has to clear, and the instrument sees it
        entry = copy.deepcopy(self.entry(KERNEL_HOST))
        only_running = [p for p in entry['packages'] if not p['name'].endswith('-27-amd64') and not p['name'].endswith('-27-common')]
        entry['kernel']['images'] = entry['kernel']['images'][:1]
        units, block, later, _left = cve_scanner.plan_host(only_running, 'Ubuntu', True, 'Ubuntu:22.04:LTS', entry['kernel'])
        self.assertEqual((block['state'], later), ('matched', []), 'nothing is installed beside the kernel that runs')

    def test_the_nas_lists_a_kernel_its_agent_does_not_say_it_runs_so_the_scan_cannot_tell_which(self):
        rec = self.findings[NOT_REPORTED_HOST]
        self.assertEqual(rec['kernel'], {'running': '', 'state': 'unknown', 'why': 'not_reported', 'left_out': 0})
        self.assertNotIn('kernel', self.entry(NOT_REPORTED_HOST), 'an agent that does not report its kernel has none stored')
        self.assertEqual([p['name'] for p in self.entry(NOT_REPORTED_HOST)['packages'] if re.match(r'linux-image-[0-9]', p['name'])], ['linux-image-6.1.0-21-amd64'])
        self.fresh()
        view = ok(self, self.api, self.api.handle_cve_device, NOT_REPORTED_HOST)
        self.assertEqual(view['kernel'], {'state': 'unknown', 'running': '', 'why': 'not_reported', 'left_out': 0})
        words = cve_fixes.kernel_words(rec['kernel'])
        self.assertIn('does not report its running kernel', words)

    def test_no_other_host_has_a_kernel_block_because_no_other_host_lists_a_kernel_image(self):
        self.assertEqual(sorted(h for h, r in self.findings.items() if 'kernel' in r), sorted([KERNEL_HOST, NOT_REPORTED_HOST]))
        for host, entry in self.raw['packages.json'].items():
            has_image = any(re.match(r'linux-image-[0-9]', p['name']) for p in entry['packages'])
            self.assertEqual(has_image, host in (KERNEL_HOST, NOT_REPORTED_HOST), host)
            self.assertEqual('kernel' in entry, host == KERNEL_HOST, host)

    def test_the_lists_are_as_long_as_they_were_and_each_kernel_is_three_packages_of_one_source(self):
        for host, releases in (('pmx01', ('6.1.0-21-amd64', '6.1.0-27-amd64')), ('tnas', ('6.1.0-21-amd64',))):
            entry = self.entry(host)
            self.assertEqual(entry['count'], len(entry['packages']), host)
            self.assertEqual(entry['count'], len(seed._demo_package_inventory(host)[0]), '%s: the kernel rows take the place of generated names, so the list is as long as it was' % host)
            for release in releases:
                rows = [p for p in entry['packages'] if release in p['name'] or release.rsplit('-', 1)[0] + '-common' in p['name']]
                self.assertEqual(len(rows), 3, (host, release))
                self.assertEqual({p['source'] for p in rows}, {'linux'})
                self.assertEqual(len({p['version'] for p in rows}), 1, 'built together, so one version')

    def test_what_the_demo_already_said_about_the_hypervisor_is_what_its_scan_says(self):
        hw = self.raw['hardware.json'][KERNEL_HOST]['kernel']
        rec = self.findings[KERNEL_HOST]['kernel']
        self.assertEqual((hw['running'], hw['reboot_for_kernel']), (rec['running'], True))
        self.assertEqual('linux-image-%s %s' % (hw['latest_installed'], seed._DEMO_KERNEL_VERSIONS[hw['latest_installed']]), rec['newer'])
        si = self.devices[KERNEL_HOST]['sysinfo']
        self.assertEqual(si['kernel'], rec['running'], 'the Kernel line of the host\'s page')
        self.assertIn(rec['running'], si['platform'])
        self.assertEqual((si['reboot_required'], si['reboot_reason']), (True, 'kernel upgrade (6.1.0-21 -> 6.1.0-27)'))
        self.assertTrue([a for a in self.raw['alerts.json']['alerts'] if a['event'] == 'kernel_outdated' and a['device_id'] == KERNEL_HOST], 'the alert of the pending reboot')
        self.assertGreaterEqual(version_tuple(self.devices[KERNEL_HOST]['version']), SECOND_HALF, 'an agent that reports its kernel')
        self.assertLess(version_tuple(self.devices[NOT_REPORTED_HOST]['version']), SECOND_HALF, 'an agent that does not')

    def test_the_fix_tiles_and_the_roll_up_count_it(self):
        self.fresh()
        report = ok(self, self.api, self.api.handle_cve_findings)
        self.assertEqual(report['summary']['fix']['reboot'], 2)
        host = next(d for d in report['devices'] if d['device_id'] == KERNEL_HOST)
        self.assertEqual(host['fix']['reboot'], 2)
        self.assertEqual(sum(report['summary']['fix'].values()), sum(1 for r in self.findings.values() for _ in r['findings']), 'the six tiles add up to the findings')
        rollup = ok(self, self.api, self.api.handle_cve_device, KERNEL_HOST)['rollup']
        self.assertEqual((rollup['packages'][0]['name'], rollup['packages'][0]['version']), ('linux', '6.1.90-1'), 'the roll-up names the kernel the host runs')
        self.assertGreater(rollup['fix']['reboot'], 0)
        self.assertEqual(sum(rollup['fix'].values()), rollup['total'])
        for host, rec in self.findings.items():
            if host != KERNEL_HOST:
                self.assertNotIn('reboot', rec['rollup']['fix'], host)

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_host_view_says_which_kernel_runs_which_is_installed_and_how_many_are_left_to_a_reboot(self):
        self.fresh()
        view, other = ok(self, self.api, self.api.handle_cve_device, KERNEL_HOST), ok(self, self.api, self.api.handle_cve_device, NOT_REPORTED_HOST)
        js = (JS / 'app-cve.js').read_text(encoding='utf-8')
        body = '\n'.join((srcpin.balanced_block(js, 'const _CVE_KERNEL_WHY = ', '{', '}') + ';', srcpin.js_function(js, '_cveKernelHtml'), srcpin.js_function(js, '_cveRollupHtml'),
                          srcpin.js_function(js, '_cveFixHtml') if 'function _cveFixHtml' in js else ''))
        script = ('const escHtml = s => String(s); const _localeTag = () => "en";\n' + body + '\nconst out = {matched: _cveKernelHtml(%s), unknown: _cveKernelHtml(%s), rollup: _cveRollupHtml(%s)};\n'
                  'console.log(JSON.stringify(out));\n' % (json.dumps(view['kernel']), json.dumps(other['kernel']), json.dumps(view['rollup'])))
        got = {k: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', v)).strip() for k, v in node_json(script).items()}
        self.assertEqual(got['matched'], 'Running kernel: 6.1.0-21-amd64 · Package: linux-image-6.1.0-21-amd64 6.1.90-1 · Installed, not running: linux-image-6.1.0-27-amd64 6.1.115-1 '
                                         'Reboot to start it. · Packages of other installed kernels, not counted: 3')
        self.assertIn('Running kernel: not reported', got['unknown'])
        self.assertIn('The agent of this host does not report its running kernel.', got['unknown'])
        self.assertIn('Of these, fixed by an installed kernel, reboot to apply: %d' % view['rollup']['fix']['reboot'], got['rollup'])


# ── 13. The hosts that carry any of this run the agent that sends it ────────────────────────────────────────────────────────────────────────────────────

class TestNoHostCarriesWhatItsPlatformOrItsAgentCannotSend(_SecondHalf):

    def test_the_two_hosts_that_run_a_newer_agent_than_the_draw_gave_are_the_ones_the_data_needs(self):
        self.assertEqual(sorted(seed._DEMO_AGENT_UPDATED), ['pmx01', 'wks01'])
        for host in seed._DEMO_AGENT_UPDATED:
            self.assertEqual(self.devices[host]['version'], seed.CURRENT_VERSION, host)

    def test_a_host_with_a_report_of_the_second_half_runs_an_agent_that_sends_it(self):
        for host, dev in self.devices.items():
            si = dev.get('sysinfo') or {}
            carries = bool({'win_build', 'shares', 'tpm', 'wu_search', 'pkg_refresh', 'capabilities'} & set(si)) or host in self.raw['persistence.json'] or 'kernel' in self.raw['packages.json'].get(host, {})
            if carries:
                self.assertGreaterEqual(version_tuple(dev['version']), SECOND_HALF, '%s carries a report of the 8.0.2 agent and runs %s' % (host, dev['version']))

    def test_no_linux_report_is_on_the_windows_host_or_the_mac_and_no_windows_report_is_on_a_linux_host_or_the_mac(self):
        for host in (WIN, MAC):
            for key in ('pkg_refresh', 'capabilities'):
                self.assertNotIn(key, self.devices[host]['sysinfo'], (host, key))
            self.assertNotIn(host, self.raw['cve_findings.json'], 'a list of applications is not scanned')
            self.assertNotIn('kernel', self.raw['packages.json'][host])
        for host, dev in linux_agent_hosts(self.devices).items():
            for key in ('win_build', 'shares', 'tpm', 'wu_search', 'win_posture'):
                self.assertNotIn(key, dev['sysinfo'], (host, key))
        self.assertNotIn('win_build', self.devices[MAC]['sysinfo'])
        self.assertEqual([r for r in self.raw['config.json']['custom_checks'] if r['type'] == 'registry' and r['target'] != 'windows'], [])
        self.assertEqual({k for h, d in self.devices.items() if h != WIN for k in (d.get('sysinfo') or {}).get('custom_check_results', {})} & {'ck_00005', 'ck_00006'}, set())


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

    def test_the_check_can_fail_for_each_part_the_second_half_adds(self):
        # one damaged sample for each place the second half writes to: the startup inventory and its log, the log buffer and the rules of the Logs page, the account of a scan and
        # its kernel block, the kernel report of a package list, the Windows fields of a host, and the inbox and the feed
        damaged = (
            ('persistence.json', {WIN: {'v': 'one', 'ts': 'soon', 'inv': 'none'}}),
            ('persistence.json', {WIN: {'log': 'none'}}),
            ('persistence.json', {WIN: {'inv': {'run': {'ts': 'soon', 'items': 'none'}}}}),
            ('log_watch.json', {WIN: {'units': 'none'}}),
            ('log_rules_global.json', {'rules': 'none'}),
            ('log_rules_global.json', {'rules': [{'pattern': ['x'], 'unit': 5}]}),
            ('cve_findings.json', {KERNEL_HOST: {'kernel': {'left_out': 'three', 'running': 6}}}),
            ('cve_findings.json', {KERNEL_HOST: {'covered': {'listed': 'many', 'packages': 'none'}}}),
            ('cve_findings.json', {KERNEL_HOST: {'covered': {'reasons': {'no_matcher': 'x'}}}}),
            ('packages.json', {KERNEL_HOST: {'kernel': {'release': 5, 'images': 'none'}}}),
            ('devices.json', {WIN: {'name': 'x', 'group': 'g', 'last_seen': 1, 'sysinfo': {'win_build': {'ubr': 'big'}, 'wu_search': {'at': 'soon'}, 'shares': {'items': 'x'}}}}),
            ('alerts.json', {'alerts': [{'id': ['x']}]}),
            ('fleet_events.json', {'events': [{'event': 5, 'ts': 'soon'}]}),
        )
        for name, doc in damaged:
            with contextlib.redirect_stderr(io.StringIO()):
                repaired = store_shapes.normalize(name, copy.deepcopy(doc))
            self.assertNotEqual(repaired, doc, (name, doc))
        self.assertLessEqual({name for name, _ in damaged}, set(store_shapes.SHAPES))

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
