#!/usr/bin/env python3
"""The demo seeder is a PRODUCER under contract, and it was breaking it.

Every rendered gate in this suite measures the seeded instance — the a11y sweep,
the box-overflow checks, the icon-gap harness, the click sweep. So a seeder that
writes a signal in a shape no agent produces does not just make one card look
wrong: it makes those gates measure something the product never emits, and an
empty card reads as "nothing to show" rather than "wrong shape".

Eight signals were doing exactly that:

  canary_status   a dict, where the agent sends a LIST of per-path arm records
  guard_quarantine   path/at, where the ledger uses id/orig/check/ts
  zram            a bool, where the agent sends a list of per-device stats
  platform_health.throttle   a `status` string, where the agent sends bit flags
  platform_health.wifi   one dict, where the agent sends a list of interfaces
  crypt_devices   bare strings, where the agent sends {dm, name, type}
  mem_total_gb / loadavg_5m / loadavg_15m   fields no agent has ever sent
  win_posture.firewall_enabled   not the Windows agent's key

The sanitizer dropped or blanked all of them, so two security surfaces, the
platform-health rows and a memory column rendered nothing in the demo, and no
gate could see it. The seeder even carried a comment saying its "field names and
record shapes match what the agents send" — true of the fields it was written
for, false of these.

The instrument here is the fix: push every seeded sysinfo through the REAL
heartbeat and compare what comes back out. Nothing is asserted about any
particular field, so a signal added next year is covered the day it is seeded.
"""
import collections
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702seed-'))
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702seed', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _shape(o, prefix=''):
    """{path: python type name} for every key, so a TYPE change is visible.

    A dict-where-a-list-was-expected is the failure this file exists for, and
    comparing key sets alone would miss it.
    """
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            p = f'{prefix}.{k}' if prefix else k
            out[p] = type(v).__name__
            if isinstance(v, dict):
                out.update(_shape(v, p))
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                out.update(_shape(v[0], p + '[]'))
    return out


def _empty(o, path):
    """Whether the seeded value at `path` was an empty container.

    The sanitizer omits empty lists and dicts on purpose — an unencrypted host
    has no crypt devices — so an empty value going missing is correct.
    """
    cur = o
    for seg in path.split('.'):
        seg = seg.replace('[]', '')
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict):
            return False
        cur = cur.get(seg)
    return cur == [] or cur == {} or cur is None


class TestEverySeededSignalSurvivesTheHeartbeat(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.seed_dir = tempfile.mkdtemp(prefix='rp-v702-seeded-')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.exists():
            raise unittest.SkipTest('seeder excluded from dist tree')
        r = subprocess.run([sys.executable, str(seeder), '--data-dir',
                            cls.seed_dir, '--apply', '--quiet'],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise AssertionError(f'seeder failed: {r.stderr[-800:]}')
        cls.devices = json.loads(
            (Path(cls.seed_dir) / 'devices.json').read_text())

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-v702-hb-'))
        self._saved = {n: getattr(api, n) for n in
                       ('DEVICES_FILE', 'CONFIG_FILE', 'CMDS_FILE',
                        'ALERTS_FILE', 'FLEET_EVENTS_FILE')}
        for n in self._saved:
        # The BASENAME is the storage key. Under SQLite/Postgres the backend
        # selects its table from it, so a synthesised name like
        # 'devices_file.json' is not the devices store — every heartbeat 403'd
        # on the JSON-backend-only spelling. Keep the product's own filename.
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'get_json_obj', 'get_json_body',
                      'audit_log', 'log_command', 'fire_webhook',
                      '_get_client_ip', '_env')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: 'POST'
        for n in ('audit_log', 'log_command', 'fire_webhook'):
            setattr(api, n, lambda *a, **k: None)
        api._get_client_ip = lambda: '127.0.0.1'
        api._env = lambda k, dflt='': dflt
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in list(self._saved.items()) + list(self._fns.items()):
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _round_trip(self, dev_id, sysinfo):
        """Seeded sysinfo in, persisted sysinfo out — the real handler."""
        api.save(api.DEVICES_FILE, {dev_id: {'name': dev_id,
                                             'token': 'tok-' + dev_id}})
        api._LOAD_CACHE.clear()
        api.get_json_obj = api.get_json_body = lambda: {
            'device_id': dev_id, 'token': 'tok-' + dev_id,
            'sysinfo': sysinfo, 'hostname': 'h', 'os': 'linux'}
        self.cap.clear()
        try:
            api.handle_heartbeat()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 200,
                         f'{dev_id}: the heartbeat refused the seeded payload')
        api._LOAD_CACHE.clear()
        return (((api.load(api.DEVICES_FILE) or {}).get(dev_id) or {})
                .get('sysinfo') or {})

    def test_the_fixture_is_worth_measuring(self):
        """A positive control. If the seeder stopped writing sysinfo, every
        assertion below would pass over an empty set."""
        with_si = [d for d in self.devices.values()
                   if isinstance((d or {}).get('sysinfo'), dict)]
        self.assertGreaterEqual(len(with_si), 10,
                                'too few seeded devices carry sysinfo')
        keys = set()
        for d in with_si:
            keys |= set(_shape(d['sysinfo']))
        # A floor against a broken instrument, not a coverage target — it
        # sits well under the ~145 paths seeded today so that removing an
        # invented field does not fail this.
        self.assertGreater(len(keys), 100,
                           f'only {len(keys)} sysinfo paths seeded — the '
                           f'sweep would prove almost nothing')

    def test_no_seeded_signal_is_dropped(self):
        dropped = collections.Counter()
        for dev_id, dev in self.devices.items():
            si = (dev or {}).get('sysinfo')
            if not isinstance(si, dict):
                continue
            before, after = _shape(si), _shape(self._round_trip(dev_id, si))
            for path, kind in before.items():
                if path not in after and not _empty(si, path):
                    dropped[f'{path} ({kind})'] += 1
        self.assertEqual(
            dict(dropped), {},
            'the sanitizer dropped these seeded signals — either the seeder '
            'invented a shape no agent sends, or the sanitizer is missing a '
            'field it should persist. Both are real; check the agent first:\n  '
            + '\n  '.join(f'{c}x {k}' for k, c in dropped.most_common()))

    def test_no_seeded_signal_changes_type(self):
        """Except int → float, which the sanitizer does on purpose to keep
        arithmetic honest."""
        retyped = collections.Counter()
        for dev_id, dev in self.devices.items():
            si = (dev or {}).get('sysinfo')
            if not isinstance(si, dict):
                continue
            before, after = _shape(si), _shape(self._round_trip(dev_id, si))
            for path, kind in before.items():
                got = after.get(path)
                if got is None or got == kind:
                    continue
                if (kind, got) == ('int', 'float'):
                    continue
                retyped[f'{path}: {kind} -> {got}'] += 1
        self.assertEqual(dict(retyped), {},
                         'the sanitizer changed these seeded types:\n  '
                         + '\n  '.join(f'{c}x {k}'
                                       for k, c in retyped.most_common()))


if __name__ == '__main__':
    unittest.main()
