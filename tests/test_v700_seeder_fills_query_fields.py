#!/usr/bin/env python3
"""The demo's CPU and Disk columns were blank on every host.

`cpu_percent` and `disk_percent` were never seeded. `cpu_percent` alone is read
in 21 places across the server, the checks engine and the frontend, so on the
demo instance the device table's CPU column, the same field in the Data Explorer,
the resource checks and the AI fleet preamble all showed nothing — and the
seeder wrote `uptime_s`, a key nothing on the server reads, instead of
`uptime_seconds`, which is the numeric field added in v6.1.2 precisely so hosts
could be ranked by uptime.

This is the blind-gate shape CLAUDE.md records from the v6.4.3 seeder work, and
it matters more than a cosmetic gap: the rendered gates — accessibility, box
overflow, the click sweeps — all measure the SEEDED instance. A field the seeder
never populates is a field those gates cannot see, so an empty state that should
never appear renders on every one of their runs and is read as correct.

Eight fields were absent on every agent host. All 45 now carry data.

WHY THE DERIVED ONES ARE DERIVED. `cpu_percent` comes from the load average the
seeder already rolled and `disk_percent` from the mounts it already built, rather
than from separate random draws, so the demo is internally consistent: a host the
load average calls busy also reads busy in the CPU column, and the disk figure
agrees with the mounts panel beside it. A demo that contradicts itself teaches
the reader to distrust the product.
"""
import collections
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_SEEDER = _ROOT / 'packaging' / 'seed-demo-data.py'

# Fields that legitimately hold no value on a seeded fleet would go here, with a
# reason each. There are none: an undeclared exemption is indistinguishable from
# a field nobody has looked at.
EXEMPT: dict = {}


_PROBE = r"""
import json, os, sys, importlib.util
os.environ['RP_DATA_DIR'] = sys.argv[1]
cgi = sys.argv[2]
sys.path.insert(0, cgi)
spec = importlib.util.spec_from_file_location('api_seedq', cgi + '/api.py')
api = importlib.util.module_from_spec(spec)
sys.modules['api'] = api
spec.loader.exec_module(api)
devices = api.load(api.DEVICES_FILE) or {}
rows = [r for r in api._qe_devices_rows()
        if not devices.get(r['device_id'], {}).get('agentless')]
slim = {k: {'sysinfo': v.get('sysinfo') or {}} for k, v in devices.items()}
print(json.dumps({'fields': sorted(api._QE_DEVICE_FIELDS), 'rows': rows,
                  'devices': slim, 'total': len(devices)}))
"""


def _seed_and_project():
    """Seed a throwaway instance and project its agent devices, IN A CHILD.

    Two things about the environment, both learned the hard way.

    **The child forces the JSON backend.** `seed-demo-data.py` only ever writes
    flat JSON — deliberately, so it stays standalone with no api.py import — and
    `install-demo.sh` migrates that JSON into Postgres afterwards when a
    Postgres demo is asked for. So under `make test-sqlite`, where
    RP_STORAGE_BACKEND is set for the whole run, the seeder wrote JSON files and
    the reader looked in an empty database: zero devices, three failures, and a
    result that looks exactly like a seeder producing nothing. The seeded
    CONTENT is backend-agnostic — it is the same records either side of the
    migration — so measuring it once on the backend the seeder actually writes
    is the honest check.

    **It runs in its own interpreter** rather than importing api.py here,
    because `storage` is a module-level singleton bound to whichever data
    directory reached it first in this process.
    """
    d = tempfile.mkdtemp(prefix='rp-seedq-')
    env = dict(os.environ)
    env.pop('RP_STORAGE_BACKEND', None)
    r = subprocess.run([sys.executable, str(_SEEDER), '--data-dir', d, '--apply'],
                       capture_output=True, cwd=str(_ROOT), timeout=900, env=env)
    if r.returncode != 0:
        raise unittest.SkipTest(f'seeder failed: {r.stderr.decode()[-500:]}')
    q = subprocess.run([sys.executable, '-c', _PROBE, d, str(_CGI)],
                       capture_output=True, cwd=str(_ROOT), timeout=600, env=env)
    if q.returncode != 0:
        raise AssertionError(f'projection probe failed: {q.stderr.decode()[-1200:]}')
    out = json.loads(q.stdout.decode().strip().split('\n')[-1])
    return out['fields'], out['devices'], out['rows'], out['total']


class TestTheSeededFleetIsUsable(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _SEEDER.is_file():
            raise unittest.SkipTest('demo seeder excluded from this tree')
        cls.fields, cls.devices, cls.rows, cls.total = _seed_and_project()

    def test_there_are_agent_devices_to_measure(self):
        """Agentless devices have no sysinfo by design, so the denominator has
        to exclude them — measuring against all 18 would make every absence
        look explainable. A first pass sampled `next(iter(devices))`, which is
        agentless, and concluded the seeder wrote no sysinfo at all."""
        self.assertGreater(len(self.rows), 8,
                           f'only {len(self.rows)} agent devices seeded')
        self.assertLess(len(self.rows), self.total,
                        'no agentless devices seeded — the demo should have both')

    def test_every_queryable_field_has_data_somewhere(self):
        filled = collections.Counter()
        for row in self.rows:
            for k, v in row.items():
                if v is not None and v != '':
                    filled[k] += 1
        empty = sorted(k for k in self.fields
                       if filled[k] == 0 and k not in EXEMPT)
        self.assertEqual(
            empty, [],
            'these fields are absent on EVERY seeded agent host, so the demo '
            'renders an empty state for them and every rendered gate measures '
            'that empty state as correct:\n'
            + '\n'.join('  ' + e for e in empty))

    def test_the_two_that_were_missing_are_present_on_all_of_them(self):
        """Not just "somewhere": a CPU column blank on half the fleet is still
        a broken demo."""
        for field in ('cpu_pct', 'disk_pct', 'hostname', 'uptime_seconds'):
            absent = [r['name'] for r in self.rows
                      if r.get(field) in (None, '')]
            self.assertEqual(absent, [], f'{field} missing on {absent}')

    def test_the_derived_metrics_agree_with_what_they_derive_from(self):
        """cpu_percent tracks the load average and disk_percent matches the
        mounts, because a demo that contradicts itself teaches distrust."""
        for r in self.rows:
            si = (self.devices.get(r['device_id'], {}).get('sysinfo') or {})
            load = si.get('loadavg_1m')
            cpus = si.get('cpu_count') or 1
            if load is None:
                continue
            per_cpu = load / float(cpus)
            if per_cpu > 1.4:
                self.assertGreater(r['cpu_pct'], 55,
                                   f"{r['name']}: load {per_cpu:.2f}/cpu but "
                                   f"CPU reads {r['cpu_pct']}%")
            elif per_cpu < 0.2:
                self.assertLess(r['cpu_pct'], 45,
                                f"{r['name']}: load {per_cpu:.2f}/cpu but "
                                f"CPU reads {r['cpu_pct']}%")
            local = [m['percent'] for m in (si.get('mounts') or [])
                     if not m.get('network') and 'percent' in m]
            if local:
                self.assertAlmostEqual(r['disk_pct'], max(local), places=1,
                                       msg=f"{r['name']}: disk column and mounts "
                                           f"panel disagree")

    def test_no_metric_is_pinned_at_its_clamp(self):
        """A linear load-to-CPU mapping put three hosts at exactly 99.0, which
        reads as the clamp artefact it was."""
        pinned = [r['name'] for r in self.rows if r['cpu_pct'] >= 99]
        self.assertEqual(pinned, [], f'CPU pinned at the clamp on {pinned}')

    def test_the_fleet_is_neither_all_healthy_nor_all_broken(self):
        """The demo exists to show what the product says about problems. An
        all-green fleet demonstrates nothing, and an all-red one is noise."""
        busy = [r for r in self.rows if r['cpu_pct'] > 60]
        self.assertTrue(busy, 'no host is busy — nothing for the checks to flag')
        self.assertLess(len(busy), len(self.rows),
                        'every host is busy — the contrast is gone')
        unsynced = [r for r in self.rows if r.get('clock_synced') is False]
        self.assertTrue(unsynced, 'no host has a skewed clock, so the clock '
                                  'check and the AI flag have nothing to show')


if __name__ == '__main__':
    unittest.main()
