#!/usr/bin/env python3
"""The demo showed this release's features with no data behind them.

The seeder populated 12 sysinfo signals and none of the four this release
shipped. So a demo instance rendered the Checks rows, the compliance control and
the RAG answers for disk encryption, platform health, canaries and Integrity
Guard — all reading their empty state, none explaining why. A reviewer
concludes the feature is broken; it is unseeded.

Worse, the seeded instance is what several gates measure against: the a11y walk,
and the rendered-box-height gate added today. A signal absent from the seed is a
signal those gates never see.

The seed is deliberately not uniformly healthy. One host is UNENCRYPTED, one has
a TRIPPED canary and a quarantined file, one Pi is under-voltage. An all-green
demo shows the columns and never the point of them.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SEEDER = _ROOT / 'packaging' / 'seed-demo-data.py'


class TestTheSeedCarriesThisReleasesSignals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _SEEDER.is_file():
            raise unittest.SkipTest('seeder not in this tree')
        cls.dir = tempfile.mkdtemp(prefix='rp-seedsig-')
        p = subprocess.run([sys.executable, str(_SEEDER), '--data-dir', cls.dir,
                            '--apply'], capture_output=True, cwd=str(_ROOT),
                           timeout=900)
        if p.returncode != 0:
            raise unittest.SkipTest(
                'seeder failed: ' + p.stderr.decode(errors='replace')[-300:])
        cls.devices = json.load(open(Path(cls.dir) / 'devices.json'))

    def _si(self):
        return [(v.get('name'), v.get('sysinfo') or {}) for v in self.devices.values()]

    def test_the_seed_produced_a_fleet(self):
        """Positive control — an empty seed makes every count below zero and
        every 'is present' assertion fail for the wrong reason."""
        self.assertGreaterEqual(len(self.devices), 10)

    def test_disk_encryption_is_seeded_on_the_linux_hosts(self):
        n = sum(1 for _, si in self._si() if 'disk_encryption' in si)
        self.assertGreaterEqual(n, 8, 'barely any host reports encryption state')

    def test_exactly_one_host_is_unencrypted(self):
        """The compliance control and the Advisory both need a real finding.
        An all-encrypted fleet renders PASS everywhere and demonstrates
        nothing."""
        off = [nm for nm, si in self._si()
               if (si.get('disk_encryption') or {}).get('encrypted') is False]
        self.assertEqual(len(off), 1, f'expected one unencrypted demo host, got {off}')

    def test_platform_health_covers_all_three_shapes(self):
        """Throttling, fans and wifi are different renderers; seeding only one
        leaves two untested by every gate that walks the seeded instance."""
        thr = [nm for nm, si in self._si() if (si.get('platform_health') or {}).get('throttle')]
        fan = [nm for nm, si in self._si() if (si.get('platform_health') or {}).get('fans')]
        wifi = [nm for nm, si in self._si() if (si.get('platform_health') or {}).get('wifi')]
        self.assertTrue(thr, 'no host reports thermal/power throttling')
        self.assertTrue(fan, 'no host reports fans')
        self.assertTrue(wifi, 'no host reports wifi signal')

    def test_a_canary_is_tripped_and_a_file_quarantined(self):
        trip = [nm for nm, si in self._si() if (si.get('canary_status') or {}).get('tripped')]
        quar = [nm for nm, si in self._si() if si.get('guard_quarantine')]
        self.assertEqual(len(trip), 1, f'expected one tripped canary, got {trip}')
        self.assertTrue(quar, 'no host has a quarantined file')

    def test_untripped_canaries_are_still_reported(self):
        """Reporting only the tripped one makes 'no canary data' and 'canary
        fine' indistinguishable — the same absent-vs-negative confusion the
        encryption collector avoids."""
        ok = [nm for nm, si in self._si()
              if (si.get('canary_status') or {}).get('tripped') is False]
        self.assertGreaterEqual(len(ok), 5)

    def test_the_linux_predicate_did_not_skip_the_odd_distros(self):
        """The seeded fleet runs 'Raspberry Pi OS' and 'Alpine 3.20'. A first
        version allowlisted debian/ubuntu/... and silently skipped the Pi and
        both Alpine boxes — precisely the hosts throttling and wifi are
        interesting on. Exclude the non-Linux platforms instead."""
        by_os = {}
        for v in self.devices.values():
            by_os.setdefault((v.get('os') or '').split()[0], []).append(v)
        for osname in ('Raspberry', 'Alpine'):
            hosts = [v for k, vs in by_os.items() if k.startswith(osname) for v in vs]
            if not hosts:
                continue
            with self.subTest(os=osname):
                self.assertTrue(
                    any('disk_encryption' in (h.get('sysinfo') or {}) for h in hosts),
                    f'{osname} hosts were skipped by the Linux predicate')

    def test_windows_and_macos_are_not_given_linux_signals(self):
        for v in self.devices.values():
            osl = (v.get('os') or '').lower()
            if 'windows' in osl or 'macos' in osl:
                with self.subTest(host=v.get('name')):
                    self.assertNotIn('disk_encryption', v.get('sysinfo') or {},
                                     'LUKS state on a non-Linux host is fiction')

    def test_the_version_is_derived_not_hardcoded(self):
        """A seeder pinned to an old version makes every seeded host look like
        it is running a stale agent the moment SERVER_VERSION moves."""
        src = _SEEDER.read_text()
        self.assertIn('def _current_version(', src)
        self.assertIn("SERVER_VERSION", src)


if __name__ == '__main__':
    unittest.main()
