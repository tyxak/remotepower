#!/usr/bin/env python3
"""The AI advisor's always-on context was an inventory with no health in it.

`build_fleet_context()` builds the preamble every AI call carries. Per host it
emitted name, OS, package manager, online/offline, group, agentless, operator
notes and tags — and nothing about the host's state. The fleet rollup line
carried two counts: offline, and needs-reboot.

So an advisor asked "what should I fix first" started from a list of machines
and no idea which were in trouble. Posture reached the model only when RAG
retrieval happened to fire and happened to retrieve the right document, which
is a different question from "does the model know this host is out of disk".

WHY FLAGS ONLY WHEN NOTABLE, and why that is the load-bearing design choice:
the preamble is on EVERY call, so a per-device health block would be a
permanent token cost on every fleet, most of which are fine most of the time. A
healthy host therefore contributes zero extra characters and a host in trouble
spends tokens on exactly the conditions worth attending to. The thresholds match
the ones the product already alerts on, so the model never sees a "problem" the
operator's own pages call fine.

WHAT THIS PINS

* A healthy host's line is unchanged — the regression that would make this
  feature expensive rather than useful.
* A host in trouble names its conditions, and the per-host flag count is CAPPED:
  one very sick machine must not crowd out the other seventy-nine.
* The rollup counts appear.
* Every flag reads off a key `safe_si` actually persists, in the shape it
  persists it. A flag keyed on a field that never arrives is a feature that can
  never fire, which is the failure mode this whole class of work exists to
  close.
"""
import importlib.util
import time
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('ai_ctx_v700', _CGI / 'ai_context.py')
ctx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctx)

_NOW = 1_760_000_000


def _dev(name, **si):
    return {'name': name, 'os': 'Debian GNU/Linux 13 (trixie)',
            'last_seen': _NOW, 'sysinfo': si}


class TestAHealthyHostCostsNothing(unittest.TestCase):
    """If this regresses, the feature becomes a permanent token tax on every
    fleet that is fine."""

    def test_no_flags_on_a_healthy_host(self):
        self.assertEqual(ctx._device_flags(_dev('ok01', cpu_percent=4,
                                                mem_percent=30,
                                                disk_percent=41)), [])

    def test_the_line_carries_no_marker(self):
        line = ctx._device_one_liner(_dev('ok01', cpu_percent=4), now=_NOW)
        self.assertNotIn('!!', line)
        self.assertLess(len(line), 60, line)

    def test_a_device_with_no_sysinfo_at_all_is_fine(self):
        """Agentless hosts have none, and this runs over every device."""
        self.assertEqual(ctx._device_flags({'name': 'sw01'}), [])
        self.assertEqual(ctx._device_flags({'name': 'sw01', 'sysinfo': {}}), [])


class TestAHostInTroubleSaysSo(unittest.TestCase):

    def test_each_condition_is_named(self):
        cases = [
            (dict(cpu_percent=97), 'cpu 97%'),
            (dict(mem_percent=94), 'mem 94%'),
            (dict(disk_percent=99), 'disk 99%'),
            (dict(reboot_required=True), 'reboot pending'),
            (dict(failed_units=['a.service']), '1 failed unit'),
            (dict(failed_units=['a.service', 'b.service']), '2 failed units'),
            (dict(mount_issues=['/srv']), 'mount issues'),
            (dict(firewall={'backends': [{'name': 'ufw', 'active': False}]}),
             'firewall off'),
            (dict(disk_encryption={'encrypted': False}), 'disks unencrypted'),
            (dict(clock={'synced': False}), 'clock unsynced'),
            (dict(guard_quarantine=[{'path': '/tmp/x'}]), 'quarantined files'),
            (dict(psutil=False), 'limited metrics'),
        ]
        for si, expect in cases:
            self.assertIn(expect, ctx._device_flags(_dev('h', **si)),
                          f'{si} did not produce {expect!r}')

    def test_a_below_threshold_value_is_not_a_flag(self):
        """Positive control for the thresholds: without this the assertions
        above would also pass if every host were flagged."""
        for si in (dict(cpu_percent=89), dict(mem_percent=50),
                   dict(disk_percent=10)):
            self.assertEqual(ctx._device_flags(_dev('h', **si)), [], si)

    def test_a_healthy_composite_is_not_a_flag(self):
        self.assertEqual(ctx._device_flags(_dev(
            'h', firewall={'backends': [{'name': 'nft', 'active': True}]},
            disk_encryption={'encrypted': True}, clock={'synced': True},
            psutil=True)), [])

    def test_a_silent_composite_is_not_a_flag(self):
        """Not-reported must not read as bad — the mistake the encryption-at-rest
        compliance control made on Linux."""
        self.assertEqual(ctx._device_flags(_dev(
            'h', firewall={}, disk_encryption={}, clock={})), [])

    def test_the_flag_count_is_capped(self):
        many = ctx._device_flags(_dev(
            'h', cpu_percent=99, mem_percent=99, disk_percent=99,
            reboot_required=True, failed_units=['a', 'b'], mount_issues=['/x'],
            firewall={'backends': [{'active': False}]},
            disk_encryption={'encrypted': False}, clock={'synced': False},
            guard_quarantine=[{}], psutil=False))
        self.assertEqual(len(many), ctx._MAX_FLAGS_PER_DEVICE)
        self.assertLessEqual(ctx._MAX_FLAGS_PER_DEVICE, 6,
                             'the cap is what stops one sick host crowding out '
                             'the rest of the fleet')

    def test_the_line_puts_identity_before_problems(self):
        line = ctx._device_one_liner(_dev('bad01', cpu_percent=97), now=_NOW)
        self.assertLess(line.index('bad01'), line.index('!!'))


class TestTheRollupCounts(unittest.TestCase):

    def test_it_names_the_notable_hosts(self):
        out = ctx.build_fleet_context(
            [_dev('ok01', cpu_percent=3),
             _dev('bad01', disk_percent=97, failed_units=['a.service'])],
            now=_NOW, ttl=300)
        head = out.split('\n', 1)[0]
        self.assertIn('1 with failed units', head)
        self.assertIn('1 with notable conditions', head)

    def test_a_healthy_fleet_rollup_stays_quiet(self):
        head = ctx.build_fleet_context(
            [_dev('ok01', cpu_percent=3), _dev('ok02', cpu_percent=5)],
            now=_NOW, ttl=300).split('\n', 1)[0]
        self.assertNotIn('notable', head)
        self.assertNotIn('failed units', head)


class TestEveryFlagReadsARealField(unittest.TestCase):
    """A flag keyed on a field the agents never send can never fire, and looks
    exactly like a feature."""

    def test_the_keys_are_ones_safe_si_persists(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_v643_sysinfo_whitelist_parity as W
        persisted = W._safe_si_persisted()
        for key in ('cpu_percent', 'mem_percent', 'disk_percent',
                    'reboot_required', 'failed_units', 'mount_issues',
                    'firewall', 'disk_encryption', 'clock', 'guard_quarantine',
                    'psutil'):
            self.assertIn(key, persisted,
                          f'{key} is read by a flag but safe_si does not '
                          f'persist it, so the flag can never fire')


if __name__ == '__main__':
    unittest.main()
