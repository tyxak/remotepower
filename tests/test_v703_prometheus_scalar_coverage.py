#!/usr/bin/env python3
"""Every per-host number the agent sends should be scrapeable.

The exporter emitted four per-host scalars — CPU, memory, disk and pending
packages — out of roughly fifteen the agents collect and the device drawer
already renders. So an operator could alert on CPU pressure and not on swap, on
disk fullness and not on file-descriptor exhaustion, and could not draw a single
absolute figure anywhere because none of the denominators were exported: a
dashboard could say "72% of disk" and never "180 GB of 250 GB".

`custom_metrics` is the sharpest case. It exists so an operator can push a number
of their own from a host — exporting it is the entire reason to collect it — and
it reached the device drawer and stopped there.

The gate names the sysinfo keys that must have a metric, and each one that is
deliberately not exported carries its reason. Deriving the list from sysinfo
instead was tried and is wrong: sysinfo carries dozens of strings, lists and
nested structures, and a rule that demands a gauge for every one of them argues
with every honest change.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EXPORTER = _ROOT / 'server' / 'cgi-bin' / 'prometheus_export.py'
_SAMPLE = _ROOT / 'docs' / 'prometheus-metrics-sample.txt'

# sysinfo key -> the metric family that carries it.
EXPORTED = {
    'cpu_percent': 'remotepower_device_cpu_percent',
    'mem_percent': 'remotepower_device_mem_percent',
    'disk_percent': 'remotepower_device_disk_percent',
    'swap_percent': 'remotepower_device_swap_percent',
    'loadavg_1m': 'remotepower_device_loadavg_1m',
    'fd_percent': 'remotepower_device_fd_percent',
    'conntrack_percent': 'remotepower_device_conntrack_percent',
    'cpu_count': 'remotepower_device_cpu_count',
    'mem_total_mb': 'remotepower_device_memory_total_bytes',
    'disk_total_gb': 'remotepower_device_disk_total_bytes',
    'failed_units': 'remotepower_device_failed_units',
    'mount_issues': 'remotepower_device_mount_issues',
    'custom_metrics': 'remotepower_device_custom_metric',
}

# Numeric sysinfo keys with no metric of their own, and why.
#
# The five- and fifteen-minute load averages were listed here first, on the
# assumption that the agent reports all three. It reports only the one-minute
# average — the control below caught the exemption naming keys nothing sends,
# which is the same class of dead weight it exists to prevent.
NOT_EXPORTED = {
    'uptime_seconds': 'the last-seen timestamp family already answers "is this '
                      'host up and for how long", and a second gauge for it '
                      'would need the same clock skew caveat',
}


def emitted_families():
    """Family names the exporter declares, from its own HELP lines."""
    return set(re.findall(r"'# HELP (remotepower_\w+)", _EXPORTER.read_text(encoding='utf-8'))) \
        | set(re.findall(r"f'# HELP \{metric_name\}", _EXPORTER.read_text(encoding='utf-8'))) \
        | set(re.findall(r"'(remotepower_device_\w+)'", _EXPORTER.read_text(encoding='utf-8')))


def sample_families():
    if not _SAMPLE.exists():
        return set()
    return set(re.findall(r'^# HELP (remotepower_\w+)', _SAMPLE.read_text(encoding='utf-8'), re.M))


class TestEveryScalarIsExported(unittest.TestCase):

    def test_each_named_key_has_its_family_in_the_exporter(self):
        emitted = emitted_families()
        missing = sorted(f'{k} -> {v}' for k, v in EXPORTED.items()
                         if v not in emitted)
        self.assertEqual(
            missing, [],
            'these sysinfo values are collected, stored and shown in the UI, '
            f'and no Prometheus family carries them: {missing}')

    def test_each_family_reaches_the_documented_sample(self):
        """The sample is what an operator reads to find out what exists. A
        family missing from it is a family nobody knows to scrape."""
        sample = sample_families()
        if not sample:
            self.skipTest('sample excluded from this tree')
        missing = sorted(v for v in EXPORTED.values() if v not in sample)
        self.assertEqual(
            missing, [],
            'emitted but undocumented — regenerate with '
            f'python3 tools/gen-prometheus-sample.py: {missing}')

    def test_the_denominators_are_bytes_not_the_agents_units(self):
        """The agent reports megabytes and gigabytes; Prometheus convention is
        base units, and a dashboard that divides a percentage by a megabyte
        figure gets the wrong answer silently."""
        src = _EXPORTER.read_text(encoding='utf-8')
        self.assertIn('remotepower_device_memory_total_bytes', src)
        self.assertIn('1024 * 1024', src)
        self.assertIn('1024 ** 3', src)


class TestTheListIsHonest(unittest.TestCase):

    def test_the_family_scan_finds_the_old_families_too(self):
        """Control: if the scan returned nothing, every check above would pass
        for exactly the wrong reason."""
        emitted = emitted_families()
        self.assertGreater(len(emitted), 10, sorted(emitted))
        for known in ('remotepower_device_cpu_percent',
                      'remotepower_device_disk_percent'):
            self.assertIn(known, emitted)

    def test_every_deliberate_omission_names_a_real_sysinfo_key(self):
        """A reason for a key nothing sends is dead weight."""
        agent = (_ROOT / 'client' / 'remotepower-agent.py').read_text(encoding='utf-8')
        stale = sorted(k for k in NOT_EXPORTED if f"'{k}'" not in agent)
        self.assertEqual(stale, [],
                         f'omission recorded for a key the agent never sends: {stale}')


if __name__ == '__main__':
    unittest.main()
