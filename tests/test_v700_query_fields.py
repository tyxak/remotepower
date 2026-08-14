#!/usr/bin/env python3
"""The Data Explorer could only ask about fourteen things.

`_qe_devices_rows()` projected 14 fields, four of them from sysinfo, against
the 105 keys `safe_si` persists. So the richest question an operator could put
to the Data Explorer was "which hosts are above 80% CPU". Whether a host's
disks are encrypted, whether its firewall is up, whether sshd still permits
root, whether automatic updates are on, when it was last seen, whether it is
online at all — collected, alerted on, rendered in a drawer, and not queryable.

That is a distinct shape from the dead-signal class. Nothing was broken and
nothing was dropped: the signal reaches several surfaces. It just never reached
the one surface whose entire purpose is asking arbitrary questions, and a fleet
tool where you cannot ask "which of my hosts have unencrypted disks" is missing
the question people actually have.

WHAT THIS PINS

* The projection and the exposed-field tuple agree in BOTH directions. The
  engine only exposes what `_QE_DEVICE_FIELDS` names, so a key added to the
  projection alone is invisible, and a name in the tuple with nothing behind it
  is a field that always reads empty. Both are silent.
* Every field is a SCALAR. The predicate engine compares numbers, strings and
  booleans; a nested dict would give the operator a field whose only working
  operator is `exists`.
* Reporting and not-reporting stay distinguishable. `disk_encrypted` is
  tri-state — False means "reported, and it is off", None means "never told
  us". Collapsing those is how a host that has never reported lands in a list
  of findings it does not belong in, which is the same mistake the
  encryption-at-rest compliance control made on Linux.
* The query path actually RUNS over the new fields, rather than the fields
  merely existing in a tuple.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-qef-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_qef', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import query_engine  # noqa: E402

# A device carrying every composite shape safe_si persists, in the shape it
# really persists them: battery is a LIST, the rest are dicts, ssh_config holds
# strings. Guessing these wrong is how a fixture makes every assertion vacuous.
_FULL_SI = {
    'hostname': 'web01.lab', 'kernel': '6.9.3-arch1-1', 'chassis': 'laptop',
    'uptime_seconds': 864000, 'loadavg_1m': 1.25, 'cpu_count': 8,
    'mem_total_mb': 16384, 'disk_total_gb': 512,
    'cpu_percent': 42, 'mem_percent': 61, 'disk_percent': 77, 'swap_percent': 3,
    'fd_percent': 12, 'conntrack_percent': 4,
    'failed_units': ['a.service', 'b.service'],
    'mount_issues': ['/srv'],
    'guard_quarantine': [{'path': '/tmp/x'}],
    'listening_ports': [{'port': 22}, {'port': 443}],
    'disk_encryption': {'encrypted': True, 'crypt_count': 2, 'dm_count': 3},
    'firewall': {'backends': [{'name': 'nftables', 'present': True,
                               'active': True, 'rules': 40}]},
    'autoupdate': {'enabled': False, 'mechanism': 'unattended-upgrades'},
    'ssh_config': {'permit_root_login': 'no', 'password_authentication': 'yes',
                   'permit_empty_passwords': 'no', 'x11_forwarding': 'yes',
                   'source': '/etc/ssh/sshd_config'},
    'secure_boot': True,
    'clock': {'synced': True, 'offset_ms': 12.5},
    'battery': [{'name': 'BAT0', 'percent': 88, 'health_pct': 71,
                 'status': 'Discharging'}],
    'audit_mode': True,
    'psutil': False,
    'reboot_required': True,
}


class TestTheTwoHalvesAgree(unittest.TestCase):

    def test_the_projection_is_not_trivially_small(self):
        """Positive control: if the projection collapsed, every set comparison
        below would still pass."""
        row = api._qe_device_posture(_FULL_SI)
        self.assertGreater(len(row), 25, f'posture returned {len(row)} fields')

    def test_every_exposed_field_exists_in_a_row(self):
        rows = [dict(api._qe_device_posture(_FULL_SI),
                     device_id='d1', name='web01', group='', site='', os='linux',
                     agent_version='7.0.0', monitored=True, agentless=False,
                     reboot_required=True, cpu_pct=1, mem_pct=1, disk_pct=1,
                     swap_pct=1, tags='', last_seen=1, online=True)]
        missing = sorted(k for k in api._QE_DEVICE_FIELDS if k not in rows[0])
        self.assertEqual(
            missing, [],
            'these names are exposed as queryable fields but no row carries '
            'them, so every query against them reads empty:\n'
            + '\n'.join('  ' + m for m in missing))

    def test_every_posture_field_is_exposed(self):
        extra = sorted(set(api._qe_device_posture(_FULL_SI))
                       - set(api._QE_DEVICE_FIELDS))
        self.assertEqual(
            extra, [],
            'these fields are computed for every device on every query and '
            'then not exposed, so the work is done and discarded:\n'
            + '\n'.join('  ' + e for e in extra))


class TestEveryFieldIsQueryable(unittest.TestCase):

    def test_no_field_is_a_container(self):
        """The engine compares scalars. A dict or list here is a field whose
        only useful operator is `exists`."""
        bad = {k: type(v).__name__
               for k, v in api._qe_device_posture(_FULL_SI).items()
               if isinstance(v, (dict, list, tuple, set))}
        self.assertEqual(bad, {}, f'non-scalar queryable fields: {bad}')

    def test_the_composite_signals_reduced_to_the_real_question(self):
        r = api._qe_device_posture(_FULL_SI)
        self.assertIs(r['disk_encrypted'], True)
        self.assertIs(r['firewall_active'], True)
        self.assertIs(r['autoupdate_enabled'], False)
        self.assertEqual(r['ssh_password_auth'], 'yes')
        self.assertEqual(r['failed_units'], 2)
        self.assertEqual(r['quarantined_files'], 1)
        self.assertEqual(r['battery_pct'], 88)
        self.assertIs(r['metrics_limited'], True)

    def test_a_predicate_runs_over_a_new_field(self):
        """The tuple existing is not the point; the query working is."""
        rows = [dict(api._qe_device_posture(_FULL_SI), device_id='d1'),
                dict(api._qe_device_posture(
                    dict(_FULL_SI, disk_encryption={'encrypted': False})),
                    device_id='d2')]
        pred = {'field': 'disk_encrypted', 'op': 'eq', 'value': False}
        # Validation first: handle_query validates before running, so a field
        # the validator rejects is unreachable however good the projection is.
        # It signals by RAISING, not by returning a pair.
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        keep = query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)
        self.assertEqual([r['device_id'] for r in keep], ['d2'])

    def test_a_numeric_predicate_runs_over_a_new_field(self):
        rows = [dict(api._qe_device_posture(_FULL_SI), device_id='d1'),
                dict(api._qe_device_posture(dict(_FULL_SI, uptime_seconds=60)),
                     device_id='d2')]
        pred = {'field': 'uptime_seconds', 'op': 'gt', 'value': 3600}
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        self.assertEqual(
            [r['device_id'] for r in
             query_engine.run(rows, pred, api._QE_DEVICE_FIELDS)], ['d1'])


class TestNotReportingIsNotTheSameAsOff(unittest.TestCase):
    """The distinction the encryption-at-rest compliance control got wrong: a
    host that never reported is not a host that reported bad news."""

    def test_a_silent_host_is_none_not_false(self):
        r = api._qe_device_posture({})
        for f in ('disk_encrypted', 'firewall_active', 'autoupdate_enabled',
                  'secure_boot', 'clock_synced'):
            self.assertIsNone(r[f], f'{f} should be None for a silent host')

    def test_a_reporting_host_that_is_off_is_false(self):
        r = api._qe_device_posture({
            'disk_encryption': {'encrypted': False},
            'firewall': {'backends': [{'name': 'ufw', 'active': False}]},
            'autoupdate': {'enabled': False, 'mechanism': ''},
            'secure_boot': False,
            'clock': {'synced': False},
        })
        for f in ('disk_encrypted', 'firewall_active', 'autoupdate_enabled',
                  'secure_boot', 'clock_synced'):
            self.assertIs(r[f], False, f'{f} should be False, not None')

    def test_an_empty_sysinfo_yields_no_exception(self):
        """Every device row runs through this, including agentless ones that
        have no sysinfo at all."""
        r = api._qe_device_posture({})
        self.assertEqual(r['failed_units'], 0)
        self.assertEqual(r['hostname'], '')
        self.assertIsNone(r['uptime_seconds'])


if __name__ == '__main__':
    unittest.main()
