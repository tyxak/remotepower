#!/usr/bin/env python3
"""A cadence sweep that never records "I ran" re-runs its expensive lookup forever.

Three per-request sweeps read a marker to decide whether they are due, then set
that marker at the end — but AFTER an `if not targets: return` that fires when
the install has no devices of the relevant kind. On the common install, which
has no SNMP gear, no RouterOS device and no agentless hosts, the marker was
therefore never written. The not-due gate could never fire. Each sweep loaded
the ENTIRE fleet dict on EVERY request, forever, to rediscover it had nothing
to do.

`load()` deepcopies on every call, warm or cold, so this is not a cheap re-read.
Measured on a synthetic fleet: three deepcopies of devices.json per request,
about 143 ms at 1,000 devices, on installs using none of the three features.

The bug hides well because each sweep looks correct in isolation: the not-due
gate is there, it uses `_config_ro()` to avoid a deepcopy, and there is a
comment explaining the cheap-when-not-due intent. The gate simply reads a value
that the only path an idle install ever takes never writes.

Cost of the fix: the FIRST device of that kind waits up to one interval for its
first poll — exactly the wait every subsequent poll already has.

HOW THIS WAS FOUND, since it argues for the method: not by reading code. Three
grep-based passes over these same functions reported them CLEAN, because the
not-due gate is right there in the source. It took counting actual load() calls
across a driven request to see the gate never firing.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

# sweep → the cadence marker it gates on
GATED_SWEEPS = {
    'run_agentless_reachability_if_due': 'last_agentless_ping',
    'run_routeros_update_check_if_due': 'last_routeros_update_check',
    'run_snmp_polls_if_due': 'last_snmp_poll',
}


def _body(name):
    m = re.search(r'def %s\(' % re.escape(name), _API)
    assert m, name
    tree = ast.parse(_API)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == name)
    return '\n'.join(_API.splitlines()[fn.lineno - 1:fn.end_lineno])


class TestTheNothingToDoPathRecordsThatItRan(unittest.TestCase):
    def test_the_sweeps_still_exist(self):
        """Positive control: a renamed sweep would make every assertion below
        pass against nothing."""
        for name in GATED_SWEEPS:
            with self.subTest(sweep=name):
                self.assertRegex(_API, r'def %s\(' % re.escape(name))

    def test_each_claims_its_slot_before_the_empty_return(self):
        """The load-bearing one. If the claim sits only after `if not targets:
        return`, an install with none of those devices never writes the marker
        and the sweep runs its full lookup on every request forever."""
        problems = []
        for name, marker in GATED_SWEEPS.items():
            body = _body(name)
            m = re.search(r'if not targets:\n(.*?)\n\s*return\n', body, re.S)
            if not m:
                problems.append(f'{name}: no `if not targets: return` — has the '
                                'shape changed? re-check the claim ordering')
                continue
            if f"_claim_cadence_slot('{marker}'" not in m.group(1):
                problems.append(f'{name}: returns on an empty target list without '
                                f"claiming {marker}")
        self.assertEqual(problems, [], '\n'.join([
            'These cadence sweeps do not record that they ran when there is '
            'nothing to do, so their not-due gate never fires on an install '
            'without that hardware:', *('  ' + p for p in problems)]))

    def test_each_still_claims_on_the_working_path(self):
        """Claiming only on the empty path would be the opposite bug — the
        sweep would do its work every request instead of skipping it."""
        for name, marker in GATED_SWEEPS.items():
            with self.subTest(sweep=name):
                body = _body(name)
                self.assertGreaterEqual(
                    body.count(f"_claim_cadence_slot('{marker}'"), 2,
                    f'{name} should claim {marker} on BOTH the empty path and '
                    'the working path')

    def test_the_gate_reads_the_same_marker_it_writes(self):
        """A gate reading one key and a claim writing another is the same
        never-fires bug wearing a typo."""
        for name, marker in GATED_SWEEPS.items():
            with self.subTest(sweep=name):
                body = _body(name)
                self.assertIn(f"'{marker}'", body)
                self.assertRegex(
                    body, r"_config_ro\(\)\.get\(\s*'%s'|_ro\.get\('%s'" % (marker, marker),
                    f'{name} claims {marker} but its not-due gate does not read it')

    def test_the_gate_uses_the_no_deepcopy_config_read(self):
        """The gate itself must not be what it is trying to avoid."""
        for name in GATED_SWEEPS:
            with self.subTest(sweep=name):
                body = _body(name)
                head = body[:body.find('load(DEVICES_FILE)')]
                self.assertIn('_config_ro()', head)
                self.assertNotIn('load(CONFIG_FILE)', head)


class TestTheSameDefectInTheSnmpModule(unittest.TestCase):
    """The fourth instance, in snmp_device_handlers rather than api.py — found
    by the same measurement, not by reading. if_history is opt-in per device,
    so MOST installs have no target and took the empty path every time."""

    SRC = (_ROOT / 'server' / 'cgi-bin' / 'snmp_device_handlers.py')

    def setUp(self):
        if not self.SRC.exists():
            self.skipTest('module not in this tree')
        self.src = self.SRC.read_text()

    def test_the_sweep_exists(self):
        self.assertIn('def run_snmp_if_history_if_due(', self.src)

    def test_the_empty_path_records_the_run(self):
        m = re.search(r'def run_snmp_if_history_if_due\(.*?\n(?=def |\Z)',
                      self.src, re.S)
        body = m.group(0)
        empty = re.search(r'if not targets:(.*?)\n        return\n', body, re.S)
        self.assertIsNotNone(empty, 'the empty-target return has changed shape')
        self.assertIn("st['last_run'] = now", empty.group(1),
                      'the nothing-to-walk path does not record that it ran, so '
                      'the gate above can never fire on an install without an '
                      'if_history switch')

    def test_the_marker_write_cannot_fail_the_request(self):
        """A contended write on a marker is not worth a 500 on a heartbeat."""
        m = re.search(r'if not targets:(.*?)\n        return\n', self.src, re.S)
        self.assertIn('except Exception', m.group(1))

    def test_the_working_path_still_records_it(self):
        m = re.search(r'def run_snmp_if_history_if_due\(.*?\n(?=def |\Z)',
                      self.src, re.S)
        self.assertGreaterEqual(m.group(0).count("st['last_run'] = now"), 2)


if __name__ == '__main__':
    unittest.main()
