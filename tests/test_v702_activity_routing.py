#!/usr/bin/env python3
"""Nineteen per-host alerts opened the KMIP key-server page.

`_homeActivityAttrs(event, devId)` decides where a click on the dashboard
activity feed goes. Its switch groups events by destination — bare `case` labels
sharing one `return`. At v6.4.1 the two KMIP certificate events were appended to
the END of the per-host group, and they brought the only `return` with them. So
every label above them fell through it:

  disk_predict_fail, resource_saturation_predicted/cleared, ups_on_battery,
  ups_critical, ups_on_line, temp_high, temp_normal, clock_skew, clock_synced,
  gateway_unreachable, gateway_reachable, oom_detected, gateway_latency_high,
  gateway_latency_normal, battery_health_low, battery_health_ok, nic_errors,
  nic_errors_cleared

Click a temperature alert, a UPS on battery, an OOM or a predicted disk failure
and you landed on the KMIP page. Every comment in that block says "the affected
host's drawer".

`test_v225` already required a case for every event, and passed throughout — it
checked that the event was HANDLED, never where it went. That is the
population-versus-rule distinction again: the rule was right and said nothing
about the answer.

The switch also carries a comment recording this same bug once before, when
server-level cases were inserted between a label and its return. Same shape,
opposite end, four releases apart — so this pins DESTINATIONS by running the
real function under node, rather than trusting the source to read correctly.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')

# What each event's own comment says its destination is. Kept as data so a new
# event added to the switch has an obvious place to be declared.
_HOST_DRAWER = (
    'disk_predict_fail', 'resource_saturation_predicted',
    'resource_saturation_cleared', 'ups_on_battery', 'ups_critical',
    'ups_on_line', 'temp_high', 'temp_normal', 'clock_skew', 'clock_synced',
    'gateway_unreachable', 'gateway_reachable', 'oom_detected',
    'gateway_latency_high', 'gateway_latency_normal', 'battery_health_low',
    'battery_health_ok', 'nic_errors', 'nic_errors_cleared',
    'av_infected', 'av_warning', 'av_clean', 'mount_issue', 'readonly_fs',
    'win_bitlocker_off', 'mac_filevault_off',
)
_KMIP = ('kmip_cert_expiring', 'kmip_cert_renewed')
_CHECKS = ('failed_unit', 'failed_unit_cleared')


@unittest.skipUnless(_NODE, 'node not installed')
class TestActivityClicksLandWhereTheCommentsSay(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        body = srcpin.js_function((_JS / 'app.js').read_text(),
                                  '_homeActivityAttrs')
        events = list(_HOST_DRAWER) + list(_KMIP) + list(_CHECKS)
        script = (
            'function escAttr(s){return String(s);}\n' + body + '\n'
            'const out = {};\n'
            f'for (const ev of {json.dumps(events)}) {{\n'
            '  try { out[ev] = String(_homeActivityAttrs(ev, "d1", "web01")); }\n'
            '  catch (e) { out[ev] = "ERR:" + e.message; }\n'
            '}\n'
            'console.log(JSON.stringify(out));\n')
        d = pathlib.Path(tempfile.mkdtemp(prefix='rp-route-'))
        f = d / 'route.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True,
                           timeout=60)
        if r.returncode != 0:
            raise AssertionError(f'node failed: {r.stderr[-600:]}')
        cls.routes = json.loads(r.stdout)

    def test_the_harness_actually_ran_the_function(self):
        """Positive control. Every assertion below reads this dict, so an empty
        or all-error dict must fail loudly rather than pass vacuously."""
        self.assertGreaterEqual(len(self.routes), 25)
        errs = {k: v for k, v in self.routes.items() if v.startswith('ERR:')}
        self.assertEqual(errs, {})

    def test_per_host_events_open_the_host(self):
        wrong = {ev: r for ev in _HOST_DRAWER
                 if 'data-home-act=' not in (r := self.routes[ev])}
        self.assertEqual(wrong, {}, 'these route somewhere other than a host')

    def test_no_per_host_event_opens_the_kmip_page(self):
        """The bug, stated directly."""
        leaked = {ev: self.routes[ev] for ev in _HOST_DRAWER
                  if 'data-page="kmip"' in self.routes[ev]}
        self.assertEqual(leaked, {},
                         'a per-host alert opened the KMIP key-server page — a '
                         'case group lost its return to a later insertion')

    def test_the_kmip_events_still_open_kmip(self):
        """Control: the fix must not take the destination away from the events
        that are meant to have it."""
        for ev in _KMIP:
            self.assertIn('data-page="kmip"', self.routes[ev], ev)

    def test_failed_units_go_to_checks_fleet_wide(self):
        """A second group with its own destination, so a fix that collapsed
        every case into one return would fail here."""
        for ev in _CHECKS:
            self.assertIn('data-home-act=', self.routes[ev], ev)
            self.assertNotIn('data-page="kmip"', self.routes[ev], ev)

    def test_every_declared_event_got_a_distinct_answer(self):
        """If the switch ever returned one string for everything, every test
        above still passes on the host-drawer group alone."""
        self.assertGreater(len(set(self.routes.values())), 1)


if __name__ == '__main__':
    unittest.main()
