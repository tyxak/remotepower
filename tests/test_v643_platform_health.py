#!/usr/bin/env python3
"""Four small host signals that homelab fleets ask for and had no source.

  throttle   Raspberry Pi under-voltage / thermal throttling — the commonest
             cause of "my Pi is randomly unstable" and invisible in every other
             metric. CPU fine, memory fine, board browning out under a bad PSU.
  fans       Fan RPM from hwmon. A stopped fan is not visible in a temperature
             reading until the thermal damage is already happening.
  governor   The cpufreq governor. A silent, permanent performance
             misconfiguration that nothing reported.
  wifi       Link quality for wireless hosts. A host at -85 dBm is not DOWN, so
             nothing alerts; it drops packets and gets blamed on the app.

All four are sysfs / procfs reads through host_path() — no vcgencmd, no
sensors, no iwconfig — so nothing depends on a package being installed or on a
tool's output format holding still, and the containerized agent reads the HOST.

WHAT THIS FILE MOSTLY GUARDS IS THE RESTRAINT. Only `throttle` raises a
non-OK status, because only there is the source unambiguous. Testing on a real
machine is what settled that: this box reports SIX fan inputs of which three
read 0 RPM forever because the headers are empty, and it runs the `powersave`
governor under intel_pstate, which is the default on most distributions and
performs perfectly well. A fan-stopped alert and a powersave warning would both
have shipped as noise on healthy hardware, and noisy gates get switched off —
taking the real signal with them.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643ph-'))

_spec = importlib.util.spec_from_file_location('api_v643_ph', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import checks as checks_mod            # noqa: E402


def _agent():
    spec = importlib.util.spec_from_file_location(
        'rp_agent_ph', _ROOT / 'client' / 'remotepower-agent.py')
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    return mod


class TestTheCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ag = _agent()

    def test_it_returns_a_dict_on_any_platform(self):
        self.assertIsInstance(self.ag.get_platform_health(), dict)

    def test_absent_sources_are_omitted_not_nulled(self):
        """A plain x86 server has no Pi firmware node and no wireless. Sending
        {'throttle': None, 'wifi': None} would make every consumer special-case
        a key that means nothing."""
        orig = self.ag.host_path
        self.ag.host_path = lambda p: '/nonexistent-for-this-test'
        try:
            self.assertEqual(self.ag.get_platform_health(), {})
        finally:
            self.ag.host_path = orig

    def test_it_uses_sysfs_not_subprocesses(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(self.ag.get_platform_health))
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)):
            fn.body.pop(0)          # the docstring names all three tools
        src = ast.unparse(fn)
        self.assertNotIn('subprocess', src)
        for tool in ('vcgencmd', 'iwconfig', 'sensors'):
            self.assertNotIn(tool, src)
        self.assertIn('host_path(', src)

    def test_the_throttle_bitmask_is_decoded_correctly(self):
        """0x50005 = under-voltage now + throttled now + the same since boot.
        Verified against the documented Raspberry Pi firmware bit layout."""
        ag = self.ag
        orig_read, orig_hp = ag._safe_read, ag.host_path
        ag.host_path = lambda p: p
        ag._safe_read = lambda p, n=None: (
            '0x50005' if 'get_throttled' in str(p) else '')
        try:
            th = ag.get_platform_health().get('throttle')
        finally:
            ag._safe_read, ag.host_path = orig_read, orig_hp
        self.assertIsNotNone(th)
        self.assertTrue(th['undervolt_now'])
        self.assertTrue(th['throttled_now'])
        self.assertTrue(th['undervolt_since_boot'])
        self.assertTrue(th['throttled_since_boot'])
        self.assertFalse(th['freq_capped_now'])
        self.assertFalse(th['soft_temp_now'])

    def test_a_healthy_pi_decodes_to_all_false(self):
        """The positive control — a decoder that returned True for everything
        would satisfy the test above."""
        ag = self.ag
        orig_read, orig_hp = ag._safe_read, ag.host_path
        ag.host_path = lambda p: p
        ag._safe_read = lambda p, n=None: (
            '0x0' if 'get_throttled' in str(p) else '')
        try:
            th = ag.get_platform_health().get('throttle')
        finally:
            ag._safe_read, ag.host_path = orig_read, orig_hp
        self.assertIsNotNone(th, 'a healthy Pi must still REPORT — "no '
                                 'under-voltage" is an answer, and its absence '
                                 'is indistinguishable from "not a Pi"')
        self.assertFalse(any(v for k, v in th.items() if k != 'raw'))

    def test_on_this_machine_it_agrees_with_sysfs(self):
        """Against the real host, not a fixture."""
        gov_path = Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
        if not gov_path.exists():
            self.skipTest('no cpufreq on this host')
        expected = gov_path.read_text().strip()
        self.assertEqual(self.ag.get_platform_health().get('governor'), expected)


class TestChecksRowsAreHonest(unittest.TestCase):
    def _rows(self, ph):
        dev = {'name': 'pi01', 'os': 'Debian GNU/Linux 12',
               'sysinfo': {'platform_health': ph}}
        rows = checks_mod.host_checks('d1', dev, {}) if hasattr(
            checks_mod, 'host_checks') else api._host_checks('d1', dev)
        return {r.get('key'): r for r in rows if isinstance(r, dict)}

    def test_undervoltage_now_is_critical(self):
        r = self._rows({'throttle': {'undervolt_now': True}})['pi_throttle']
        self.assertEqual(r['status'], 'critical')

    def test_undervoltage_since_boot_still_warns(self):
        """An intermittent 3am brownout explains last night's corruption. It
        must not be silent just because nothing is wrong this second."""
        r = self._rows({'throttle': {'undervolt_since_boot': True}})['pi_throttle']
        self.assertEqual(r['status'], 'warning')
        self.assertIn('since boot', r['output'])

    def test_a_healthy_pi_is_ok(self):
        r = self._rows({'throttle': {'undervolt_now': False,
                                     'throttled_now': False}})['pi_throttle']
        self.assertEqual(r['status'], 'ok')

    def test_a_zero_rpm_fan_does_NOT_warn(self):
        """The restraint this file exists to protect. Three of the six fan
        inputs on the machine this was written on read 0 forever because the
        headers are empty. Warning here fires on most desktops and every board
        with a spare header — and a gate that cries wolf on healthy hardware
        gets switched off, taking the real signal with it. Distinguishing a
        stopped fan from an empty header needs per-fan history."""
        r = self._rows({'fans': [{'name': 'fan1', 'rpm': 900},
                                 {'name': 'fan3', 'rpm': 0}]})['fan_rpm']
        self.assertEqual(r['status'], 'ok')
        self.assertIn('1/2', r['output'])

    def test_powersave_governor_does_NOT_warn(self):
        """intel_pstate's powersave is the default on most distributions and
        performs fine — it is not acpi-cpufreq's powersave. Warning on the
        string would fire on a large share of healthy servers."""
        r = self._rows({'governor': 'powersave',
                        'governor_driver': 'intel_pstate'})['cpu_governor']
        self.assertEqual(r['status'], 'ok')
        self.assertIn('intel_pstate', r['output'])

    def test_a_weak_wireless_link_warns(self):
        r = self._rows({'wifi': [{'iface': 'wlan0', 'level_dbm': -82,
                                  'link': 20}]})['wifi_link_wlan0']
        self.assertEqual(r['status'], 'warning')

    def test_a_strong_wireless_link_does_not(self):
        r = self._rows({'wifi': [{'iface': 'wlan0', 'level_dbm': -45,
                                  'link': 65}]})['wifi_link_wlan0']
        self.assertEqual(r['status'], 'ok')

    def test_a_host_reporting_nothing_gets_no_rows(self):
        rows = self._rows({})
        for k in ('pi_throttle', 'fan_rpm', 'cpu_governor'):
            self.assertNotIn(k, rows)


class TestItSurvivesTheHeartbeat(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix='rp-v643ph-hb-'))
        self._saved = (api.DEVICES_FILE, api.CONFIG_FILE, api.respond)
        api.DEVICES_FILE = tmp / 'devices.json'
        api.CONFIG_FILE = tmp / 'config.json'
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'pi01',
                                           'token': 'tok', 'monitored': True}})
        api.respond = lambda s, b: (_ for _ in ()).throw(SystemExit(0))

    def tearDown(self):
        api.DEVICES_FILE, api.CONFIG_FILE, api.respond = self._saved

    def _beat(self, ph):
        api.get_json_body = lambda: {
            'device_id': 'd1', 'token': 'tok',
            'sysinfo': {'platform_health': ph}}
        api.method = lambda: 'POST'
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        api._invalidate_load_cache(api.DEVICES_FILE)
        return ((api.load(api.DEVICES_FILE)['d1'].get('sysinfo') or {})
                .get('platform_health'))

    def test_all_four_survive(self):
        out = self._beat({
            'throttle': {'undervolt_now': True, 'raw': '0x1'},
            'fans': [{'name': 'fan1', 'chip': 'nct6798', 'rpm': 900}],
            'governor': 'performance', 'governor_driver': 'acpi-cpufreq',
            'wifi': [{'iface': 'wlan0', 'link': 60.0, 'level_dbm': -50.0}],
        })
        self.assertIsNotNone(out, 'safe_si dropped platform_health entirely')
        self.assertTrue(out['throttle']['undervolt_now'])
        self.assertEqual(out['fans'][0]['rpm'], 900)
        self.assertEqual(out['governor'], 'performance')
        self.assertEqual(out['wifi'][0]['level_dbm'], -50.0)

    def test_junk_is_clamped(self):
        out = self._beat({
            'fans': [{'name': 'x' * 300, 'chip': 'y' * 300, 'rpm': 10 ** 9}] * 60,
            'governor': 'z' * 200,
            'wifi': [{'iface': 'w', 'level_dbm': 1e9}] * 40,
            'unexpected': 'dropped',
        })
        self.assertNotIn('unexpected', out)
        self.assertLessEqual(len(out['fans']), 16)
        self.assertLessEqual(out['fans'][0]['rpm'], 100000)
        self.assertLessEqual(len(out['fans'][0]['name']), 32)
        self.assertLessEqual(len(out['governor']), 32)
        self.assertLessEqual(len(out['wifi']), 8)
        self.assertNotIn('level_dbm', out['wifi'][0])   # out of range → dropped

    def test_a_non_bool_throttle_flag_is_rejected(self):
        out = self._beat({'throttle': {'undervolt_now': 'yes', 'raw': '0x1'}})
        self.assertNotIn('undervolt_now', out.get('throttle', {}))


if __name__ == '__main__':
    unittest.main()
