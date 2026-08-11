#!/usr/bin/env python3
"""SMART polling must not wake a sleeping disk.

`collect_smart` ran `smartctl -H -A -i <dev>` with no `-n standby`, so every
hardware cycle — roughly every five minutes — spun up every idle spindle on the
host to ask whether it was healthy. That defeats spindown entirely. The drives
never sleep, and the cost lands on exactly the archive and backup arrays whose
owners configured spin-down deliberately: power, heat, and start/stop cycles,
which are a rated, finite quantity on a consumer disk.

Monitoring that changes what it measures is a category of bug worth naming. The
poll was not wrong about the disks' health; it was the reason the disks were
never asleep to have their health mis-measured in the first place.

`smartctl -n standby` exits 2 and prints "Device is in STANDBY mode" WITHOUT
touching the drive.

The disk is still REPORTED, marked standby, rather than omitted: a device that
vanishes from the inventory every time it sleeps and returns when it wakes is a
flapping device list, which is worse than a missing reading. UNKNOWN health is
already treated as "not a failure" by the health check and the risk score, so
this cannot manufacture an alert.
"""
import ast
import importlib.util
import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643smart-'))

_spec = importlib.util.spec_from_file_location('api_v643_smart', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


def _agent():
    spec = importlib.util.spec_from_file_location(
        'rp_agent_smart', _ROOT / 'client' / 'remotepower-agent.py')
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    return mod


_STANDBY_OUT = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux] (local build)
Copyright (C) 2002-23, Bruce Allen, Christian Franke, www.smartmontools.org

Device is in STANDBY mode, exit(2)
"""

_AWAKE_OUT = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux] (local build)
=== START OF INFORMATION SECTION ===
Device Model:     WDC WD80EFZX-68UW8N0
Serial Number:    VKH8XYZ1
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   200   200   140    Pre-fail  Always       -       0
  9 Power_On_Hours          0x0032   088   088   000    Old_age   Always       -       9001
"""


class _FakeRun:
    """Records argv and replays canned smartctl output per device."""

    def __init__(self, per_device):
        self.per_device = per_device
        self.calls = []

    def __call__(self, argv, *a, **k):
        self.calls.append(list(argv))
        dev = argv[-1]
        out = self.per_device.get(dev, '')
        return type('R', (), {'stdout': out, 'stderr': '', 'returncode': 0})()


class TestTheStandbyFlagIsPassed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ag = _agent()

    def _collect(self, per_device, devices):
        ag = self.ag
        saved = (ag.subprocess.run, ag._which, ag._list_block_devices)
        fake = _FakeRun(per_device)
        ag.subprocess.run = fake
        ag._which = lambda n: '/usr/sbin/smartctl' if n == 'smartctl' else None
        ag._list_block_devices = lambda: list(devices)
        try:
            return fake, ag.get_smart_status()
        finally:
            (ag.subprocess.run, ag._which, ag._list_block_devices) = saved

    def test_every_invocation_carries_dash_n_standby(self):
        fake, _ = self._collect({'/dev/sda': _AWAKE_OUT}, ['/dev/sda'])
        self.assertTrue(fake.calls, 'smartctl was never invoked')
        for argv in fake.calls:
            self.assertIn('-n', argv, f'no -n flag: {argv}')
            self.assertEqual(argv[argv.index('-n') + 1], 'standby',
                             f'-n is not "standby": {argv}')

    def test_a_sleeping_disk_is_reported_not_dropped(self):
        _f, disks = self._collect({'/dev/sda': _STANDBY_OUT}, ['/dev/sda'])
        self.assertEqual(len(disks), 1,
                         'the disk vanished from the inventory while asleep — '
                         'a device list that flaps with spindown is worse than '
                         'a missing reading')
        self.assertIs(disks[0].get('standby'), True)
        self.assertEqual(disks[0]['device'], '/dev/sda')

    def test_a_sleeping_disk_reports_unknown_not_a_failure(self):
        """UNKNOWN is explicitly not a failure anywhere downstream. Any other
        value here would turn every spun-down archive disk into an alert."""
        _f, disks = self._collect({'/dev/sda': _STANDBY_OUT}, ['/dev/sda'])
        self.assertEqual(disks[0]['health'], 'UNKNOWN')
        self.assertNotIn('reallocated_sectors', disks[0],
                         'no attributes can be known without waking the disk')

    def test_an_awake_disk_is_still_parsed_fully(self):
        """The positive control. A collector that returned a standby stub for
        everything would satisfy both tests above."""
        _f, disks = self._collect({'/dev/sda': _AWAKE_OUT}, ['/dev/sda'])
        self.assertEqual(disks[0]['health'], 'PASSED')
        self.assertEqual(disks[0]['model'], 'WDC WD80EFZX-68UW8N0')
        self.assertEqual(disks[0]['power_on_hours'], 9001)
        self.assertNotIn('standby', disks[0])

    def test_a_mixed_host_reports_both(self):
        _f, disks = self._collect(
            {'/dev/sda': _AWAKE_OUT, '/dev/sdb': _STANDBY_OUT},
            ['/dev/sda', '/dev/sdb'])
        by_dev = {d['device']: d for d in disks}
        self.assertEqual(by_dev['/dev/sda']['health'], 'PASSED')
        self.assertIs(by_dev['/dev/sdb'].get('standby'), True)

    def test_the_source_does_not_merely_mention_standby_in_prose(self):
        """Assert against the CODE, with the docstring stripped — this file's
        own explanation contains the word "standby" a dozen times, and so does
        the collector's."""
        tree = ast.parse(inspect.getsource(self.ag.get_smart_status))
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)):
            fn.body.pop(0)
        self.assertIn("'-n', 'standby'", ast.unparse(fn))


class TestTheServerKeepsTheFlag(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix='rp-v643smart-hb-'))
        self._saved = (api.DEVICES_FILE, api.CONFIG_FILE, api.respond,
                       api.HARDWARE_FILE)
        api.DEVICES_FILE = tmp / 'devices.json'
        api.CONFIG_FILE = tmp / 'config.json'
        api.HARDWARE_FILE = tmp / 'hardware.json'
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'nas01',
                                           'token': 'tok', 'monitored': True}})
        api.respond = lambda status, body: (_ for _ in ()).throw(SystemExit(0))

    def tearDown(self):
        (api.DEVICES_FILE, api.CONFIG_FILE, api.respond,
         api.HARDWARE_FILE) = self._saved

    def _beat(self, smart):
        """SMART is NOT stored on the device row — it goes to HARDWARE_FILE,
        keyed by device id. The first draft of this test looked for it under
        dev['sysinfo'] and dev['hardware'], found neither, and SKIPPED with a
        plausible-sounding reason. Two green skips assert nothing; a skip is a
        gate that is not running, and one that explains itself convincingly is
        worse than one that fails."""
        api.get_json_body = lambda: {'device_id': 'd1', 'token': 'tok',
                                     'smart': smart}
        api.method = lambda: 'POST'
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        api._invalidate_load_cache(api.HARDWARE_FILE)
        rec = (api.load(api.HARDWARE_FILE) or {}).get('d1') or {}
        return rec.get('smart') or []

    def test_standby_survives_the_sanitiser(self):
        """Without a whitelist entry the flag is dropped and the UI cannot tell
        a sleeping disk from one that stopped answering."""
        rows = self._beat([{'device': '/dev/sdb', 'health': 'UNKNOWN',
                            'standby': True}])
        self.assertTrue(rows, 'no SMART record was stored at all')
        self.assertIs(rows[0].get('standby'), True)

    def test_a_truthy_non_true_value_is_not_accepted(self):
        """`is True`, not truthiness — an agent sending the string "no" must
        not mark the disk asleep."""
        rows = self._beat([{'device': '/dev/sdb', 'health': 'PASSED',
                            'standby': 'no'}])
        self.assertTrue(rows, 'no SMART record was stored at all')
        self.assertNotIn('standby', rows[0])


if __name__ == '__main__':
    unittest.main()
