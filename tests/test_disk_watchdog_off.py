"""Regression: the /api/self-test 'Disk space' check must honour
disk_watchdog_pct=0 (watchdog off) instead of coercing the 0 back to the 85%
default and flagging the controller disk red for a feature the operator turned
off. The real alerting path (_disk_watchdog) already honours 0 = off; the
self-test summary must match.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_disk_watchdog_off', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Statvfs:
    # ~95% used: 100 blocks total, 5 available, 1 byte per block.
    f_blocks = 100
    f_frsize = 1
    f_bavail = 5


def _disk_space_check(cfg):
    """Run handle_self_test with admin auth + respond stubbed and a near-full
    filesystem, and return its 'Disk space' check dict."""
    cap = {}

    def _resp(status, body=None):
        cap['body'] = body
        raise api.HTTPError(status, body)

    orig = {n: getattr(api, n) for n in ('require_admin_auth', 'respond')}
    api.save(api.CONFIG_FILE, cfg)
    api.require_admin_auth = lambda: 'admin'
    api.respond = _resp
    try:
        with mock.patch('os.statvfs', return_value=_Statvfs()):
            try:
                api.handle_self_test()
            except api.HTTPError:
                pass
    finally:
        for n, v in orig.items():
            setattr(api, n, v)
    checks = (cap.get('body') or {}).get('checks', [])
    return next(c for c in checks if c['name'] == 'Disk space')


class TestDiskWatchdogOff(unittest.TestCase):
    def test_zero_means_off_not_eightyfive(self):
        # disk_watchdog_pct=0 disables the watchdog, so the self-test disk
        # check must report ok even though the filesystem is ~95% used.
        chk = _disk_space_check({'disk_watchdog_pct': 0})
        self.assertTrue(chk['ok'], chk.get('detail'))

    def test_default_still_flags_full_disk(self):
        # With the watchdog at its default (85), a ~95%-used fs still fails -
        # the guard must not suppress a real alert.
        chk = _disk_space_check({})
        self.assertFalse(chk['ok'], chk.get('detail'))


if __name__ == '__main__':
    unittest.main()
