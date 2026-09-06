#!/usr/bin/env python3
"""Three surfaces asked the Linux agent and reported the answer as the fleet's.

Firewall, disk encryption and automatic updates are reported by all three
agents under different keys: Linux writes `firewall`, `disk_encryption` and
`autoupdate` at the top of sysinfo; Windows writes `bitlocker`, `firewall` and
`wu_service` under `win_posture`; macOS writes `filevault`, `firewall` and
`auto_security_update` under `mac_posture`.

`checks.py` reads all three, and so does the risk score. Three surfaces read
only the Linux producer:

  * the Data Explorer — `disk_encrypted`, `firewall_active` and
    `autoupdate_enabled` were None on every Windows and macOS row;
  * the Fleet Query facets — "which hosts have no firewall" silently excluded
    every Windows and macOS host, so the answer looked complete and was not;
  * the printable report — on a Windows-heavy fleet the denominators were zero,
    and report.js drops a section whose denominator is zero, so the PDF showed
    NO firewall posture rather than a wrong one.

This is the same shape as the `secure_boot` bug fixed at v7.0.2 two lines below
the Data Explorer's copy; looking at its neighbours is what found these.

One shared helper rather than a fourth copy of the fan-out, and the tri-state is
the part worth guarding: False means "reported, and it is off", None means "this
host never told us". Collapsing them puts a host whose probes all failed into a
list of findings it does not belong in.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v703-posture-'))
for _k, _v in (('REQUEST_METHOD', 'GET'), ('PATH_INFO', '/'),
               ('CONTENT_LENGTH', '0')):
    os.environ.setdefault(_k, _v)
import checks

_LINUX = {'disk_encryption': {'encrypted': True},
          'firewall': {'backends': [{'name': 'nftables', 'active': True}],
                       'active': True},
          'autoupdate': {'enabled': False}}
_WINDOWS = {'win_posture': {'bitlocker': True, 'firewall': False,
                            'wu_service': True}}
_MACOS = {'mac_posture': {'filevault': False, 'firewall': True,
                          'auto_security_update': True}}


class TestEveryPlatformIsRead(unittest.TestCase):

    def test_linux(self):
        self.assertEqual(checks.posture_flags(_LINUX),
                         {'disk_encrypted': True, 'firewall_active': True,
                          'autoupdate_enabled': False})

    def test_windows(self):
        self.assertEqual(checks.posture_flags(_WINDOWS),
                         {'disk_encrypted': True, 'firewall_active': False,
                          'autoupdate_enabled': True})

    def test_macos(self):
        self.assertEqual(checks.posture_flags(_MACOS),
                         {'disk_encrypted': False, 'firewall_active': True,
                          'autoupdate_enabled': True})

    def test_a_host_that_reported_nothing_is_unknown_not_off(self):
        self.assertEqual(checks.posture_flags({}),
                         {'disk_encrypted': None, 'firewall_active': None,
                          'autoupdate_enabled': None})

    def test_unreadable_firewall_probes_stay_unknown(self):
        """Every backend probe failed. `any()` over that is False, which would
        report the host as having no firewall — the reason the rollup is the
        agent's own field and the fallback keeps the tri-state."""
        si = {'firewall': {'backends': [{'name': 'nftables', 'active': None},
                                        {'name': 'ufw', 'active': None}]}}
        self.assertIsNone(checks.posture_flags(si)['firewall_active'])

    def test_backends_without_the_rollup_still_resolve(self):
        si = {'firewall': {'backends': [{'name': 'ufw', 'active': False},
                                        {'name': 'nft', 'active': None}]}}
        self.assertIs(checks.posture_flags(si)['firewall_active'], False)


class TestTheSurfacesUseIt(unittest.TestCase):
    """Source-level: three call sites, and the rule is that there are no
    hand-written copies of the fan-out left."""

    _API = _CGI / 'api.py'
    _REPORTS = _CGI / 'reports_handlers.py'

    def test_the_data_explorer_uses_the_helper(self):
        import ast
        tree = ast.parse(self._API.read_text(encoding='utf-8'))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == '_qe_device_posture')
        self.assertIn('posture_flags', ast.unparse(fn))

    def test_the_fleet_query_facets_use_the_helper(self):
        """Bounded by content, not by a character count — a fixed window is the
        class tests/test_srcpin_ratchet.py holds at a shrink-only ceiling, and
        one added comment is enough to push the line being pinned out of it."""
        from srcpin import py_block
        src = self._API.read_text(encoding='utf-8')
        fw = py_block(src, 'if fwoff_q:')
        self.assertIn('posture_flags', fw)
        self.assertIn('firewall_active', fw)
        au = py_block(src, 'if auoff_q:')
        self.assertIn('posture_flags', au)
        self.assertIn('autoupdate_enabled', au)

    def test_the_printable_report_uses_the_helper(self):
        src = self._REPORTS.read_text(encoding='utf-8')
        self.assertIn('posture_flags', src)
        self.assertNotIn("fw = si.get('firewall')", src,
                         'the Linux-only read is back in the report')


class TestTheHelperIsTheOnlyCopy(unittest.TestCase):
    """A fourth copy is how the third one came to disagree with the other two."""

    def test_no_surface_derives_firewall_from_backends_by_hand(self):
        import re
        offenders = []
        for name in ('api.py', 'reports_handlers.py', 'advisory_handlers.py'):
            path = _CGI / name
            if not path.exists():
                continue
            for i, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if line.lstrip().startswith('#'):
                    continue
                if re.search(r"any\(\s*b\.get\('active'\)\s+for\s+b\s+in", line):
                    offenders.append(f'{name}:{i}')
        self.assertEqual(
            offenders, [],
            'a hand-rolled firewall rollup — it collapses the unknown case to '
            f'False. Use checks.posture_flags: {offenders}')

    def test_the_detector_recognises_the_shape(self):
        import re
        sample = "        'firewall_active': (any(b.get('active') for b in backends)"
        self.assertTrue(re.search(r"any\(\s*b\.get\('active'\)\s+for\s+b\s+in", sample))


if __name__ == '__main__':
    unittest.main()
