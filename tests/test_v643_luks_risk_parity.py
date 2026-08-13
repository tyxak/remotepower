#!/usr/bin/env python3
"""An unencrypted Linux disk contributed nothing to a host's risk score.

The risk score has an `encryption_off` factor worth the same weight whichever
platform raises it. It was raised for BitLocker and for FileVault, and not for
LUKS — so on a fleet of Linux hosts, which is what this product is mostly used
to run, "is the disk encrypted?" contributed zero to every score.

The signal was not missing. The agent collects `disk_encryption`, the heartbeat
sanitiser whitelists it, the compliance control started scoring it earlier in
this same release, and the RAG corpus and reports both read it. One consumer
never did, which is the dead-signal shape this codebase keeps finding: a feature
that is wired end to end except at the point where it would have mattered.

Precedence is asserted as well as presence. FileVault and BitLocker answer the
encryption question where they exist and LUKS answers it where they do not, so a
host cannot be scored twice for one question — the same ordering the compliance
fact already uses.
"""
import os
import sys
import time
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-luks-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


def _factors(sysinfo):
    """Run the REAL scorer and return its factor list.

    Called with the true signature rather than a convenience wrapper: a helper
    that quietly swallowed a TypeError would make every assertion below pass
    against a function that never ran.
    """
    now = int(time.time())
    dev = {'sysinfo': sysinfo, 'last_seen': now}
    out = api._device_risk('d1', dev, {}, {}, {}, now, 300)
    return out.get('factors') or []


def _encryption_factors(sysinfo):
    return [f for f in _factors(sysinfo) if f.get('kind') == 'encryption_off']


def _has_encryption_off(sysinfo):
    return bool(_encryption_factors(sysinfo))


class TestEncryptionRiskIsPlatformNeutral(unittest.TestCase):

    def test_unencrypted_linux_disk_raises_the_factor(self):
        self.assertTrue(
            _has_encryption_off({'disk_encryption': {'encrypted': False}}),
            'an unencrypted Linux root contributed nothing to the risk score '
            'while the same condition on Windows or macOS scored the full weight')

    def test_encrypted_linux_disk_does_not(self):
        """POSITIVE CONTROL for the negative direction: the factor must be
        absent when the disk IS encrypted, or the test above would pass against
        a scorer that flags every host."""
        self.assertFalse(
            _has_encryption_off({'disk_encryption': {'encrypted': True}}))

    def test_absent_data_is_not_treated_as_unencrypted(self):
        """The agent returns {} when it cannot see device-mapper at all. Absence
        of an answer must not be scored as a bad answer — that would flag every
        host running an agent too old to collect it."""
        for si in ({}, {'disk_encryption': {}}, {'disk_encryption': None}):
            self.assertFalse(_has_encryption_off(si), si)

    def test_windows_still_scores(self):
        """Unchanged behaviour, pinned so the new branch cannot displace it."""
        self.assertTrue(_has_encryption_off({'win_posture': {
            'bitlocker': [{'status': 'off'}]}}))

    def test_macos_still_scores(self):
        self.assertTrue(_has_encryption_off({'mac_posture': {
            'filevault': False}}))

    def test_a_host_is_not_scored_twice_for_one_question(self):
        """FileVault answers it where it exists; the LUKS branch must not add a
        second, duplicate factor for the same host."""
        si = {'mac_posture': {'filevault': False},
              'disk_encryption': {'encrypted': False}}
        self.assertEqual(len(_encryption_factors(si)), 1,
                         'the same host was scored twice for encryption')


if __name__ == '__main__':
    unittest.main()
