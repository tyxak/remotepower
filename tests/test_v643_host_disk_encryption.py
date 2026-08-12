#!/usr/bin/env python3
"""The control plane grades every managed host on encryption — including itself.

RemotePower's Compliance page scores encryption-at-rest across the fleet. The
one box it never asked was its own: the machine holding device tokens, the CMDB
credential vault, API-key hashes and the backups. `/api/security-posture` had
16 rows and none concerned the host disk; `/api/self/status` carries no such
field; no module under server/cgi-bin reads the dm-crypt sysfs at all.

An operator COULD get this by enrolling the server host as a managed device —
the check catalog even presupposes it, with "RemotePower (self-infra)" rows —
but install-server.sh never does that and no document suggests it. So the
answer depended on someone having thought of it.

THE THIRD STATE IS THE POINT. `None` means "cannot determine", not "no". In a
container /proc/self/mounts describes the container and the host's sysfs is not
visible; reporting "unencrypted" there would fabricate a finding out of a blind
spot — the same reasoning behind the agent collector returning {} and
compliance.py's NOT_ASSESSED. It reports OK with an honest detail instead.

Every test below drives the helper against a SYNTHETIC sysfs and mounts file.
That is deliberate: parameterising the roots is what stops the test asserting
against whatever disk the runner happens to have, which would pass on an
unencrypted CI box and measure the machine instead of the code.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643fde-'))

_spec = importlib.util.spec_from_file_location('api_v643_fde', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Fixture(unittest.TestCase):
    """A synthetic /sys/block + /proc/self/mounts, so both answers are
    reachable regardless of the machine running the suite."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-fde-'))
        self.sysfs = self.root / 'sys' / 'block'
        self.data = self.root / 'data'
        self.data.mkdir(parents=True)
        self.sysfs.mkdir(parents=True)

    def _dm(self, dm, name, uuid):
        d = self.sysfs / dm / 'dm'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'name').write_text(name + '\n')
        (d / 'uuid').write_text(uuid + '\n')

    def _mounts(self, source, mountpoint=None):
        mp = mountpoint or str(self.data)
        f = self.root / 'mounts'
        f.write_text(f'/dev/sda1 / ext4 rw 0 0\n{source} {mp} ext4 rw 0 0\n')
        return f

    def _ask(self, source, mountpoint=None):
        return api._host_disk_encrypted(
            sysfs_root=str(self.sysfs),
            mounts_path=str(self._mounts(source, mountpoint)),
            data_dir=str(self.data))


class TestTheVerdict(_Fixture):
    def test_a_luks_volume_is_encrypted(self):
        self._dm('dm-0', 'luks-root', 'CRYPT-LUKS2-abcdef-luks-root')
        self.assertIs(self._ask('/dev/mapper/luks-root'), True)

    def test_a_plain_block_device_is_not(self):
        """The finding this exists to make. A confident False, not a shrug."""
        self.assertIs(self._ask('/dev/sda2'), False)

    def test_a_non_crypt_mapper_target_is_not(self):
        """LVM without encryption is device-mapper too — the mapper prefix
        alone is not evidence."""
        self._dm('dm-0', 'vg0-root', 'LVM-xyz')
        self.assertIs(self._ask('/dev/mapper/vg0-root'), False)

    def test_an_unknown_filesystem_is_cannot_tell(self):
        """tmpfs/overlay: not a block device, so neither answer is honest."""
        self.assertIsNone(self._ask('tmpfs'))

    def test_an_unmatched_mapper_name_is_cannot_tell(self):
        """A mapper device with no sysfs entry we can read — do not guess."""
        self.assertIsNone(self._ask('/dev/mapper/luks-elsewhere'))

    def test_the_longest_prefix_wins(self):
        """DATA_DIR may sit on a nested mount; matching '/' first would report
        the wrong volume."""
        self._dm('dm-0', 'luks-data', 'CRYPT-LUKS2-1234-luks-data')
        f = self.root / 'mounts'
        f.write_text('/dev/sda1 / ext4 rw 0 0\n'
                     f'/dev/mapper/luks-data {self.data} ext4 rw 0 0\n')
        self.assertIs(api._host_disk_encrypted(
            sysfs_root=str(self.sysfs), mounts_path=str(f),
            data_dir=str(self.data)), True)


class TestThePostureRow(unittest.TestCase):
    def _rows(self):
        cap = {}
        orig = (api.require_admin_or_auditor_auth, api.method, api.respond)
        api.require_admin_or_auditor_auth = lambda *a, **k: 'root'
        api.method = lambda: 'GET'

        def _r(status, data=None, *a, **k):
            cap['d'] = data
            raise api.HTTPError(status, data)
        api.respond = _r
        try:
            api.handle_security_posture()
        except (SystemExit, api.HTTPError):
            pass
        finally:
            (api.require_admin_or_auditor_auth, api.method, api.respond) = orig
        return {r['key']: r for r in (cap.get('d') or {}).get('checks') or []}

    def test_the_row_exists(self):
        self.assertIn('host_disk_encrypted', self._rows())

    def test_an_undeterminable_host_does_not_warn(self):
        """"Cannot see" must not render as a finding. A containerised install
        would otherwise show a permanent red row nobody can clear."""
        orig = api._host_disk_encrypted
        api._host_disk_encrypted = lambda *a, **k: None
        try:
            row = self._rows()['host_disk_encrypted']
        finally:
            api._host_disk_encrypted = orig
        self.assertEqual(row['status'], 'ok')
        self.assertIn('cannot be determined', row['detail'])

    def test_an_unencrypted_host_warns_and_says_what_is_at_stake(self):
        orig = api._host_disk_encrypted
        api._host_disk_encrypted = lambda *a, **k: False
        try:
            row = self._rows()['host_disk_encrypted']
        finally:
            api._host_disk_encrypted = orig
        self.assertEqual(row['status'], 'warn')
        self.assertIn('vault', row['detail'])

    def test_an_encrypted_host_passes(self):
        orig = api._host_disk_encrypted
        api._host_disk_encrypted = lambda *a, **k: True
        try:
            row = self._rows()['host_disk_encrypted']
        finally:
            api._host_disk_encrypted = orig
        self.assertEqual(row['status'], 'ok')

    def test_it_offers_no_settings_link(self):
        """There is no in-app fix — it is a host build decision. A fix_tab
        would send the operator somewhere that cannot help."""
        self.assertFalse(self._rows()['host_disk_encrypted'].get('fix_tab'))


if __name__ == '__main__':
    unittest.main()
