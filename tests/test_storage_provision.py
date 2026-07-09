"""v6.1.1 — guided storage provisioning (create, not just maintain):
_sp_build, the pure command-builder + validator behind
POST /api/devices/{id}/storage-provision. Handler-level (dry_run, confirm
gate, force_approval routing) is covered in tests/test_v3140.py.

Scoped narrower than a general partition-table editor
(docs/feature-buildout-scoping-internal.md #7): whole-disk block devices
only, every recipe requires a server-checked type-to-confirm, and every
mutating call is routed through _queue_command(force_approval=True) --
these tests exist specifically to prove those guardrails hold, since
exec: commands are shell-interpreted on the agent (see _valid_fw_token's
docstring) and this is the only thing standing between a bad parameter and
command injection into an mdadm/lvm/mkfs invocation.
"""
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import api  # noqa: E402


class TestMdadmCreate(unittest.TestCase):
    def test_valid_raid1(self):
        cmd, target, detail = api._sp_build('mdadm_create', {
            'device': '/dev/md0', 'level': '1', 'members': ['/dev/sdb', '/dev/sdc']})
        self.assertEqual(cmd, 'mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sdb /dev/sdc --run')
        self.assertEqual(target, '/dev/md0')

    def test_minimum_members_enforced_per_level(self):
        with self.assertRaisesRegex(ValueError, 'RAID5 needs at least 3'):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '5',
                          'members': ['/dev/sdb', '/dev/sdc']})
        with self.assertRaisesRegex(ValueError, 'RAID6 needs at least 4'):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '6',
                          'members': ['/dev/sdb', '/dev/sdc', '/dev/sdd']})
        with self.assertRaisesRegex(ValueError, 'RAID10 needs at least 4'):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '10',
                          'members': ['/dev/sdb', '/dev/sdc', '/dev/sdd']})

    def test_bad_device_path_rejected(self):
        for bad in ('/dev/sda1', '/etc/passwd', 'md0', '/dev/md'):
            with self.assertRaises(ValueError, msg=bad):
                api._sp_build('mdadm_create', {'device': bad, 'level': '1',
                              'members': ['/dev/sdb', '/dev/sdc']})

    def test_bad_level_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '4',
                          'members': ['/dev/sdb', '/dev/sdc']})

    def test_member_shell_injection_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '1',
                          'members': ['/dev/sdb; rm -rf /', '/dev/sdc']})

    def test_partition_member_rejected(self):
        # whole-disk only -- /dev/sdb1 (a partition) must not slip through
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '1',
                          'members': ['/dev/sdb1', '/dev/sdc']})

    def test_duplicate_members_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '1',
                          'members': ['/dev/sdb', '/dev/sdb']})

    def test_member_cap_enforced(self):
        many = [f'/dev/sd{chr(ord("b") + i)}' for i in range(30)]
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_create', {'device': '/dev/md0', 'level': '1', 'members': many})


class TestLvmRecipes(unittest.TestCase):
    def test_pvcreate(self):
        cmd, target, _ = api._sp_build('lvm_pvcreate', {'members': ['/dev/sdb', '/dev/sdc']})
        self.assertEqual(cmd, 'pvcreate /dev/sdb /dev/sdc')
        self.assertEqual(target, '/dev/sdb /dev/sdc')

    def test_vgcreate_validates_name(self):
        cmd, target, _ = api._sp_build('lvm_vgcreate', {'vgname': 'data1', 'members': ['/dev/sdb']})
        self.assertEqual(cmd, 'vgcreate data1 /dev/sdb')
        for bad in ('data 1', 'data;rm', '1data', ''):
            with self.assertRaises(ValueError, msg=bad):
                api._sp_build('lvm_vgcreate', {'vgname': bad, 'members': ['/dev/sdb']})

    def test_lvcreate_explicit_size(self):
        cmd, target, _ = api._sp_build('lvm_lvcreate', {'vgname': 'data', 'lvname': 'store', 'size': '500G'})
        self.assertEqual(cmd, 'lvcreate -n store -L 500G data')
        self.assertEqual(target, 'store')

    def test_lvcreate_defaults_to_100pct_free(self):
        cmd, _, _ = api._sp_build('lvm_lvcreate', {'vgname': 'data', 'lvname': 'store'})
        self.assertEqual(cmd, 'lvcreate -n store -l 100%FREE data')

    def test_lvcreate_bad_size_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('lvm_lvcreate', {'vgname': 'data', 'lvname': 'store', 'size': '500G; rm -rf /'})


class TestMkfs(unittest.TestCase):
    def test_valid(self):
        cmd, target, _ = api._sp_build('mkfs', {'device': '/dev/sdb', 'fstype': 'ext4'})
        self.assertEqual(cmd, 'mkfs.ext4 -F /dev/sdb')
        self.assertEqual(target, '/dev/sdb')

    def test_btrfs_uses_lowercase_f_flag(self):
        cmd, _, _ = api._sp_build('mkfs', {'device': '/dev/sdb', 'fstype': 'btrfs'})
        self.assertEqual(cmd, 'mkfs.btrfs -f /dev/sdb')

    def test_fstype_allowlisted(self):
        for bad in ('ntfs', 'vfat', 'ext4; rm -rf /', ''):
            with self.assertRaises(ValueError, msg=bad):
                api._sp_build('mkfs', {'device': '/dev/sdb', 'fstype': bad})

    def test_partition_target_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('mkfs', {'device': '/dev/sdb1', 'fstype': 'ext4'})


class TestUnknownRecipe(unittest.TestCase):
    def test_unknown_recipe_rejected(self):
        with self.assertRaises(ValueError):
            api._sp_build('mdadm_delete_everything', {})


if __name__ == '__main__':
    unittest.main()
