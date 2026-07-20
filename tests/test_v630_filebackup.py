"""v6.3.0: structured file-backup command generation + injection resistance.

filebackup.build_backup_command runs as ROOT on the host, so these tests are the
security contract: (1) every field is validated against a strict allowlist and a
malformed/injection value is REJECTED, never quietly escaped into the command;
(2) the generated command is well-formed and contains no unescaped shell
metacharacters from operator input.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import filebackup as F  # noqa: E402


def _ssh_rsync():
    return {'paths': ['/etc', '/var/www'], 'method': 'rsync',
            'dest': {'transport': 'ssh', 'host': 'backup.example.com',
                     'user': 'bak', 'remote_path': '/backups/h1', 'port': 22}}


class TestValidation(unittest.TestCase):
    def test_valid_ssh_rsync(self):
        ok, err = F.validate_spec(_ssh_rsync())
        self.assertTrue(ok, err)

    def test_rejects_no_paths(self):
        s = _ssh_rsync(); s['paths'] = []
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_relative_path(self):
        s = _ssh_rsync(); s['paths'] = ['etc/passwd']
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_traversal(self):
        s = _ssh_rsync(); s['paths'] = ['/var/../etc/shadow']
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_shell_metachars_in_path(self):
        for bad in ['/etc;rm -rf /', '/etc$(whoami)', '/etc`id`', '/etc|nc evil 1',
                    '/etc&& curl evil', '/etc\nrm', '/etc>x']:
            s = _ssh_rsync(); s['paths'] = [bad]
            self.assertFalse(F.validate_spec(s)[0], f'accepted {bad!r}')

    def test_rejects_bad_host(self):
        for bad in ['a b', 'a;b', 'a$(b)', '../evil', 'a/b']:
            s = _ssh_rsync(); s['dest']['host'] = bad
            self.assertFalse(F.validate_spec(s)[0], f'accepted host {bad!r}')

    def test_rejects_bad_user(self):
        s = _ssh_rsync(); s['dest']['user'] = 'root; rm'
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_spaces_in_remote_path(self):
        s = _ssh_rsync(); s['dest']['remote_path'] = '/backups/my host'
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_bad_method_transport(self):
        s = _ssh_rsync(); s['method'] = 'dd'
        self.assertFalse(F.validate_spec(s)[0])
        s = _ssh_rsync(); s['dest']['transport'] = 'ftp'
        self.assertFalse(F.validate_spec(s)[0])

    def test_rejects_bad_port(self):
        for bad in [0, 70000, 'x', -1]:
            s = _ssh_rsync(); s['dest']['port'] = bad
            self.assertFalse(F.validate_spec(s)[0], f'accepted port {bad!r}')


class TestGeneration(unittest.TestCase):
    def test_ssh_rsync_command(self):
        cmd = F.build_backup_command(_ssh_rsync(), 'job-abc')
        self.assertIn('rsync -a --info=progress2', cmd)
        self.assertIn('BatchMode=yes', cmd)
        self.assertIn('bak@backup.example.com:', cmd)   # safe value → shlex adds no quotes
        self.assertIn('/etc', cmd)
        self.assertIn('/var/www', cmd)

    def test_ssh_tar_command_is_timestamped(self):
        s = _ssh_rsync(); s['method'] = 'tar'
        cmd = F.build_backup_command(s, 'job-abc')
        self.assertIn('tar czf -', cmd)
        self.assertIn('job-abc-$(date', cmd)
        self.assertIn('.tar.gz', cmd)

    def test_nfs_mounts_and_always_unmounts(self):
        s = {'paths': ['/data'], 'method': 'rsync',
             'dest': {'transport': 'nfs', 'host': 'nas', 'export': '/export/bak',
                      'remote_path': '/h1'}}
        cmd = F.build_backup_command(s, 'j1')
        self.assertIn('mount -t nfs', cmd)
        self.assertIn('umount', cmd)
        # unmount is in both the success and failure arms
        self.assertGreaterEqual(cmd.count('umount'), 2)

    def test_smb_uses_credentials_file_not_inline_password(self):
        s = {'paths': ['/data'], 'method': 'tar',
             'dest': {'transport': 'smb', 'host': 'nas', 'share': 'backups',
                      'remote_path': '/h1', 'credentials_file': '/etc/rp/smb.cred'}}
        cmd = F.build_backup_command(s, 'j1')
        self.assertIn('mount -t cifs', cmd)
        self.assertIn('credentials=', cmd)
        # never an inline password= in the generated command
        self.assertNotIn('password=', cmd)

    def test_generation_raises_on_invalid_spec(self):
        s = _ssh_rsync(); s['paths'] = ['/etc;rm']
        with self.assertRaises(ValueError):
            F.build_backup_command(s, 'j1')

    def test_generation_rejects_bad_job_id(self):
        with self.assertRaises(ValueError):
            F.build_backup_command(_ssh_rsync(), 'job; rm -rf /')


class TestRestore(unittest.TestCase):
    def test_ssh_rsync_restore_pulls_back(self):
        cmd = F.build_restore_command(_ssh_rsync(), '/restore/here', 'job-abc')
        self.assertIn('rsync', cmd)
        self.assertIn('bak@backup.example.com:', cmd)   # safe value → no quotes
        self.assertTrue(cmd.rstrip().endswith('/restore/here/'))

    def test_tar_restore_needs_archive(self):
        s = _ssh_rsync(); s['method'] = 'tar'
        with self.assertRaises(ValueError):
            F.build_restore_command(s, '/restore', 'j1')   # no archive
        cmd = F.build_restore_command(s, '/restore', 'j1', archive='j1-20260101.tar.gz')
        self.assertIn('tar xzf -', cmd)

    def test_restore_rejects_bad_target(self):
        with self.assertRaises(ValueError):
            F.build_restore_command(_ssh_rsync(), '/restore;rm', 'j1')

    def test_restore_rejects_injection_archive(self):
        s = _ssh_rsync(); s['method'] = 'tar'
        with self.assertRaises(ValueError):
            F.build_restore_command(s, '/restore', 'j1', archive='x.tar.gz; rm -rf /')


if __name__ == '__main__':
    unittest.main()
