"""v6.4.1 — backup at-rest hygiene.

Field report: "sometimes I see unencrypted backups", with a listing showing a
192K 0644 `*.tar.gz` sitting between healthy 4.6M 0600 `*.tar.gz.enc` archives.

Three distinct defects behind it:

1. **A second instance wrote into the first one's backup directory.** The
   default backup path was the hardcoded absolute `/var/lib/remotepower/backups`
   rather than `<RP_DATA_DIR>/backups`, so the read-only demo instance (its own
   gunicorn, `RP_DATA_DIR=/var/lib/remotepower-demo`, no RP_BACKUP_PASSPHRASE)
   dropped small plaintext archives into production's directory. That is the
   192K file. It also meant each instance's pruner deleted the other's
   archives, and the restore drill (which picks the NEWEST archive) could
   verify the demo's data while reporting on production.

2. **The plaintext tarball was written to its FINAL name, then encrypted.** So a
   complete readable copy of the whole data dir existed at the resting name for
   the length of the run — and if the process died in that window (a deploy
   restarting the service, an OOM), the partial plaintext stayed forever and
   was retained by the pruner as if it were a backup.

3. **It was created with the default umask (0644), not 0600.** Same for the
   pre-restore snapshot, which was additionally never encrypted and never
   pruned — so every restore left a permanent unencrypted image of the install.
"""

import importlib.machinery
import importlib.util
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_ldr = importlib.machinery.SourceFileLoader('api', str(_CGI / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _BackupCase(unittest.TestCase):
    def setUp(self):
        self._real_pp = api._backup_passphrase
        self.cap = {}
        self._real_resp = api.respond

        def _resp(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # The backup directory is derived from RP_DATA_DIR, which every test
        # module in a given xdist worker shares — so any other module that
        # runs a backup leaves archives here. Asserting "no *.tar.gz exists"
        # against a directory we never reset is the order-dependent
        # false-failure class: green alone, red only under a particular
        # cross-module order.
        d = Path(api._default_backup_dir())
        if d.is_dir():
            for f in d.glob('remotepower_data_*'):
                try:
                    f.unlink()
                except OSError:
                    pass

    def tearDown(self):
        api._backup_passphrase = self._real_pp
        api.respond = self._real_resp

    def _run(self, passphrase=''):
        api._backup_passphrase = lambda: passphrase
        return api._run_data_backup(triggered_by='manual')

    @staticmethod
    def _mode(p):
        return stat.S_IMODE(os.stat(p).st_mode)


class TestBackupDirIsPerInstance(unittest.TestCase):
    """Defect 1 — the one that actually produced the reported file."""

    def test_default_is_derived_from_the_data_dir(self):
        self.assertEqual(api._default_backup_dir(),
                         str(api.DATA_DIR / 'backups'))

    def test_no_hardcoded_absolute_default_remains(self):
        """A literal path here makes every co-hosted instance share a
        directory: crossed retention, a restore drill verifying the wrong
        instance, and someone else's plaintext among your encrypted archives."""
        for rel in ('server/cgi-bin/backups_handlers.py', 'server/cgi-bin/api.py'):
            src = (_ROOT / rel).read_text()
            code = '\n'.join(l for l in src.splitlines()
                             if not l.lstrip().startswith('#'))
            # Allow the explanatory docstring, reject an executable default.
            self.assertNotIn("or '/var/lib/remotepower/backups'", code, rel)
            self.assertNotIn('or "/var/lib/remotepower/backups"', code, rel)

    def test_two_instances_do_not_share_a_directory(self):
        """The demo runs the same code with a different RP_DATA_DIR."""
        a = Path(tempfile.mkdtemp()) / 'inst-a'
        b = Path(tempfile.mkdtemp()) / 'inst-b'
        real = api.DATA_DIR
        try:
            api.DATA_DIR = a
            first = api._default_backup_dir()
            api.DATA_DIR = b
            second = api._default_backup_dir()
        finally:
            api.DATA_DIR = real
        self.assertNotEqual(first, second)


class TestArchivesArePrivateAndComplete(_BackupCase):
    """Defects 2 and 3."""

    def test_plaintext_archive_is_0600_not_world_readable(self):
        self._run(passphrase='')
        self.assertEqual(self._mode(self._newest()), 0o600,
                         'a plaintext DR archive must never be world-readable')

    def _newest(self):
        d = Path(api._default_backup_dir())
        files = sorted(d.glob('remotepower_data_*'), key=lambda f: f.stat().st_mtime)
        self.assertTrue(files, 'no archive produced')
        return files[-1]

    def test_encrypted_archive_is_0600(self):
        self._run(passphrase='a-long-enough-passphrase')
        p = self._newest()
        self.assertTrue(str(p).endswith('.enc'))
        self.assertEqual(self._mode(p), 0o600)

    def test_no_plaintext_survives_an_encrypted_run(self):
        self._run(passphrase='a-long-enough-passphrase')
        d = Path(api._default_backup_dir())
        self.assertEqual(list(d.glob('remotepower_data_*.tar.gz')), [],
                         'the plaintext working copy must be removed')

    def test_working_copy_is_not_written_under_the_final_name(self):
        """Source pin: the whole point is that a *.tar.gz appearing in the
        directory is always a COMPLETE archive, never a run in progress."""
        src = (_CGI / 'backups_handlers.py').read_text()
        fn = src[src.index('def _run_data_backup'):]
        fn = fn[:fn.index('\ndef ')]
        self.assertIn('.partial', fn, 'build under a non-final temp name')
        self.assertIn('os.replace', fn, 'publish atomically')
        self.assertNotIn("tarfile.open(str(out_path)", fn,
                         'must not tar straight to the resting name')

    def test_interrupted_run_leaves_no_archive_shaped_file(self):
        """Simulate the reported crash: die mid-tar. Whatever is left must not
        match the archive globs, so the pruner cannot retain it and the UI
        cannot list it as a backup."""
        d = Path(api._default_backup_dir())
        d.mkdir(parents=True, exist_ok=True)
        for f in d.glob('remotepower_data_*'):
            f.unlink()
        boom = RuntimeError('service restarted mid-backup')
        real_walk = os.walk

        def _explode(*a, **k):
            raise boom
        os.walk = _explode
        try:
            with self.assertRaises(Exception):
                self._run(passphrase='')
        finally:
            os.walk = real_walk
        self.assertEqual(list(d.glob('remotepower_data_*.tar.gz')), [],
                         'a killed run must not leave an archive-named file')
        self.assertEqual(list(d.glob('remotepower_data_*.tar.gz.enc')), [])

    def test_stale_partials_are_swept(self):
        d = Path(api._default_backup_dir())
        d.mkdir(parents=True, exist_ok=True)
        stale = d / '.remotepower_data_old.999.partial'
        stale.write_bytes(b'leftover plaintext')
        os.utime(stale, (time.time() - 86400, time.time() - 86400))
        fresh = d / '.remotepower_data_new.998.partial'
        fresh.write_bytes(b'a concurrent run')
        api._sweep_stale_partials(d)
        self.assertFalse(stale.exists(), 'abandoned plaintext must be removed')
        self.assertTrue(fresh.exists(),
                        "a concurrent run's partial must be left alone")

    def test_partial_name_matches_neither_prune_glob(self):
        """If it matched, a leftover would be listed and retained as a backup."""
        name = '.remotepower_data_20260725_082543.1234.partial'
        d = Path(tempfile.mkdtemp())
        (d / name).write_bytes(b'x')
        self.assertEqual(list(d.glob('remotepower_data_*.tar.gz')), [])
        self.assertEqual(list(d.glob('remotepower_data_*.tar.gz.enc')), [])


class TestPreRestoreSnapshotIsProtected(unittest.TestCase):
    """The snapshot taken before a restore is a full copy of the data dir —
    tokens, API keys, the vault blob, the audit log. It was plaintext with
    umask perms regardless of RP_BACKUP_PASSPHRASE, and nothing pruned it."""

    def test_snapshot_is_encrypted_when_a_passphrase_is_set(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        i = src.index('# 1) Safety snapshot')
        blk = src[i:src.index('# 2) Open + validate', i)]
        self.assertIn('_backup_passphrase', blk,
                      'the pre-restore snapshot must honour the passphrase')
        self.assertIn('encrypt_file', blk)

    def test_snapshot_is_created_0600(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        blk = src[src.index("_snap_work = snap_dir"):]
        blk = blk[:blk.index('# 2) Open + validate')]
        self.assertIn('0o600', blk)

    def test_snapshot_dir_is_0700(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        self.assertIn('snap_dir.mkdir(parents=True, exist_ok=True, mode=0o700)', src)


if __name__ == '__main__':
    unittest.main()
