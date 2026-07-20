"""v6.3.0: file-backup job handler wiring — create / run (command gen) / restore.

Complements test_v630_filebackup (the pure generator). Here we drive the real
handlers to confirm: a structured 'file' job is created + validated, running it
queues the GENERATED command, and restore is gated (admin + typed confirm +
tenant scope) and queues the reverse command.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v630-fbh-')
    spec = importlib.util.spec_from_file_location('api_v630_fbh', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.api._LOAD_CACHE.clear()
        self.api.save(self.api.CONFIG_FILE, {})
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1', 'token': 't'}})
        self.api.save(self.api.CMDS_FILE, {})
        self.api.save(self.api.BACKUP_JOBS_FILE, {'jobs': []})
        self.api.audit_log = lambda *a, **k: None
        self.api.log_command = lambda *a, **k: None
        self.api.require_admin_auth = lambda *a, **k: 'admin'
        self.api.require_perm = lambda *a, **k: 'admin'
        self.api._scope_block_device = lambda *a, **k: None
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _respond
        self.api.method = lambda: 'POST'

    def _spec(self):
        return {'paths': ['/etc', '/var/www'], 'method': 'rsync',
                'dest': {'transport': 'ssh', 'host': 'nas', 'user': 'bak',
                         'remote_path': '/backups/h1', 'port': 22}}

    def _create(self, body):
        self.api.get_json_obj = lambda: body
        try:
            self.api.handle_backup_job_create()
        except (self.api.HTTPError, SystemExit):
            pass
        return self.cap

    def _jobs(self):
        return (self.api.load(self.api.BACKUP_JOBS_FILE) or {}).get('jobs', [])

    def _cmds(self):
        return self.api.load(self.api.CMDS_FILE) or {}


class TestCreate(_Base):
    def test_create_file_job(self):
        self._create({'name': 'nightly', 'device_id': 'd1', 'spec': self._spec(),
                      'cron': '0 2 * * *'})
        jobs = self._jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['type'], 'file')
        self.assertEqual(jobs[0]['spec']['method'], 'rsync')

    def test_create_rejects_bad_spec(self):
        bad = self._spec(); bad['paths'] = ['/etc;rm -rf /']
        self.cap.clear()
        self._create({'name': 'x', 'device_id': 'd1', 'spec': bad})
        self.assertEqual(self.cap.get('s'), 400)
        self.assertEqual(self._jobs(), [])

    def test_legacy_command_job_still_works(self):
        self._create({'name': 'legacy', 'device_id': 'd1', 'command': 'restic backup /etc'})
        jobs = self._jobs()
        self.assertEqual(jobs[0]['type'], 'command')
        self.assertEqual(jobs[0]['command'], 'restic backup /etc')


class TestRunGeneratesCommand(_Base):
    def test_run_queues_generated_command(self):
        self._create({'name': 'nightly', 'device_id': 'd1', 'spec': self._spec()})
        jid = self._jobs()[0]['id']
        self.cap.clear()
        try:
            self.api.handle_backup_job_run(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        queued = self._cmds().get('d1', [])
        self.assertEqual(len(queued), 1)
        self.assertTrue(queued[0].startswith('exec:rsync -a --info=progress2'))
        self.assertIn('bak@nas:', queued[0])


class TestRestore(_Base):
    def _job(self):
        self._create({'name': 'nightly', 'device_id': 'd1', 'spec': self._spec()})
        return self._jobs()[0]['id']

    def _restore(self, jid, body):
        self.api.get_json_obj = lambda: body
        self.cap.clear()
        try:
            self.api.handle_backup_job_restore(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        return self.cap

    def test_restore_requires_confirm(self):
        jid = self._job()
        self._restore(jid, {'restore_path': '/restore'})   # no confirm
        self.assertEqual(self.cap.get('s'), 400)
        self.assertEqual(self._cmds().get('d1', [])[1:], [])   # nothing new queued

    def test_restore_queues_reverse_command(self):
        jid = self._job()
        self._restore(jid, {'restore_path': '/restore/here', 'confirm': 'RESTORE'})
        queued = self._cmds().get('d1', [])
        # the run wasn't called, so only the restore command is queued
        self.assertTrue(any('exec:rsync' in c and '/restore/here/' in c for c in queued),
                        queued)

    def test_restore_rejects_bad_restore_path(self):
        jid = self._job()
        self._restore(jid, {'restore_path': '/restore;rm -rf /', 'confirm': 'RESTORE'})
        self.assertEqual(self.cap.get('s'), 400)

    def test_restore_only_for_file_jobs(self):
        self._create({'name': 'legacy', 'device_id': 'd1', 'command': 'restic backup /etc'})
        jid = self._jobs()[0]['id']
        self._restore(jid, {'restore_path': '/restore', 'confirm': 'RESTORE'})
        self.assertEqual(self.cap.get('s'), 400)


class TestMultiDeviceBaseline(_Base):
    """v6.3.0 baseline: one job → many devices."""

    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'h1', 'token': 't'},
            'd2': {'id': 'd2', 'name': 'h2', 'token': 't'},
            'd3': {'id': 'd3', 'name': 'h3', 'token': 't'},
        })

    def test_create_multi_device_job(self):
        self._create({'name': 'fleet', 'device_ids': ['d1', 'd2', 'd3'],
                      'command': 'restic backup /etc'})
        j = self._jobs()[0]
        self.assertEqual(sorted(j['device_ids']), ['d1', 'd2', 'd3'])
        self.assertIn('+2 more', j['device_name'])

    def test_run_fans_out_to_all_targets(self):
        self._create({'name': 'fleet', 'device_ids': ['d1', 'd2', 'd3'],
                      'command': 'restic backup /etc'})
        jid = self._jobs()[0]['id']
        self.cap.clear()
        self.api.get_json_obj = lambda: {}
        try:
            self.api.handle_backup_job_run(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        cmds = self._cmds()
        self.assertTrue(all(d in cmds for d in ('d1', 'd2', 'd3')),
                        'run should queue on every target')
        self.assertEqual(self.cap.get('d', {}).get('queued'), 3)

    def test_restore_needs_device_when_multi(self):
        self._create({'name': 'fleet', 'device_ids': ['d1', 'd2'], 'spec': self._spec()})
        jid = self._jobs()[0]['id']
        self.cap.clear()
        self.api.get_json_obj = lambda: {'restore_path': '/r', 'confirm': 'RESTORE'}
        try:
            self.api.handle_backup_job_restore(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 400)   # must specify device_id

    def test_restore_to_named_target(self):
        self._create({'name': 'fleet', 'device_ids': ['d1', 'd2'], 'spec': self._spec()})
        jid = self._jobs()[0]['id']
        self.cap.clear()
        self.api.get_json_obj = lambda: {'restore_path': '/r', 'confirm': 'RESTORE', 'device_id': 'd2'}
        try:
            self.api.handle_backup_job_restore(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertIn('d2', self._cmds())

    def test_restore_rejects_non_target_device(self):
        self._create({'name': 'fleet', 'device_ids': ['d1'], 'spec': self._spec()})
        jid = self._jobs()[0]['id']
        self.cap.clear()
        self.api.get_json_obj = lambda: {'restore_path': '/r', 'confirm': 'RESTORE', 'device_id': 'd3'}
        try:
            self.api.handle_backup_job_restore(jid)
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 400)   # d3 not a target


if __name__ == '__main__':
    unittest.main()
