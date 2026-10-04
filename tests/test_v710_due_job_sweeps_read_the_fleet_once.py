"""The two cron sweeps read the fleet through a shared view, not a fresh copy for every due job.

`process_schedule` (scheduled power and patch commands) and `process_backup_jobs` (cron backup jobs) each
called load(DEVICES_FILE) inside the loop, once per DUE job, and only looked devices up. A fleet-wide schedule
makes hundreds of jobs due in the same minute, and each one copied the whole fleet (116 ms at 2,000
devices), so the sweep took minutes and, on an install without the external scheduler, held every request
behind it. Both read the fleet with _load_ro now.

This drives the real sweeps with N due jobs and counts load() calls on the devices store, and checks what
each sweep queues, so a view that changed the outcome would fail as well.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-due-')
    spec = importlib.util.spec_from_file_location('api_v710_due', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.log_command = lambda *a, **k: None
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.logged = []

    def seed_devices(self, n):
        self.api.save(self.api.DEVICES_FILE, {'d%03d' % i: {'name': 'host-%03d' % i, 'token': 't', 'os': 'Ubuntu 22.04'}
                                              for i in range(n)})
        self.api.save(self.api.CMDS_FILE, {})
        self.api._LOAD_CACHE.clear()

    def run_counting(self, fn):
        """{store file name: load() calls} while `fn` runs."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        try:
            fn()
        finally:
            api.load = real
        return calls


class TestScheduledCommands(_Base):

    def seed_jobs(self, n):
        now = int(time.time())
        self.seed_devices(n)
        self.api.save(self.api.SCHEDULE_FILE, {'jobs': [
            {'id': 'j%03d' % i, 'device_id': 'd%03d' % i, 'device_name': 'host-%03d' % i, 'command': 'docker_prune',
             'run_at': now - 30, 'actor': 'alice'} for i in range(n)]})

    def test_devices_are_not_copied_per_due_job(self):
        self.seed_jobs(4)
        small = self.run_counting(self.api.process_schedule)
        self.seed_jobs(40)
        big = self.run_counting(self.api.process_schedule)
        self.assertEqual(40, len([k for k in (self.api.load(self.api.CMDS_FILE) or {})]), 'control: all 40 jobs should have queued a command')
        self.assertEqual(0, big.get('devices.json', 0), 'the fleet was copied %r times for 40 due jobs' % big.get('devices.json'))
        self.assertEqual(small.get('devices.json', 0), big.get('devices.json', 0))

    def test_each_due_job_still_queues_its_command_on_its_own_device(self):
        self.seed_jobs(5)
        self.api.process_schedule()
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertEqual({'d%03d' % i for i in range(5)}, set(cmds))
        for dev, queue in cmds.items():
            self.assertEqual(1, len(queue), (dev, queue))
            self.assertTrue(queue[0].startswith('exec:'), queue)
        self.assertEqual([], self.api.load(self.api.SCHEDULE_FILE)['jobs'], 'one-shot jobs should be consumed')

    def test_a_job_for_a_device_that_is_gone_queues_nothing(self):
        self.seed_jobs(3)
        sched = self.api.load(self.api.SCHEDULE_FILE)
        sched['jobs'][1]['device_id'] = 'ghost'
        self.api.save(self.api.SCHEDULE_FILE, sched)
        self.api.process_schedule()
        self.assertEqual({'d000', 'd002'}, set(self.api.load(self.api.CMDS_FILE)))

    def test_the_fleet_comes_out_unchanged(self):
        self.seed_jobs(6)
        import json
        before = json.dumps(self.api.load(self.api.DEVICES_FILE), sort_keys=True)
        self.api.process_schedule()
        self.assertEqual(before, json.dumps(self.api.load(self.api.DEVICES_FILE), sort_keys=True))


class TestCronBackupJobs(_Base):

    def seed_jobs(self, n):
        self.seed_devices(n)
        self.api.save(self.api.BACKUP_JOBS_FILE, {'jobs': [
            {'id': 'b%03d' % i, 'name': 'job%d' % i, 'type': 'command', 'command': 'restic backup /etc',
             'device_ids': ['d%03d' % i], 'device_id': 'd%03d' % i, 'device_name': 'host-%03d' % i,
             'enabled': True, 'cron': '* * * * *', 'created_by': 'alice', 'last_fired_minute': 0} for i in range(n)]})

    def test_devices_are_not_copied_per_due_job(self):
        self.seed_jobs(4)
        small = self.run_counting(self.api.process_backup_jobs)
        self.seed_jobs(40)
        big = self.run_counting(self.api.process_backup_jobs)
        queued = self.api.load(self.api.CMDS_FILE)
        self.assertEqual(40, len(queued), 'control: all 40 due jobs should have queued their command')
        self.assertEqual(0, big.get('devices.json', 0), 'the fleet was copied %r times for 40 due jobs' % big.get('devices.json'))
        self.assertEqual(small.get('devices.json', 0), big.get('devices.json', 0))

    def test_each_due_job_queues_its_command_and_is_marked_fired(self):
        self.seed_jobs(5)
        minute_before = int(time.time()) // 60
        self.api.process_backup_jobs()
        minute_after = int(time.time()) // 60
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertEqual({'d%03d' % i for i in range(5)}, set(cmds))
        for dev, queue in cmds.items():
            self.assertEqual(1, len(queue), (dev, queue))
            job_id = 'b' + dev[1:]
            self.assertTrue(queue[0].startswith('exec:') and 'restic backup /etc' in queue[0] and job_id in queue[0], queue)
        jobs = self.api.load(self.api.BACKUP_JOBS_FILE)['jobs']
        self.assertTrue(all(minute_before <= j['last_fired_minute'] <= minute_after for j in jobs), jobs)
        self.assertTrue(all(j['last_run'] for j in jobs))

    def test_a_quarantined_host_is_skipped(self):
        self.seed_jobs(3)
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['d001']['quarantined'] = True
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api.process_backup_jobs()
        self.assertEqual({'d000', 'd002'}, set(self.api.load(self.api.CMDS_FILE)))


if __name__ == '__main__':
    unittest.main()
