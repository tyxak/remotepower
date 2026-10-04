"""GET /api/backup-jobs reads the fleet once, however many jobs there are.

`_backup_job_visible(job)` loaded the devices store and ran the role-scope and tenant filters for EVERY job,
so the list cost jobs x fleet: 70 jobs on a 2,000-device fleet answered a 29 KB page in 9.7 s, nearly all of
it in copy.deepcopy (220 load() calls in one request). The list handler now builds the (all devices, visible
devices) pair once and passes it to every job.

This runs the real handler as a tenant-scoped admin and counts calls to api.load() while it does, so it
measures the thing that scaled. The visibility rule itself is checked alongside, because a hoist that
changed who sees which job would be worse than the slowness.
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
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-bjl-')
    spec = importlib.util.spec_from_file_location('api_v710_bjl', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api._LOAD_CACHE.clear()
        devices = {}
        for i in range(40):
            devices['devA%02d' % i] = {'name': 'a%02d' % i, 'tenant': 'tenantA', 'token': 'ta', 'ip': '10.0.0.%d' % (i + 1)}
            devices['devB%02d' % i] = {'name': 'b%02d' % i, 'tenant': 'tenantB', 'token': 'tb', 'ip': '10.1.0.%d' % (i + 1)}
        api.save(api.DEVICES_FILE, devices)
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'], self.cap['d'] = s, d
            raise api.HTTPError(s, d)
        api.respond = _respond
        api.method = lambda: 'GET'

    def as_tenant(self, tenant, role='admin'):
        api = self.api
        api.verify_token = lambda tok=None, _r=role: ('alice', _r)
        api.require_auth = lambda *a, **k: ('alice', role)
        api._caller_effective_tenant = lambda u, _t=tenant: _t
        api._caller_scope = lambda: None

    def seed_jobs(self, n_a, n_b, deleted=0):
        jobs = []
        for i in range(n_a):
            jobs.append({'id': 'ja%d' % i, 'name': 'a%d' % i, 'type': 'command', 'command': 'restic backup /etc',
                         'device_ids': ['devA%02d' % (i % 40)], 'enabled': True, 'cron': None})
        for i in range(n_b):
            jobs.append({'id': 'jb%d' % i, 'name': 'b%d' % i, 'type': 'command', 'command': 'restic backup /etc',
                         'device_ids': ['devB%02d' % (i % 40)], 'enabled': True, 'cron': None})
        for i in range(deleted):
            jobs.append({'id': 'jx%d' % i, 'name': 'x%d' % i, 'type': 'command', 'command': 'restic backup /etc',
                         'device_ids': ['gone%d' % i], 'enabled': True, 'cron': None})
        self.api.save(self.api.BACKUP_JOBS_FILE, {'jobs': jobs})

    def list_jobs(self):
        """(job ids, {store file name: load() calls}) for one real GET /api/backup-jobs."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            calls[Path(str(path)).name] = calls.get(Path(str(path)).name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        self.cap.clear()
        try:
            api.handle_backup_jobs_list()
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.load = real
        self.assertEqual(200, self.cap.get('s'), self.cap)
        return sorted(j['id'] for j in self.cap['d']['jobs']), calls


class TestTheListDoesNotReadTheFleetPerJob(_Base):

    def test_devices_are_read_at_most_once_and_the_count_does_not_grow_with_the_jobs(self):
        self.as_tenant('tenantA')
        self.seed_jobs(2, 2)
        ids_small, small = self.list_jobs()
        self.seed_jobs(30, 30)
        ids_big, big = self.list_jobs()
        self.assertEqual(2, len(ids_small), 'control: the small list should hold the two tenant-A jobs')
        self.assertEqual(30, len(ids_big), 'control: the big list should hold the thirty tenant-A jobs')
        self.assertLessEqual(big.get('devices.json', 0), 1, 'the devices store was loaded %r times for 30 jobs' % big.get('devices.json'))
        self.assertEqual(small.get('devices.json', 0), big.get('devices.json', 0))
        self.assertEqual(sum(small.values()), sum(big.values()),
                         'load() calls grew with the number of jobs: %r -> %r' % (small, big))


class TestWhoSeesWhichJobIsUnchanged(_Base):

    def test_a_tenant_sees_its_own_jobs_and_never_the_other_tenants(self):
        self.seed_jobs(3, 3)
        self.as_tenant('tenantA')
        ids, _ = self.list_jobs()
        self.assertEqual(['ja0', 'ja1', 'ja2'], ids)
        self.as_tenant('tenantB')
        ids, _ = self.list_jobs()
        self.assertEqual(['jb0', 'jb1', 'jb2'], ids)

    def test_a_job_whose_targets_were_all_deleted_belongs_to_an_unrestricted_caller_only(self):
        self.seed_jobs(1, 1, deleted=2)
        self.as_tenant('tenantA')
        ids, _ = self.list_jobs()
        self.assertEqual(['ja0'], ids, 'a tenant admin must not see a job whose devices are gone')
        self.as_tenant(self.api.DEFAULT_TENANT)
        ids, _ = self.list_jobs()
        self.assertEqual(['ja0', 'jb0', 'jx0', 'jx1'], ids)

    def test_update_and_delete_still_judge_one_job_without_a_prepared_view(self):
        """The two single-job callers pass no view; they build their own."""
        self.seed_jobs(1, 1)
        self.as_tenant('tenantA')
        visible = self.api._backup_job_visible
        jobs = self.api.load(self.api.BACKUP_JOBS_FILE)['jobs']
        self.assertTrue(visible(jobs[0]))
        self.assertFalse(visible(jobs[1]))


if __name__ == '__main__':
    unittest.main()
