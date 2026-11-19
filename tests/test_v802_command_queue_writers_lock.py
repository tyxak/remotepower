#!/usr/bin/env python3
"""The command queue is written under its lock by every writer: nothing a host was handed is queued again, nothing an administrator queued is lost.

27 functions of the server change the queue (commands.json: what each host is handed on its next heartbeat) under `_LockedUpdate(CMDS_FILE)`. Three read it whole and saved it
whole with no lock held across the pair: `process_backup_jobs` (every request, for each cron backup that is due), `_backup_queue_and_wait` (run-and-wait of a backup) and
`_rollout_tick` (a rollout advancing a ring). A heartbeat that hands a host its next command removes it under the lock, and an administrator who queues one adds it under the
lock; a save of the snapshot taken before either put the handed command back (the host was handed it a second time: a quarantine, an uninstall or a patch ran twice) and
removed the queued one (it was never sent). The window was the sweep itself, one history write for each job that is due.

Each writer is driven the way the finding was found: inside its own window a host takes its command through the real heartbeat and an administrator queues one for another host
through the same locked write the other 27 use, then the writer finishes.

* the host's command is not queued again, the administrator's command is there, and the writer's own commands are queued, for each of the three writers;
* the writer waits for the queue's lock when another request holds it, and what that request wrote is in the queue afterwards;
* the controls: the same window with nothing in it queues what the writer decided, and a command already in a host's queue is not queued twice.

The ratchet over every function of the server that saves the queue is in tests/test_v802_store_write_locks.py.
"""
import os
import sys
import tempfile
import threading
import unittest

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cmdqueue-'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stores_support as S  # noqa: E402

setUpModule, tearDownModule = S.set_up_module, S.tear_down_module
api = S.api

HOSTS = ('hx', 'hy', 'hz')
TOKEN = {h: ('t' + h) * 12 for h in HOSTS}
FIRST = 'exec:echo FIRST-COMMAND-OF-X'
FOR_Z = 'exec:echo QUEUED-BY-ADMIN-FOR-Z'
JOB = {'id': 'bj1', 'name': 'nightly', 'enabled': True, 'cron': '* * * * *', 'device_id': 'hy', 'command': 'echo backup', 'created_by': 'admin'}


class _Queue(S.Case):
    def setUp(self):
        super().setUp()
        api.save(api.CMDS_FILE, {})
        api.save(api.BACKUP_JOBS_FILE, {'jobs': []})
        api.save(api.ROLLOUTS_FILE, {'rollouts': []})
        api.save(api.LONGPOLL_FILE, {})
        for h in HOSTS:
            self.seed_device(h, name=h, token_hash=api._hash_device_token(TOKEN[h]), os='Debian GNU/Linux 12',
                             platform='Linux-6.1.0-18-amd64-x86_64-with-glibc2.36')
        self.put_queue(hx=[FIRST])

    def put_queue(self, **hosts):
        with api._LockedUpdate(api.CMDS_FILE) as c:
            for h, cmds in hosts.items():
                c[h] = list(cmds)
        api._LOAD_CACHE.clear()

    def queue(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CMDS_FILE)

    def host_takes_its_command(self, host='hx'):
        """The real heartbeat: the host reports and is handed the next command of its queue."""
        st, d = S.call('POST', '/api/heartbeat', {'device_id': host, 'token': TOKEN[host], 'sysinfo': {}})
        self.assertEqual(st, 200, d)
        return (d or {}).get('command') if isinstance(d, dict) else None

    def admin_queues_for_z(self):
        with api._LockedUpdate(api.CMDS_FILE) as c:
            c.setdefault('hz', []).append(FOR_Z)

    def in_the_window(self):
        """What happens inside the writer's window; remembered, so a test can say what the host was handed."""
        done = []

        def run():
            if not done:
                done.append(self.host_takes_its_command())
                self.admin_queues_for_z()
        return run, done


class TestProcessBackupJobs(_Queue):
    def setUp(self):
        super().setUp()
        api.save(api.BACKUP_JOBS_FILE, {'jobs': [dict(JOB)]})
        api._LOAD_CACHE.clear()

    def sweep_with(self, window):
        real = api.log_command

        def hooked(*a, **k):
            window()
            return real(*a, **k)

        api.log_command = hooked
        try:
            api.process_backup_jobs()
        finally:
            api.log_command = real
        return self.queue()

    def test_control_without_anything_in_the_window_the_job_is_queued_for_its_host(self):
        q = self.sweep_with(lambda: None)
        self.assertEqual(q.get('hy'), ['exec:: rp-bk:bj1; echo backup'])
        self.assertEqual(q.get('hx'), [FIRST], 'the other hosts are as they were')

    def test_a_command_the_host_was_handed_is_not_queued_again_and_the_administrators_is_kept(self):
        window, done = self.in_the_window()
        q = self.sweep_with(window)
        self.assertEqual(done, [FIRST], 'control: the host was handed its command in the window')
        self.assertNotIn(FIRST, q.get('hx') or [], 'the command the host was already handed was queued again: it would run twice')
        self.assertIn(FOR_Z, q.get('hz') or [], 'the command an administrator queued during the sweep is gone')
        self.assertEqual(q.get('hy'), ['exec:: rp-bk:bj1; echo backup'], 'and the sweep queued what it decided')

    def test_a_command_already_in_the_queue_is_not_queued_twice(self):
        self.put_queue(hy=['exec:: rp-bk:bj1; echo backup'])
        q = self.sweep_with(lambda: None)
        self.assertEqual(q.get('hy'), ['exec:: rp-bk:bj1; echo backup'])


class TestBackupQueueAndWait(_Queue):
    def setUp(self):
        super().setUp()
        self._wait = api._longpoll_wait
        api._longpoll_wait = lambda dev_id, timeout: ('ok', {'output': ''})      # the wait is for the host to answer; the queue write is what this is about
        self.addCleanup(setattr, api, '_longpoll_wait', self._wait)

    def run_fn(self):
        return api._backup_queue_and_wait('hy', 'echo hello', 'admin', 'hy', 'backup(run-and-wait)')

    def test_control_the_command_is_queued_for_its_host(self):
        self.run_fn()
        self.assertEqual(self.queue().get('hy'), ['exec:echo hello'])
        self.assertEqual(self.queue().get('hx'), [FIRST])

    def test_a_command_the_host_was_handed_is_not_queued_again_and_the_administrators_is_kept(self):
        # the window of the old code is between its read of the queue and its save of it; the save is where the test reaches in
        real_save, state = api.save, {}

        def hooked(path, data, *a, **k):
            if os.path.basename(str(path)) == 'commands.json' and 'done' not in state and sys._getframe(1).f_code.co_name == '_backup_queue_and_wait':
                state['done'] = True
                state['handed'] = self.host_takes_its_command()
                self.admin_queues_for_z()
            return real_save(path, data, *a, **k)

        api.save = hooked
        try:
            self.run_fn()
        finally:
            api.save = real_save
        if 'done' not in state:                  # a writer that holds the lock has no unlocked window to reach into: the same two requests come right after it
            state['handed'] = self.host_takes_its_command()
            self.admin_queues_for_z()
        q = self.queue()
        self.assertEqual(state['handed'], FIRST, 'control: the host was handed its command')
        self.assertNotIn(FIRST, q.get('hx') or [], 'the command the host was already handed was queued again: it would run twice')
        self.assertIn(FOR_Z, q.get('hz') or [], 'the command an administrator queued was lost')
        self.assertEqual(q.get('hy'), ['exec:echo hello'])


class TestMcpReboot(_Queue):
    """The fourth writer, found by reading each save of the queue instead of each function: the approved MCP reboot saved a snapshot while the branches around it locked."""

    def run_fn(self):
        return api._mcp_execute('reboot_device', 'hy', {}, 'admin', None, None)

    def test_control_the_reboot_is_queued_for_its_host(self):
        self.run_fn()
        self.assertEqual(self.queue().get('hy'), ['reboot'])
        self.assertEqual(self.queue().get('hx'), [FIRST])

    def test_a_command_the_host_was_handed_is_not_queued_again_and_the_administrators_is_kept(self):
        real_save, state = api.save, {}

        def hooked(path, data, *a, **k):
            if os.path.basename(str(path)) == 'commands.json' and 'done' not in state and sys._getframe(1).f_code.co_name == '_mcp_execute':
                state['done'] = True
                state['handed'] = self.host_takes_its_command()
                self.admin_queues_for_z()
            return real_save(path, data, *a, **k)

        api.save = hooked
        try:
            self.run_fn()
        finally:
            api.save = real_save
        if 'done' not in state:
            state['handed'] = self.host_takes_its_command()
            self.admin_queues_for_z()
        q = self.queue()
        self.assertEqual(state['handed'], FIRST, 'control: the host was handed its command')
        self.assertNotIn(FIRST, q.get('hx') or [], 'the command the host was already handed was queued again: it would run twice')
        self.assertIn(FOR_Z, q.get('hz') or [], 'the command an administrator queued was lost')
        self.assertEqual(q.get('hy'), ['reboot'])


class TestRolloutTick(_Queue):
    def start_rollout(self):
        st, d = S.call('POST', '/api/rollouts', {'name': 'ring-test', 'action': 'reboot', 'rings': [{'name': 'r1', 'selector': {'type': 'ids', 'ids': ['hy']}}]},
                       token=self.admin)
        self.assertEqual(st, 200, d)
        rid = d['rollout']['id']
        # running, with its first ring still to be dispatched: the start route ticks at once, and a ring it has already dispatched leaves the tick nothing to write
        with api._LockedUpdate(api.ROLLOUTS_FILE) as store:
            for roll in store['rollouts']:
                if roll['id'] == rid:
                    roll['state'] = 'running'
        api._LOAD_CACHE.clear()
        return rid

    def tick_with(self, window):
        real = api._rollout_advance

        def hooked(*a, **k):
            out = real(*a, **k)
            window()
            return out

        api._rollout_advance = hooked
        try:
            api._rollout_tick()
        finally:
            api._rollout_advance = real
        return self.queue()

    def test_control_the_ring_is_dispatched_to_its_host(self):
        self.start_rollout()
        q = self.tick_with(lambda: None)
        self.assertEqual(q.get('hy'), ['reboot'])
        self.assertEqual(q.get('hx'), [FIRST])

    def test_a_command_the_host_was_handed_is_not_queued_again_and_the_administrators_is_kept(self):
        self.start_rollout()
        # The tick holds the rollouts lock while it advances, so the two requests run in a thread of their own. On JSON and Postgres they get through inside the tick's window.
        # On SQLite the tick holds the one write lock of the database, so they wait until it has committed: there is no window, and the same assertions hold.
        done, errors = [], []

        def requests():
            try:
                done.append(self.host_takes_its_command())
                self.admin_queues_for_z()
            except BaseException as e:      # noqa: BLE001  (reported by the assertion below, not lost in a thread)
                errors.append(e)

        t = threading.Thread(target=requests)

        def window():
            t.start()
            t.join(2.5)

        q = self.tick_with(window)
        t.join(30)
        q = self.queue()
        self.assertEqual(errors, [])
        self.assertEqual(done, [FIRST], 'control: the host was handed its command')
        self.assertNotIn(FIRST, q.get('hx') or [], 'the command the host was already handed was queued again: it would run twice')
        self.assertIn(FOR_Z, q.get('hz') or [], 'the command an administrator queued during the tick is gone')
        self.assertEqual(q.get('hy'), ['reboot'], 'and the ring was dispatched')

    def test_the_ring_is_dispatched_once_when_its_command_is_already_queued(self):
        self.start_rollout()
        self.put_queue(hy=['reboot'])
        q = self.tick_with(lambda: None)
        self.assertEqual(q.get('hy'), ['reboot'])


class TestTheWritersWaitForTheLock(_Queue):
    """While another request holds the queue's lock the writer does not write: it waits, and what that request wrote is in the queue afterwards."""

    def holder(self, release):
        started = threading.Event()

        def run():
            with api._LockedUpdate(api.CMDS_FILE) as c:
                started.set()
                release.wait(20)
                c.setdefault('hz', []).append(FOR_Z)

        t = threading.Thread(target=run)
        t.start()
        self.assertTrue(started.wait(10))
        return t

    def check(self, fn):
        release, finished = threading.Event(), threading.Event()
        t_hold = self.holder(release)

        def writer():
            fn()
            finished.set()

        t_w = threading.Thread(target=writer)
        t_w.start()
        waited = not finished.wait(0.6)
        release.set()
        t_hold.join(20)
        t_w.join(20)
        self.assertTrue(waited, 'the writer finished while another request held the queue: it wrote without the lock')
        self.assertIn(FOR_Z, self.queue().get('hz') or [], 'what the other request wrote while it held the lock was overwritten')
        self.assertTrue(finished.is_set())

    def test_run_and_wait_of_a_backup(self):
        real = api._longpoll_wait
        api._longpoll_wait = lambda dev_id, timeout: ('ok', {'output': ''})
        self.addCleanup(setattr, api, '_longpoll_wait', real)
        self.check(lambda: api._backup_queue_and_wait('hy', 'echo hello', 'admin', 'hy', 'backup(run-and-wait)'))
        self.assertEqual(self.queue().get('hy'), ['exec:echo hello'])

    def test_the_cron_sweep(self):
        api.save(api.BACKUP_JOBS_FILE, {'jobs': [dict(JOB)]})
        api._LOAD_CACHE.clear()
        self.check(api.process_backup_jobs)
        self.assertEqual(self.queue().get('hy'), ['exec:: rp-bk:bj1; echo backup'])

    def test_the_rollout_tick(self):
        TestRolloutTick.start_rollout(self)
        self.check(api._rollout_tick)
        self.assertEqual(self.queue().get('hy'), ['reboot'])

    def test_the_approved_mcp_reboot(self):
        self.check(lambda: api._mcp_execute('reboot_device', 'hy', {}, 'admin', None, None))
        self.assertEqual(self.queue().get('hy'), ['reboot'])


if __name__ == '__main__':
    unittest.main()
