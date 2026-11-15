"""The "agent uninstalled" mark follows what became of the command (8.0.1).

Pressing Uninstall agent marks the host and queues `uninstall`. Three things were wrong with what happened next:

  * the command goes out WITH a heartbeat, and every heartbeat cleared the mark. So the beat that delivered the
    uninstall took the mark away and wrote "agent_reinstalled" to the audit log;
  * the Hosts list never carried the mark, so the badge the page has drawn from it since v3.3.0 never showed;
  * an uninstall that a second admin approved, or that was queued some other way, was never marked at all.

The mark is settled now where every uninstall passes: the heartbeat that hands commands out. Driven here through the
real handlers (the button, the heartbeat, the Hosts list), with the clock set by the test.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_APP = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
T = 1_800_000_000
HAVE_NODE = shutil.which('node') is not None
KEYS = ('agent_uninstalled', 'agent_uninstalled_at', 'agent_uninstalled_by', 'agent_uninstall_sent_at')


class _Uninstall(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.CMDS_FILE, {})
        api.save(api.AUDIT_LOG_FILE, [])
        api._LOAD_CACHE.clear()
        self._saved = (api.require_admin_auth, api.require_auth, api.method, api.get_json_obj, api.verify_token)

    def tearDown(self):
        (api.require_admin_auth, api.require_auth, api.method, api.get_json_obj, api.verify_token) = self._saved
        super().tearDown()

    def click(self, at=T):
        """The operator presses Uninstall agent: the real handler, signed in as an administrator."""
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {}
        try:
            with mock.patch('time.time', return_value=at):
                api.handle_uninstall_agent(DEV)
        except _Captured as c:
            return c.status, c.body
        finally:
            api.require_admin_auth, api.method, api.get_json_obj = self._saved[0], self._saved[2], self._saved[3]
            api._LOAD_CACHE.clear()
        self.fail('the handler did not answer')

    def beat(self, at):
        """The agent's heartbeat at `at`, through the real handler. Returns what the agent is told."""
        raw = json.dumps({'device_id': DEV, 'token': 'tok'}).encode()
        os.environ.update({'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/heartbeat', 'QUERY_STRING': '',
                           'CONTENT_LENGTH': str(len(raw))})
        for k in ('HTTP_X_TOKEN', 'HTTP_X_RP_VAULT_KEY'):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            with mock.patch('time.time', return_value=at):
                api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            api._LOAD_CACHE.clear()
            return c.body
        self.fail('the heartbeat did not answer')

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(DEV, {})

    def mark(self):
        d = self.stored()
        return {k: d[k] for k in KEYS if k in d}

    def queue(self):
        api._LOAD_CACHE.clear()
        return list((api.load(api.CMDS_FILE) or {}).get(DEV) or [])

    def set_queue(self, cmds):
        api.save(api.CMDS_FILE, {DEV: list(cmds)})
        api._LOAD_CACHE.clear()

    def audit(self):
        api._LOAD_CACHE.clear()
        log = api.load(api.AUDIT_LOG_FILE)
        rows = log.get('entries') if isinstance(log, dict) else log
        return [r.get('action') for r in (rows or []) if isinstance(r, dict)
                and ('uninstall' in str(r.get('action')) or 'reinstall' in str(r.get('action')))]

    def row(self, at=T):
        """This host's row as the Hosts page gets it, from the real list handler."""
        api.verify_token = lambda _t=None: ('admin', 'admin')
        api.method = lambda: 'GET'
        os.environ.update({'REQUEST_METHOD': 'GET', 'PATH_INFO': '/api/devices', 'QUERY_STRING': ''})
        api._LOAD_CACHE.clear()
        try:
            with mock.patch('time.time', return_value=at):
                api.handle_devices_list()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            body = c.body
        except api.HTTPError as e:
            body = e.body if isinstance(e.body, (dict, list)) else json.loads(e.body)
        finally:
            api.verify_token, api.method = self._saved[4], self._saved[2]
        rows = body.get('devices') if isinstance(body, dict) else body
        return next(r for r in rows if r['id'] == DEV)


class TestTheButton(_Uninstall):
    def test_it_marks_the_host_and_queues_the_command(self):
        self.assertEqual(self.click(), (200, {'ok': True, 'queued': 'uninstall'}))
        self.assertEqual(self.mark(), {'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstalled_by': 'admin'})
        self.assertEqual(self.queue(), ['uninstall'])
        self.assertEqual(self.audit(), ['agent_uninstall_queued'])


class TestTheHeartbeatThatDeliversIt(_Uninstall):
    def test_it_hands_the_command_over_and_keeps_the_mark(self):
        self.click()
        told = self.beat(T + 30)
        self.assertEqual(told['command'], 'uninstall')
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.mark(), {'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstalled_by': 'admin',
                                       'agent_uninstall_sent_at': T + 30})
        self.assertEqual(self.audit(), ['agent_uninstall_queued'], 'the agent that is being told to go has not come back')

    def test_a_beat_while_the_agent_is_on_its_way_out_changes_nothing(self):
        self.click()
        self.beat(T + 30)
        before = self.mark()
        for later in (31, 90, api.UNINSTALL_SETTLE_S + 29):
            self.assertIsNone(self.beat(T + later)['command'])
            self.assertEqual(self.mark(), before, later)
        self.assertEqual(self.audit(), ['agent_uninstall_queued'])

    def test_an_agent_that_still_reports_after_that_is_back_and_the_log_says_so(self):
        self.click()
        self.beat(T + 30)
        self.beat(T + 30 + api.UNINSTALL_SETTLE_S)
        self.assertEqual(self.mark(), {}, 'every part of the mark is gone')
        self.assertEqual(self.audit(), ['agent_uninstall_queued', 'agent_reinstalled'])
        self.beat(T + 30 + api.UNINSTALL_SETTLE_S + 60)
        self.assertEqual(self.audit().count('agent_reinstalled'), 1, 'said once')

    def test_the_settle_time_is_minutes_and_not_a_poll(self):
        self.assertGreaterEqual(api.UNINSTALL_SETTLE_S, 120)
        self.assertLessEqual(api.UNINSTALL_SETTLE_S, 900)


class TestAnUninstallThatIsStillWaiting(_Uninstall):
    def test_a_host_that_has_not_reported_keeps_its_request(self):
        self.click()
        row = self.row(T + 86400)
        self.assertEqual((row['agent_uninstalled'], row['agent_uninstalled_at'], row['agent_uninstall_sent_at']), (True, T, 0))
        self.assertEqual(self.queue(), ['uninstall'], 'it waits for the host')

    def test_a_command_ahead_of_it_goes_first_and_the_request_waits(self):
        self.set_queue(['poll_interval:120'])
        self.click()
        self.assertEqual(self.queue(), ['poll_interval:120', 'uninstall'])
        self.assertEqual(self.beat(T + 30)['command'], 'poll_interval:120')
        self.assertEqual(self.mark().get('agent_uninstall_sent_at'), None, 'not handed over yet')
        self.assertTrue(self.mark()['agent_uninstalled'])
        self.assertEqual(self.beat(T + 90)['command'], 'uninstall')
        self.assertEqual(self.mark()['agent_uninstall_sent_at'], T + 90)
        self.assertEqual(self.audit(), ['agent_uninstall_queued'])

    def test_an_uninstall_that_left_the_queue_is_taken_back_and_is_not_a_reinstall(self):
        self.click()
        self.set_queue([])
        self.assertIsNone(self.beat(T + 30)['command'])
        self.assertEqual(self.mark(), {})
        self.assertEqual(self.audit(), ['agent_uninstall_queued', 'agent_uninstall_dropped'])

    def test_a_quarantined_host_is_not_told_and_the_request_goes_with_the_dropped_command(self):
        self.click()
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]['quarantined'] = True
        self.assertIsNone(self.beat(T + 30)['command'], 'a quarantined host acts on nothing')
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.mark(), {})
        self.assertIn('agent_uninstall_dropped', self.audit())
        self.assertNotIn('agent_reinstalled', self.audit())


class TestAnUninstallQueuedAnotherWay(_Uninstall):
    def test_it_is_marked_when_it_goes_out(self):
        """An approval a second admin gives queues the command and marks nothing. The heartbeat is where it is seen."""
        self.set_queue(['uninstall'])
        self.assertEqual(self.mark(), {})
        self.assertEqual(self.beat(T + 30)['command'], 'uninstall')
        self.assertEqual(self.mark(), {'agent_uninstalled': True, 'agent_uninstalled_at': T + 30, 'agent_uninstall_sent_at': T + 30})
        row = self.row(T + 40)
        self.assertEqual((row['agent_uninstalled'], row['agent_uninstall_sent_at']), (True, T + 30))

    def test_a_host_with_no_mark_and_no_command_is_left_alone(self):
        before = dict(self.stored())
        self.assertIsNone(self.beat(T + 30)['command'])
        self.assertEqual(self.mark(), {})
        self.assertEqual({k for k in self.stored() if 'uninstall' in k}, set())
        self.assertEqual(before.get('name'), self.stored().get('name'))
        self.assertEqual(self.audit(), [])


class TestTheHostsList(_Uninstall):
    def test_a_host_with_no_mark(self):
        row = self.row()
        self.assertEqual((row['agent_uninstalled'], row['agent_uninstalled_at'], row['agent_uninstall_sent_at']), (False, 0, 0))

    def test_the_row_carries_the_mark_the_page_draws_its_badge_from(self):
        self.click()
        self.beat(T + 30)
        row = self.row(T + 40)
        self.assertEqual((row['agent_uninstalled'], row['agent_uninstalled_at'], row['agent_uninstall_sent_at']), (True, T, T + 30))
        self.assertNotIn('agent_uninstalled_by', row, 'who asked is in the audit log, not in every list')

    def test_a_stored_stamp_of_the_wrong_kind_is_zero_and_nothing_fails(self):
        for bad in ('yesterday', True, None, [1], {'a': 1}, -5, 2.5):
            with self.subTest(bad=bad):
                with api._LockedUpdate(api.DEVICES_FILE) as devs:
                    devs[DEV].update(agent_uninstalled=True, agent_uninstalled_at=bad, agent_uninstall_sent_at=bad)
                row = self.row()
                self.assertEqual((row['agent_uninstalled'], row['agent_uninstalled_at'], row['agent_uninstall_sent_at']), (True, 0, 0))
                self.set_queue(['uninstall'])
                self.assertEqual(self.beat(T + 30)['command'], 'uninstall', 'read as a request that was not handed over')
                self.assertEqual(self.mark()['agent_uninstall_sent_at'], T + 30)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheBadge(unittest.TestCase):
    """The page's own function, under node."""

    def badge(self, host):
        esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
        esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
        script = '\n'.join([esc, esca, 'function timeAgo(t) { return "5m ago"; }', srcpin.js_function(_APP, '_uninstallBadge'),
                            'console.log(JSON.stringify({html: _uninstallBadge(%s)}));' % json.dumps(host)])
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        html = json.loads(r.stdout)['html']
        m = re.fullmatch(r' <span class="[a-z0-9-]+" title="([^"]*)">([^<]*)</span>', html) if html else None
        return (m.group(2), m.group(1)) if m else html

    def test_a_host_with_no_mark_has_no_badge(self):
        self.assertEqual(self.badge({'agent_uninstalled': False}), '')
        self.assertEqual(self.badge({}), '')

    def test_the_three_states(self):
        sent = self.badge({'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstall_sent_at': T + 30, 'online': False})
        self.assertEqual(sent[0], 'agent uninstalled')
        self.assertIn('told to remove itself', sent[1])
        online = self.badge({'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstall_sent_at': 0, 'online': True})
        self.assertEqual(online[0], 'agent uninstalling…')
        self.assertIn('next check-in', online[1])
        offline = self.badge({'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstall_sent_at': 0, 'online': False})
        self.assertEqual(offline[0], 'agent uninstall queued')
        self.assertIn('offline', offline[1])
        self.assertNotIn('removed', offline[1], 'a host that has not been told is not said to be rid of its agent')

    def test_a_host_that_was_told_reads_as_uninstalled_whether_or_not_it_is_online(self):
        for online in (True, False):
            got = self.badge({'agent_uninstalled': True, 'agent_uninstalled_at': T, 'agent_uninstall_sent_at': T + 30, 'online': online})
            self.assertEqual(got[0], 'agent uninstalled', online)

    def test_the_three_words_are_in_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        for word in ('agent uninstalled', 'agent uninstalling…', 'agent uninstall queued'):
            self.assertTrue(rows.get(word) and all(rows[word].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')), word)


if __name__ == '__main__':
    unittest.main()
