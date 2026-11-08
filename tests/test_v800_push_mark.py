#!/usr/bin/env python3
"""8.0.0: the push mark. A host whose agent holds the push channel open has a small bolt on the Hosts page, the card and the drawer.

Three things have to be true for the mark to say something, and each has its tests here:

  * the AGENT says it: its listener thread sets a flag while its WebSocket is open and clears it the moment it is not, and its heartbeat carries that flag as
    `push_connected` once a listener has been started (and nothing before). The round is run against the real push daemon (server/push/remotepower-push.py, started
    here on a free port with a device store of its own) and the real `websockets` library, not a stand-in: the flag goes up when the daemon accepts the host, a
    wake nudge reaches the agent, the flag goes down when the daemon goes away, and a host with a wrong token never raises it;
  * the SERVER keeps the word fresh: only the JSON `true` stamps `push_seen`, anything else clears it, and the host list says `push` only for a host that is online
    and said so within three polls of its own interval (never less than three minutes), whatever junk the store holds;
  * the PAGE draws it from that field: tests/test_v800_push_mark_e2e.py.

Skips the daemon round when the `websockets` package is not installed (it is not one of the packages the CI installs): the agent works without it too.
"""
import asyncio
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from importlib import machinery
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-push-mark-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

try:
    import websockets
except ImportError:                                     # pragma: no cover
    websockets = None

ROOT = _TESTS.parent
_AGENT = {}


def setUpModule():
    loader = machinery.SourceFileLoader('rp_agent_push_mark', str(ROOT / 'client' / 'remotepower-agent.py'))
    spec = importlib.util.spec_from_loader('rp_agent_push_mark', loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    _AGENT['m'] = mod


def wait_for(cond, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return bool(cond())


class TestWhatTheHeartbeatSays(unittest.TestCase):

    def setUp(self):
        self.agent = _AGENT['m']
        self.addCleanup(self.agent._PUSH_STATE.update, up=False)

    def test_a_host_that_has_not_started_a_listener_says_nothing(self):
        self.agent._PUSH_STATE['up'] = True              # even a stale True is not said: there is no listener to speak for
        self.assertEqual(self.agent._push_report(False), {})

    def test_once_a_listener_has_started_the_heartbeat_says_the_json_true_or_false(self):
        self.agent._PUSH_STATE['up'] = False
        self.assertEqual(self.agent._push_report(True), {'push_connected': False})
        self.agent._PUSH_STATE['up'] = True
        got = self.agent._push_report(True)
        self.assertEqual(got, {'push_connected': True})
        self.assertIs(got['push_connected'], True)

    def test_the_state_is_a_bool_even_when_something_else_was_stored_in_it(self):
        self.agent._PUSH_STATE['up'] = 1
        self.assertIs(self.agent._push_report(True)['push_connected'], True)
        self.agent._PUSH_STATE['up'] = None
        self.assertIs(self.agent._push_report(True)['push_connected'], False)

    def test_the_main_loop_puts_that_word_in_every_heartbeat_it_builds(self):
        src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertEqual(src.count('payload.update(_push_report(_push_thread_started))'), 1)
        self.assertEqual((ROOT / 'client' / 'remotepower-agent').read_text(), src, 'the extensionless copy is the same file')


@unittest.skipIf(websockets is None, 'the websockets package is not installed')
class TestTheAgentAgainstTheRealPushDaemon(unittest.TestCase):

    def setUp(self):
        self.agent = _AGENT['m']
        self.agent._PUSH_STATE['up'] = False
        self.data = Path(tempfile.mkdtemp(prefix='rp-push-daemon-'))
        (self.data / 'devices.json').write_text(json.dumps({'d1': {'name': 'box', 'token_hash': hashlib.sha256(b'tok-1').hexdigest()}}))
        (self.data / 'commands.json').write_text('{}')
        loader = machinery.SourceFileLoader('rp_push_daemon_mark', str(ROOT / 'server' / 'push' / 'remotepower-push.py'))
        spec = importlib.util.spec_from_loader('rp_push_daemon_mark', loader)
        self.daemon = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        loader.exec_module(self.daemon)                      # type: ignore[union-attr]
        self.daemon.POLL_INTERVAL_S = 0.2                    # the real value is 2 s; the same loop, sooner
        self.loop = asyncio.new_event_loop()
        self.holder, ready = {}, threading.Event()

        async def run():
            server = self.daemon.PushServer(self.daemon.StoreReader(str(self.data)))
            self.holder['server'] = server
            task = asyncio.create_task(server.poll_and_nudge())
            self.holder['stop'] = asyncio.Event()
            async with websockets.serve(server.handler, '127.0.0.1', 0, ping_interval=20, ping_timeout=20, max_size=4096) as srv:
                self.holder['port'] = srv.sockets[0].getsockname()[1]
                ready.set()
                await self.holder['stop'].wait()
                # what the daemon's own shutdown does (main_async): close the clients itself, because leaving the context waits for every connection to end
                # and asyncio's Server.wait_closed() has waited for them since Python 3.12, so a connected host would hold the daemon (and this test) up
                close_all = [ws.close(code=1001, reason='server shutting down') for ws in list(server.connections.values())]
                if close_all:
                    await asyncio.wait_for(asyncio.gather(*close_all, return_exceptions=True), timeout=3)
            task.cancel()
        self.thread = threading.Thread(target=lambda: self.loop.run_until_complete(run()), daemon=True)
        self.thread.start()
        self.assertTrue(ready.wait(15), 'the daemon did not start')
        self.agent_stops = []
        self.addCleanup(self.shutdown)

    def shutdown(self):
        for ev in self.agent_stops:
            ev.set()
        stop = self.holder.get('stop')
        if stop is not None and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(stop.set)
        self.thread.join(15)

    def start_agent(self, token):
        wake, stop = threading.Event(), threading.Event()
        self.agent_stops.append(stop)
        url = 'http://127.0.0.1:%d' % self.holder['port']
        threading.Thread(target=self.agent._push_listener_thread, args=(url, 'd1', token, wake, stop), daemon=True).start()
        return wake

    def test_the_flag_is_up_while_the_daemon_holds_the_connection_a_nudge_arrives_and_the_flag_drops_when_the_daemon_goes(self):
        wake = self.start_agent('tok-1')
        self.assertTrue(wait_for(lambda: self.agent._PUSH_STATE['up']), 'the host never said the channel was open')
        self.assertEqual(self.agent._push_report(True), {'push_connected': True})
        self.assertTrue(wait_for(lambda: 'd1' in self.holder['server'].connections), 'the daemon never counted the host')
        (self.data / 'commands.json').write_text(json.dumps({'d1': ['exec:true']}))
        self.assertTrue(wake.wait(15), 'a command waiting for the host did not wake it: this is not a working channel')
        self.loop.call_soon_threadsafe(self.holder['stop'].set)
        self.assertTrue(wait_for(lambda: not self.agent._PUSH_STATE['up']), 'the flag stayed up after the daemon went away')
        self.assertEqual(self.agent._push_report(True), {'push_connected': False})

    def test_a_host_with_a_wrong_token_never_raises_the_flag(self):
        self.start_agent('not-the-token')
        time.sleep(2.5)
        self.assertFalse(self.agent._PUSH_STATE['up'])
        self.assertNotIn('d1', self.holder['server'].connections)


class _Captured(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _run(api, fn, body=None, method='POST', env=None):
    """A handler run as a request: (status, body) of what it answered."""
    names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
    saved_env = {n: os.environ.get(n) for n in names}
    api._begin_request()
    raw = b'' if body is None else json.dumps(body).encode()
    # a request carries the credentials the caller gives and no others: another test module's session token, left in the environment, is read before an API key (a 401 for the
    # whole of test_v800_app_discovery when tests.test_v642_integration_routing ran first, as it does in the alphabetical order of the gate)
    os.environ.pop('HTTP_AUTHORIZATION', None)
    os.environ.pop('HTTP_X_TOKEN', None)
    os.environ.update(REQUEST_METHOD=method, PATH_INFO='/api/x', REMOTE_ADDR='203.0.113.50', CONTENT_LENGTH=str(len(raw)), QUERY_STRING='')
    os.environ.update(env or {})
    saved_stdin, saved_respond = sys.stdin, api.respond

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    sys.stdin, api.respond = _Stdin(raw), fake
    try:
        try:
            fn()
            return None, None
        except _Captured as c:
            return c.status, c.body
    finally:
        sys.stdin, api.respond = saved_stdin, saved_respond
        for n, v in saved_env.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


class TestTheServerKeepsTheWordFresh(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.api.verify_token = lambda token: ('admin', 'admin') if token == 'k' else (None, None)
        self.plant()

    def plant(self, **dev):
        base = {'id': 'd1', 'name': 'box', 'os': 'Ubuntu 24.04', 'token': 'tok', 'last_seen': int(time.time()), 'sysinfo': {}}
        base.update(dev)
        # written directly: save() refuses to move a last_seen back (a host that went quiet is the point of one test), and refuses a NaN (a hand-edited store is another)
        Path(self.api.DEVICES_FILE).write_text(json.dumps({'d1': base}))
        self.api._LOAD_CACHE.clear()

    def stored(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.DEVICES_FILE)['d1']

    def beat(self, **extra):
        st, _ = _run(self.api, self.api.handle_heartbeat, dict({'device_id': 'd1', 'token': 'tok', 'version': '8.0.0'}, **extra))
        self.assertEqual(st, 200)
        return self.stored()

    def row(self):
        self.api._LOAD_CACHE.clear()
        st, rows = _run(self.api, self.api.handle_devices_list, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer k'})
        self.assertEqual(st, 200, rows)
        return {r['id']: r for r in (rows if isinstance(rows, list) else rows.get('devices', []))}['d1']

    def test_only_the_json_true_stamps_the_host_and_anything_else_clears_it(self):
        before = int(time.time())
        got = self.beat(push_connected=True)
        self.assertTrue(before <= got['push_seen'] <= int(time.time()) + 1)
        for said in (False, None, 'true', 'yes', 1, [True], {'a': 1}):
            self.assertIn('push_seen', self.beat(push_connected=True))
            self.assertNotIn('push_seen', self.beat(push_connected=said), repr(said))
        self.assertIn('push_seen', self.beat(push_connected=True))
        self.assertNotIn('push_seen', self.beat(), 'an agent that says nothing (older, Windows, macOS, no listener) has no mark')

    def test_the_host_list_says_push_for_an_online_host_that_said_so_a_moment_ago(self):
        self.assertIs(self.row()['push'], False)
        self.beat(push_connected=True)
        self.assertIs(self.row()['push'], True)

    def test_a_host_that_stopped_saying_it_loses_the_mark_after_three_polls_and_never_before_three_minutes(self):
        now = int(time.time())
        for age, poll, want in ((10, 60, True), (179, 60, True), (181, 60, False), (300, 120, True), (361, 120, False), (100, 10, True), (181, 10, False), (800, 300, True), (901, 300, False)):
            self.plant(push_seen=now - age, poll_interval=poll)
            self.assertIs(self.row()['push'], want, (age, poll))

    def test_an_offline_host_has_no_mark_however_fresh_its_last_word_was(self):
        self.plant(push_seen=int(time.time()), last_seen=int(time.time()) - 86400)
        row = self.row()
        self.assertIs(row['online'], False)
        self.assertIs(row['push'], False)

    def test_an_agentless_host_has_no_mark(self):
        self.plant(push_seen=int(time.time()), agentless=True)
        self.assertIs(self.row()['push'], False)

    def test_a_stored_value_of_the_wrong_kind_says_nothing_and_does_not_break_the_list(self):
        now = int(time.time())
        for junk in ('x', True, False, [now], {'a': 1}, float('nan'), now + 3600, -5, None):
            self.plant(push_seen=junk)
            self.assertIs(self.row()['push'], False, repr(junk))

    def test_the_helper_alone(self):
        up = self.api._push_channel_up
        now = 1_000_000
        self.assertIs(up({'push_seen': now - 5}, now), True)
        self.assertIs(up({'push_seen': now + 5}, now), False, 'a stamp from the future is not a word of this server')
        self.assertIs(up({}, now), False)
        self.assertIs(up(None, now), False)
        self.assertIs(up({'push_seen': now - 5, 'poll_interval': 'x'}, now), True, 'a poll interval of the wrong kind is the default one')
        self.assertIs(up({'push_seen': now - 5, 'poll_interval': True}, now), True)

    def test_the_store_registry_knows_the_field_as_a_number_or_nothing(self):
        import store_shapes
        shape = store_shapes.SHAPES['devices.json']
        self.assertIn('push_seen', json.dumps(shape, default=str))
        fixed = store_shapes.normalize('devices.json', {'d1': {'name': 'box', 'last_seen': 5, 'push_seen': 'junk'}})
        self.assertNotIn('push_seen', json.dumps(fixed.get('d1') or {}), 'text in it is removed, so the reader never subtracts from it')


if __name__ == '__main__':
    unittest.main()
