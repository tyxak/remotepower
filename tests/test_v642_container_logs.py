"""v6.4.2 — the container log viewer's server + agent halves.

The old Logs button queued `container:<rt>:logs:<id>` and toasted "runs on next
heartbeat" with nothing behind it. Three things had to change for the viewer to
be able to say anything true:

  1. the longpoll slot must only accept the output of the command it queued
     (otherwise a logs request behind a queued restart renders the restart's
     output as the container's logs),
  2. the agent must accept a tail size, and
  3. the server must not claim to have applied a tail an old agent can't parse.
"""

import os as _rp_os, tempfile as _rp_tempfile
_rp_os.environ.setdefault("RP_DATA_DIR", _rp_tempfile.mkdtemp())
import importlib.util
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_CLIENT = _ROOT / 'client'
sys.path.insert(0, str(_CLIENT))

_spec = importlib.util.spec_from_file_location('api_ctr_logs', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_aspec = importlib.util.spec_from_file_location(
    'rp_agent_ctrlogs', _CLIENT / 'remotepower-agent.py')
agent = importlib.util.module_from_spec(_aspec)
_aspec.loader.exec_module(agent)


class _Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = rc, out, err


# ── 1. longpoll slot matching ────────────────────────────────────────────────

class TestLongpollMatchGuard(unittest.TestCase):
    def setUp(self):
        api.save(api.LONGPOLL_FILE, {})

    def tearDown(self):
        api.save(api.LONGPOLL_FILE, {})

    def _slot(self, **extra):
        s = {'cmd': 'x', 'ready': False, 'output': None, 'ts': 1}
        s.update(extra)
        api.save(api.LONGPOLL_FILE, {'d1': s})

    def _read(self):
        api._invalidate_load_cache(api.LONGPOLL_FILE)
        return (api.load(api.LONGPOLL_FILE) or {}).get('d1') or {}

    def test_a_slot_with_no_match_takes_anything(self):
        # Every pre-v6.4.2 caller (file manager, docker prune, /exec/wait) relies
        # on this — the guard must be strictly opt-in.
        self._slot()
        api._resolve_longpoll('d1', {'cmd': 'exec:whatever', 'output': 'hi', 'rc': 0})
        self.assertTrue(self._read().get('ready'))

    def test_a_matching_command_resolves(self):
        want = 'container:docker:logs:web:200'
        self._slot(cmd=want, match=want)
        api._resolve_longpoll('d1', {'cmd': want, 'output': 'log text', 'rc': 0})
        slot = self._read()
        self.assertTrue(slot.get('ready'))
        self.assertEqual(slot['output']['output'], 'log text')

    def test_someone_else_s_output_is_left_alone(self):
        self._slot(cmd='container:docker:logs:web:200',
                   match='container:docker:logs:web:200')
        api._resolve_longpoll('d1', {'cmd': 'container:docker:restart:web',
                                     'output': 'restarted', 'rc': 0})
        slot = self._read()
        self.assertFalse(slot.get('ready'),
                         'a restart\'s output must not resolve a logs wait')
        self.assertIsNone(slot.get('output'))

    def test_a_prefix_named_sibling_does_not_resolve(self):
        # `:logs:web` is a substring of `:logs:web2`. The old client-side poll
        # used `includes()` and would have shown web2's logs under web's name.
        self._slot(cmd='container:docker:logs:web:200',
                   match='container:docker:logs:web:200')
        api._resolve_longpoll('d1', {'cmd': 'container:docker:logs:web2:200',
                                     'output': 'wrong container', 'rc': 0})
        self.assertFalse(self._read().get('ready'))

    def test_no_slot_at_all_is_a_no_op(self):
        api.save(api.LONGPOLL_FILE, {})
        api._resolve_longpoll('d1', {'cmd': 'x', 'output': 'y', 'rc': 0})
        self.assertEqual(api.load(api.LONGPOLL_FILE) or {}, {})


# ── 2. agent-side tail parsing ───────────────────────────────────────────────

class TestAgentTailParsing(unittest.TestCase):
    def setUp(self):
        self._run = agent.subprocess.run
        self._which = agent._which
        self.calls = []
        agent._which = lambda n: '/usr/bin/' + n
        agent.subprocess.run = lambda argv, **kw: (self.calls.append(argv),
                                                   _Result(0, 'line1\nline2'))[1]

    def tearDown(self):
        agent.subprocess.run = self._run
        agent._which = self._which

    def test_four_segment_command_keeps_the_old_default(self):
        r = agent._run_container_action('container:docker:logs:web')
        self.assertEqual(r['rc'], 0)
        self.assertIn(f'--tail={agent.CONTAINER_LOG_TAIL_DEFAULT}', self.calls[0])

    def test_five_segment_command_uses_the_requested_tail(self):
        agent._run_container_action('container:docker:logs:web:500')
        self.assertIn('--tail=500', self.calls[0])

    def test_the_tail_is_clamped(self):
        agent._run_container_action('container:docker:logs:web:999999')
        self.assertIn(f'--tail={agent.CONTAINER_LOG_TAIL_MAX}', self.calls[0])

    def test_a_non_numeric_tail_is_refused_not_guessed(self):
        r = agent._run_container_action('container:docker:logs:web:$(id)')
        self.assertEqual(r['rc'], -1)
        self.assertEqual(r['output'], 'invalid tail size')
        self.assertEqual(self.calls, [], 'nothing may be executed')

    def test_the_container_id_never_absorbs_the_tail(self):
        # split(':', 4) is what keeps these separate; a maxsplit of 3 would hand
        # docker an id of "web:500" (and the id regex would reject the whole run).
        agent._run_container_action('container:docker:logs:web:500')
        self.assertIn('web', self.calls[0])
        self.assertNotIn('web:500', self.calls[0])

    def test_non_logs_verbs_are_unchanged(self):
        agent._run_container_action('container:docker:restart:web')
        self.assertEqual(self.calls[0], ['docker', 'restart', 'web'])


class TestOverCapLogsKeepTheNEWESTLines(unittest.TestCase):
    """`logs` is a TAIL request. Cutting the over-cap capture from the FRONT —
    which is what every other verb wants — handed back the OLDEST 32 KB while
    the viewer scrolled to the bottom as if the last line were the latest one.
    A log viewer showing yesterday's first 32 KB is worse than showing nothing,
    because nothing about it looks wrong."""

    def test_logs_keep_the_tail_and_say_what_was_dropped(self):
        raw = '\n'.join('line-%05d' % i for i in range(60000))
        self.assertGreater(len(raw), agent.CONTAINER_OUT_CAP)
        out = agent._cap_container_output('logs', raw)
        self.assertLessEqual(len(out), agent.CONTAINER_OUT_CAP + 128)
        self.assertTrue(out.endswith('line-59999'), 'the NEWEST line must survive')
        self.assertNotIn('line-00000', out)
        self.assertIn('older lines dropped', out,
                      'a silently-truncated log looks complete')

    def test_no_partial_first_line(self):
        raw = '\n'.join('x' * 200 for _ in range(1000))
        out = agent._cap_container_output('logs', raw)
        body = out.split('\n', 1)[1]          # drop the notice
        self.assertTrue(all(len(l) == 200 for l in body.split('\n') if l),
                        'the line the cut landed inside must be discarded')

    def test_other_verbs_still_keep_the_head(self):
        raw = 'HEAD' + 'z' * (agent.CONTAINER_OUT_CAP + 500)
        out = agent._cap_container_output('restart', raw)
        self.assertTrue(out.startswith('HEAD'))
        self.assertEqual(len(out), agent.CONTAINER_OUT_CAP)

    def test_under_cap_output_is_untouched(self):
        self.assertEqual(agent._cap_container_output('logs', '  a\nb  '), 'a\nb')

    def test_windows_agent_has_the_same_rule(self):
        src = (_CLIENT / 'remotepower-agent-win.py').read_text()
        i = src.index('def _cap_container_output_win')
        block = src[i:src.index('\ndef ', i + 10)]
        self.assertIn("action != 'logs'", block)
        self.assertIn('raw[-CONTAINER_OUT_CAP:]', block)
        self.assertIn('_CONTAINER_TRUNC_NOTE', block)


# ── 3. server: wait + tail, and the honest old-agent fallback ────────────────

class TestContainerActionWaitAndTail(unittest.TestCase):
    def setUp(self):
        self._orig = (api.require_perm, api.method, api.get_json_body,
                      api.audit_log, api.log_command, api.fire_webhook,
                      api._longpoll_wait, api._needs_approval)
        api.require_perm = lambda *a, **k: 'tester'
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api._needs_approval = lambda kind: False
        self.waited = []
        api._longpoll_wait = lambda dev, to: (self.waited.append((dev, to)),
                                              ('ok', {'cmd': 'x', 'output': 'LOGS', 'rc': 0}))[1]
        api.save(api.CMDS_FILE, {})
        api.save(api.LONGPOLL_FILE, {})
        api.save(api.CONTAINERS_FILE, {'d1': {'ts': 1, 'items': [
            {'name': 'web', 'id': 'web', 'status': 'Up', 'runtime': 'docker'}]}})

    def tearDown(self):
        (api.require_perm, api.method, api.get_json_body, api.audit_log,
         api.log_command, api.fire_webhook, api._longpoll_wait,
         api._needs_approval) = self._orig
        api.save(api.CMDS_FILE, {})
        api.save(api.LONGPOLL_FILE, {})

    def _call(self, body, agent_version='6.4.2'):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1',
                                           'version': agent_version}})
        api.get_json_body = lambda: dict(body)
        try:
            api.handle_device_container_action('d1')
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, 'status', None), getattr(e, 'body', None)
        return None, None

    def _queued(self):
        api._invalidate_load_cache(api.CMDS_FILE)
        return (api.load(api.CMDS_FILE) or {}).get('d1') or []

    def test_tail_is_appended_as_a_fifth_segment(self):
        status, body = self._call({'action': 'logs', 'container_id': 'web',
                                   'runtime': 'docker', 'tail': 500})
        self.assertEqual(status, 200)
        self.assertIn('container:docker:logs:web:500', self._queued())
        self.assertEqual(body['tail'], 500)

    def test_an_old_agent_gets_no_tail_and_the_response_says_so(self):
        # Silently serving 50 lines while the picker says 1000 is the "UI text
        # that lies" class — the response separates requested from applied.
        status, body = self._call({'action': 'logs', 'container_id': 'web',
                                   'runtime': 'docker', 'tail': 1000},
                                  agent_version='6.4.0')
        self.assertEqual(status, 200)
        self.assertIn('container:docker:logs:web', self._queued())
        self.assertNotIn('container:docker:logs:web:1000', self._queued())
        self.assertEqual(body['tail'], 0)
        self.assertEqual(body['tail_requested'], 1000)

    def test_the_tail_is_clamped_server_side_too(self):
        _, body = self._call({'action': 'logs', 'container_id': 'web',
                              'runtime': 'docker', 'tail': 10 ** 9})
        self.assertEqual(body['tail'], api.CONTAINER_LOG_TAIL_MAX)

    def test_wait_returns_the_real_output(self):
        status, body = self._call({'action': 'logs', 'container_id': 'web',
                                   'runtime': 'docker', 'wait': True})
        self.assertEqual(status, 200)
        self.assertEqual(body['output']['output'], 'LOGS')
        self.assertEqual(len(self.waited), 1)

    def test_wait_registers_an_exact_match_slot(self):
        recorded = {}

        def _capture(dev, to):
            api._invalidate_load_cache(api.LONGPOLL_FILE)
            recorded.update((api.load(api.LONGPOLL_FILE) or {}).get(dev) or {})
            return ('timeout', None)

        api._longpoll_wait = _capture
        self._call({'action': 'logs', 'container_id': 'web', 'runtime': 'docker',
                    'tail': 200, 'wait': True})
        self.assertEqual(recorded.get('match'), 'container:docker:logs:web:200')
        self.assertEqual(recorded.get('cmd'), 'container:docker:logs:web:200')

    def test_a_timeout_is_reported_as_such_not_as_success_with_no_logs(self):
        api._longpoll_wait = lambda dev, to: ('timeout', None)
        status, body = self._call({'action': 'logs', 'container_id': 'web',
                                   'runtime': 'docker', 'wait': True})
        self.assertEqual(status, 200)
        self.assertTrue(body.get('timeout'))
        self.assertNotIn('output', body)

    def test_wait_is_ignored_for_disruptive_verbs(self):
        # Blocking a request on a restart buys nothing and would make the button
        # feel broken; only logs run-and-wait.
        status, body = self._call({'action': 'restart', 'container_id': 'web',
                                   'runtime': 'docker', 'wait': True})
        self.assertEqual(status, 200)
        self.assertEqual(self.waited, [])
        self.assertNotIn('output', body)

    def test_macos_is_refused_up_front_not_queued(self):
        # The macOS agent has no container handler at all, so queueing anything
        # for it is a success toast in front of silence.
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1',
                                           'version': '6.4.2',
                                           'os': 'macOS 14.5 (23F79)'}})
        api.get_json_body = lambda: {'action': 'logs', 'container_id': 'web',
                                     'runtime': 'docker'}
        try:
            api.handle_device_container_action('d1')
            status, body = None, None
        except (SystemExit, api.HTTPError) as e:
            status, body = getattr(e, 'status', None), getattr(e, 'body', None)
        self.assertEqual(status, 400)
        self.assertIn('macOS', (body or {}).get('error', ''))
        self.assertEqual(self._queued(), [])

    def test_windows_update_is_refused_up_front(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1',
                                           'version': '6.4.2',
                                           'os': 'Windows 11 (Build 22631)'}})
        api.get_json_body = lambda: {'action': 'update', 'container_id': 'web',
                                     'runtime': 'docker'}
        try:
            api.handle_device_container_action('d1')
            status, body = None, None
        except (SystemExit, api.HTTPError) as e:
            status, body = getattr(e, 'status', None), getattr(e, 'body', None)
        self.assertEqual(status, 400)
        self.assertIn('Windows', (body or {}).get('error', ''))
        self.assertEqual(self._queued(), [])

    def test_windows_logs_still_go_through(self):
        status, _ = self._call({'action': 'logs', 'container_id': 'web',
                                'runtime': 'docker'})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1',
                                           'version': '6.4.2',
                                           'os': 'Windows 11 (Build 22631)'}})
        api.get_json_body = lambda: {'action': 'logs', 'container_id': 'web',
                                     'runtime': 'docker', 'tail': 200}
        try:
            api.handle_device_container_action('d1')
            status = None
        except (SystemExit, api.HTTPError) as e:
            status = getattr(e, 'status', None)
        self.assertEqual(status, 200)
        self.assertIn('container:docker:logs:web:200', self._queued())

    def test_approval_still_wins_over_wait(self):
        api._needs_approval = lambda kind: True
        api._park_for_approval = lambda *a, **k: 'conf-1'
        status, body = self._call({'action': 'logs', 'container_id': 'web',
                                   'runtime': 'docker', 'wait': True})
        self.assertEqual(status, 202)
        self.assertTrue(body.get('approval_required'))
        self.assertEqual(self.waited, [])


# ── 4. Windows agent parity ──────────────────────────────────────────────────

class TestWindowsAgentRunsContainerActions(unittest.TestCase):
    """The Windows agent has REPORTED containers since v6.2.0, so the Containers
    page has been drawing Start/Stop/Restart/Logs for Windows hosts the whole
    time — and every one came back "unsupported command"."""

    SRC = (_CLIENT / 'remotepower-agent-win.py').read_text()

    def test_the_dispatcher_routes_container_commands(self):
        self.assertIn("cmd.startswith('container:')", self.SRC)
        self.assertIn('_run_container_action_win(cmd)', self.SRC)

    def test_the_handler_exists_and_is_argv_only(self):
        i = self.SRC.index('def _run_container_action_win')
        block = self.SRC[i:self.SRC.index('\ndef ', i + 10)]
        self.assertIn('_CONTAINER_ID_RE.match(container_id)', block)
        self.assertIn('--tail=', block)
        self.assertNotIn('shell=True', block)

    def test_update_is_refused_honestly_rather_than_faked(self):
        i = self.SRC.index('def _run_container_action_win')
        block = self.SRC[i:self.SRC.index('\ndef ', i + 10)]
        m = re.search(r"if action == 'update':(.{0,400})", block, re.S)
        self.assertIsNotNone(m)
        self.assertIn('not supported', m.group(1))


# ── 5. the viewer's own state machine ───────────────────────────────────────

class TestLogViewerStateInvariants(unittest.TestCase):
    """STRUCTURAL, and deliberately so: these are the two invariants that make
    the window recoverable, and both were violated in the first draft.

    `busy` guards against two concurrent fetches — but it is also the thing that
    deadlocks the window if any path leaves it set. Opening logs for a second
    container while the first was still in its fallback poll killed the poll's
    timer (the only code that would ever clear busy), so every later fetch
    returned instantly and the window sat empty with the right title.

    A behavioural test would need a DOM and a resolvable async api(); the load
    harness stubs every browser API as a permissive proxy and cannot express
    that. So this pins the SHAPE of the invariant rather than proving it at
    runtime — which is worth stating plainly, because a source test proves a
    line exists, never that it works."""

    JS = (_ROOT / 'server/html/static/js/app.js').read_text()

    def _fn(self, name):
        sys.path.insert(0, str(_ROOT / 'tests'))
        import srcpin
        return srcpin.js_function(self.JS, name)

    @staticmethod
    def _blank_strings(src):
        """Same-length copy with every string, template literal and comment
        blanked, so brace counting can't be thrown by a brace inside one.
        Offsets are preserved, so a position in the original is a position in
        this. Comments matter as much as strings here: an apostrophe in
        "the device's output" would otherwise open a phantom string literal."""
        out = list(src)
        i, n = 0, len(src)
        while i < n:
            ch = src[i]
            if ch == '/' and i + 1 < n and src[i + 1] == '/':
                j = src.find('\n', i)
                j = n if j < 0 else j
                out[i:j] = ' ' * (j - i)
                i = j
                continue
            if ch == '/' and i + 1 < n and src[i + 1] == '*':
                j = src.find('*/', i + 2)
                j = n if j < 0 else j + 2
                out[i:j] = ' ' * (j - i)
                i = j
                continue
            if ch in '\'"`':
                j = i + 1
                while j < n:
                    if src[j] == '\\':
                        j += 2
                        continue
                    if src[j] == ch:
                        break
                    out[j] = ' '
                    j += 1
                i = j + 1
                continue
            i += 1
        return ''.join(out)

    @classmethod
    def _enclosing_block(cls, src, pos):
        """Text of the innermost {...} containing `pos`."""
        src = cls._blank_strings(src)
        depth = 0
        for i in range(pos - 1, -1, -1):
            if src[i] == '}':
                depth += 1
            elif src[i] == '{':
                if depth == 0:
                    j, d = i + 1, 1
                    while j < len(src) and d:
                        d += (src[j] == '{') - (src[j] == '}')
                        j += 1
                    return src[i:j]
                depth -= 1
        return src

    def test_every_early_return_after_busy_clears_it(self):
        body = self._fn('_ctrLogsFetch')
        i = body.index('_ctrLogs.busy = true')
        offenders = []
        for m in re.finditer(r'\breturn\b', body[i:]):
            pos = i + m.start()
            block = self._enclosing_block(body, pos)
            # A return inside a setInterval callback exits the CALLBACK, not the
            # fetch, so it owes nothing to the flag.
            if 'setInterval' in body[:pos].rsplit('\n', 1)[0][-400:] and \
                    '_ctrLogsStopTimers' in block:
                continue
            if '_ctrLogs.busy = false' not in block:
                offenders.append(body[max(0, pos - 120):pos + 10])
        self.assertEqual(offenders, [],
                         'a return path in _ctrLogsFetch leaves busy set — the '
                         'window deadlocks:\n' + '\n---\n'.join(offenders))

    def test_the_fallback_poll_clears_busy_on_every_exit(self):
        body = self._fn('_ctrLogsFallbackPoll')
        for marker in ('_ctrLogs.seq', '!_ctrLogsOpen()', 'tries > 20'):
            self.assertIn(marker, body, marker)
        # Three exits: superseded/closed, give-up, and a result. Each either
        # clears busy inline or hands off to a helper that does — assert BOTH
        # helpers own it, so the delegation can't silently become a hole.
        self.assertIn('_ctrLogs.busy = false', body, 'the closed/superseded exit')
        for helper in ('_ctrLogsError', '_ctrLogsShow'):
            self.assertIn(helper + '(', body, f'{helper} is an exit of the poll')
            self.assertIn('_ctrLogs.busy = false', self._fn(helper),
                          f'{helper} is a terminal transition and must clear busy')

    def test_a_new_session_and_an_explicit_refresh_both_reset_busy(self):
        for name in ('fetchContainerLogs', 'containerLogsRefetch'):
            body = self._fn(name)
            self.assertIn('_ctrLogs.busy = false', body,
                          f'{name} must reset busy — it has just killed the '
                          'timers that would otherwise clear it')
            self.assertIn('_ctrLogs.seq++', body,
                          f'{name} must bump seq so an in-flight response is '
                          'orphaned rather than rendered into the new session')

    def test_no_timer_escapes_the_state_object(self):
        # A setInterval whose handle isn't stored in _ctrLogs can never be
        # cleared, so it outlives the modal — the "Logs tail keeps fetching
        # after you leave the page" class.
        for name in ('_ctrLogsFetch', '_ctrLogsFallbackPoll',
                     'containerLogsToggleAuto'):
            body = self._fn(name)
            for m in re.finditer(r'setInterval\(', body):
                lead = body[max(0, m.start() - 60):m.start()]
                self.assertRegex(lead, r'_ctrLogs\.\w+Timer\s*=\s*$',
                                 f'{name}: setInterval handle not stored on _ctrLogs')

    def test_the_log_body_is_never_built_with_innerhtml(self):
        # Container output is untrusted — it prints whatever it likes.
        body = self._fn('_ctrLogsRender')
        self.assertNotIn('innerHTML', body)
        self.assertIn('textContent', body)

    def test_ai_explain_gets_the_whole_log_not_the_filtered_view(self):
        body = self._fn('aiExplainContainerLogsBtn')
        self.assertIn('_ctrLogs.raw', body)
        self.assertNotIn("getElementById('container-logs-body')", body,
                         'reading the DOM would hand the AI only the filtered '
                         'lines while the button says "these logs"')


class TestAgentTwinStaysInSync(unittest.TestCase):
    def test_extensionless_matches_py(self):
        self.assertEqual((_CLIENT / 'remotepower-agent.py').read_bytes(),
                         (_CLIENT / 'remotepower-agent').read_bytes(),
                         'run: cp client/remotepower-agent.py client/remotepower-agent')


if __name__ == '__main__':
    unittest.main()
