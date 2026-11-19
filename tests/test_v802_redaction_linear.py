"""The redaction of a command line or a log line takes time in proportion to the text, and gives the answer it always gave (8.0.2).

A command line can hold a password: a Run value of an installer, the arguments of a scheduled task. The Windows agent replaces the value that follows a name that looks
like a secret (`--password x`, `Password=x;`) before it sends the line, and the server does the same again to what a host sends, because a host's word is not trusted.
Two more places do it to a host's free text: the log sweep the AI triage reads, and the text the hosted MCP endpoint hands to a model.

The pattern that finds `name=value` led with `\\b[\\w.-]*`, kept `[\\w.-]*` after the name, and so tried every start, every name after it and every length of the rest on a
run of word characters, dots and hyphens that holds the name many times ("pwd.pwd.pwd."). Doubling the text cost eight times as much: 2,000 characters took four
seconds. A standard user of a Windows host writes the arguments of a scheduled task, and the inventory (every 15 minutes, on by default) and the log rule of event 4698 both
redact them inline in the heartbeat of a service that runs as SYSTEM; a host with its own token sends the server 1,500 such commands in one heartbeat, and the server
redacted each of them, 13 seconds of processor time for 393 KB. A log sweep holds up to 48 files of 400 lines of 1,024 characters and went through the same pattern line by
line, and the text of one command a host ran (8,192 characters are kept) went through it whole when a model asked for the recent commands.

The run is taken whole at the place it starts now, and a look-ahead only asks whether the name is somewhere in it, so each run is read about twice. The first version's
patterns are kept here as the oracle: the answer must be the same text for every input the oracle can answer in a moment, and the time must grow with the text. The one
difference is on purpose: the log sweep's pattern stopped an unquoted value at 256 characters and left the rest of the word in the clear.

The timing checks run in a child process with a hard limit, because a pattern that has gone wrong cannot be interrupted from inside the interpreter that runs it, and a test
that hung would take the gate with it.
"""
import ast
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-redact-'))

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import ai_triage_handlers as T  # noqa: E402
import mcp_http as M  # noqa: E402
import persistence as P  # noqa: E402
from test_win_persistence import _Server, win  # noqa: E402

NAME = win._SECRET_NAME_PATTERN
# the first version of each pattern, exactly: the oracle
OLD_FLAG = re.compile(r'(?i)((?:^|\s)(?:--?|/)[\w.-]*' + NAME + r'[\w.-]*)(\s*[=:]\s*|\s+)("[^"]*"|\'[^\']*\'|\S+)')
OLD_KV = re.compile(r'(?i)(\b[\w.-]*' + NAME + r'[\w.-]*)(\s*[=:]\s*)("[^"]*"|\'[^\']*\'|\S+)')
OLD_TRIAGE_KV = re.compile(
    r'(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|'
    r'passphrase|private[_-]?key|client[_-]?secret|access[_-]?key|community|'
    r'credential|auth)[\w.-]*)\s*([=:])\s*("[^"]{1,256}"|\'[^\']{1,256}\'|\S{1,256})')
OLD_MASK_PAIR = re.compile(
    r"""(\b[\w.-]*(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|community)[\w.-]*\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;]+)""", re.I)


def first_version(text):
    """What the redaction of a command line answered before: the two patterns in the same order, then the password of a URL."""
    s = OLD_FLAG.sub(r'\1\2[REDACTED]', str(text))
    s = OLD_KV.sub(r'\1\2[REDACTED]', s)
    return win._PERSIST_URL_CREDENTIAL.sub(r'\1[REDACTED]\2', s)


def sweep_first_version(line):
    """What the log sweep's scrubber answered before: bearer, then the pattern, then the password of a URL."""
    line = T._REDACT_BEARER.sub(r'\1 [REDACTED]', line)
    line = OLD_TRIAGE_KV.sub(r'\1\2[REDACTED]', line)
    return T._REDACT_URLCRED.sub(r'://\1:[REDACTED]@', line)


def mask_first_version(value, limit):
    """What the hosted MCP endpoint's mask answered before."""
    text = str(value if value is not None else '')
    text = OLD_MASK_PAIR.sub(lambda m: m.group(1) + '***', text)
    text = M._MASK_FLAG.sub(lambda m: m.group(1) + '***', text)
    text = M._MASK_AUTH.sub(lambda m: m.group(1) + '***', text)
    return text[:limit]


# what is written in a command line, in pieces: names, separators, quotes, flags, a URL with a password
VOCABULARY = ['--password', '-p', '/token:', '--pwd', 'pwd', 'secret', 'x', '=', ':', ' ', ' ', ' ', '"a b"', "'c d'", '"', "'", 'https://u:pw@h/', '.', '-', '--', '/',
              'ApiKey', 'Authorization', 'Bearer', 'a.b', '\t', 'password=', 'client_secret', 'api-key', 'sign', 'key', 'token:', 'tool.exe', 'abc123', '\u00e9', '_', '9',
              'Password', 'PASS', 'pass.', '-pwd.', '/secret.']
# and in a log line or the output of a command: the same, with the words the other two patterns know and the separators of a list
VOCABULARY_TEXT = VOCABULARY + ['community', 'credential', 'auth', 'passphrase', 'private_key', 'Bearer abcdefghijkl', 'Basic dXNlcjpwYXNz', ',', ';', 'token=', 'auth.',
                                'access-key', '"', '\n', 'a=b', 'x.y.z', '-token', 'password:']

EXAMPLES = [
    'tool.exe --password hunter2 --silent',
    'tool.exe /token:abc123 /q',
    'tool.exe -ApiKey=abc123',
    'tool.exe --client-secret "a b c" --x',
    'tool.exe password=hunter2',
    'tool.exe --db "https://admin:s3cret@db.example/x"',
    'tool.exe --pwd=abc',
    'Server=db1;Database=app;User Id=sa;Password=p@ss w0rd;Encrypt=true',
    'a.b-password=1 pwd.pwd=2 x.secret:3 .token=4 -secret=5',
    'C:\\Windows\\System32\\svchost.exe -k netsvcs',
    'https://example.test/path?x=1&token=abc',
    'cmd.exe /c "set PASSWORD=abc & run.exe"',
    "tool 'it''s' password='a b' next",
    '',
    '=',
    'password=',
    '--password',
    'passwordpassword=x',
]


class TestTheAnswerIsTheFirstVersions(unittest.TestCase):
    def test_each_example_is_redacted_as_it_was_by_the_agent_and_by_the_server(self):
        for text in EXAMPLES:
            with self.subTest(text=text):
                want = first_version(text)
                self.assertEqual(win._reg_redact(text), want)
                self.assertEqual(P.redact_command(text), want)

    def test_the_examples_do_hide_a_secret_and_leave_the_rest(self):
        # the control: an oracle that took everything out, or nothing, would agree with itself
        self.assertEqual(win._reg_redact('tool.exe --password hunter2 --silent'), 'tool.exe --password [REDACTED] --silent')
        self.assertEqual(win._reg_redact('a.b-password=1 x'), 'a.b-password=[REDACTED] x')
        self.assertEqual(win._reg_redact('C:\\Windows\\System32\\svchost.exe -k netsvcs'), 'C:\\Windows\\System32\\svchost.exe -k netsvcs')
        self.assertEqual(P.redact_command('Server=db1;Password=p@ss'), 'Server=db1;Password=[REDACTED]')

    def test_random_command_lines_are_redacted_as_the_first_version_did(self):
        rnd = random.Random(8022)
        for _ in range(20000):
            text = ''.join(rnd.choice(VOCABULARY) for _ in range(rnd.randint(1, 12)))
            want = first_version(text)
            got = win._reg_redact(text)
            if got != want or P.redact_command(text) != want:
                self.fail('%r: the first version says %r, now %r / %r' % (text, want, got, P.redact_command(text)))

    def test_the_fuzz_hides_something_in_a_fair_share_of_its_lines(self):
        # a population of lines nothing is hidden in would pass the test above without asking the question
        rnd = random.Random(8022)
        hidden = sum('[REDACTED]' in win._reg_redact(''.join(rnd.choice(VOCABULARY) for _ in range(rnd.randint(1, 12)))) for _ in range(2000))
        self.assertGreater(hidden, 300)

    def test_dotted_runs_that_hold_a_name_are_redacted_as_the_first_version_did(self):
        # the shape that cost the time: names inside runs of word characters, dots and hyphens, with and without a value after them
        rnd = random.Random(8023)
        words = ['pwd', 'pass', 'token', 'x', 'secret', 'key', 'api-key', 'abc']
        for _ in range(3000):
            run = ''.join(rnd.choice(words) + rnd.choice('.-_') for _ in range(rnd.randint(1, 5)))
            tail = rnd.choice(['', '=v', ': v', '=', ' v', '="a b"', "='q'"])
            text = rnd.choice(['', 'tool ', '-a ', '/b ', '--']) + run + tail + rnd.choice(['', ' rest', ' pwd=1'])
            self.assertEqual(win._reg_redact(text), first_version(text), text)
            self.assertEqual(P.redact_command(text), first_version(text), text)

    def test_what_the_agent_sends_and_what_the_server_keeps_agree_on_hostile_runs(self):
        for shape in ('pwd.', '-pwd.', 'x.token.', 'password-'):
            text = 'tool ' + (shape * 40)[:150] + '=value rest'
            self.assertEqual(win._reg_redact(text), P.redact_command(text), shape)
            self.assertIn('[REDACTED]', win._reg_redact(text), shape)


class TestTheLogSweepAndTheModelKeepTheirAnswers(unittest.TestCase):
    def test_a_log_line_is_scrubbed_as_it_was(self):
        for text in ['db password=hunter2 api_key: sk-live-123 client_secret=\'abc12345\'', 'Authorization: Bearer abcdef123456789',
                     'fetch https://user:s3cretpw@host.example/x failed', 'x.token=1 and auth.key: "a b" and community=public', '', 'nothing here', 'password=']:
            with self.subTest(text=text):
                self.assertEqual(T._redact_log_line(text), sweep_first_version(text))

    def test_random_log_lines_are_scrubbed_as_the_first_version_did(self):
        rnd = random.Random(8024)
        for _ in range(20000):
            text = ''.join(rnd.choice(VOCABULARY_TEXT) for _ in range(rnd.randint(1, 12)))
            want = sweep_first_version(text)
            if T._redact_log_line(text) != want:
                self.fail('%r: the first version says %r, now %r' % (text, want, T._redact_log_line(text)))

    def test_a_value_of_more_than_256_characters_is_hidden_whole(self):
        # on purpose: the first version stopped at 256 characters and left the rest of the word in the clear
        line = 'password=' + 'a' * 300 + ' next'
        self.assertEqual(T._redact_log_line(line), 'password=[REDACTED] next')
        self.assertEqual(sweep_first_version(line), 'password=[REDACTED]' + 'a' * 44 + ' next', 'the oracle shows what was left')
        glued = 'password=' + 'a' * 255 + '.token=second rest'
        self.assertEqual(T._redact_log_line(glued), 'password=[REDACTED] rest', 'a name inside the word is part of the value that is hidden')

    def test_the_model_sees_a_text_masked_as_it_was(self):
        for text in ['db password=hunter2 api_key: sk-live-123', 'token=abc, secret=def; community=public', 'a.token="x y" b', 'curl --token abc -H "Authorization: Bearer xyz"',
                     'plain text', '', 'x' * 500]:
            with self.subTest(text=text):
                self.assertEqual(M._mask_text(text, 400), mask_first_version(text, 400))

    def test_random_texts_are_masked_as_the_first_version_did(self):
        rnd = random.Random(8025)
        for _ in range(20000):
            text = ''.join(rnd.choice(VOCABULARY_TEXT) for _ in range(rnd.randint(1, 12)))
            want = mask_first_version(text, 400)
            if M._mask_text(text, 400) != want:
                self.fail('%r: the first version says %r, now %r' % (text, want, M._mask_text(text, 400)))

    def test_the_fuzz_hides_something_in_a_fair_share_of_the_texts(self):
        rnd = random.Random(8025)
        texts = [''.join(rnd.choice(VOCABULARY_TEXT) for _ in range(rnd.randint(1, 12))) for _ in range(2000)]
        self.assertGreater(sum('[REDACTED]' in T._redact_log_line(t) for t in texts), 300)
        self.assertGreater(sum('***' in M._mask_text(t, 400) for t in texts), 300)


# ── time ──────────────────────────────────────────────────────────────────────

_PRELUDE = textwrap.dedent('''
    import importlib.util, json, os, sys, tempfile, time
    root = sys.argv[1]
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-redact-child-")
    sys.path.insert(0, os.path.join(root, "server", "cgi-bin"))
    sys.path.insert(0, os.path.join(root, "tests"))
    import persistence as P
    import ai_triage_handlers as T
    import mcp_http as M
    spec = importlib.util.spec_from_file_location("rp_win_child", os.path.join(root, "client", "remotepower-agent-win.py"))
    win = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(win)
    FUNCTIONS = (("agent", win._reg_redact), ("inventory", win._persist_command), ("server", P.redact_command),
                 ("sweep", T._redact_log_line), ("mcp", lambda text: M._mask_text(text, 400)))
''')


def run_child(body, timeout=25):
    """(parsed JSON the child printed, timed_out). The child has the Windows agent as `win`, the server's persistence module as `P`, the AI triage module as `T`
    and the hosted MCP module as `M`."""
    code = _PRELUDE + textwrap.dedent(body)
    try:
        r = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT)], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, True
    if r.returncode != 0:
        raise AssertionError('child failed: ' + r.stderr[-800:])
    return json.loads(r.stdout), False


SHAPES = ['pwd.', 'password-', 'x.token.', ' -pwd.', '/pwd.', '-pwd.', '--pass-', 'a', 'pass ', '=pwd:', 'token.', 'auth.', 'community-']


class TestTheTimeIsInProportionToTheText(unittest.TestCase):
    def test_hostile_text_of_thousands_of_characters_is_redacted_at_once(self):
        # 4,000 characters took half a minute, and 8,000 an eternity; the five functions that run the patterns
        got, timed_out = run_child('''
            shapes = %r
            worst = {}
            for shape in shapes:
                for n in (4000, 8000):
                    text = (shape * n)[:n]
                    for name, fn in FUNCTIONS:
                        t = time.perf_counter()
                        fn(text)
                        worst[name] = max(worst.get(name, 0.0), time.perf_counter() - t)
            print(json.dumps(worst))
        ''' % (SHAPES,))
        self.assertFalse(timed_out, 'the redaction of a text of 4,000 characters did not finish in 25 seconds')
        self.assertEqual(sorted(got), ['agent', 'inventory', 'mcp', 'server', 'sweep'], 'every function was timed')
        for name, seconds in got.items():
            self.assertLess(seconds, 0.5, name)

    def test_doubling_the_text_does_not_cost_more_than_three_times_as_much(self):
        got, timed_out = run_child('''
            def best(fn, text, loops):
                runs = []
                for _ in range(4):
                    t = time.perf_counter()
                    for _ in range(loops):
                        fn(text)
                    runs.append(time.perf_counter() - t)
                return min(runs)
            out = {}
            for name, fn in FUNCTIONS:
                if name == "inventory":
                    continue                     # the same two patterns as "agent", cut to what the inventory keeps
                for shape in %r:
                    times = []
                    for n in (2000, 4000, 8000):
                        text = (shape * n)[:n]
                        times.append(best(fn, text, 240000 // n))
                    out[name + " " + shape] = [round(b / a, 2) for a, b in zip(times, times[1:])]
            print(json.dumps(out))
        ''' % (SHAPES,), timeout=150)
        self.assertFalse(timed_out, 'the redaction did not finish in 150 seconds')
        self.assertEqual(len(got), 4 * len(SHAPES), 'every function and shape was timed')
        for shape, ratios in got.items():
            for ratio in ratios:
                self.assertLess(ratio, 3.0, '%r: doubling the text cost %s times as much' % (shape, ratio))

    def test_the_timing_instrument_sees_a_slow_pattern(self):
        # the control: the first version's patterns, run the same way, are over the bounds the tests above hold the new ones to
        got, timed_out = run_child('''
            import re
            name = win._SECRET_NAME_PATTERN
            old_kv = re.compile(r'(?i)(\\b[\\w.-]*' + name + r'[\\w.-]*)(\\s*[=:]\\s*)("[^"]*"|\\'[^\\']*\\'|\\S+)')
            old_flag = re.compile(r'(?i)((?:^|\\s)(?:--?|/)[\\w.-]*' + name + r'[\\w.-]*)(\\s*[=:]\\s*|\\s+)("[^"]*"|\\'[^\\']*\\'|\\S+)')
            old_mcp = re.compile(r"""(\\b[\\w.-]*(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|community)[\\w.-]*\\s*[=:]\\s*)("[^"\\n]*"|'[^'\\n]*'|[^\\s,;]+)""", re.I)
            def ratio(rx, shape):
                times = []
                for n in (500, 1000, 2000):
                    t = time.perf_counter()
                    rx.sub(r'\\1[R]', (shape * n)[:n])
                    times.append(time.perf_counter() - t)
                return times[2] / times[1]
            print(json.dumps({"kv": ratio(old_kv, "pwd."), "flag": ratio(old_flag, "-pwd."), "mcp": ratio(old_mcp, "token.")}))
        ''')
        self.assertFalse(timed_out)
        self.assertGreater(got['kv'], 4.0, 'a cubic pattern costs about eight times as much for twice the text')
        self.assertGreater(got['flag'], 3.0, 'a quadratic pattern costs about four times as much')
        self.assertGreater(got['mcp'], 4.0)


class TestWhatTheAgentAndTheServerDoWithAHostileText(unittest.TestCase):
    def test_the_inventory_of_scheduled_tasks_is_not_held_up_by_their_arguments(self):
        got, timed_out = run_child('''
            from xml.sax.saxutils import escape
            NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
            def task(i, args):
                return ('<?xml version="1.0" encoding="UTF-16"?>\\n<Task version="1.2" xmlns="%s"><RegistrationInfo><URI>\\\\Updater%04d</URI></RegistrationInfo>'
                        '<Settings><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>%s</Arguments></Exec></Actions></Task>'
                        % (NS, i, escape(args)))
            text = "\\n".join(task(i, ("pwd." * 200)[:470]) for i in range(500))
            env = {"systemroot": "C:\\\\Windows", "windir": "C:\\\\Windows", "temp": "C:\\\\Windows\\\\TEMP"}
            t = time.perf_counter()
            found, any_task, truncated = win._persist_parse_tasks(text, env)
            print(json.dumps({"seconds": time.perf_counter() - t, "entries": len(found)}))
        ''')
        self.assertFalse(timed_out, '500 tasks whose arguments are 470 characters of one name took more than 25 seconds')
        self.assertEqual(got['entries'], 500, 'the instrument sees the tasks')
        self.assertLess(got['seconds'], 3.0)

    def test_the_event_log_rule_for_a_new_task_is_not_held_up_by_its_arguments(self):
        got, timed_out = run_child('''
            import win_event_samples as S
            from xml.sax.saxutils import escape
            def definition(args):
                return ('<?xml version="1.0" encoding="UTF-16"?>\\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo>'
                        '<URI>\\\\Updater</URI></RegistrationInfo><Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>%s</Arguments></Exec></Actions></Task>' % escape(args))
            def event(rid, args):
                return S.event_xml(4698, rid, "Security", S.PROVIDERS["Security"], [("SubjectUserSid", S.SID_USER), ("SubjectUserName", "bob"), ("SubjectDomainName", "CORP"),
                                   ("SubjectLogonId", "0x5b3c2d"), ("TaskName", "\\\\Updater"), ("TaskContent", definition(args))])
            def run(args):
                count = int([a for a in args if a.startswith("/c:")][0][3:])
                if any(a.startswith("/q:") for a in args):
                    return "".join(event(1000 + i, ("pwd." * 600)[:1988]) for i in range(count))
                return event(5000, "x")
            t = time.perf_counter()
            units, baseline, advance = win._winevt_collect({"Security": [4698]}, {"Security": {"4698": 999}}, run=run)
            lines = units.get("eventlog.Security.4698", [])
            print(json.dumps({"seconds": time.perf_counter() - t, "lines": len(lines)}))
        ''')
        self.assertFalse(timed_out, '50 events of a new task whose arguments are 1,988 characters of one name took more than 25 seconds')
        self.assertEqual(got['lines'], win._WINEVT_PER_ID, 'the instrument sees the events')
        self.assertLess(got['seconds'], 3.0)

    def test_the_server_cleans_a_heartbeat_full_of_hostile_commands_at_once(self):
        got, timed_out = run_child('''
            snap = {"v": P.VERSION}
            for cat, cap in P.CAPS.items():
                reach = cap * 3
                snap[cat] = {"ok": True, "cut": False, "items": ([["Place", "entry%04d" % i, "pwd." * 60] for i in range(reach)] if cat != "winlogon"
                                                                   else [["Winlogon", "Shell", "pwd." * 60], ["Winlogon", "Userinit", "pwd." * 60]])}
            t = time.perf_counter()
            clean = P.clean_snapshot(snap)
            print(json.dumps({"seconds": time.perf_counter() - t, "entries": sum(len(v["items"]) for k, v in clean.items() if k != "v")}))
        ''')
        self.assertFalse(timed_out, 'the cleaning of 1,500 commands of 240 characters of one name took more than 25 seconds')
        self.assertGreater(got['entries'], 400, 'the instrument sees the entries')
        self.assertLess(got['seconds'], 3.0)

    def test_a_model_that_asks_for_the_recent_commands_of_a_host_is_not_held_up_by_what_they_printed(self):
        got, timed_out = run_child('''
            def fetch(path):
                if path == "/api/devices":
                    return [{"device_id": "d1", "name": "web01"}]
                if path.endswith("/output"):
                    return {"outputs": [{"ts": i, "cmd": "run", "rc": 0, "output": ("token." * 2000)[:8192]} for i in range(10)]}
                return {}
            t = time.perf_counter()
            out = M.tool_get_recent_commands({"name": "web01"}, fetch)
            print(json.dumps({"seconds": time.perf_counter() - t, "commands": len(out["commands"]), "shown": len(out["commands"][0]["output"])}))
        ''')
        self.assertFalse(timed_out, 'ten outputs of 8,192 characters of one name took more than 25 seconds')
        self.assertEqual((got['commands'], got['shown']), (10, 2000), 'the instrument sees the commands, each cut to what a model is shown')
        self.assertLess(got['seconds'], 3.0)


class TestARealHeartbeatFromAHostileHost(_Server):
    """The handler itself, with the host's own token: 1,500 commands of 240 characters of one name cost it 13 seconds of processor time, and a benign body of the same
    size and shape 0.13."""

    def snapshot(self, command):
        snap = {'v': P.VERSION}
        for cat, cap in P.CAPS.items():
            reach = cap * 3
            snap[cat] = {'ok': True, 'cut': False,
                         'items': ([['Place', 'entry%04d' % i, command] for i in range(reach)] if cat != 'winlogon'
                                   else [['Winlogon', 'Shell', command], ['Winlogon', 'Userinit', command]])}
        return snap

    def cpu(self, snap):
        t = os.times()
        status, _resp = self.beat('win1', snap)
        spent = os.times().user - t.user
        self.assertEqual(status, 200)
        return spent

    def test_a_heartbeat_of_hostile_commands_costs_about_what_a_benign_one_does(self):
        self.cpu(self.snapshot('abcd' * 60))                    # the first inventory of a host is its baseline
        benign = self.cpu(self.snapshot('abcd' * 60))
        hostile = self.cpu(self.snapshot('pwd.' * 60))
        self.assertLess(hostile, max(2.0, 15 * benign), 'benign %.2f s, hostile %.2f s of processor time' % (benign, hostile))
        stored = self.stored('win1')
        self.assertEqual(len(stored['inv']['run']['items']), P.CAPS['run'], 'the instrument sees the entries it timed')


class TestARealHeartbeatThatCarriesALogSweep(unittest.TestCase):
    """The heartbeat takes `log_sweep` from any host with a token, whether or not a sweep was asked for, and scrubs every line it keeps: 320 lines of 1,024 characters
    of one name cost it minutes of processor time. Run in a child with a limit, with the scratch data directory of its own."""

    def test_a_sweep_of_hostile_lines_is_taken_at_once(self):
        got, timed_out = run_child('''
            spec = importlib.util.spec_from_file_location("api_sweep_child", os.path.join(root, "server", "cgi-bin", "api.py"))
            api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(api)
            now = int(time.time())
            api.save(api.TENANTS_FILE, {"default": {"name": "Default", "status": "active", "builtin": True}})
            api.save(api.USERS_FILE, {"platform": {"role": "admin", "tenant_id": "default"}})
            api.save(api.DEVICES_FILE, {"lin1": {"name": "lin1", "hostname": "lin1", "os": "Debian GNU/Linux 12", "token": "tok-lin1", "last_seen": now, "enrolled": now,
                                                  "tags": [], "group": "", "sysinfo": {}, "agentless": False, "tenant": "default"}})
            api.save(api.CONFIG_FILE, {})
            api._LOAD_CACHE.clear()
            api.fire_webhook = lambda *a, **k: None
            api.audit_log = lambda *a, **k: None
            sweep = {"files": [{"path": "/var/log/app%02d.log" % i, "mtime": now, "size": 1, "score": 1.0, "lines": [("password." * 200)[:1024]] * 400} for i in range(48)],
                     "scanned": 48, "skipped": 0}
            wire = json.dumps({"device_id": "lin1", "token": "tok-lin1", "log_sweep": sweep})
            def respond(status, data=None):
                raise api.HTTPError(status, data)
            api.respond = respond
            api.method = lambda: "POST"
            api.get_json_obj = lambda: json.loads(wire)
            api.get_json_body = api.get_json_obj
            api.get_token_from_request = lambda: "tok-lin1"
            c0 = time.process_time()
            try:
                api.handle_heartbeat()
            except (api.HTTPError, SystemExit):
                pass
            cpu = time.process_time() - c0
            api._LOAD_CACHE.clear()
            stored = (api.load(api.LOG_SWEEP_FILE) or {}).get("lin1") or {}
            print(json.dumps({"cpu": cpu, "lines": sum(len(f["lines"]) for f in stored.get("files", [])), "bytes": len(wire)}))
        ''', timeout=60)
        self.assertFalse(timed_out, 'a log sweep of hostile lines kept the handler for more than 60 seconds')
        self.assertGreater(got['lines'], 200, 'the instrument sees the lines the handler kept')
        self.assertLess(got['cpu'], 5.0, 'processor time of the handler')


# ── the class ────────────────────────────────────────────────────────────────
# The four sites above are one pattern written four times, and the rule is that no pattern has an unbounded run of word characters, dots and hyphens on both sides of a
# secret name. The population is every pattern a `re` call in the three agents and in the server's modules is given, read by syntax tree (a pattern that is built from
# constants and names, as the Windows agent builds its own, is put together first).

RE_FUNCTIONS = ('compile', 'sub', 'subn', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'split')
GREEDY_RUN = r'\[\\w\.\\?-\]\*(?!\?)'       # `[\w.-]*` or `[\w.\-]*` that is not the lazy `[\w.-]*?` of a look-ahead
SECRET_BOTH_SIDES = re.compile(GREEDY_RUN + r'.{0,400}?(?:pass|secret|token|pwd|api|community|credential|auth|bearer)' + r'.{0,400}?' + GREEDY_RUN, re.S | re.I)


def fold(node, env):
    """The text of a pattern given as constants, names of constants and `+`, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = fold(node.left, env), fold(node.right, env)
        return a + b if a is not None and b is not None else None
    return None


def patterns_of(source):
    """[(line, pattern text)] for every `re.<function>(pattern, ...)` in a module's source whose pattern can be put together without running the module."""
    tree = ast.parse(source)
    env = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            value = fold(stmt.value, env)
            if value is not None:
                env[stmt.targets[0].id] = value
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ('re', '_re') and node.func.attr in RE_FUNCTIONS and node.args):
            text = fold(node.args[0], env)
            if text is not None:
                found.append((node.lineno, text))
    return found


def population():
    files = sorted((ROOT / 'client').glob('remotepower-agent*.py')) + sorted((ROOT / 'server' / 'cgi-bin').glob('*.py'))
    out = {}
    for path in files:
        out[path] = patterns_of(path.read_text(encoding='utf-8'))
    return out


class TestNoPatternHasAnUnboundedRunOnBothSidesOfASecretName(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = population()
        cls.every = [(p, line, text) for p, rows in cls.found.items() for line, text in rows]

    def test_the_population_is_the_three_agents_and_the_server_and_it_is_not_empty(self):
        names = {p.name for p in self.found}
        self.assertTrue({'remotepower-agent.py', 'remotepower-agent-win.py', 'remotepower-agent-mac.py', 'api.py', 'persistence.py', 'mcp_http.py',
                         'ai_triage_handlers.py'} <= names)
        self.assertGreater(len(self.every), 600, 'the derivation reads the patterns of every module (748 when this was written)')

    def test_the_derivation_reaches_each_pattern_this_module_times(self):
        texts = {text for _p, _line, text in self.every}
        for label, rx in (('the Windows agent, the flag pattern', win._PERSIST_SECRET_FLAG), ('the Windows agent, the name=value pattern', win._PERSIST_SECRET_KV),
                          ('the server, the flag pattern', P._SECRET_FLAG), ('the server, the name=value pattern', P._SECRET_KV),
                          ('the log sweep', T._REDACT_KV), ('the hosted MCP endpoint', M._MASK_PAIR)):
            self.assertIn(rx.pattern, texts, label + ': the pattern the module compiles is one the derivation found')

    def test_the_detector_sees_the_first_versions(self):
        # the control: the shape that cost the time, in the patterns as they were
        for label, rx in (('flag', OLD_FLAG), ('name=value', OLD_KV), ('log sweep', OLD_TRIAGE_KV), ('mcp', OLD_MASK_PAIR)):
            self.assertTrue(SECRET_BOTH_SIDES.search(rx.pattern), label)
        for label, rx in (('flag', win._PERSIST_SECRET_FLAG), ('name=value', win._PERSIST_SECRET_KV), ('log sweep', T._REDACT_KV), ('mcp', M._MASK_PAIR),
                          ('server flag', P._SECRET_FLAG), ('server name=value', P._SECRET_KV)):
            self.assertFalse(SECRET_BOTH_SIDES.search(rx.pattern), label + ' as it is now')

    def test_the_detector_finds_a_pattern_in_source_that_is_built_the_way_the_windows_agent_builds_its_own(self):
        source = textwrap.dedent('''
            import re
            NAME = r'(?:pass|secret)'
            KV = re.compile(r'(?i)(\\b[\\w.-]*' + NAME + r'[\\w.-]*)(\\s*[=:]\\s*)(\\S+)')
        ''')
        rows = patterns_of(source)
        self.assertEqual(len(rows), 1)
        self.assertTrue(SECRET_BOTH_SIDES.search(rows[0][1]))

    def test_no_pattern_of_the_agents_or_the_server_has_one(self):
        bad = ['%s:%d' % (p.relative_to(ROOT), line) for p, line, text in self.every if SECRET_BOTH_SIDES.search(text)]
        self.assertEqual(bad, [], 'a run of word characters, dots and hyphens on both sides of a secret name takes time in proportion to the cube of the text: take the run '
                                 'whole at its start, `(?<![\\w.-])(?=[\\w.-]*?NAME)([\\w.-]+)`, as tests/test_v802_redaction_linear.py shows')


if __name__ == '__main__':
    unittest.main()
