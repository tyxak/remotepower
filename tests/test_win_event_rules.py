#!/usr/bin/env python3
"""Log rules for the Windows event log: failed logons, lockouts, a service or a task or a user created, an administrator added, the audit log cleared.

Before this, a Windows host had no way to match a log rule against its event log. The agent put Event Log lines in a journal that only the host's page shows (a comment in it
said a rule could key on "[4625]", and no rule could), and the one thing a Windows host sent to POST /api/logs, the file tails, never carried an event. The reader that
exists now is wevtutil, asked for the event ids that the rules of the host name, one unit for each (`eventlog.Security.4625`), through the ordinary rule engine.

What is held here, and how:

  * the parser is shown the eight events as Windows prints them (tests/win_event_samples.py: every field the provider documents, not only the ones read), a batch of several,
    UTF-16 output, and what is hostile in an event: control characters, ANSI escapes, bidi overrides, a name that carries another event's tag, a 10 KB name, a DTD and an
    entity bomb;
  * the wevtutil argument list is built from a fixed channel and numbers only, is exactly what the quoting test says, and is run without a shell;
  * the cursor is driven against a fake event log that answers the way wevtutil does and fails if it is asked anything else: first sight starts at the newest record, nothing
    repeats, nothing is skipped past the cap, a failed post is read again, a cleared log is read from its start, an unreadable log moves nothing;
  * the rules are driven through the real server handlers: the burst threshold, the dedupe of a re-sent line, one unit not crowding out another, `*` leaving the units alone;
  * the real chain, from a rule saved on a host to the alert in the inbox, through the real heartbeat, the real agent and the real log handler;
  * the eight templates of the Add log rule dialog, read out of the shipped script, against the lines the agent writes for the eight events.

Nothing runs on Windows: the event log is a fake that answers in wevtutil's format, and what could not be shown (the output encoding of a real pipe, the audit policy a host
has) is in the hand-over.
"""
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-winevt-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import win_event_samples as S  # noqa: E402
import win_events  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_win_event_rules', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_wspec = importlib.util.spec_from_file_location('rp_win_event_rules', _ROOT / 'client' / 'remotepower-agent-win.py')
win = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(win)

_NODE = shutil.which('node')


# ── an event log that answers the way wevtutil does ──────────────────────────
class FakeEventLog:
    """`run(args)` for _winevt_collect. It reads the argument list the agent builds, insists on exactly the query shapes the agent is meant to send, and answers with the XML
    wevtutil prints (oldest first, or newest first with /rd:true, cut at /c:). A channel in `unreadable` answers None, as wevtutil does when it may not read it."""
    QUERY = re.compile(r'\*\[System\[\(EventID=([0-9]+)\) and \(EventRecordID>([0-9]+)\)\]\]')

    def __init__(self):
        self.events = {c: [] for c in win._WINEVT_CHANNELS}
        self.next_rid = {c: 1 for c in win._WINEVT_CHANNELS}
        self.unreadable = set()
        self.calls = []

    def add(self, channel, builder, **kw):
        """Add an event made by one of the sample builders; returns its record id."""
        rid = self.next_rid[channel]
        self.next_rid[channel] += 1
        xml = builder(rid=rid, **kw)
        self.events[channel].append({'rid': rid, 'id': int(re.search(r'<EventID[^>]*>(\d+)</EventID>', xml).group(1)), 'xml': xml})
        return rid

    def clear(self, channel):
        """What clearing a log does: its records start again from 1."""
        self.events[channel] = []
        self.next_rid[channel] = 1

    def run(self, args):
        self.calls.append(list(args))
        assert args[1] == 'qe' and args[2] in win._WINEVT_CHANNELS, args
        if args[2] in self.unreadable:
            return None
        q = [a[3:] for a in args if a.startswith('/q:')]
        count = int([a[3:] for a in args if a.startswith('/c:')][0])
        newest = [a[4:] for a in args if a.startswith('/rd:')][0] == 'true'
        assert '/f:xml' in args and count >= 1
        rows = list(self.events[args[2]])
        if q:
            m = self.QUERY.fullmatch(q[0])
            assert m, 'the agent sent a query shape the fake does not know: %r' % q[0]
            rows = [e for e in rows if e['id'] == int(m.group(1)) and e['rid'] > int(m.group(2))]
        else:
            assert newest, 'a query with no filter must be the newest-event probe'
        rows.sort(key=lambda e: e['rid'], reverse=newest)
        return '\n'.join(e['xml'] for e in rows[:count])


def _sent(units):
    """{unit: [rid of each line]} from what _winevt_collect would POST."""
    return {u: [int(re.search(r' rid=(\d+) ', e['message']).group(1)) for e in v] for u, v in units.items()}


# ── the argument list ────────────────────────────────────────────────────────
class TestTheWevtutilArguments(unittest.TestCase):
    def test_the_exact_argument_list_of_each_kind_of_query(self):
        a = win._wevtutil_args('Security', 4625, 1048576, 50)
        self.assertIn(os.path.basename(a[0]).lower(), ('wevtutil', 'wevtutil.exe'))
        self.assertEqual(a[1:], ['qe', 'Security', '/q:*[System[(EventID=4625) and (EventRecordID>1048576)]]', '/f:xml', '/c:50', '/rd:false'])
        b = win._wevtutil_args('System', count=1, newest=True)
        self.assertEqual(b[1:], ['qe', 'System', '/f:xml', '/c:1', '/rd:true'])

    def test_a_windows_command_line_quotes_only_the_query_and_nothing_can_become_a_second_command(self):
        line = subprocess.list2cmdline(['wevtutil'] + win._wevtutil_args('Security', 4698, 77, 50)[1:])
        self.assertEqual(line, 'wevtutil qe Security "/q:*[System[(EventID=4698) and (EventRecordID>77)]]" /f:xml /c:50 /rd:false')
        for args in (win._wevtutil_args('Application', 1000, 0, 1), win._wevtutil_args('System', 7045, 2 ** 40, 50)):
            for arg in args[1:]:
                self.assertEqual([c for c in arg if c in '&|;`$%^"\'\n\r\t'], [], arg)

    def test_only_the_three_channels_and_whole_numbers_are_accepted(self):
        for channel in ('security', 'Security ', 'Security;calc', 'Security\n', '', None, 'Microsoft-Windows-PowerShell/Operational', 'ForwardedEvents', '../Security',
                        'Security /c:1', 5):
            with self.subTest(channel=channel):
                with self.assertRaises(ValueError):
                    win._wevtutil_args(channel, 4625, 0, 1)
        for bad_id in ('4625', '4625 or 1=1', True, False, 0, -1, 65536, 1.5, [4625]):
            with self.subTest(event_id=bad_id):
                with self.assertRaises(ValueError):
                    win._wevtutil_args('Security', bad_id, 0, 1)
        for bad_after in ('1', -1, 2 ** 63, True, 1.0, [0]):
            with self.subTest(after=bad_after):
                with self.assertRaises(ValueError):
                    win._wevtutil_args('Security', 4625, bad_after, 1)
        for bad_count in (0, -5, 1001, '50', True, 2.5):
            with self.subTest(count=bad_count):
                with self.assertRaises(ValueError):
                    win._wevtutil_args('Security', 4625, 0, bad_count)

    def test_it_is_run_as_a_list_with_a_timeout_and_never_through_a_shell(self):
        seen = {}

        def fake_run(args, **kw):
            seen['args'], seen['kw'] = args, kw
            return mock.Mock(returncode=0, stdout=b'')
        with mock.patch.object(win.subprocess, 'run', fake_run):
            self.assertEqual(win._winevt_run(win._wevtutil_args('Security', 4625, 5, 50)), '')
        self.assertIsInstance(seen['args'], list)
        self.assertFalse(seen['kw'].get('shell'))
        self.assertTrue(0 < seen['kw']['timeout'] <= 30)
        self.assertTrue(seen['kw']['capture_output'])

    def test_a_failure_is_none_not_an_exception_and_not_an_empty_answer(self):
        for boom in (OSError('no such file'), subprocess.TimeoutExpired('wevtutil', 20)):
            with mock.patch.object(win.subprocess, 'run', mock.Mock(side_effect=boom)):
                self.assertIsNone(win._winevt_run(['wevtutil']))
        with mock.patch.object(win.subprocess, 'run', mock.Mock(return_value=mock.Mock(returncode=5, stdout=b'<Event/>'))):
            self.assertIsNone(win._winevt_run(['wevtutil']), 'access denied must not be read as an answer')
        big = b'x' * (win._WINEVT_STDOUT_MAX + 1)
        with mock.patch.object(win.subprocess, 'run', mock.Mock(return_value=mock.Mock(returncode=0, stdout=big))):
            self.assertIsNone(win._winevt_run(['wevtutil']))

    def test_the_new_code_names_no_shell(self):
        src = (_ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        block = src[src.index('# ── Windows event log rules'):src.index('# v6.3.1: hail-mary log sweep')]
        self.assertGreater(len(block), 8000, 'the region found is too small to be the reader')
        for needle in ('shell=True', 'os.system', 'Popen', 'powershell', '_powershell_bin'):
            self.assertNotIn(needle, block)


# ── the parser, on the events as Windows prints them ─────────────────────────
class TestTheEightEvents(unittest.TestCase):
    EXPECTED = {
        4625: '[4625] failed logon rid=1048576 source=203.0.113.50 type=3 status=0xc000006d substatus=0xc000006a user="bob" domain="CORP" workstation="ATTACKBOX"',
        4740: '[4740] account locked out rid=2001 sid=S-1-5-21-3623811015-3361044348-30300820-1013 user="bob" caller="ATTACKBOX" by="DC01$"',
        7045: '[7045] service installed rid=3001 type="user mode service" start="auto start" name="Updater" '
              'image="C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run" account="LocalSystem"',
        4697: '[4697] service installed rid=4001 type=0x10 start=2 name="Updater" image="C:\\Windows\\Temp\\upd.exe" account="LocalSystem" by="Administrator"',
        4698: '[4698] scheduled task created rid=5001 name="\\Updater" command="C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run" by="bob"',
        4720: '[4720] user created rid=6001 sid=S-1-5-21-3623811015-3361044348-30300820-1014 user="svc-backup2" domain="DESK01" by="Administrator"',
        4732: '[4732] member added rid=7001 group_sid=S-1-5-32-544 member_sid=S-1-5-21-3623811015-3361044348-30300820-1013 group="Administrators" member="-" '
              'by="Administrator"',
        1102: '[1102] audit log cleared rid=8001 by="Administrator" domain="DESK01"',
    }

    def test_each_event_becomes_one_event_and_one_line(self):
        for build, eid, channel in S.EIGHT:
            with self.subTest(eid):
                events = win._winevt_parse(build(ts=S.FIXED_TS))
                self.assertEqual(len(events), 1)
                ev = events[0]
                self.assertEqual((ev['id'], ev['ts']), (eid, S.FIXED_TS_MS))     # 2026-11-18T00:23:45Z
                self.assertEqual(win._winevt_line(ev), self.EXPECTED[eid])

    def test_a_service_event_with_qualifiers_and_a_userdata_event_both_read(self):
        ev = win._winevt_parse(S.service_installed_system())[0]
        self.assertEqual(ev['provider'], 'Service Control Manager')
        ev = win._winevt_parse(S.audit_log_cleared())[0]
        self.assertEqual(ev['data']['SubjectUserName'], 'Administrator')       # 1102 keeps its fields in UserData, one level down

    def test_a_batch_comes_back_in_the_order_wevtutil_printed_it_and_with_any_separator(self):
        xs = [S.failed_logon(rid=10 + i, user='u%d' % i) for i in range(5)]
        for sep in ('\n', '\r\n', '', '\n\n'):
            with self.subTest(sep=repr(sep)):
                events = win._winevt_parse(sep.join(xs))
                self.assertEqual([e['rid'] for e in events], [10, 11, 12, 13, 14])
                self.assertEqual([e['data']['TargetUserName'] for e in events], ['u0', 'u1', 'u2', 'u3', 'u4'])

    def test_an_xml_declaration_before_the_events_is_ignored(self):
        events = win._winevt_parse("<?xml version='1.0' encoding='utf-8'?>\n" + S.failed_logon())
        self.assertEqual(len(events), 1)

    def test_the_output_may_be_utf8_with_a_mark_or_utf16(self):
        text = S.failed_logon(user='Müller')
        self.assertIn('Müller', win._winevt_decode(text.encode('utf-8')))
        self.assertIn('Müller', win._winevt_decode(b'\xef\xbb\xbf' + text.encode('utf-8')))
        self.assertIn('Müller', win._winevt_decode(b'\xff\xfe' + text.encode('utf-16-le')))
        self.assertEqual(win._winevt_parse(win._winevt_decode(b'\xff\xfe' + text.encode('utf-16-le')))[0]['data']['TargetUserName'], 'Müller')

    def test_utf16_without_a_byte_order_mark_is_read_as_utf16_and_not_as_text_with_zero_bytes_in_it(self):
        text = S.failed_logon(user='Müller')
        for codec in ('utf-16-le', 'utf-16-be'):
            with self.subTest(codec):
                got = win._winevt_decode(text.encode(codec))
                self.assertEqual(got, text)
                self.assertEqual(win._winevt_parse(got)[0]['data']['TargetUserName'], 'Müller')
        self.assertEqual(win._winevt_decode(b''), '')
        self.assertEqual(win._winevt_decode('plain text'.encode('utf-8')), 'plain text')

    def test_an_event_with_unnamed_data_and_one_the_agent_has_no_format_for_is_still_a_line(self):
        xml = S.event_xml(4624, 99, 'Security', S.PROVIDERS['Security'], [(None, 'first'), (None, 'second')])
        ev = win._winevt_parse(xml)[0]
        self.assertEqual(ev['data'], {'Data0': 'first', 'Data1': 'second'})
        self.assertEqual(win._winevt_line(ev), '[4624] "Microsoft-Windows-Security-Auditing" rid=99 data0="first" data1="second"')

    def test_the_task_a_new_scheduled_task_runs_is_taken_from_its_definition(self):
        line = win._winevt_line(win._winevt_parse(S.scheduled_task_created())[0])
        self.assertIn(r'command="C:\Users\bob\AppData\Local\Temp\upd.exe -k run"', line)
        no_cmd = S.event_xml(4698, 5, 'Security', S.PROVIDERS['Security'], [('TaskName', 'x'), ('TaskContent', '<Task/>'), ('SubjectUserName', 'bob')])
        self.assertIn('command=""', win._winevt_line(win._winevt_parse(no_cmd)[0]))

    def test_the_time_is_the_events_own_in_utc(self):
        ev = win._winevt_parse(S.failed_logon(ts='2026-01-01T00:00:00.0000000Z'))[0]
        self.assertEqual(ev['ts'], 1767225600000)
        ev = win._winevt_parse(S.failed_logon(ts='not a time'))[0]
        self.assertAlmostEqual(ev['ts'] / 1000.0, time.time(), delta=5)


class TestWhatAnEventCanCarry(unittest.TestCase):
    """The name in a failed logon is whatever the person at the other end typed. None of it may end up as structure in the line."""

    def line(self, **kw):
        return win._winevt_line(win._winevt_parse(S.failed_logon(**kw))[0])

    def test_control_characters_ansi_escapes_and_newlines_become_spaces_and_the_line_stays_one_line(self):
        name = 'bob' + chr(27) + '[31mRED' + chr(0) + chr(10) + 'forged' + chr(13) + chr(9) + 'tab' + chr(0x85) + 'nel' + chr(0x2028) + 'ls' + chr(0x2029) + 'ps'
        out = self.line(user=name)
        self.assertEqual([c for c in out if ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or c in chr(0x2028) + chr(0x2029)], [])
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn('user="bob [31mRED forged tab nel ls ps"', out)

    def test_the_delete_character_and_the_eight_bit_controls_are_gone_too(self):
        """XML 1.0 allows DEL and the C1 range, and str.split() does not treat them as white space (it does treat 0x85 so): only the clean-up itself removes them.
        0x9b is the eight-bit form of the escape that starts an ANSI sequence."""
        out = self.line(user='a' + chr(0x7f) + 'b' + chr(0x9b) + '31m' + chr(0x80) + 'c' + chr(0x9f) + 'd')
        self.assertEqual([c for c in out if 0x7f <= ord(c) <= 0x9f], [])
        self.assertIn('user="a b 31m c d"', out)

    def test_the_characters_that_reorder_or_hide_text_are_gone(self):
        hidden = ''.join(chr(c) for c in (0xad, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff))
        out = self.line(workstation='A' + hidden + 'B')
        self.assertEqual([c for c in out if c in hidden], [])
        self.assertIn('workstation="A B"', out)

    @unittest.skipUnless(_NODE, 'node is not installed')
    def test_a_name_that_carries_another_events_tag_cannot_stand_where_the_tag_is(self):
        out = self.line(user='x" [4732] member added rid=1 group_sid=S-1-5-32-544 y="z')
        self.assertTrue(out.startswith('[4625] failed logon rid='))
        self.assertEqual(out.count('"') % 2, 0, 'a double quote in the text turned into structure: %s' % out)
        # the text is inside its own quotes, with the quote it tried to close turned into a single one
        self.assertIn("user=\"x' [4732] member added rid=1 group_sid=S-1-5-32-544 y='z\"", out)
        self.assertIsNone(re.search(win_events_pattern('administrators-member-added'), out))

    def test_every_text_is_cut_at_64_characters_and_the_line_at_400(self):
        out = self.line(user='u' * 10000, domain='d' * 10000, workstation='w' * 10000)
        self.assertIn('user="%s"' % ('u' * 64), out)
        self.assertNotIn('u' * 65, out)
        self.assertLessEqual(len(out), win._WINEVT_LINE_MAX)
        cmd = S.event_xml(4698, 5, 'Security', S.PROVIDERS['Security'], [('TaskName', 'n' * 500), ('TaskContent', '<Command>%s</Command>' % ('c' * 1500)), ('SubjectUserName', 'b')])
        out = win._winevt_line(win._winevt_parse(cmd)[0])
        self.assertLessEqual(len(out), win._WINEVT_LINE_MAX)
        self.assertNotIn('c' * 121, out)

    def test_a_machine_value_keeps_only_the_characters_such_a_value_has(self):
        out = self.line(ip='1.2.3.4" user="admin', status='0xc000006d; calc', logon_type='3 4')
        self.assertIn('source=1.2.3.4useradmin ', out)
        self.assertIn('status=0xc000006dcalc ', out)
        self.assertIn('type=34 ', out)
        self.assertEqual(self.line(ip='').split(' source=')[1].split(' ')[0], '-')

    def test_a_field_name_an_event_invents_cannot_be_written_as_structure(self):
        xml = S.event_xml(9999, 7, 'Application', ('Evil Provider', '{x}'), [('na me="x" user', 'v')])
        out = win._winevt_line(win._winevt_parse(xml)[0])
        self.assertTrue(out.startswith('[9999] "Evil Provider" rid=7 '))
        self.assertIsNone(re.search(r'[^ ]="[^"]*" user=', out.replace('"v"', 'V')))

    def test_a_dtd_or_an_entity_is_never_parsed_so_nothing_expands_and_the_event_is_still_counted(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>')
        started = time.time()
        # the declaration sits outside every event, so no event is parsed with it; the event that refers to the entity is kept without its fields
        got = win._winevt_parse(bomb + S.failed_logon(rid=41).replace('>bob<', '>&lol3;<'))
        self.assertEqual([(e['rid'], e['id'], e['data']) for e in got], [(41, 4625, {})])
        self.assertNotIn('lollol', repr(got))
        # a declaration inside an event: the event is not handed to the parser at all
        inside = win._winevt_parse(S.failed_logon(rid=42).replace('<Data Name=', '<!ENTITY x "y"><Data Name=', 1))
        self.assertEqual([(e['rid'], e['data']) for e in inside], [(42, {})])
        # a lone declaration outside every event is ignored and the event after it reads whole
        ok = win._winevt_parse('<!doctype x>' + S.failed_logon(rid=43))
        self.assertEqual(ok[0]['data']['TargetUserName'], 'bob')
        self.assertLess(time.time() - started, 2.0)

    def test_a_character_xml_forbids_in_a_name_does_not_cost_the_event_and_so_cannot_stall_the_cursor(self):
        raw = S.failed_logon(rid=7, user='a' + chr(0) + 'b' + chr(27) + 'c' + chr(11) + 'd')
        ref = S.failed_logon(rid=8).replace('>bob<', '>x&#0;y&#27;z&#x1b;w&#65;<')
        refs_ok = S.failed_logon(rid=9).replace('>bob<', '>t&#9;u&#x41;<')
        got = win._winevt_parse(raw + ref + refs_ok)
        self.assertEqual([e['rid'] for e in got], [7, 8, 9])
        users = [e['data'].get('TargetUserName') for e in got]
        self.assertEqual(users, ['a b c d', 'x y z wA', 't\tuA'])
        self.assertEqual(win._winevt_line(got[0]).split(' user=')[1].split(' domain=')[0], '"a b c d"')

    def test_an_event_that_does_not_parse_at_all_is_a_line_without_its_fields_not_a_wall(self):
        broken = S.failed_logon(rid=20).replace('<Data Name=', '<Data Nam e=', 1)
        batch = S.failed_logon(rid=19) + broken + S.failed_logon(rid=21)
        got = win._winevt_parse(batch)
        self.assertEqual([(e['rid'], e['id']) for e in got], [(19, 4625), (20, 4625), (21, 4625)])
        self.assertEqual(got[1]['data'], {})
        self.assertEqual(win._winevt_line(got[1]), '[4625] failed logon rid=20 source=- type=- status=- substatus=- user="" domain="" workstation=""')

    def test_a_bad_event_in_the_middle_of_a_batch_moves_the_cursor_past_itself(self):
        log = FakeEventLog()
        log.add('Security', S.audit_log_cleared)
        cursor = {}
        units, baseline, advance = win._winevt_collect({'Security': [4625]}, cursor, run=log.run)
        cursor.update(baseline)
        log.add('Security', S.failed_logon)
        bad = log.add('Security', S.failed_logon, user='x' + chr(0) + '&#27;')
        log.events['Security'][-1]['xml'] = log.events['Security'][-1]['xml'].replace('<Data Name=', '<Data Nam e=', 1)
        log.add('Security', S.failed_logon)
        units, baseline, advance = win._winevt_collect({'Security': [4625]}, cursor, run=log.run)
        self.assertEqual(_sent(units), {'eventlog.Security.4625': [2, bad, 4]})
        self.assertEqual(advance, {'Security': {'4625': 4}})

    def test_what_is_not_wevtutils_output_reads_as_nothing_and_not_as_an_empty_log(self):
        for junk in ('Access is denied.', '<Event><System>', '{"json": 1}', S.failed_logon()[:-30], '<<<>>>', b'bytes'):
            self.assertIsNone(win._winevt_parse(junk), junk)
        for empty in ('', '  \n'):
            self.assertEqual(win._winevt_parse(empty), [])

    def test_an_event_that_cannot_be_numbered_is_left_out_not_guessed_at(self):
        good, bad = S.failed_logon(rid=5), S.failed_logon(rid=6).replace('<EventRecordID>6<', '<EventRecordID>six<')
        self.assertEqual([e['rid'] for e in win._winevt_parse(good + bad)], [5])
        no_id = S.failed_logon(rid=7).replace('<EventID>4625</EventID>', '')
        self.assertEqual(win._winevt_parse(no_id), [])

    def test_a_flood_of_fields_is_cut(self):
        many = S.event_xml(4625, 1, 'Security', S.PROVIDERS['Security'], [('F%d' % i, 'v') for i in range(500)])
        self.assertLessEqual(len(win._winevt_parse(many)[0]['data']), win._WINEVT_DATA_MAX)


def win_events_pattern(template_id):
    return next(t['pattern'] for t in _templates() if t['id'] == template_id)


_TEMPLATES = None


def _templates():
    """LOG_RULE_TEMPLATES, evaluated out of the script the dialog ships."""
    global _TEMPLATES
    if _TEMPLATES is None:
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-logs.js').read_text(encoding='utf-8')
        m = re.search(r'const LOG_RULE_TEMPLATES = (\[.*?\n\]);', js, re.S)
        assert m, 'LOG_RULE_TEMPLATES is not in app-logs.js'
        out = subprocess.run([_NODE, '-e', 'console.log(JSON.stringify(eval(process.argv[1])))', m.group(1)], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        _TEMPLATES = json.loads(out.stdout)
    return _TEMPLATES


# ── the cursor ───────────────────────────────────────────────────────────────
class TestAPasswordInAProgramIsNotInTheLine(unittest.TestCase):
    """The program a new service or task runs, with its arguments, can hold a password. The persistence inventory and the registry check replace it; the event line did not."""

    def line(self, xml):
        (ev,) = win._winevt_parse(xml)
        return win._winevt_line(ev)

    def task(self, arguments):
        content = S.TASK_DEFINITION.replace('<Arguments>-k run</Arguments>', '<Arguments>%s</Arguments>' % arguments)
        return S.event_xml(4698, 9001, 'Security', S.PROVIDERS['Security'], [('SubjectUserName', 'bob'), ('TaskName', '\\Backup'), ('TaskContent', content)])

    def test_a_password_in_the_arguments_of_a_new_task_is_replaced(self):
        line = self.line(self.task('--password hunter2 --server nas'))
        self.assertIn('--password [REDACTED] --server nas', line)
        self.assertNotIn('hunter2', line)

    def test_a_password_in_the_program_of_a_new_service_is_replaced_in_both_events(self):
        for build, secret in ((S.service_installed_system, 'abc123'), (S.service_installed_security, 'abc123')):
            line = self.line(build(image=r'C:\Tools\svc.exe -token abc123 -x'))
            self.assertIn('-token [REDACTED] -x', line)
            self.assertNotIn(secret, line)

    def test_the_cut_cannot_leave_half_of_a_password_in_the_line(self):
        for pad in range(30, 125):
            line = self.line(self.task('a' * pad + ' --password hunter2'))
            self.assertNotIn('hunter', line, pad)
            line = self.line(self.task('a' * pad + ' --password "alpha bravo charlie"'))      # a secret with spaces in it: a cut inside it must not leave the rest of the words
            for word in ('alpha', 'bravo', 'charlie'):
                self.assertNotIn(word, line, pad)

    def test_a_program_with_no_secret_in_it_is_in_the_line_as_it_is(self):
        """The control: a replacement that took the whole command out would pass the tests above."""
        self.assertIn('command="C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run"', self.line(S.scheduled_task_created()))
        self.assertIn('image="C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run"', self.line(S.service_installed_system()))

    def test_a_name_that_is_not_a_program_is_left_alone(self):
        line = self.line(S.failed_logon(user='token', workstation='password=1'))
        self.assertIn('user="token"', line)
        self.assertIn('workstation="password=1"', line)


class TestTheCursor(unittest.TestCase):
    WATCH = {'Security': [4625, 1102]}

    def setUp(self):
        self.log = FakeEventLog()
        self.cursor = {}

    def poll(self, watch=None, commit=True):
        """One check-in: collect, remember the baselines at once, and the advance only when the post is taken (`commit`)."""
        watch = self.WATCH if watch is None else watch
        units, baseline, advance = win._winevt_collect(watch, self.cursor, run=self.log.run)
        merged = {ch: v for ch, v in self.cursor.items() if ch in watch}
        merged.update({ch: dict(v) for ch, v in baseline.items()})
        self.cursor.clear()
        self.cursor.update(merged)
        if commit:
            for ch, ids in advance.items():
                self.cursor.setdefault(ch, {}).update(ids)
        return units

    def test_first_sight_starts_at_the_newest_record_and_sends_no_history(self):
        for _ in range(3):
            self.log.add('Security', S.failed_logon)
        self.log.add('Security', S.audit_log_cleared)
        self.assertEqual(self.poll(), {})
        self.assertEqual(self.cursor, {'Security': {'4625': 4, '1102': 4}})
        self.assertEqual(self.poll(), {}, 'nothing new, nothing sent')

    def test_what_happens_after_is_sent_once_oldest_first_and_never_again(self):
        self.log.add('Security', S.failed_logon)
        self.poll()
        a = self.log.add('Security', S.failed_logon, user='a', ts=S.FIXED_TS)
        self.log.add('Security', S.account_locked_out)             # another id of the channel: not asked for
        b = self.log.add('Security', S.failed_logon, user='b')
        units = self.poll()
        self.assertEqual(_sent(units), {'eventlog.Security.4625': [a, b]})
        self.assertEqual(units['eventlog.Security.4625'][0]['ts'], S.FIXED_TS_MS)
        self.assertEqual(self.poll(), {})
        c = self.log.add('Security', S.audit_log_cleared)
        self.assertEqual(_sent(self.poll()), {'eventlog.Security.1102': [c]})
        self.assertEqual(self.cursor['Security'], {'4625': b, '1102': c})

    def test_more_than_the_cap_is_read_over_several_check_ins_with_none_skipped_and_none_repeated(self):
        self.log.add('Security', S.audit_log_cleared)
        self.poll({'Security': [4625]})
        rids = [self.log.add('Security', S.failed_logon) for _ in range(130)]
        got = []
        for _ in range(5):
            got += _sent(self.poll({'Security': [4625]})).get('eventlog.Security.4625', [])
        self.assertEqual(got, rids)
        sizes = [len(c) for c in [rids[:50], rids[50:100], rids[100:]]]
        self.assertEqual(sizes, [50, 50, 30])

    def test_a_flood_of_one_id_does_not_stand_in_front_of_another(self):
        self.poll()
        flood = [self.log.add('Security', S.failed_logon) for _ in range(120)]
        cleared = self.log.add('Security', S.audit_log_cleared)
        units = self.poll()
        self.assertEqual(len(units['eventlog.Security.4625']), 50)
        self.assertEqual(_sent(units)['eventlog.Security.1102'], [cleared], 'the one rare event waits behind a flood of another id')
        self.assertEqual(flood[49], _sent(units)['eventlog.Security.4625'][-1])

    def test_the_lines_of_one_check_in_are_capped_in_all_and_the_rest_waits(self):
        watch = {'Security': [4625, 4740, 4720, 4732, 4697, 4698, 1102]}
        self.poll(watch)
        builders = {4625: S.failed_logon, 4740: S.account_locked_out, 4720: S.user_created, 4732: S.member_added, 4697: S.service_installed_security,
                    4698: S.scheduled_task_created, 1102: S.audit_log_cleared}
        added = {eid: [self.log.add('Security', b) for _ in range(60)] for eid, b in builders.items()}
        total = 0
        seen = {eid: [] for eid in builders}
        for _ in range(4):
            units = self.poll(watch)
            total_now = sum(len(v) for v in units.values())
            self.assertLessEqual(total_now, win._WINEVT_MAX_LINES)
            total += total_now
            for unit, rids in _sent(units).items():
                seen[int(unit.rsplit('.', 1)[1])] += rids
        self.assertEqual(total, 7 * 60)
        self.assertEqual(seen, added)

    def test_the_total_cap_holds_when_the_per_id_cap_does_not_divide_it(self):
        """With 50 events an id and 300 lines in all the second cap can only ever fall on a whole query, so a cap that is not a multiple of the first
        shows whether the trimming itself is there: the last query of a check-in is cut to what is left, and the cursor stops at the last line sent."""
        watch = {'Security': [4625, 4740]}
        self.poll(watch)
        a = [self.log.add('Security', S.failed_logon) for _ in range(70)]
        b = [self.log.add('Security', S.account_locked_out) for _ in range(70)]
        seen = {4625: [], 4740: []}
        with mock.patch.object(win, '_WINEVT_PER_ID', 70), mock.patch.object(win, '_WINEVT_MAX_LINES', 100):
            for n in range(3):
                units = self.poll(watch)
                self.assertLessEqual(sum(len(v) for v in units.values()), 100)
                if n == 0:
                    self.assertEqual({u.rsplit('.', 1)[1]: len(v) for u, v in units.items()}, {'4625': 70, '4740': 30})
                for unit, rids in _sent(units).items():
                    seen[int(unit.rsplit('.', 1)[1])] += rids
        self.assertEqual(seen, {4625: a, 4740: b}, 'what the cap cut off waits behind the cursor and comes at the next check-in')

    def test_a_failed_post_leaves_the_cursor_where_it_was_and_the_same_events_come_again(self):
        self.poll()
        a = self.log.add('Security', S.failed_logon)
        first = self.poll(commit=False)
        again = self.poll(commit=False)
        self.assertEqual(_sent(first), _sent(again))
        self.assertEqual(_sent(first), {'eventlog.Security.4625': [a]})
        self.assertEqual(_sent(self.poll()), {'eventlog.Security.4625': [a]})
        self.assertEqual(self.poll(), {})

    def test_a_cleared_log_is_read_from_its_start_and_the_clearing_itself_is_found(self):
        for _ in range(100):
            self.log.add('Security', S.failed_logon)
        self.poll()
        self.assertEqual(self.cursor['Security']['4625'], 100)
        self.log.clear('Security')
        cleared = self.log.add('Security', S.audit_log_cleared)          # record 1: below the cursor of 100
        later = self.log.add('Security', S.failed_logon)
        self.assertEqual((cleared, later), (1, 2))
        units = self.poll()
        self.assertEqual(_sent(units), {'eventlog.Security.1102': [1], 'eventlog.Security.4625': [2]})
        self.assertEqual(self.poll(), {})

    def test_a_log_that_cannot_be_read_moves_nothing_and_says_nothing(self):
        self.log.add('Security', S.failed_logon)
        self.poll()
        before = json.dumps(self.cursor, sort_keys=True)
        self.log.add('Security', S.failed_logon)
        self.log.unreadable.add('Security')
        self.assertEqual(self.poll(), {})
        self.assertEqual(json.dumps(self.cursor, sort_keys=True), before)
        self.log.unreadable.clear()
        self.assertEqual(len(self.poll()['eventlog.Security.4625']), 1, 'the event is still there when the log can be read again')

    def test_an_event_of_another_id_that_a_query_returns_is_not_sent(self):
        self.poll()
        self.log.add('Security', S.failed_logon)
        real = self.log.run

        def lying(args):
            out = real(args)
            return (out or '') + S.account_locked_out(rid=999)
        units, _b, _a = win._winevt_collect(self.WATCH, self.cursor, run=lying)
        self.assertEqual(_sent(units), {'eventlog.Security.4625': [1]})

    def test_an_id_that_is_no_longer_asked_for_is_forgotten_so_asking_again_starts_fresh(self):
        self.log.add('Security', S.failed_logon)
        self.poll()
        self.poll({'Security': [1102]})
        self.assertEqual(self.cursor['Security'], {'1102': 1})
        gap = self.log.add('Security', S.failed_logon)            # while nobody was asking
        self.assertEqual(self.poll(), {}, 'the event from the gap must not come back as news')
        self.assertEqual(self.cursor['Security']['4625'], gap)

    def test_the_number_of_runs_and_the_seconds_are_bounded_and_what_is_left_is_read_next_time(self):
        watch = {'Security': [4625, 4740, 4720], 'System': [7045]}
        self.poll(watch)
        want = [(self.log.add('Security', S.failed_logon), 4625), (self.log.add('Security', S.account_locked_out), 4740),
                (self.log.add('Security', S.user_created), 4720), (self.log.add('System', S.service_installed_system), 7045)]
        with mock.patch.object(win, '_WINEVT_MAX_RUNS', 3):
            first = self.poll(watch)
        self.assertEqual(sorted(first), ['eventlog.Security.4625', 'eventlog.Security.4740'], 'three runs: the Security probe and two ids')
        with mock.patch.object(win, '_WINEVT_MAX_RUNS', 40):
            rest = self.poll(watch)
            rest2 = self.poll(watch)
        got = sorted(int(u.rsplit('.', 1)[1]) for u in list(first) + list(rest) + list(rest2))
        self.assertEqual(got, [4625, 4720, 4740, 7045])
        self.assertEqual(len(want), 4)
        calls = len(self.log.calls)
        with mock.patch.object(win, '_WINEVT_BUDGET_S', -1):
            self.assertEqual(self.poll(watch), {})
        self.assertEqual(len(self.log.calls), calls, 'no budget, no run')

    def test_every_query_the_agent_sends_is_one_the_fake_accepts_and_a_watch_of_nothing_runs_nothing(self):
        self.poll()
        self.log.add('Security', S.failed_logon)
        self.poll()
        self.assertTrue(self.log.calls)
        n = len(self.log.calls)
        self.assertEqual(self.poll({}), {})
        self.assertEqual(len(self.log.calls), n)


class TestTheWatchTheServerSends(unittest.TestCase):
    def rules(self, *units):
        return [{'unit': u, 'pattern': 'x'} for u in units]

    def test_the_units_of_the_list_are_what_is_read_and_it_is_checked_again_here(self):
        watch = win._winevt_watch_from_rules
        self.assertEqual(watch(self.rules('eventlog.Security.4625', 'eventlog.Security.1102', 'eventlog.System.7045')), {'Security': [1102, 4625], 'System': [7045]})
        self.assertEqual(watch(self.rules('eventlog.Security.4625', 'eventlog.Security.4625', 'eventlog.Security.4625')), {'Security': [4625]})
        self.assertEqual(watch(self.rules(*['eventlog.Security.%d' % i for i in range(1, 100)])), {'Security': list(range(1, 13))})

    def test_a_row_that_is_not_an_event_unit_asks_for_nothing(self):
        watch = win._winevt_watch_from_rules
        bad = ['eventlog.Foo.1', 'eventlog.security.4625', 'eventlog.Security.0', 'eventlog.Security.65536', 'eventlog.Security.04625', 'eventlog.Security.4625x',
               'eventlog.Security.4625\n', 'eventlog.Security', 'x.eventlog.Security.4625', 'nginx.service', '*', 'file:C:\\logs\\x.log', '', None, 5, True]
        self.assertEqual(watch(self.rules(*bad)), {})
        self.assertEqual(watch(['eventlog.Security.4625', None, 5, ['eventlog.Security.4625'], {'path': 'C:\\x.log'}, {'unit': ['eventlog.Security.4625']}]), {})
        self.assertEqual(watch(None), {})
        self.assertEqual(watch({'unit': 'eventlog.Security.4625'}), {})
        self.assertEqual(watch([]), {})


class TestTheSubmitStep(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='rp-winevt-agent-')
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.saved = (win._eventlog_watch, win._winevt_cursor)
        self.addCleanup(lambda: setattr(win, '_eventlog_watch', self.saved[0]))
        self.addCleanup(lambda: setattr(win, '_winevt_cursor', self.saved[1]))
        win._eventlog_watch, win._winevt_cursor = {}, None
        self.log = FakeEventLog()
        self.posts = []
        self.fail_posts = False

        def post(url, body, *a, **k):
            if self.fail_posts:
                raise OSError('connection refused')
            self.posts.append((url, body))
            return {'ok': True}
        patches = [mock.patch.object(win, '_data_dir', lambda: self.dir), mock.patch.object(win, '_winevt_run', self.log.run),
                   mock.patch.object(win, '_post_json', post)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.creds = {'server_url': 'https://rp.example', 'device_id': 'winhost', 'token': 't0k'}

    def cursor_file(self):
        path = os.path.join(self.dir, win._WINEVT_CURSOR_FILE)
        if not os.path.exists(path):
            return None
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def test_nothing_is_asked_nothing_runs_and_nothing_is_posted(self):
        win._submit_event_logs(self.creds, 1)
        self.assertEqual((self.log.calls, self.posts, self.cursor_file()), ([], [], None))

    def test_the_post_is_the_log_endpoint_with_the_units_and_the_cursor_is_saved_after_it(self):
        win._eventlog_watch = {'Security': [4625]}
        win._submit_event_logs(self.creds, 1)                                  # first sight: baseline, saved at once
        self.assertEqual((self.posts, self.cursor_file()), ([], {'Security': {'4625': 0}}))
        rid = self.log.add('Security', S.failed_logon)
        win._submit_event_logs(self.creds, 2)
        (url, body), = self.posts
        self.assertEqual(url, 'https://rp.example/api/logs')
        self.assertEqual({k: body[k] for k in ('device_id', 'token')}, {'device_id': 'winhost', 'token': 't0k'})
        (unit, entries), = body['units'].items()
        self.assertEqual(unit, 'eventlog.Security.4625')
        self.assertEqual(len(entries), 1)
        self.assertEqual(set(entries[0]), {'message', 'ts'})
        self.assertIn(' rid=%d ' % rid, entries[0]['message'])
        self.assertEqual(self.cursor_file(), {'Security': {'4625': rid}})
        win._submit_event_logs(self.creds, 3)
        self.assertEqual(len(self.posts), 1, 'what was taken is not sent again')

    def test_a_post_that_fails_is_read_again_and_one_that_works_is_not(self):
        win._eventlog_watch = {'Security': [4625]}
        win._submit_event_logs(self.creds, 1)
        self.log.add('Security', S.failed_logon)
        self.fail_posts = True
        win._submit_event_logs(self.creds, 2)
        self.assertEqual((self.posts, self.cursor_file()), ([], {'Security': {'4625': 0}}))
        self.fail_posts = False
        win._submit_event_logs(self.creds, 3)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(len(self.posts[0][1]['units']['eventlog.Security.4625']), 1)

    def test_the_cursor_survives_a_restart_and_a_corrupt_file_is_a_first_sight(self):
        win._eventlog_watch = {'Security': [4625]}
        win._submit_event_logs(self.creds, 1)
        self.log.add('Security', S.failed_logon)
        win._submit_event_logs(self.creds, 2)
        win._winevt_cursor = None                                              # the agent starts again
        win._submit_event_logs(self.creds, 3)
        self.assertEqual(len(self.posts), 1)
        win._winevt_cursor = None
        Path(self.dir, win._WINEVT_CURSOR_FILE).write_text('{not json', encoding='utf-8')
        self.log.add('Security', S.failed_logon)
        win._submit_event_logs(self.creds, 4)
        self.assertEqual(len(self.posts), 1, 'a lost cursor starts from the newest record, it does not replay')
        self.assertEqual(self.cursor_file(), {'Security': {'4625': 2}})

    def test_when_the_last_rule_goes_the_cursor_goes_and_a_later_rule_starts_fresh(self):
        win._eventlog_watch = {'Security': [4625]}
        win._submit_event_logs(self.creds, 1)
        win._eventlog_watch = {}
        win._submit_event_logs(self.creds, 2)
        self.assertEqual(self.cursor_file(), {})
        self.log.add('Security', S.failed_logon)
        win._eventlog_watch = {'Security': [4625]}
        win._submit_event_logs(self.creds, 3)
        self.assertEqual(self.posts, [], 'an event from the gap is not news')

    def test_a_cursor_file_is_not_trusted_for_its_types(self):
        Path(self.dir, win._WINEVT_CURSOR_FILE).write_text(
            json.dumps({'Security': {'4625': 'x', '1102': -5, '4740': True, '4720': 2.5}, 'Evil': {'1': 1}}), encoding='utf-8')
        win._eventlog_watch = {'Security': [4625, 1102, 4740, 4720]}
        self.log.add('Security', S.failed_logon)
        win._submit_event_logs(self.creds, 1)
        self.assertEqual(self.posts, [])
        self.assertEqual(self.cursor_file(), {'Security': {'4625': 1, '1102': 1, '4740': 1, '4720': 1}})


# ── the server ───────────────────────────────────────────────────────────────
class TestTheUnitsAndTheWatch(unittest.TestCase):
    def test_the_shape_of_a_unit(self):
        for ok in ('eventlog.Security.4625', 'eventlog.System.7045', 'eventlog.Application.1000', 'eventlog.Security.65535', 'eventlog.Security.1'):
            self.assertIsNotNone(win_events.parse_unit(ok), ok)
        for bad in ('eventlog.Security.0', 'eventlog.Security.65536', 'eventlog.Security.04625', 'eventlog.security.4625', 'eventlog.Security.4625x', 'eventlog.Security',
                    'eventlog.Foo.1', 'eventlog.Security.4625.1', 'eventlog.Security. 4625', 'eventlog.', 'Eventlog.Security.4625', 'x.eventlog.Security.4625',
                    'eventlog.Security.4625\n', '*', '', None, 5, 'eventlog.Security.-1', 'eventlog.Security.1e3', 'file:/x'):
            self.assertIsNone(win_events.parse_unit(bad), repr(bad))
        self.assertEqual(win_events.parse_unit('eventlog.System.7045'), ('System', 7045))

    def test_a_star_rule_and_a_normal_unit_are_not_event_units(self):
        self.assertTrue(win_events.is_event_unit('eventlog.Security.4625'))
        self.assertTrue(win_events.is_event_unit('eventlog.nonsense'))
        for u in ('*', 'nginx.service', 'file:/x', '', None):
            self.assertFalse(win_events.is_event_unit(u))

    def test_the_watch_is_the_units_of_the_rules_validated_sorted_and_capped(self):
        own = [{'unit': 'eventlog.Security.4625', 'pattern': 'x'}, {'unit': 'nginx.service'}, {'unit': 'eventlog.Foo.1'}, 'junk', None]
        glob = [{'unit': 'eventlog.Security.1102'}, {'unit': 'eventlog.System.7045'}, {'unit': 'eventlog.Security.4625'}, {'unit': '*'}]
        self.assertEqual(win_events.watch_for(own, glob), {'Security': [1102, 4625], 'System': [7045]})
        self.assertEqual(win_events.watch_for(None, 'x', {'a': 1}), {})
        self.assertEqual(win_events.watch_for([], []), {})
        many = [{'unit': 'eventlog.Application.%d' % i} for i in range(1, 40)]
        self.assertEqual(win_events.watch_for(many), {'Application': list(range(1, 13))})

    def test_the_server_and_the_agent_hold_the_same_limits(self):
        self.assertEqual(win_events.CHANNELS, win._WINEVT_CHANNELS)
        self.assertEqual((win_events.MAX_IDS_PER_CHANNEL, win_events.MAX_EVENT_ID), (win._WINEVT_MAX_IDS, win._WINEVT_MAX_ID))
        rules = [{'unit': 'eventlog.Security.%d' % i} for i in range(1, 50)]
        self.assertEqual(win._winevt_watch_from_rules(rules), win_events.watch_for(rules))
        for unit in ('eventlog.Security.4625', 'eventlog.System.7045', 'eventlog.Security.0', 'eventlog.Security.65536', 'eventlog.Foo.1', 'eventlog.Security.01'):
            self.assertEqual(win._winevt_watch_from_rules([{'unit': unit}]), win_events.watch_for([{'unit': unit}]), unit)


class _Server(unittest.TestCase):
    STORES = ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE', 'DEVICES_FILE', 'ALERTS_FILE', 'FLEET_EVENTS_FILE', 'LOG_WATCH_FILE', 'LOG_RULES_GLOBAL_FILE',
              'AUDIT_LOG_FILE', 'LOG_ACKS_FILE')
    FNS = ('respond', 'method', 'get_json_obj', 'get_json_body', 'audit_log', 'get_token_from_request', 'verify_token', 'path_info')

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-winevt-srv-'))
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self._saved = {n: getattr(api, n) for n in self.STORES if hasattr(api, n)}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)
        self._fns = {n: getattr(api, n) for n in self.FNS}
        self.cap, self.body, self.m, self.who = {}, {}, 'POST', 'platform'

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: self.m
        api.get_json_obj = lambda: dict(self.body)
        api.get_json_body = lambda: dict(self.body)
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: ((self.who, (api._load_ro(api.USERS_FILE) or {}).get(self.who, {}).get('role')) if self.who else (None, None))
        now = int(time.time())
        mk = lambda name, os_, tenant='default', tags=(): {'name': name, 'hostname': name, 'os': os_, 'token': 'tok-' + name, 'last_seen': now, 'enrolled': now,
                                                           'tags': list(tags), 'group': '', 'sysinfo': {}, 'agentless': False, 'tenant': tenant}
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True}, 'tenantB': {'name': 'B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'platform': {'role': 'admin', 'tenant_id': 'default'}, 'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
                                  'viewer1': {'role': 'viewer', 'tenant_id': 'default'}})
        api.save(api.DEVICES_FILE, {'win1': mk('win1', 'Windows 11 Pro'), 'win2': mk('win2', 'Windows Server 2022'), 'lin1': mk('lin1', 'Debian GNU/Linux 12'),
                                    'mac1': mk('mac1', 'macOS 14.5'), 'winB': mk('winB', 'Windows 11 Pro', tenant='tenantB')})
        api.save(api.CONFIG_FILE, {})
        api.save(api.LOG_RULES_GLOBAL_FILE, {'rules': []})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *args, body=None, m='POST', who='platform'):
        self.who, self.body, self.m = who, dict(body or {}), m
        self.cap.clear()
        api._LOAD_CACHE.clear()
        try:
            fn(*args)
        except (api.HTTPError, SystemExit):
            pass
        api._LOAD_CACHE.clear()
        data = self.cap.get('data')
        return self.cap.get('status'), ({} if data is None else data)

    def beat(self, dev_id):
        return self.call(api.handle_heartbeat, body={'device_id': dev_id, 'token': 'tok-' + dev_id, 'sysinfo': {}})

    def submit(self, dev_id, units):
        return self.call(api.handle_log_submit, body={'device_id': dev_id, 'token': 'tok-' + dev_id, 'units': units})

    def alerts(self, **match):
        rows = (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
        return [a for a in rows if a.get('event') == 'log_alert' and all((a.get('payload') or {}).get(k) == v for k, v in match.items())]

    def add_global(self, **rule):
        st, d = self.call(api.handle_log_rules_global_add, body=rule)
        self.assertEqual(st, 200, d)
        return d['rule']


class TestWhatTheHeartbeatAsksFor(_Server):
    def own_rule(self, dev_id, unit):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[dev_id].setdefault('log_watch', []).append({'unit': unit, 'pattern': '^x', 'threshold': 1, 'severity': 'WARN'})

    def units(self, resp):
        return [r.get('unit') for r in resp.get('log_watch') or [] if isinstance(r, dict)]

    def test_a_windows_host_is_told_the_event_units_of_its_own_rules_and_of_the_fleets(self):
        self.own_rule('win1', 'eventlog.Security.4625')
        self.own_rule('win1', 'nginx.service')
        self.add_global(unit='eventlog.System.7045', pattern='^x', threshold=1)
        st, resp = self.beat('win1')
        self.assertEqual(st, 200, resp)
        self.assertEqual(self.units(resp), ['eventlog.Security.4625', 'nginx.service', 'eventlog.System.7045'])
        self.assertNotIn('eventlog_watch', resp, 'no new key travels in the answer')
        self.assertEqual(win._winevt_watch_from_rules(resp['log_watch']), {'Security': [4625], 'System': [7045]})
        st, resp = self.beat('win2')
        self.assertEqual(self.units(resp), ['eventlog.System.7045'], 'a rule of win1 is not given to win2, the fleet-wide one is')

    def test_what_is_added_for_a_fleet_wide_rule_is_its_unit_and_nothing_of_the_rule(self):
        self.add_global(unit='eventlog.Security.4625', pattern='^secret-looking-pattern', threshold=7, severity='CRIT', display_template='{device}: {sample0}')
        st, resp = self.beat('win1')
        self.assertEqual(resp['log_watch'], [{'unit': 'eventlog.Security.4625'}])

    def test_a_unit_the_host_already_names_is_not_added_twice(self):
        self.own_rule('win1', 'eventlog.Security.4625')
        self.add_global(unit='eventlog.Security.4625', pattern='^x', threshold=1)
        self.add_global(unit='eventlog.Security.4625', pattern='^y', threshold=1)
        st, resp = self.beat('win1')
        self.assertEqual(self.units(resp), ['eventlog.Security.4625'])
        st, resp = self.beat('win2')
        self.assertEqual(self.units(resp), ['eventlog.Security.4625'], 'two fleet-wide rules on one unit are one unit to read')

    def test_a_windows_host_with_no_event_rule_is_told_none_so_removing_the_last_one_reaches_it(self):
        self.add_global(unit='eventlog.Security.4625', pattern='^x', threshold=1)
        st, resp = self.beat('win1')
        self.assertEqual(self.units(resp), ['eventlog.Security.4625'])
        rule_id = (api.load(api.LOG_RULES_GLOBAL_FILE) or {})['rules'][0]['id']
        st, d = self.call(api.handle_log_rules_global_delete, rule_id, m='DELETE')
        self.assertEqual(st, 200, d)
        st, resp = self.beat('win1')
        self.assertEqual(resp['log_watch'], [])
        self.assertEqual(win._winevt_watch_from_rules(resp['log_watch']), {})

    def test_a_linux_or_macos_host_is_given_none_of_it(self):
        self.add_global(unit='eventlog.System.7045', pattern='^x', threshold=1)
        for dev in ('lin1', 'mac1'):
            st, resp = self.beat(dev)
            self.assertEqual(st, 200, resp)
            self.assertEqual(resp['log_watch'], [], dev)

    def test_a_star_rule_and_a_service_rule_add_nothing(self):
        self.add_global(unit='*', pattern='fail', threshold=1)
        self.add_global(unit='sshd.service', pattern='fail', threshold=1)
        st, resp = self.beat('win1')
        self.assertEqual(resp['log_watch'], [])

    def test_the_fleet_wide_event_units_are_capped_for_each_channel(self):
        for i in range(1, 25):
            self.add_global(unit='eventlog.Application.%d' % i, pattern='^x', threshold=1)
        st, resp = self.beat('win1')
        self.assertEqual(len(self.units(resp)), win_events.MAX_IDS_PER_CHANNEL)

    def test_the_real_agent_takes_the_list_the_way_its_heartbeat_loop_does(self):
        self.add_global(unit='eventlog.Security.4625', pattern='^x', threshold=1)
        st, resp = self.beat('win1')
        saved = (win._eventlog_watch, win._winevt_cursor)
        self.addCleanup(lambda: (setattr(win, '_eventlog_watch', saved[0]), setattr(win, '_winevt_cursor', saved[1])))
        win._eventlog_watch, win._winevt_cursor = {}, None
        with mock.patch.object(win, '_post_json', lambda *a, **k: dict(resp, ok=True)), mock.patch.object(win, '_winevt_run', lambda a: None):
            win.heartbeat_once({'server_url': 'http://x', 'device_id': 'win1', 'token': 'tok-win1'}, 2)
        self.assertEqual(win._eventlog_watch, {'Security': [4625]})
        # an answer with no list at all leaves what the agent was reading alone; an empty list stops the reading
        with mock.patch.object(win, '_post_json', lambda *a, **k: {'ok': True}), mock.patch.object(win, '_winevt_run', lambda a: None):
            win.heartbeat_once({'server_url': 'http://x', 'device_id': 'win1', 'token': 'tok-win1'}, 3)
        self.assertEqual(win._eventlog_watch, {'Security': [4625]})
        with mock.patch.object(win, '_post_json', lambda *a, **k: {'ok': True, 'log_watch': []}), mock.patch.object(win, '_winevt_run', lambda a: None):
            win.heartbeat_once({'server_url': 'http://x', 'device_id': 'win1', 'token': 'tok-win1'}, 4)
        self.assertEqual(win._eventlog_watch, {})
        # a file rule in the same list is still tailed, and does not ask for an event
        rules = [{'unit': 'file:C:\\logs\\app.log', 'path': 'C:\\logs\\app.log', 'pattern': 'x'}, {'unit': 'eventlog.System.7045'}]
        with mock.patch.object(win, '_post_json', lambda *a, **k: {'ok': True, 'log_watch': rules}), mock.patch.object(win, '_winevt_run', lambda a: None):
            win.heartbeat_once({'server_url': 'http://x', 'device_id': 'win1', 'token': 'tok-win1'}, 5)
        self.assertEqual(win._eventlog_watch, {'System': [7045]})
        self.assertEqual(win._log_watch_paths, ['C:\\logs\\app.log'])


class TestRulesOnEventUnits(_Server):
    BAD = 'eventlog.Foo.1'

    def test_a_fleet_rule_on_a_unit_no_agent_could_feed_is_refused_with_the_sentence(self):
        for unit in (self.BAD, 'eventlog.Security', 'eventlog.Security.0', 'eventlog.security.4625', 'eventlog.Security.4625.2'):
            st, d = self.call(api.handle_log_rules_global_add, body={'unit': unit, 'pattern': 'x', 'threshold': 1})
            self.assertEqual((st, d['error']), (400, win_events.BAD_UNIT), unit)
        self.assertEqual((api.load(api.LOG_RULES_GLOBAL_FILE) or {}).get('rules'), [])

    def test_a_valid_event_unit_is_accepted_as_a_fleet_rule_and_a_host_rule(self):
        st, d = self.call(api.handle_log_rules_global_add, body={'unit': 'eventlog.Security.4625', 'pattern': '^\\[4625\\] failed logon', 'threshold': 10, 'severity': 'WARN'})
        self.assertEqual(st, 200, d)
        st, d = self.call(api.handle_services_config, 'win1', body={'services_watched': [], 'log_watch': [
            {'unit': 'eventlog.System.7045', 'pattern': '^\\[7045\\]', 'threshold': 1, 'severity': 'WARN'}]})
        self.assertEqual(st, 200, d)
        self.assertEqual([r['unit'] for r in d['log_watch']], ['eventlog.System.7045'])

    def test_a_host_rule_on_a_bad_event_unit_is_a_400_and_not_a_rule_that_looks_saved(self):
        st, d = self.call(api.handle_services_config, 'win1', body={'services_watched': [], 'log_watch': [
            {'unit': self.BAD, 'pattern': 'x', 'threshold': 1, 'severity': 'WARN'}]})
        self.assertEqual((st, d['error']), (400, win_events.BAD_UNIT))
        self.assertEqual(api.load(api.DEVICES_FILE)['win1'].get('log_watch', []), [])

    def test_a_tenant_administrator_cannot_set_a_fleet_rule_or_a_rule_on_another_tenants_host(self):
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api._LOAD_CACHE.clear()
        self.who = 'badmin'
        # a fleet-wide rule reaches every tenant's hosts, so its writes are the platform operator's (the dispatcher's table)
        for method in ('POST', 'PUT', 'DELETE'):
            self.cap.clear()
            with self.assertRaises(api.HTTPError):
                api._enforce_platform_routes('/api/logs/rules/global', method)
            self.assertEqual(self.cap['status'], 403, method)
        self.who = 'platform'
        self.assertIsNone(api._enforce_platform_routes('/api/logs/rules/global', 'POST'))
        # a host's own rules are under /api/devices/<id>/, which the pre-dispatch gate checks against the caller's tenant
        api.path_info = lambda: '/api/devices/win1/services/config'
        self.who = 'badmin'
        self.cap.clear()
        with self.assertRaises(api.HTTPError):
            api._enforce_device_scope()
        self.assertEqual((self.cap['status'], self.cap['data']['error']), (403, 'Host belongs to another tenant'))
        api.path_info = lambda: '/api/devices/winB/services/config'
        self.assertIsNone(api._enforce_device_scope())

    def test_a_read_only_user_cannot_save_a_rule_on_a_host(self):
        st, d = self.call(api.handle_services_config, 'win1', body={'services_watched': [], 'log_watch': [
            {'unit': 'eventlog.System.7045', 'pattern': 'x', 'threshold': 1, 'severity': 'WARN'}]}, who='viewer1')
        self.assertEqual(st, 403, d)
        self.assertEqual(api.load(api.DEVICES_FILE)['win1'].get('log_watch', []), [])

    def test_the_log_buffer_takes_an_event_unit_of_the_right_shape_and_no_other(self):
        self.assertEqual(api._sanitize_log_unit('eventlog.Security.4625'), 'eventlog.Security.4625')
        for bad in ('eventlog.Foo.1', 'eventlog.Security.99999999', 'eventlog.', 'eventlog.Security.4625.x'):
            self.assertIsNone(api._sanitize_log_unit(bad), bad)
        self.assertEqual(api._sanitize_log_unit('nginx.service'), 'nginx.service')
        self.assertEqual(api._sanitize_log_unit('file:/var/log/x.log'), 'file:/var/log/x.log')

    def test_an_agent_cannot_make_up_an_event_unit(self):
        st, d = self.submit('win1', {'eventlog.Foo.1': ['a line'], 'eventlog.Security.4625': ['[4625] failed logon rid=1 user="x"']})
        self.assertEqual(st, 200, d)
        units = api.load(api.LOG_WATCH_FILE)['win1']['units']
        self.assertEqual(sorted(units), ['eventlog.Security.4625'])


class TestTheRuleEngineOnEventUnits(_Server):
    def lines(self, builder, n, start=100, **kw):
        return [win._winevt_line(win._winevt_parse(builder(rid=start + i, **kw))[0]) for i in range(n)]

    def test_a_burst_rule_fires_at_its_threshold_in_one_delivery_and_not_below(self):
        self.add_global(unit='eventlog.Security.4625', pattern='^\\[4625\\] failed logon', threshold=5, severity='WARN')
        self.submit('win1', {'eventlog.Security.4625': self.lines(S.failed_logon, 4)})
        self.assertEqual(self.alerts(device_id='win1'), [])
        self.submit('win1', {'eventlog.Security.4625': self.lines(S.failed_logon, 5, start=200)})
        (alert,) = self.alerts(device_id='win1', unit='eventlog.Security.4625')
        self.assertEqual(alert['payload']['count'], 5)
        self.assertTrue(alert['payload']['sample'][0].startswith('[4625] failed logon rid='))

    def test_a_line_sent_again_does_not_count_again(self):
        self.add_global(unit='eventlog.Security.4625', pattern='^\\[4625\\] failed logon', threshold=3, severity='WARN')
        three = self.lines(S.failed_logon, 3)
        self.submit('win1', {'eventlog.Security.4625': three})
        self.assertEqual(len(self.alerts(device_id='win1')), 1)
        self.submit('win1', {'eventlog.Security.4625': three})
        self.submit('win1', {'eventlog.Security.4625': three[:2]})
        self.assertEqual(len(self.alerts(device_id='win1')), 1)
        n_lines = len(api.load(api.LOG_WATCH_FILE)['win1']['units']['eventlog.Security.4625'])
        self.assertEqual(n_lines, 3, 'a re-sent line is stored once')

    def test_two_events_of_one_second_with_the_same_text_are_two_lines_because_their_record_ids_differ(self):
        a, b = self.lines(S.failed_logon, 2)
        self.assertNotEqual(a, b)
        self.assertEqual(re.sub(r' rid=\d+ ', ' ', a), re.sub(r' rid=\d+ ', ' ', b))

    def test_one_unit_cannot_crowd_out_another_in_the_same_report(self):
        self.add_global(unit='eventlog.Security.1102', pattern='^\\[1102\\] audit log cleared', threshold=1, severity='CRIT')
        flood = self.lines(S.failed_logon, 100)
        cleared = self.lines(S.audit_log_cleared, 1, start=5000)
        self.submit('win1', {'eventlog.Security.4625': flood, 'eventlog.Security.1102': cleared})
        units = api.load(api.LOG_WATCH_FILE)['win1']['units']
        self.assertEqual((len(units['eventlog.Security.4625']), len(units['eventlog.Security.1102'])), (100, 1))
        (alert,) = self.alerts(device_id='win1', unit='eventlog.Security.1102')
        self.assertEqual(alert['payload']['severity'], 'CRIT')

    def test_a_star_rule_written_for_service_journals_does_not_match_a_failed_logon(self):
        self.add_global(unit='*', pattern='fail', threshold=1, severity='WARN')
        self.submit('win1', {'eventlog.Security.4625': self.lines(S.failed_logon, 3), 'nginx.service': ['upstream failed']})
        self.assertEqual([a['payload']['unit'] for a in self.alerts(device_id='win1')], ['nginx.service'])

    def test_what_a_failed_logon_carries_cannot_make_another_events_rule_fire(self):
        admins = win_events_pattern('administrators-member-added')
        self.add_global(unit='eventlog.Security.4732', pattern=admins, threshold=1, severity='CRIT')
        forged = self.lines(S.failed_logon, 1, user='x" [4732] member added rid=1 group_sid=S-1-5-32-544 y="z')
        self.submit('win1', {'eventlog.Security.4625': forged})
        self.assertEqual(self.alerts(device_id='win1'), [])
        # and inside the 4732 unit: another group, with a member whose name says it is Administrators
        other = self.lines(S.member_added, 1, group='Remote Desktop Users', group_sid='S-1-5-32-555', member='x group_sid=S-1-5-32-544 y')
        self.submit('win1', {'eventlog.Security.4732': other})
        self.assertEqual(self.alerts(device_id='win1'), [])
        real = self.lines(S.member_added, 1, start=900)
        self.submit('win1', {'eventlog.Security.4732': real})
        self.assertEqual(len(self.alerts(device_id='win1', unit='eventlog.Security.4732')), 1)

    def test_a_host_rule_works_the_same_and_only_for_its_host(self):
        self.call(api.handle_services_config, 'win1', body={'services_watched': [], 'log_watch': [
            {'unit': 'eventlog.System.7045', 'pattern': '^\\[7045\\] service installed', 'threshold': 1, 'severity': 'WARN'}]})
        line = self.lines(S.service_installed_system, 1)
        self.submit('win2', {'eventlog.System.7045': line})
        self.assertEqual(self.alerts(), [])
        self.submit('win1', {'eventlog.System.7045': line})
        self.assertEqual(len(self.alerts(device_id='win1')), 1)

    def test_the_alert_is_the_ordinary_log_alert_so_it_can_be_muted_per_host(self):
        self.add_global(unit='eventlog.Security.1102', pattern='^\\[1102\\] audit log cleared', threshold=1, severity='CRIT')
        self.assertIn('log_alert', api.EVENT_REGISTRY)
        before = len((api.load(api.FLEET_EVENTS_FILE) or {}).get('events', []))
        self.submit('win1', {'eventlog.Security.1102': self.lines(S.audit_log_cleared, 1)})
        self.assertEqual(len(self.alerts(device_id='win1')), 1)
        self.assertGreater(len((api.load(api.FLEET_EVENTS_FILE) or {}).get('events', [])), before)


class TestTheWholeChain(_Server):
    """A rule saved on a host, the heartbeat that asks for it, the real agent that reads a (fake) event log, the real log handler and the alert in the inbox."""

    def test_from_the_rule_to_the_alert(self):
        saved = (win._eventlog_watch, win._winevt_cursor)
        self.addCleanup(lambda: (setattr(win, '_eventlog_watch', saved[0]), setattr(win, '_winevt_cursor', saved[1])))
        win._eventlog_watch, win._winevt_cursor = {}, None
        agent_dir = tempfile.mkdtemp(prefix='rp-winevt-chain-')
        self.addCleanup(lambda: shutil.rmtree(agent_dir, ignore_errors=True))
        log = FakeEventLog()
        templates = {t['id']: t for t in _templates()}
        for tid in ('failed-logons', 'audit-log-cleared'):
            t = templates[tid]
            self.add_global(unit=t['unit'], pattern=t['pattern'], threshold=t['threshold'], severity=t['severity'], display_template=t['message'])
        creds = {'server_url': 'http://x', 'device_id': 'win1', 'token': 'tok-win1'}

        def post(url, body, *a, **k):
            if url.endswith('/api/heartbeat'):
                st, resp = self.beat('win1')
                return dict(resp, ok=True)
            st, resp = self.submit('win1', body['units'])
            return resp

        with mock.patch.object(win, '_data_dir', lambda: agent_dir), mock.patch.object(win, '_winevt_run', log.run), mock.patch.object(win, '_post_json', post):
            win.heartbeat_once(creds, 2)                                        # the answer says which events to read; the first sight starts at the newest
            self.assertEqual(win._eventlog_watch, {'Security': [1102, 4625]})
            self.assertEqual(self.alerts(), [])
            for i in range(9):
                log.add('Security', S.failed_logon, user='bob%d' % i)
            win.heartbeat_once(creds, 3)
            self.assertEqual(self.alerts(device_id='win1'), [], '9 failed logons are under the threshold of 10')
            for i in range(10):
                log.add('Security', S.failed_logon, user='eve%d' % i)
            log.add('Security', S.audit_log_cleared)
            win.heartbeat_once(creds, 4)
        by_unit = {a['payload']['unit']: a for a in self.alerts(device_id='win1')}
        self.assertEqual(sorted(by_unit), ['eventlog.Security.1102', 'eventlog.Security.4625'])
        self.assertEqual(by_unit['eventlog.Security.4625']['payload']['count'], 10)
        self.assertEqual(by_unit['eventlog.Security.1102']['payload']['severity'], 'CRIT')
        self.assertIn('audit log cleared', by_unit['eventlog.Security.1102']['payload']['sample'][0])
        stored = api.load(api.LOG_WATCH_FILE)['win1']['units']['eventlog.Security.4625']
        self.assertEqual(len(stored), 19)
        self.assertEqual(len({e['line'] for e in stored}), 19)


class TestTheSamplesDoNotDependOnTheDay(unittest.TestCase):
    """The samples carried a stamp written into the file. The server drops a log line older than its ring keeps (six hours), so the chain test was green for six hours on the day it
    was written and red from then on. A sample is stamped with the time it is built, and the chain is run here with the clock moved to where the old stamp would have failed it."""

    def test_a_sample_is_stamped_with_the_time_it_is_built_and_a_moved_clock_moves_it(self):
        ev = win._winevt_parse(S.failed_logon())[0]
        self.assertLess(abs(ev['ts'] / 1000.0 - time.time()), 60)
        real = time.time
        with mock.patch('time.time', lambda: real() + 30 * 86400):
            moved = win._winevt_parse(S.failed_logon())[0]
        self.assertLess(abs(moved['ts'] / 1000.0 - (real() + 30 * 86400)), 60)
        self.assertEqual(win._winevt_parse(S.failed_logon(ts=S.FIXED_TS))[0]['ts'], S.FIXED_TS_MS, 'a test about the stamp itself can still fix it')

    def test_the_whole_chain_passes_at_the_edge_of_the_ring_and_a_month_on(self):
        real = time.time
        for label, offset in (('now', 0), ('5 h 59 min on', 5 * 3600 + 59 * 60), ('6 h 01 min on', 6 * 3600 + 60), ('a month on', 30 * 86400)):
            with self.subTest(label):
                with mock.patch('time.time', lambda: real() + offset):
                    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(unittest.TestSuite([TestTheWholeChain('test_from_the_rule_to_the_alert')]))
                self.assertTrue(result.wasSuccessful(), [t[1][-300:] for t in result.failures + result.errors])


# ── the dialog's templates ───────────────────────────────────────────────────
@unittest.skipUnless(_NODE, 'node is not installed')
class TestTheTemplates(_Server):
    BRIEF = {4625: 'failed logons', 4740: 'account lockout', 7045: 'service installed (System)', 4697: 'service installed (Security)', 4698: 'scheduled task created',
             4720: 'local user created', 4732: 'member added to Administrators', 1102: 'audit log cleared'}

    def test_there_is_one_template_for_each_event_of_the_brief(self):
        ids = sorted(win_events.parse_unit(t['unit'])[1] for t in _templates())
        self.assertEqual(ids, sorted(self.BRIEF))
        self.assertEqual(len({t['id'] for t in _templates()}), 8)

    def test_each_is_a_rule_the_server_accepts_as_it_stands(self):
        for t in _templates():
            with self.subTest(t['id']):
                rule, err = api._validate_global_rule({'unit': t['unit'], 'pattern': t['pattern'], 'threshold': t['threshold'], 'severity': t['severity'],
                                                       'display_template': t['message']})
                self.assertIsNone(err)
                self.assertEqual((rule['unit'], rule['pattern'], rule['threshold']), (t['unit'], t['pattern'], t['threshold']))
                self.assertFalse(api._regex_redos_risky(t['pattern']))
                self.assertLessEqual(len(t['pattern']), 128)
                self.assertEqual(t['pattern'], t['pattern'].strip(), 'the dialog trims the pattern, so a trailing space would not survive')
                self.assertTrue(1 <= t['threshold'] <= 100)
                self.assertIn(t['severity'], ('WARN', 'CRIT'))
                self.assertTrue(t['pattern'].startswith('^\\['), 'anchored at the start of the line')
                self.assertIn('event %d' % win_events.parse_unit(t['unit'])[1], t['note'])

    def test_each_template_matches_the_line_of_its_own_event_and_no_other_of_the_eight(self):
        lines = {}
        for build, eid, channel in S.EIGHT:
            lines.setdefault(eid, []).append(win._winevt_line(win._winevt_parse(build())[0]))
        for t in _templates():
            unit_id = win_events.parse_unit(t['unit'])[1]
            rx = re.compile(t['pattern'])
            for eid, ls in lines.items():
                for ln in ls:
                    with self.subTest(template=t['id'], line_of=eid):
                        self.assertEqual(bool(rx.search(ln)), eid == unit_id, ln)

    def test_the_failed_logon_note_says_the_number_the_template_sets(self):
        t = next(t for t in _templates() if t['id'] == 'failed-logons')
        self.assertEqual(t['threshold'], 10)
        self.assertIn('%d or more' % t['threshold'], t['note'])
        self.assertIn('%d or more' % t['threshold'], t['label'])

    def test_the_templates_ask_for_exactly_the_events_they_name(self):
        rules = [{'unit': t['unit']} for t in _templates()]
        self.assertEqual(win_events.watch_for(rules), {'Security': [1102, 4625, 4697, 4698, 4720, 4732, 4740], 'System': [7045]})

    def test_the_messages_use_only_placeholders_the_server_allows(self):
        for t in _templates():
            clean, err = api._validate_log_template(t['message'])
            self.assertIsNone(err, t['id'])
            self.assertTrue(clean)

    def test_the_dialog_has_the_picker_and_fills_the_form(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-logs.js').read_text(encoding='utf-8')
        for needle in ('id="log-rule-tpl-row"', 'id="log-rule-tpl"', 'data-change="logRulePickTemplate"', 'id="log-rule-tpl-note"'):
            self.assertIn(needle, html)
        for needle in ('function logRulePickTemplate', 'function _logRuleTemplatesInit', '_logRuleTemplatesInit(true)', '_logRuleTemplatesInit(false)'):
            self.assertIn(needle, js)


# ── what a person reads ──────────────────────────────────────────────────────
class TestSixLanguages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = dict_rows()

    def strings(self):
        out = ['Ready-made Windows rule', 'None, I will write my own', win_events.BAD_UNIT]
        if _NODE:
            for t in _templates():
                out += [t['label'], t['note']]
        return out

    @unittest.skipUnless(_NODE, 'node is not installed')
    def test_every_string_the_picker_shows_has_all_six_languages(self):
        self.assertEqual(len(self.strings()), 3 + 16)
        missing = {s: sorted(set(LANGS) - self.rows.get(s, set())) for s in self.strings() if not set(LANGS) <= self.rows.get(s, set())}
        self.assertEqual(missing, {})

    @unittest.skipUnless(_NODE, 'node is not installed')
    def test_the_markup_holds_the_sentences_the_dictionary_is_keyed_on(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        self.assertIn('>Ready-made Windows rule<', html)
        self.assertIn('>None, I will write my own<', html)

    @unittest.skipUnless(_NODE, 'node is not installed')
    def test_no_word_the_house_style_drops_is_in_what_was_added(self):
        banned = ('genu' + 'ine', 'verba' + 'tim', 'delib' + 'erate')      # written in two parts so that this file does not hold the words it checks for
        for s in self.strings():
            for w in banned:
                self.assertNotIn(w, s.lower())
        agent = (_ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        region = agent[agent.index('# ── Windows event log rules'):agent.index('# v6.3.1: hail-mary log sweep')]
        docs = (_ROOT / 'docs' / 'log-watch.md').read_text(encoding='utf-8')
        docs_region = docs[docs.index('## Windows event rules'):docs.index('## Clearing a noisy line')]
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-logs.js').read_text(encoding='utf-8')
        js_region = js[js.index('// Ready-made rules for a Windows host'):js.index('async function openAddRuleModal')]
        for text in (region, docs_region, js_region, (_CGI / 'win_events.py').read_text(encoding='utf-8')):
            for w in banned:
                self.assertNotIn(w, text.lower())


class TestNoOtherAgentHasAnythingToIgnore(unittest.TestCase):
    """The units reach a Windows agent in the `log_watch` list it already reads, so the other two agents are not sent a key they would have to declare."""

    def test_the_answer_has_no_event_log_key_and_the_other_agents_name_none(self):
        client = _ROOT / 'client'
        api_src = (_CGI / 'api.py').read_text(encoding='utf-8')
        self.assertNotIn("common_resp['eventlog_watch']", api_src)
        for name in ('remotepower-agent.py', 'remotepower-agent-mac.py', 'remotepower-agent-win.py'):
            self.assertNotIn("'eventlog_watch'", (client / name).read_text(encoding='utf-8'), name)
        self.assertEqual((client / 'remotepower-agent').read_text(encoding='utf-8'), (client / 'remotepower-agent.py').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
