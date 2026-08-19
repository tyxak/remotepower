#!/usr/bin/env python3
"""`files:upload` corrupted the file it uploaded, or failed outright.

The server queues five colon-separated parts —
`files:upload:<b64path>:<b64bytes>:<overwrite>` — and both agents that
implement the channel parsed it with `cmd.split(':', 3)`. That yields four
elements at most, so:

  - `bits[4]` could never exist, and `len(bits) > 4` is a constant False. The
    overwrite flag was always read as off, whatever the operator ticked.
  - the flag stayed glued to the payload. `bits[3]` arrived as `'MTIzNDU=:1'`.
    Base64 decoding drops the colon but `0` and `1` are alphabet characters, so
    it either raised (most lengths) or decoded ONE BYTE LONG and wrote a
    corrupted file with rc 0 and a success toast.

This is the more dangerous half: a failed upload is visible, a file that is
wrong by one byte is not.
"""
import base64
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))
import srcpin  # noqa: E402

# The two agents that implement the channel — `files:` is declared for
# ('linux', 'windows') in api.py's verb/OS table; the macOS agent has no file op.
_IMPLS = (('client/remotepower-agent.py', '_handle_file_op'),
          ('client/remotepower-agent-win.py', '_handle_file_op_win'))


def _round_trip(maxsplit, payload, overwrite='1'):
    """What the agent's parser would recover for a given maxsplit."""
    cmd = ('files:upload:' + base64.urlsafe_b64encode(b'/tmp/x').decode()
           + ':' + base64.urlsafe_b64encode(payload).decode() + ':' + overwrite)
    bits = cmd.split(':', maxsplit)
    try:
        got = base64.urlsafe_b64decode(bits[3])
    except Exception as exc:
        got = exc
    return bits, got


class TestTheOldSplitBrokeIt(unittest.TestCase):
    """The bug, stated as a fact about the string — no agent import needed."""

    def test_three_either_raises_or_corrupts(self):
        raised = corrupt = 0
        for payload in (b'a', b'ab', b'abc', b'hello world!!', b'12345'):
            _bits, got = _round_trip(3, payload)
            if isinstance(got, Exception):
                raised += 1
            elif got != payload:
                corrupt += 1
        self.assertTrue(raised, 'expected most lengths to fail to decode')
        self.assertTrue(corrupt, 'expected at least one length to decode LONG — '
                                 'that is the silent one')

    def test_three_can_never_see_the_overwrite_flag(self):
        bits, _ = _round_trip(3, b'abc')
        self.assertEqual(len(bits), 4)
        self.assertFalse(len(bits) > 4, 'the flag test was a constant False')

    def test_four_round_trips_every_length(self):
        for payload in (b'', b'a', b'ab', b'abc', b'hello world!!', b'12345',
                        bytes(range(256))):
            bits, got = _round_trip(4, payload)
            self.assertEqual(got, payload, repr(payload[:12]))
            self.assertEqual(bits[4], '1')

    def test_four_leaves_the_four_part_ops_alone(self):
        """write/list/read/mkdir/delete have four parts or fewer, so a larger
        maxsplit cannot change what they see."""
        for op, parts in (('write', 4), ('list', 3), ('read', 3),
                          ('mkdir', 3), ('delete', 3)):
            cmd = ':'.join(['files', op, 'cGF0aA=='] + ['Y29udGVudA=='] * (parts - 3))
            self.assertEqual(cmd.split(':', 3), cmd.split(':', 4), op)


class TestBothAgentsParseWithFour(unittest.TestCase):

    def test_the_maxsplit_is_four(self):
        for rel, fn in _IMPLS:
            body = srcpin.py_function((_ROOT / rel).read_text(), fn)
            code = '\n'.join(ln for ln in body.splitlines()
                             if not ln.lstrip().startswith('#'))
            m = re.search(r"cmd\.split\(':',\s*(\d+)\)", code)
            self.assertTrue(m, f'{rel}: {fn} no longer splits the command')
            self.assertEqual(int(m.group(1)), 4, rel)

    def test_the_overwrite_flag_is_read_from_the_fifth_part(self):
        for rel, fn in _IMPLS:
            body = srcpin.py_function((_ROOT / rel).read_text(), fn)
            self.assertIn('len(bits) > 4', body,
                          f'{rel}: overwrite is not read from bits[4]')


class TestTheServerStillSendsFiveParts(unittest.TestCase):
    """If the server ever stopped appending the flag, maxsplit=4 would be
    harmless but the agents' bits[4] read would go dead — so pin the producer
    to the shape the parser expects."""

    def test_upload_appends_the_flag(self):
        body = srcpin.py_function(
            (_ROOT / 'server/cgi-bin/api.py').read_text(), 'handle_device_files')
        m = re.search(r"elif op == 'upload':(.{0,900})", body, re.S)
        self.assertTrue(m, 'the upload branch moved')
        self.assertIn("parts.append('1' if", m.group(1))


if __name__ == '__main__':
    unittest.main()
