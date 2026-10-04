"""An agent that is opted in to the SSH gateway but lacks `websockets` says so once.

pmg01 ran agent 7.1.0, was opted in, and never opened a tunnel: the heartbeat
branch was `if sshgw_enabled and _PUSH_AVAILABLE`, so without the module nothing
happened and nothing was logged. This is a source-shape test (the loop is not
drivable here); the undefined-name gate covers the new local.
"""
import re
import unittest
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py'


class TestMissingWebsocketsIsReported(unittest.TestCase):
    def setUp(self):
        self.src = _AGENT.read_text()

    def test_the_branch_sits_between_the_tunnel_start_and_the_close(self):
        start = self.src.index("if resp.get('sshgw_enabled') and _PUSH_AVAILABLE:")
        warn = self.src.index("elif resp.get('sshgw_enabled'):", start)
        close = self.src.index("elif _sshgw_stop_event is not None:", start)
        self.assertLess(start, warn)
        self.assertLess(warn, close, 'the opted-in-but-unable branch must come before the close branch')

    def test_it_warns_once_and_names_the_fix(self):
        block = self.src[self.src.index("elif resp.get('sshgw_enabled'):"):]
        block = block[:block.index("elif _sshgw_stop_event is not None:")]
        self.assertIn('if not _sshgw_warned_no_ws:', block)
        self.assertIn('_sshgw_warned_no_ws = True', block)
        self.assertIn('log.warning(', block)
        self.assertRegex(block, r'python3-websockets')

    def test_the_flag_is_initialised_next_to_the_stop_event(self):
        m = re.search(r"\n    _sshgw_stop_event = None\n    _sshgw_warned_no_ws = False\n", self.src)
        self.assertIsNotNone(m, 'the once-flag must start False in the same function as _sshgw_stop_event')


if __name__ == '__main__':
    unittest.main()
