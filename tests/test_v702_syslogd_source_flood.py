#!/usr/bin/env python3
"""remotepower-syslogd grew without limit under spoofed source addresses.

The daemon binds UDP on the LAN by design — appliances send syslog from across
the segment. A UDP source address is a claim, not a fact: anything on that
segment can forge one per packet, with no handshake and no cost.

Three dicts are keyed by source address. `pending` and `first_at` self-clear
each flush window, so they were bounded in time but not in width — one burst of
forged addresses inside a single window allocated an entry each.
`unknown_logged` was worse: it is only ever assigned, never popped, so it kept
one entry per distinct address for the life of the process. A sender walking a
/8 adds sixteen million entries and the daemon dies.

Both are capped now. The test drives the real `serve()` loop over a real socket
with forged sources rather than calling the helpers, because the growth happens
in the loop body and a unit test of `flush()` would not see it.
"""
import importlib.util
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / 'server' / 'syslog' / 'remotepower-syslogd.py'


def _load():
    spec = importlib.util.spec_from_loader(
        'rp_syslogd_flood',
        importlib.machinery.SourceFileLoader('rp_syslogd_flood', str(_SRC)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestTheCapsExist(unittest.TestCase):

    def setUp(self):
        self.m = _load()

    def test_both_ceilings_are_declared(self):
        self.assertGreater(self.m.MAX_TRACKED_SOURCES, 0)
        self.assertGreater(self.m.MAX_UNKNOWN_TRACKED, 0)

    def test_they_are_high_enough_for_a_real_fleet(self):
        """A cap that a legitimate deployment hits is an outage, not a fix.
        4096 distinct senders in one 2-second window is far past any real
        syslog fan-in."""
        self.assertGreaterEqual(self.m.MAX_TRACKED_SOURCES, 1024)
        self.assertGreaterEqual(self.m.MAX_UNKNOWN_TRACKED, 256)

    def test_the_unknown_table_is_actually_pruned(self):
        src = _SRC.read_text()
        self.assertIn('del unknown_logged[_ip]', src,
                      'entries are still only ever added')


class TestTheLoopIsBounded(unittest.TestCase):
    """Drives the real serve() loop. The dicts live in its frame, so they are
    observed by monkeypatching the flush target rather than by reaching in."""

    def setUp(self):
        self.m = _load()
        self.m.MAX_TRACKED_SOURCES = 8      # shrink so the test is quick
        self.m.MAX_UNKNOWN_TRACKED = 4
        self.m.FLUSH_S = 999                # never flush on time during the test
        self.posted = []
        self.m.post_lines = lambda tok, lines: self.posted.append((tok, len(lines)))
        self.buffered = set()

    def _run_with_sources(self, n_sources, known):
        """Send one datagram from each of n_sources forged addresses.

        The socket is real but the datagrams are injected by replacing recvfrom,
        which is the only way to present a forged source without root.
        """
        m = self.m
        sent = {'i': 0}
        addrs = [f'10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}'
                 for i in range(n_sources)]

        class _Sock:
            def setsockopt(self, *a): pass
            def bind(self, *a): pass
            def setblocking(self, *a): pass
            def fileno(self): return 0

        def _recvfrom(_n):
            i = sent['i']
            if i >= n_sources:
                raise OSError('drained')
            sent['i'] += 1
            return b'<14>test line\n', (addrs[i], 514)

        sk = _Sock()
        sk.recvfrom = _recvfrom
        m.socket = type('S', (), {
            'socket': staticmethod(lambda *a, **k: sk),
            'AF_INET': 0, 'SOCK_DGRAM': 0, 'SOL_SOCKET': 0, 'SO_REUSEADDR': 0})

        # select() says ready until the injector is drained, then not-ready so
        # the `once` path returns.
        m.select = type('X', (), {'select': staticmethod(
            lambda r, w, x, t: ((r if sent['i'] < n_sources else []), [], []))})

        # Only a source that made it into `pending` is ever flushed, and flush()
        # is the only caller of token_for — so this counts the distinct sources
        # the loop actually buffered. That is the number the cap bounds.
        seen = self.buffered

        class _Map:
            enrolled_ips = set(addrs) if known else set()
            def __init__(self, *a): pass
            def token_for(self, src):
                seen.add(src)
                return 'tok' if known else None
        m.SourceMap = _Map

        m.serve(bind='127.0.0.1:0', reader=object(), once=True)

    def test_a_forged_source_flood_does_not_grow_past_the_cap(self):
        """40 forged sources against a table capped at 8. The count is the
        assertion — an earlier version of this test checked that a string was
        present in the source, which passes whether or not the cap works."""
        self._run_with_sources(40, known=False)
        self.assertEqual([], self.posted, 'unknown sources were forwarded')
        self.assertLessEqual(
            len(self.buffered), self.m.MAX_TRACKED_SOURCES,
            f'{len(self.buffered)} distinct forged sources were buffered '
            f'against a cap of {self.m.MAX_TRACKED_SOURCES} — the table still '
            f'grows one entry per forged address')
        self.assertGreater(len(self.buffered), 0,
                           'nothing was buffered at all, so the cap above is '
                           'not what stopped it')

    def test_known_sources_below_the_cap_still_deliver(self):
        """Positive control. A daemon that dropped everything would satisfy the
        test above while breaking syslog ingest completely."""
        self._run_with_sources(5, known=True)
        self.assertEqual(5, len(self.posted),
                         'legitimate sources under the cap were dropped')

    def test_the_cap_drops_the_newcomer_not_the_established_source(self):
        """Evicting an established source loses the burst already buffered;
        a real appliance that loses one batch retries on its next line."""
        src = _SRC.read_text()
        i = src.index('MAX_TRACKED_SOURCES:')
        self.assertIn('continue', src[i:i + 200],
                      'the over-cap branch does something other than skip')


if __name__ == '__main__':
    unittest.main()
