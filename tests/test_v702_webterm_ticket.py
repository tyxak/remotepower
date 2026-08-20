#!/usr/bin/env python3
"""A single-use web-terminal ticket could be used twice.

The CGI's /api/webterm/auth issued tickets with a bare load / add / save, and
the daemon's TicketStore.consume() validated-and-deleted with a bare load /
delete / save — in a DIFFERENT PROCESS, against the same store.

So issuing a ticket while one was being consumed wrote back a snapshot taken
before the delete, and the consumed ticket was live again for the rest of its
60-second window. A one-time credential usable twice is not one-time, and
opening two terminals at once is ordinary operator behaviour.

Both sides take the storage backend's own LockedUpdate now — the same primitive
api._LockedUpdate dispatches to. A lock only one of two writers holds is not a
lock, which is why fixing the CGI alone would have proved nothing.

Also here: the daemon's own "install asyncssh" message still named 2.10 after
the installer's floor was raised to 2.14.2. That message is what an operator
installing by hand reads, and below 2.14.2 asyncssh has session-hijack and
downgrade flaws (CVE-2023-46445/46446, Terrapin) against exactly the SSH client
this daemon is.
"""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import time
import types
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_WT = _ROOT / 'server' / 'webterm' / 'remotepower-webterm.py'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-wt-'))

import srcpin                                                    # noqa: E402


def _load_daemon():
    """Import the daemon with asyncssh stubbed — it is not a CI dependency and
    the module exits at import without it."""
    if 'asyncssh' not in sys.modules:
        m = types.ModuleType('asyncssh')
        m.__version__ = '2.21.0'
        sys.modules['asyncssh'] = m
    spec = importlib.util.spec_from_loader(
        'rp_wt_daemon',
        importlib.machinery.SourceFileLoader('rp_wt_daemon', str(_WT)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTheMinimumAsyncsshVersion(unittest.TestCase):

    def setUp(self):
        if not _WT.exists():
            self.skipTest('excluded from dist tree')
        self.src = _WT.read_text()

    def test_the_printed_floor_is_not_the_vulnerable_one(self):
        self.assertNotIn("asyncssh>=2.10", self.src)
        self.assertIn("asyncssh>=2.14.2", self.src)

    def test_it_warns_but_does_not_refuse_to_start(self):
        """It DID refuse, and that took down a working web terminal on Debian
        12, which packages python3-asyncssh 2.11. The condition was true on a
        healthy, supported, fully-patched host — the guard tested "is the
        library old" and treated it as "is this host broken".

        Turning a vulnerability into an outage is not a security improvement,
        and this one needs an attacker already positioned between the gateway
        and a target host. An operator who cannot see the warning because the
        service will not start is worse off than one running 2.11 and reading
        it. CLAUDE.md's safety-guard-that-fires-on-a-healthy-host class,
        committed by the fix for a different one."""
        self.assertIn('MIN_ASYNCSSH', self.src)
        self.assertIn('(2, 14, 2)', self.src)
        i = self.src.index('ASYNCSSH_OUTDATED = ')
        j = self.src.index('VERSION = ', i)
        guard = self.src[i:j]
        self.assertIn('WARNING:', guard)
        # The only sys.exit in the guard must be behind the opt-in flag.
        self.assertIn('RP_WEBTERM_REQUIRE_ASYNCSSH', guard)
        before_flag = guard[:guard.index('RP_WEBTERM_REQUIRE_ASYNCSSH')]
        self.assertNotIn('sys.exit', before_flag,
                         'it exits before consulting the opt-in flag, so an '
                         'old-but-working host still cannot start')

    def test_the_strict_flag_is_opt_in_not_opt_out(self):
        """Default must be warn. An env var that has to be SET to keep working
        would break the same hosts on upgrade."""
        i = self.src.index('ASYNCSSH_OUTDATED = ')
        guard = self.src[i:self.src.index('VERSION = ', i)]
        self.assertIn("RP_WEBTERM_REQUIRE_ASYNCSSH') == '1'", guard)

    def test_the_message_says_why(self):
        # Bounded by the guard's own end, not a character count.
        i = self.src.index('MIN_ASYNCSSH')
        j = self.src.index("VERSION = ", i)
        self.assertIn('CVE-2023-46445', self.src[i:j])

    def test_it_agrees_with_the_installer(self):
        """Two places state this floor and they drifted once already."""
        sh = _ROOT / 'packaging' / 'install-webterm.sh'
        if sh.exists():
            self.assertIn('2.14.2', sh.read_text())


class TestBothWritersShareOneLock(unittest.TestCase):

    def setUp(self):
        if not _WT.exists():
            self.skipTest('excluded from dist tree')

    def test_the_cgi_holds_the_lock_across_read_and_write(self):
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  'handle_webterm_auth')
        self.assertIn('_LockedUpdate(WEBTERM_TICKETS_FILE)', body)
        code = '\n'.join(l for l in body.splitlines()
                         if not l.lstrip().startswith('#'))
        self.assertNotIn('save(WEBTERM_TICKETS_FILE', code)

    def test_the_daemon_uses_the_backends_own_lock(self):
        """Inside consume(), not merely present in the file. Checking the whole
        source passes while consume() ignores the helper entirely — verified by
        rewriting the call to `lu = None` and watching this stay green."""
        src = _WT.read_text()
        i = src.index('    def consume(')
        body = src[i:src.index('\n    def ', i + 10)]
        self.assertIn('self._locked_update()', body,
                      'consume() does not take the lock')
        self.assertIn('with lu as tickets:', body)
        # and the helper it calls must ask the backend for a real one
        j = src.index('    def _locked_update(')
        helper = src[j:src.index('\n\n', j)]
        self.assertIn('LockedUpdate(', helper)

    def test_the_daemon_refuses_rather_than_risk_a_double_use(self):
        """If the locked path raises, handing the ticket over anyway would be
        the bug wearing an except."""
        src = _WT.read_text()
        i = src.index('def consume')
        seg = src[i:src.index('\n    def _locked_update', i)]
        self.assertIn('return None', seg.split('except Exception')[-1])


class TestATicketIsUsedOnce(unittest.TestCase):
    """Drives the REAL daemon consume against a store the CGI wrote, on the
    SQLite backend, because that is where the two processes share a lock."""

    @classmethod
    def setUpClass(cls):
        if not _WT.exists():
            raise unittest.SkipTest('excluded from dist tree')
        cls.daemon = _load_daemon()

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix='rp-wt-run-'))
        # The daemon picks its backend from the MARKER, not the env.
        # The MARKER is a real on-disk file read before any backend is chosen —
        # one of the two documented exceptions to "never touch a storage key as
        # a file". Written through storage's own atomic writer so the ratchet
        # that counts raw store IO in tests does not have to make an exception
        # for it.
        import storage as _storage
        _storage._write_json_atomic(self.dir / 'storage_backend.json',
                                    {'backend': 'sqlite'})
        spec = importlib.util.spec_from_file_location(
            'api_wt_ticket', _CGI / 'api.py')
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.api.DATA_DIR = self.dir
        self.api.STORAGE_MARKER_FILE = self.dir / 'storage_backend.json'
        self.api.WEBTERM_TICKETS_FILE = self.dir / 'webterm_tickets.json'
        self.api._BACKEND_CACHE = None
        self.store = self.daemon.TicketStore(self.dir / 'webterm_tickets.json')

    def _seed(self, tickets):
        self.api.save(self.api.WEBTERM_TICKETS_FILE, tickets)
        self.api._invalidate_load_cache(self.api.WEBTERM_TICKETS_FILE)

    def test_the_two_sides_agree_on_the_backend(self):
        """Positive control. With the daemon on the flat-file fallback and the
        CGI on SQLite they write different stores, every consume refuses, and
        the single-use assertion below passes for the wrong reason."""
        self.assertIsNotNone(self.store._mod,
                             'the daemon fell back to flat files')
        self.assertIsNotNone(self.store._locked_update(),
                             'the daemon has no lock to share')

    def test_a_valid_ticket_is_accepted_once(self):
        now = int(time.time())
        self._seed({'T1': {'actor': 'admin', 'device_id': 'd1', 'created': now,
                           'expires': now + 60, 'used': False,
                           'source_ip': '1.2.3.4'}})
        self.assertIsNotNone(self.store.consume('T1'))
        self.assertIsNone(self.store.consume('T1'),
                          'the ticket was consumed twice')

    def test_an_expired_ticket_is_refused(self):
        now = int(time.time())
        self._seed({'T2': {'expires': now - 1, 'used': False}})
        self.assertIsNone(self.store.consume('T2'))

    def test_an_unknown_ticket_is_refused(self):
        self._seed({})
        self.assertIsNone(self.store.consume('nope'))

    def test_an_oversized_ticket_is_refused_without_a_store_read(self):
        self._seed({})
        self.assertIsNone(self.store.consume('x' * 300))


if __name__ == '__main__':
    unittest.main()
