#!/usr/bin/env python3
"""
v3.14.0: PostgreSQL HA — automatic failover (multi-host DSN + connect retry +
broken-connection reconnect) and opt-in read-replica routing. These exercise
storage_pg's connection logic with a fake psycopg, so they run without a live
database (the live round-trip tests live in test_pg.py and self-skip).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
spec = importlib.util.spec_from_file_location("storage_pg_ha", _ROOT / "server/cgi-bin/storage_pg.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class _FakeOpErr(Exception):
    pass


class _FakeConn:
    def __init__(self, dsn):
        self.dsn = dsn
        self.closed = False
        self.broken = False

    def close(self):
        self.closed = True


def _fake_psycopg(connect):
    ns = type('pg', (), {})()
    ns.OperationalError = _FakeOpErr
    ns.connect = staticmethod(connect)
    ns.rows = type('r', (), {'dict_row': object()})()
    return ns


class TestPrepDsn(unittest.TestCase):
    """target_session_attrs is injected only for multi-host DSNs, so libpq lands
    on the writable primary and a failover is transparent on reconnect."""

    def test_multihost_url_gets_read_write(self):
        out = s._prep_dsn('postgresql://u:p@pg-a,pg-b:5432/db', True)
        self.assertTrue(out.endswith('?target_session_attrs=read-write'))

    def test_query_string_uses_ampersand(self):
        out = s._prep_dsn('postgresql://u:p@pg-a,pg-b/db?sslmode=require', True)
        self.assertTrue(out.endswith('&target_session_attrs=read-write'))

    def test_single_host_untouched(self):
        for dsn in ('postgresql://u:p@only:5432/db', 'postgresql://u:p@only/db'):
            self.assertEqual(s._prep_dsn(dsn, True), dsn)

    def test_keyword_dsn_multihost(self):
        out = s._prep_dsn('host=pg-a,pg-b dbname=db', True)
        self.assertIn('target_session_attrs=read-write', out)

    def test_explicit_attr_respected(self):
        dsn = 'postgresql://u:p@pg-a,pg-b/db?target_session_attrs=primary'
        self.assertEqual(s._prep_dsn(dsn, True), dsn)

    def test_replica_attr_is_any(self):
        out = s._prep_dsn('postgresql://u:p@r1,r2/db', False)
        self.assertIn('target_session_attrs=any', out)


class TestPgStatus(unittest.TestCase):
    def setUp(self):
        self._d, self._r = s._DSN, s._READ_DSN
    def tearDown(self):
        s._DSN, s._READ_DSN = self._d, self._r

    def test_status_exposes_hosts_no_secrets(self):
        s._DSN = 'postgresql://rp:secret@pg-a,pg-b:5432/db'
        s._READ_DSN = 'postgresql://rp:secret@replica:5432/db'
        st = s.pg_status()
        self.assertEqual(st['primary'], 'pg-a,pg-b:5432')
        self.assertEqual(st['replica'], 'replica:5432')
        self.assertTrue(st['replica_configured'])
        self.assertNotIn('secret', str(st))

    def test_no_replica(self):
        s._DSN = 'postgresql://rp:x@only/db'; s._READ_DSN = None
        self.assertFalse(s.pg_status()['replica_configured'])


class TestConnectRetry(unittest.TestCase):
    """A failover/promotion window must be retried, not surfaced as an error."""

    def setUp(self):
        self._pg, self._sleep = s._pg, s.time.sleep
        s.time.sleep = lambda *_a, **_k: None
    def tearDown(self):
        s._pg, s.time.sleep = self._pg, self._sleep

    def test_retries_then_succeeds(self):
        calls = {'n': 0}
        def connect(dsn, **k):
            calls['n'] += 1
            if calls['n'] < 3:
                raise _FakeOpErr('the database system is starting up')
            return _FakeConn(dsn)
        s._pg = lambda: _fake_psycopg(connect)
        conn = s._new_conn('postgresql://u:p@pg-a,pg-b/db', read_write=True)
        self.assertEqual(calls['n'], 3)
        self.assertIsInstance(conn, _FakeConn)

    def test_gives_up_after_retries(self):
        def connect(dsn, **k):
            raise _FakeOpErr('down')
        s._pg = lambda: _fake_psycopg(connect)
        with self.assertRaises(_FakeOpErr):
            s._new_conn('postgresql://u:p@h/db', read_write=True)


class TestReadReplicaRouting(unittest.TestCase):
    """Pure load() uses the replica when configured; everything else the primary.
    Verified at the routing level (no live DB)."""

    def setUp(self):
        self._cf = {n: getattr(s, n) for n in ('_connect', '_new_conn', '_READ_DSN', '_READ_CONN', '_alive')}

    def tearDown(self):
        for n, v in self._cf.items():
            setattr(s, n, v)
        s._READ_CONN = None

    def test_read_conn_falls_back_to_primary_without_read_dsn(self):
        s._READ_DSN = None
        sentinel = object()
        s._connect = lambda data_dir=None: sentinel
        self.assertIs(s._read_conn(), sentinel)

    def test_read_conn_uses_replica_when_configured(self):
        s._READ_DSN = 'postgresql://u:p@replica/db'
        s._READ_CONN = None
        s._alive = lambda c: False
        replica = _FakeConn('replica')
        s._new_conn = lambda dsn, read_write=True: replica
        got = s._read_conn()
        self.assertIs(got, replica)

    def test_locked_update_reads_primary_not_replica(self):
        # Guardrail on the source: LockedUpdate must read via _load_with_conn on
        # its own (primary) connection, never the replica-routed load().
        src = (_ROOT / "server/cgi-bin/storage_pg.py").read_text()
        self.assertIn('self._data = _load_with_conn(conn, self.path)', src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
