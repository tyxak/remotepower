#!/usr/bin/env python3
"""
RemotePower — PostgreSQL storage backend (v3.14.0).

A third storage backend behind the same four helpers api.py already dispatches
to (load / save / LockedUpdate / DeviceTxn + the row-level fast paths), joining
the JSON (flat files) and SQLite (single-file DB) backends. For fleets/operators
who want a real RDBMS — concurrency, replication/HA, central backups — instead of
files on one host.

Design (mirrors storage.py's SQLite backend so callers can't tell the difference):
  * SAME logical schema: kv / devices / entity / listrow / file_meta. The exact
    decomposition + reconstruction logic (classification, JSON round-trip) is
    SHARED with storage.py — imported, not duplicated — so the two DB backends
    can never drift on what a document looks like.
  * Per-"file" read-modify-write serialised with a Postgres TRANSACTION-scoped
    ADVISORY LOCK (pg_advisory_xact_lock) instead of SQLite's BEGIN IMMEDIATE.
  * Heartbeat fast path = a single-row INSERT … ON CONFLICT DO UPDATE (upsert),
    O(1), with the same monotonic last_seen clamp as the other backends.
  * autocommit=True + explicit BEGIN/COMMIT, so a save() called inside a
    LockedUpdate's transaction transparently joins it (no nested BEGIN) — the
    same _Tx ownership trick the SQLite backend uses.

Connection: a single connection per process (CGI = one process per request), the
DSN from RP_PG_DSN (or set via configure_dsn() / api config). psycopg is imported
lazily so non-Postgres deployments never need the dependency installed (same
pattern as ldap3 / psutil).

This module imports storage.py for the shared pure logic but NEVER imports api.py.
"""

import os
import json
import time
import atexit

# Shared, backend-agnostic logic — single source of truth for classification +
# serialisation so the SQLite and Postgres backends always agree on shape.
import storage
from storage import (
    WRAPPED_LIST_FILES, DEVICES_FILE_NAME, _NON_STATE,
    _classify, _name, _dir, _dumps,
    json_inventory, read_marker, write_marker, _read_json, _write_json_atomic, _norm,
)

SCHEMA_VERSION = 1

# psycopg is optional — only imported when this backend is actually used.
_psycopg = None


def _pg():
    global _psycopg
    if _psycopg is None:
        import psycopg  # noqa: WPS433 (lazy, optional dependency)
        _psycopg = psycopg
    return _psycopg


# ── DSN + connection ─────────────────────────────────────────────────────────

_DSN = None        # primary / read-write DSN (configure_dsn; else env RP_PG_DSN)
_READ_DSN = None   # optional read-replica DSN (configure_read_dsn; else env RP_PG_READ_DSN)
_CONN = None       # cached primary connection
_READ_CONN = None  # cached read-replica connection (only when a read DSN is set)
_ATEXIT = False
# v3.14.0: a primary failover (or a mid-promotion connect) shouldn't fail the
# request — retry the connect a few times so libpq can re-resolve hosts and land
# on the newly-promoted primary.
_CONNECT_RETRIES = 3
_CONNECT_BACKOFF = 0.5


def configure_dsn(dsn):
    """Set the primary DSN explicitly (api passes the operator-configured one).
    Closes any cached connection so the next call reconnects to the new target.

    For HA, pass a multi-host DSN (e.g.
    `postgresql://rp:pw@pg-a,pg-b:5432/db`) — `target_session_attrs=read-write`
    is added automatically so libpq always lands on the writable primary, and a
    failover is transparent on the next (retried) reconnect."""
    global _DSN
    close_connection()
    _DSN = dsn or None


def configure_read_dsn(dsn):
    """Optional read-replica DSN. When set, pure `load()` reads are served from
    it; every write and every locked read-modify-write stays on the primary.
    Unset (default) → reads use the primary, behaviour unchanged."""
    global _READ_DSN, _READ_CONN
    if _READ_CONN is not None:
        try:
            _READ_CONN.close()
        except Exception:
            pass
        _READ_CONN = None
    _READ_DSN = dsn or None


def configure(data_dir):
    """No-op for parity with the SQLite backend's configure(). Postgres has one
    logical store (the connected database), not a per-directory file."""
    return None


def _dsn():
    return _DSN or os.environ.get('RP_PG_DSN') or ''


def _read_dsn():
    return _READ_DSN or os.environ.get('RP_PG_READ_DSN') or ''


def _prep_dsn(dsn, read_write=True):
    """For a multi-host (HA) DSN, make libpq pick the right node automatically:
    `target_session_attrs=read-write` lands on the primary and skips replicas,
    so a primary failover is transparent (libpq re-resolves on reconnect). Only
    injected when several hosts are present AND the operator didn't set it."""
    if not dsn or 'target_session_attrs' in dsn:
        return dsn
    hostpart = dsn.split('@')[-1].split('/')[0] if '://' in dsn else dsn
    multi = (',' in hostpart) or ('host=' in dsn and ',' in dsn.split('host=', 1)[1].split()[0])
    if not multi:
        return dsn
    attr = 'read-write' if read_write else 'any'
    if '://' in dsn:
        return f"{dsn}{'&' if '?' in dsn else '?'}target_session_attrs={attr}"
    return f'{dsn} target_session_attrs={attr}'   # keyword DSN


def _alive(conn):
    return conn is not None and not conn.closed and not getattr(conn, 'broken', False)


def _new_conn(dsn, read_write=True):
    """Open a connection with bounded retry — survives a brief failover /
    promotion window instead of erroring the request."""
    psycopg = _pg()
    last = None
    for attempt in range(_CONNECT_RETRIES):
        try:
            return psycopg.connect(_prep_dsn(dsn, read_write), autocommit=True,
                                   connect_timeout=10, row_factory=psycopg.rows.dict_row)
        except psycopg.OperationalError as e:
            last = e
            if attempt < _CONNECT_RETRIES - 1:
                time.sleep(_CONNECT_BACKOFF * (attempt + 1))
    raise last


def db_path(data_dir=None):
    """Parity stub — the SQLite backend returns a Path; here there is no file.
    Returns the DSN's target as a label for status/UI."""
    return _dsn() or 'postgresql://(unconfigured)'


def _is_network_fs(path):
    return False   # irrelevant for a DB server; WAL-on-NFS concerns don't apply


def _connect(data_dir=None):
    """The cached primary (read-write) connection. autocommit=True; we open
    explicit BEGIN/COMMIT blocks ourselves (so save() can join a LockedUpdate
    transaction). Reconnects if the cached connection was closed or BROKEN
    (psycopg marks a connection broken after a failover killed it), retrying so
    a promotion window doesn't surface as an error."""
    global _CONN, _ATEXIT
    if _alive(_CONN):
        return _CONN
    dsn = _dsn()
    if not dsn:
        raise RuntimeError('Postgres backend selected but no DSN configured '
                           '(set RP_PG_DSN or storage_pg.configure_dsn()).')
    conn = _new_conn(dsn, read_write=True)
    _ensure_schema(conn)
    _CONN = conn
    if not _ATEXIT:
        atexit.register(close_connection)
        _ATEXIT = True
    return conn


def _read_conn(data_dir=None):
    """Connection for PURE reads (public load()). Uses the read-replica DSN when
    one is configured, else the primary. Never used for writes or locked RMW —
    those always go through _connect()/the primary, so replica lag can't cause a
    lost update."""
    global _READ_CONN
    rdsn = _read_dsn()
    if not rdsn:
        return _connect(data_dir)
    if _alive(_READ_CONN):
        return _READ_CONN
    _READ_CONN = _new_conn(rdsn, read_write=False)
    return _READ_CONN


def close_connection():
    global _CONN, _READ_CONN
    for c in (_CONN, _READ_CONN):
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
    _CONN = None
    _READ_CONN = None


def pg_status():
    """Small status surface for the UI / db-maintenance: the connected primary
    host(s) and whether a read replica is configured. Never raises / no secrets."""
    def _host(dsn):
        if not dsn:
            return ''
        try:
            if '://' in dsn:
                return dsn.split('@')[-1].split('/')[0]
            for tok in dsn.split():
                if tok.startswith('host='):
                    return tok[5:]
        except Exception:
            pass
        return ''
    return {'primary': _host(_dsn()), 'replica': _host(_read_dsn()),
            'replica_configured': bool(_read_dsn())}


def _ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT);
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            path    TEXT PRIMARY KEY,
            doc     TEXT NOT NULL,
            updated DOUBLE PRECISION
        );""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id        TEXT PRIMARY KEY,
            doc       TEXT NOT NULL,
            last_seen BIGINT DEFAULT 0
        );""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entity (
            file TEXT NOT NULL,
            k    TEXT NOT NULL,
            doc  TEXT NOT NULL,
            PRIMARY KEY (file, k)
        );""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS listrow (
            id   BIGSERIAL PRIMARY KEY,
            file TEXT NOT NULL,
            doc  TEXT NOT NULL
        );""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_listrow_file ON listrow(file, id);")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_meta (
            file    TEXT PRIMARY KEY,
            updated DOUBLE PRECISION NOT NULL
        );""")
    # v3.14.0: append-only per-device metric time-series (see storage.py).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metric_samples (
            device TEXT NOT NULL,
            ts     BIGINT NOT NULL,
            cpu    REAL, mem REAL, swap REAL, disk REAL
        );""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_metric_samples ON metric_samples(device, ts);")
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', %s) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),))


# ── transaction helper (ownership by transaction_status) ──────────────────────

class _Tx:
    """BEGIN only if no transaction is open, so a save() called inside a
    LockedUpdate's BEGIN doesn't nest. autocommit=True means status is IDLE
    between our explicit blocks."""

    def __init__(self, conn):
        self.conn = conn
        self._owns = False

    def __enter__(self):
        from psycopg.pq import TransactionStatus
        if self.conn.info.transaction_status == TransactionStatus.IDLE:
            self.conn.execute('BEGIN')
            self._owns = True
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._owns:
            return False
        if exc_type is None:
            self.conn.execute('COMMIT')
        else:
            try:
                self.conn.execute('ROLLBACK')
            except Exception:
                pass
        return False


def _lock_key(name):
    """Stable 64-bit advisory-lock key for a logical file name."""
    # hashtext() is int4; advisory locks take bigint. Compute in SQL for parity.
    return name


def _acquire(conn, name, non_blocking):
    """Take the per-file advisory lock inside the current transaction. In
    non_blocking mode, raise LockBusyError instead of waiting."""
    if non_blocking:
        got = conn.execute(
            'SELECT pg_try_advisory_xact_lock(hashtext(%s))', (name,)).fetchone()
        # dict_row → {'pg_try_advisory_xact_lock': bool}
        if not list(got.values())[0]:
            raise LockBusyError(name)
    else:
        conn.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', (name,))


def _touch(conn, name):
    try:
        conn.execute(
            'INSERT INTO file_meta(file, updated) VALUES(%s,%s) '
            'ON CONFLICT(file) DO UPDATE SET updated=excluded.updated',
            (name, time.time()))
    except Exception:
        pass


def mtime(path):
    conn = _connect(_dir(path))
    row = conn.execute('SELECT updated FROM file_meta WHERE file=%s',
                       (_name(path),)).fetchone()
    return float(row['updated']) if row else 0.0


# ── load ───────────────────────────────────────────────────────────────────

def load(path):
    # Pure read → may use the read replica (when configured). The locked RMW
    # paths call _load_with_conn(primary_conn, …) directly so they never read a
    # lagging replica under a lock.
    return _load_with_conn(_read_conn(_dir(path)), path)


def _load_with_conn(conn, path):
    kind = _classify(path)
    if kind == 'devices':
        rows = conn.execute('SELECT id, doc FROM devices').fetchall()
        return {r['id']: json.loads(r['doc']) for r in rows}
    if kind == 'entity':
        n = _name(path)
        rows = conn.execute('SELECT k, doc FROM entity WHERE file=%s', (n,)).fetchall()
        return {r['k']: json.loads(r['doc']) for r in rows}
    if kind == 'wrapped':
        n = _name(path)
        wrapkey = WRAPPED_LIST_FILES[n]
        meta = conn.execute('SELECT doc FROM kv WHERE path=%s', (n + '#meta',)).fetchone()
        out = json.loads(meta['doc']) if meta else {}
        rows = conn.execute(
            'SELECT doc FROM listrow WHERE file=%s ORDER BY id', (n,)).fetchall()
        out[wrapkey] = [json.loads(r['doc']) for r in rows]
        return out
    n = _name(path)
    row = conn.execute('SELECT doc FROM kv WHERE path=%s', (n,)).fetchone()
    return json.loads(row['doc']) if row else {}


# ── save ───────────────────────────────────────────────────────────────────

def save(path, data, non_blocking=False, clamp_last_seen=True):
    conn = _connect(_dir(path))
    kind = _classify(path)
    name = _name(path)
    try:
        with _Tx(conn) as c:
            _acquire(c, name, non_blocking)
            if kind == 'devices':
                _save_devices(c, data, clamp_last_seen=clamp_last_seen)
            elif kind == 'entity':
                _save_entity(c, name, data)
            elif kind == 'wrapped':
                _save_wrapped(c, name, data)
            else:
                _save_cold(c, name, data)
            _touch(c, name)
    except LockBusyError:
        raise


def _save_cold(conn, name, data):
    conn.execute(
        'INSERT INTO kv(path, doc, updated) VALUES(%s,%s,%s) '
        'ON CONFLICT(path) DO UPDATE SET doc=excluded.doc, updated=excluded.updated',
        (name, _dumps(data), time.time()))


def _save_devices(conn, data, clamp_last_seen=True):
    if not isinstance(data, dict):
        raise ValueError('devices payload must be a dict')
    current = {r['id']: (r['doc'], r['last_seen'])
               for r in conn.execute('SELECT id, doc, last_seen FROM devices').fetchall()}
    incoming = set()
    for dev_id, dev in data.items():
        incoming.add(dev_id)
        doc = _dumps(dev)
        try:
            inc_ls = int((dev or {}).get('last_seen', 0) or 0)
        except (TypeError, ValueError, AttributeError):
            inc_ls = 0
        cur = current.get(dev_id)
        if cur is None:
            conn.execute('INSERT INTO devices(id, doc, last_seen) VALUES(%s,%s,%s)',
                         (dev_id, doc, inc_ls))
        else:
            cur_doc, cur_ls = cur
            new_ls = max(inc_ls, int(cur_ls or 0)) if clamp_last_seen else inc_ls
            if doc != cur_doc or new_ls != cur_ls:
                if new_ls != inc_ls:
                    dev = dict(dev)
                    dev['last_seen'] = new_ls
                    doc = _dumps(dev)
                conn.execute('UPDATE devices SET doc=%s, last_seen=%s WHERE id=%s',
                             (doc, new_ls, dev_id))
    stale = set(current) - incoming
    if stale:
        conn.cursor().executemany('DELETE FROM devices WHERE id=%s',
                                  [(i,) for i in stale])


def _save_entity(conn, name, data):
    if not isinstance(data, dict):
        raise ValueError(f'{name} payload must be a dict')
    current = {r['k']: r['doc'] for r in conn.execute(
        'SELECT k, doc FROM entity WHERE file=%s', (name,)).fetchall()}
    incoming = set()
    for k, v in data.items():
        incoming.add(k)
        doc = _dumps(v)
        if current.get(k) != doc:
            conn.execute(
                'INSERT INTO entity(file, k, doc) VALUES(%s,%s,%s) '
                'ON CONFLICT(file, k) DO UPDATE SET doc=excluded.doc',
                (name, k, doc))
    stale = set(current) - incoming
    if stale:
        conn.cursor().executemany('DELETE FROM entity WHERE file=%s AND k=%s',
                                  [(name, k) for k in stale])


def _save_wrapped(conn, name, data):
    wrapkey = WRAPPED_LIST_FILES[name]
    if not isinstance(data, dict):
        data = {}
    items = data.get(wrapkey) or []
    if not isinstance(items, list):
        items = []
    conn.execute('DELETE FROM listrow WHERE file=%s', (name,))
    if items:
        conn.cursor().executemany('INSERT INTO listrow(file, doc) VALUES(%s,%s)',
                                  [(name, _dumps(it)) for it in items])
    meta = {k: v for k, v in data.items() if k != wrapkey}
    if meta:
        conn.execute(
            'INSERT INTO kv(path, doc, updated) VALUES(%s,%s,%s) '
            'ON CONFLICT(path) DO UPDATE SET doc=excluded.doc, updated=excluded.updated',
            (name + '#meta', _dumps(meta), time.time()))
    else:
        conn.execute('DELETE FROM kv WHERE path=%s', (name + '#meta',))


# ── locked read-modify-write ─────────────────────────────────────────────────

class LockBusyError(Exception):
    """Contended non-blocking write — api.py maps this to HTTP 202."""


class LockedUpdate:
    def __init__(self, path, non_blocking=False):
        self.path = path
        self.non_blocking = non_blocking
        self._data = None

    def __enter__(self):
        conn = self.conn = _connect(_dir(self.path))
        conn.execute('BEGIN')
        try:
            _acquire(conn, _name(self.path), self.non_blocking)
        except LockBusyError:
            try:
                conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
        # v3.14.0: read on the PRIMARY conn inside the lock (never the replica),
        # so the read-modify-write can't be based on stale replica data.
        self._data = _load_with_conn(conn, self.path)
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        conn = self.conn
        try:
            if exc_type is None and self._data is not None:
                save(self.path, self._data)   # joins this transaction (_Tx no-own)
                conn.execute('COMMIT')
            else:
                conn.execute('ROLLBACK')
        except Exception:
            try:
                conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
        return False


class DeviceTxn:
    """Heartbeat fast path: atomic RMW of a SINGLE device row, O(1)."""

    def __init__(self, devices_path, dev_id, non_blocking=False):
        self.path = devices_path
        self.dev_id = dev_id
        self.non_blocking = non_blocking

    def __enter__(self):
        conn = self.conn = _connect(_dir(self.path))
        conn.execute('BEGIN')
        try:
            _acquire(conn, DEVICES_FILE_NAME + '#' + self.dev_id, self.non_blocking)
        except LockBusyError:
            try:
                conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
        row = conn.execute('SELECT doc, last_seen FROM devices WHERE id=%s',
                           (self.dev_id,)).fetchone()
        self._cur_ls = int(row['last_seen']) if row else 0
        dev = json.loads(row['doc']) if row else None
        self._data = {self.dev_id: dev} if dev is not None else {}
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        conn = self.conn
        try:
            dev = self._data.get(self.dev_id)
            if exc_type is None and dev is not None:
                try:
                    inc = int((dev or {}).get('last_seen', 0) or 0)
                except (TypeError, ValueError, AttributeError):
                    inc = 0
                new_ls = max(inc, self._cur_ls)
                if new_ls != inc:
                    dev = dict(dev)
                    dev['last_seen'] = new_ls
                conn.execute(
                    'INSERT INTO devices(id, doc, last_seen) VALUES(%s,%s,%s) '
                    'ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, last_seen=excluded.last_seen',
                    (self.dev_id, _dumps(dev), new_ls))
                _touch(conn, DEVICES_FILE_NAME)
                conn.execute('COMMIT')
            else:
                conn.execute('ROLLBACK')
        except Exception:
            try:
                conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
        return False


# ── row-level fast helpers ───────────────────────────────────────────────────

def upsert_device(devices_path, dev_id, mutate):
    conn = _connect(_dir(devices_path))
    with _Tx(conn) as c:
        _acquire(c, DEVICES_FILE_NAME + '#' + dev_id, False)
        row = c.execute('SELECT doc, last_seen FROM devices WHERE id=%s',
                       (dev_id,)).fetchone()
        cur = json.loads(row['doc']) if row else {}
        cur_ls = int(row['last_seen']) if row else 0
        new = mutate(dict(cur))
        try:
            inc_ls = int((new or {}).get('last_seen', 0) or 0)
        except (TypeError, ValueError, AttributeError):
            inc_ls = 0
        new_ls = max(inc_ls, cur_ls)
        if new_ls != inc_ls:
            new['last_seen'] = new_ls
        c.execute(
            'INSERT INTO devices(id, doc, last_seen) VALUES(%s,%s,%s) '
            'ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, last_seen=excluded.last_seen',
            (dev_id, _dumps(new), new_ls))
        _touch(c, DEVICES_FILE_NAME)
    return new


# ── v3.14.0: metric time-series (append-only) ────────────────────────────────

def metric_append(data_dir, device, ts, cpu, mem, swap, disk):
    conn = _connect(data_dir)
    with _Tx(conn) as c:
        c.execute(
            'INSERT INTO metric_samples(device, ts, cpu, mem, swap, disk) '
            'VALUES(%s,%s,%s,%s,%s,%s)', (device, int(ts), cpu, mem, swap, disk))


def metric_range(data_dir, device, since_ts, max_points=400):
    conn = _connect(data_dir)
    now = int(time.time())
    since = int(since_ts)
    width = max(1, (now - since) // max(1, int(max_points)))
    rows = conn.execute(
        'SELECT MIN(ts) AS ts, AVG(cpu) AS cpu, AVG(mem) AS mem, '
        '       AVG(swap) AS swap, AVG(disk) AS disk '
        'FROM metric_samples WHERE device=%s AND ts>=%s '
        'GROUP BY (ts - %s) / %s ORDER BY MIN(ts)',
        (device, since, since, width)).fetchall()
    out = []
    for r in rows:
        out.append({'ts': int(r['ts']),
                    'cpu':  round(float(r['cpu']), 2)  if r['cpu']  is not None else None,
                    'mem':  round(float(r['mem']), 2)  if r['mem']  is not None else None,
                    'swap': round(float(r['swap']), 2) if r['swap'] is not None else None,
                    'disk': round(float(r['disk']), 2) if r['disk'] is not None else None})
    return out


def metric_prune(data_dir, older_than_ts):
    conn = _connect(data_dir)
    with _Tx(conn) as c:
        cur = c.execute('DELETE FROM metric_samples WHERE ts < %s', (int(older_than_ts),))
        return cur.rowcount if cur.rowcount is not None else 0


def metric_has_any(data_dir, device):
    conn = _connect(data_dir)
    return conn.execute('SELECT 1 FROM metric_samples WHERE device=%s LIMIT 1',
                       (device,)).fetchone() is not None


def entity_get(path, key, default=None):
    conn = _connect(_dir(path))
    row = conn.execute('SELECT doc FROM entity WHERE file=%s AND k=%s',
                       (_name(path), key)).fetchone()
    return json.loads(row['doc']) if row else default


def entity_set(path, key, value):
    conn = _connect(_dir(path))
    name = _name(path)
    with _Tx(conn) as c:
        _acquire(c, name, False)
        c.execute(
            'INSERT INTO entity(file, k, doc) VALUES(%s,%s,%s) '
            'ON CONFLICT(file, k) DO UPDATE SET doc=excluded.doc',
            (name, key, _dumps(value)))
        _touch(c, name)


def list_append(path, entry, cap=None):
    conn = _connect(_dir(path))
    name = _name(path)
    overflow = []
    with _Tx(conn) as c:
        _acquire(c, name, False)
        c.execute('INSERT INTO listrow(file, doc) VALUES(%s,%s)', (name, _dumps(entry)))
        if cap is not None:
            n = c.execute('SELECT COUNT(*) AS ct FROM listrow WHERE file=%s',
                         (name,)).fetchone()['ct']
            if n > cap:
                old = c.execute(
                    'SELECT id, doc FROM listrow WHERE file=%s ORDER BY id LIMIT %s',
                    (name, n - cap)).fetchall()
                overflow = [json.loads(r['doc']) for r in old]
                c.cursor().executemany('DELETE FROM listrow WHERE id=%s',
                                       [(r['id'],) for r in old])
        _touch(c, name)
    return overflow


# ── presence / inventory / maintenance ───────────────────────────────────────

def exists(path):
    conn = _connect(_dir(path))
    kind = _classify(path)
    if kind == 'devices':
        return conn.execute('SELECT 1 FROM devices LIMIT 1').fetchone() is not None
    if kind == 'entity':
        return conn.execute('SELECT 1 FROM entity WHERE file=%s LIMIT 1',
                           (_name(path),)).fetchone() is not None
    if kind == 'wrapped':
        n = _name(path)
        if conn.execute('SELECT 1 FROM listrow WHERE file=%s LIMIT 1',
                       (n,)).fetchone() is not None:
            return True
        return conn.execute('SELECT 1 FROM kv WHERE path=%s',
                           (n + '#meta',)).fetchone() is not None
    return conn.execute('SELECT 1 FROM kv WHERE path=%s',
                       (_name(path),)).fetchone() is not None


def iter_files(data_dir=None):
    conn = _connect(data_dir)
    names = set()
    for r in conn.execute('SELECT path FROM kv').fetchall():
        p = r['path']
        names.add(p[:-len('#meta')] if p.endswith('#meta') else p)
    for r in conn.execute('SELECT DISTINCT file FROM entity').fetchall():
        names.add(r['file'])
    for r in conn.execute('SELECT DISTINCT file FROM listrow').fetchall():
        names.add(r['file'])
    if conn.execute('SELECT 1 FROM devices LIMIT 1').fetchone() is not None:
        names.add(DEVICES_FILE_NAME)
    names -= _NON_STATE
    return sorted(names)


def doc_size(path):
    conn = _connect(_dir(path))
    kind = _classify(path)
    if kind == 'devices':
        r = conn.execute('SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM devices').fetchone()
        return int(r['b'])
    if kind == 'entity':
        r = conn.execute('SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM entity WHERE file=%s',
                        (_name(path),)).fetchone()
        return int(r['b'])
    if kind == 'wrapped':
        r = conn.execute('SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM listrow WHERE file=%s',
                        (_name(path),)).fetchone()
        return int(r['b'])
    r = conn.execute('SELECT LENGTH(doc) AS b FROM kv WHERE path=%s',
                    (_name(path),)).fetchone()
    return int(r['b']) if r else 0


def maintenance(data_dir=None, full=False):
    conn = _connect(data_dir)
    result = {'backend': 'postgres'}
    try:
        conn.execute('ANALYZE')
        result['analyze'] = True
    except Exception as e:
        result['analyze_error'] = str(e)
    if full:
        try:
            conn.execute('VACUUM')   # autocommit — must be outside a txn
            result['vacuum'] = True
        except Exception as e:
            result['vacuum_error'] = str(e)
    try:
        row = conn.execute("SELECT pg_database_size(current_database()) AS b").fetchone()
        result['db_bytes'] = int(row['b'])
    except Exception:
        result['db_bytes'] = None
    return result


def snapshot(dest, data_dir=None):
    """Logical export of all stored documents to a single JSON file (DR / backup
    artifact). Postgres has no single-file image like SQLite, so we dump the
    reconstructed logical view; restore by loading each file back."""
    from pathlib import Path
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dump = {name: load(Path(data_dir or '.') / name) for name in iter_files(data_dir)}
    _write_json_atomic(dest, dump)
    return dest


# ── migration: JSON  <->  Postgres ───────────────────────────────────────────

def import_from_json(data_dir, log=lambda m: None):
    """Load every *.json on disk into Postgres (faithful timestamps)."""
    from pathlib import Path
    data_dir = Path(data_dir)
    names = json_inventory(data_dir)
    for name in names:
        save(data_dir / name, _read_json(data_dir / name), clamp_last_seen=False)
        log(f"  json -> postgres  {name}")
    return names


def export_to_json(data_dir, log=lambda m: None):
    """Write every Postgres-stored document back out as a *.json file."""
    from pathlib import Path
    data_dir = Path(data_dir)
    names = iter_files(data_dir)
    for name in names:
        _write_json_atomic(data_dir / name, load(data_dir / name))
        log(f"  postgres -> json  {name}")
    return names


def verify_against_json(data_dir, log=lambda m: None):
    """Compare the JSON-on-disk view with the Postgres reconstruction."""
    from pathlib import Path
    data_dir = Path(data_dir)
    names = set(json_inventory(data_dir)) | set(iter_files(data_dir))
    problems = []
    for name in sorted(names):
        jp = data_dir / name
        j = _read_json(jp) if jp.exists() else None
        s = load(jp) if exists(jp) else None
        if j is None and s is None:
            continue
        if j is None or s is None:
            problems.append(f"{name}: present in only one backend")
            continue
        if _norm(j) != _norm(s):
            problems.append(f"{name}: content differs")
    ok = not problems
    log(f"verify: OK ({len(names)} files match)" if ok
        else f"verify: {len(problems)} mismatch(es)")
    return ok, problems
