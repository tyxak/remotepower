#!/usr/bin/env python3
"""
RemotePower — SQLite storage backend (v3.12.0).

RemotePower has always persisted state as flat-JSON files in DATA_DIR, read and
written through api.py's load()/save()/_save_held()/_locked_update() helpers.
That design is robust but every write rewrites a whole file — on a busy fleet
devices.json is rewritten on *every* heartbeat (O(N) per heartbeat for N
devices, serialised behind one flock). This module is the optional "real
database" backend an operator can switch to under Settings → Advanced.

Design goals:
  * Drop-in behind the existing 4 helpers — api.py branches to us when the
    active backend is 'sqlite', so the ~1000 call sites don't change.
  * stdlib sqlite3 only, zero new dependencies. Fits the FastCGI/fcgiwrap
    runtime (one process per request — no server or connection pool to run).
  * WAL mode: concurrent readers + a single writer, each write a fast row op.
  * Full decomposition of the hot, high-cardinality files so a heartbeat
    becomes a single-row UPSERT instead of a whole-file rewrite.

File classification (by basename — see _classify):
  * dict-of-entity  {key: value}        -> one row per key
        devices.json (own table, last_seen promoted to its own column),
        cmd_output.json, metrics.json, monitor_history.json,
        metrics_history.json  (shared `entity` table, keyed by (file, k))
  * wrapped-list    {"<wrapkey>": [...]} -> one row per list element
        history.json (entries), alerts.json (alerts), fleet_events.json (events)
        Any sibling metadata keys are preserved in a kv `<file>#meta` row.
  * everything else (cold)               -> a single JSON blob row in `kv`

The reconstruction is exact: load() returns the same Python structure the JSON
backend would have, so callers cannot tell the difference.

This module never imports api.py (api imports us). The data directory is set by
api via configure(); we fall back to RP_DATA_DIR so the migration CLI and tests
work standalone.
"""

import os
import json
import time
import atexit
import sqlite3
from pathlib import Path

# ── data dir + db path ───────────────────────────────────────────────────────

DATA_DIR = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
DB_NAME = 'remotepower.db'

SCHEMA_VERSION = 2  # v3.12.0: +file_meta (per-file last-write time)


def configure(data_dir):
    """Set the default data directory used by name-only helpers and by
    iter_files(). The connection itself is keyed per directory (see _connect),
    derived from each path's parent — so the test suite's per-test trick of
    repointing the *_FILE constants at a fresh temp dir transparently gets its
    own database, and in production (all files under one DATA_DIR) there is a
    single DB at DATA_DIR/remotepower.db."""
    global DATA_DIR
    DATA_DIR = Path(data_dir)


def db_path(data_dir=None):
    return Path(data_dir or DATA_DIR) / DB_NAME


def _dir(path):
    """The data directory a given file path lives in — the DB lives beside it."""
    return Path(path).parent


# ── file classification ──────────────────────────────────────────────────────

# dict-of-entity files stored in the shared `entity` table (devices.json has its
# own table for the indexed last_seen column, handled separately).
ENTITY_FILES = {
    'cmd_output.json',
    'metrics.json',
    'monitor_history.json',
    'metrics_history.json',
}

# wrapped-list files: basename -> the single top-level list key.
# NOTE: fleet_events.json is deliberately NOT here — it is polymorphic in the
# codebase (written dict-wrapped by _record_fleet_event, but read as a bare list
# by _compute_attention), so it's kept a COLD blob that round-trips whatever
# shape it's given, exactly like the JSON backend.
WRAPPED_LIST_FILES = {
    'history.json': 'entries',
    'alerts.json': 'alerts',
    # v4.3.0: capped slow-handler ring, written via list_append (O(1)).
    'slow_handlers.json': 'entries',
}

DEVICES_FILE_NAME = 'devices.json'

# Files that are intentionally NOT part of the JSON state model and must stay on
# the filesystem regardless of backend (transient / non-JSON). api.py knows
# these too; listed here so backend_iter_files() never claims them.
_NON_STATE = {'storage_backend.json'}


def _name(path):
    return Path(path).name


def _classify(path):
    """Return one of 'devices', 'entity', 'wrapped', 'cold'."""
    n = _name(path)
    if n == DEVICES_FILE_NAME:
        return 'devices'
    if n in ENTITY_FILES:
        return 'entity'
    if n in WRAPPED_LIST_FILES:
        return 'wrapped'
    return 'cold'


# ── connection management ────────────────────────────────────────────────────

# One connection per data directory per CGI process, opened lazily, closed at
# process exit (atexit) so the final WAL checkpoint runs and we never pin the
# -wal across requests. In production there's exactly one entry (DATA_DIR); the
# test suite gets one per temp dir it repoints the constants at.
_CONNS = {}
_ATEXIT_REGISTERED = False


_NETFS_CACHE = {}


def _is_network_fs(path):
    """Best-effort: WAL's shared-memory index (-shm) is broken over NFS/CIFS and
    corrupts or throws 'database is locked' storms. Detect so the migration can
    warn and fall back to a rollback journal.

    v4.2.0 sweep (perf): reads /proc/self/mounts instead of forking a `stat`
    subprocess (which ran on the first _connect of EVERY CGI process), and the
    verdict is cached per path for the process lifetime. Non-Linux (no /proc)
    falls through to False, same as the old GNU-stat failure path."""
    key = str(path)
    if key in _NETFS_CACHE:
        return _NETFS_CACHE[key]
    verdict = False
    try:
        real = os.path.realpath(key)
        best_type = ''
        best_len = -1
        with open('/proc/self/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                # /proc/mounts octal-escapes spaces in mountpoints as \040
                mnt = parts[1].replace('\\040', ' ')
                if (real == mnt or real.startswith(mnt.rstrip('/') + '/')) \
                        and len(mnt) > best_len:
                    best_len = len(mnt)
                    best_type = parts[2].lower()
        verdict = best_type in ('nfs', 'nfs4', 'smb', 'smb2', 'smb3',
                                'cifs', 'fuseblk', 'fuse')
    except Exception:
        verdict = False
    _NETFS_CACHE[key] = verdict
    return verdict


def _connect(data_dir=None):
    global _ATEXIT_REGISTERED
    d = Path(data_dir or DATA_DIR)
    key = str(d)
    conn = _CONNS.get(key)
    if conn is not None:
        return conn
    d.mkdir(parents=True, exist_ok=True)
    p = d / DB_NAME
    # isolation_level=None -> autocommit; we manage transactions explicitly with
    # BEGIN/BEGIN IMMEDIATE/COMMIT so a multi-statement diff-save is atomic and
    # _locked_update gets a real write lock at statement start (BEGIN IMMEDIATE).
    conn = sqlite3.connect(str(p), isolation_level=None, timeout=30.0)
    conn.row_factory = sqlite3.Row
    journal = 'WAL'
    if _is_network_fs(d):
        # WAL is unsafe here; a rollback journal still gives ACID, just less
        # concurrency. Better correct-and-slow than corrupt.
        journal = 'TRUNCATE'
    try:
        conn.execute(f'PRAGMA journal_mode={journal}')
    except sqlite3.OperationalError:
        conn.execute('PRAGMA journal_mode=TRUNCATE')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA foreign_keys=ON')
    _ensure_schema(conn)
    _CONNS[key] = conn
    if not _ATEXIT_REGISTERED:
        atexit.register(close_connection)
        _ATEXIT_REGISTERED = True
    return conn


def close_connection():
    """Close every open per-directory connection (process exit / data-dir
    change / test teardown)."""
    for conn in list(_CONNS.values()):
        try:
            if conn.in_transaction:
                conn.execute('ROLLBACK')
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
    _CONNS.clear()


def _ensure_schema(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS kv (
            path    TEXT PRIMARY KEY,
            doc     TEXT NOT NULL,
            updated REAL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id        TEXT PRIMARY KEY,
            doc       TEXT NOT NULL,
            last_seen INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS entity (
            file TEXT NOT NULL,
            k    TEXT NOT NULL,
            doc  TEXT NOT NULL,
            PRIMARY KEY (file, k)
        );
        CREATE TABLE IF NOT EXISTS listrow (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            doc  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_listrow_file ON listrow(file, id);
        -- v3.12.0: per-logical-file last-write time, so callers that used a
        -- file mtime for change detection (e.g. the RAG reindexer) have a
        -- backend-agnostic signal under SQLite where the .json artifacts don't
        -- exist on disk. Touched by every writer below.
        CREATE TABLE IF NOT EXISTS file_meta (
            file    TEXT PRIMARY KEY,
            updated REAL NOT NULL
        );
        -- v3.14.0: append-only per-device metric time-series. Unlike metrics.json
        -- (a per-device blob rewritten every heartbeat), this is one cheap row
        -- per sample, so long retention (30d+) stays O(1)/heartbeat. Queried by
        -- device + time range with on-read downsampling.
        CREATE TABLE IF NOT EXISTS metric_samples (
            device TEXT NOT NULL,
            ts     INTEGER NOT NULL,
            cpu    REAL,
            mem    REAL,
            swap   REAL,
            disk   REAL
        );
        CREATE INDEX IF NOT EXISTS idx_metric_samples ON metric_samples(device, ts);
        """
    )
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),))


# ── transaction helper ───────────────────────────────────────────────────────

class _Tx:
    """Begin a transaction only if one isn't already open (so a save() called
    inside _locked_update's BEGIN IMMEDIATE doesn't try to nest)."""

    def __init__(self, conn, immediate=False):
        self.conn = conn
        self.immediate = immediate
        self._owns = False

    def __enter__(self):
        if not self.conn.in_transaction:
            self.conn.execute('BEGIN IMMEDIATE' if self.immediate else 'BEGIN')
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


def _dumps(value):
    """Serialise a doc the way api.save validates — reject NaN/Infinity so no
    non-Python consumer chokes. Compact; key order doesn't matter to callers."""
    try:
        return json.dumps(value, allow_nan=False, sort_keys=True,
                          separators=(',', ':'))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Refusing to store unserialisable data: {exc}")


def _touch(conn, name):
    """Record `name`'s last-write time. Called by every writer (inside the
    caller's transaction) so mtime(path) gives a backend-agnostic change signal.
    Best-effort: a touch failure must never fail the actual write."""
    try:
        conn.execute(
            'INSERT INTO file_meta(file, updated) VALUES(?,?) '
            'ON CONFLICT(file) DO UPDATE SET updated=excluded.updated',
            (name, time.time()))
    except sqlite3.Error:
        pass


def mtime(path):
    """Last-write time of a logical file (epoch seconds), or 0.0 if never
    written. The SQLite analogue of Path.stat().st_mtime for data files."""
    conn = _connect(_dir(path))
    row = conn.execute('SELECT updated FROM file_meta WHERE file=?',
                       (_name(path),)).fetchone()
    return float(row['updated']) if row else 0.0


# ── load ─────────────────────────────────────────────────────────────────────

def load(path):
    """Reconstruct the whole document for `path` from its decomposed rows,
    returning the exact structure the JSON backend would have."""
    conn = _connect(_dir(path))
    kind = _classify(path)
    if kind == 'devices':
        rows = conn.execute('SELECT id, doc FROM devices').fetchall()
        return {r['id']: json.loads(r['doc']) for r in rows}
    if kind == 'entity':
        n = _name(path)
        rows = conn.execute(
            'SELECT k, doc FROM entity WHERE file=?', (n,)).fetchall()
        return {r['k']: json.loads(r['doc']) for r in rows}
    if kind == 'wrapped':
        n = _name(path)
        wrapkey = WRAPPED_LIST_FILES[n]
        meta_row = conn.execute(
            'SELECT doc FROM kv WHERE path=?', (n + '#meta',)).fetchone()
        out = json.loads(meta_row['doc']) if meta_row else {}
        rows = conn.execute(
            'SELECT doc FROM listrow WHERE file=? ORDER BY id', (n,)).fetchall()
        out[wrapkey] = [json.loads(r['doc']) for r in rows]
        return out
    # cold
    n = _name(path)
    row = conn.execute('SELECT doc FROM kv WHERE path=?', (n,)).fetchone()
    if row is None:
        return {}
    return json.loads(row['doc'])


# ── save ─────────────────────────────────────────────────────────────────────

def save(path, data, non_blocking=False, clamp_last_seen=True):
    """Persist the whole document for `path`, decomposed into rows. Only rows
    whose serialised form changed are written (devices/entity), so the common
    heartbeat save touches one row even when the caller hands us the whole dict.

    Atomic: wrapped in its own transaction unless one is already open (i.e.
    we're inside _locked_update). In non_blocking mode a contended write raises
    LockBusyError instead of waiting out the busy_timeout, so the heartbeat can
    return HTTP 202.

    `clamp_last_seen=False` disables the devices.json monotonic guard — used by
    the migration (which must reproduce stored timestamps faithfully) and by
    tests that deliberately age a device backwards."""
    conn = _connect(_dir(path))
    kind = _classify(path)
    name = _name(path)
    if non_blocking:
        conn.execute('PRAGMA busy_timeout=100')
    try:
        with _Tx(conn, immediate=True):
            if kind == 'devices':
                _save_devices(conn, data, clamp_last_seen=clamp_last_seen)
            elif kind == 'entity':
                _save_entity(conn, name, data)
            elif kind == 'wrapped':
                _save_wrapped(conn, name, data)
            else:
                _save_cold(conn, name, data)
            _touch(conn, name)
    except sqlite3.OperationalError as exc:
        if non_blocking and 'locked' in str(exc).lower():
            raise LockBusyError(path)
        raise
    finally:
        if non_blocking:
            conn.execute('PRAGMA busy_timeout=10000')


def _save_cold(conn, name, data):
    conn.execute(
        'INSERT INTO kv(path, doc, updated) VALUES(?,?,?) '
        'ON CONFLICT(path) DO UPDATE SET doc=excluded.doc, updated=excluded.updated',
        (name, _dumps(data), time.time()))


def _save_devices(conn, data, clamp_last_seen=True):
    if not isinstance(data, dict):
        raise ValueError('devices payload must be a dict')
    current = {r['id']: (r['doc'], r['last_seen'])
               for r in conn.execute(
                   'SELECT id, doc, last_seen FROM devices').fetchall()}
    incoming_ids = set()
    for dev_id, dev in data.items():
        incoming_ids.add(dev_id)
        doc = _dumps(dev)
        try:
            inc_ls = int((dev or {}).get('last_seen', 0) or 0)
        except (TypeError, ValueError, AttributeError):
            inc_ls = 0
        cur = current.get(dev_id)
        if cur is None:
            conn.execute(
                'INSERT INTO devices(id, doc, last_seen) VALUES(?,?,?)',
                (dev_id, doc, inc_ls))
        else:
            cur_doc, cur_ls = cur
            # last_seen monotonic guard (mirrors api.save's regression guard):
            # never let a stale write move a device's clock backwards, but still
            # apply the other field changes the caller computed.
            new_ls = max(inc_ls, int(cur_ls or 0)) if clamp_last_seen else inc_ls
            if doc != cur_doc or new_ls != cur_ls:
                if new_ls != inc_ls:
                    dev = dict(dev)
                    dev['last_seen'] = new_ls
                    doc = _dumps(dev)
                conn.execute(
                    'UPDATE devices SET doc=?, last_seen=? WHERE id=?',
                    (doc, new_ls, dev_id))
    stale = set(current) - incoming_ids
    if stale:
        conn.executemany('DELETE FROM devices WHERE id=?',
                         [(i,) for i in stale])


def _save_entity(conn, name, data):
    if not isinstance(data, dict):
        raise ValueError(f'{name} payload must be a dict')
    current = {r['k']: r['doc'] for r in conn.execute(
        'SELECT k, doc FROM entity WHERE file=?', (name,)).fetchall()}
    incoming = set()
    for k, v in data.items():
        incoming.add(k)
        doc = _dumps(v)
        if current.get(k) != doc:
            conn.execute(
                'INSERT INTO entity(file, k, doc) VALUES(?,?,?) '
                'ON CONFLICT(file, k) DO UPDATE SET doc=excluded.doc',
                (name, k, doc))
    stale = set(current) - incoming
    if stale:
        conn.executemany('DELETE FROM entity WHERE file=? AND k=?',
                         [(name, k) for k in stale])


def _save_wrapped(conn, name, data):
    wrapkey = WRAPPED_LIST_FILES[name]
    if not isinstance(data, dict):
        data = {}
    items = data.get(wrapkey) or []
    if not isinstance(items, list):
        items = []
    # Full replace of the list rows. Hot append callers should use db_append /
    # db_prune instead; this path handles wholesale writers (clear-all, etc.).
    conn.execute('DELETE FROM listrow WHERE file=?', (name,))
    if items:
        conn.executemany(
            'INSERT INTO listrow(file, doc) VALUES(?,?)',
            [(name, _dumps(it)) for it in items])
    # Preserve any sibling metadata keys (everything except the list key).
    meta = {k: v for k, v in data.items() if k != wrapkey}
    if meta:
        conn.execute(
            'INSERT INTO kv(path, doc, updated) VALUES(?,?,?) '
            'ON CONFLICT(path) DO UPDATE SET doc=excluded.doc, updated=excluded.updated',
            (name + '#meta', _dumps(meta), time.time()))
    else:
        conn.execute('DELETE FROM kv WHERE path=?', (name + '#meta',))


# ── locked read-modify-write ─────────────────────────────────────────────────

class LockedUpdate:
    """SQLite analogue of api._LockedUpdate: BEGIN IMMEDIATE -> load -> yield ->
    save -> COMMIT. The IMMEDIATE write lock at statement start removes the
    read-modify-write race the JSON flock pattern existed to fix. On any
    exception (including SystemExit from respond()) the transaction rolls back
    and nothing is published."""

    def __init__(self, path, non_blocking=False):
        self.path = path
        self.non_blocking = non_blocking
        self._data = None

    def __enter__(self):
        conn = _connect(_dir(self.path))
        if self.non_blocking:
            conn.execute('PRAGMA busy_timeout=100')
        try:
            conn.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as exc:
            if self.non_blocking and 'locked' in str(exc).lower():
                raise LockBusyError(self.path)
            raise
        finally:
            if self.non_blocking:
                conn.execute('PRAGMA busy_timeout=10000')
        self._data = load(self.path)
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        conn = _connect(_dir(self.path))
        try:
            if exc_type is None and self._data is not None:
                save(self.path, self._data)
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
    """Heartbeat fast path: atomic read-modify-write of a SINGLE device row.

    BEGIN IMMEDIATE → load one row as {dev_id: dev} → yield → upsert that one
    row (monotonic last_seen clamp) → COMMIT. Any exception (incl. SystemExit
    from respond()) → ROLLBACK. O(1): no whole-table scan or rewrite, unlike the
    generic LockedUpdate which reconstructs every device. Only upserts dev_id —
    it never deletes other devices (the heartbeat only ever touches its own)."""

    def __init__(self, devices_path, dev_id, non_blocking=False):
        self.dir = _dir(devices_path)
        self.dev_id = dev_id
        self.non_blocking = non_blocking

    def __enter__(self):
        self.conn = _connect(self.dir)
        if self.non_blocking:
            self.conn.execute('PRAGMA busy_timeout=100')
        try:
            self.conn.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as exc:
            if self.non_blocking and 'locked' in str(exc).lower():
                raise LockBusyError(self.dev_id)
            raise
        finally:
            if self.non_blocking:
                self.conn.execute('PRAGMA busy_timeout=10000')
        row = self.conn.execute(
            'SELECT doc, last_seen FROM devices WHERE id=?',
            (self.dev_id,)).fetchone()
        self._cur_ls = int(row['last_seen']) if row else 0
        dev = json.loads(row['doc']) if row else None
        self._data = {self.dev_id: dev} if dev is not None else {}
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
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
                self.conn.execute(
                    'INSERT INTO devices(id, doc, last_seen) VALUES(?,?,?) '
                    'ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, last_seen=excluded.last_seen',
                    (self.dev_id, _dumps(dev), new_ls))
                _touch(self.conn, DEVICES_FILE_NAME)
                self.conn.execute('COMMIT')
            else:
                self.conn.execute('ROLLBACK')
        except Exception:
            try:
                self.conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
        return False


class LockBusyError(Exception):
    """Raised by LockedUpdate(non_blocking=True) when the write lock is
    contended. api.py translates this into its own LockBusy so the heartbeat
    still returns HTTP 202."""


# ── row-level fast helpers (used by the hot paths in api.py) ──────────────────

def upsert_device(devices_path, dev_id, mutate):
    """Read one device row, apply mutate(dev_dict)->dev_dict, write it back —
    O(1), under a single IMMEDIATE transaction with the last_seen clamp. This is
    the heartbeat fast path: no whole-dict reconstruction.

    `devices_path` is the DEVICES_FILE Path (selects the per-dir DB). `mutate`
    receives the current device dict ({} if new) and returns the dict to store.
    Returns the stored dict."""
    conn = _connect(_dir(devices_path))
    with _Tx(conn, immediate=True):
        row = conn.execute(
            'SELECT doc, last_seen FROM devices WHERE id=?', (dev_id,)).fetchone()
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
        doc = _dumps(new)
        conn.execute(
            'INSERT INTO devices(id, doc, last_seen) VALUES(?,?,?) '
            'ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, last_seen=excluded.last_seen',
            (dev_id, doc, new_ls))
        _touch(conn, DEVICES_FILE_NAME)
    return new


# ── v3.14.0: metric time-series (append-only) ────────────────────────────────

def metric_append(data_dir, device, ts, cpu, mem, swap, disk):
    """Append one metric sample row — O(1), no whole-document rewrite."""
    conn = _connect(data_dir)
    with _Tx(conn, immediate=True):
        conn.execute(
            'INSERT INTO metric_samples(device, ts, cpu, mem, swap, disk) '
            'VALUES(?,?,?,?,?,?)', (device, int(ts), cpu, mem, swap, disk))


def metric_range(data_dir, device, since_ts, max_points=400):
    """Return up to ~max_points downsampled samples for `device` since `since_ts`
    (epoch seconds). Buckets the range and averages within each bucket so a chart
    stays readable whether the window is 24h or 30d. [{ts,cpu,mem,swap,disk}]."""
    conn = _connect(data_dir)
    now = int(time.time())
    since = int(since_ts)
    width = max(1, (now - since) // max(1, int(max_points)))
    rows = conn.execute(
        'SELECT CAST(MIN(ts) AS INTEGER) AS ts, '
        '       AVG(cpu) AS cpu, AVG(mem) AS mem, AVG(swap) AS swap, AVG(disk) AS disk '
        'FROM metric_samples WHERE device=? AND ts>=? '
        'GROUP BY (ts - ?) / ? ORDER BY ts',
        (device, since, since, width)).fetchall()
    out = []
    for r in rows:
        out.append({'ts': int(r['ts']),
                    'cpu':  round(r['cpu'], 2)  if r['cpu']  is not None else None,
                    'mem':  round(r['mem'], 2)  if r['mem']  is not None else None,
                    'swap': round(r['swap'], 2) if r['swap'] is not None else None,
                    'disk': round(r['disk'], 2) if r['disk'] is not None else None})
    return out


def metric_prune(data_dir, older_than_ts):
    """Delete samples older than `older_than_ts`. Returns the row count removed."""
    conn = _connect(data_dir)
    with _Tx(conn, immediate=True):
        cur = conn.execute('DELETE FROM metric_samples WHERE ts < ?',
                           (int(older_than_ts),))
        return cur.rowcount if cur.rowcount is not None else 0


def metric_has_any(data_dir, device):
    """True if the time-series already holds any sample for `device` — used to
    seed it once from the legacy metrics.json window."""
    conn = _connect(data_dir)
    return conn.execute('SELECT 1 FROM metric_samples WHERE device=? LIMIT 1',
                       (device,)).fetchone() is not None


def device_get(path, dev_id, default=None):
    """v4.3.0: read ONE device by id with a single-row SELECT instead of loading
    and json.loads-ing every device. Read-only mirror of DeviceTxn's row read —
    no transaction, no lock (callers that mutate must still use DeviceTxn).
    Returns `default` when the device isn't found."""
    conn = _connect(_dir(path))
    row = conn.execute(
        'SELECT doc FROM devices WHERE id=?', (dev_id,)).fetchone()
    return json.loads(row['doc']) if row else default


def entity_get(path, key, default=None):
    conn = _connect(_dir(path))
    name = _name(path)
    row = conn.execute(
        'SELECT doc FROM entity WHERE file=? AND k=?', (name, key)).fetchone()
    return json.loads(row['doc']) if row else default


def entity_set(path, key, value):
    conn = _connect(_dir(path))
    name = _name(path)
    with _Tx(conn, immediate=True):
        conn.execute(
            'INSERT INTO entity(file, k, doc) VALUES(?,?,?) '
            'ON CONFLICT(file, k) DO UPDATE SET doc=excluded.doc',
            (name, key, _dumps(value)))
        _touch(conn, name)


def list_append(path, entry, cap=None):
    """Append one element to a wrapped-list file and optionally prune to the
    newest `cap` elements — O(1)/O(overflow), not O(list). Returns the list of
    evicted (overflow) elements so the caller can archive them."""
    conn = _connect(_dir(path))
    name = _name(path)
    overflow = []
    with _Tx(conn, immediate=True):
        conn.execute('INSERT INTO listrow(file, doc) VALUES(?,?)',
                    (name, _dumps(entry)))
        if cap is not None:
            n = conn.execute(
                'SELECT COUNT(*) AS c FROM listrow WHERE file=?',
                (name,)).fetchone()['c']
            if n > cap:
                excess = n - cap
                old = conn.execute(
                    'SELECT id, doc FROM listrow WHERE file=? ORDER BY id LIMIT ?',
                    (name, excess)).fetchall()
                overflow = [json.loads(r['doc']) for r in old]
                conn.executemany('DELETE FROM listrow WHERE id=?',
                                [(r['id'],) for r in old])
        _touch(conn, name)
    return overflow


# ── presence / inventory / snapshot (the widened seam) ────────────────────────

def exists(path):
    """SQLite analogue of Path.exists() used as a 'is there data?' guard."""
    conn = _connect(_dir(path))
    kind = _classify(path)
    if kind == 'devices':
        return conn.execute(
            'SELECT 1 FROM devices LIMIT 1').fetchone() is not None
    if kind == 'entity':
        return conn.execute(
            'SELECT 1 FROM entity WHERE file=? LIMIT 1',
            (_name(path),)).fetchone() is not None
    if kind == 'wrapped':
        n = _name(path)
        if conn.execute('SELECT 1 FROM listrow WHERE file=? LIMIT 1',
                       (n,)).fetchone() is not None:
            return True
        return conn.execute('SELECT 1 FROM kv WHERE path=?',
                           (n + '#meta',)).fetchone() is not None
    return conn.execute('SELECT 1 FROM kv WHERE path=?',
                       (_name(path),)).fetchone() is not None


def iter_files(data_dir=None):
    """Logical filenames that currently hold data — drives backup/export in
    place of DATA_DIR.glob('*.json')."""
    conn = _connect(data_dir)
    names = set()
    for r in conn.execute('SELECT path FROM kv').fetchall():
        p = r['path']
        if p.endswith('#meta'):
            names.add(p[:-len('#meta')])
        else:
            names.add(p)
    for r in conn.execute('SELECT DISTINCT file FROM entity').fetchall():
        names.add(r['file'])
    for r in conn.execute('SELECT DISTINCT file FROM listrow').fetchall():
        names.add(r['file'])
    if conn.execute('SELECT 1 FROM devices LIMIT 1').fetchone() is not None:
        names.add(DEVICES_FILE_NAME)
    names -= _NON_STATE
    return sorted(names)


def doc_size(path):
    """Approximate serialized byte size of a logical document — for the
    self-status disk report, replacing per-file stat()."""
    conn = _connect(_dir(path))
    kind = _classify(path)
    if kind == 'devices':
        r = conn.execute(
            'SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM devices').fetchone()
        return int(r['b'])
    if kind == 'entity':
        r = conn.execute(
            'SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM entity WHERE file=?',
            (_name(path),)).fetchone()
        return int(r['b'])
    if kind == 'wrapped':
        r = conn.execute(
            'SELECT COALESCE(SUM(LENGTH(doc)),0) AS b FROM listrow WHERE file=?',
            (_name(path),)).fetchone()
        return int(r['b'])
    r = conn.execute('SELECT LENGTH(doc) AS b FROM kv WHERE path=?',
                    (_name(path),)).fetchone()
    return int(r['b']) if r else 0


def maintenance(data_dir=None, full=False):
    """Periodic upkeep for the database. Always truncates the WAL (which would
    otherwise grow unbounded between connection closes); when `full`, also
    VACUUMs (reclaims free pages) and runs an integrity_check. Returns a dict
    with what ran + the resulting db size and integrity verdict."""
    conn = _connect(data_dir)
    result = {}
    try:
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        result['checkpoint'] = True
    except sqlite3.Error as e:
        result['checkpoint_error'] = str(e)
    if full:
        try:
            conn.execute('VACUUM')   # must be outside a transaction (autocommit)
            result['vacuum'] = True
        except sqlite3.Error as e:
            result['vacuum_error'] = str(e)
        try:
            row = conn.execute('PRAGMA integrity_check').fetchone()
            result['integrity'] = row[0] if row else 'unknown'
        except sqlite3.Error as e:
            result['integrity'] = f'error: {e}'
    try:
        result['db_bytes'] = db_path(data_dir).stat().st_size
    except OSError:
        result['db_bytes'] = None
    return result


def snapshot(dest, data_dir=None):
    """Write a consistent copy of the database to `dest` (a file path). Uses
    sqlite's online backup so a live WAL DB is captured without tearing."""
    conn = _connect(data_dir)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    bck = sqlite3.connect(str(dest))
    try:
        conn.backup(bck)
    finally:
        bck.close()
    return dest


# ── migration core (JSON <-> SQLite) ─────────────────────────────────────────
#
# Shared by the in-app migrate endpoint (handle_storage_backend_migrate) and the
# tools/migrate_storage.py CLI. Reads/writes each backend through its own
# primitives so it never depends on which backend is currently "active". Lives
# here (not in tools/) so it ships with the server and the endpoint can import
# it directly.

MARKER_NAME = 'storage_backend.json'
_MIGRATE_SKIP_SUFFIXES = ('.bak', '.lock', '.db', '.db-wal', '.db-shm',
                          '.db-journal')


def json_inventory(data_dir):
    """Logical *.json data files present on disk (the JSON backend's view)."""
    out = []
    for p in sorted(Path(data_dir).glob('*.json')):
        if p.name in (MARKER_NAME,) or '.tmp.' in p.name:
            continue
        if any(p.name.endswith(s) for s in _MIGRATE_SKIP_SUFFIXES):
            continue
        out.append(p.name)
    return out


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _write_json_atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'{path.name}.tmp.{os.getpid()}')
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(str(tmp), str(path))
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def _norm(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)


def migration_snapshot(data_dir, label='premigrate'):
    """Tar the whole data dir to a rollback artifact, capturing any live DB via
    the online-backup snapshot (never the raw -wal). Returns its path."""
    import tarfile
    data_dir = Path(data_dir)
    backups = data_dir / 'backups'
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    ts = time.strftime('%Y%m%d_%H%M%S', time.localtime())
    out = backups / f'premigrate_{label}_{ts}.tar.gz'
    db = db_path(data_dir)
    live = {db.name, db.name + '-wal', db.name + '-shm', db.name + '-journal'}
    snap_tmp = None
    with tarfile.open(str(out), 'w:gz') as tar:
        def _filt(ti):
            bn = os.path.basename(ti.name)
            if bn == 'backups' or '.tmp.' in bn or bn in live:
                return None
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ''
            return ti
        tar.add(str(data_dir), arcname='remotepower', filter=_filt)
        if db.exists():
            snap_tmp = backups / f'.snap_{ts}.db'
            try:
                snapshot(snap_tmp, data_dir)
                tar.add(str(snap_tmp), arcname=f'remotepower/{db.name}')
            finally:
                try:
                    if snap_tmp and snap_tmp.exists():
                        snap_tmp.unlink()
                except OSError:
                    pass
    return out


def migrate_json_to_sqlite(data_dir, log=lambda m: None):
    data_dir = Path(data_dir)
    names = json_inventory(data_dir)
    close_connection()
    for name in names:
        # clamp_last_seen=False: reproduce stored timestamps faithfully.
        save(data_dir / name, _read_json(data_dir / name), clamp_last_seen=False)
        log(f"  json -> sqlite  {name}")
    return names


def migrate_sqlite_to_json(data_dir, log=lambda m: None):
    data_dir = Path(data_dir)
    close_connection()
    names = iter_files(data_dir)
    for name in names:
        _write_json_atomic(data_dir / name, load(data_dir / name))
        log(f"  sqlite -> json  {name}")
    return names


def verify_migration(data_dir, log=lambda m: None):
    """Compare the JSON-on-disk view against the SQLite reconstruction for every
    logical file. Returns (ok, [problem strings])."""
    data_dir = Path(data_dir)
    close_connection()
    names = set(json_inventory(data_dir)) | set(iter_files(data_dir))
    problems = []
    for name in sorted(names):
        jp = data_dir / name
        j = _read_json(jp) if jp.exists() else None
        s = load(jp) if exists(jp) else None
        if j is None and s is None:
            continue
        if j is None or s is None:
            problems.append(f"{name}: present in only one backend "
                            f"(json={j is not None}, sqlite={s is not None})")
            continue
        if _norm(j) != _norm(s):
            problems.append(f"{name}: content differs "
                            f"(json_len={len(j) if hasattr(j,'__len__') else '?'} "
                            f"sqlite_len={len(s) if hasattr(s,'__len__') else '?'})")
    ok = not problems
    log(f"verify: OK ({len(names)} files match)" if ok
        else f"verify: {len(problems)} mismatch(es)")
    return ok, problems


def write_marker(data_dir, backend):
    _write_json_atomic(Path(data_dir) / MARKER_NAME,
                       {'backend': backend, 'migrated_at': int(time.time())})


def read_marker(data_dir):
    p = Path(data_dir) / MARKER_NAME
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            pass
    return {}


def migrate_run(data_dir, target, dry_run=False, verify_only=False,
                do_snapshot=True, flip=True, log=lambda m: None):
    """One-call migration used by both the CLI and the migrate endpoint."""
    data_dir = Path(data_dir)
    if target not in ('json', 'sqlite'):
        raise ValueError("target must be 'json' or 'sqlite'")

    if verify_only:
        ok, problems = verify_migration(data_dir, log=log)
        return {'ok': ok, 'verified': True, 'problems': problems}

    if dry_run:
        names = (json_inventory(data_dir) if target == 'sqlite'
                 else iter_files(data_dir))
        log(f"dry-run: would migrate {len(names)} files to {target}")
        return {'ok': True, 'dry_run': True, 'files': names}

    net_fs = _is_network_fs(data_dir)

    snap = None
    if do_snapshot:
        snap = migration_snapshot(data_dir, label=f'to_{target}')
        log(f"snapshot: {snap}")

    if target == 'sqlite':
        t0 = time.time()
        names = migrate_json_to_sqlite(data_dir, log=log)
        # Catch-up passes: a live heartbeat can write a JSON file (the active
        # backend is still JSON until we flip) after we copied it. Re-migrate
        # any source file whose mtime advanced during the copy. Bounded — a
        # continuously-written file (devices.json on a busy fleet) shrinks to a
        # sub-second residual window rather than being fully frozen.
        for _ in range(3):
            changed = []
            for n in json_inventory(data_dir):
                try:
                    if (data_dir / n).stat().st_mtime >= t0:
                        changed.append(n)
                except OSError:
                    pass
            if not changed:
                break
            t0 = time.time()
            for n in changed:
                save(data_dir / n, _read_json(data_dir / n), clamp_last_seen=False)
            log(f"catch-up: re-migrated {len(changed)} file(s) "
                f"written during migration")
    else:
        names = migrate_sqlite_to_json(data_dir, log=log)
        # Reverse direction: SQLite is the active backend until the flip, so a
        # heartbeat may have updated a row after we read it. A second full pass
        # is cheap and idempotent and narrows the window.
        migrate_sqlite_to_json(data_dir, log=lambda m: None)

    ok, problems = verify_migration(data_dir, log=log)
    if not ok:
        return {'ok': False, 'snapshot': str(snap) if snap else None,
                'problems': problems,
                'error': 'verification failed — backend NOT switched'}

    if flip:
        write_marker(data_dir, target)
        log(f"marker: active backend is now '{target}'")

    result = {'ok': True, 'target': target, 'files': len(names),
              'snapshot': str(snap) if snap else None}
    if target == 'sqlite' and net_fs:
        result['warning'] = ('data directory appears to be on a network '
                             'filesystem (NFS/CIFS); SQLite WAL is unsafe there '
                             'and a rollback journal was used instead — '
                             'concurrency will be lower. A local disk is '
                             'strongly recommended.')
    return result
