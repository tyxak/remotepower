"""RemotePower — backup orchestration (data-dir DR + per-device jobs + Proxmox cache).

Bound-module decomposition of api.py (same pattern as tickets_handlers.py —
see its module docstring for the full rationale): every api service, and
every call BETWEEN these functions, resolves dynamically through the bound
``A`` namespace proxy so test monkeypatching of api attributes keeps
working; api.py execs a PRIVATE instance per api instance and binds its own
globals(); handler names are bound back into api's globals so the route
tables and all existing callers are untouched. Constants and routes stay in
api.py. Adding a feature here: edit this file; new routes go in api.py's
_PATTERN_ROUTE_DEFS / _build_exact_routes as usual.
"""
import os
import secrets
import shutil
import sys
import time


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once per api instance, with api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


def _backup_include(rel):
    """True if a data-dir-relative path belongs in a backup. Skips transient
    caches, lock/tmp artifacts, and the pre-restore snapshots themselves."""
    parts = rel.replace('\\', '/').split('/')
    if parts and parts[0] == A._BACKUP_SNAPSHOT_DIR:
        return False
    base = parts[-1]
    if base in A._BACKUP_EXCLUDE_NAMES:
        return False
    if base.endswith('.lock') or base.endswith('.tmp') or '.tmp.' in base:
        return False
    return True


def _backup_jobs_load():
    data = A.load(A.BACKUP_JOBS_FILE)
    if not isinstance(data, dict) or 'jobs' not in data:
        return {'jobs': []}
    return data


def _default_backup_dir():
    """`<data dir>/backups` — derived, never a hardcoded absolute path.

    v6.4.1 (SECURITY/correctness): the default used to be the literal
    '/var/lib/remotepower/backups'. A SECOND instance on the same host — the
    read-only demo, which runs its own gunicorn with RP_DATA_DIR=
    /var/lib/remotepower-demo — therefore wrote ITS backups into the
    PRODUCTION backup directory. Observed in the field as a small plaintext
    *.tar.gz appearing among the real encrypted archives: the demo's tiny data
    dir, unencrypted because that unit has no RP_BACKUP_PASSPHRASE.

    It was not only confusing. The two instances shared a directory, so each
    one's retention pruner deleted the other's archives; the restore drill
    picks the NEWEST archive and could therefore verify the demo's data while
    reporting on production; and production's posture page flagged "plaintext
    archives" because of the demo. Deriving from DATA_DIR keeps every instance
    in its own tree.
    """
    return str(A.DATA_DIR / 'backups')


def _sweep_stale_partials(p_base, max_age_s=6 * 3600):
    """Remove abandoned in-progress archives.

    A partial only exists if a previous run died mid-write (service restart
    during a deploy, OOM, an exception in the SQLite snapshot). It is plaintext
    by definition, so leaving it is exactly the leak the temp-name scheme
    exists to prevent. Age-gated so a CONCURRENT run's partial is never
    deleted out from under it.
    """
    now = time.time()
    for f in list(p_base.glob('.remotepower_data_*.partial')):
        try:
            if now - f.stat().st_mtime > max_age_s:
                f.unlink()
                sys.stderr.write(
                    f'[remotepower] removed abandoned partial backup {f.name} '
                    '(a previous run was interrupted before it completed)\n')
        except OSError:
            pass


def _backup_passphrase():
    """v5.0.0 (#C2): the DR-backup encryption passphrase, sourced ONLY from the
    `RP_BACKUP_PASSPHRASE` environment variable — never the config/data dir (the
    backup contains the data dir, so storing the key there would be circular).
    Empty/unset → backups stay plaintext (legacy behavior). v5.4.1 (C8): may also
    be sourced from an external command via RP_BACKUP_PASSPHRASE_CMD (Vault/KMS)."""
    return (A._secret_from_env('RP_BACKUP_PASSPHRASE') or '').strip()


def _maybe_run_scheduled_backup():
    """Daily scheduled backup. Called from the heartbeat hot path with
    a poll-rate gate so the check itself is cheap.

    Schedule: once per 24h, regardless of which agent's heartbeat triggers
    the check. State stored in self_backup_state.json so a restart of the
    server doesn't double-fire.
    """
    cfg = A.load(A.CONFIG_FILE) or {}
    if not (cfg.get('backup') or {}).get('enabled', True):
        return
    state_file = A.DATA_DIR / 'self_backup_state.json'
    # v5.0.0 CRITICAL: must use backend_exists, NOT Path.exists(). Under the
    # SQLite/Postgres backend self_backup_state.json is a DB row, not a file, so
    # Path.exists() is always False → the persisted last_run was never read → the
    # 24h gate never tripped → EVERY heartbeat ran a full backup (runaway, filled
    # the backup dir). The sibling _maybe_check_disk_space already does this right.
    state = A.load(state_file) if A.backend_exists(state_file) else {}
    last = state.get('last_run') or 0
    if int(time.time()) - last < 86400:
        return  # ran within the last 24h
    # Use a lock-file so two simultaneous heartbeats don't both run it
    sentinel = A.DATA_DIR / '.backup_in_progress'
    if sentinel.exists():
        # Stale lock recovery: if the sentinel is >1h old, assume the
        # previous attempt died and clear it.
        try:
            if time.time() - sentinel.stat().st_mtime < 3600:
                return
            sentinel.unlink()
        except OSError:
            return
    try:
        sentinel.write_text(str(os.getpid()))
        A._run_data_backup(triggered_by='scheduled')
    except Exception as e:
        sys.stderr.write(f'[remotepower] scheduled backup failed: {e}\n')
    finally:
        try: sentinel.unlink()
        except OSError: pass


def _refresh_proxmox_backup_cache(pc: dict) -> None:
    """v3.6.0: per-guest vzdump backup recency → PROXMOX_BACKUP_CACHE, so
    _compute_attention() can flag guests with stale / missing backups without a
    live Proxmox call. Opportunistic, like the snapshot cache. Covers BOTH
    guest types in one pass (backups aren't typed), so it only needs to run once
    per Virtualization page load."""
    now = int(time.time())
    # Names from both guest types (a backup archive only carries a vmid).
    names = {}
    nodes = set()
    for gt in ('qemu', 'lxc'):
        try:
            for g in A.proxmox_client.list_guests(pc, gt):
                if g.get('vmid'):
                    names[int(g['vmid'])] = g.get('name', str(g['vmid']))
                    if g.get('node'):
                        nodes.add(g['node'])
        except Exception:
            pass
    # Enumerate vzdump archives on every node a guest lives on (a cluster writes
    # backups to per-node local storage), not just the configured node, so
    # cross-node guests are not falsely flagged as having no backup. Node names
    # are already validated by the client, and the newest-ctime merge below
    # dedups any shared-storage archive seen from more than one node.
    # All-or-nothing: if ANY node's backup listing fails (transient API error,
    # member briefly unreachable), preserve the previous cache rather than
    # rebuilding it from a partial set -- a partial rebuild would write
    # age_days=None for guests on the failed node and fire false "no backup"
    # alerts. Matches the pre-cluster single-node abort-on-error behaviour.
    backups = []
    for node in (nodes or {pc['node']}):
        try:
            backups.extend(A.proxmox_client.list_backups({**pc, 'node': node}))
        except Exception:
            return  # leave the previous cache intact on any node failure
    newest = {}   # vmid -> newest ctime
    for b in backups:
        vid = b.get('vmid')
        if not vid:
            continue
        newest[vid] = max(newest.get(vid, 0), b.get('ctime', 0))
    guests = []
    for vmid, name in sorted(names.items()):
        ct = newest.get(vmid, 0)
        age_days = int((now - ct) / 86400) if ct else None
        guests.append({'vmid': vmid, 'name': name, 'age_days': age_days,
                       'last_backup': ct or None})
    A.save(A.PROXMOX_BACKUP_CACHE, {'updated_at': now, 'node': pc.get('node', ''),
                                'guests': guests})


def _run_data_backup(triggered_by='scheduled'):
    """Snapshot DATA_DIR to a tarball; prune old ones; record state.

    Excluded: the backup dir itself, .tmp.* in-flight writes, .gz archives
    (already compressed; their inclusion would double size for no value).
    """
    cfg = A.load(A.CONFIG_FILE) or {}
    bcfg = cfg.get('backup') or {}
    enabled = bcfg.get('enabled', True)
    if not enabled and triggered_by != 'manual':
        return {'skipped': True, 'reason': 'backup disabled in config'}
    base = bcfg.get('path') or _default_backup_dir()
    keep = int(bcfg.get('retain_days') or 14)
    p_base = A.Path(base)
    p_base.mkdir(parents=True, exist_ok=True, mode=0o700)
    import tarfile
    ts = time.strftime('%Y%m%d_%H%M%S', time.localtime())
    final_path = p_base / f'remotepower_data_{ts}.tar.gz'
    # v6.4.1 (SECURITY): build into a PRIVATE, non-final path, publish only when
    # complete. The tarball used to be written straight to its final name with
    # default umask perms (0644) and only encrypted afterwards, so:
    #   * a full plaintext copy of the whole data dir existed at the resting
    #     name for the duration of the run, world-readable, and
    #   * if the process died in that window — a deploy restarting the service,
    #     an OOM kill, an exception in the SQLite snapshot — a PARTIAL plaintext
    #     archive was left behind forever, retained by the pruner and counted as
    #     a backup. Observed in the field: a 192K 0644 *.tar.gz next to healthy
    #     4.6M 0600 *.tar.gz.enc files, written while a deploy restarted the app.
    # The temp name is deliberately outside both prune globs so a stale one can
    # never masquerade as an archive; _sweep_stale_partials() cleans them up.
    out_path = p_base / f'.remotepower_data_{ts}.{os.getpid()}.partial'
    _sweep_stale_partials(p_base)
    # kmip_master.key: NEVER in generic backups — it travels only in the
    # passphrase-encrypted KMIP recovery bundle, so a stolen backup archive
    # holds only ciphertext (mirrors A._BACKUP_EXCLUDE_NAMES on the
    # download-path filter).
    # restore-snapshots/ joined this list at v6.4.1. The walk's filter drops
    # `bn.endswith('.gz')`, which used to exclude pre-restore-*.tar.gz by
    # accident — encrypting them to *.enc removed that accident, so every DR
    # archive started embedding a FULL data-dir image per past restore, and
    # they compound (two restores → the next backup carries both).
    # _write_data_dir_tar already skips this directory; match it.
    excluded_names = {'backups', 'kmip_master.key', A._BACKUP_SNAPSHOT_DIR}
    # v3.12.0: under SQLite, never tar the live DB or its WAL sidecars — a
    # mid-checkpoint copy can be torn/unrecoverable. We exclude them here and
    # add a consistent online-backup snapshot below instead.
    sqlite_mode = A._storage_backend() == 'sqlite'
    live_db_names = set()
    if sqlite_mode:
        _dbn = A.storage.db_path(A.DATA_DIR).name
        live_db_names = {_dbn, _dbn + '-wal', _dbn + '-shm', _dbn + '-journal'}
    def _filter(tarinfo):
        # Skip the backups dir, in-flight tmp files, and already-compressed
        # archive files (re-compressing wastes time).
        bn = os.path.basename(tarinfo.name)
        if bn in excluded_names: return None
        if '.tmp.' in bn: return None
        if bn.endswith('.gz'): return None
        if bn in live_db_names: return None
        # Drop owner/group info so restoring on a different host doesn't
        # complain about missing uids
        tarinfo.uid = 0; tarinfo.gid = 0
        tarinfo.uname = ''; tarinfo.gname = ''
        return tarinfo
    _snap_tmp = None
    skipped_unreadable = []
    # 0600 from creation — never rely on the directory mode alone, and never
    # leave a readable window even before the encrypt step.
    _fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(_fd, 'wb') as _raw, tarfile.open(fileobj=_raw, mode='w:gz') as tar:
        # v6.2.2: add entries one by one instead of one recursive tar.add — a
        # single unreadable file used to abort the WHOLE backup with
        # PermissionError, and the daily gate then retried (and failed) on
        # every sweep, forever. Live case: a host running BOTH the server and
        # an agent shares /var/lib/remotepower, and the agent's root-owned
        # 0600 state files (secrets_scan_last, …) are unreadable to the
        # server. A DR backup must degrade (skip + warn), never vanish.
        _base_dir = str(A.DATA_DIR)
        for _root, _dirs, _files in os.walk(_base_dir):
            _dirs[:] = [d for d in _dirs if d not in excluded_names]
            for _name in sorted(_dirs) + sorted(_files):
                _full = os.path.join(_root, _name)
                _arc = 'remotepower/' + os.path.relpath(_full, _base_dir)
                try:
                    tar.add(_full, arcname=_arc, filter=_filter,
                            recursive=False)
                except (PermissionError, OSError):
                    skipped_unreadable.append(os.path.relpath(_full, _base_dir))
        if sqlite_mode:
            # Consistent snapshot of the database into the tarball.
            _snap_tmp = p_base / f'.snap_{ts}_{os.getpid()}.db'
            try:
                A.storage.snapshot(_snap_tmp, A.DATA_DIR)
                tar.add(str(_snap_tmp),
                        arcname=f'remotepower/{A.storage.db_path(A.DATA_DIR).name}')
            finally:
                try:
                    if _snap_tmp and _snap_tmp.exists():
                        _snap_tmp.unlink()
                except OSError:
                    pass
        # v6.4.2: export the logical stores for ANY database backend. Under
        # SQLite this rides alongside the .db snapshot (belt and braces, and it
        # makes the archive restorable onto a JSON install); under Postgres —
        # the install-server.sh default — it is the ONLY copy of the state,
        # because nothing the walk above can see holds it.
        _stores = A._tar_add_logical_stores(tar, 'remotepower/')
    # v5.0.0 (#C2): encrypt at rest if RP_BACKUP_PASSPHRASE is set. The plaintext
    # tarball is replaced by `*.tar.gz.enc` (AES-256-GCM, streamed) and unlinked,
    # so nothing readable lingers in backup_path. The passphrase lives ONLY in the
    # environment — never in the data dir the backup contains.
    encrypted = False
    passphrase = A._backup_passphrase()
    if passphrase:
        if not A.backup_crypto.available():
            # Don't silently ship plaintext when the operator asked for crypto.
            try:
                out_path.unlink()
            except OSError:
                pass
            raise RuntimeError("RP_BACKUP_PASSPHRASE is set but the 'cryptography' "
                               "library is missing — refusing to write a plaintext backup")
        enc_path = final_path.with_suffix(final_path.suffix + '.enc')
        try:
            A.backup_crypto.encrypt_file(out_path, enc_path, passphrase)
        finally:
            # The plaintext working copy goes even if encryption raised — a
            # failed run must not leave readable data behind.
            try:
                out_path.unlink()
            except OSError:
                pass
        out_path = enc_path
        encrypted = True
    else:
        # No passphrase: publish the completed archive under its real name.
        # os.replace is atomic, so a plaintext archive that EXISTS is always a
        # COMPLETE one — never a truncated leftover.
        os.replace(str(out_path), str(final_path))
        out_path = final_path
        # v6.3.0: a scheduled backup written without RP_BACKUP_PASSPHRASE is
        # plaintext at rest — and the archive contains the whole data dir
        # (session tokens, hashed passwords, config secrets, the CMDB vault
        # blob). This used to be entirely silent, so plaintext DR archives
        # accumulated unnoticed. Warn on every scheduled write; the operator
        # sees it in the journal + the self-status page flags plaintext_archives,
        # and "Encrypt existing backups" remediates what's already on disk.
        sys.stderr.write(
            f'[remotepower] WARNING: scheduled backup written UNENCRYPTED at '
            f'rest ({out_path.name}) — RP_BACKUP_PASSPHRASE is not set, so the '
            f'archive holds tokens/secrets in plaintext. Set RP_BACKUP_PASSPHRASE '
            f'(or RP_BACKUP_PASSPHRASE_CMD) to encrypt new snapshots, and use '
            f'"Encrypt existing backups" for archives already on disk.\n')
    # Prune — retain BOTH plaintext and encrypted archives (a fleet may have a mix
    # across a passphrase change).
    cutoff = time.time() - keep * 86400
    pruned = 0
    for pat in ('remotepower_data_*.tar.gz', 'remotepower_data_*.tar.gz.enc'):
        for f in p_base.glob(pat):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink(); pruned += 1
            except OSError:
                pass
    # v5.4.1 (G1): mirror the finished archive to an offsite destination — a path,
    # typically an NFS/SMB/sshfs mount to OFF-host storage, so a host loss doesn't
    # take the backups with it. Best-effort: a copy failure NEVER fails the backup;
    # the result is recorded in state + graded on the posture page. The same
    # retention prunes the offsite copies.
    offsite = (bcfg.get('offsite_dir') or '').strip()
    offsite_ok = None
    if offsite:
        try:
            od = A.Path(offsite)
            od.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(str(out_path), str(od / out_path.name))
            for pat in ('remotepower_data_*.tar.gz', 'remotepower_data_*.tar.gz.enc'):
                for f in od.glob(pat):
                    try:
                        if f.stat().st_mtime < cutoff:
                            f.unlink()
                    except OSError:
                        pass
            offsite_ok = True
        except Exception as e:
            offsite_ok = False
            sys.stderr.write(f'[remotepower] offsite backup copy failed: {e}\n')
    if skipped_unreadable:
        sys.stderr.write(
            f"[remotepower] backup: skipped {len(skipped_unreadable)} "
            f"unreadable path(s): {', '.join(skipped_unreadable[:5])}"
            f"{' …' if len(skipped_unreadable) > 5 else ''} — the archive was "
            "still written; fix the permissions if these files matter\n")
    state = {
        'last_run':    int(time.time()),
        'last_file':   str(out_path),
        'last_bytes':  out_path.stat().st_size,
        'triggered_by': triggered_by,
        'encrypted':   encrypted,
        'pruned':      pruned,
        'retain_days': keep,
        'offsite_dir': offsite,
        'offsite_ok':  offsite_ok,
        # v6.2.2: visible on the posture/self page — a backup that silently
        # skipped paths must say so, not present itself as complete.
        'skipped_unreadable': skipped_unreadable[:50],
        # v6.4.2: how many logical stores the archive actually carries. On a DB
        # backend this is the state; 0 there means the archive is hollow and the
        # operator needs to know BEFORE they need the restore.
        'stores': _stores,
    }
    A.save(A.DATA_DIR / 'self_backup_state.json', state)
    return {'ok': True, 'file': str(out_path), 'encrypted': encrypted,
            'bytes': out_path.stat().st_size, 'pruned': pruned,
            'offsite_ok': offsite_ok, 'stores': _stores,
            'skipped_unreadable': len(skipped_unreadable)}


def handle_backup_clear():
    """DELETE /api/self/backup-state — delete all backup archives + reset state."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'}); return
    cfg = A.load(A.CONFIG_FILE) or {}
    bcfg = cfg.get('backup') or {}
    base = bcfg.get('path') or _default_backup_dir()
    p_base = A.Path(base)
    deleted = 0
    if p_base.exists():
        # Both plaintext (*.tar.gz) AND encrypted (*.tar.gz.enc) archives — the
        # glob `*.tar.gz` does NOT match `*.tar.gz.enc`, so clearing an
        # encryption-armed instance used to leave every archive behind. Mirror
        # the retention pruner, which iterates both patterns.
        for pat in ('remotepower_data_*.tar.gz', 'remotepower_data_*.tar.gz.enc'):
            for f in p_base.glob(pat):
                try:
                    f.unlink()
                    deleted += 1
                except OSError:
                    pass
    # v5.0.0: reset the backup state for BOTH backends. Under SQLite/Postgres it's
    # a DB row (no file to unlink), so save({}) clears it; also drop the JSON-backend
    # file if one is present. (The old code only unlink()ed, so a DB-backed instance
    # kept its stale last_run.)
    bs_file = A.DATA_DIR / 'self_backup_state.json'
    if A.backend_exists(bs_file):
        try: A.save(bs_file, {})
        except Exception: pass
    try:
        if bs_file.exists(): bs_file.unlink()
    except OSError: pass
    A.audit_log(actor, 'backup_clear', detail=f'deleted={deleted} path={base}')
    A.respond(200, {'ok': True, 'deleted': deleted})


def handle_backup_download():
    """GET /api/backup/download — stream a gzip tarball of the whole data dir.
    Admin only. This is the controller's disaster-recovery snapshot."""
    actor = A.require_admin_auth()
    import tarfile
    stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    fname = f'remotepower-backup-{stamp}.tar.gz'
    A.audit_log(actor, 'backup_download', fname)
    print("Status: 200 OK")
    print("Content-Type: application/gzip")
    print(f'Content-Disposition: attachment; filename="{fname}"')
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    tar = tarfile.open(mode='w:gz', fileobj=sys.stdout.buffer)
    try:
        A._write_data_dir_tar(tar)
    finally:
        tar.close()
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_backup_encrypt_existing():
    """v5.0.0: POST /api/self/backup-encrypt — migrate existing PLAINTEXT backup
    archives to encrypted (AES-256-GCM) using an admin-supplied passphrase.

    The passphrase is used for THIS request only and is never persisted (same
    philosophy as the env-var path — the thing the backup protects must not store
    the key). Each `remotepower_data_*.tar.gz` is encrypted to `*.tar.gz.enc`,
    the result is verified decryptable, then the plaintext is removed. For ONGOING
    scheduled backups, set `RP_BACKUP_PASSPHRASE` so new snapshots are encrypted
    at write time — this endpoint only converts the archives already on disk."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    if not A.backup_crypto.available():
        A.respond(400, {'error': "the 'cryptography' library is not installed"}); return
    passphrase = str(A.get_json_obj().get('passphrase') or '')
    if len(passphrase) < 8:
        A.respond(400, {'error': 'passphrase must be at least 8 characters'}); return
    bcfg = (A.load(A.CONFIG_FILE) or {}).get('backup') or {}
    bdir = A.Path(bcfg.get('path') or _default_backup_dir())
    encrypted = failed = 0
    import tempfile as _tf
    for f in sorted(bdir.glob('remotepower_data_*.tar.gz')):
        if f.name.endswith('.enc') or '.tmp.' in f.name:
            continue
        enc = f.with_suffix(f.suffix + '.enc')
        try:
            A.backup_crypto.encrypt_file(f, enc, passphrase)
            # verify it round-trips before deleting the plaintext
            with _tf.NamedTemporaryFile(dir=str(bdir), delete=False,
                                        prefix='.verify_', suffix='.tmp') as _vt:
                _vpath = A.Path(_vt.name)
            try:
                A.backup_crypto.decrypt_file(enc, _vpath, passphrase)
            finally:
                try:
                    _vpath.unlink()
                except OSError:
                    pass
            f.unlink()
            encrypted += 1
        except Exception:
            failed += 1
            try:
                if enc.exists():
                    enc.unlink()
            except OSError:
                pass
    A.audit_log(actor, 'backup_encrypt_existing',
              detail=f'encrypted={encrypted} failed={failed}')
    A.respond(200, {'ok': True, 'encrypted': encrypted, 'failed': failed})


def handle_backup_job_create():
    """POST /api/backup-jobs — define a backup job (admin)."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    name = A._sanitize_str(body.get('name', ''), 80).strip()
    cron = A._sanitize_str(body.get('cron', ''), 64).strip()
    # v6.3.0: a job is EITHER a raw command (legacy default) OR a structured
    # 'file' backup (paths[] + method + dest ssh/nfs/smb). For a file job the
    # server GENERATES the command at run time from the validated spec, so the
    # operator never supplies shell text.
    jtype = 'file' if body.get('spec') is not None or body.get('type') == 'file' else 'command'
    command = str(body.get('command', '')).strip()
    spec = None
    if jtype == 'file':
        spec = body.get('spec')
        ok, err = A.filebackup_mod.validate_spec(spec)
        if not ok:
            A.respond(400, {'error': f'invalid file-backup spec: {err}'})
    else:
        if not command:
            A.respond(400, {'error': 'name and command are required'})
        if len(command) > A.MAX_BACKUP_CMD_LEN:
            A.respond(400, {'error': f'command too long (max {A.MAX_BACKUP_CMD_LEN})'})
    if not name:
        A.respond(400, {'error': 'name is required'})
    # v6.3.0 "baseline": a job can target MULTIPLE devices — define once, apply to
    # many. _resolve_targets reads device_ids / tag / group / device_id AND
    # tenant/scope-filters the set at the same chokepoint the command family uses
    # (so a cross-tenant id can't be assigned). Keep only ids that name a real
    # device the caller may manage.
    devices = A.load(A.DEVICES_FILE)
    targets = [d for d in A._resolve_targets(body) if d in devices]
    if not targets:
        A.respond(400, {'error': 'select at least one device you can manage'})
    # v6.4.2: structured FILE jobs are POSIX-only — `filebackup._is_abs_path`
    # rejects any path not starting with '/' and the generated command is
    # rsync/tar over ssh. A Windows or macOS host could be picked from the same
    # device picker as everything else, got a success toast, and then failed
    # silently on every cron tick (the success-toast-then-silence class). Split
    # the batch honestly, the way SCAP already does.
    os_skipped = []
    if jtype == 'file':
        targets, os_skipped = A._split_targets_by_os_support(
            targets, supported=('linux',))
        if not targets:
            A.respond(400, {'error': 'file-backup jobs run on Linux hosts only — '
                            f'{len(os_skipped)} target(s) skipped '
                            f'({", ".join(os_skipped[:5])}). Use a command job '
                            'with a platform-native tool for these hosts.'})
    if cron and not A._valid_cron(cron):
        A.respond(400, {'error': 'invalid cron expression'})
    data = A._backup_jobs_load()
    if len(data['jobs']) >= A.MAX_BACKUP_JOBS:
        A.respond(400, {'error': f'job limit reached (max {A.MAX_BACKUP_JOBS})'})
    job = {'id': secrets.token_urlsafe(8), 'name': name,
           'device_ids': targets,
           'device_id': targets[0],   # legacy field = first target (old readers)
           'device_name': _backup_targets_summary(targets, devices),
           'type': jtype, 'command': command, 'spec': spec,
           'cron': cron or None, 'enabled': True, 'created': int(time.time()),
           'created_by': actor, 'last_run': 0, 'last_fired_minute': int(time.time()) // 60 - 1}
    data['jobs'].append(job)
    A.save(A.BACKUP_JOBS_FILE, data)
    A.audit_log(actor, 'backup_job_create',
                detail=f'job={job["id"]} devices={len(targets)} type={jtype}')
    A.respond(200, {'ok': True, 'id': job['id'],
                    'skipped_unsupported': os_skipped,
                    'note': (f'{len(os_skipped)} non-Linux host(s) were left out of '
                             f'this file job: {", ".join(os_skipped[:5])}'
                             if os_skipped else '')})


def _backup_targets_summary(target_ids, devices):
    """A short display label for a job's device set: 'host1' or 'host1 +2 more'."""
    names = [devices.get(d, {}).get('name', d) for d in target_ids]
    if not names:
        return ''
    if len(names) == 1:
        return names[0]
    return f'{names[0]} +{len(names) - 1} more'


def _backup_job_targets(job):
    """The device ids a job applies to — the v6.3.0 device_ids list, or the
    legacy single device_id. Always a list."""
    ids = job.get('device_ids')
    if isinstance(ids, list) and ids:
        return [str(d) for d in ids]
    d = job.get('device_id')
    return [str(d)] if d else []


def _backup_job_visible(job):
    """v6.3.0 SECURITY: a backup job is device-keyed (device_ids), so — like the
    alerts store (v6.1.1) — list/update/delete must tenant/scope-gate it, not just
    RBAC. The /api/backup-jobs routes are NOT under /api/devices/<id>/, so main()'s
    _enforce_device_scope never covers them. A job is visible only if every one of
    its KNOWN target devices is in the caller's scope (role scope AND tenant, via
    _scope_filter_devices — a no-op for a superadmin / non-tenant admin). A job
    whose targets were all deleted is manageable only by a fully-unrestricted
    caller. run/restore/archives already re-filter via _resolve_targets /
    _scope_block_device; this closes list/update/delete."""
    devs = A.load(A.DEVICES_FILE) or {}
    allowed = A._scope_filter_devices(devs)
    known = [t for t in _backup_job_targets(job) if t in devs]
    if known:
        return all(t in allowed for t in known)
    return len(allowed) == len(devs)   # all-deleted targets → only an unrestricted caller


def _backup_job_status(job):
    """v6.3.0 (UX): derive a job's last-run OUTCOME so the table can show ✓/✗/
    running, not just a timestamp. Correlates by the (deterministic) generated
    command: the agent echoes the queued command back with its exit code into
    CMD_OUTPUT_FILE, and a queued-but-unreported command means it's still running.
    A stored command is a truncated prefix of the generated one, so we match on
    prefix equality (distinguishes same-paths-different-host jobs).

    Returns {state, ts, rc, per_device}. state ∈ ok|failed|running|never|unknown."""
    try:
        cmd = _backup_job_command(job)
    except ValueError:
        return {'state': 'unknown'}
    if not cmd:
        return {'state': 'unknown'}
    targets = _backup_job_targets(job)
    per, newest_ts, worst_rc, running = {}, 0, None, False
    for dev in targets:
        queued = A._entity_read_one(A.CMDS_FILE, dev, []) or []
        if any(isinstance(q, str) and q.startswith('exec:') and cmd[:120] == q[5:5 + 120]
               for q in queued):
            per[dev] = 'running'; running = True; continue
        outs = A._entity_read_one(A.CMD_OUTPUT_FILE, dev, []) or []
        hit = None
        for o in reversed(outs):          # newest first
            oc = str(o.get('cmd') or '')
            oc = oc[5:] if oc.startswith('exec:') else oc
            if len(oc) >= 20 and cmd[:len(oc)] == oc:
                hit = o; break
        if hit is None:
            per[dev] = 'never'
        else:
            rc = hit.get('rc', -1)
            per[dev] = 'ok' if rc == 0 else 'failed'
            newest_ts = max(newest_ts, int(hit.get('ts', 0) or 0))
            if rc != 0:
                worst_rc = rc
    states = set(per.values())
    if running:
        state = 'running'
    elif 'failed' in states:
        state = 'failed'
    elif 'ok' in states:
        state = 'ok'
    elif states in (set(), {'never'}):
        state = 'never'
    else:
        state = 'unknown'
    # v6.3.0: the command is popped off the queue when dispatched, BEFORE the
    # (often multi-minute) backup finishes — during that window it's neither
    # queued nor yet in the output, so the loop reports 'never'. If the job was
    # dispatched recently and has no fresher result, it's actually running.
    last_run = int(job.get('last_run') or 0)
    if state == 'never' and last_run and (int(time.time()) - last_run) < 900 and last_run > newest_ts:
        state = 'running'
    return {'state': state, 'ts': newest_ts, 'rc': worst_rc, 'per_device': per}


def handle_backup_job_delete(job_id):
    """DELETE /api/backup-jobs/{id} (admin)."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    data = A._backup_jobs_load()
    job = next((j for j in data['jobs'] if j['id'] == job_id), None)
    if not job or not _backup_job_visible(job):
        A.respond(404, {'error': 'job not found'})   # 404, not 403 — don't confirm cross-tenant existence
    data['jobs'] = [j for j in data['jobs'] if j['id'] != job_id]
    A.save(A.BACKUP_JOBS_FILE, data)
    A.audit_log(actor, 'backup_job_delete', detail=f'job={job_id}')
    A.respond(200, {'ok': True})


def _backup_job_command(job):
    """The shell command a job runs: the raw `command` for a legacy job, or the
    server-generated command for a structured 'file' job (validated at run time,
    so a spec edited out-of-band can never produce an unsafe command). Raises
    ValueError for an invalid file spec — callers decide how to surface it
    (respond for a request, skip+log for the cron sweep).

    v6.3.0: prefix a `: rp-bk:<job_id>;` shell no-op that carries the JOB ID. It
    runs as a no-op on the host but is echoed back verbatim in the command result,
    so _backup_job_status can tell TWO jobs with byte-identical commands apart
    (e.g. a baseline split across device sets, same paths + same dest). The job id
    is a URL-safe token (no shell metacharacters), so the prefix is injection-safe.
    Both the run/cron path and the status read call this, so they stay in sync."""
    if job.get('type') == 'file' and job.get('spec') is not None:
        ok, err = A.filebackup_mod.validate_spec(job['spec'])
        if not ok:
            raise ValueError(f'file-backup spec invalid: {err}')
        base = A.filebackup_mod.build_backup_command(job['spec'], job['id'])
    else:
        base = job.get('command') or ''
    if not base:
        return ''
    return f': rp-bk:{job["id"]}; {base}'


def _backup_wait_timeout(dev):
    """How long to run-and-wait for a device's backup/list output. The round-trip
    is ~2 heartbeats (dispatch on one, result on the next), so derive it from the
    device's poll interval. Returns 0 to SKIP the wait entirely when the host polls
    too slowly for a synchronous wait to be meaningful — otherwise the wait always
    timed out (the v6.3.0 'run-and-wait dead on slow pollers' bug)."""
    try:
        interval = int(dev.get('poll_interval') or 60)
    except (TypeError, ValueError):
        interval = 60
    if interval > 80:
        return 0
    return min(180, 2 * interval + 20)


def _backup_queue_and_wait(dev_id, cmd, actor, dev_name, label, timeout=120):
    """Queue a server-generated backup command on ONE device via the longpoll slot
    and block for its output. Returns (status, output_dict) — 'ok' | 'timeout' |
    'shutdown'. Shared by run-and-wait feedback AND the archive-list step."""
    lp = A.load(A.LONGPOLL_FILE)
    lp[dev_id] = {'cmd': cmd, 'ready': False, 'output': None, 'ts': int(time.time())}
    A.save(A.LONGPOLL_FILE, lp)
    cmds = A.load(A.CMDS_FILE)
    cmds.setdefault(dev_id, [])
    _q = f'exec:{cmd}'
    if _q not in cmds[dev_id]:
        cmds[dev_id].append(_q)
    A.save(A.CMDS_FILE, cmds)
    A.log_command(actor, dev_id, dev_name, label)
    return A._longpoll_wait(dev_id, timeout)


def _backup_run_and_wait(dev_id, cmd, actor, dev_name, timeout=120):
    """Run-and-wait a backup on ONE device so the UI can show live feedback.
    The command is server-generated + admin-gated (bypasses the operator exec
    allowlist). Responds 200 with the captured output, or a graceful 'still
    running' when a long backup outlasts the timeout."""
    status, output = _backup_queue_and_wait(dev_id, cmd, actor, dev_name,
                                            'backup(run-and-wait)', timeout)
    if status == 'ok':
        A.respond(200, {'ok': True, 'output': output})
    elif status == 'shutdown':
        A.respond(503, {'ok': False, 'message': 'Server restarting — the backup is queued; check the device command history.'})
    else:
        A.respond(200, {'ok': True, 'running': True,
                        'message': 'Backup is taking longer than the wait window — it keeps running; output appears in the device command history.'})


def handle_backup_job_run(job_id):
    """POST /api/backup-jobs/{id}/run — run the backup now on all of the job's
    devices. Body: {wait?} — with a single target, wait for output (live feedback);
    with multiple, queue on all and return the count."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    data = A._backup_jobs_load()
    job = next((j for j in data['jobs'] if j['id'] == job_id), None)
    if not job:
        A.respond(404, {'error': 'job not found'})
    # v6.3.0 baseline: fan out to every device the job targets, re-filtered to the
    # caller's scope/tenant at run time (device set can change after creation).
    targets = [d for d in A._resolve_targets({'device_ids': _backup_job_targets(job)})]
    if not targets:
        A.respond(400, {'error': 'no devices you can manage are targeted by this job'})
    # v6.4.3: filter at DISPATCH, not only at create/update. The OS gate added
    # earlier in this release sits on the two WRITE paths — so a job that
    # ALREADY held a Windows or macOS target (created before the gate, or whose
    # device changed platform) kept firing a bash rsync at it on every run,
    # forever, with nothing reporting the mismatch. Gating the write path and
    # not the dispatch path is a gate that only stops NEW instances of a bug it
    # leaves running.
    targets, _os_skipped = A._split_targets_by_os_support(targets)
    if not targets:
        A.respond(400, {
            'error': 'structured file-backup jobs run on Linux hosts only',
            'skipped': _os_skipped})
    actor = A.require_perm('command', targets)
    try:
        cmd = _backup_job_command(job)
    except ValueError as e:
        A.respond(400, {'error': str(e)}); return
    if not cmd:
        A.respond(400, {'error': 'job has no command'})
    job['last_run'] = int(time.time())
    A.save(A.BACKUP_JOBS_FILE, data)
    A.audit_log(actor, 'backup_job_run', detail=f'job={job_id} devices={len(targets)}')
    body = A.get_json_obj()
    devices = A.load(A.DEVICES_FILE)
    if body.get('wait') and len(targets) == 1:
        dev = devices.get(targets[0], {})
        tmo = _backup_wait_timeout(dev)
        if tmo:
            _backup_run_and_wait(targets[0], cmd, actor,
                                 dev.get('name', targets[0]), timeout=tmo)  # responds
            return
        # Host polls too slowly to wait synchronously — queue and let the output
        # land in the command history (avoids a dead 120s wait that always times out).
        A._queue_command_batch(targets, f'exec:{cmd}', actor)
        A.respond(200, {'ok': True, 'queued': 1, 'running': True,
                        'message': 'Backup queued — this host polls slowly, so its output will appear in the command history.'})
        return
    res = A._queue_command_batch(targets, f'exec:{cmd}', actor)
    # Count only devices actually queued (batch skips quarantined / audit-mode / unknown).
    n = sum(1 for r in res.values() if isinstance(r, dict) and r.get('ok')) if isinstance(res, dict) else len(targets)
    A.respond(200, {'ok': True, 'queued': n})


def handle_backup_job_archives(job_id):
    """POST /api/backup-jobs/{id}/archives — list this tar job's archives at the
    destination (run-and-wait), so Restore can offer a pick-list instead of asking
    the operator to type a filename. Body: {device_id?}. Admin + tenant-gated."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    data = A._backup_jobs_load()
    job = next((j for j in data['jobs'] if j['id'] == job_id), None)
    if not job:
        A.respond(404, {'error': 'job not found'})
    if job.get('type') != 'file' or job.get('spec') is None:
        A.respond(400, {'error': 'archives are only listed for file-backup jobs'})
    if (job['spec'].get('method') != 'tar'):
        # rsync jobs are a synced tree, not per-run archives — restore pulls the latest.
        A.respond(200, {'ok': True, 'archives': [],
                        'note': 'rsync jobs restore the latest synced copy — no archive to pick'})
    body = A.get_json_obj()
    targets = _backup_job_targets(job)
    dev_id = str(body.get('device_id', '')).strip() or (targets[0] if len(targets) == 1 else '')
    if not dev_id:
        A.respond(400, {'error': 'this job targets multiple devices — specify device_id'})
    if dev_id not in targets:
        A.respond(400, {'error': 'device is not one of this job\'s targets'})
    A._scope_block_device(dev_id)
    ok, err = A.filebackup_mod.validate_spec(job['spec'])
    if not ok:
        A.respond(400, {'error': f'file-backup spec no longer valid: {err}'})
    cmd = A.filebackup_mod.build_list_command(job['spec'], job['id'])
    devices = A.load(A.DEVICES_FILE)
    dev = devices.get(dev_id, {})
    tmo = _backup_wait_timeout(dev)   # poll-interval-aware; 0 = too slow to wait
    if not tmo:
        A._queue_command_batch([dev_id], f'exec:{cmd}', actor)
        A.respond(200, {'ok': True, 'archives': [], 'pending': True,
                        'message': 'This host polls slowly — the archive list is queued; try again shortly, or type the archive name.'})
    status, output = _backup_queue_and_wait(dev_id, cmd, actor,
                                            dev.get('name', dev_id),
                                            'backup(list-archives)', timeout=tmo)
    if status != 'ok':
        A.respond(200, {'ok': True, 'archives': [], 'pending': True,
                        'message': 'The host has not reported yet — try again in a moment, or type the archive name.'})
    raw = ''
    if isinstance(output, dict):
        raw = str(output.get('output') or output.get('stdout') or '')
    # Parse filenames, keep only well-formed archive names for THIS job.
    names = []
    for ln in raw.splitlines():
        n = ln.strip()
        if n and n.startswith(job['id'] + '-') and n.endswith('.tar.gz') and len(n) < 200 \
                and all(c.isalnum() or c in '._-' for c in n):
            names.append(n)
    A.respond(200, {'ok': True, 'archives': names[:200]})


def handle_backup_job_restore(job_id):
    """POST /api/backup-jobs/{id}/restore — pull a structured file-backup back to
    the host. Destructive (overwrites the restore target), so: admin-only, a
    typed confirmation, and fully audited. Body: {restore_path, confirm, archive?}."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    data = A._backup_jobs_load()
    job = next((j for j in data['jobs'] if j['id'] == job_id), None)
    if not job:
        A.respond(404, {'error': 'job not found'})
    if job.get('type') != 'file' or job.get('spec') is None:
        A.respond(400, {'error': 'restore is only available for structured file-backup jobs'})
    body = A.get_json_obj()
    # v6.3.0 baseline: a job can target several devices — restore goes to ONE
    # host (you restore TO a specific machine). Pick it from the body; default to
    # the sole target when there's only one. Must be a device the caller manages.
    job_targets = _backup_job_targets(job)
    dev_id = str(body.get('device_id', '')).strip() or (job_targets[0] if len(job_targets) == 1 else '')
    if not dev_id:
        A.respond(400, {'error': 'this job targets multiple devices — specify device_id to restore to'})
    if dev_id not in job_targets:
        A.respond(400, {'error': 'device is not one of this job\'s targets'})
    A._scope_block_device(dev_id)   # tenant + role scope for the chosen host
    if str(body.get('confirm', '')).strip().upper() != 'RESTORE':
        A.respond(400, {'error': 'type RESTORE to confirm — this overwrites the restore path'})
    restore_path = str(body.get('restore_path', '')).strip()
    archive = A._sanitize_str(body.get('archive', ''), 128).strip() or None
    ok, err = A.filebackup_mod.validate_spec(job['spec'])
    if not ok:
        A.respond(400, {'error': f'file-backup spec no longer valid: {err}'})
    try:
        cmd = A.filebackup_mod.build_restore_command(job['spec'], restore_path, job['id'], archive)
    except ValueError as e:
        A.respond(400, {'error': str(e)})
        return
    A.audit_log(actor, 'backup_job_restore',
                detail=f'job={job_id} device={dev_id} target={restore_path}')
    A._queue_command(dev_id, f'exec:{cmd}', actor)  # responds + exits


def handle_backup_job_update(job_id):
    """PUT /api/backup-jobs/{id} — edit a backup job (admin)."""
    actor = A.require_admin_auth()
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    data = A._backup_jobs_load()
    job = next((j for j in data['jobs'] if j['id'] == job_id), None)
    if not job or not _backup_job_visible(job):
        # SECURITY: without the visibility gate a tenant admin could edit another
        # tenant's job's command/spec/cron (leaving its device_ids intact) → the
        # cron sweep then runs it as root on the victim's hosts. 404, not 403.
        A.respond(404, {'error': 'job not found'})
    if 'name' in body:
        job['name'] = A._sanitize_str(body['name'], 80).strip() or job['name']
    if 'command' in body:
        c = str(body['command']).strip()
        if not c or len(c) > A.MAX_BACKUP_CMD_LEN:
            A.respond(400, {'error': 'invalid command'})
        job['command'] = c
    if 'spec' in body and body['spec'] is not None:
        ok, err = A.filebackup_mod.validate_spec(body['spec'])
        if not ok:
            A.respond(400, {'error': f'invalid file-backup spec: {err}'})
        job['spec'] = body['spec']
        job['type'] = 'file'
    os_skipped = []
    devices = None
    if 'device_ids' in body or 'device_id' in body:
        # v6.3.0 baseline: re-target the job (tenant/scope-filtered).
        devices = A.load(A.DEVICES_FILE)
        targets = [d for d in A._resolve_targets(body) if d in devices]
        if not targets:
            A.respond(400, {'error': 'select at least one device you can manage'})
        job['device_ids'] = targets
        job['device_id'] = targets[0]
        job['device_name'] = A._backup_targets_summary(targets, devices)

    # v6.4.3: the SAME Linux-only gate the create path applies, keyed on the
    # job's POST-EDIT type rather than on whether this request re-targeted it.
    #
    # Two ways in, and the first fix only closed one of them: retarget an
    # existing file job onto a Windows host, OR send a `spec` alone — which
    # flips an existing COMMAND job (already pointing at Windows hosts) to
    # type 'file' while touching no device id at all. Either way the cron sweep
    # then dispatches a bash rsync/tar to a host that cannot run it, on every
    # tick, forever, while the job reads as healthy. Gate on the end state.
    if job.get('type') == 'file' and job.get('device_ids'):
        _kept, os_skipped = A._split_targets_by_os_support(
            job['device_ids'], supported=('linux',))
        if not _kept:
            A.respond(400, {'error': 'file-backup jobs run on Linux hosts only — '
                            f'{len(os_skipped)} target(s) skipped '
                            f'({", ".join(os_skipped[:5])}). Use a command job '
                            'with a platform-native tool for these hosts.'})
        if _kept != job['device_ids']:
            job['device_ids'] = _kept
            job['device_id'] = _kept[0]
            job['device_name'] = A._backup_targets_summary(
                _kept, devices if devices is not None else (A.load(A.DEVICES_FILE) or {}))
    if 'cron' in body:
        cron = A._sanitize_str(body['cron'], 64).strip()
        if cron and not A._valid_cron(cron):
            A.respond(400, {'error': 'invalid cron expression'})
        job['cron'] = cron or None
    if 'enabled' in body:
        job['enabled'] = bool(body['enabled'])
    A.save(A.BACKUP_JOBS_FILE, data)
    A.audit_log(actor, 'backup_job_update', detail=f'job={job_id}')
    # Report the dropped hosts the same way the create path does, or the edit
    # answers "ok" while having silently narrowed the target list.
    A.respond(200, {'ok': True,
                    'skipped_unsupported': os_skipped,
                    'note': (f'{len(os_skipped)} non-Linux host(s) were left out of '
                             f'this file job: {", ".join(os_skipped[:5])}'
                             if os_skipped else '')})


def handle_backup_jobs_list():
    """GET /api/backup-jobs — all defined backup jobs, each with its last-run
    outcome (v6.3.0) so the table shows ✓/✗/running, not just a timestamp."""
    A.require_auth()
    # SECURITY: jobs are device-keyed — show only jobs whose targets the caller may
    # see (else a viewer / other-tenant admin reads every tenant's destinations and
    # legacy command text, which can embed secrets). run/restore/archives re-filter.
    jobs = [j for j in A._backup_jobs_load()['jobs'] if _backup_job_visible(j)]
    for j in jobs:
        try:
            j['status'] = _backup_job_status(j)
        except Exception:
            j['status'] = {'state': 'unknown'}
    A.respond(200, {'ok': True, 'jobs': jobs})


def handle_backup_restore():
    """POST /api/backup/restore — restore the data dir from an uploaded gzip
    tarball (as produced by /api/backup/download). Admin only. Takes a safety
    snapshot of the CURRENT data dir first, then extracts with strict path
    validation (no absolute paths, no '..', regular files/dirs only — symlinks,
    devices and hardlinks are rejected)."""
    actor = A.require_admin_auth()
    import tarfile, io as _io
    raw = A.get_body()
    if not raw:
        A.respond(400, {'error': 'empty body — POST the backup .tar.gz'})
    # v5.0.0 (#C2): transparently decrypt an uploaded `*.tar.gz.enc`. The
    # passphrase comes from the X-RP-Backup-Passphrase header (so an operator can
    # restore on a fresh box) or falls back to RP_BACKUP_PASSPHRASE in the env.
    if raw[:len(A.backup_crypto.MAGIC)] == A.backup_crypto.MAGIC:
        pw = (A._env('HTTP_X_RP_BACKUP_PASSPHRASE') or A._backup_passphrase()).strip()
        if not pw:
            A.respond(400, {'error': 'encrypted backup — supply the passphrase via the '
                                   'X-RP-Backup-Passphrase header or RP_BACKUP_PASSPHRASE env'})
        if not A.backup_crypto.available():
            A.respond(400, {'error': "the 'cryptography' library is required to decrypt this backup"})
        import tempfile as _tf
        with _tf.TemporaryDirectory() as _td:
            _ep = A.Path(_td) / 'in.enc'
            _dp = A.Path(_td) / 'out.tar.gz'
            _ep.write_bytes(raw)
            try:
                A.backup_crypto.decrypt_file(_ep, _dp, pw)
            except A.backup_crypto.BackupCryptoError as e:
                A.respond(400, {'error': str(e)})
            raw = _dp.read_bytes()
    stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    # 1) Safety snapshot of the current state before we overwrite anything.
    try:
        snap_dir = A.DATA_DIR / A._BACKUP_SNAPSHOT_DIR
        snap_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # v6.4.1 (SECURITY): this is a FULL copy of the data dir — tokens, API
        # keys, the vault blob, the audit log, config secrets. It used to be
        # written plaintext with umask perms whatever RP_BACKUP_PASSPHRASE said,
        # and nothing ever pruned it, so every restore left a permanent
        # unencrypted image of the install. Same treatment as a real backup:
        # 0600, built under a temp name, encrypted when a passphrase is set.
        snap_name = f'pre-restore-{stamp}.tar.gz'
        _snap_final = snap_dir / snap_name
        _snap_work = snap_dir / f'.pre-restore-{stamp}.{os.getpid()}.partial'
        _sfd = os.open(str(_snap_work), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_sfd, 'wb') as _sraw, \
                tarfile.open(fileobj=_sraw, mode='w:gz') as snap:
            A._write_data_dir_tar(snap)
        _snap_pw = A._backup_passphrase()
        if _snap_pw:
            if not A.backup_crypto.available():
                # Match _run_data_backup: when the operator asked for
                # encryption, refuse rather than quietly writing a full
                # plaintext image of the data dir — that is the exact leak
                # this block exists to close.
                try:
                    _snap_work.unlink()
                except OSError:
                    pass
                raise RuntimeError(
                    "RP_BACKUP_PASSPHRASE is set but the 'cryptography' "
                    'library is missing — refusing to write a plaintext '
                    'pre-restore snapshot')
            snap_name += '.enc'
            # `with_suffix` REPLACES the last suffix, so pre-restore-X.tar.gz
            # became pre-restore-X.tar.tar.gz.enc — a file the operator was
            # then told to look for under a name that did not exist. Append.
            _snap_enc = _snap_final.with_suffix(_snap_final.suffix + '.enc')
            try:
                A.backup_crypto.encrypt_file(_snap_work, _snap_enc, _snap_pw)
            finally:
                try:
                    _snap_work.unlink()
                except OSError:
                    pass
        else:
            os.replace(str(_snap_work), str(_snap_final))
    except Exception as e:
        A.respond(500, {'error': f'pre-restore snapshot failed (nothing changed): {e}'})
    # 2) Open + validate the uploaded archive.
    try:
        tf = tarfile.open(fileobj=_io.BytesIO(raw), mode='r:gz')
    except Exception as e:
        A.respond(400, {'error': f'not a valid .tar.gz: {e}'})
    base = os.path.realpath(str(A.DATA_DIR))
    # v3.13.0: decompression-bomb guard — a 50 MB gzip can inflate to many GB.
    # Cap the cumulative uncompressed size and member count before extracting so
    # a crafted archive can't fill the data-dir filesystem.
    _MAX_RESTORE_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB uncompressed
    _MAX_RESTORE_MEMBERS = 50000
    safe_members = []
    total_bytes = 0
    _members = tf.getmembers()
    # v6.4.2: the two archive shapes this endpoint has to accept.
    # `GET /api/backup/download` writes members relative to DATA_DIR
    # (`devices.json`); the SCHEDULED DR archive written by _run_data_backup
    # prefixes every member with `remotepower/`. Extraction joins the member
    # name onto DATA_DIR verbatim, so uploading a nightly archive used to
    # recreate the whole install one level down at DATA_DIR/remotepower/ and
    # restore nothing usable — while still reporting "N files restored". Strip
    # the shared root when (and only when) every member carries it.
    _strip_root = bool(_members) and all(
        m.name == 'remotepower' or m.name.startswith('remotepower/')
        for m in _members)
    for m in _members:
        if not (m.isfile() or m.isdir()):
            A.respond(400, {'error': f'archive contains a non-regular entry ({m.name}) — refused'})
        if _strip_root:
            m.name = m.name[len('remotepower/'):] if m.name != 'remotepower' else ''
            if not m.name:
                continue          # the root dir entry itself
        name = m.name
        if name.startswith('/') or '..' in name.replace('\\', '/').split('/'):
            A.respond(400, {'error': f'unsafe path in archive: {name}'})
        dest = os.path.realpath(os.path.join(base, name))
        if dest != base and not dest.startswith(base + os.sep):
            A.respond(400, {'error': f'path escapes data dir: {name}'})
        total_bytes += int(getattr(m, 'size', 0) or 0)
        if total_bytes > _MAX_RESTORE_BYTES or len(safe_members) > _MAX_RESTORE_MEMBERS:
            A.respond(400, {'error': 'archive too large when decompressed — refused (possible zip bomb)'})
        safe_members.append(m)
    # 3) Extract.
    restored = 0
    for m in safe_members:
        try:
            tf.extract(m, path=base)
            if m.isfile():
                restored += 1
        except Exception:
            pass
    tf.close()
    # Storage backend may cache file handles / mtimes — drop them.
    try:
        A._invalidate_backend_cache()
    except Exception:
        pass
    # v6.4.2: on SQLite/Postgres the extracted *.json files are inert — load()
    # reads the database, not the disk. Import them so a restore actually
    # restores. (Under SQLite an archive may instead carry the .db image, which
    # the walk above put back in place; importing the JSON stores on top of it
    # is idempotent and makes a cross-backend restore work either way.)
    imported = []
    try:
        imported = A._import_json_stores_into_backend()
    except Exception as e:
        A.respond(500, {'error': f'files were extracted but importing them into the '
                                 f'{A._storage_backend()} backend failed: {e} — the '
                                 f'pre-restore snapshot is {snap_name}'})
    A.audit_log(actor, 'backup_restore',
              f'{restored} files restored, {len(imported)} stores imported '
              f'(safety snapshot {snap_name})')
    A.respond(200, {'ok': True, 'restored': restored, 'snapshot': snap_name,
                    'stores_imported': len(imported)})


def handle_backup_run():
    """POST /api/self/backup-now — manually run a snapshot backup of DATA_DIR.

    Mirrors what the scheduled job does (`_maybe_run_scheduled_backup`).
    Writes a tarball into the configured backup_path (default
    `<RP_DATA_DIR>/backups/`), records state, prunes by retention.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    try:
        result = A._run_data_backup(triggered_by='manual')
    except Exception as e:
        A.respond(500, {'error': str(e)}); return
    A.audit_log(actor, 'backup_run_manual',
              detail=f"file={result.get('file','?')} bytes={result.get('bytes','?')}")
    A.respond(200, result)


def _drill_one_dir(base):
    """Decrypt → decompress → structure-check the newest archive in one
    directory. Returns the same result dict the drill has always returned.

    Split out in v6.4.3 so the OFF-HOST copy can be checked with exactly the
    same rigour as the local one — see _restore_drill_core.
    """
    p_base = A.Path(base)
    files = [f for f in (list(p_base.glob('remotepower_data_*.tar.gz'))
                         + list(p_base.glob('remotepower_data_*.tar.gz.enc'))) if f.exists()]
    if not files:
        return {'ok': False, 'no_archives': True, 'http': 404,
                'error': 'no backup archives found to test'}
    latest = max(files, key=lambda f: f.stat().st_mtime)
    import tarfile
    import tempfile as _tf
    scratch = A.Path(_tf.mkdtemp(prefix='rp_restore_test_'))
    started = time.time()
    try:
        src = latest
        if str(latest).endswith('.enc'):
            pp = A._backup_passphrase()
            if not pp:
                return {'ok': False, 'file': latest.name, 'http': 400,
                        'error': 'latest backup is encrypted but RP_BACKUP_PASSPHRASE is not set'}
            if not A.backup_crypto.available():
                return {'ok': False, 'file': latest.name, 'http': 400,
                        'error': "encrypted backup but the 'cryptography' library is missing"}
            dec = scratch / 'dec.tar.gz'
            A.backup_crypto.decrypt_file(latest, dec, pp)
            src = dec
        members = 0
        saw_root = False
        # v6.4.2: a structure check that only asserted "the tar opens and has a
        # remotepower/ member" passed on an archive carrying no state at all —
        # which is exactly what a Postgres install produced before the logical
        # -store export landed. Count the restorable STATE the archive holds
        # (logical *.json documents, or a SQLite image) and fail the drill when
        # it is empty, so a hollow archive can never report green.
        stores = 0
        db_image = False
        with tarfile.open(str(src), 'r:gz') as tar:
            for m in tar:
                members += 1
                parts = m.name.split('/', 1)
                if parts[0] == 'remotepower':
                    saw_root = True
                if not m.isfile():
                    continue
                bn = os.path.basename(m.name)
                if bn.endswith('.json') and not bn.endswith('.lock'):
                    stores += 1
                elif bn.endswith('.db'):
                    db_image = True
        has_state = stores > 0 or db_image
        ok = saw_root and members > 0 and has_state
        # master-improvement-scoping #56: record how long the check itself took
        # as a REAL, measured lower-bound signal toward the declared RTO target
        # -- this is decrypt+decompress+structure-check only, not a full
        # service restore, so it's surfaced as a floor, never implied to BE
        # the RTO measurement.
        elapsed = round(time.time() - started, 2)
        return {'ok': ok, 'file': latest.name, 'members': members,
                'stores': stores, 'db_image': db_image,
                'encrypted': str(latest).endswith('.enc'), 'seconds': elapsed,
                'error': None if ok else (
                    'Archive opened but the expected remotepower/ tree was missing.'
                    if not saw_root else
                    'the archive contains no restorable state (no logical stores '
                    'and no database image) — a restore from it would produce an '
                    'empty install')}
    except Exception as e:
        return {'ok': False, 'file': latest.name,
                'error': f'restore test failed: {str(e)[:200]}'}
    finally:
        shutil.rmtree(str(scratch), ignore_errors=True)


def _restore_drill_core():
    """Drill the local archive AND, when configured, the off-host mirror.

    v6.4.3: this used to glob the LOCAL backup directory only, so the off-host
    copy had never been verified by anything. That copy is the entire point of
    configuring an off-host destination — it is the one that survives losing
    the machine — and a drill that proves only the local archive restorable
    proves the wrong artifact. The mirror step reports whether the COPY
    succeeded; nothing checked the result was readable.

    The overall verdict is a conjunction: if an off-host destination is
    configured and its archive fails, the drill FAILS. A green drill must mean
    "the backup I would actually restore from works", not "one of them does".
    """
    cfg = A.load(A.CONFIG_FILE) or {}
    bk = cfg.get('backup') or {}
    local = _drill_one_dir(bk.get('path') or _default_backup_dir())

    offsite_dir = (bk.get('offsite_dir') or '').strip()
    if not offsite_dir:
        return local

    off = _drill_one_dir(offsite_dir)
    out = dict(local)
    out['offsite'] = dict(off, dir=offsite_dir)
    if not off.get('ok'):
        out['ok'] = False
        _why = ('no archive found at the off-host destination'
                if off.get('no_archives') else (off.get('error') or 'unknown'))
        out['error'] = (f'off-host copy at {offsite_dir} did not verify: {_why}'
                        + (f' (the local archive passed: {local.get("file")})'
                           if local.get('ok') else
                           f' — and the local archive also failed: {local.get("error")}'))
        out.setdefault('http', 500)
    return out


def _maybe_run_restore_drill():
    """v6.3.0: scheduled restore drill for the SERVER'S OWN DR backup — the
    manual test-restore (v5.4.1) proved restorability only when an admin
    remembered to click it. Weekly by default (`backup.drill_days`, 0
    disables), gated cheaply off `_config_ro()` on the not-due path.

    Edge-fires `restore_drill_failed` / `restore_drill_ok` with
    path='self:dr-archive' — DISTINCT from the per-device W6-43 backup-monitor
    drills, whose open alerts auto-resolve by their own path (rule 3b)."""
    cfg = A._config_ro()
    bk = cfg.get('backup') or {}
    if not bk.get('enabled', True):
        return
    try:
        days = int(bk.get('drill_days', 7))
    except (TypeError, ValueError):
        days = 7
    if days <= 0:
        return
    state_file = A.DATA_DIR / 'self_backup_state.json'
    # backend_exists, NOT Path.exists() — same v5.0.0 gotcha as the backup gate.
    state = A.load(state_file) if A.backend_exists(state_file) else {}
    now = int(time.time())
    if now - (state.get('last_drill_at') or 0) < days * 86400:
        return
    if not (state.get('last_run') or 0):
        return   # never backed up — backup_stale owns alerting for that
    r = _restore_drill_core()
    drill_ok = None if r.get('no_archives') else bool(r.get('ok'))
    prev_failed = bool(state.get('drill_alerted'))
    events = []
    with A._LockedUpdate(state_file) as st:
        st['last_drill_at'] = now   # re-arm even on no-archives (no hot rescan)
        if drill_ok is not None:
            st['last_drill_ok'] = drill_ok
            st['last_drill_seconds'] = r.get('seconds')
            st['last_drill_file'] = r.get('file')
            # v6.4.2: persist WHAT the drill found, not just pass/fail. Server
            # status can then say "the archive holds no restorable state" — the
            # case a Postgres install used to produce — instead of a generic
            # failure the operator has to go and reproduce by hand.
            st['last_drill_stores'] = r.get('stores')
            st['last_drill_db_image'] = r.get('db_image')
            st['last_drill_error'] = (r.get('error') or '')[:300]
            payload = {'path': 'self:dr-archive', 'file': r.get('file') or '',
                       'seconds': r.get('seconds'),
                       'error': (r.get('error') or '')[:200]}
            if not drill_ok and not prev_failed:
                st['drill_alerted'] = True
                events.append(('restore_drill_failed', payload))
            elif drill_ok and prev_failed:
                st['drill_alerted'] = False
                events.append(('restore_drill_ok', payload))
    for ev, payload in events:   # fire AFTER the lock (collect-then-fire)
        A.fire_webhook(ev, payload)


def handle_backup_test_restore():
    """POST /api/backup/test-restore — v5.4.1 (G1): verify the LATEST backup is
    actually restorable without touching the live data. Decrypts it (if encrypted +
    RP_BACKUP_PASSPHRASE set), opens the gzip/tar stream, and confirms it carries
    the expected ``remotepower/`` tree — exercising the whole decrypt→decompress→
    parse path. Nothing is extracted to a real location. Admin only; audited.
    v6.3.0: the check itself moved to _restore_drill_core (shared with the
    scheduled drill); responses are unchanged."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    r = _restore_drill_core()
    if r.get('http'):
        A.respond(r['http'], {'error': r['error']})
    if r.get('error') and 'restore test failed' in r['error']:
        A.audit_log(actor, 'backup_test_restore', f"file={r.get('file')} FAILED: {r['error'][:120]}")
        A.respond(200, {'ok': False, 'file': r.get('file'), 'error': r['error']})
    try:
        with A._LockedUpdate(A.DATA_DIR / 'self_backup_state.json') as state:
            state['last_test_restore_at'] = int(time.time())
            state['last_test_restore_seconds'] = r['seconds']
            state['last_test_restore_ok'] = r['ok']
    except Exception:
        pass
    A.audit_log(actor, 'backup_test_restore', f"file={r['file']} members={r['members']} ok={r['ok']}")
    A.respond(200, {'ok': r['ok'], 'file': r['file'], 'members': r['members'],
                  'encrypted': r['encrypted'],
                  'seconds': r['seconds'],
                  'message': ('Backup is restorable (decrypted, decompressed, '
                              f"{r['members']} entries, data tree present, "
                              f"checked in {r['seconds']}s).") if r['ok']
                             else r['error']})


def _backup_321_score(items, monitors):
    """v5.8.0 (B2.2): a 3-2-1 backup-rule assessment for one host from data
    RemotePower already has. The 3-2-1 rule: >=3 copies, on >=2 distinct media/
    targets, with >=1 kept off-site. Each leg is a heuristic (we don't see the
    physical media), so the result is INFORMATIONAL — the stale/verify events
    still do the paging. Returns {score 0-3, legs{...}, label, detail}.

    Legs:
      copies   — number of watched, currently-fresh backup paths (a stale path
                 doesn't count as a live copy). >=3 satisfies leg 1.
      media    — distinct backup *targets* (a monitor's `target`/`tool`/`dest`
                 or the path's top-level mount). >=2 satisfies leg 2.
      offsite  — any monitor flagged offsite (offsite_dir / offsite / remote /
                 a pbs/ssh/s3/rsync-style target). >=1 satisfies leg 3.
    ``items`` are the per-path dicts handle_device_backups built; ``monitors``
    is the matching backup_monitors config subset (carries the target hints
    that the freshness items don't)."""
    fresh = [it for it in items if it.get('ok')]
    copies = len(fresh)
    mon_by_path = {m.get('path'): m for m in monitors if isinstance(m, dict)}

    def _target_of(it):
        m = mon_by_path.get(it.get('path')) or {}
        for k in ('target', 'dest', 'tool', 'offsite_dir'):
            v = (m.get(k) or '').strip()
            if v:
                return v.lower()
        p = str(it.get('path') or '')
        # Fall back to the top-level directory as a coarse "medium" proxy.
        parts = [seg for seg in p.split('/') if seg]
        return ('/' + parts[0]).lower() if parts else p.lower()

    media = len({_target_of(it) for it in fresh})

    _OFFSITE_HINT = ('offsite', 'remote', 'pbs', 's3', 'b2', 'ssh://', 'rsync',
                     'nfs', 'smb', 'cifs', 'cloud', 'backblaze', 'wasabi')

    def _is_offsite(it):
        m = mon_by_path.get(it.get('path')) or {}
        if m.get('offsite') or m.get('offsite_dir'):
            return True
        blob = ' '.join(str(m.get(k) or '') for k in ('target', 'dest', 'tool',
                                                       'type', 'label')).lower()
        return any(h in blob for h in _OFFSITE_HINT)

    offsite = any(_is_offsite(it) for it in fresh)

    legs = {
        'copies':  {'ok': copies >= 3, 'value': copies,
                    'label': f'{copies} fresh cop{"y" if copies == 1 else "ies"}'},
        'media':   {'ok': media >= 2, 'value': media,
                    'label': f'{media} target{"" if media == 1 else "s"}'},
        'offsite': {'ok': offsite, 'value': int(offsite),
                    'label': 'off-site copy' if offsite else 'no off-site copy'},
    }
    score = sum(1 for leg in legs.values() if leg['ok'])
    if not fresh:
        label = 'no fresh backups'
    elif score == 3:
        label = '3-2-1 satisfied'
    else:
        label = f'{score}/3 of the 3-2-1 rule'
    return {
        'score': score, 'max': 3, 'legs': legs, 'label': label,
        'detail': ' · '.join(leg['label'] for leg in legs.values()),
        'fresh': copies, 'total': len(items),
    }


def handle_device_backups(dev_id):
    """GET /api/devices/<id>/backups — live freshness of this device's watched
    backup paths. Joins backup_state.json (per-path ok/age, written on every
    heartbeat that carries backup_status) with the backup_monitors config for
    the label + threshold. Surfaces what previously only drove the
    backup_stale webhook. Adds a 3-2-1-rule score (v5.8.0, informational).
    Auth: require_auth (+ central per-device scope)."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Device not found'})
    state = A.load(A.DATA_DIR / 'backup_state.json') or {}
    monitors = (A.load(A.CONFIG_FILE) or {}).get('backup_monitors') or []
    mon_by_path = {m.get('path'): m for m in monitors if isinstance(m, dict)}
    prefix = f'{dev_id}:'
    items = []
    for key, st in state.items():
        if not key.startswith(prefix) or not isinstance(st, dict):
            continue
        path = key[len(prefix):]
        mon = mon_by_path.get(path) or {}
        items.append({
            'path':          path,
            'label':         mon.get('label') or path,
            'ok':            bool(st.get('ok')),
            'age_h':         st.get('age_h'),
            'max_age_hours': float(mon.get('max_age_hours', 24)),
            # v4.10.0: integrity-verification status (when verify is enabled)
            'verify_enabled': bool(mon.get('verify_enabled')),
            'verify_status':  st.get('verify_status', 'unknown'),
            'verify_output':  st.get('verify_output', ''),
            'verify_at':      st.get('verify_at', 0),
            'verify_tool':    st.get('verify_tool', mon.get('tool', '')),
            # W6-43: restore-drill status (when a drill is enabled for this path)
            'restore_drill_enabled': bool(mon.get('restore_drill_enabled')),
            'drill_status':   st.get('drill_status', 'unknown'),
            'drill_output':   st.get('drill_output', ''),
            'drill_at':       st.get('drill_at', 0),
            'drill_bytes':    st.get('drill_bytes', 0),
        })
    # Stale first, then by label, so the actionable rows are at the top.
    items.sort(key=lambda x: (x['ok'], str(x['label']).lower()))
    dev_paths = {it['path'] for it in items}
    dev_monitors = [m for m in monitors
                    if isinstance(m, dict) and m.get('path') in dev_paths]
    A.respond(200, {
        'backups': items,
        'score_321': _backup_321_score(items, dev_monitors),
    })


def handle_proxmox_backup_threshold() -> None:
    """``POST /api/proxmox/backups/threshold`` — set proxmox_backup_warn_days."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    try:
        days = int((A.get_json_obj()).get('days'))
    except (TypeError, ValueError):
        A.respond(400, {'error': 'days must be an integer'})
    if not (1 <= days <= 365):
        A.respond(400, {'error': 'days must be between 1 and 365'})
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['proxmox_backup_warn_days'] = days
    A.audit_log(actor, 'proxmox_backup_threshold', detail=f'days={days}')
    A.respond(200, {'ok': True, 'warn_days': days})


def handle_proxmox_backups_get() -> None:
    """``GET /api/proxmox/backups`` — per-guest vzdump backup recency, plus the
    adjustable staleness threshold. Live-refreshes the cache when Proxmox is
    configured so the Backups page is always current; falls back to the last
    cached snapshot on a transient API error."""
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE)
    warn_days = int(cfg.get('proxmox_backup_warn_days', 7))
    pc = A.proxmox_client.config_from(cfg)
    enabled = bool(pc['enabled'])
    configured = enabled and A.proxmox_client.is_configured(pc)
    if configured:
        try:
            A._refresh_proxmox_backup_cache(pc)
        except Exception:
            pass
    cache = A.load(A.PROXMOX_BACKUP_CACHE) if A.backend_exists(A.PROXMOX_BACKUP_CACHE) else {}
    if not isinstance(cache, dict):
        cache = {}
    guests = cache.get('guests', [])
    for g in guests:
        age = g.get('age_days')
        g['status'] = ('missing' if age is None
                       else 'stale' if age > warn_days else 'ok')
    A.respond(200, {'ok': True, 'enabled': enabled, 'configured': configured,
                  'warn_days': warn_days, 'node': cache.get('node', ''),
                  'updated_at': cache.get('updated_at', 0), 'guests': guests})


def process_backup_jobs():
    """Per-request sweep: fire cron-scheduled backup jobs whose minute matches."""
    data = A._backup_jobs_load()
    now = int(time.time())
    current_minute = now // 60
    changed = False
    cmds = None
    for job in data['jobs']:
        if not job.get('enabled') or not job.get('cron'):
            continue
        if job.get('last_fired_minute') == current_minute:
            continue
        # v6.4.2: catch-up window, not an exact-minute match (see _cron_due_since).
        if not A._cron_due_since(job['cron'], now, job.get('last_fired_minute')):
            continue
        devices = A.load(A.DEVICES_FILE)
        try:
            _bc = _backup_job_command(job)   # v6.3.0: generated for file jobs
        except ValueError as _e:
            A.log_command(f'backup({job["created_by"]})', job.get('device_id', '?'),
                          job.get('device_name', '?'),
                          f'backup:{job["name"]} SKIPPED ({_e})')
            _bc = ''
        # v6.3.0 baseline: fan out to every targeted device (skipping quarantined).
        if _bc:
            for dev_id in _backup_job_targets(job):
                if dev_id not in devices or A._device_quarantined(devices[dev_id]):
                    continue
                # v6.4.3: the SCHEDULED path needs the same OS gate as create,
                # update and run. Without it a pre-existing job kept queueing a
                # bash rsync at a Windows or macOS host on every cron tick,
                # silently, forever — the agent drops the command and nothing
                # reports it. Logged rather than skipped in silence, so the
                # operator sees WHY that host never backs up.
                if A._device_os_family(devices[dev_id]) != 'linux':
                    A.log_command(f'backup({job["created_by"]})', dev_id,
                                  devices[dev_id].get('name', dev_id),
                                  f'backup:{job["name"]} SKIPPED '
                                  '(structured file backup is Linux-only)')
                    continue
                if cmds is None:
                    cmds = A.load(A.CMDS_FILE)
                cmds.setdefault(dev_id, [])
                queued = f'exec:{_bc}'
                if queued not in cmds[dev_id]:
                    cmds[dev_id].append(queued)
                A.log_command(f'backup({job["created_by"]})', dev_id,
                            devices[dev_id].get('name', dev_id), f'backup:{job["name"]}')
        job['last_fired_minute'] = current_minute
        job['last_run'] = now
        changed = True
    if cmds is not None:
        A.save(A.CMDS_FILE, cmds)
    if changed:
        A.save(A.BACKUP_JOBS_FILE, data)
