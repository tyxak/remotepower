"""Structured file-backup command generation (v6.3.0).

A "file" backup job carries STRUCTURED fields — a list of source paths, a method
(rsync/tar) and a destination (ssh / nfs / smb) — instead of an operator-typed
shell command. The server generates the actual command from those fields, so the
operator never supplies shell text. Because the generated command runs as ROOT on
the host via the agent's command channel, this module is the security boundary:

  * every field is validated against a STRICT allowlist (absolute paths, no shell
    metacharacters, no `..` traversal, hostname/user charsets; remote paths carry
    no spaces so no quoting ambiguity survives);
  * every interpolated value is additionally `shlex.quote`d as defense-in-depth;
  * NO credential ever appears in the generated command or in RemotePower — ssh
    uses key auth (BatchMode, never prompts), nfs needs none, and smb references a
    host-side credentials FILE (same posture as an ssh key). Credentials live on
    the host, never in a command line (which would leak via argv / the audit log).

Pure + import-free (only stdlib) so it unit-tests without the server.
"""
import shlex

MAX_PATHS = 20
MAX_PATH_LEN = 512
METHODS = ('rsync', 'tar')
TRANSPORTS = ('ssh', 'nfs', 'smb')

_PATH_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")
_HOST_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
_USER_OK = _HOST_OK
# A CIFS share is a SINGLE name component — no '/', no '..' traversal (a subpath
# belongs in remote_path). Restricting it keeps the //host/share UNC well-formed.
_SHARE_OK = _HOST_OK


def _is_abs_path(p, allow_space=False):
    """True if p is a safe absolute path. Spaces allowed only for LOCAL source
    paths (they get shlex.quote'd); remote paths forbid them so the generated
    remote command needs no fragile cross-shell quoting."""
    if not isinstance(p, str) or not p or not p.startswith('/'):
        return False
    if len(p) > MAX_PATH_LEN:
        return False
    chars = _PATH_CHARS | {' '} if allow_space else _PATH_CHARS
    if any(c not in chars for c in p):
        return False
    if '..' in p.split('/'):
        return False
    return True


def _ok(s, allowed, maxlen=255):
    return isinstance(s, str) and 0 < len(s) <= maxlen and all(c in allowed for c in s)


def validate_spec(spec):
    """Validate a file-backup spec. Returns (True, None) or (False, 'reason')."""
    if not isinstance(spec, dict):
        return False, 'spec must be an object'
    paths = spec.get('paths')
    if not isinstance(paths, list) or not paths:
        return False, 'at least one source path is required'
    if len(paths) > MAX_PATHS:
        return False, f'too many paths (max {MAX_PATHS})'
    for p in paths:
        if not _is_abs_path(p, allow_space=True):
            return False, f'invalid source path: {p!r} (absolute, no "..")'
    if spec.get('method') not in METHODS:
        return False, f'method must be one of {METHODS}'
    dest = spec.get('dest')
    if not isinstance(dest, dict):
        return False, 'dest is required'
    transport = dest.get('transport')
    if transport not in TRANSPORTS:
        return False, f'transport must be one of {TRANSPORTS}'
    if not _ok(dest.get('host'), _HOST_OK):
        return False, 'invalid destination host'
    try:
        port = int(dest.get('port', 22))
    except (TypeError, ValueError):
        return False, 'invalid port'
    if not (1 <= port <= 65535):
        return False, 'port out of range'
    if not _is_abs_path(dest.get('remote_path')):
        return False, 'invalid remote_path (absolute, no spaces, no "..")'
    if transport == 'ssh':
        if not _ok(dest.get('user'), _USER_OK, 64):
            return False, 'ssh transport requires a valid user'
    elif transport == 'nfs':
        if not _is_abs_path(dest.get('export')):
            return False, 'nfs transport requires a valid export path'
    elif transport == 'smb':
        share = dest.get('share')
        if not _ok(share, _SHARE_OK, 255) or (isinstance(share, str) and '..' in share):
            return False, 'smb transport requires a valid single-component share (no "/" or "..")'
        cf = dest.get('credentials_file')
        if cf and not _is_abs_path(cf):
            return False, 'invalid credentials_file path'
    return True, None


# Job-scoped mountpoint under tmpfs (/run) — never persisted, never operator input.
_MNT_BASE = '/run/remotepower-filebackup'


def _ssh_e(port):
    return f'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p {int(port)}'


def _mount_cmd(dest, mnt):
    """mount command for nfs/smb (no credentials in argv — smb uses a host file)."""
    if dest['transport'] == 'nfs':
        return f'mount -t nfs {shlex.quote(dest["host"] + ":" + dest["export"])} {shlex.quote(mnt)}'
    opts = 'vers=3.0'
    cf = dest.get('credentials_file')
    opts += f',credentials={shlex.quote(cf)}' if cf else ',guest'
    unc = f'//{dest["host"]}/{dest["share"].strip("/")}'
    return f'mount -t cifs {shlex.quote(unc)} {shlex.quote(mnt)} -o {opts}'


def build_backup_command(spec, job_id):
    """Generate the safe backup command for a VALIDATED spec (caller runs
    validate_spec first). job_id is an opaque token used in the mountpoint /
    archive name."""
    ok, err = validate_spec(spec)
    if not ok:
        raise ValueError(err)
    if not _ok(job_id, _HOST_OK, 64):
        raise ValueError('invalid job id')
    dest, paths, method = spec['dest'], spec['paths'], spec['method']
    transport = dest['transport']
    rpath = dest['remote_path'].rstrip('/')
    qpaths = ' '.join(shlex.quote(p) for p in paths)

    if transport == 'ssh':
        remote = shlex.quote(f'{dest["user"]}@{dest["host"]}')
        ssh_e = _ssh_e(dest.get('port', 22))
        if method == 'rsync':
            target = f'{remote}:{shlex.quote(rpath + "/")}'
            return f'rsync -a --info=progress2 -e {shlex.quote(ssh_e)} {qpaths} {target}'
        # tar → one timestamped archive. $(date) expands in the AGENT shell, then
        # the literal path is handed to the remote `cat >` redirect. rpath has no
        # spaces (validated), so the remote redirect target needs no quoting.
        arch = f'{rpath}/{job_id}-$(date +%Y%m%d-%H%M%S).tar.gz'
        return f'tar czf - {qpaths} | {ssh_e} {remote} "cat > {arch}"'

    # nfs / smb: mount → transfer → always unmount.
    mnt = f'{_MNT_BASE}/{job_id}'
    dstdir = f'{mnt}/{rpath.lstrip("/")}'
    pre = f'mkdir -p {shlex.quote(mnt)} && {_mount_cmd(dest, mnt)} && mkdir -p {shlex.quote(dstdir)}'
    post = f'umount {shlex.quote(mnt)}; rmdir {shlex.quote(mnt)} 2>/dev/null || true'
    if method == 'rsync':
        xfer = f'rsync -a --info=progress2 {qpaths} {shlex.quote(dstdir + "/")}'
    else:
        xfer = (f'tar czf {shlex.quote(dstdir)}/"{job_id}-$(date +%Y%m%d-%H%M%S).tar.gz" '
                f'{qpaths}')
    return f'{pre} && {{ {xfer}; rc=$?; {post}; exit $rc; }} || {{ {post}; exit 1; }}'


def build_restore_command(spec, restore_target, job_id, archive=None):
    """Reverse: pull the backup back to `restore_target` on the host. For tar,
    `archive` is the remote archive filename. Destructive — the caller gates it
    (admin + typed confirmation + audit)."""
    ok, err = validate_spec(spec)
    if not ok:
        raise ValueError(err)
    if not _is_abs_path(restore_target):
        raise ValueError('invalid restore target')
    if not _ok(job_id, _HOST_OK, 64):
        raise ValueError('invalid job id')
    if archive is not None and not _ok(archive, _HOST_OK | {'.'}, 128):
        raise ValueError('invalid archive name')
    dest, method = spec['dest'], spec['method']
    transport = dest['transport']
    rpath = dest['remote_path'].rstrip('/')
    rt = shlex.quote(restore_target.rstrip('/') + '/')

    if transport == 'ssh':
        remote = shlex.quote(f'{dest["user"]}@{dest["host"]}')
        ssh_e = _ssh_e(dest.get('port', 22))
        if method == 'rsync':
            src = f'{remote}:{shlex.quote(rpath + "/")}'
            return f'rsync -a --info=progress2 -e {shlex.quote(ssh_e)} {src} {rt}'
        if not archive:
            raise ValueError('tar restore needs an archive name')
        return f'{ssh_e} {remote} "cat {rpath}/{archive}" | tar xzf - -C {rt}'

    mnt = f'{_MNT_BASE}/{job_id}-restore'
    srcdir = f'{mnt}/{rpath.lstrip("/")}'
    pre = f'mkdir -p {shlex.quote(mnt)} && {_mount_cmd(dest, mnt)}'
    post = f'umount {shlex.quote(mnt)}; rmdir {shlex.quote(mnt)} 2>/dev/null || true'
    if method == 'rsync':
        xfer = f'rsync -a --info=progress2 {shlex.quote(srcdir + "/")} {rt}'
    else:
        if not archive:
            raise ValueError('tar restore needs an archive name')
        xfer = f'tar xzf {shlex.quote(srcdir + "/" + archive)} -C {rt}'
    return f'{pre} && {{ {xfer}; rc=$?; {post}; exit $rc; }} || {{ {post}; exit 1; }}'


def build_list_command(spec, job_id):
    """List this job's archives at the destination, newest first, so the restore
    flow can offer a pick-list instead of asking the operator to type a filename.
    Only meaningful for tar jobs (rsync is a synced tree, not per-run archives).
    Returns just the archive filenames (one per line)."""
    ok, err = validate_spec(spec)
    if not ok:
        raise ValueError(err)
    if not _ok(job_id, _HOST_OK, 64):
        raise ValueError('invalid job id')
    dest = spec['dest']
    transport = dest['transport']
    rpath = dest['remote_path'].rstrip('/')
    # job_id is validated (safe charset), so this grep pattern is injection-free.
    grep = f"grep -E '^{job_id}-.*[.]tar[.]gz$'"
    if transport == 'ssh':
        remote = shlex.quote(f'{dest["user"]}@{dest["host"]}')
        return (f'{_ssh_e(dest.get("port", 22))} {remote} '
                f'"ls -1t {rpath} 2>/dev/null | {grep}"')
    mnt = f'{_MNT_BASE}/{job_id}-ls'
    srcdir = f'{mnt}/{rpath.lstrip("/")}'
    pre = f'mkdir -p {shlex.quote(mnt)} && {_mount_cmd(dest, mnt)}'
    post = f'umount {shlex.quote(mnt)}; rmdir {shlex.quote(mnt)} 2>/dev/null || true'
    return (f'{pre} && {{ ls -1t {shlex.quote(srcdir)} 2>/dev/null | {grep}; rc=$?; '
            f'{post}; exit $rc; }} || {{ {post}; exit 1; }}')


def describe(spec):
    """One-line human summary for the UI / audit log (no secrets)."""
    d = spec.get('dest', {}) if isinstance(spec, dict) else {}
    t = d.get('transport', '?')
    where = {
        'ssh': f'{d.get("user","?")}@{d.get("host","?")}:{d.get("remote_path","?")}',
        'nfs': f'{d.get("host","?")}:{d.get("export","?")}{d.get("remote_path","")}',
        'smb': f'//{d.get("host","?")}/{d.get("share","?")}{d.get("remote_path","")}',
    }.get(t, d.get('host', '?'))
    n = len(spec.get('paths', []) or []) if isinstance(spec, dict) else 0
    return f'{spec.get("method","?")} {n} path(s) → {t} {where}'
