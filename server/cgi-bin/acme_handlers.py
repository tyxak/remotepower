"""RemotePower — ACME / acme.sh per-device certificate lifecycle: fleet cert
overview, centrally-managed DNS-01 credentials, single-cert detail + action
logs, and the queued issue / renew / revoke / cancel / ignore actions (dispatched
through the standard audited command channel).

A bound-module carve-out following the dmarc_handlers / dns_dashboard_handlers
pattern: api.py execs a PRIVATE instance, binds its own ``globals()`` here (every
api service reached as ``A.<name>`` — a dynamic lookup that keeps the suite's
monkeypatching + inspect.getsource assertions working), then re-imports the
names back so routes + the heartbeat callers of _ingest_acme_state /
_acme_log_path and the command-output scrub caller of _scrub_acme_credentials
resolve unchanged. The ACME_* constants (ACME_DNS_PROVIDERS /
ACME_DNS_CREDENTIAL_FIELDS / ACME_STATE_FILE / ACME_LOGS_DIR) + CONFIG_FILE /
DEVICES_FILE / CMDS_FILE stay in api.py, read via A. The queued acme.sh commands
ride the same audited exec channel as everything else (A._acme_queue_command →
CMDS_FILE + A.log_command + A.audit_log).
"""
import json
import re
import secrets
import shlex
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
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


def _acme_credential_env_prefix(provider: str) -> str:
    """Return the `export X=... Y=...` prefix for a given provider, or
    empty string if no credentials are stored. The prefix is injected
    into the queued acme.sh command so the agent sees the secrets in
    the spawned shell only — not as persistent env. Values are
    single-quoted; embedded single quotes are escaped.

    v3.3.0: lets RemotePower centrally manage DNS-01 credentials
    instead of asking the operator to edit ~/.acme.sh/account.conf
    on every device.
    """
    if provider not in A.ACME_DNS_CREDENTIAL_FIELDS:
        return ''
    cfg = A.load(A.CONFIG_FILE) or {}
    creds = (cfg.get('acme_dns_credentials') or {}).get(provider) or {}
    parts = []
    for field in A.ACME_DNS_CREDENTIAL_FIELDS[provider]:
        name = field['name']
        val = creds.get(name)
        if not val:
            continue
        # Single-quote and escape any embedded quotes
        escaped = str(val).replace("'", "'\"'\"'")
        parts.append(f"{name}='{escaped}'")
    if not parts:
        return ''
    return 'export ' + ' '.join(parts) + ' && '


def _scrub_acme_credentials(cmd: str) -> str:
    """Replace credential values in a queued acme.sh command with
    `***REDACTED***` for audit-log + UI display. Operators see the
    structure of the command but not the secret material."""
    if 'export ' not in cmd:
        return cmd
    out = cmd
    for provider, fields in A.ACME_DNS_CREDENTIAL_FIELDS.items():
        for f in fields:
            name = f['name']
            # Match: NAME='anything-up-to-trailing-quote'
            out = re.sub(
                rf"({re.escape(name)})='[^']*'",
                r"\1='***REDACTED***'",
                out,
            )
    return out


def _ingest_acme_state(dev_id, acme):
    """Persist the latest per-device acme.sh scan. acme is whatever the
    agent reported under payload['acme']."""
    if not A._validate_id(dev_id):
        return
    # Bound — don't trust unbounded lists from the agent
    if not isinstance(acme, dict):
        return
    certs = acme.get('certs') or []
    if not isinstance(certs, list):
        certs = []
    safe_certs = []
    for c in certs[:200]:  # hard cap
        if not isinstance(c, dict):
            continue
        domain = A._sanitize_str(str(c.get('domain', '')), 253)
        if not domain:
            continue
        alt_raw = c.get('alt_names') or []
        if not isinstance(alt_raw, list):
            alt_raw = []
        alt_names = [A._sanitize_str(str(a), 253) for a in alt_raw[:50] if a]
        safe_certs.append({
            'domain':             domain,
            'alt_names':          alt_names,
            'is_wildcard':        bool(c.get('is_wildcard')),
            'challenge':          A._sanitize_str(str(c.get('challenge', '')), 64),
            'is_dns_challenge':   bool(c.get('is_dns_challenge')),
            'dns_provider':       A._sanitize_str(str(c.get('dns_provider', '')), 64),
            'dns_provider_label': A._sanitize_str(str(c.get('dns_provider_label', '')), 128),
            'key_length':         A._sanitize_str(str(c.get('key_length', '')), 16),
            'created_ts':         int(c['created_ts']) if isinstance(c.get('created_ts'), int) else None,
            'next_renew_ts':      int(c['next_renew_ts']) if isinstance(c.get('next_renew_ts'), int) else None,
            'created_str':        A._sanitize_str(str(c.get('created_str', '')), 64),
            'next_renew_str':     A._sanitize_str(str(c.get('next_renew_str', '')), 64),
            'reload_cmd':         A._sanitize_str(str(c.get('reload_cmd', '')), 512),
            'cert_path':          A._sanitize_str(str(c.get('cert_path', '')), 512),
            'key_path':           A._sanitize_str(str(c.get('key_path', '')), 512),
            'fullchain_path':     A._sanitize_str(str(c.get('fullchain_path', '')), 512),
        })
    record = {
        'available': bool(acme.get('available')),
        'home':      A._sanitize_str(str(acme.get('home', '')), 256),
        'version':   A._sanitize_str(str(acme.get('version', '')), 32),
        'updated_at': int(time.time()),
        'certs':     safe_certs,
    }
    # v5.6.x perf: single-row entity write (store is ENTITY-promoted; the
    # old non-dict guard rebound the yielded name and never persisted anyway).
    A._entity_write_one(A.ACME_STATE_FILE, dev_id, record)


def _acme_log_path(dev_id, action_id):
    """File path for captured acme.sh stdout. action_id is the queued cmd id."""
    safe_did = re.sub(r'[^a-zA-Z0-9_-]', '_', str(dev_id))[:64]
    safe_act = re.sub(r'[^a-zA-Z0-9_-]', '_', str(action_id))[:64]
    return A.ACME_LOGS_DIR / f'{safe_did}__{safe_act}.log'


def _acme_validate_domain(domain):
    """Strict-ish domain validation. Allows wildcards via '*.example.com'."""
    if not isinstance(domain, str) or not domain or len(domain) > 253:
        return False
    # Wildcard: only as the leftmost label
    if domain.startswith('*.'):
        domain = domain[2:]
    # Standard FQDN regex: labels are 1-63 chars of [A-Za-z0-9-], no leading
    # or trailing hyphen. At least one dot.
    return bool(re.match(
        r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$',
        domain
    ))


def handle_acme_list():
    """GET /api/acme — fleet-wide cert overview, joined with device names."""
    A.require_auth()
    store   = A.load(A.ACME_STATE_FILE) or {}
    # v6.2.2 (SECURITY): scope/tenant-filter the per-device cert overview so
    # other scopes'/tenants' certs don't leak. No-op for a single-org admin.
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    now     = int(time.time())
    out = []
    for dev_id, dev in devices.items():
        rec = store.get(dev_id)
        if not rec:
            continue
        out.append({
            'device_id':   dev_id,
            'device_name': dev.get('name', dev_id),
            'available':   bool(rec.get('available')),
            'home':        rec.get('home', ''),
            'version':     rec.get('version', ''),
            'updated_at':  rec.get('updated_at', 0),
            'stale':       (now - (rec.get('updated_at') or 0)) > 4 * 3600,
            'cert_count':  len(rec.get('certs') or []),
            'certs':       rec.get('certs') or [],
        })
    out.sort(key=lambda r: r['device_name'].lower())
    A.respond(200, {'devices': out, 'providers': A.ACME_DNS_PROVIDERS})


def handle_acme_dns_credentials_get():
    """GET /api/acme/dns-credentials — list providers with credential
    metadata + which fields are currently set (boolean only, never
    the secret value).

    v3.3.0: centrally-managed DNS-01 credentials so the operator
    doesn't have to ssh into each device and edit
    ~/.acme.sh/account.conf.
    """
    A.require_admin_auth()
    cfg = A.load(A.CONFIG_FILE) or {}
    saved = cfg.get('acme_dns_credentials') or {}
    out = []
    for pkey, plabel in A.ACME_DNS_PROVIDERS.items():
        fields = A.ACME_DNS_CREDENTIAL_FIELDS.get(pkey)
        if not fields:
            continue
        provider_saved = saved.get(pkey) or {}
        ui_fields = []
        for f in fields:
            ui_fields.append({
                'name':     f['name'],
                'label':    f['label'],
                'required': bool(f.get('required')),
                'secret':   bool(f.get('secret')),
                'hint':     f.get('hint', ''),
                'set':      bool(provider_saved.get(f['name'])),
            })
        out.append({
            'provider': pkey,
            'label':    plabel,
            'fields':   ui_fields,
        })
    A.respond(200, {'providers': out})


def handle_acme_dns_credentials_set():
    """POST /api/acme/dns-credentials — save credentials for a single
    provider. Empty/missing string for a field means "leave
    unchanged" (so the UI can render masked placeholders without
    forcing re-entry on every save).

    Body: {provider: "dns_cf", credentials: {CF_Token: "...", ...}}.
    Sending an explicit null value clears the field.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.AcmeDnsCredentialsSetRequest)
    provider = str(body.get('provider', '')).strip()
    if provider not in A.ACME_DNS_CREDENTIAL_FIELDS:
        A.respond(400, {'error': f'unknown provider {provider!r}'})
    new_creds = body.get('credentials') or {}
    if not isinstance(new_creds, dict):
        A.respond(400, {'error': 'credentials must be an object'})
    allowed_fields = {f['name']: f for f in A.ACME_DNS_CREDENTIAL_FIELDS[provider]}
    changed = []
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        store = cfg.setdefault('acme_dns_credentials', {})
        provider_store = store.setdefault(provider, {})
        for fname, val in new_creds.items():
            if fname not in allowed_fields:
                continue  # silently drop unknown keys
            if val is None:
                if fname in provider_store:
                    del provider_store[fname]
                    changed.append(fname)
                continue
            sval = A._sanitize_str(str(val), 1024, allow_empty=True).strip()
            if not sval:
                continue  # blank = leave unchanged
            provider_store[fname] = sval
            changed.append(fname)
        # Prune the provider entry if all fields ended up empty
        if not provider_store:
            store.pop(provider, None)
    A.audit_log(actor, 'acme_dns_credentials_set',
                detail=f'provider={provider} fields={",".join(changed) or "(none)"}')
    A.respond(200, {'ok': True, 'updated_fields': changed})


def handle_acme_detail(dev_id, domain):
    """GET /api/acme/<dev_id>/<domain> — single-cert detail + recent log files."""
    A.require_auth()
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'}); return
    if not A._acme_validate_domain(domain):
        A.respond(400, {'error': 'invalid domain'}); return
    store = A.load(A.ACME_STATE_FILE) or {}
    rec = store.get(dev_id)
    if not rec:
        A.respond(404, {'error': 'no acme state reported for device'}); return
    cert = next((c for c in (rec.get('certs') or []) if c.get('domain') == domain), None)
    if not cert:
        A.respond(404, {'error': 'cert not found in last scan'}); return
    # Walk ACME_LOGS_DIR for matching action logs (most-recent first, last 10)
    logs = []
    try:
        if A.ACME_LOGS_DIR.is_dir():
            safe_did = re.sub(r'[^a-zA-Z0-9_-]', '_', dev_id)[:64]
            for f in sorted(A.ACME_LOGS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                # v3.0.1: only .log files are real action logs. Each has a
                # .meta.json sibling; without this filter the sidecar files
                # showed up as bogus "actions" named <id>.meta with NaN size,
                # and "View log" 404'd because no <id>.meta.log exists.
                if f.suffix != '.log':
                    continue
                if not f.name.startswith(f'{safe_did}__'):
                    continue
                try:
                    meta_path = f.with_suffix('.meta.json')
                    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                except Exception:
                    meta = {}
                if meta.get('domain') and meta.get('domain') != domain:
                    continue
                logs.append({
                    'id':       f.stem.split('__', 1)[-1] if '__' in f.stem else f.stem,
                    'ts':       int(meta.get('queued_at') or f.stat().st_mtime),
                    'action':   meta.get('action', ''),
                    'rc':       meta.get('rc'),
                    'size':     f.stat().st_size,
                })
                if len(logs) >= 10:
                    break
    except Exception:
        pass
    A.respond(200, {'cert': cert, 'logs': logs})


def handle_acme_log(dev_id, action_id):
    """GET /api/acme/<dev_id>/log/<action_id> — full captured stdout for one action."""
    A.require_auth()
    # Per-device read NOT under /api/devices/, so the dispatch guard
    # (_enforce_device_scope) doesn't cover it — block out-of-scope roles here.
    A._scope_block_device(dev_id)
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'}); return
    log_path = A._acme_log_path(dev_id, action_id)
    if not log_path.is_file():
        A.respond(404, {'error': 'log not found'}); return
    try:
        # Cap at 256 KB just in case
        text = log_path.read_text(errors='replace')[:256 * 1024]
    except Exception as e:
        A.respond(500, {'error': f'failed to read log: {e}'}); return
    A.respond(200, {'content': text, 'size': log_path.stat().st_size})


def _acme_queue_command(dev_id, action, domain, cmd_str):
    """Queue an exec: command on the device, and stash a meta-file so the
    response handler can write the output into the right log slot."""
    actor = A.require_admin_auth()
    devices = A.load(A.DEVICES_FILE) or {}
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'}); return None
    action_id = secrets.token_hex(6)
    # Reserve the log file so it shows up in the detail view immediately
    try:
        A.ACME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    log_path = A._acme_log_path(dev_id, action_id)
    try:
        log_path.write_text('# pending — awaiting agent\n')
        meta_path = log_path.with_suffix('.meta.json')
        meta_path.write_text(json.dumps({
            'action':   action,
            'domain':   domain,
            'queued_at': int(time.time()),
            'actor':    actor,
        }))
    except Exception:
        pass
    # Queue the exec — output comes back through the standard command-output
    # ingestion path and gets re-pointed at the acme log in v3.0.1 (handled
    # in handle_command_output below).
    with A._LockedUpdate(A.CMDS_FILE) as cmds:
        pending = cmds.get(dev_id) or []
        # Tag the command so we can detect its output and route it
        tagged = f'exec:#acme:{action_id}#{cmd_str}'
        pending.append(tagged)
        cmds[dev_id] = pending
    # v3.9.0: record it in the command history so it shows in the Command
    # Queue's "recently dispatched" log like every other queued command —
    # previously ACME actions waited in the queue invisibly.
    A.log_command(actor, dev_id, devices[dev_id].get('name', dev_id),
                  f'acme: {action} {domain}')
    A.audit_log(actor, f'acme_{action}',
                detail=f'device={dev_id} domain={domain} action_id={action_id}')
    return {'ok': True, 'action_id': action_id}


def handle_acme_force_renew(dev_id, domain):
    """POST /api/acme/<dev_id>/<domain>/renew — queue acme.sh --renew --force."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    if not A._validate_id(dev_id) or not A._acme_validate_domain(domain):
        A.respond(400, {'error': 'invalid device or domain'}); return
    store = A.load(A.ACME_STATE_FILE) or {}
    rec = store.get(dev_id) or {}
    home = rec.get('home') or '/root/.acme.sh'
    # Shell-escape domain via single quotes; domain is already validated against
    # a strict regex so this is paranoia, not the security boundary.
    safe_domain = domain.replace("'", "'\\''")
    # v4.4.0 (SECURITY): shlex.quote the agent-reported `home` path too — it was
    # interpolated raw inside the quotes, so a rogue/compromised agent could set
    # `home` to break out of the acme.sh invocation.
    acme_bin = shlex.quote(f'{home}/acme.sh')
    cmd = f"{acme_bin} --renew --force -d '{safe_domain}'"
    result = A._acme_queue_command(dev_id, 'renew', domain, cmd)
    if result:
        A.respond(200, result)


def handle_acme_revoke(dev_id, domain):
    """POST /api/acme/<dev_id>/<domain>/revoke — queue acme.sh --revoke + --remove."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    if not A._validate_id(dev_id) or not A._acme_validate_domain(domain):
        A.respond(400, {'error': 'invalid device or domain'}); return
    store = A.load(A.ACME_STATE_FILE) or {}
    rec = store.get(dev_id) or {}
    home = rec.get('home') or '/root/.acme.sh'
    safe_domain = domain.replace("'", "'\\''")
    acme_bin = shlex.quote(f'{home}/acme.sh')   # v4.4.0: quote agent-reported home
    # v4.10.0: acme.sh stores EC/ECC certs under <domain>_ecc/. Without --ecc,
    # --revoke/--remove look in the RSA dir, can't find the key, and fail with
    # "Only RSA or EC key is supported. keyfile=…/". Mirror the key type the last
    # scan recorded (Le_Keylength like 'ec-256'/'ec-384' → --ecc).
    cert = next((c for c in (rec.get('certs') or []) if c.get('domain') == domain), None)
    ecc = ' --ecc' if cert and str(cert.get('key_length', '')).startswith('ec-') else ''
    # --revoke tells LE the cert is no longer trusted; --remove drops the
    # local files so the next scan reflects the change.
    cmd = (f"{acme_bin} --revoke{ecc} -d '{safe_domain}' && "
           f"{acme_bin} --remove{ecc} -d '{safe_domain}'")
    result = A._acme_queue_command(dev_id, 'revoke', domain, cmd)
    if result:
        A.respond(200, result)


def handle_acme_cancel(dev_id, action_id):
    """POST /api/acme/<dev_id>/cancel/<action_id>

    Three cases:
      1. Still in CMDS_FILE queue (agent hasn't picked it up yet) → remove
         it from the queue, mark meta as cancelled. Action will never run.
      2. Already running on the agent (sent in a previous heartbeat,
         agent hasn't reported back yet) → we can't unkill; mark meta as
         cancelled-after-dispatch so UI stops polling and shows the state.
      3. Already completed (meta has rc) → already not pending; return 409.
    """
    A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'}); return
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', action_id or ''):
        A.respond(400, {'error': 'invalid action id'}); return
    log_path = A._acme_log_path(dev_id, action_id)
    meta_path = log_path.with_suffix('.meta.json')
    if not meta_path.exists():
        A.respond(404, {'error': 'action not found'}); return
    try:
        meta = json.loads(meta_path.read_text())
    except Exception as e:
        A.respond(500, {'error': f'meta read failed: {e}'}); return
    if meta.get('rc') is not None:
        A.respond(409, {'error': 'action already completed', 'rc': meta.get('rc')}); return
    # Try to find and remove from the pending command queue
    tag_needle = f'#acme:{action_id}#'
    removed_from_queue = False
    with A._LockedUpdate(A.CMDS_FILE) as cmds:
        queue = cmds.get(dev_id) or []
        kept = [c for c in queue if tag_needle not in c]
        if len(kept) != len(queue):
            removed_from_queue = True
            if kept:
                cmds[dev_id] = kept
            else:
                cmds.pop(dev_id, None)
    # Mark meta as cancelled regardless. UI distinguishes via rc value:
    #   -3 = cancelled before dispatch (queue removal succeeded)
    #   -4 = cancelled after dispatch (queue removal failed, agent may
    #        still complete; if it does, the rc gets overwritten on
    #        next ingestion)
    now = int(time.time())
    actor = A.current_username() or 'unknown'
    meta['rc']            = -3 if removed_from_queue else -4
    meta['done_at']       = now
    meta['cancelled_at']  = now
    meta['cancelled_by']  = actor
    try:
        meta_path.write_text(json.dumps(meta))
        # Replace the placeholder log so the UI shows the cancellation
        # in the log viewer rather than an empty file.
        log_path.write_text(
            f'(Cancelled by {actor} at {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))}.\n'
            f' {"Removed from queue before dispatch." if removed_from_queue else "Already sent to agent — dispatch cannot be undone, but UI will stop polling."})\n')
    except Exception as e:
        A.respond(500, {'error': f'meta write failed: {e}'}); return
    A.audit_log(actor, 'acme_cancel',
                f'action={action_id} domain={meta.get("domain","?")} '
                f'queue_removed={removed_from_queue}')
    A.respond(200, {
        'ok':                True,
        'removed_from_queue': removed_from_queue,
        'rc':                meta['rc'],
    })


def handle_acme_ignore(dev_id, action_id):
    """POST /api/acme/<dev_id>/ignore/<action_id>

    Permanently remove the action's log + meta from disk. Used to clean up
    stuck-pending entries that can't be cancelled (queue already empty but
    agent never reported — happens if agent crashed mid-dispatch). Unlike
    cancel, this doesn't try to manage the queue cleanly — it just makes
    the row disappear from the UI.

    Admin-only, like every other ACME mutation (cancel / force-renew /
    revoke): this destroys on-disk action state + edits the command queue, so
    a read-only role (viewer / mcp / auditor / finance — all admitted by a bare
    require_auth) must NOT reach it. The audit log records what was removed.
    """
    A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'}); return
    # v5.0.1 (SECURITY): this route isn't under /api/devices/, so the global
    # device-scope chokepoint doesn't cover it. Block cross-scope deletes the
    # same way the acme detail/log read siblings do (was an IDOR).
    A._scope_block_device(dev_id)
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', action_id or ''):
        A.respond(400, {'error': 'invalid action id'}); return
    log_path = A._acme_log_path(dev_id, action_id)
    meta_path = log_path.with_suffix('.meta.json')
    if not log_path.exists() and not meta_path.exists():
        A.respond(404, {'error': 'action not found'}); return
    # Snapshot for audit before delete
    domain = action = '?'
    try:
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            domain = meta.get('domain', '?')
            action = meta.get('action', '?')
    except Exception:
        pass
    # Also defensively remove from queue if still there
    tag_needle = f'#acme:{action_id}#'
    try:
        with A._LockedUpdate(A.CMDS_FILE) as cmds:
            queue = cmds.get(dev_id) or []
            kept = [c for c in queue if tag_needle not in c]
            if len(kept) != len(queue):
                if kept: cmds[dev_id] = kept
                else: cmds.pop(dev_id, None)
    except Exception:
        pass
    # Delete files
    for p in (log_path, meta_path):
        try:
            if p.exists(): p.unlink()
        except Exception as e:
            sys.stderr.write(f"[remotepower] acme_ignore: failed to unlink {p}: {e}\n")
    actor = A.current_username() or 'unknown'
    A.audit_log(actor, 'acme_ignore',
                f'action={action_id} domain={domain} kind={action}')
    A.respond(200, {'ok': True})


def handle_acme_issue(dev_id):
    """POST /api/acme/<dev_id>/issue — issue a new cert. Body:
       {domain, alt_names?, dns_provider, key_length?, wildcard?}.
       Wildcard is implicit when domain or alt_name starts with '*.'."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'}); return
    body = A._read_valid(A.request_models.AcmeIssueRequest)
    domain = (body.get('domain') or '').strip().lower()
    if not A._acme_validate_domain(domain):
        A.respond(400, {'error': 'invalid primary domain'}); return
    alt_names_raw = body.get('alt_names') or []
    if not isinstance(alt_names_raw, list):
        A.respond(400, {'error': 'alt_names must be a list'}); return
    alt_names = []
    for a in alt_names_raw[:20]:
        a = (a or '').strip().lower()
        if not A._acme_validate_domain(a):
            A.respond(400, {'error': f'invalid alt name: {a}'}); return
        if a != domain and a not in alt_names:
            alt_names.append(a)
    dns_provider = (body.get('dns_provider') or '').strip()
    if dns_provider not in A.ACME_DNS_PROVIDERS:
        A.respond(400, {'error': f'unknown dns provider {dns_provider!r}'}); return
    key_length = str(body.get('key_length') or '4096').strip()
    if key_length not in ('2048', '3072', '4096', 'ec-256', 'ec-384'):
        A.respond(400, {'error': 'invalid key_length'}); return
    store = A.load(A.ACME_STATE_FILE) or {}
    rec = store.get(dev_id) or {}
    home = rec.get('home') or '/root/.acme.sh'
    # Build the acme.sh command. acme.sh accepts multiple -d for SAN.
    d_args = [f"-d '{d}'" for d in [domain, *alt_names]]
    # v3.3.0: inject DNS-provider credentials from the server's central
    # store so the operator doesn't have to edit ~/.acme.sh/account.conf
    # on every device. Empty prefix when no creds are stored — the agent
    # falls back to acme.sh's normal env/config-file lookup.
    cred_prefix = A._acme_credential_env_prefix(dns_provider)
    acme_bin = shlex.quote(f'{home}/acme.sh')   # v4.4.0: quote agent-reported home
    cmd = (cred_prefix
           + f"{acme_bin} --issue --dns {dns_provider} "
           + f"{' '.join(d_args)} --keylength {key_length}")
    result = A._acme_queue_command(dev_id, 'issue', domain, cmd)
    if result:
        A.respond(200, result)
