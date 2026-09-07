"""RemotePower — Web-terminal ticket issue, session audit and host-key lookup

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


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



# ── moved out of api.py at v7.0.3 ────────────────────────────────────────────
# Three handlers, one route prefix. They were inline in api.py, and adding the
# host-key lookup pushed the inline-handler count past the ratchet ceiling —
# which is the ratchet doing its job: the documented default for a cohesive
# subsystem is its own bound module, not a raised ceiling.
#
# api globals are reached as `A.<name>` (a dynamic lookup, so the suite's
# monkeypatching of A.respond / A.load / … keeps working). Constants stay in
# api.py.
import hmac
import secrets
import time
import urllib.parse

# ─── v1.11.11: web terminal auth + audit endpoints ──────────────────────────
#
# The CGI's job in the web-terminal flow is narrow:
#   1. Re-validate the user's admin password BEFORE we let them open a shell.
#   2. Issue a short-lived single-use ticket the daemon will recognise.
#   3. Accept session-completion audit POSTs from the daemon.
#
# Everything else — the actual SSH connection, byte pumping, recording —
# is the daemon's job. The CGI never holds an SSH connection open.


def _purge_expired_webterm_tickets(tickets, now):
    """Drop tickets past their TTL. Mutates ``tickets`` and returns it."""
    expired = [t for t, meta in tickets.items()
               if meta.get('expires', 0) < now or meta.get('used')]
    for t in expired:
        tickets.pop(t, None)
    return tickets


def handle_webterm_auth():
    """``POST /api/webterm/auth`` — re-prompt admin password, issue ticket.

    Body:
        device_id      — which device to open a terminal to
        admin_password — must match the *current user's* password

    The user is already authenticated via the session token (X-Token
    header), so this isn't asking them to log in again — it's a re-auth
    challenge specifically for the terminal action. Same pattern banks
    use for "you're logged in but we want a password before this
    privileged action."

    Why not TOTP? You explicitly didn't ask for it. The spec was
    "admin password every time" and that's what this is. If you ever
    want TOTP on top, it's a small addition.

    Response:
        ``{ticket, expires, daemon_url}`` — daemon_url is the WebSocket
        endpoint the browser should connect to. We compute it from the
        request's Host header so it works the same in dev (single host)
        and production (real domain).
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.WebtermAuthRequest)
    dev_id = str(body.get('device_id', '')).strip()
    admin_password = str(body.get('admin_password', ''))

    if not dev_id or not A._validate_id(dev_id):
        A.respond(400, {'error': 'device_id required'})
    if not admin_password:
        A.respond(400, {'error': 'admin_password required'})

    # Look up the device (just to confirm it exists; we don't pass any
    # device data to the daemon — the user supplies SSH host/user/pw).
    devices = A._load_ro(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'Device not found'})
    A._scope_block_device(dev_id)   # SEC: body device_id, not under /api/devices/ — tenant/scope gate

    # W6-49: RDP-tunnel intent is gated behind an explicit opt-in — it exposes a
    # native-RDP bridge (mstsc/Remmina to localhost:PORT), not an in-browser
    # client, and is off by default.
    _intent = str(body.get('intent', '')).strip().lower()
    if _intent == 'rdp' and not A.load(A.CONFIG_FILE).get('rdp_enabled'):
        A.respond(403, {'error': 'RDP tunnelling is disabled. Enable it in Settings → Security.'})

    # Re-verify the admin's password
    users = A.load(A.USERS_FILE)
    user = users.get(actor)
    if not user:
        A.respond(403, {'error': 'User no longer exists'})
    if not A.verify_password(admin_password, user.get('password_hash', '')):
        # Audit-log the failure so a brute-force attempt against this
        # endpoint shows up. Real defence is the rate limiter on the
        # CGI; this is just visibility.
        A.audit_log(actor, 'webterm_auth_failed', f'device={dev_id}')
        A.respond(403, {'error': 'Admin password did not match'})

    # Issue ticket
    ticket = secrets.token_urlsafe(32)
    now = int(time.time())
    # v7.0.2: locked, and it has to be — the webterm DAEMON consumes from this
    # same store in another process. Unlocked, issuing a ticket while one was
    # being consumed wrote back a snapshot taken before the delete and brought
    # the consumed single-use ticket back for the rest of its 60-second window.
    # The daemon's consume() takes the storage backend's LockedUpdate, which is
    # the same primitive this dispatches to; a lock only one of two writers
    # holds is not a lock.
    with A._LockedUpdate(A.WEBTERM_TICKETS_FILE) as tickets:
        _purge_expired_webterm_tickets(tickets, now)
        tickets[ticket] = {
            'actor':     actor,
            'device_id': dev_id,
            'created':   now,
            'expires':   now + A.WEBTERM_TICKET_TTL,
            'used':      False,
            'source_ip': A._get_client_ip(),
        }
    A.audit_log(actor, 'webterm_ticket_issued',
              f'device={dev_id} expires_in={A.WEBTERM_TICKET_TTL}s')

    # Build daemon URL. nginx proxies /api/webterm/connect to the daemon,
    # so the browser uses the same host as the dashboard (real TLS,
    # real cookies). In dev / non-nginx setups the user can override
    # via config.
    cfg = A.load(A.CONFIG_FILE)
    daemon_url_override = cfg.get('webterm_daemon_url', '')
    if daemon_url_override:
        daemon_url = daemon_url_override
    else:
        # Same host as the request. The browser sets the protocol to wss
        # automatically when the page is HTTPS.
        daemon_url = '/api/webterm/connect'

    A.respond(200, {
        'ticket':     ticket,
        'expires':    now + A.WEBTERM_TICKET_TTL,
        'daemon_url': daemon_url,
        'device':     {
            'id':       dev_id,
            'name':     devices[dev_id].get('name', dev_id),
            'ip':       devices[dev_id].get('ip', ''),
            'hostname': devices[dev_id].get('hostname', ''),
        },
    })


def handle_webterm_session_audit():
    """``POST /api/webterm/audit`` — daemon reports session completion.

    Called by the daemon when an SSH session ends, with metadata about
    the session (duration, byte counts, exit reason). The CGI logs it
    to the audit log so it shows up alongside the rest of the audit
    trail. Authenticated via a shared secret stored in config —
    daemon and CGI both read the same config.json so this works
    automatically once the deploy script generates the secret.
    """
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.WebtermSessionAuditRequest)

    # Daemon authenticates with a shared secret rather than session
    # tokens — the daemon doesn't have a session token, it's a system
    # service. The secret is generated once by the deploy script and
    # written to config.json (only readable by the rp-www user) and to
    # /etc/remotepower/webterm-secret (only readable by the daemon's
    # user). If they match, it's the legit daemon talking.
    cfg = A.load(A.CONFIG_FILE)
    expected = cfg.get('webterm_daemon_secret', '')
    provided = A._env('HTTP_X_WEBTERM_SECRET', '')
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        A.respond(403, {'error': 'Daemon secret mismatch'})

    actor       = A._sanitize_str(body.get('actor', 'unknown'), 64)
    dev_id      = A._sanitize_str(body.get('device_id', ''), 64)
    ssh_user    = A._sanitize_str(body.get('ssh_user', ''), 64)
    ssh_host    = A._sanitize_str(body.get('ssh_host', ''), 256)
    duration_s  = int(body.get('duration_s', 0)) if isinstance(body.get('duration_s'), (int, float)) else 0
    bytes_in    = int(body.get('bytes_in', 0))   if isinstance(body.get('bytes_in'), int) else 0
    bytes_out   = int(body.get('bytes_out', 0))  if isinstance(body.get('bytes_out'), int) else 0
    reason      = A._sanitize_str(body.get('reason', ''), 128)
    session_id  = A._sanitize_str(body.get('session_id', ''), 64)
    # v7.0.3: whether the SSH host key matched what RemotePower has on file.
    # A session that connected to a host nothing vouches for is a different
    # event from one that did, and the audit trail is where that belongs.
    hk_state    = A._sanitize_str(body.get('host_key_state', ''), 16)
    hk_fp       = A._sanitize_str(body.get('host_key_fp', ''), 80)
    detail = (f'device={dev_id} ssh_user={ssh_user}@{ssh_host} '
              f'duration={duration_s}s bytes_in={bytes_in} bytes_out={bytes_out} '
              f'reason={reason} session_id={session_id}'
              + (f' host_key={hk_state}' if hk_state else '')
              + (f' fp={hk_fp}' if hk_fp else ''))
    A.audit_log(actor, 'webterm_session', detail[:600])
    A.respond(200, {'ok': True})


def handle_webterm_hostkeys():
    """``GET /api/webterm/hostkeys?device_id=…`` — the host-key fingerprints
    RemotePower has on file for a device.

    v7.0.3 (SECURITY). The web terminal connected with host-key checking off
    while sending the operator's SSH password, so anything able to answer on
    that address and port — an ARP or DHCP spoof on the management segment, a
    stale DNS record, a re-provisioned IP — received the password on the first
    connect, because password authentication happens after an unverified key
    exchange. There was no setting to turn checking on.

    The trust anchor already existed and nothing used it: the agent reports
    `sysinfo.ssh_hostkeys` as `{keytype: 'SHA256:…'}`, `safe_si` persists it,
    and the product fires `hostkey_changed` when it moves. The daemon takes its
    connection parameters from the browser, not from here, so it needs a way to
    ask what this device's keys should be. This is it.

    Authenticated with the daemon shared secret, like the audit endpoint. It
    returns fingerprints, which are public by nature, for one device at a time.
    """
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    cfg = A._config_ro() or {}
    expected = cfg.get('webterm_daemon_secret', '')
    provided = A._env('HTTP_X_WEBTERM_SECRET', '')
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        A.respond(403, {'error': 'Daemon secret mismatch'})
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    dev_id = A._sanitize_str((qs.get('device_id') or [''])[0], 64)
    if not dev_id:
        A.respond(400, {'error': 'device_id required'})
    dev = (A._load_ro(A.DEVICES_FILE) or {}).get(dev_id) or {}
    keys = ((dev.get('sysinfo') or {}).get('ssh_hostkeys') or {})
    fingerprints = sorted({str(v) for v in keys.values()
                           if isinstance(v, str) and v.startswith('SHA256:')})
    # `known` says whether RemotePower has an opinion at all. An empty list and
    # "we have never seen this host" are different answers, and the daemon has
    # to tell them apart to decide between refusing and warning.
    A.respond(200, {'ok': True, 'device_id': dev_id,
                  'known': bool(fingerprints),
                  'fingerprints': fingerprints})
