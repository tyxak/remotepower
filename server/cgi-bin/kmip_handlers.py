"""RemotePower — KMIP key-management server (sidecar control plane) (v6.4.0).

The `remotepower-kmipd` sidecar is a stateless TTLV/mTLS protocol shim; THIS
module is where the actual KMIP server lives: CA + server/client certificate
issuance (cryptography x509, RSA — maximum appliance compatibility), the
managed-object store (key material encrypted at rest with AES-256-GCM via the
cmdb_vault primitives, under a dedicated random master key held only by the
API process), per-client object scoping, the KMIP activity log (every
connect / auth failure / operation is traceable), and the passphrase-encrypted
recovery export/import.

A bound-module carve-out following the dmarc/acme/webhook_log pattern: api.py
execs a PRIVATE instance, binds its own ``globals()`` here (every api service
reached as ``A.<name>``), then re-imports the names back so the route table
resolves unchanged. The KMIP_* file constants stay in api.py, read via A.

Security model (documented in docs/kmip.md):
  * Admin routes: global admins only — a tenant admin 404s (KMIP is host
    infrastructure, like the storage backend; it is not tenant-scoped).
  * Daemon routes (/api/kmip/daemon/*): authenticated by a shared secret,
    compared constant-time. Resolved env → /etc/remotepower/kmipd.env → the
    config store (`kmip_daemon_secret`, auto-redacted by the secret-name
    scrub). systemd feeds the file to the daemon AS ROOT, so it stays 0600
    root:root and the API never needs to read it — it keeps its own copy.
    Requiring the app to read that file is what made the page report
    "Not installed" while the daemon was running perfectly well.
  * Key material: returned ONLY on the daemon `get` op (to serve a KMIP Get
    to an mTLS-authenticated client). Admin/auditor endpoints see metadata
    only, never material.
  * Objects are scoped to the OWNING client: one appliance can never Get or
    Locate another appliance's keys. Certificate re-issue keeps the client id
    (and therefore its objects) — that is the cert-loss recovery path.
  * The master key file (KMIP_MASTER_KEY_FILE, a REAL 0600 file — one of the
    documented non-storage-key exceptions, like STORAGE_MARKER_FILE) is
    excluded from scheduled backups; it travels only inside the
    passphrase-encrypted recovery bundle. A stolen backup therefore holds
    only ciphertext.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path


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


# KMIP object states (string ↔ KMIP State enumeration).
_KMIP_STATES = {'pre_active': 1, 'active': 2, 'deactivated': 3,
                'compromised': 4, 'destroyed': 5}
_KMIP_CLIENT_KINDS = ('synology', 'truenas', 'vsphere', 'generic')

_KMIP_CA_DAYS = 3650
_KMIP_SERVER_CERT_DAYS = 1460
_KMIP_CLIENT_CERT_DAYS = 1825
_KMIP_BUNDLE_FORMAT = 'rp-kmip-bundle-1'


# ── secret / master key ──────────────────────────────────────────────────────
def _kmip_secret_file():
    return Path(os.environ.get('RP_KMIP_SECRET_FILE',
                               '/etc/remotepower/kmipd.env'))


def _kmip_secret_file_exists():
    """True if the env file is present, regardless of whether we can READ it —
    'there but unreadable' and 'not there at all' need different advice."""
    try:
        return _kmip_secret_file().exists()
    except OSError:
        return False


def _kmip_secret_from_file():
    """The secret as written in the env file, or None if absent/unreadable.
    Distinguishes the two so the UI can say WHICH it is."""
    try:
        for line in _kmip_secret_file().read_text().splitlines():
            line = line.strip()
            if line.startswith('RP_KMIP_SECRET='):
                return line.split('=', 1)[1].strip().strip('"\'')
    except OSError:
        return None
    return None


def _kmip_daemon_secret():
    """The shared daemon secret, resolved so a file-permission problem can
    never blind the API.

    Order: env (docker) → the env FILE → the config store.

    The file is preferred over config because systemd feeds that exact value
    to the daemon, so trusting it keeps both sides in step; when we can read
    it we adopt it into config. Config is the fallback for the normal case
    where the file is 0600 root:root — systemd reads it as root for the
    daemon, so it never needs to be readable by the app user, and an earlier
    design that REQUIRED the app to read it was wrong: the install snippet
    derived the group from `api.env`, which is root:root because only systemd
    ever reads THAT too, so the secret landed unreadable and the page said
    "Not installed" while the daemon ran happily.
    """
    env = (os.environ.get('RP_KMIP_SECRET') or '').strip()
    if env:
        return env
    from_file = _kmip_secret_from_file()
    if from_file:
        if (A._config_ro() or {}).get('kmip_daemon_secret') != from_file:
            try:
                with A._LockedUpdate(A.CONFIG_FILE) as cfg:
                    cfg['kmip_daemon_secret'] = from_file
            except Exception:  # nosec B110 — see below
                # Deliberate: adopting the secret into config is an
                # OPTIMISATION. If the config is locked or read-only we still
                # return the file's value, so auth keeps working; raising here
                # would turn a cache miss into an outage.
                pass
        return from_file
    return str((A._config_ro() or {}).get('kmip_daemon_secret') or '').strip()


def _kmip_require_daemon():
    """Gate the /api/kmip/daemon/* endpoints on the shared secret."""
    secret = _kmip_daemon_secret()
    got = (A._env('HTTP_X_KMIP_SECRET') or '').strip()
    if not secret or not got or not hmac.compare_digest(secret, got):
        A.respond(403, {'error': 'KMIP daemon secret missing or wrong'})


def _kmip_require_admin():
    """Global admins only — KMIP is host infrastructure, not tenant-scoped.
    A tenant admin gets 404 (not 403) so the surface doesn't leak."""
    actor = A.require_admin_auth()
    if A._tenant_gate():
        A.respond(404, {'error': 'Not found'})
    return actor


def _kmip_require_viewer():
    """Read endpoints: global admin or auditor."""
    actor = A.require_admin_or_auditor_auth()
    if A._tenant_gate():
        A.respond(404, {'error': 'Not found'})
    return actor


def _kmip_master_key(create=False):
    """The 32-byte at-rest master key. A REAL file (not a storage key) so it
    can be excluded from generic backups — it travels only in the recovery
    bundle. 0600, API user only; the daemon never reads it."""
    path = A.KMIP_MASTER_KEY_FILE
    try:
        if path.exists():
            key = bytes.fromhex(path.read_text().strip())
            if len(key) == 32:
                return key
    except (OSError, ValueError):
        pass
    if not create:
        return None
    key = secrets.token_bytes(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(key.hex() + '\n')
    return key


# ── x509 issuance (cryptography, in-process — mirrors _tls_gen_self_signed) ──
def _kmip_x509():
    try:
        import datetime as _dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        return x509, hashes, serialization, rsa, NameOID, ExtendedKeyUsageOID, _dt
    except ImportError:
        A.respond(500, {'error': "Python 'cryptography' package is required "
                                 'for the KMIP server — re-run install-server.sh'})


def _kmip_key_usage(x509, cert_sign=False):
    return x509.KeyUsage(
        digital_signature=not cert_sign, content_commitment=False,
        key_encipherment=not cert_sign, data_encipherment=False,
        key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign,
        encipher_only=False, decipher_only=False)


def _kmip_gen_ca():
    """Fresh RSA-3072 CA. Returns (cert_pem, key_pem, sha256_fp, not_after)."""
    x509, hashes, ser, rsa, NameOID, _eku, dt = _kmip_x509()
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'RemotePower'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'RemotePower KMIP CA')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=_KMIP_CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .add_extension(_kmip_key_usage(x509, cert_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(ser.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
        ser.NoEncryption()).decode()
    fp = hashlib.sha256(cert.public_bytes(ser.Encoding.DER)).hexdigest()
    return cert_pem, key_pem, fp, int(cert.not_valid_after_utc.timestamp())


def _kmip_issue_cert(cn, ca_cert_pem, ca_key_pem, days, server=False,
                     san_hosts=None):
    """RSA-2048 leaf signed by the KMIP CA. Returns (cert_pem, key_pem,
    sha256_fingerprint, not_after_epoch)."""
    import ipaddress
    x509, hashes, ser, rsa, NameOID, ExtendedKeyUsageOID, dt = _kmip_x509()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = ser.load_pem_private_key(ca_key_pem.encode(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'RemotePower'),
        x509.NameAttribute(NameOID.COMMON_NAME, str(cn)[:64] or 'kmip')])
    now = dt.datetime.now(dt.timezone.utc)
    eku = (ExtendedKeyUsageOID.SERVER_AUTH if server
           else ExtendedKeyUsageOID.CLIENT_AUTH)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=5))
               .not_valid_after(now + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True)
               .add_extension(_kmip_key_usage(x509), critical=True)
               .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))
    if server and san_hosts:
        sans = []
        for h in san_hosts:
            h = str(h).strip()
            if not h:
                continue
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(h)))
            except ValueError:
                sans.append(x509.DNSName(h))
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(ser.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
        ser.NoEncryption()).decode()
    fp = hashlib.sha256(cert.public_bytes(ser.Encoding.DER)).hexdigest()
    return cert_pem, key_pem, fp, int(cert.not_valid_after_utc.timestamp())


# ── activity log ─────────────────────────────────────────────────────────────
def _kmip_log(kind, **fields):
    """Append one activity-log row (capped). The trail that makes every KMIP
    action traceable — admin actions, daemon lifecycle, per-client ops."""
    entry = {'ts': int(time.time()), 'kind': str(kind)}
    for k, v in fields.items():
        if v is not None:
            entry[k] = v
    with A._LockedUpdate(A.KMIP_LOG_FILE) as store:
        entries = store.setdefault('entries', [])
        entries.append(entry)
        if len(entries) > A.MAX_KMIP_LOG:
            del entries[:len(entries) - A.MAX_KMIP_LOG]


def _kmip_bump_rev(store):
    store['rev'] = int(store.get('rev') or 0) + 1


def _kmip_hosts(store):
    """SAN host list for the server certificate: configured hosts, else the
    request host (so the default cert matches how the operator reaches us)."""
    hosts = [h for h in (store.get('hosts') or []) if str(h).strip()]
    if not hosts:
        req = (A._request_base_url() or '').split('//')[-1].split('/')[0]
        req = req.split(':')[0]
        hosts = sorted({h for h in (req, 'localhost') if h})
    return hosts


def _kmip_ensure_pki(store, key):
    """Generate CA + server cert on first enable (idempotent)."""
    changed = False
    if not (store.get('ca') or {}).get('cert_pem'):
        cert_pem, key_pem, fp, not_after = A._kmip_gen_ca()
        store['ca'] = {'cert_pem': cert_pem,
                       'key_enc': A.cmdb_vault.encrypt(key, key_pem),
                       'fingerprint': fp, 'created': int(time.time()),
                       'not_after': not_after}
        changed = True
    if not (store.get('server_cert') or {}).get('cert_pem'):
        ca = store['ca']
        ca_key_pem = A.cmdb_vault.decrypt(key, ca['key_enc'])
        hosts = _kmip_hosts(store)
        cert_pem, key_pem, fp, not_after = A._kmip_issue_cert(
            'remotepower-kmip', ca['cert_pem'], ca_key_pem,
            _KMIP_SERVER_CERT_DAYS, server=True, san_hosts=hosts)
        store['server_cert'] = {'cert_pem': cert_pem,
                                'key_enc': A.cmdb_vault.encrypt(key, key_pem),
                                'fingerprint': fp, 'hosts': hosts,
                                'created': int(time.time()),
                                'not_after': not_after}
        changed = True
    return changed


# ── admin endpoints ──────────────────────────────────────────────────────────
def handle_kmip_status():
    """GET /api/kmip/status — overview for the KMIP page."""
    _kmip_require_viewer()
    store = A.load(A.KMIP_FILE) or {}
    objs = (A.load(A.KMIP_OBJECTS_FILE) or {}).get('objects') or {}
    log_store = A.load(A.KMIP_LOG_FILE) or {}
    clients = store.get('clients') or {}
    daemon = store.get('daemon') or {}
    now = int(time.time())
    last_fetch = int(daemon.get('last_state_fetch') or 0)
    ca = store.get('ca') or {}
    sc = store.get('server_cert') or {}
    # Why the sidecar isn't visible, phrased so the operator can act. A bare
    # "not installed" was actively misleading in the case where the daemon is
    # running fine and only the API's view of the secret is broken.
    _secret = _kmip_daemon_secret()
    _file_secret = _kmip_secret_from_file()
    _secret_hint = None
    if not _secret:
        if _kmip_secret_file_exists():
            _secret_hint = (
                f'{_kmip_secret_file()} exists but this server cannot read it '
                'and no secret is stored in the config. Re-run the install '
                'snippet below — it writes the file and records the secret here.')
        else:
            # nosec B105 — a UI hint string, not a credential (bandit
            # matches on the '_secret_hint' variable name).
            _secret_hint = ('Run the install snippet to set up the '
                            'sidecar.')  # nosec B105
    elif _file_secret is None and not _kmip_secret_file_exists():
        _secret_hint = (
            f'A secret is configured but {_kmip_secret_file()} is missing, so '
            'the sidecar has nothing to authenticate with — run the install '
            'snippet on this host.')

    A.respond(200, {
        'enabled': bool(store.get('enabled')),
        'port': int(store.get('port') or 5696),
        'secret_installed': bool(_secret),
        'secret_hint': _secret_hint,
        'master_key': _kmip_master_key() is not None,
        'daemon_alive': bool(last_fetch and now - last_fetch < 90),
        'daemon_last_seen': last_fetch or None,
        'daemon_started': daemon.get('last_started'),
        'ca': ({'fingerprint': ca.get('fingerprint'),
                'not_after': ca.get('not_after'),
                'created': ca.get('created')} if ca.get('cert_pem') else None),
        'server_cert': ({'hosts': sc.get('hosts') or [],
                         'not_after': sc.get('not_after')}
                        if sc.get('cert_pem') else None),
        'counts': {
            'clients': len(clients),
            'clients_active': sum(1 for c in clients.values()
                                  if not c.get('revoked')),
            'objects': len(objs),
            'keys_active': sum(1 for o in objs.values()
                               if o.get('state') == 'active'),
            'log': len(log_store.get('entries') or []),
        },
    })


def handle_kmip_config():
    """POST /api/kmip/config — enable/disable + port + SAN hosts. First
    enable generates the master key, the CA and the server certificate."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.KmipConfigRequest)
    enabled = bool(body.get('enabled'))
    port = int(body.get('port') or 5696)
    if not (1 <= port <= 65535):
        A.respond(400, {'error': 'port out of range'})
    hosts_raw = body.get('hosts')
    hosts = None
    if isinstance(hosts_raw, str):
        hosts = [h.strip() for h in hosts_raw.replace(',', ' ').split()
                 if h.strip()][:16]
    key = _kmip_master_key(create=enabled)
    if enabled and key is None:
        A.respond(500, {'error': 'could not create the KMIP master key file'})
    reissue = False
    with A._LockedUpdate(A.KMIP_FILE) as store:
        store['enabled'] = enabled
        store['port'] = port
        if hosts is not None and hosts != (store.get('hosts') or []):
            store['hosts'] = hosts
            # Re-issue the server cert so its SANs match the new hosts.
            store.pop('server_cert', None)
            reissue = True
        if enabled:
            A._kmip_ensure_pki(store, key)
        _kmip_bump_rev(store)
    A.audit_log(actor, 'kmip_config',
                detail=f'enabled={enabled} port={port}'
                       + (' hosts-changed' if reissue else ''),
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='config', actor=actor, ok=True,
                detail=f'enabled={enabled} port={port}')
    A.handle_kmip_status()


def handle_kmip_install_snippet():
    """GET /api/kmip/install — the root install snippet for the sidecar.

    The secret is generated ONCE and persisted in config (`kmip_daemon_secret`,
    auto-redacted from GET /api/config by the secret-name scrub). Two reasons
    it lives here rather than only in the env file:
      * The API must know it without reading a root-owned file — systemd feeds
        the file to the daemon as root, so it can stay 0600 root:root.
      * Re-opening this dialog must NOT mint a new secret: that would silently
        invalidate a working install the moment an operator looked twice.
    Admin-only, same trust model as the agent-install one-liner.
    """
    _kmip_require_admin()
    secret = _kmip_daemon_secret()
    if not secret:
        secret = secrets.token_hex(32)
        with A._LockedUpdate(A.CONFIG_FILE) as cfg:
            cfg['kmip_daemon_secret'] = secret
    path = str(_kmip_secret_file())
    # 0600 root:root on purpose — systemd reads EnvironmentFile as root, so no
    # group grant is needed and none should be given.
    snippet = (
        '# Run on the RemotePower server as root, from the repo checkout:\n'
        f"printf 'RP_KMIP_SECRET=%s\\n' '{secret}' | "
        f'sudo install -o root -g root -m 600 /dev/stdin {path}\n'
        'sudo install -m 755 server/kmip/remotepower-kmipd.py '
        '/usr/local/bin/remotepower-kmipd\n'
        'sudo install -m 644 packaging/remotepower-kmipd.service '
        '/etc/systemd/system/\n'
        'sudo systemctl daemon-reload && '
        'sudo systemctl enable --now remotepower-kmipd\n'
        '# Or simply: sudo ./install-server.sh --with-kmip\n')
    A.respond(200, {'snippet': snippet, 'secret_file': path,
                    'already_installed': _kmip_secret_from_file() is not None})


def handle_kmip_clients():
    """GET /api/kmip/clients — registered appliance clients (scrubbed)."""
    _kmip_require_viewer()
    store = A.load(A.KMIP_FILE) or {}
    objs = (A.load(A.KMIP_OBJECTS_FILE) or {}).get('objects') or {}
    per_client = {}
    for o in objs.values():
        ocid = o.get('client_id')
        if ocid:
            per_client[ocid] = per_client.get(ocid, 0) + 1
    out = []
    for cid, c in (store.get('clients') or {}).items():
        out.append({'id': cid, 'name': c.get('name'), 'kind': c.get('kind'),
                    'fingerprint': c.get('fingerprint'),
                    'created': c.get('created'),
                    'created_by': c.get('created_by'),
                    'revoked': bool(c.get('revoked')),
                    'revoked_at': c.get('revoked_at'),
                    'last_seen': c.get('last_seen'),
                    'last_peer': c.get('last_peer'),
                    'not_after': c.get('not_after'),
                    'objects': per_client.get(cid, 0)})
    out.sort(key=lambda c: c.get('created') or 0, reverse=True)
    A.respond(200, {'clients': out})


def handle_kmip_client_create():
    """POST /api/kmip/clients — register an appliance + issue its mTLS cert.
    The private key is returned ONCE and never stored server-side."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.KmipClientCreateRequest)
    name = str(body.get('name') or '').strip()[:64]
    kind = str(body.get('kind') or 'generic').strip().lower()
    if not name:
        A.respond(400, {'error': 'name required'})
    if kind not in _KMIP_CLIENT_KINDS:
        A.respond(400, {'error': 'kind must be one of: '
                                 + ', '.join(_KMIP_CLIENT_KINDS)})
    key = _kmip_master_key()
    if key is None:
        A.respond(400, {'error': 'KMIP is not set up yet — enable it first'})
    # Non-numeric by construction (data-arg coercion rule): 'kc-' prefix.
    cid = 'kc-' + secrets.token_hex(6)
    with A._LockedUpdate(A.KMIP_FILE) as store:
        clients = store.setdefault('clients', {})
        if len(clients) >= A.MAX_KMIP_CLIENTS:
            A.respond(400, {'error': 'client cap reached'})
        if not (store.get('ca') or {}).get('cert_pem'):
            A._kmip_ensure_pki(store, key)
        ca = store['ca']
        ca_key_pem = A.cmdb_vault.decrypt(key, ca['key_enc'])
        cert_pem, key_pem, fp, not_after = A._kmip_issue_cert(
            f'{name} ({kind})', ca['cert_pem'], ca_key_pem,
            _KMIP_CLIENT_CERT_DAYS)
        clients[cid] = {'name': name, 'kind': kind, 'fingerprint': fp,
                        'cert_pem': cert_pem, 'created': int(time.time()),
                        'created_by': actor, 'revoked': False,
                        'not_after': not_after}
        ca_pem = ca['cert_pem']
        _kmip_bump_rev(store)
    A.audit_log(actor, 'kmip_client_create', detail=f'{name} ({kind}) {cid}',
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='client_create', actor=actor, client_id=cid,
                client=name, ok=True)
    A.respond(200, {'id': cid, 'name': name, 'kind': kind, 'fingerprint': fp,
                    'ca_pem': ca_pem, 'cert_pem': cert_pem,
                    'key_pem': key_pem, 'not_after': not_after})


def _kmip_client_or_404(store, cid):
    c = (store.get('clients') or {}).get(cid)
    if not c:
        A.respond(404, {'error': 'no such KMIP client'})
    return c


def handle_kmip_client_revoke(cid):
    """POST /api/kmip/clients/<cid>/revoke — the daemon rejects the client
    on its next state refresh (≤30 s)."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    with A._LockedUpdate(A.KMIP_FILE) as store:
        c = A._kmip_client_or_404(store, cid)
        c['revoked'] = True
        c['revoked_at'] = int(time.time())
        _kmip_bump_rev(store)
        name = c.get('name')
    A.audit_log(actor, 'kmip_client_revoke', detail=f'{name} {cid}',
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='client_revoke', actor=actor, client_id=cid,
                client=name, ok=True)
    A.respond(200, {'ok': True})


def handle_kmip_client_reissue(cid):
    """POST /api/kmip/clients/<cid>/reissue — new cert + key, SAME client id,
    so the appliance keeps access to its objects (the cert-loss recovery
    path). Un-revokes: re-issuing is an explicit re-trust decision."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    key = _kmip_master_key()
    if key is None:
        A.respond(400, {'error': 'KMIP is not set up yet — enable it first'})
    with A._LockedUpdate(A.KMIP_FILE) as store:
        c = A._kmip_client_or_404(store, cid)
        ca = store.get('ca') or {}
        if not ca.get('cert_pem'):
            A.respond(400, {'error': 'KMIP CA missing — enable KMIP first'})
        ca_key_pem = A.cmdb_vault.decrypt(key, ca['key_enc'])
        cert_pem, key_pem, fp, not_after = A._kmip_issue_cert(
            f"{c.get('name')} ({c.get('kind')})", ca['cert_pem'], ca_key_pem,
            _KMIP_CLIENT_CERT_DAYS)
        c['fingerprint'] = fp
        c['cert_pem'] = cert_pem
        c['not_after'] = not_after
        c['revoked'] = False
        c.pop('revoked_at', None)
        ca_pem = ca['cert_pem']
        name = c.get('name')
        _kmip_bump_rev(store)
    A.audit_log(actor, 'kmip_client_reissue', detail=f'{name} {cid}',
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='client_reissue', actor=actor, client_id=cid,
                client=name, ok=True)
    A.respond(200, {'id': cid, 'fingerprint': fp, 'ca_pem': ca_pem,
                    'cert_pem': cert_pem, 'key_pem': key_pem,
                    'not_after': not_after})


def handle_kmip_keys():
    """GET /api/kmip/keys — managed-object inventory. Metadata ONLY —
    key material is never readable through the admin API."""
    _kmip_require_viewer()
    store = A.load(A.KMIP_OBJECTS_FILE) or {}
    kstore = A.load(A.KMIP_FILE) or {}
    clients = kstore.get('clients') or {}
    out = []
    for uid, o in (store.get('objects') or {}).items():
        cid = o.get('client_id')
        out.append({'uid': uid, 'name': o.get('name'),
                    'object_type': o.get('object_type'),
                    'algorithm': o.get('algorithm'),
                    'length': o.get('length'),
                    'state': o.get('state'),
                    'client_id': cid,
                    'client': (clients.get(cid) or {}).get('name'),
                    'created': o.get('created'),
                    'last_access': o.get('last_access'),
                    'access_count': o.get('access_count') or 0})
    out.sort(key=lambda o: o.get('created') or 0, reverse=True)
    A.respond(200, {'keys': out})


def handle_kmip_key_destroy(uid):
    """DELETE /api/kmip/keys/<uid> — admin override destroy (the appliance
    normally destroys its own keys via KMIP). Material is dropped; the
    metadata row stays as a tombstone for the audit trail."""
    actor = _kmip_require_admin()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    now = int(time.time())
    with A._LockedUpdate(A.KMIP_OBJECTS_FILE) as store:
        objs = store.get('objects') or {}
        o = objs.get(uid)
        if not o:
            A.respond(404, {'error': 'no such object'})
        o.pop('material', None)
        o['state'] = 'destroyed'
        o['state_enum'] = _KMIP_STATES['destroyed']
        o['destroyed'] = now
        o['updated'] = now
    A.audit_log(actor, 'kmip_key_destroy', detail=f'uid={uid}',
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='destroy', actor=actor, uid=uid, ok=True,
                detail='admin override')
    A.respond(200, {'ok': True})


def handle_kmip_log_list():
    """GET /api/kmip/log — the KMIP activity log (newest first)."""
    _kmip_require_viewer()
    qs = A._env('QUERY_STRING', '') or ''
    n = 200
    for part in qs.split('&'):
        if part.startswith('n='):
            try:
                n = max(1, min(1000, int(part[2:])))
            except ValueError:
                pass
    store = A.load(A.KMIP_LOG_FILE) or {}
    entries = list(store.get('entries') or [])[-n:]
    entries.reverse()
    A.respond(200, {'entries': entries})


# ── recovery export / import ─────────────────────────────────────────────────
def handle_kmip_export():
    """POST /api/kmip/export — passphrase-encrypted recovery bundle (CA,
    server cert, clients, all key objects, master key). The ONLY place the
    master key ever leaves the box — scheduled backups exclude it."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    import backup_crypto
    body = A._read_valid(A.request_models.KmipExportRequest)
    passphrase = str(body.get('passphrase') or '')
    if len(passphrase) < 12:
        A.respond(400, {'error': 'passphrase must be at least 12 characters'})
    key = _kmip_master_key()
    if key is None:
        A.respond(400, {'error': 'KMIP is not set up yet — nothing to export'})
    bundle = {
        'format': _KMIP_BUNDLE_FORMAT,
        'exported': int(time.time()),
        'exported_by': actor,
        'server_version': A.SERVER_VERSION,
        'master_key_hex': key.hex(),
        'kmip': A.load(A.KMIP_FILE) or {},
        'objects': A.load(A.KMIP_OBJECTS_FILE) or {},
    }
    raw = json.dumps(bundle).encode()
    with tempfile.TemporaryDirectory(prefix='rp-kmip-') as td:
        src = Path(td) / 'bundle.json'
        dst = Path(td) / 'bundle.enc'
        src.write_bytes(raw)
        try:
            backup_crypto.encrypt_file(src, dst, passphrase)
        except backup_crypto.BackupCryptoError as e:
            A.respond(500, {'error': str(e)})
        data = dst.read_bytes()
    A.audit_log(actor, 'kmip_export', detail=f'{len(data)} bytes',
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='export', actor=actor, ok=True)
    fname = f'kmip-recovery-{time.strftime("%Y%m%d-%H%M%S")}.rpkmip'
    print('Status: 200 OK')
    print('Content-Type: application/octet-stream')
    print(f'Content-Disposition: attachment; filename="{fname}"')
    print(f'Content-Length: {len(data)}')
    print('Cache-Control: no-store')
    print('X-Content-Type-Options: nosniff')
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_kmip_import():
    """POST /api/kmip/import — restore from a recovery bundle. Refuses to
    overwrite a live store unless `confirm` is set (explicit decision, no
    silent clobber)."""
    actor = _kmip_require_admin()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    import backup_crypto
    body = A._read_valid(A.request_models.KmipImportRequest)
    passphrase = str(body.get('passphrase') or '')
    b64 = str(body.get('bundle_b64') or '')
    if not passphrase or not b64:
        A.respond(400, {'error': 'passphrase and bundle_b64 required'})
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        A.respond(400, {'error': 'bundle_b64 is not valid base64'})
    with tempfile.TemporaryDirectory(prefix='rp-kmip-') as td:
        src = Path(td) / 'bundle.enc'
        dst = Path(td) / 'bundle.json'
        src.write_bytes(blob)
        try:
            backup_crypto.decrypt_file(src, dst, passphrase)
        except backup_crypto.BackupCryptoError:
            A.respond(400, {'error': 'decryption failed — wrong passphrase '
                                     'or corrupt bundle'})
        try:
            bundle = json.loads(dst.read_text())
        except ValueError:
            A.respond(400, {'error': 'bundle is not valid JSON'})
    if not isinstance(bundle, dict) \
            or bundle.get('format') != _KMIP_BUNDLE_FORMAT:
        A.respond(400, {'error': 'not a RemotePower KMIP recovery bundle'})
    try:
        mk = bytes.fromhex(str(bundle.get('master_key_hex') or ''))
        if len(mk) != 32:
            raise ValueError
    except ValueError:
        A.respond(400, {'error': 'bundle master key is corrupt'})
    existing = A.load(A.KMIP_OBJECTS_FILE) or {}
    if existing.get('objects') and not body.get('confirm'):
        A.respond(409, {'error': 'this server already holds KMIP objects — '
                                 'pass confirm=true to replace them',
                        'needs_confirm': True})
    # Master key first (a crash between the two writes must never leave
    # objects that no key can decrypt).
    fd = os.open(str(A.KMIP_MASTER_KEY_FILE),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(mk.hex() + '\n')
    kmip_store = bundle.get('kmip') if isinstance(bundle.get('kmip'), dict) else {}
    obj_store = (bundle.get('objects')
                 if isinstance(bundle.get('objects'), dict) else {})
    with A._LockedUpdate(A.KMIP_FILE) as store:
        store.clear()
        store.update(kmip_store)
        _kmip_bump_rev(store)
    with A._LockedUpdate(A.KMIP_OBJECTS_FILE) as store:
        store.clear()
        store.update(obj_store)
    A.audit_log(actor, 'kmip_import',
                detail=f"{len(obj_store.get('objects') or {})} objects",
                source_ip=A._get_client_ip())
    A._kmip_log('admin', op='import', actor=actor, ok=True,
                detail=f"{len(obj_store.get('objects') or {})} objects restored")
    A.respond(200, {'ok': True,
                    'objects': len(obj_store.get('objects') or {}),
                    'clients': len(kmip_store.get('clients') or {})})


# ── daemon endpoints (shared-secret gated) ───────────────────────────────────
def handle_kmip_daemon_state():
    """GET /api/kmip/daemon/state — TLS material + client registry for the
    sidecar. The ONLY place the server TLS key leaves the store (loopback,
    secret-authed). Also serves as the daemon liveness heartbeat."""
    _kmip_require_daemon()
    store = A.load(A.KMIP_FILE) or {}
    key = _kmip_master_key()
    resp = {'enabled': bool(store.get('enabled')),
            'rev': int(store.get('rev') or 0),
            'port': int(store.get('port') or 5696),
            'clients': [
                {'id': cid, 'name': c.get('name'), 'kind': c.get('kind'),
                 'fingerprint': c.get('fingerprint'),
                 'revoked': bool(c.get('revoked'))}
                for cid, c in (store.get('clients') or {}).items()]}
    ca = store.get('ca') or {}
    sc = store.get('server_cert') or {}
    if key is not None and ca.get('cert_pem') and sc.get('cert_pem'):
        try:
            resp['ca_pem'] = ca['cert_pem']
            resp['server_cert_pem'] = sc['cert_pem']
            resp['server_key_pem'] = A.cmdb_vault.decrypt(key, sc['key_enc'])
        except A.cmdb_vault.VaultError:
            resp.pop('server_key_pem', None)
    with A._LockedUpdate(A.KMIP_FILE) as live:
        live.setdefault('daemon', {})['last_state_fetch'] = int(time.time())
    A.respond(200, resp)


def handle_kmip_daemon_event():
    """POST /api/kmip/daemon/event — lifecycle + auth events from the
    sidecar into the activity log."""
    _kmip_require_daemon()
    body = A.get_json_obj()
    kind = str(body.get('kind') or '')[:32]
    if kind not in ('started', 'connect', 'auth_fail'):
        A.respond(400, {'error': 'unknown event kind'})
    cid = str(body.get('client_id') or '')[:32] or None
    name = None
    if kind == 'started':
        with A._LockedUpdate(A.KMIP_FILE) as store:
            store.setdefault('daemon', {})['last_started'] = int(time.time())
    if kind == 'connect' and cid:
        with A._LockedUpdate(A.KMIP_FILE) as store:
            c = (store.get('clients') or {}).get(cid)
            if c:
                c['last_seen'] = int(time.time())
                c['last_peer'] = str(body.get('peer') or '')[:64]
                name = c.get('name')
    A._kmip_log(kind, client_id=cid, client=name,
                peer=str(body.get('peer') or '')[:64] or None,
                fingerprint=str(body.get('fingerprint') or '')[:64] or None,
                detail=str(body.get('detail') or '')[:256] or None)
    A.respond(200, {'ok': True})


def _kmip_op_fail(reason, message):
    """KMIP-level failure — HTTP 200, error carried as data (the daemon maps
    it to a KMIP ResultReason)."""
    A.respond(200, {'ok': False, 'reason': reason, 'message': message})


def _kmip_object_visible(o, client_id):
    """Objects are scoped to the owning client — one appliance can never
    read another appliance's keys."""
    return o.get('client_id') == client_id


def handle_kmip_daemon_op():
    """POST /api/kmip/daemon/op — one KMIP operation from the sidecar."""
    _kmip_require_daemon()
    body = A.get_json_obj()
    cid = str(body.get('client_id') or '')
    fp = str(body.get('fingerprint') or '')
    op = str(body.get('op') or '')
    params = body.get('params') if isinstance(body.get('params'), dict) else {}

    kstore = A.load(A.KMIP_FILE) or {}
    if not kstore.get('enabled'):
        A._kmip_op_fail('denied', 'KMIP server is disabled')
    client = (kstore.get('clients') or {}).get(cid)
    # Defense in depth: the daemon already verified the mTLS fingerprint,
    # but the control plane re-checks identity + revocation on every op.
    if not client or client.get('revoked') \
            or not hmac.compare_digest(str(client.get('fingerprint') or ''), fp):
        A._kmip_log('auth_fail', client_id=cid or None, op=op or None,
                    detail='op with unknown/revoked/mismatched client identity')
        A._kmip_op_fail('denied', 'client identity rejected')
    cname = client.get('name')

    def _log_op(uid=None, ok=True, detail=None):
        A._kmip_log('op', client_id=cid, client=cname, op=op, uid=uid, ok=ok,
                    detail=detail)

    now = int(time.time())

    if op in ('register', 'create'):
        key = _kmip_master_key()
        if key is None:
            _log_op(ok=False, detail='master key missing')
            A._kmip_op_fail('denied', 'KMIP master key unavailable')
        if op == 'register':
            try:
                material = base64.b64decode(
                    str(params.get('material_b64') or ''), validate=True)
            except Exception:
                _log_op(ok=False, detail='bad material encoding')
                A._kmip_op_fail('invalid', 'key material is not valid base64')
            if not material or len(material) > 65536:
                _log_op(ok=False, detail='bad material size')
                A._kmip_op_fail('invalid', 'key material empty or too large')
            object_type = str(params.get('object_type') or 'secret_data')
            length = None
        else:
            length = int(params.get('length') or 256)
            if not (64 <= length <= 4096) or length % 8:
                _log_op(ok=False, detail=f'bad length {length}')
                A._kmip_op_fail('invalid', 'cryptographic length out of range')
            material = secrets.token_bytes(length // 8)
            object_type = 'symmetric_key'
        with A._LockedUpdate(A.KMIP_OBJECTS_FILE) as store:
            objs = store.setdefault('objects', {})
            if len(objs) >= A.MAX_KMIP_OBJECTS:
                A.respond(200, {'ok': False, 'reason': 'invalid',
                                'message': 'object cap reached'})
            store['seq'] = int(store.get('seq') or 0) + 1
            uid = str(store['seq'])
            obj = {'uid': uid, 'object_type': object_type,
                   'key_format': int(params.get('key_format') or 1),
                   'state': 'pre_active',
                   'state_enum': _KMIP_STATES['pre_active'],
                   'created': now, 'updated': now, 'client_id': cid,
                   'material': A.cmdb_vault.encrypt_bytes(key, material),
                   'access_count': 0}
            for f in ('algorithm', 'length', 'usage_mask',
                      'secret_data_type', 'opaque_data_type'):
                v = params.get(f)
                if v:
                    obj[f] = int(v)
            if op == 'create':
                obj['algorithm'] = int(params.get('algorithm') or 3)
                obj['length'] = length
            oname = str(params.get('name') or '').strip()[:128]
            if oname:
                obj['name'] = oname
            objs[uid] = obj
        _log_op(uid=uid)
        A.respond(200, {'ok': True, 'uid': uid})

    if op == 'locate':
        objs = (A.load(A.KMIP_OBJECTS_FILE) or {}).get('objects') or {}
        name = str(params.get('name') or '').strip()
        want_type = params.get('object_type')
        max_items = params.get('max_items')
        uids = []
        for uid, o in objs.items():
            if not A._kmip_object_visible(o, cid):
                continue
            if o.get('state') == 'destroyed':
                continue
            if name and (o.get('name') or '') != name:
                continue
            if want_type and o.get('object_type') != want_type:
                continue
            uids.append((o.get('created') or 0, uid))
        uids.sort(reverse=True)
        out = [u for _, u in uids]
        if max_items:
            out = out[:max(1, int(max_items))]
        _log_op(detail=f'{len(out)} matched'
                       + (f' name={name}' if name else ''))
        A.respond(200, {'ok': True, 'uids': out})

    # Remaining ops all address one object by uid.
    uid = str(params.get('uid') or '')
    if not uid:
        _log_op(ok=False, detail='uid missing')
        A._kmip_op_fail('missing', 'unique identifier required')

    if op in ('get', 'get_attributes'):
        objs = (A.load(A.KMIP_OBJECTS_FILE) or {}).get('objects') or {}
        o = objs.get(uid)
        if not o or not A._kmip_object_visible(o, cid):
            _log_op(uid=uid, ok=False, detail='not found')
            A._kmip_op_fail('not_found', 'object not found')
        out = {k: o.get(k) for k in
               ('uid', 'object_type', 'key_format', 'algorithm', 'length',
                'usage_mask', 'secret_data_type', 'opaque_data_type', 'name',
                'state', 'state_enum', 'created', 'activated', 'updated')}
        if op == 'get':
            if o.get('state') == 'destroyed' or not o.get('material'):
                _log_op(uid=uid, ok=False, detail='destroyed')
                A._kmip_op_fail('state', 'object has been destroyed')
            key = _kmip_master_key()
            if key is None:
                _log_op(uid=uid, ok=False, detail='master key missing')
                A._kmip_op_fail('denied', 'KMIP master key unavailable')
            try:
                material = A.cmdb_vault.decrypt_bytes(key, o['material'])
            except A.cmdb_vault.VaultError:
                _log_op(uid=uid, ok=False, detail='decrypt failed')
                A._kmip_op_fail('denied', 'key material undecryptable')
            out['material_b64'] = base64.b64encode(material).decode()
            with A._LockedUpdate(A.KMIP_OBJECTS_FILE) as store:
                live = (store.get('objects') or {}).get(uid)
                if live:
                    live['last_access'] = now
                    live['access_count'] = int(live.get('access_count') or 0) + 1
        _log_op(uid=uid)
        A.respond(200, {'ok': True, 'object': out})

    if op in ('activate', 'revoke', 'destroy'):
        with A._LockedUpdate(A.KMIP_OBJECTS_FILE) as store:
            objs = store.get('objects') or {}
            o = objs.get(uid)
            if not o or not A._kmip_object_visible(o, cid):
                A.respond(200, {'ok': False, 'reason': 'not_found',
                                'message': 'object not found'})
            if op == 'activate':
                if o.get('state') not in ('pre_active', 'active'):
                    A.respond(200, {'ok': False, 'reason': 'state',
                                    'message': 'object is not activatable'})
                o['state'] = 'active'
                o['state_enum'] = _KMIP_STATES['active']
                o.setdefault('activated', now)
            elif op == 'revoke':
                code = int(params.get('reason_code') or 1)
                o['state'] = 'compromised' if code == 2 else 'deactivated'
                o['state_enum'] = _KMIP_STATES[o['state']]
                o['deactivated'] = now
            else:  # destroy — KMIP forbids destroying an Active object
                if o.get('state') == 'active':
                    A.respond(200, {'ok': False, 'reason': 'state',
                                    'message': 'object is active — revoke '
                                               'it first'})
                o.pop('material', None)
                o['state'] = 'destroyed'
                o['state_enum'] = _KMIP_STATES['destroyed']
                o['destroyed'] = now
            o['updated'] = now
        _log_op(uid=uid)
        A.respond(200, {'ok': True, 'uid': uid})

    _log_op(ok=False, detail=f'unsupported op {op}')
    A._kmip_op_fail('unsupported', f'operation {op} not supported')
