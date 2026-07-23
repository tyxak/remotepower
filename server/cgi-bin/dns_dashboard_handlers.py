"""RemotePower — DNS dashboard: read/write DNS records via provider APIs
(Cloudflare/…), plus the provider-credential plumbing (plaintext ACME store +
encrypted CMDB-vault storage + import-from-agent harvest) and the live
resolve/propagation checks.

Reuses the ACME DNS-01 credential store (config['acme_dns_credentials']) so a
single scoped API token drives both cert issuance and this dashboard. Every
endpoint is admin-only; writes are audit-logged. The provider clients live in
dns_zones.py; the live resolvers in dns_resolve.py; api.py owns the SSRF-safe
HTTP client (the same one integrations use — allow_loopback=False,
no_redirect=True) + credential resolution.

A bound-module carve-out following the dmarc_handlers / scap_handlers pattern:
api.py execs a PRIVATE instance, binds its own ``globals()`` here (every api
service reached as ``A.<name>`` — a dynamic lookup that keeps the suite's
monkeypatching + inspect.getsource assertions working), then re-imports the
names back so routes + the heartbeat caller of _ingest_dns_creds_harvest resolve
unchanged. Constants (CONFIG_FILE / DEVICES_FILE / ACME_DNS_CREDENTIAL_FIELDS /
ACME_STATE_FILE / _INTEGRATION_HTTP_TIMEOUT_S) and the sibling modules
(dns_zones_mod / dns_resolve_mod / cmdb_vault) + _SSRFIntegrationClient stay in
api.py, reached via A. (NOT distinct 'this file is the mitigation' — this is a
transport carve, behaviour is byte-identical).
"""
import time
import urllib.parse


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


def _dns_vault_key_optional():
    """A verified 32-byte vault key from the X-RP-Vault-Key request header, or
    None when no/invalid header or the vault isn't configured. Never raises —
    the vault is OPTIONAL for DNS: plaintext acme_dns_credentials is the fallback,
    and not every request carries (or needs) a vault key."""
    raw = A._env('HTTP_X_RP_VAULT_KEY', '')
    if not raw:
        return None
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        return None
    try:
        key = A.cmdb_vault.parse_key_header(raw)
    except A.cmdb_vault.VaultError:
        return None
    return key if A.cmdb_vault.verify_key(key, meta) else None


def _dns_resolve_creds(spec, cfg, vault_key):
    """A provider's effective credentials: the plaintext acme_dns_credentials as
    a base, with any vault-encrypted dns_vault_creds decrypted ON TOP (vault
    wins) when an unlocked key is supplied. Returns (creds_dict, has_vault_blobs)."""
    creds = dict((cfg.get('acme_dns_credentials') or {}).get(spec.acme_provider) or {})
    vstore = (cfg.get('dns_vault_creds') or {}).get(spec.key) or {}
    if vstore and vault_key:
        for field, blob in vstore.items():
            if isinstance(blob, dict) and blob.get('ct'):
                try:
                    creds[field] = A.cmdb_vault.decrypt(vault_key, blob)
                except A.cmdb_vault.VaultError:
                    pass   # bad key/blob → fall through to whatever plaintext exists
    return creds, bool(vstore)


def _dns_make_provider(provider_key):
    """Build a live provider client. Credentials come from the plaintext ACME
    store and/or the CMDB vault (decrypted per-request with the X-RP-Vault-Key
    header — never persisted in clear). Short-circuits with 400/401 on unknown
    provider / missing creds / locked vault."""
    spec = A.dns_zones_mod.PROVIDERS.get(provider_key)
    if not spec:
        A.respond(400, {'error': f'unknown provider {provider_key!r}'})
    cfg = A.load(A.CONFIG_FILE) or {}
    vault_key = A._dns_vault_key_optional()
    creds, has_vault = A._dns_resolve_creds(spec, cfg, vault_key)
    if not creds:
        if has_vault and not vault_key:
            # 409 (not 401): the generic api() client logs out on 401 — a locked
            # vault is not an auth failure, so the UI must get the body instead.
            A.respond(409, {'error': f'{spec.label} credentials are stored in the vault — '
                                     f'unlock the vault to use them.',
                            'code': 'vault_locked', 'vault_locked': True})
        A.respond(400, {'error': f'No API credentials configured for {spec.label}. Set them '
                                 f'under ACME → DNS credentials, or store them encrypted in '
                                 f'the vault.',
                        'cred_hint': spec.cred_hint, 'acme_provider': spec.acme_provider})
    client = A._SSRFIntegrationClient(spec.base_url, verify_tls=True,
                                      timeout=A._INTEGRATION_HTTP_TIMEOUT_S)
    return spec(client, creds)


def _dns_target(body):
    """Resolve (provider, zone_id, zone_name) from a write request body."""
    prov = A._dns_make_provider(str(body.get('provider', '')).strip())
    zone = str(body.get('zone', '')).strip()
    zone_name = str(body.get('zone_name', '')).strip()
    if not zone:
        A.respond(400, {'error': 'zone required'})
    return prov, zone, zone_name


def _dns_record_from_body(body):
    """Build + validate a normalised record dict from a write request body."""
    rtype = str(body.get('type', '')).strip().upper()
    if rtype not in A.dns_zones_mod.RECORD_TYPES:
        A.respond(400, {'error': f'unsupported record type {rtype!r}'})
    rec = {
        'type': rtype,
        'name': A._sanitize_str(str(body.get('name', '')), 253, allow_empty=True).strip(),
        'content': A._sanitize_str(str(body.get('content', '')), 8192, allow_empty=True).strip(),
        'ttl': A.dns_zones_mod._int(body.get('ttl'), 0),
    }
    if not rec['content']:
        A.respond(400, {'error': 'content required'})
    if body.get('priority') not in (None, ''):
        rec['priority'] = A.dns_zones_mod._int(body.get('priority'), 0)
    if 'proxied' in body:
        rec['proxied'] = bool(body.get('proxied'))
    return rec


def handle_dns_providers():
    """GET /api/dns/providers — provider catalog + where each provider's
    credentials live (plaintext ACME store and/or the encrypted CMDB vault) +
    the credential fields each provider accepts (for the vault-store form)."""
    A.require_admin_auth()
    cfg = A.load(A.CONFIG_FILE) or {}
    saved = cfg.get('acme_dns_credentials') or {}
    vault = cfg.get('dns_vault_creds') or {}
    out = []
    for p in A.dns_zones_mod.list_providers():
        fields = A.ACME_DNS_CREDENTIAL_FIELDS.get(p['acme_provider'], [])
        out.append({**p,
                    'creds_set': bool(saved.get(p['acme_provider'])),
                    'vault_set': bool(vault.get(p['key'])),
                    'cred_fields': [{'name': f['name'], 'label': f['label'],
                                     'secret': bool(f.get('secret'))} for f in fields]})
    # Agent devices — candidates for "Import from agent". List every device with
    # an agent (NOT agentless), regardless of whether the slow acme.sh scan has
    # reported yet (the harvest reads account.conf on demand). Flag which report
    # an acme.sh install + which are online, so the picker can hint.
    acme_state = A.load(A.ACME_STATE_FILE) or {}
    devs = A.load(A.DEVICES_FILE) or {}
    now = int(time.time())
    agent_devices = [{'id': did,
                      'name': d.get('name', did),
                      'online': (now - int(d.get('last_seen') or 0)) < 600,
                      'acme': bool((acme_state.get(did) or {}).get('available'))}
                     for did, d in devs.items()
                     if isinstance(d, dict) and d.get('group') != 'agentless']
    agent_devices.sort(key=lambda x: x['name'].lower())
    A.respond(200, {'providers': out,
                    'vault_configured': A.cmdb_vault.is_configured(A._cmdb_get_vault_meta()),
                    'agent_devices': agent_devices})


def handle_dns_vault_creds_set():
    """POST /api/dns/vault-credentials — encrypt + store a provider's DNS API
    credentials in the CMDB vault, so NO plaintext is written to disk. Requires
    an unlocked vault (the X-RP-Vault-Key header). Body
    {provider, credentials:{<field>:<value>,...}}; a blank value leaves a field
    unchanged, an explicit null clears it. Admin-only, audit-logged."""
    actor = A.require_admin_auth()
    # Don't use _cmdb_require_unlocked here: it responds 401 on a locked vault,
    # and the generic api() client logs the user out on 401. Use 409 for vault
    # state so the UI gets the body and can prompt to unlock.
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault not configured — set up the CMDB vault first',
                        'code': 'vault_not_configured'})
    try:
        key = A.cmdb_vault.parse_key_header(A._env('HTTP_X_RP_VAULT_KEY', ''))
    except A.cmdb_vault.VaultError:
        A.respond(409, {'error': 'vault locked — unlock to store credentials',
                        'code': 'vault_locked'})
    if not A.cmdb_vault.verify_key(key, meta):
        A.respond(409, {'error': 'invalid vault key — unlock the vault',
                        'code': 'vault_locked'})
    body = A._read_valid(A.request_models.DnsVaultCredsSetRequest)
    if not isinstance(body, dict):
        body = {}
    provider = str(body.get('provider', '')).strip()
    spec = A.dns_zones_mod.PROVIDERS.get(provider)
    if not spec:
        A.respond(400, {'error': f'unknown provider {provider!r}'})
    new_creds = body.get('credentials') or {}
    if not isinstance(new_creds, dict):
        A.respond(400, {'error': 'credentials must be an object'})
    allowed = {f['name'] for f in A.ACME_DNS_CREDENTIAL_FIELDS.get(spec.acme_provider, [])}
    changed = []
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        store = cfg.setdefault('dns_vault_creds', {})
        pstore = store.setdefault(provider, {})
        for fname, val in new_creds.items():
            if fname not in allowed:
                continue  # silently drop unknown keys
            if val is None:
                if fname in pstore:
                    del pstore[fname]; changed.append(fname)
                continue
            sval = A._sanitize_str(str(val), 4096, allow_empty=True).strip()
            if not sval:
                continue  # blank = leave unchanged
            # encrypt() is pure crypto (no I/O, no nested lock) — safe in here
            pstore[fname] = A.cmdb_vault.encrypt(key, sval)
            changed.append(fname)
        if not pstore:
            store.pop(provider, None)
    A.audit_log(actor, 'dns_vault_credentials_set',
                detail=f'provider={provider} fields={",".join(changed) or "(none)"}')
    A.respond(200, {'ok': True, 'updated_fields': changed})


def _ingest_dns_creds_harvest(dev_id, harvest):
    """Store the DNS provider credentials an agent harvested from its acme.sh
    account.conf. ``harvest`` = {<ENV_NAME>: <value>} (e.g. {'CF_Token': '…'}).
    Each name is mapped to its provider via ACME_DNS_CREDENTIAL_FIELDS and saved
    into acme_dns_credentials (0600). The per-device pending flag is cleared
    either way (so a harvest that found nothing doesn't loop). Runs POST-lock —
    takes its own CONFIG/device locks. Returns a (provider, field) list for the
    caller's audit log (names only — never the secret values)."""
    field_to_provider = {}
    for prov, fields in A.ACME_DNS_CREDENTIAL_FIELDS.items():
        for f in fields:
            field_to_provider.setdefault(f['name'], prov)
    stored = []
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        if isinstance(harvest, dict) and harvest:
            store = cfg.setdefault('acme_dns_credentials', {})
            for name, val in harvest.items():
                prov = field_to_provider.get(str(name))
                if not prov or val in (None, ''):
                    continue
                sval = A._sanitize_str(str(val), 4096, allow_empty=True).strip()
                if not sval:
                    continue
                store.setdefault(prov, {})[str(name)] = sval
                stored.append((prov, str(name)))
        # Transient result marker (provider NAMES only — no secrets) so the UI's
        # import poll can tell "delivered" from "still waiting" and react. Map the
        # ACME provider keys (dns_cf) to the DASHBOARD keys (cloudflare) the vault
        # import + dashboard use — only providers the dashboard supports.
        _acme_to_dash = {p.acme_provider: p.key for p in A.dns_zones_mod.PROVIDERS.values()}
        cfg.setdefault('dns_harvest_result', {})[dev_id] = {
            'ts': int(time.time()),
            'providers': sorted({_acme_to_dash[p] for p, _ in stored if p in _acme_to_dash}),
        }
    with A._DeviceUpdate(dev_id) as devices:
        dev = devices.get(dev_id)
        if isinstance(dev, dict) and dev.pop('dns_harvest_pending', None) is not None:
            devices[dev_id] = dev
    return stored


def handle_dns_import_status():
    """GET /api/dns/import-from-agent/status?device_id=X — poll the one-shot
    harvest. Returns state: 'pending' (still waiting on the agent's next
    check-in), 'ready' (the agent delivered creds into acme_dns_credentials;
    `providers` lists them — the UI then encrypts them into the vault), or
    'empty' (the agent ran but found no DNS credentials). Reading a finished
    result consumes the marker. Admin-only."""
    A.require_admin_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    dev_id = (qs.get('device_id', [''])[0] or '').strip()
    # SEC (v6.4.0): body/query device_id under /api/dns/ — NOT covered by the
    # pre-dispatch _enforce_device_scope. Without this gate a tenant admin could
    # poll another tenant's harvest (a provider-list read) AND consume/delete its
    # result marker below, silently breaking that tenant's import. Matches the
    # POST sibling handle_dns_import_from_agent.
    A._scope_block_device(dev_id)
    dev = A.device_get(dev_id) or {}
    if dev.get('dns_harvest_pending'):
        A.respond(200, {'state': 'pending'})
    cfg = A.load(A.CONFIG_FILE) or {}
    result = (cfg.get('dns_harvest_result') or {}).get(dev_id)
    if not result:
        A.respond(200, {'state': 'pending'})    # not triggered yet / not delivered
    providers = result.get('providers') or []
    with A._LockedUpdate(A.CONFIG_FILE) as c:      # consume the marker
        marks = c.get('dns_harvest_result')
        if isinstance(marks, dict):
            marks.pop(dev_id, None)
    A.respond(200, {'state': 'ready' if providers else 'empty', 'providers': providers})


def handle_dns_import_from_agent():
    """POST /api/dns/import-from-agent {device_id} — flag a device to harvest its
    acme.sh DNS credentials (SAVED_* in account.conf) on its next heartbeat and
    import them into acme_dns_credentials. The agent reads the secrets locally
    and returns them over the authenticated heartbeat — never via the
    command-output channel. One-shot, admin-only, audit-logged. From there, use
    'Import from config' to encrypt them into the vault and drop the plaintext."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.DnsImportFromAgentRequest)
    if not isinstance(body, dict):
        body = {}
    dev_id = str(body.get('device_id', '')).strip()
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    if not A.device_get(dev_id):
        A.respond(404, {'error': 'unknown device'})
    A._scope_block_device(dev_id)   # SEC: body device_id, not under /api/devices/ — tenant/scope gate
    with A._DeviceUpdate(dev_id) as devices:
        dev = devices.get(dev_id)
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'unknown device'})
        dev['dns_harvest_pending'] = True
        devices[dev_id] = dev
    A.audit_log(actor, 'dns_import_from_agent_requested', detail=f'device={dev_id}')
    A.respond(200, {'ok': True, 'queued': True,
                    'message': 'Queued — the device will report its DNS credentials on its '
                               'next heartbeat. Refresh in a moment.'})


def handle_dns_vault_import():
    """POST /api/dns/vault-credentials/import — encrypt a provider's EXISTING
    plaintext acme_dns_credentials into the vault, no re-typing. Body
    {provider, clear_plaintext?:bool}. With clear_plaintext the plaintext copy is
    removed afterwards so the credentials then exist ONLY encrypted. Requires an
    unlocked vault. Admin-only, audit-logged."""
    actor = A.require_admin_auth()
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault not configured — set up the CMDB vault first',
                        'code': 'vault_not_configured'})
    try:
        key = A.cmdb_vault.parse_key_header(A._env('HTTP_X_RP_VAULT_KEY', ''))
    except A.cmdb_vault.VaultError:
        A.respond(409, {'error': 'vault locked — unlock to import credentials',
                        'code': 'vault_locked'})
    if not A.cmdb_vault.verify_key(key, meta):
        A.respond(409, {'error': 'invalid vault key — unlock the vault', 'code': 'vault_locked'})
    body = A._read_valid(A.request_models.DnsVaultImportRequest)
    if not isinstance(body, dict):
        body = {}
    provider = str(body.get('provider', '')).strip()
    spec = A.dns_zones_mod.PROVIDERS.get(provider)
    if not spec:
        A.respond(400, {'error': f'unknown provider {provider!r}'})
    clear_plain = bool(body.get('clear_plaintext'))
    imported = []
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        plain = (cfg.get('acme_dns_credentials') or {}).get(spec.acme_provider) or {}
        if plain:
            store = cfg.setdefault('dns_vault_creds', {})
            pstore = store.setdefault(provider, {})
            for fname, val in plain.items():
                if val is None or val == '':
                    continue
                pstore[fname] = A.cmdb_vault.encrypt(key, str(val))
                imported.append(fname)
            if clear_plain:
                cfg['acme_dns_credentials'].pop(spec.acme_provider, None)
    if not imported:
        A.respond(400, {'error': f'No plaintext ACME credentials to import for {spec.label}. '
                                 f'Add them under ACME → DNS credentials first.'})
    A.audit_log(actor, 'dns_vault_credentials_import',
                detail=f'provider={provider} fields={",".join(imported)} '
                       f'cleared_plaintext={clear_plain}')
    A.respond(200, {'ok': True, 'imported': imported, 'cleared_plaintext': clear_plain})


def handle_dns_zones():
    """GET /api/dns/zones?provider=cloudflare — list a provider's zones."""
    A.require_admin_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    prov = A._dns_make_provider((qs.get('provider', [''])[0] or '').strip())
    try:
        zones = prov.list_zones()
    except A.dns_zones_mod.DNSError as e:
        A.respond(502, {'error': str(e)})
    A.respond(200, {'zones': zones})


def handle_dns_records():
    """GET /api/dns/records?provider=&zone=&zone_name= — records in one zone."""
    A.require_admin_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    prov = A._dns_make_provider((qs.get('provider', [''])[0] or '').strip())
    zone = (qs.get('zone', [''])[0] or '').strip()
    zone_name = (qs.get('zone_name', [''])[0] or '').strip()
    if not zone:
        A.respond(400, {'error': 'zone required'})
    try:
        records = prov.list_records(zone, zone_name)
    except A.dns_zones_mod.DNSError as e:
        A.respond(502, {'error': str(e)})
    A.respond(200, {'records': records, 'zone': zone, 'zone_name': zone_name})


def _dns_resolve_args():
    """Validate the shared name/type query args for the resolve endpoints."""
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    name = (qs.get('name', [''])[0] or '').strip()
    rtype = (qs.get('type', ['A'])[0] or 'A').strip().upper()
    if not A.dns_resolve_mod.valid_name(name):
        A.respond(400, {'error': 'invalid DNS name'})
    if not A.dns_resolve_mod.valid_type(rtype):
        A.respond(400, {'error': f'unsupported record type {rtype!r}',
                        'types': list(A.dns_resolve_mod.RECORD_TYPES)})
    return qs, name, rtype


def handle_dns_resolve():
    """GET /api/dns/resolve?name=&type= — resolve a name live and show what the
    zone's authoritative nameservers serve vs. what public recursive resolvers
    return (surfaces drift between provider state and reality). Admin-only;
    read-only DNS queries against a fixed resolver allowlist (no user IPs)."""
    A.require_admin_auth()
    _qs, name, rtype = A._dns_resolve_args()
    try:
        authoritative = A.dns_resolve_mod.resolve_authoritative(name, rtype)
        public = A.dns_resolve_mod.resolve_public(name, rtype)
    except Exception as e:                       # noqa: BLE001 — never 500 the page
        A.respond(502, {'error': f'resolution failed: {str(e)[:120]}'})
    A.respond(200, {'name': name, 'type': rtype,
                    'authoritative': authoritative, 'public': public})


def handle_dns_propagation():
    """GET /api/dns/propagation?name=&type=&expected= — poll public resolvers and
    report how many already serve the expected value ("propagated X/N"), e.g.
    right after editing a record. Admin-only; fixed resolver allowlist."""
    A.require_admin_auth()
    qs, name, rtype = A._dns_resolve_args()
    expected = (qs.get('expected', [''])[0] or '').strip()[:512] or None
    try:
        result = A.dns_resolve_mod.propagation(name, rtype, expected)
    except Exception as e:                       # noqa: BLE001
        A.respond(502, {'error': f'propagation check failed: {str(e)[:120]}'})
    A.respond(200, {'name': name, 'type': rtype, 'expected': expected, **result})


def handle_dns_record_create():
    """POST /api/dns/records — create a record. Admin-only, audit-logged."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.DnsRecordCreateRequest)
    if not isinstance(body, dict):
        body = {}
    prov, zone, zone_name = A._dns_target(body)
    rec = A._dns_record_from_body(body)
    try:
        prov.create_record(zone, zone_name, rec)
    except A.dns_zones_mod.DNSError as e:
        A.respond(502, {'error': str(e)})
    A.audit_log(actor, 'dns_record_create',
                detail=f'provider={body.get("provider")} zone={zone_name or zone} '
                       f'{rec["type"]} {rec["name"]}')
    A.respond(200, {'ok': True})


def handle_dns_record_update():
    """POST /api/dns/records/update — edit a record. Admin-only, audit-logged."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.DnsRecordUpdateRequest)
    if not isinstance(body, dict):
        body = {}
    prov, zone, zone_name = A._dns_target(body)
    rec_id = str(body.get('id', '')).strip()
    if not rec_id:
        A.respond(400, {'error': 'record id required'})
    rec = A._dns_record_from_body(body)
    try:
        prov.update_record(zone, zone_name, rec_id, rec)
    except A.dns_zones_mod.DNSError as e:
        A.respond(502, {'error': str(e)})
    A.audit_log(actor, 'dns_record_update',
                detail=f'provider={body.get("provider")} zone={zone_name or zone} '
                       f'{rec["type"]} {rec["name"]} id={rec_id}')
    A.respond(200, {'ok': True})


def handle_dns_record_delete():
    """POST /api/dns/records/delete — delete a record. Admin-only, audit-logged."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.DnsRecordDeleteRequest)
    if not isinstance(body, dict):
        body = {}
    prov, zone, zone_name = A._dns_target(body)
    rec_id = str(body.get('id', '')).strip()
    if not rec_id:
        A.respond(400, {'error': 'record id required'})
    rtype = str(body.get('type', '')).strip().upper()
    name = str(body.get('name', '')).strip()
    try:
        prov.delete_record(zone, zone_name, rec_id, name=name, rtype=rtype)
    except A.dns_zones_mod.DNSError as e:
        A.respond(502, {'error': str(e)})
    A.audit_log(actor, 'dns_record_delete',
                detail=f'provider={body.get("provider")} zone={zone_name or zone} '
                       f'{rtype} {name} id={rec_id}')
    A.respond(200, {'ok': True})
