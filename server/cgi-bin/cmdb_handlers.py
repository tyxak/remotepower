"""RemotePower — CMDB assets + encrypted credentials + vault + scoped credentials.

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
import secrets
import time
import urllib


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


def _caller_scope_covers_credential(scope_type: str, scope_value: str) -> bool:
    """v4.10.0: does the caller's RBAC scope cover a scoped credential? Admins and
    all-scope roles → True. A scoped operator covers a credential only when its
    scope_type maps to the operator's RBAC scope type AND the value is in scope —
    so a sites-scoped tech can reveal that site's credentials, but not another
    site's, and not a group/tag credential. Used to relax list/reveal/inherited
    from admin-only to admin-or-scope-covered (create/delete stay admin-only)."""
    caller = A._caller_scope()
    if caller is None:                              # admin / all-scope
        return True
    rbac_type = {'site': 'sites', 'group': 'groups', 'tag': 'tags'}.get(scope_type)
    if not rbac_type or caller.get('type') != rbac_type:
        return False
    return scope_value in (caller.get('values') or [])


def _cmdb_clean_list(items, spec):
    """Sanitize a CMDB business list (contracts/contacts/licenses) to its spec.
    Returns (clean_list, error_or_None). Drops wholly-empty rows; caps length."""
    import datetime as _dt
    if not isinstance(items, list):
        return [], 'must be a list'
    out = []
    for it in items[:A.MAX_CMDB_LIST_ITEMS]:
        if not isinstance(it, dict):
            continue
        rec = {}
        for f, rule in spec.items():
            v = it.get(f)
            if rule == 'date':
                s = str(v or '').strip()
                if s:
                    try:
                        _dt.date.fromisoformat(s)
                    except ValueError:
                        return [], f'{f} must be an ISO date (YYYY-MM-DD) or empty'
                rec[f] = s
            elif rule == 'int':
                try:
                    rec[f] = max(0, int(v)) if v not in (None, '') else 0
                except (TypeError, ValueError):
                    rec[f] = 0
            elif rule == 'ip':       # v5.0.0: optional IPv4/IPv6 literal
                s = str(v or '').strip()
                if s:
                    import ipaddress as _ipa
                    try:
                        s = str(_ipa.ip_address(s))
                    except ValueError:
                        return [], f'{f} must be a valid IP address or empty'
                rec[f] = s
            elif rule == 'iface':    # v5.0.0: NIC name
                s = str(v or '').strip()
                if s and not A._CMDB_IFACE_RE.match(s):
                    return [], f'{f} must be letters/digits/.:_- (max 32)'
                rec[f] = s
            elif rule == 'bool':
                rec[f] = bool(v)
            else:
                rec[f] = A._sanitize_str(str(v or ''), rule)
        # Drop wholly-empty rows — but ignore bool flags (a lone primary=True
        # with no iface/IP is still empty and shouldn't be kept).
        if any(rec.get(f) for f in spec if spec[f] != 'bool'):
            out.append(rec)
    return out, None


def _cmdb_get_request_key() -> bytes:
    """Extract the derived vault key from the request headers.

    Returns:
        The 32-byte key as raw bytes.

    Raises:
        cmdb_vault.VaultLockedError: Header is missing.
        cmdb_vault.VaultKeyError: Header is malformed (not hex, wrong length).
    """
    raw = A._env('HTTP_X_RP_VAULT_KEY', '')
    return A.cmdb_vault.parse_key_header(raw)


def _cmdb_get_vault_meta() -> dict:
    """Load vault metadata (KDF params + canary) from disk."""
    return A.load(A.CMDB_VAULT_FILE)


def _cmdb_load() -> dict:
    """Load the CMDB store from disk.

    Returns:
        Mapping of ``device_id`` to record dict. Returns an empty dict if
        the store file is missing or corrupt — never raises.

    Migration: v2.0 introduced the multi-doc ``docs`` field. Records that
    were last written under v1.x have ``documentation`` (a single Markdown
    string) but no ``docs`` list. We synthesise a single-doc list from
    the legacy field so downstream code only has to handle the new shape.
    The legacy field is left in place — old API consumers (scripts, the
    ``documentation`` field in the existing ``handle_cmdb_update``) keep
    working unchanged. On first save through the new endpoints the legacy
    field is cleared.
    """
    store = A.load(A.CMDB_FILE)
    if not isinstance(store, dict):
        return {}
    # Lightweight in-memory migration. Cheap to do on every load (just
    # walks N records, conditional). Pushing it into save() would mean
    # records weren't migrated until they were modified.
    for rec in store.values():
        if not isinstance(rec, dict):
            continue
        if 'docs' not in rec or not isinstance(rec.get('docs'), list):
            legacy = rec.get('documentation') or ''
            if isinstance(legacy, str) and legacy.strip():
                rec['docs'] = [{
                    'id':         'legacy',
                    'title':      'Documentation',
                    'body':       legacy,
                    'created_by': rec.get('updated_by', ''),
                    'created_at': rec.get('updated_at', 0),
                    'updated_by': rec.get('updated_by', ''),
                    'updated_at': rec.get('updated_at', 0),
                }]
            else:
                rec['docs'] = []
        # v5.0.0: synthesise the interfaces list from the legacy single
        # primary_interface/nat_ip fields so older records show up in the new
        # multi-NIC editor. Left non-destructive; the single fields stay in sync.
        if 'interfaces' not in rec or not isinstance(rec.get('interfaces'), list):
            _pi = (rec.get('primary_interface') or '').strip()
            _nat = (rec.get('nat_ip') or '').strip()
            rec['interfaces'] = ([{'iface': _pi, 'ip': '', 'nat_ip': _nat,
                                   'primary': True}] if (_pi or _nat) else [])
    return store


def _cmdb_record_default() -> dict:
    """Build an empty CMDB record skeleton.

    Every enrolled device implicitly has one of these — the storage layer
    only persists records the user has actually edited, but the API
    presents a uniform shape.

    Returns:
        Dict with all CMDB fields set to their type-appropriate empties
        (empty string, empty list, default port, zero timestamp).
    """
    return {
        'asset_id':        '',
        'server_function': '',
        'environment':     '',     # v3.12.0: test / dev / staging / prod
        # v5.0.0: coarse operational ownership bucket (fixed allowlist — see
        # CMDB_BUSINESS_FUNCTIONS). Drives reporting/grouping, not a free-text.
        'business_function': '',
        'vlan':            '',
        # v5.0.0: network interfaces, each with an optional NAT/public IP child.
        # `interfaces` is the source of truth (multi-NIC, multi-NAT); the legacy
        # single primary_interface/nat_ip are kept in sync (derived from the
        # primary row) for back-compat with older readers.
        'interfaces':        [],   # [{iface, ip, nat_ip, primary}]
        'primary_interface': '',
        'nat_ip':            '',
        'hypervisor_url':  '',
        'ssh_port':        A.CMDB_DEFAULT_SSH_PORT,
        'documentation':   '',     # v1.x: single Markdown blob (kept for back-compat)
        'docs':            [],     # v2.0: multiple titled Markdown docs
        'credentials':     [],
        # v3.5.0: lifecycle expiry dates (ISO YYYY-MM-DD or ''). Drive the
        # warranty/license/support attention items — same NA pattern as os_eol.
        'warranty_expiry':          '',
        'license_expiry':           '',
        'support_contract_expiry':  '',
        # W5-3: rack placement — which rack, bottom U (1-based), and height in U.
        'rack_id':         '',
        'rack_unit':       0,      # 0 = not placed
        'rack_height_u':   1,
        # v3.12.0: business lists — see _CMDB_LIST_SPECS.
        'contracts':       [],
        'contacts':        [],
        'licenses':        [],
        'updated_by':      '',
        'updated_at':      0,
    }


def _cmdb_require_unlocked() -> 'tuple[bytes, dict]':
    """Common preamble for credential operations.

    Loads the vault metadata, extracts and verifies the request's vault
    key, and returns both for the caller to use. Short-circuits via
    :func:`respond` (which raises :class:`HTTPError`) on any failure.

    Returns:
        A ``(key, vault_meta)`` tuple. ``key`` is 32 bytes; ``vault_meta``
        is the dict from ``cmdb_vault.json``.
    """
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    try:
        key = A._cmdb_get_request_key()
    except A.cmdb_vault.VaultLockedError:
        A.respond(401, {'error': 'vault locked', 'code': 'vault_locked'})
    except A.cmdb_vault.VaultKeyError as e:
        A.respond(400, {'error': str(e)})
    if not A.cmdb_vault.verify_key(key, meta):
        A.respond(403, {'error': 'invalid vault key', 'code': 'vault_key_invalid'})
    return key, meta


def _cmdb_strip_creds(record: dict) -> dict:
    """Redact credential ciphertext from a CMDB record.

    Returns a shallow copy of ``record`` where each credential keeps only
    its plaintext-safe metadata (``id``, ``label``, ``username``, ``note``,
    timestamps). The ``nonce`` and ``ct`` fields — the AES-GCM ciphertext
    — are never returned by list endpoints; only ``/reveal`` decrypts and
    surfaces plaintext.

    Args:
        record: The full CMDB record as stored in ``cmdb.json``.

    Returns:
        A new dict safe to serialise to API clients.
    """
    out = dict(record)
    safe = []
    for c in record.get('credentials') or []:
        # v3.7.0: rotation policy + a derived "due" flag (age since last
        # set/rotate exceeds the per-credential policy).
        rad = int(c.get('rotate_after_days', 0) or 0)
        anchor = int(c.get('rotated_at') or c.get('created_at') or 0)
        age_days = int((time.time() - anchor) / 86400) if anchor else None
        rotation_due = bool(rad and age_days is not None and age_days > rad)
        safe.append({
            'id':            c.get('id', ''),
            'label':         c.get('label', ''),
            'username':      c.get('username', ''),
            'note':          c.get('note', ''),
            'created_by':    c.get('created_by', ''),
            'created_at':    c.get('created_at', 0),
            'updated_by':    c.get('updated_by', ''),
            'updated_at':    c.get('updated_at', 0),
            'rotate_after_days': rad,
            'age_days':      age_days,
            'rotation_due':  rotation_due,
        })
    out['credentials'] = safe
    return out


def _cmdb_validate_doc_body(raw) -> 'str | None':
    """Validate a CMDB doc body. Returns cleaned body or None with 400."""
    if not isinstance(raw, str):
        A.respond(400, {'error': 'doc body must be a string'})
        return None
    if len(raw) > A.MAX_CMDB_DOC_LEN:
        A.respond(400, {'error': f'doc body too large (max {A.MAX_CMDB_DOC_LEN} bytes)'})
        return None
    return raw


def _cmdb_validate_doc_title(raw) -> 'str | None':
    """Validate a CMDB doc title.

    Returns the cleaned title if valid, or None and emits a 400 response.
    Titles are required (a doc with no title is unsearchable in the UI).
    They have a sane upper bound — anything longer is probably a mistake.
    """
    if not isinstance(raw, str):
        A.respond(400, {'error': 'doc title must be a string'})
        return None
    title = raw.strip()
    if not title:
        A.respond(400, {'error': 'doc title is required'})
        return None
    if len(title) > A.MAX_CMDB_DOC_TITLE:
        A.respond(400, {'error': f'doc title too long (max {A.MAX_CMDB_DOC_TITLE})'})
        return None
    # Disallow control characters that could mangle UI rendering or
    # produce confusable headings. Allow common Unicode (people might
    # title things in their own language).
    if any(ord(c) < 0x20 and c not in '\t' for c in title):
        A.respond(400, {'error': 'doc title may not contain control characters'})
        return None
    return title


def _cmdb_validate_function(fn) -> 'str | None':
    """Validate a ``server_function`` value.

    Free text but charset-restricted to ``[A-Za-z0-9 _\\-/]`` (max 64
    chars) so the value is safe to splice into autocomplete dropdowns
    without HTML escaping every code path.

    Args:
        fn: Raw value from the request body.

    Returns:
        Cleaned string on success, empty string for falsy input,
        ``None`` to signal validation failure.
    """
    if fn is None:
        return ''
    fn = str(fn).strip()
    if not fn:
        return ''
    if not A._CMDB_FUNC_RE.match(fn):
        return None
    return fn


def _cmdb_validate_url(url) -> 'str | None':
    """Validate a hypervisor URL.

    Empty is acceptable (resets the field). Anything else must be
    ``http://`` or ``https://``, ≤512 characters, and free of whitespace
    or control characters. The latter is a defence against header /
    response splitting if the URL is later interpolated unsafely.

    Args:
        url: Raw value from the request body. Strings, ints, ``None`` —
            anything stringifiable.

    Returns:
        The cleaned URL string on success, an empty string for falsy
        input, or ``None`` to indicate a validation failure (caller
        should respond with 400).
    """
    if not url:
        return ''
    url = str(url).strip()
    if len(url) > A.MAX_CMDB_URL_LEN:
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        return None
    # Reject control characters / whitespace inside the URL
    if any(c.isspace() or ord(c) < 0x20 for c in url):
        return None
    return url


def handle_cmdb_credentials_add(dev_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials`` — encrypt and store a credential.

    Requires admin role and an unlocked vault (via the
    ``X-RP-Vault-Key`` request header). The plaintext password is
    AES-GCM-encrypted with a fresh nonce and stored alongside the
    plaintext metadata.

    Args:
        dev_id: The enrolled device's ID.

    Audit:
        Logs ``cmdb_credential_add`` with the credential ID + label.

    Raises:
        HTTPError 400: Missing/empty label or password, or password too long.
        HTTPError 401: Vault not unlocked (``code=vault_locked``).
        HTTPError 403: Bad vault key.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})

    key, _meta = A._cmdb_require_unlocked()
    body = A.get_json_obj()
    label    = A._sanitize_str(body.get('label', ''),    A.MAX_CMDB_LABEL,    allow_empty=False)
    username = A._sanitize_str(body.get('username', ''), A.MAX_CMDB_USERNAME, allow_empty=True) or ''
    password = body.get('password', '')
    note     = A._sanitize_str(body.get('note', ''),     A.MAX_CMDB_CRED_NOTE, allow_empty=True) or ''

    if not label:
        A.respond(400, {'error': 'label required'})
    if not isinstance(password, str):
        A.respond(400, {'error': 'password must be a string'})
    if len(password) > A.MAX_CMDB_PASSWORD:
        A.respond(400, {'error': f'password too long (max {A.MAX_CMDB_PASSWORD})'})
    if not password:
        A.respond(400, {'error': 'password required'})

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id) or A._cmdb_record_default()
    creds = rec.get('credentials') or []
    if len(creds) >= A.MAX_CMDB_CREDS:
        A.respond(400, {'error': f'max {A.MAX_CMDB_CREDS} credentials per asset'})

    try:
        blob = A.cmdb_vault.encrypt(key, password)
    except A.cmdb_vault.VaultError as e:
        A.respond(500, {'error': f'encrypt failed: {e}'})

    try:
        rotate_after_days = int(body.get('rotate_after_days', 0) or 0)
    except (TypeError, ValueError):
        rotate_after_days = 0
    if not (0 <= rotate_after_days <= 3650):
        A.respond(400, {'error': 'rotate_after_days must be 0 (off) to 3650'})

    now = int(time.time())
    new_id = 'cred_' + secrets.token_hex(8)
    creds.append({
        'id':         new_id,
        'label':      label,
        'username':   username,
        'note':       note,
        'nonce':      blob['nonce'],
        'ct':         blob['ct'],
        'rotate_after_days': rotate_after_days,
        'rotated_at': now,   # v3.7.0: anchor for rotation reminders
        # v5.0.0 (#C3): mark a sensitive credential (root/IPMI/etc.) for
        # break-glass — its reveal then requires a SECOND admin's approval.
        'break_glass': bool(body.get('break_glass')),
        'created_by': actor,
        'created_at': now,
        'updated_by': actor,
        'updated_at': now,
    })
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = now
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_credential_add',
              detail=f'device={dev_id} cred={new_id} label={label[:40]}')
    A.respond(200, {'ok': True, 'id': new_id})


def handle_cmdb_credentials_delete(dev_id: str, cred_id: str) -> None:
    """``DELETE /api/cmdb/{device_id}/credentials/{cred_id}`` — hard-delete.

    The encrypted blob is removed from ``cmdb.json`` on save. The audit
    log keeps the ``cmdb_credential_delete`` entry but the ciphertext
    itself is gone — there's no trash can.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not A._validate_id(cred_id[len('cred_'):]):
        A.respond(404, {'error': 'credential not found'})

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        A.respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    remaining = [c for c in creds if c.get('id') != cred_id]
    if len(remaining) == len(creds):
        A.respond(404, {'error': 'credential not found'})
    rec['credentials'] = remaining
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_credential_delete',
              detail=f'device={dev_id} cred={cred_id}')
    A.respond(200, {'ok': True})


def handle_cmdb_credentials_list(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}/credentials`` — list credentials, metadata only.

    Returns each credential with ``id``, ``label``, ``username``, ``note``,
    and timestamps. The encrypted ciphertext is never included; callers
    that need plaintext use the dedicated ``/reveal`` endpoint.

    Args:
        dev_id: The enrolled device's ID.
    """
    A.require_auth()
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})
    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id) or A._cmdb_record_default()
    safe = A._cmdb_strip_creds(rec)
    A.respond(200, {'credentials': safe.get('credentials') or []})


def handle_cmdb_credentials_reveal(dev_id: str, cred_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials/{cred_id}/reveal`` — return plaintext.

    The audit-logged moment of truth. Decrypts the credential's
    ciphertext using the vault key from the request header and returns
    the plaintext. Every reveal is recorded with actor, source IP,
    asset, and credential label so post-incident review can answer
    "who looked at the IPMI password last Thursday".

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.

    Audit:
        ``cmdb_credential_reveal`` on success,
        ``cmdb_credential_reveal_failed`` on decrypt failure.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not A._validate_id(cred_id[len('cred_'):]):
        A.respond(404, {'error': 'credential not found'})

    key, _meta = A._cmdb_require_unlocked()

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        A.respond(404, {'error': 'credential not found'})
    cred = next((c for c in (rec.get('credentials') or []) if c.get('id') == cred_id), None)
    if not cred:
        A.respond(404, {'error': 'credential not found'})

    # v5.0.0 (#C3): break-glass two-person rule. A flagged credential can only
    # be revealed once a SECOND admin has approved a pending request. The first
    # reveal opens the request (and notifies via webhook); the reveal that
    # carries an approved, fresh, non-self request_id returns the plaintext.
    bg_body = A.get_json_obj() if A.method() == 'POST' else {}  # coerce non-dict → {} (stdin reads once)
    bg_req_id = str(bg_body.get('request_id', '')).strip()
    if cred.get('break_glass'):
        if not bg_req_id:
            new_req = A._breakglass_open(actor, dev_id, cred_id, cred.get('label', ''),
                                       str(bg_body.get('reason', ''))[:200])
            A.respond(202, {'break_glass': True, 'pending': True,
                          'request_id': new_req,
                          'message': 'Break-glass credential — a second admin must '
                                     'approve before it is revealed.'})
        ok, why = A._breakglass_check(bg_req_id, dev_id, cred_id, actor)
        if not ok:
            A.respond(403, {'break_glass': True, 'error': why})

    try:
        plaintext = A.cmdb_vault.decrypt(key,
                                       {'nonce': cred.get('nonce', ''), 'ct': cred.get('ct', '')})
    except A.cmdb_vault.VaultKeyError:
        A.audit_log(actor, 'cmdb_credential_reveal_failed',
                  detail=f'device={dev_id} cred={cred_id} reason=decrypt',
                  source_ip=A._get_client_ip())
        A.respond(403, {'error': 'decryption failed — vault key may be stale'})
    except A.cmdb_vault.VaultError as e:
        A.respond(500, {'error': f'decrypt failed: {e}'})

    if cred.get('break_glass'):
        A._breakglass_consume(bg_req_id)
        A.audit_log(actor, 'cmdb_break_glass_reveal',
                  detail=f'device={dev_id} cred={cred_id} label={cred.get("label","")[:40]}',
                  source_ip=A._get_client_ip())
    A.audit_log(actor, 'cmdb_credential_reveal',
              detail=f'device={dev_id} cred={cred_id} label={cred.get("label","")[:40]}',
              source_ip=A._get_client_ip())
    A.respond(200, {
        'ok':       True,
        'id':       cred_id,
        'label':    cred.get('label', ''),
        'username': cred.get('username', ''),
        'password': plaintext,
        'note':     cred.get('note', ''),
    })


def handle_cmdb_credentials_update(dev_id: str, cred_id: str) -> None:
    """``PUT /api/cmdb/{device_id}/credentials/{cred_id}`` — update a credential.

    Sends only the fields you want to change. The vault key is required
    only if the password is being changed; metadata-only edits skip
    the unlock check. This lets viewers (in some configurations) update
    their own labels without touching ciphertext.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = A.require_admin_auth()
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not A._validate_id(cred_id[len('cred_'):]):
        A.respond(404, {'error': 'credential not found'})

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        A.respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    idx = next((i for i, c in enumerate(creds) if c.get('id') == cred_id), -1)
    if idx < 0:
        A.respond(404, {'error': 'credential not found'})

    body = A.get_json_obj()
    cred = dict(creds[idx])
    changed = []

    if 'label' in body:
        label = A._sanitize_str(body.get('label', ''), A.MAX_CMDB_LABEL, allow_empty=False)
        if not label:
            A.respond(400, {'error': 'label cannot be empty'})
        cred['label'] = label
        changed.append('label')
    if 'username' in body:
        cred['username'] = A._sanitize_str(body.get('username', ''),
                                         A.MAX_CMDB_USERNAME, allow_empty=True) or ''
        changed.append('username')
    if 'note' in body:
        cred['note'] = A._sanitize_str(body.get('note', ''),
                                     A.MAX_CMDB_CRED_NOTE, allow_empty=True) or ''
        changed.append('note')
    if 'password' in body:
        password = body.get('password', '')
        if not isinstance(password, str):
            A.respond(400, {'error': 'password must be a string'})
        if len(password) > A.MAX_CMDB_PASSWORD:
            A.respond(400, {'error': f'password too long (max {A.MAX_CMDB_PASSWORD})'})
        if not password:
            A.respond(400, {'error': 'password cannot be empty'})
        key, _meta = A._cmdb_require_unlocked()
        try:
            blob = A.cmdb_vault.encrypt(key, password)
        except A.cmdb_vault.VaultError as e:
            A.respond(500, {'error': f'encrypt failed: {e}'})
        cred['nonce'] = blob['nonce']
        cred['ct']    = blob['ct']
        cred['rotated_at'] = int(time.time())   # v3.7.0: a password change is a rotation
        changed.append('password')
    if 'rotate_after_days' in body:
        try:
            rad = int(body.get('rotate_after_days', 0) or 0)
        except (TypeError, ValueError):
            A.respond(400, {'error': 'rotate_after_days must be an integer'})
        if not (0 <= rad <= 3650):
            A.respond(400, {'error': 'rotate_after_days must be 0 (off) to 3650'})
        cred['rotate_after_days'] = rad
        changed.append('rotate_after_days')

    if not changed:
        A.respond(400, {'error': 'no recognised fields to update'})

    cred['updated_by'] = actor
    cred['updated_at'] = int(time.time())
    creds[idx] = cred
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_credential_update',
              detail=f'device={dev_id} cred={cred_id} fields={",".join(changed)}')
    A.respond(200, {'ok': True})


def handle_cmdb_doc_add(dev_id: str) -> None:
    """``POST /api/cmdb/{device_id}/docs`` — attach a new doc to an asset.

    Body: ``{"title": "...", "body": "..."}``. Body may be empty;
    title may not. Returns the created doc with its server-assigned id.

    The new doc is appended (not prepended) so existing UI ordering
    is preserved.
    """
    actor = A.require_write_role('edit CMDB documentation')
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2: per-device write scope
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})

    body = A.get_json_obj()
    title = A._cmdb_validate_doc_title(body.get('title'))
    if title is None:
        return
    doc_body = A._cmdb_validate_doc_body(body.get('body', ''))
    if doc_body is None:
        return

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id) or A._cmdb_record_default()
    docs = rec.get('docs') or []
    if len(docs) >= A.MAX_CMDB_DOCS:
        A.respond(400, {'error': f'too many docs (max {A.MAX_CMDB_DOCS} per asset)'})

    now = int(time.time())
    new_doc = {
        'id':         secrets.token_hex(6),   # 12 hex chars, ~48 bits — plenty per asset
        'title':      title,
        'body':       doc_body,
        'created_by': actor,
        'created_at': now,
        'updated_by': actor,
        'updated_at': now,
    }
    docs.append(new_doc)
    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = now
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_doc_add', f'device={dev_id} doc={new_doc["id"]} title="{title}"')
    A.respond(200, new_doc)


def handle_cmdb_doc_delete(dev_id: str, doc_id: str) -> None:
    """``DELETE /api/cmdb/{device_id}/docs/{doc_id}`` — remove a doc.

    Hard delete. Audit log retains the title so you can tell after the
    fact what got removed.
    """
    actor = A.require_write_role('edit CMDB documentation')
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2: per-device write scope
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})

    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id)
    if rec is None:
        A.respond(404, {'error': 'no CMDB record'})
    docs = rec.get('docs') or []

    idx = next((i for i, d in enumerate(docs) if d.get('id') == doc_id), -1)
    if idx < 0:
        A.respond(404, {'error': 'doc not found'})

    removed = docs.pop(idx)
    # If we just deleted the last doc that's a legacy migration, clear
    # the back-compat field too. Otherwise it'd reappear on next load.
    if doc_id == 'legacy' and not docs:
        rec['documentation'] = ''

    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = int(time.time())
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_doc_delete',
              f'device={dev_id} doc={doc_id} title="{removed.get("title", "")}"')
    A.respond(200, {'ok': True})


def handle_cmdb_doc_update(dev_id: str, doc_id: str) -> None:
    """``PUT /api/cmdb/{device_id}/docs/{doc_id}`` — edit a doc.

    Body: any subset of ``{"title", "body"}``. Updates ``updated_by``
    and ``updated_at`` on the doc and on the parent record. Returns
    the updated doc.

    Migrated 'legacy' docs use a fixed id of ``legacy``; once edited,
    they get a real random id assigned to make subsequent operations
    less ambiguous and to clear the legacy flag.
    """
    actor = A.require_write_role('edit CMDB documentation')
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2: per-device write scope
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})

    body = A.get_json_obj()
    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id)
    if rec is None:
        A.respond(404, {'error': 'no CMDB record'})
    docs = rec.get('docs') or []

    idx = next((i for i, d in enumerate(docs) if d.get('id') == doc_id), -1)
    if idx < 0:
        A.respond(404, {'error': 'doc not found'})
    doc = docs[idx]

    changed = []
    if 'title' in body:
        title = A._cmdb_validate_doc_title(body.get('title'))
        if title is None:
            return
        doc['title'] = title
        changed.append('title')
    if 'body' in body:
        new_body = A._cmdb_validate_doc_body(body.get('body'))
        if new_body is None:
            return
        doc['body'] = new_body
        changed.append('body')

    if not changed:
        A.respond(400, {'error': 'no recognised fields'})

    now = int(time.time())
    doc['updated_by'] = actor
    doc['updated_at'] = now
    # Promote legacy doc to a real id once edited
    if doc_id == 'legacy':
        doc['id'] = secrets.token_hex(6)
        # Clear the legacy field — it's been superseded by the docs list
        rec['documentation'] = ''
    docs[idx] = doc
    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = now
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_doc_update',
              f'device={dev_id} doc={doc["id"]} changed={",".join(changed)}')
    A.respond(200, doc)


def handle_cmdb_get(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}`` — full asset detail with credentials redacted.

    Args:
        dev_id: The enrolled device's ID.

    Side effects:
        Calls :func:`respond` with 200 + asset detail, or 404 if the
        device is unknown.
    """
    A.require_auth()
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})
    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id) or A._cmdb_record_default()
    # Backfill ssh_port for records created before v1.10.0.
    if 'ssh_port' not in rec:
        rec['ssh_port'] = A.CMDB_DEFAULT_SSH_PORT
    dev = devices[dev_id]
    payload = A._cmdb_strip_creds(rec)
    payload['device_id'] = dev_id
    payload['name']      = dev.get('name', dev_id)
    payload['hostname']  = dev.get('hostname', '')
    payload['os']        = dev.get('os', '')
    payload['ip']        = dev.get('ip', '')
    payload['mac']       = dev.get('mac', '')
    payload['version']   = dev.get('version', '')
    payload['group']     = dev.get('group', '')
    payload['tags']      = dev.get('tags', [])
    payload['decommissioned'] = bool(dev.get('decommissioned'))   # v5.0.0
    # v1.10.0: send a trimmed sysinfo subset rather than the full dict.
    # Saves ~50 KB on busy assets, cuts CMDB modal load time noticeably.
    payload['sysinfo']   = A._trim_sysinfo(dev.get('sysinfo', {}))
    A.respond(200, payload)


def handle_cmdb_list() -> None:
    """``GET /api/cmdb`` — list assets joined with their CMDB metadata.

    Returns one entry per enrolled device (devices with no CMDB record
    appear with empty fields). Supports two query-string filters:

    ``?q=<text>``
        Free-text search across name, hostname, OS, IP, MAC, group,
        asset_id, server_function, hypervisor_url, tags, and the
        documentation body. Case-insensitive substring match.

    ``?function=<value>``
        Exact match on ``server_function`` (case-insensitive).

    Results are sorted by ``server_function`` then by ``name``;
    unspecified-function assets sort last.

    Side effects:
        Calls :func:`respond` with status 200 and the asset list.
    """
    A.require_auth()
    # v3.5.0 RBAC v2: a scoped role only sees CMDB metadata for in-scope assets
    # (mirrors the device-list filter — the per-device GET is already guarded).
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE))
    cmdb = A._cmdb_load()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', ''))
    q = (qs.get('q', [''])[0] or '').strip().lower()
    func_filter = (qs.get('function', [''])[0] or '').strip().lower()

    out = []
    for dev_id, dev in devices.items():
        rec = cmdb.get(dev_id) or A._cmdb_record_default()
        rec_safe = A._cmdb_strip_creds(rec)
        entry = {
            'device_id':       dev_id,
            'name':            dev.get('name', dev_id),
            'hostname':        dev.get('hostname', ''),
            'os':              dev.get('os', ''),
            'ip':              dev.get('ip', ''),
            'mac':             dev.get('mac', ''),
            'group':           dev.get('group', ''),
            'tags':            dev.get('tags', []),
            'asset_id':        rec_safe.get('asset_id', ''),
            'server_function': rec_safe.get('server_function', ''),
            'environment':     rec_safe.get('environment', ''),
            'business_function': rec_safe.get('business_function', ''),     # v5.0.0
            'vlan':            rec_safe.get('vlan', ''),
            'interfaces':      rec_safe.get('interfaces', []),            # v5.0.0
            'primary_interface': rec_safe.get('primary_interface', ''),   # v5.0.0
            'nat_ip':          rec_safe.get('nat_ip', ''),                # v5.0.0
            'decommissioned':  bool(dev.get('decommissioned')),          # v5.0.0
            'hypervisor_url':  rec_safe.get('hypervisor_url', ''),
            'ssh_port':        rec_safe.get('ssh_port', A.CMDB_DEFAULT_SSH_PORT),
            # True if EITHER the legacy single-blob `documentation` OR the v2.0
            # multi-doc `docs` list has content. Checking only `documentation`
            # missed every asset whose docs were written through the new
            # multi-doc editor (which clears the legacy field on first save) →
            # the green "has docs" dot never lit despite attached docs.
            'has_documentation': bool(rec_safe.get('documentation')
                                      or rec_safe.get('docs')),
            'credential_count': len(rec_safe.get('credentials') or []),
        }
        if func_filter and entry['server_function'].lower() != func_filter:
            continue
        if q:
            haystack = ' '.join([
                entry['name'], entry['hostname'], entry['os'], entry['ip'],
                entry['mac'], entry['group'], entry['asset_id'],
                entry['server_function'], entry['vlan'], entry['hypervisor_url'],
                ' '.join(entry['tags'] or []),
                rec_safe.get('documentation', ''),
            ]).lower()
            if q not in haystack:
                continue
        out.append(entry)
    out.sort(key=lambda x: (x.get('server_function') or '~', x['name'].lower()))
    A.respond(200, out)


def handle_cmdb_server_functions() -> None:
    """``GET /api/cmdb/server-functions`` — distinct values for autocomplete.

    Returns the set of ``server_function`` values currently in use across
    all assets, sorted case-insensitively. The frontend feeds this into a
    ``<datalist>`` for the asset-edit modal.
    """
    A.require_auth()
    cmdb = A._cmdb_load()
    seen = set()
    for rec in cmdb.values():
        fn = (rec or {}).get('server_function') or ''
        if fn:
            seen.add(fn)
    A.respond(200, sorted(seen, key=str.lower))


def handle_cmdb_update(dev_id: str) -> None:
    """``PUT /api/cmdb/{device_id}`` — patch CMDB metadata for an asset.

    Accepts a JSON body with any subset of the writable fields.
    Unrecognised keys are silently ignored; recognised keys that fail
    validation cause a 400. At least one recognised key is required.

    Writable fields:
        ``asset_id``: Free text, ``[A-Za-z0-9_-]{0,64}``.
        ``server_function``: Free text, ``[A-Za-z0-9 _\\-/]{0,64}``.
        ``vlan``: Free text, ``[A-Za-z0-9 _\\-/,()]{0,64}``. Lets the
            operator capture single IDs, comma-lists for trunks, or
            descriptive labels like "100 (DMZ)".
        ``hypervisor_url``: ``http(s)://…``, max 512 chars.
        ``ssh_port``: 1-65535. Empty/0 resets to default 22.
        ``documentation``: Markdown, max 64 KB.
        ``warranty_expiry`` / ``license_expiry`` /
            ``support_contract_expiry``: ISO date (YYYY-MM-DD) or '' to
            clear. Drive the lifecycle-expiry attention items (v3.5.0).

    Args:
        dev_id: The enrolled device's ID.
    """
    actor = A.require_write_role('edit CMDB')
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2: per-device write scope
    devices = A.load(A.DEVICES_FILE)
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})

    body = A.get_json_obj()
    cmdb = A._cmdb_load()
    rec = cmdb.get(dev_id) or A._cmdb_record_default()

    changed = []

    if 'asset_id' in body:
        asset_id = str(body.get('asset_id') or '').strip()
        if asset_id and not A._SAFE_ID_RE.match(asset_id):
            A.respond(400, {'error': 'asset_id must match [A-Za-z0-9_-]{1,64}'})
        if len(asset_id) > A.MAX_CMDB_ASSET_ID:
            A.respond(400, {'error': f'asset_id too long (max {A.MAX_CMDB_ASSET_ID})'})
        rec['asset_id'] = asset_id
        changed.append('asset_id')

    if 'server_function' in body:
        fn = A._cmdb_validate_function(body.get('server_function'))
        if fn is None:
            A.respond(400, {'error': 'server_function: alphanumerics/spaces/_-/, max 64 chars'})
        rec['server_function'] = fn
        changed.append('server_function')

    if 'environment' in body:
        env = str(body.get('environment') or '').strip().lower()
        if env not in A.CMDB_ENVIRONMENTS:
            A.respond(400, {'error': f'environment must be one of: {", ".join(e for e in A.CMDB_ENVIRONMENTS if e)} (or empty)'})
        rec['environment'] = env
        changed.append('environment')

    if 'business_function' in body:
        bf = str(body.get('business_function') or '').strip()
        if bf not in A.CMDB_BUSINESS_FUNCTIONS:
            A.respond(400, {'error': f'business_function must be one of: {", ".join(b for b in A.CMDB_BUSINESS_FUNCTIONS if b)} (or empty)'})
        rec['business_function'] = bf
        changed.append('business_function')

    if 'vlan' in body:
        vlan = str(body.get('vlan') or '').strip()
        if vlan and not A._CMDB_VLAN_RE.match(vlan):
            A.respond(400, {'error': 'vlan: alphanumerics/spaces/_-/,() , max 64 chars'})
        rec['vlan'] = vlan
        changed.append('vlan')

    # W5-3: rack placement. rack_id references the rack registry (or '' to
    # unplace). rack_unit is the bottom U (1-based); rack_height_u the size.
    if 'rack_id' in body:
        rid = A._sanitize_str(str(body.get('rack_id') or ''), 32)
        if rid and rid not in (A.load(A.RACKS_FILE) or {}):
            A.respond(400, {'error': 'rack_id: unknown rack'})
        rec['rack_id'] = rid
        if not rid:
            rec['rack_unit'] = 0
        changed.append('rack_id')
    if 'rack_unit' in body:
        try:
            ru = int(body.get('rack_unit') or 0)
        except (TypeError, ValueError):
            A.respond(400, {'error': 'rack_unit must be an integer'})
        if not (0 <= ru <= 100):
            A.respond(400, {'error': 'rack_unit must be 0–100 (0 = not placed)'})
        rec['rack_unit'] = ru
        changed.append('rack_unit')
    if 'rack_height_u' in body:
        try:
            rh = int(body.get('rack_height_u') or 1)
        except (TypeError, ValueError):
            A.respond(400, {'error': 'rack_height_u must be an integer'})
        if not (1 <= rh <= 60):
            A.respond(400, {'error': 'rack_height_u must be 1–60'})
        rec['rack_height_u'] = rh
        changed.append('rack_height_u')

    # v5.0.0: primary interface name (free-form NIC label).
    if 'primary_interface' in body:
        iface = str(body.get('primary_interface') or '').strip()
        if iface and not A._CMDB_IFACE_RE.match(iface):
            A.respond(400, {'error': 'primary_interface: letters/digits/.:_- , max 32 chars'})
        rec['primary_interface'] = iface
        changed.append('primary_interface')

    # v5.0.0: NAT / public IP attached to the primary interface as a child.
    # Validated as a real IPv4/IPv6 literal (or '' to clear).
    if 'nat_ip' in body:
        nat = str(body.get('nat_ip') or '').strip()
        if nat:
            import ipaddress as _ipa
            try:
                nat = str(_ipa.ip_address(nat))
            except ValueError:
                A.respond(400, {'error': 'nat_ip must be a valid IPv4/IPv6 address or empty'})
        rec['nat_ip'] = nat
        changed.append('nat_ip')

    if 'hypervisor_url' in body:
        url = A._cmdb_validate_url(body.get('hypervisor_url'))
        if url is None:
            A.respond(400, {'error': 'hypervisor_url must be http(s)://… and ≤512 chars'})
        rec['hypervisor_url'] = url
        changed.append('hypervisor_url')

    if 'ssh_port' in body:
        # Accept int, numeric string, or empty/None → reset to default.
        raw = body.get('ssh_port')
        if raw in (None, '', 0):
            port = A.CMDB_DEFAULT_SSH_PORT
        else:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                A.respond(400, {'error': 'ssh_port must be an integer'})
            if port < A.CMDB_SSH_PORT_MIN or port > A.CMDB_SSH_PORT_MAX:
                A.respond(400, {'error': f'ssh_port must be between '
                                       f'{A.CMDB_SSH_PORT_MIN} and {A.CMDB_SSH_PORT_MAX}'})
        rec['ssh_port'] = port
        changed.append('ssh_port')

    if 'documentation' in body:
        doc = body.get('documentation') or ''
        if not isinstance(doc, str):
            A.respond(400, {'error': 'documentation must be a string'})
        if len(doc) > A.MAX_CMDB_DOC_LEN:
            A.respond(400, {'error': f'documentation too large (max {A.MAX_CMDB_DOC_LEN} bytes)'})
        rec['documentation'] = doc
        changed.append('documentation')

    # v3.5.0: lifecycle expiry dates. Each is an ISO YYYY-MM-DD string, or
    # empty to clear. Validated for shape so the attention computation can
    # parse them without try/excepting per device.
    for _field in ('warranty_expiry', 'license_expiry', 'support_contract_expiry'):
        if _field in body:
            val = str(body.get(_field) or '').strip()
            if val:
                import datetime as _dt
                try:
                    _dt.date.fromisoformat(val)
                except ValueError:
                    A.respond(400, {'error': f'{_field} must be an ISO date (YYYY-MM-DD) or empty'})
            rec[_field] = val
            changed.append(_field)

    # v3.12.0: business lists — contracts / contacts / licenses.
    # v5.0.0: + interfaces (multi-NIC, multi-NAT). All validated by spec.
    for _lf, _spec in A._CMDB_LIST_SPECS.items():
        if _lf in body:
            _clean, _err = A._cmdb_clean_list(body.get(_lf), _spec)
            if _err:
                A.respond(400, {'error': f'{_lf}: {_err}'})
            rec[_lf] = _clean
            changed.append(_lf)

    # v5.0.0: normalise interfaces to exactly one primary and mirror it into the
    # legacy single fields so older readers (cmdb table/list) keep working.
    if 'interfaces' in body:
        ifaces = rec.get('interfaces') or []
        prim_idx = next((i for i, x in enumerate(ifaces) if x.get('primary')),
                        0 if ifaces else None)
        for i, x in enumerate(ifaces):
            x['primary'] = (i == prim_idx)
        prim = ifaces[prim_idx] if prim_idx is not None else {}
        rec['primary_interface'] = prim.get('iface', '')
        rec['nat_ip'] = prim.get('nat_ip', '')

    if not changed:
        A.respond(400, {'error': 'no recognised fields to update'})

    rec['updated_by'] = actor
    rec['updated_at'] = int(time.time())
    cmdb[dev_id] = rec
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_update', detail=f'device={dev_id} fields={",".join(changed)}')
    A.respond(200, {'ok': True, 'record': A._cmdb_strip_creds(rec)})


def handle_cmdb_vault_change() -> None:
    """``POST /api/cmdb/vault/change`` — rotate passphrase, re-encrypt credentials.

    Walks every credential in the CMDB, decrypts under the old key, and
    re-encrypts under the new key. The new vault metadata is written
    first so a crash mid-rotation leaves the vault openable with the
    old passphrase. Credentials that fail to decrypt during rotation
    (corrupt entries) are dropped and logged as
    ``cmdb_vault_change_drop`` for the admin to investigate.

    Returns:
        ``{'ok': True, 'key': <hex>, 'rotated': <int>}`` where ``rotated``
        is the count of credentials successfully re-encrypted.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault not configured'})
    body = A.get_json_obj()
    old_pw = body.get('old_passphrase') or ''
    new_pw = body.get('new_passphrase') or ''

    try:
        old_key = A.cmdb_vault.derive_key_from_meta(old_pw, meta)
    except A.cmdb_vault.VaultNotInstalledError as e:
        A.respond(500, {'error': str(e)})
    except A.cmdb_vault.VaultKeyError as e:
        A.respond(400, {'error': str(e)})
    if not A.cmdb_vault.verify_key(old_key, meta):
        A.audit_log(actor, 'cmdb_vault_change_failed', detail='bad old passphrase',
                  source_ip=A._get_client_ip())
        A.respond(403, {'error': 'invalid old passphrase'})

    try:
        new_meta = A.cmdb_vault.setup_vault(new_pw)
    except A.cmdb_vault.VaultKeyError as e:
        A.respond(400, {'error': str(e)})
    new_key = A.cmdb_vault.derive_key_from_meta(new_pw, new_meta)

    # Re-encrypt every credential in cmdb.json. We build the new file fully
    # before persisting it so a crash mid-rotation can't corrupt the vault.
    cmdb = A._cmdb_load()
    rotated = 0
    for dev_id, rec in cmdb.items():
        new_creds = []
        for c in (rec.get('credentials') or []):
            try:
                pw_pt = A.cmdb_vault.decrypt(old_key,
                                           {'nonce': c.get('nonce', ''), 'ct': c.get('ct', '')})
            except A.cmdb_vault.VaultError:
                # Corrupt entry — drop it but log so the admin notices
                A.audit_log(actor, 'cmdb_vault_change_drop',
                          detail=f'device={dev_id} cred={c.get("id","?")} reason=decrypt_failed')
                continue
            blob = A.cmdb_vault.encrypt(new_key, pw_pt)
            new_c = dict(c)
            new_c['nonce'] = blob['nonce']
            new_c['ct']    = blob['ct']
            new_creds.append(new_c)
            rotated += 1
        rec['credentials'] = new_creds

    new_meta['created_at']   = meta.get('created_at') or int(time.time())
    new_meta['created_by']   = meta.get('created_by') or actor
    new_meta['rotated_at']   = int(time.time())
    new_meta['rotated_by']   = actor

    A.save(A.CMDB_VAULT_FILE, new_meta)
    A.save(A.CMDB_FILE, cmdb)
    A.audit_log(actor, 'cmdb_vault_change', detail=f'rotated_credentials={rotated}')
    A.respond(200, {'ok': True, 'key': new_key.hex(), 'rotated': rotated})


def handle_cmdb_vault_setup() -> None:
    """``POST /api/cmdb/vault/setup`` — initialise the credential vault.

    One-shot operation: subsequent calls return 409 even from the same
    admin. Use ``/cmdb/vault/change`` to rotate the passphrase later.

    The derived AES-GCM key is returned in the response so the browser
    doesn't need to re-unlock immediately after setup. The passphrase
    itself is never persisted.

    Audit:
        Logs ``cmdb_vault_setup`` with the chosen KDF.

    Raises:
        HTTPError 400: Passphrase fails strength validation.
        HTTPError 409: Vault already configured.
        HTTPError 500: ``cryptography`` package not installed.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    meta = A._cmdb_get_vault_meta()
    if A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault already configured'})
    body = A.get_json_obj()
    passphrase = body.get('passphrase') or ''
    try:
        new_meta = A.cmdb_vault.setup_vault(passphrase)
    except A.cmdb_vault.VaultNotInstalledError as e:
        A.respond(500, {'error': str(e)})
    except A.cmdb_vault.VaultKeyError as e:
        A.respond(400, {'error': str(e)})
    new_meta['created_at'] = int(time.time())
    new_meta['created_by'] = actor
    A.save(A.CMDB_VAULT_FILE, new_meta)
    A.audit_log(actor, 'cmdb_vault_setup', detail=f'kdf={new_meta["kdf"]}')
    # Derive and return the key so the caller doesn't have to re-unlock
    key = A.cmdb_vault.derive_key_from_meta(passphrase, new_meta)
    A.respond(200, {'ok': True, 'key': key.hex()})


def handle_cmdb_vault_status() -> None:
    """``GET /api/cmdb/vault/status`` — has the vault been initialised?

    Returns a ``VaultStatus`` payload (see OpenAPI schema). Safe to call
    pre-login from the frontend bootstrap path — though it currently
    requires auth like every other endpoint.
    """
    A.require_auth()
    meta = A._cmdb_get_vault_meta()
    A.respond(200, {
        'configured': A.cmdb_vault.is_configured(meta),
        'kdf':        meta.get('kdf') if meta else None,
        'iterations': meta.get('iterations') if meta else None,
        'created_at': meta.get('created_at') if meta else None,
        'created_by': meta.get('created_by') if meta else None,
    })


def handle_cmdb_vault_unlock() -> None:
    """``POST /api/cmdb/vault/unlock`` — derive the vault key from a passphrase.

    Any authenticated user can attempt to unlock; it's only the
    *credential operations* that require admin role. This split lets
    viewers see encrypted credential metadata (label, username) without
    being able to decrypt the password.

    Audit:
        Logs ``cmdb_vault_unlock`` on success, ``cmdb_vault_unlock_failed``
        on bad passphrase. Source IP recorded in both cases.
    """
    actor = A.require_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    meta = A._cmdb_get_vault_meta()
    if not A.cmdb_vault.is_configured(meta):
        A.respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    body = A.get_json_obj()
    passphrase = body.get('passphrase') or ''
    try:
        key = A.cmdb_vault.derive_key_from_meta(passphrase, meta)
    except A.cmdb_vault.VaultNotInstalledError as e:
        A.respond(500, {'error': str(e)})
    except A.cmdb_vault.VaultKeyError as e:
        A.respond(400, {'error': str(e)})
    if not A.cmdb_vault.verify_key(key, meta):
        A.audit_log(actor, 'cmdb_vault_unlock_failed', detail='bad passphrase',
                  source_ip=A._get_client_ip())
        A.respond(403, {'error': 'invalid passphrase'})
    A.audit_log(actor, 'cmdb_vault_unlock', source_ip=A._get_client_ip())
    A.respond(200, {'ok': True, 'key': key.hex()})


def handle_device_inherited_credentials(dev_id: str) -> None:
    """GET /api/cmdb/{device_id}/inherited-credentials — the scope-scoped
    credentials that apply to this device by its site/group/tags. Metadata only;
    reveal goes through /api/scoped-credentials/{id}/reveal. Admin, or a scoped
    operator who can see the device + the credential's scope."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'device not found'})
    dev = (A.load(A.DEVICES_FILE) or {}).get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    if not A._device_in_scope(A._caller_scope(), dev):
        A.respond(403, {'error': 'this device is outside your role scope'})
    out = [A._scoped_cred_meta(c) for c in A._scoped_creds_load()['creds']
           if isinstance(c, dict) and A._scoped_cred_applies(c, dev)
           and A._caller_scope_covers_credential(c.get('scope_type'), c.get('scope_value'))]
    A.respond(200, {'ok': True, 'credentials': out})


def handle_scoped_credentials_add() -> None:
    """POST /api/scoped-credentials — encrypt + store a scope-scoped credential.
    Admin + unlocked vault (X-RP-Vault-Key)."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    key, _meta = A._cmdb_require_unlocked()
    body = A.get_json_obj()
    scope_type  = str(body.get('scope_type', '')).strip().lower()
    scope_value = A._sanitize_str(body.get('scope_value', ''), 128, allow_empty=False)
    label    = A._sanitize_str(body.get('label', ''),    A.MAX_CMDB_LABEL,    allow_empty=False)
    username = A._sanitize_str(body.get('username', ''), A.MAX_CMDB_USERNAME, allow_empty=True) or ''
    password = body.get('password', '')
    note     = A._sanitize_str(body.get('note', ''),     A.MAX_CMDB_CRED_NOTE, allow_empty=True) or ''
    if scope_type not in A._SCOPED_CRED_SCOPES:
        A.respond(400, {'error': 'scope_type must be site, group or tag'})
    if not scope_value:
        A.respond(400, {'error': 'scope_value required'})
    if not label:
        A.respond(400, {'error': 'label required'})
    if not isinstance(password, str) or not password:
        A.respond(400, {'error': 'password required'})
    if len(password) > A.MAX_CMDB_PASSWORD:
        A.respond(400, {'error': f'password too long (max {A.MAX_CMDB_PASSWORD})'})
    store = A._scoped_creds_load()
    if len(store['creds']) >= A.MAX_SCOPED_CREDS:
        A.respond(400, {'error': f'max {A.MAX_SCOPED_CREDS} scoped credentials'})
    try:
        blob = A.cmdb_vault.encrypt(key, password)
    except A.cmdb_vault.VaultError as e:
        A.respond(500, {'error': f'encrypt failed: {e}'})
    now = int(time.time())
    new_id = 'scred_' + secrets.token_hex(8)
    store['creds'].append({
        'id': new_id, 'scope_type': scope_type, 'scope_value': scope_value,
        'label': label, 'username': username, 'note': note,
        'nonce': blob['nonce'], 'ct': blob['ct'],
        'created_by': actor, 'created_at': now,
    })
    A.save(A.SCOPED_VAULT_FILE, store)
    A.audit_log(actor, 'scoped_credential_add',
              detail=f'{scope_type}={scope_value} cred={new_id} label={label[:40]}')
    A.respond(200, {'ok': True, 'id': new_id})


def handle_scoped_credentials_delete(cred_id: str) -> None:
    """DELETE /api/scoped-credentials/{id} — remove a scope-scoped credential."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    if not cred_id.startswith('scred_') or not A._validate_id(cred_id[len('scred_'):]):
        A.respond(404, {'error': 'credential not found'})
    store = A._scoped_creds_load()
    before = len(store['creds'])
    store['creds'] = [c for c in store['creds'] if c.get('id') != cred_id]
    if len(store['creds']) == before:
        A.respond(404, {'error': 'credential not found'})
    A.save(A.SCOPED_VAULT_FILE, store)
    A.audit_log(actor, 'scoped_credential_delete', detail=f'cred={cred_id}')
    A.respond(200, {'ok': True})


def handle_scoped_credentials_list() -> None:
    """GET /api/scoped-credentials — metadata for every scope-scoped credential
    the caller can see, plus the count of devices each applies to. No ciphertext.
    Admins see all; a scoped operator sees only credentials within its scope."""
    A.require_auth()
    creds = A._scoped_creds_load()['creds']
    devices = A.load(A.DEVICES_FILE) or {}
    out = []
    for c in creds:
        if not isinstance(c, dict):
            continue
        if not A._caller_scope_covers_credential(c.get('scope_type'), c.get('scope_value')):
            continue
        m = A._scoped_cred_meta(c)
        m['applies_to'] = sum(1 for d in devices.values()
                              if isinstance(d, dict) and A._scoped_cred_applies(c, d))
        out.append(m)
    A.respond(200, {'ok': True, 'credentials': out})


def handle_scoped_credentials_reveal(cred_id: str) -> None:
    """POST /api/scoped-credentials/{id}/reveal — decrypt + return plaintext.
    Admin OR a scoped operator whose RBAC scope covers the credential, plus the
    vault key; every reveal is audit-logged."""
    actor = A.require_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # v5.0.1 (SECURITY): revealing a credential is privileged. Read-only roles
    # (viewer/mcp/auditor) resolve to an EMPTY permission set + scope 'all', so
    # the scope-cover check below would otherwise pass — a viewer holding the
    # vault key could reveal any scoped credential. Require admin OR a role with
    # at least one action permission (a scoped operator). Permission-based, not a
    # role-string denylist (per the denylist-role bug class).
    _su, _srole = A.verify_token(A.get_token_from_request())
    _srr = A._resolve_role(_srole)
    if not _srr.get('admin') and not _srr.get('permissions'):
        A.respond(403, {'error': 'your role cannot reveal credentials'})
    if not cred_id.startswith('scred_') or not A._validate_id(cred_id[len('scred_'):]):
        A.respond(404, {'error': 'credential not found'})
    key, _meta = A._cmdb_require_unlocked()
    cred = next((c for c in A._scoped_creds_load()['creds'] if c.get('id') == cred_id), None)
    if not cred:
        A.respond(404, {'error': 'credential not found'})
    if not A._caller_scope_covers_credential(cred.get('scope_type'), cred.get('scope_value')):
        A.respond(403, {'error': 'this credential is outside your role scope'})
    try:
        plaintext = A.cmdb_vault.decrypt(key, {'nonce': cred.get('nonce', ''), 'ct': cred.get('ct', '')})
    except A.cmdb_vault.VaultKeyError:
        A.audit_log(actor, 'scoped_credential_reveal_failed',
                  detail=f'cred={cred_id} reason=decrypt', source_ip=A._get_client_ip())
        A.respond(403, {'error': 'decryption failed — vault key may be stale'})
    except A.cmdb_vault.VaultError as e:
        A.respond(500, {'error': f'decrypt failed: {e}'})
    A.audit_log(actor, 'scoped_credential_reveal',
              detail=(f'cred={cred_id} {cred.get("scope_type")}={cred.get("scope_value")} '
                      f'label={cred.get("label","")[:40]}'),
              source_ip=A._get_client_ip())
    A.respond(200, {'ok': True, 'id': cred_id, 'label': cred.get('label', ''),
                  'username': cred.get('username', ''), 'password': plaintext,
                  'note': cred.get('note', '')})
