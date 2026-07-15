"""Pydantic v2 request-body validation — OPTIONAL, pilot scope (docs/master-
improvement-scoping-internal.md #5). Matches the near-stdlib posture the rest
of the repo holds to: pydantic is not in the required dependency list
(packaging/requirements-server.txt), so every model here is guarded by
``available()`` the same way webauthn_auth.py/saml_auth.py gate their own
optional library.

Scope, deliberately narrow (a pilot, not a sweep): small, genuinely
security-relevant handlers with clean, mostly-scalar request bodies —
handle_user_create (privilege-escalation target), handle_apikeys_create
(credential minting), handle_billing_payment_webhook (external-facing, money-
adjacent), and (v6.1.1 follow-up) handle_enroll_token_create (a second
credential-minting handler), handle_litigation_hold_set (a compliance-
relevant toggle), handle_tenant_create (a tenancy security-boundary root).
NOT config-save-shaped monoliths (handle_config_save alone is thousands of
lines of `if 'key' in body` clauses) — those stay hand-rolled until/unless a
real sweep is scoped separately.

Every model uses ``extra='ignore'`` (pydantic's default), NOT
``extra='forbid'``: rejecting previously-tolerated extra fields would be a
real behavior change for existing API clients (a breaking change this repo
doesn't ship without an explicit deprecation policy — see #40). The value
here is type/requiredness checking, not typo-catching on unknown keys.

Usage (see the three call sites in api.py):
    ok, data_or_error = validate(UserCreateRequest, body)
    if not ok:
        respond(400, {'error': data_or_error})
    # ok and data_or_error is None means pydantic isn't installed --
    # existing hand-rolled validation in the handler is untouched either way.
"""

try:
    from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, Field
    from typing import Any
    _AVAILABLE = True
except Exception:  # library not installed -> pilot disabled, handlers unchanged
    _AVAILABLE = False
    BaseModel = object  # placeholder so class bodies below don't NameError


def available():
    return _AVAILABLE


if _AVAILABLE:

    # v6.1.1 (#5 follow-up, adversarial self-review): these `mode='before'`
    # coercions exist so pydantic's validation is a SUPERSET of the existing
    # hand-rolled checks, never a narrower one. Plain type annotations
    # (`rate_limit: int`, `username: str`) were caught rejecting requests the
    # OLD code accepted -- `rate_limit: null`/`""` (old: `int(x or 0)` -> 0),
    # a float timestamp (old: `int(x)` truncates), a numeric `username` (old:
    # `_sanitize_str` coerces via `str(x)`) -- a real behavior regression for
    # any API client relying on the old tolerant contract, defeating the
    # whole point of "falls back to hand-rolled validation unchanged." Each
    # helper below replicates the EXACT coercion the site it guards already
    # performs, so a value the old code accepted still validates here, and a
    # value the old code already rejected (with its own exception handling)
    # still gets rejected here too -- just earlier, with a schema-checked
    # error instead of a handler-specific one.
    def _coerce_str_loose(v):
        """Matches _sanitize_str(v, ...)'s str(v) coercion (sanitize.py) --
        any scalar becomes a string; the handler's own _sanitize_str/regex
        checks still run afterward and reject a nonsensical result."""
        if v is None:
            return ''
        return str(v)

    def _coerce_int_default_zero(v):
        """Matches `int(body.get(field) or 0)` -- None/''/0/False all become
        0, a float truncates, a non-numeric value raises (caught by the
        handler's own except today; here it becomes a ValidationError)."""
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            raise ValueError('must be an integer')

    def _coerce_optional_int(v):
        """Matches `expires_at = int(expires_at) if expires_at is not None
        else None` -- None stays None, else truncates like int()."""
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            raise ValueError('must be an integer or null')

    def _coerce_int_strict(v):
        """Matches `int(body.get(field, default))` with NO None-tolerance --
        old code's `int(None)` raises TypeError (caught by the handler's own
        try/except), so an explicit null must still raise here too, not
        silently fall back to the field default (that only happens when the
        key is ABSENT, which pydantic already handles via the field's own
        default -- this validator never runs for a genuinely missing key)."""
        try:
            return int(v)
        except (TypeError, ValueError):
            raise ValueError('must be an integer')

    def _coerce_bool_loose(v):
        """Matches bare `bool(body.get(field))` -- Python truthiness of
        WHATEVER JSON type arrives (a non-empty string, list, or dict is
        truthy even if it reads like "false"/"[]"-ish; pydantic's own bool
        parsing is stricter and would reject those instead of coercing)."""
        return bool(v)

    def _coerce_str_falsy_empty(v):
        """Matches `body.get(field) if body.get(field) else ''` -- ANY
        falsy raw value (None/''/0/False/[]/{}), not just None, becomes ''.
        A truthy value is coerced via str() same as _coerce_str_loose (the
        handler's own _sanitize_str still runs afterward)."""
        if not v:
            return ''
        return str(v)

    def _coerce_tag_list(v):
        """Matches `body.get('default_tags', []) or []` followed by an
        isinstance(list) check -- any falsy value (of any type) becomes []
        (the old "or []" fallback); a truthy non-list is rejected (old code
        400s); each item in a truthy list is stringified via str(), never
        rejected individually (the handler's own per-item
        _sanitize_str(str(t), ...) + MAX_TAG_COUNT truncation still runs
        afterward, unchanged)."""
        if not v:
            return []
        if not isinstance(v, list):
            raise ValueError('must be a list of strings')
        return [str(t) for t in v]

    def _coerce_int_or(default):
        """Factory matching `int(body.get(field) or <default>)` -- a falsy raw
        value (None/''/0/False) falls back to <default>, a truthy value is
        int()'d (a float truncates, a non-numeric raises -> old code's 400).
        Used where the handler CLAMPS the result afterward (max/min), so the
        model must NOT impose ge/le bounds here or it would 400 a value the old
        code silently clamped -- a narrower contract, which this module forbids."""
        def _coerce(v):
            try:
                return int(v or default)
            except (TypeError, ValueError):
                raise ValueError('must be a number')
        return _coerce

    def _coerce_dict_loose(v):
        """Matches `body.get(field) or {}` -- any falsy value becomes {}. A truthy
        non-dict is rejected here (old code did `x or {}` then `x.get(...)`, which
        AttributeError'd -> a 500 on a truthy non-dict; a 400 is strictly better and
        never rejects a body the old code actually accepted -- a non-dict never was)."""
        if not v:
            return {}
        if not isinstance(v, dict):
            raise ValueError('must be an object')
        return v

    def _require_list(v):
        """Matches `raw = get(field); if not isinstance(raw, list): respond(400)`
        -- None and any non-list are a 400, a list passes. Pair with a required
        field (no default) so an ABSENT key is a 400 too, exactly like the old
        `isinstance(None, list)` check. Never str->list coercion (pydantic's
        default would iterate a string into chars -- accepting input old code
        rejected)."""
        if not isinstance(v, list):
            raise ValueError('must be a list')
        return v

    class UserCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        username: str = ''
        password: str = ''   # NOT coerced -- old code requires isinstance(password, str) already
        role: str = 'admin'

        _v_username = field_validator('username', mode='before')(_coerce_str_loose)
        _v_role = field_validator('role', mode='before')(_coerce_str_loose)

    class ApiKeyCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        name: str = ''
        role: str = 'admin'
        user: str = 'api'
        rate_limit: int = 0
        expires_at: int | None = None
        rotate_after_days: int = 0

        _v_str = field_validator('name', 'role', 'user', mode='before')(_coerce_str_loose)
        _v_int0 = field_validator('rate_limit', 'rotate_after_days', mode='before')(_coerce_int_default_zero)
        _v_expires = field_validator('expires_at', mode='before')(_coerce_optional_int)

    class BillingPaymentWebhookRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        invoice_id: str = ''
        amount: float          # required -- matches float(body.get('amount')) raising on None
        currency: str = ''
        provider: str = ''
        external_ref: str = ''
        kind: str = 'payment'

        _v_str = field_validator(
            'invoice_id', 'currency', 'provider', 'external_ref', 'kind',
            mode='before')(_coerce_str_loose)

    class LitigationHoldSetRequest(BaseModel):
        """handle_litigation_hold_set — a compliance-relevant toggle
        (docs/master-improvement-scoping-internal.md #21)."""
        model_config = ConfigDict(extra='ignore')
        enabled: bool = False
        reason: str = ''

        _v_enabled = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v_reason = field_validator('reason', mode='before')(_coerce_str_loose)

    class EnrollTokenCreateRequest(BaseModel):
        """handle_enroll_token_create — a second credential-minting handler,
        same bar as ApiKeyCreateRequest above. expires_in has no static
        default here (the handler's own DEFAULT_ENROLL_TOKEN_TTL constant
        isn't importable from this leaf module without a cycle) -- an
        absent key still falls through to the handler's own
        `body.get('expires_in', DEFAULT_ENROLL_TOKEN_TTL)` unchanged, since
        pydantic only applies a field's default when the key is missing,
        never re-validates it."""
        model_config = ConfigDict(extra='ignore')
        expires_in: int | None = None
        default_group: str = ''
        default_tags: list[str] = []
        label: str = ''

        _v_expires = field_validator('expires_in', mode='before')(_coerce_int_strict)
        _v_group = field_validator('default_group', mode='before')(_coerce_str_falsy_empty)
        _v_tags = field_validator('default_tags', mode='before')(_coerce_tag_list)
        _v_label = field_validator('label', mode='before')(_coerce_str_loose)

    class TenantCreateRequest(BaseModel):
        """handle_tenant_create — a tenancy security-boundary root."""
        model_config = ConfigDict(extra='ignore')
        name: str = ''

        _v_name = field_validator('name', mode='before')(_coerce_str_loose)

    class DeadmanCreateRequest(BaseModel):
        """handle_deadman_jobs POST. period/grace are int-COERCED to match
        `int(body.get(f) or <default>)`; the handler CLAMPS them into range
        (max(1,min(43200,...))) afterward, so no ge/le here (bounds would 400 a
        value the old code clamped). name is str-coerced; the handler's own
        _sanitize_str + non-empty check still run."""
        model_config = ConfigDict(extra='ignore')
        name: str = ''
        period_minutes: int = 60
        grace_minutes: int = 10

        _v_name = field_validator('name', mode='before')(_coerce_str_loose)
        _v_period = field_validator('period_minutes', mode='before')(_coerce_int_or(60))
        _v_grace = field_validator('grace_minutes', mode='before')(_coerce_int_or(10))

    class DockerPruneRequest(BaseModel):
        """handle_device_docker_prune POST. scope/confirm are str-coerced to
        match `str(body.get(f, default))`; the handler validates scope against
        the runtime _DOCKER_PRUNE_CMDS table and checks confirm, so no Literal
        here (the two can't drift)."""
        model_config = ConfigDict(extra='ignore')
        scope: str = 'all'
        confirm: str = ''

        _v_scope = field_validator('scope', mode='before')(_coerce_str_loose)
        _v_confirm = field_validator('confirm', mode='before')(_coerce_str_loose)

    # ── v6.1.2 full-adoption sweep ───────────────────────────────────────────
    # Every body-reading handler gets a superset model (all-optional loose
    # coercers matching the handler's own str()/bool()/int() dance, extra='ignore').
    # A model here NEVER rejects a body the handler accepted; it only turns a body
    # the handler would 500 on (a non-dict where a dict is required) into a clean
    # 400, and documents the accepted shape. Ordered to match api.py.

    class MaintenanceModeSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        enabled: bool = False
        reason: str = ''
        _v_enabled = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v_reason = field_validator('reason', mode='before')(_coerce_str_loose)

    class StepUpVerifyRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        password: str = ''
        totp_code: str = ''
        _v_str = field_validator('password', 'totp_code', mode='before')(_coerce_str_loose)

    class ServiceBaselinesRequest(BaseModel):
        """handle_service_baselines — `raw = get('baselines'); if not
        isinstance(raw, list): 400`. Required list (absent/non-list = 400)."""
        model_config = ConfigDict(extra='ignore')
        baselines: list
        _v_baselines = field_validator('baselines', mode='before')(_require_list)

    class PushSubscribeRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        subscription: dict = {}
        _v_sub = field_validator('subscription', mode='before')(_coerce_dict_loose)

    class PushUnsubscribeRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        endpoint: str = ''
        _v_endpoint = field_validator('endpoint', mode='before')(_coerce_str_loose)

    class ContactCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        name: str = ''
        role: str = ''
        company: str = ''
        email: str = ''
        phone: str = ''
        notes: str = ''
        site: str = ''
        portal_enabled: bool = False
        _v_str = field_validator('name', 'role', 'company', 'email', 'phone',
                                 'notes', 'site', mode='before')(_coerce_str_loose)
        _v_portal = field_validator('portal_enabled', mode='before')(_coerce_bool_loose)

    class ContactUpdateRequest(BaseModel):
        """PATCH — every field is `if 'x' in body: c[x] = ...`, so all optional."""
        model_config = ConfigDict(extra='ignore')
        name: str = ''
        role: str = ''
        company: str = ''
        email: str = ''
        phone: str = ''
        notes: str = ''
        site: str = ''
        portal_enabled: bool = False
        _v_str = field_validator('name', 'role', 'company', 'email', 'phone',
                                 'notes', 'site', mode='before')(_coerce_str_loose)
        _v_portal = field_validator('portal_enabled', mode='before')(_coerce_bool_loose)

    class PortalMagicLinkRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        email: str = ''
        _v_email = field_validator('email', mode='before')(_coerce_str_loose)

    class PortalSessionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        token: str = ''
        _v0 = field_validator('token', mode='before')(_coerce_str_loose)

    class PortalTicketsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        message: str = ''
        subject: str = ''
        _v0 = field_validator('message', 'subject', mode='before')(_coerce_str_loose)

    class PortalTicketQueueDecideRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        decision: str = ''
        _v0 = field_validator('decision', mode='before')(_coerce_str_loose)

    class PortalTicketRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        message: str = ''
        _v0 = field_validator('message', mode='before')(_coerce_str_loose)

    class KbRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        category: str = ''
        linked_devices: Any = None
        pinned: bool = False
        tags: str = ''
        title: str = ''
        _v0 = field_validator('body', 'category', 'tags', 'title', mode='before')(_coerce_str_loose)
        _v1 = field_validator('pinned', mode='before')(_coerce_bool_loose)

    class KbArticleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        category: str = ''
        linked_devices: Any = None
        pinned: bool = False
        tags: str = ''
        title: str = ''
        _v0 = field_validator('body', 'category', 'tags', 'title', mode='before')(_coerce_str_loose)
        _v1 = field_validator('pinned', mode='before')(_coerce_bool_loose)

    class LoginRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        password: str = ''
        remember_me: bool = False
        totp_code: str = ''
        username: str = ''
        _v0 = field_validator('password', 'totp_code', 'username', mode='before')(_coerce_str_loose)
        _v1 = field_validator('remember_me', mode='before')(_coerce_bool_loose)

    class DevicesBulkDeleteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_ids: Any = None

    class DeviceTagsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        tags: Any = None

    class DevicesBulkTagsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        add: str = ''
        device_ids: Any = None
        remove: str = ''
        _v0 = field_validator('add', 'remove', mode='before')(_coerce_str_loose)

    class DeviceNotesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        notes: str = ''
        _v0 = field_validator('notes', mode='before')(_coerce_str_loose)

    class DeviceSaveBulkRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cmd_allowlist: Any = None
        decommissioned: bool = False
        group: str = ''
        icon: str = ''
        log_watch: Any = None
        manual_status: bool = False
        monitored: bool = False
        offline_alert_delay_min: int = 0
        poll_interval: str = ''
        reachability: str = ''
        remediation_enabled: bool = False
        ssh_host: str = ''
        ssh_port: int = 22
        ssh_user: str = ''
        tags: Any = None
        tenant: str = ''
        update_channel: str = ''
        watched_files: Any = None
        watched_services: Any = None
        _v0 = field_validator('decommissioned', 'manual_status', 'monitored', 'remediation_enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('group', 'icon', 'poll_interval', 'reachability', 'ssh_host', 'ssh_user', 'tenant', 'update_channel', mode='before')(_coerce_str_loose)
        _v2 = field_validator('offline_alert_delay_min', mode='before')(_coerce_int_or(0))
        _v3 = field_validator('ssh_port', mode='before')(_coerce_int_or(22))

    class DeviceMetricThresholdsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        disk_per_mount: str = ''
        _v0 = field_validator('disk_per_mount', mode='before')(_coerce_str_loose)

    class DeviceProfilesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class DeviceProfileRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class DeviceProfileApplyRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_ids: str = ''
        _v0 = field_validator('device_ids', mode='before')(_coerce_str_loose)

    class SmartGroupsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        rules: dict = {}
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)
        _v1 = field_validator('rules', mode='before')(_coerce_dict_loose)

    class SmartGroupRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        rules: str = ''
        _v0 = field_validator('rules', mode='before')(_coerce_str_loose)

    class RacksRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        height_u: int = 42
        name: str = ''
        site: str = ''
        _v0 = field_validator('height_u', mode='before')(_coerce_int_or(42))
        _v1 = field_validator('name', 'site', mode='before')(_coerce_str_loose)

    class RackRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        height_u: str = ''
        name: str = ''
        site: str = ''
        _v0 = field_validator('height_u', 'name', 'site', mode='before')(_coerce_str_loose)

    class IpamSubnetsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cidr: str = ''
        notes: str = ''
        site: str = ''
        vlan: str = ''
        _v0 = field_validator('cidr', 'notes', 'site', 'vlan', mode='before')(_coerce_str_loose)

    class IpamSubnetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        notes: str = ''
        reservations: str = ''
        site: str = ''
        vlan: str = ''
        _v0 = field_validator('notes', 'reservations', 'site', 'vlan', mode='before')(_coerce_str_loose)

    class TimeEntryUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        billable: bool = False
        category: str = ''
        date: str = ''
        hours: str = ''
        note: str = ''
        rate_name: str = ''
        site_id: str = ''
        tag: str = ''
        _v0 = field_validator('billable', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('category', 'date', 'hours', 'note', 'rate_name', 'site_id', 'tag', mode='before')(_coerce_str_loose)

    class TimesheetWatchersRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        scope: str = ''
        value: str = ''
        watcher: str = ''
        _v0 = field_validator('scope', 'value', 'watcher', mode='before')(_coerce_str_loose)

    class BillingConfigRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        billing_webhook_secret: str = ''
        currency: str = ''
        default_rate: str = ''
        default_vat: str = ''
        invoice_prefix: str = ''
        issuer_address: str = ''
        issuer_name: str = ''
        rate_card: str = ''
        reminder_days: str = ''
        reminders_enabled: bool = False
        site: str = ''
        _v0 = field_validator('billing_webhook_secret', 'currency', 'default_rate', 'default_vat', 'invoice_prefix', 'issuer_address', 'issuer_name', 'rate_card', 'reminder_days', 'site', mode='before')(_coerce_str_loose)
        _v1 = field_validator('reminders_enabled', mode='before')(_coerce_bool_loose)

    class InvoicesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        extra_lines: Any = None
        from_: str = Field(default='', alias='from')
        month: str = ''
        notes: str = ''
        site_id: str = ''
        to: str = ''
        _v0 = field_validator('from_', 'month', 'notes', 'site_id', 'to', mode='before')(_coerce_str_loose)

    class InvoiceUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        notes: str = ''
        status: str = ''
        _v0 = field_validator('notes', 'status', mode='before')(_coerce_str_loose)

    class SiteCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class SiteUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        note: str = ''
        _v0 = field_validator('name', 'note', mode='before')(_coerce_str_loose)

    class TenantUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        status: str = ''
        _v0 = field_validator('name', 'status', mode='before')(_coerce_str_loose)

    class TenantBrandingRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        accent: str = ''
        name: str = ''
        _v0 = field_validator('accent', 'name', mode='before')(_coerce_str_loose)

    class DeviceSiteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        site: str = ''
        _v0 = field_validator('site', mode='before')(_coerce_str_loose)

    class DeviceUserActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        sshkey: str = ''
        username: str = ''
        _v0 = field_validator('action', 'sshkey', 'username', mode='before')(_coerce_str_loose)

    class DeviceFirewallActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        backend: str = ''
        port: str = ''
        proto: str = ''
        _v0 = field_validator('action', 'backend', 'port', 'proto', mode='before')(_coerce_str_loose)

    class DeviceFirewallRuleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        backend: str = ''
        op: str = ''
        preview: str = ''
        ref: str = ''
        spec: str = ''
        _v0 = field_validator('backend', 'op', 'preview', 'ref', 'spec', mode='before')(_coerce_str_loose)

    class DeviceFilesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        content: str = ''
        op: str = ''
        overwrite: bool = False
        path: str = ''
        _v0 = field_validator('content', 'op', 'path', mode='before')(_coerce_str_loose)
        _v1 = field_validator('overwrite', mode='before')(_coerce_bool_loose)

    class FilesArchiveStartRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        path: str = ''
        _v0 = field_validator('path', mode='before')(_coerce_str_loose)

    class FilesArchiveCancelRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        job_id: str = ''
        _v0 = field_validator('job_id', mode='before')(_coerce_str_loose)

    class FilesArchiveChunkRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        chunk: str = ''
        error: str = ''
        final: bool = False
        job_id: str = ''
        token: str = ''
        _v0 = field_validator('chunk', 'error', 'job_id', 'token', mode='before')(_coerce_str_loose)
        _v1 = field_validator('final', mode='before')(_coerce_bool_loose)

    class DeviceCronActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        content: str = ''
        op: str = ''
        unit: str = ''
        user: str = ''
        _v0 = field_validator('action', 'content', 'op', 'unit', 'user', mode='before')(_coerce_str_loose)

    class DeviceStorageActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        kind: str = ''
        snapshot: str = ''
        target: str = ''
        _v0 = field_validator('action', 'kind', 'snapshot', 'target', mode='before')(_coerce_str_loose)

    class DeviceStorageProvisionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        confirm: str = ''
        dry_run: bool = False
        params: str = ''
        recipe: str = ''
        _v0 = field_validator('confirm', 'params', 'recipe', mode='before')(_coerce_str_loose)
        _v1 = field_validator('dry_run', mode='before')(_coerce_bool_loose)

    class DeviceFail2banActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        ip: str = ''
        jail: str = ''
        _v0 = field_validator('action', 'ip', 'jail', mode='before')(_coerce_str_loose)

    class AutopatchCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        auto_promote: bool = False
        cron: str = ''
        health_gate: str = ''
        name: str = ''
        reboot: bool = False
        rings: str = ''
        target: dict = {}
        verify_minutes: int = 15
        _v0 = field_validator('auto_promote', 'reboot', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('cron', 'health_gate', 'name', 'rings', mode='before')(_coerce_str_loose)
        _v2 = field_validator('target', mode='before')(_coerce_dict_loose)
        _v3 = field_validator('verify_minutes', mode='before')(_coerce_int_or(15))

    class AutopatchUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        auto_promote: bool = False
        cron: str = ''
        enabled: bool = False
        health_gate: str = ''
        name: str = ''
        reboot: bool = False
        rings: str = ''
        target: str = ''
        verify_minutes: str = ''
        _v0 = field_validator('auto_promote', 'enabled', 'reboot', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('cron', 'health_gate', 'name', 'rings', 'target', 'verify_minutes', mode='before')(_coerce_str_loose)

    class AnsiblePlaybookCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        content: str = ''
        name: str = ''
        _v0 = field_validator('content', 'name', mode='before')(_coerce_str_loose)

    class AnsiblePlaybookUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        content: str = ''
        name: str = ''
        _v0 = field_validator('content', 'name', mode='before')(_coerce_str_loose)

    class AnsiblePlaybookRunRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        become: bool = False
        device_ids: str = ''
        ssh_key: str = ''
        ssh_password: str = ''
        ssh_user: str = ''
        target: dict = {}
        _v0 = field_validator('become', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('device_ids', 'ssh_key', 'ssh_password', 'ssh_user', mode='before')(_coerce_str_loose)
        _v2 = field_validator('target', mode='before')(_coerce_dict_loose)

    class DeviceGroupRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        group: str = ''
        _v0 = field_validator('group', mode='before')(_coerce_str_loose)

    class DevicePollIntervalRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        poll_interval: str = ''
        _v0 = field_validator('poll_interval', mode='before')(_coerce_str_loose)

    class DeviceIconRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        icon: str = ''
        _v0 = field_validator('icon', mode='before')(_coerce_str_loose)

    class DeviceMonitoredRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        monitored: bool = False
        _v0 = field_validator('monitored', mode='before')(_coerce_bool_loose)

    class DeviceDecommissionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        decommissioned: str = ''
        _v0 = field_validator('decommissioned', mode='before')(_coerce_str_loose)

    class DeviceRequireConfirmationRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        require_confirmation: bool = False
        _v0 = field_validator('require_confirmation', mode='before')(_coerce_bool_loose)

    class DeviceComposeEnabledRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        compose_enabled: bool = False
        _v0 = field_validator('compose_enabled', mode='before')(_coerce_bool_loose)

    class WebtermAuthRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        admin_password: str = ''
        device_id: str = ''
        intent: str = ''
        _v0 = field_validator('admin_password', 'device_id', 'intent', mode='before')(_coerce_str_loose)

    class WebtermSessionAuditRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        actor: str = ''
        bytes_in: int = 0
        bytes_out: int = 0
        device_id: str = ''
        duration_s: int = 0
        reason: str = ''
        session_id: str = ''
        ssh_host: str = ''
        ssh_user: str = ''
        _v0 = field_validator('actor', 'device_id', 'reason', 'session_id', 'ssh_host', 'ssh_user', mode='before')(_coerce_str_loose)
        _v1 = field_validator('bytes_in', 'bytes_out', 'duration_s', mode='before')(_coerce_int_or(0))

    class EnrollRegisterRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        enrollment_token: str = ''
        hostname: str = ''
        ip: str = ''
        mac: str = ''
        name: str = ''
        os: str = ''
        pin: str = ''
        token: str = ''
        version: str = ''
        _v0 = field_validator('device_id', 'enrollment_token', 'hostname', 'ip', 'mac', 'name', 'os', 'pin', 'token', 'version', mode='before')(_coerce_str_loose)

    class DevicePduRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        host: str = ''
        kind: str = ''
        outlet: str = ''
        _v0 = field_validator('host', 'kind', 'outlet', mode='before')(_coerce_str_loose)

    class DevicePowerControlRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        _v0 = field_validator('action', mode='before')(_coerce_str_loose)

    class ServiceActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        unit: str = ''
        _v0 = field_validator('action', 'unit', mode='before')(_coerce_str_loose)

    class ProcessKillRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        pid: str = ''
        signal: str = ''
        _v0 = field_validator('pid', 'signal', mode='before')(_coerce_str_loose)

    class DeviceUpsDependencyRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        source_device_id: str = ''
        ups_name: str = ''
        _v0 = field_validator('source_device_id', 'ups_name', mode='before')(_coerce_str_loose)

    class UpdateDeviceRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        force: str = ''
        _v0 = field_validator('force', mode='before')(_coerce_str_loose)

    class WolRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class IntegrationsSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        integrations: str = ''
        interval: int = 300
        show_homelab: bool = False
        show_provisioning: bool = False
        _v0 = field_validator('integrations', mode='before')(_coerce_str_loose)
        _v1 = field_validator('interval', mode='before')(_coerce_int_or(300))
        _v2 = field_validator('show_homelab', 'show_provisioning', mode='before')(_coerce_bool_loose)

    class IntegrationTestRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        type: str = ''
        _v0 = field_validator('type', mode='before')(_coerce_str_loose)

    class VirtPowerRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        vm_id: str = ''
        _v0 = field_validator('action', 'vm_id', mode='before')(_coerce_str_loose)

    class VirtSnapshotActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        desc: str = ''
        name: str = ''
        vm_id: str = ''
        _v0 = field_validator('action', 'desc', 'name', 'vm_id', mode='before')(_coerce_str_loose)

    class MonitorPauseRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        label: str = ''
        paused: bool = False
        _v0 = field_validator('label', mode='before')(_coerce_str_loose)
        _v1 = field_validator('paused', mode='before')(_coerce_bool_loose)

    class ConfigSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        ack_comment_enabled: bool = False
        after_hours: str = ''
        agentless_ssh_enabled: bool = False
        agentless_ssh_key: str = ''
        alert_email_ack_links: bool = False
        alert_runbooks: str = ''
        allow_internal_monitors: bool = False
        apikey_default_expiry_days: str = ''
        approval_gated_kinds: str = ''
        audit_forward_enabled: bool = False
        audit_forward_host: str = ''
        audit_forward_mode: str = ''
        audit_forward_port: str = ''
        audit_forward_tcp: bool = False
        audit_forward_token: str = ''
        audit_forward_url: str = ''
        audit_hmac_auto_rotate_days: str = ''
        audit_log_retention_days: str = ''
        audit_worm_path: str = ''
        backup: str = ''
        backup_monitors: str = ''
        backup_size_anomaly_pct: str = ''
        billing_enabled: bool = False
        brand_accent: str = ''
        brand_name: str = ''
        brute_force_enabled: bool = False
        brute_force_threshold: str = ''
        brute_force_window_seconds: str = ''
        canary_files: str = ''
        cert_expiry_alerts_enabled: bool = False
        change_approval_enabled: bool = False
        change_approval_no_self: bool = False
        cloud_accounts: str = ''
        cloud_autosync_enabled: bool = False
        cloud_autosync_interval: str = ''
        compliance_baseline: str = ''
        container_stale_ttl: str = ''
        csp_report_logging: bool = False
        csp_report_throttle_per_minute: str = ''
        ct_watch_domains: str = ''
        custom_metric_thresholds: str = ''
        cve_cache_days: str = ''
        cve_severity_filter: str = ''
        cve_webhook_enabled: bool = False
        dashboard_hidden_activity_events: str = ''
        dashboard_hidden_attention_kinds: str = ''
        ddns: str = ''
        debug_logging: bool = False
        default_poll_interval: str = ''
        disk_watchdog_pct: str = ''
        # v6.2.2: Settings → Alert parameters thresholds (loose str, coerced below).
        nic_err_alert_min: str = ''
        snmp_dead_threshold: str = ''
        temp_alert_threshold_c: str = ''
        clock_skew_threshold_ms: str = ''
        proxmox_snapshot_warn_days: str = ''
        drift_watch_compose: bool = False
        email_events: bool = False
        enrol_rules: str = ''
        escalation: str = ''
        external_scheduler: bool = False
        file_manager: str = ''
        fleet_note: str = ''
        geo_anomaly_enabled: bool = False
        geo_anomaly_hours: str = ''
        geoip_asn_db_path: str = ''
        geoip_db_path: str = ''
        health_alert_threshold: str = ''
        healthchecks_interval_seconds: str = ''
        healthchecks_url: str = ''
        iac_execute_enabled: bool = False
        idle_timeout_minutes: str = ''
        image_scan_enabled: bool = False
        incident_auto_promote_enabled: bool = False
        incident_device_threshold: str = ''
        ip_allowlist: str = ''
        ip_allowlist_enabled: str = ''
        kb_enabled: bool = False
        ldap_admin_group: str = ''
        ldap_bind_dn: str = ''
        ldap_bind_password: str = ''
        ldap_enabled: bool = False
        ldap_required_group: str = ''
        ldap_timeout: str = ''
        ldap_tls_verify: bool = False
        ldap_url: str = ''
        ldap_user_base: str = ''
        ldap_user_filter: str = ''
        log_ignore_patterns: str = ''
        login_banner: str = ''
        max_devices: str = ''
        max_sessions_per_user: str = ''
        mdns_enabled: bool = False
        metric_failures_before_alert: str = ''
        mfa_required_roles: str = ''
        monitor_interval: str = ''
        monitor_webhook_enabled: bool = False
        monitors: str = ''
        notifications_test_mode: bool = False
        offline_webhook_enabled: bool = False
        oidc_client_secret: str = ''
        oidc_enabled: bool = False
        oncall: str = ''
        online_ttl: str = ''
        otlp_enabled: bool = False
        otlp_endpoint: str = ''
        otlp_interval: str = ''
        otlp_token: str = ''
        otlp_traces_enabled: bool = False
        otlp_traces_interval: str = ''
        password_breach_check: bool = False
        password_min_length: str = ''
        password_require_classes: bool = False
        patch_alert_threshold: str = ''
        patch_sla: str = ''
        port_audit_enabled: bool = False
        portal_base_url: str = ''
        portal_enabled: bool = False
        portal_ticket_approval_required: bool = False
        posture_digest_cadence: str = ''
        posture_digest_enabled: bool = False
        posture_digest_recipients: str = ''
        process_watches: str = ''
        proxmox_enabled: bool = False
        proxmox_host: str = ''
        proxmox_lifecycle_enabled: bool = False
        proxmox_node: str = ''
        proxmox_token_id: str = ''
        proxmox_token_secret: str = ''
        proxmox_verify_tls: bool = False
        push_enabled: bool = False
        quiet_hours: str = ''
        rdp_enabled: bool = False
        release_key_fingerprint: str = ''
        release_pubkey: str = ''
        remember_me_default: bool = False
        require_agent_mtls: bool = False
        scim_enabled: bool = False
        scim_token: str = ''
        scrub_overdue_days: str = ''
        secrets_mutes: str = ''
        secrets_scan_enabled: bool = False
        secrets_scan_paths: str = ''
        self_update_command: str = ''
        server_name: str = ''
        service_webhook_enabled: bool = False
        session_ttl_long: str = ''
        session_ttl_short: str = ''
        show_provisioning: bool = False
        siem_enabled: bool = False
        siem_format: str = ''
        siem_token: str = ''
        siem_url: str = ''
        slo_target_percent: str = ''
        smtp_enabled: bool = False
        smtp_from: str = ''
        smtp_helo_name: str = ''
        smtp_host: str = ''
        smtp_password: str = ''
        smtp_port: str = ''
        smtp_recipients: str = ''
        smtp_tls: str = ''
        smtp_username: str = ''
        smtp_verify_tls: bool = False
        snapshot_stale_days: str = ''
        snmp_failures_before_alert: str = ''
        software_meters: str = ''
        sso_group_roles: str = ''
        sso_only: bool = False
        status_incident_recipients: str = ''
        status_page: str = ''
        tenancy_enforced: bool = False
        tenancy_rls: bool = False
        ticket_business_hours: str = ''
        ticket_csat_enabled: bool = False
        trust_proxy: bool = False
        unit_flap_restarts: str = ''
        ups_auto_shutdown_enabled: bool = False
        ups_critical_battery_pct: str = ''
        ups_critical_runtime_s: str = ''
        viewers_can_ack_alerts: bool = False
        wan_watch_enabled: bool = False
        warranty_lenovo_client_id: str = ''
        warranty_lookup_enabled: bool = False
        warranty_provider: str = ''
        webhook_allow_loopback: bool = False
        webhook_block_local: bool = False
        webhook_events: bool = False
        webhook_url: str = ''
        webhook_urls: str = ''
        webpush_enabled: bool = False
        webpush_subject: str = ''
        wol_broadcast: str = ''
        wol_port: str = ''
        _v0 = field_validator('ack_comment_enabled', 'agentless_ssh_enabled', 'alert_email_ack_links', 'allow_internal_monitors', 'audit_forward_enabled', 'audit_forward_tcp', 'billing_enabled', 'brute_force_enabled', 'cert_expiry_alerts_enabled', 'change_approval_enabled', 'change_approval_no_self', 'cloud_autosync_enabled', 'csp_report_logging', 'cve_webhook_enabled', 'debug_logging', 'drift_watch_compose', 'email_events', 'external_scheduler', 'geo_anomaly_enabled', 'iac_execute_enabled', 'image_scan_enabled', 'incident_auto_promote_enabled', 'kb_enabled', 'ldap_enabled', 'ldap_tls_verify', 'mdns_enabled', 'monitor_webhook_enabled', 'notifications_test_mode', 'offline_webhook_enabled', 'oidc_enabled', 'otlp_enabled', 'otlp_traces_enabled', 'password_breach_check', 'password_require_classes', 'port_audit_enabled', 'portal_enabled', 'portal_ticket_approval_required', 'posture_digest_enabled', 'proxmox_enabled', 'proxmox_lifecycle_enabled', 'proxmox_verify_tls', 'push_enabled', 'rdp_enabled', 'remember_me_default', 'require_agent_mtls', 'scim_enabled', 'secrets_scan_enabled', 'service_webhook_enabled', 'show_provisioning', 'siem_enabled', 'smtp_enabled', 'smtp_verify_tls', 'sso_only', 'tenancy_enforced', 'tenancy_rls', 'ticket_csat_enabled', 'trust_proxy', 'ups_auto_shutdown_enabled', 'viewers_can_ack_alerts', 'wan_watch_enabled', 'warranty_lookup_enabled', 'webhook_allow_loopback', 'webhook_block_local', 'webhook_events', 'webpush_enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('after_hours', 'agentless_ssh_key', 'alert_runbooks', 'apikey_default_expiry_days', 'approval_gated_kinds', 'audit_forward_host', 'audit_forward_mode', 'audit_forward_port', 'audit_forward_token', 'audit_forward_url', 'audit_hmac_auto_rotate_days', 'audit_log_retention_days', 'audit_worm_path', 'backup', 'backup_monitors', 'backup_size_anomaly_pct', 'brand_accent', 'brand_name', 'brute_force_threshold', 'brute_force_window_seconds', 'canary_files', 'cloud_accounts', 'cloud_autosync_interval', 'compliance_baseline', 'container_stale_ttl', 'csp_report_throttle_per_minute', 'ct_watch_domains', 'custom_metric_thresholds', 'cve_cache_days', 'cve_severity_filter', 'dashboard_hidden_activity_events', 'dashboard_hidden_attention_kinds', 'ddns', 'default_poll_interval', 'disk_watchdog_pct', 'nic_err_alert_min', 'snmp_dead_threshold', 'temp_alert_threshold_c', 'clock_skew_threshold_ms', 'proxmox_snapshot_warn_days', 'enrol_rules', 'escalation', 'file_manager', 'fleet_note', 'geo_anomaly_hours', 'geoip_asn_db_path', 'geoip_db_path', 'health_alert_threshold', 'healthchecks_interval_seconds', 'healthchecks_url', 'idle_timeout_minutes', 'incident_device_threshold', 'ip_allowlist', 'ip_allowlist_enabled', 'ldap_admin_group', 'ldap_bind_dn', 'ldap_bind_password', 'ldap_required_group', 'ldap_timeout', 'ldap_url', 'ldap_user_base', 'ldap_user_filter', 'log_ignore_patterns', 'login_banner', 'max_devices', 'max_sessions_per_user', 'metric_failures_before_alert', 'mfa_required_roles', 'monitor_interval', 'monitors', 'oidc_client_secret', 'oncall', 'online_ttl', 'otlp_endpoint', 'otlp_interval', 'otlp_token', 'otlp_traces_interval', 'password_min_length', 'patch_alert_threshold', 'patch_sla', 'portal_base_url', 'posture_digest_cadence', 'posture_digest_recipients', 'process_watches', 'proxmox_host', 'proxmox_node', 'proxmox_token_id', 'proxmox_token_secret', 'quiet_hours', 'release_key_fingerprint', 'release_pubkey', 'scim_token', 'scrub_overdue_days', 'secrets_mutes', 'secrets_scan_paths', 'self_update_command', 'server_name', 'session_ttl_long', 'session_ttl_short', 'siem_format', 'siem_token', 'siem_url', 'slo_target_percent', 'smtp_from', 'smtp_helo_name', 'smtp_host', 'smtp_password', 'smtp_port', 'smtp_recipients', 'smtp_tls', 'smtp_username', 'snapshot_stale_days', 'snmp_failures_before_alert', 'software_meters', 'sso_group_roles', 'status_incident_recipients', 'status_page', 'ticket_business_hours', 'unit_flap_restarts', 'ups_critical_battery_pct', 'ups_critical_runtime_s', 'warranty_lenovo_client_id', 'warranty_provider', 'webhook_url', 'webhook_urls', 'webpush_subject', 'wol_broadcast', 'wol_port', mode='before')(_coerce_str_loose)

    class QueryBatchRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        queries: str = ''
        _v0 = field_validator('queries', mode='before')(_coerce_str_loose)

    class QueryTemplateCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        entity: str = ''
        name: str = ''
        shared: str = ''
        sort: str = ''
        sort_desc: bool = False
        where: str = ''
        _v0 = field_validator('entity', 'name', 'shared', 'sort', 'where', mode='before')(_coerce_str_loose)
        _v1 = field_validator('sort_desc', mode='before')(_coerce_bool_loose)

    class ScimUsersCollectionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        active: bool = False
        emails: str = ''
        name: str = ''
        userName: str = ''
        _v0 = field_validator('active', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('emails', 'name', 'userName', mode='before')(_coerce_str_loose)

    class ScimUserRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        Operations: Any = None
        active: bool = False
        _v0 = field_validator('active', mode='before')(_coerce_bool_loose)

    class ScimGroupRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        Operations: Any = None
        members: str = ''
        _v0 = field_validator('members', mode='before')(_coerce_str_loose)

    class UserUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        role: str = ''
        _v0 = field_validator('role', mode='before')(_coerce_str_loose)

    class RoleUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class UserPasswdRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        new_password: str = ''
        old_password: str = ''
        username: str = ''
        _v0 = field_validator('new_password', 'old_password', 'username', mode='before')(_coerce_str_loose)

    class MeLangRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        lang: str = ''
        _v0 = field_validator('lang', mode='before')(_coerce_str_loose)

    class TotpConfirmRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        code: str = ''
        _v0 = field_validator('code', mode='before')(_coerce_str_loose)

    class TotpRegenerateCodesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        password: str = ''
        _v0 = field_validator('password', mode='before')(_coerce_str_loose)

    class TotpDisableRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        password: str = ''
        _v0 = field_validator('password', mode='before')(_coerce_str_loose)

    class SigningSignRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        password: str = ''
        _v0 = field_validator('password', mode='before')(_coerce_str_loose)

    class SigningToggleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        password: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('password', mode='before')(_coerce_str_loose)

    class TlsGenSelfSignedRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        hosts: str = ''
        _v0 = field_validator('hosts', mode='before')(_coerce_str_loose)

    class TlsImportP12Request(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        p12: str = ''
        p12_b64: str = ''
        password: str = ''
        _v0 = field_validator('p12', 'p12_b64', 'password', mode='before')(_coerce_str_loose)

    class StorageBackendMigrateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        dry_run: bool = False
        dsn: str = ''
        dsn_read: str = ''
        target: str = ''
        verify_only: bool = False
        _v0 = field_validator('dry_run', 'verify_only', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('dsn', 'dsn_read', 'target', mode='before')(_coerce_str_loose)

    class SlaTargetsPutRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        default: str = ''
        _v0 = field_validator('default', mode='before')(_coerce_str_loose)

    class ScheduleAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        command: str = ''
        cron: str = ''
        device_id: str = ''
        run_at: str = ''
        _v0 = field_validator('command', 'cron', 'device_id', 'run_at', mode='before')(_coerce_str_loose)

    class ScheduleUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        command: str = ''
        cron: str = ''
        device_id: str = ''
        run_at: str = ''
        _v0 = field_validator('command', 'cron', 'device_id', 'run_at', mode='before')(_coerce_str_loose)

    class CustomCmdRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cmd: str = ''
        timeout: int = 0
        _v0 = field_validator('cmd', mode='before')(_coerce_str_loose)
        _v1 = field_validator('timeout', mode='before')(_coerce_int_or(0))

    class ProxmoxTestRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        proxmox_token_secret: str = ''
        proxmox_verify_tls: bool = False
        _v0 = field_validator('proxmox_token_secret', mode='before')(_coerce_str_loose)
        _v1 = field_validator('proxmox_verify_tls', mode='before')(_coerce_bool_loose)

    class ProxmoxLifecycleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        dry: str = ''
        guest_type: str = ''
        params: str = ''
        vmid: str = ''
        _v0 = field_validator('action', 'dry', 'guest_type', 'params', 'vmid', mode='before')(_coerce_str_loose)

    class CloudImportRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        provider: str = ''
        region: str = ''
        _v0 = field_validator('provider', 'region', mode='before')(_coerce_str_loose)

    class ImageCveScanRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class SecretsScanNowRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class ProxmoxLxcCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        hostname: str = ''
        ostemplate: str = ''
        _v0 = field_validator('hostname', 'ostemplate', mode='before')(_coerce_str_loose)

    class ProxmoxQemuCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class ProxmoxSnapshotActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        confirm: str = ''
        description: str = ''
        name: str = ''
        type: str = ''
        vmid: str = ''
        _v0 = field_validator('action', 'confirm', 'description', 'name', 'type', 'vmid', mode='before')(_coerce_str_loose)

    class DeviceComposeActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        dir: str = ''
        _v0 = field_validator('action', 'dir', mode='before')(_coerce_str_loose)

    class DeviceContainerActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        container_id: str = ''
        runtime: str = ''
        _v0 = field_validator('action', 'container_id', 'runtime', mode='before')(_coerce_str_loose)

    class DmarcImapSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        folder: str = ''
        host: str = ''
        interval: int = 900
        password: str = ''
        port: int = 993
        use_ssl: str = ''
        username: str = ''
        verify_tls: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('folder', 'host', 'password', 'use_ssl', 'username', 'verify_tls', mode='before')(_coerce_str_loose)
        _v2 = field_validator('interval', mode='before')(_coerce_int_or(900))
        _v3 = field_validator('port', mode='before')(_coerce_int_or(993))

    class MailflowSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        imap_folder: str = ''
        imap_host: str = ''
        imap_password: str = ''
        imap_port: int = 993
        imap_ssl: str = ''
        imap_user: str = ''
        imap_verify_tls: str = ''
        max_latency_seconds: int = 300
        to_address: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('imap_folder', 'imap_host', 'imap_password', 'imap_ssl', 'imap_user', 'imap_verify_tls', 'to_address', mode='before')(_coerce_str_loose)
        _v2 = field_validator('imap_port', mode='before')(_coerce_int_or(993))
        _v3 = field_validator('max_latency_seconds', mode='before')(_coerce_int_or(300))

    class ResolverHealthAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        label: str = ''
        name: str = ''
        type: str = ''
        _v0 = field_validator('label', 'name', 'type', mode='before')(_coerce_str_loose)

    class AgentlessCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        connected_to: str = ''
        device_type: str = ''
        group: str = ''
        hostname: str = ''
        ip: str = ''
        mac: str = ''
        manual_status: bool = False
        name: str = ''
        notes: str = ''
        os: str = ''
        tags: Any = None
        _v0 = field_validator('connected_to', 'device_type', 'group', 'hostname', 'ip', 'mac', 'name', 'notes', 'os', mode='before')(_coerce_str_loose)
        _v1 = field_validator('manual_status', mode='before')(_coerce_bool_loose)

    class DeviceConnectedToRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        connected_to: str = ''
        _v0 = field_validator('connected_to', mode='before')(_coerce_str_loose)

    class DeviceDependsOnRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        depends_on: Any = None

    class RebootPlanRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        scope: dict = {}
        _v0 = field_validator('scope', mode='before')(_coerce_dict_loose)

    class DeviceLiveSampleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cpu: str = ''
        disk: str = ''
        mem: str = ''
        swap: str = ''
        token: str = ''
        _v0 = field_validator('cpu', 'disk', 'mem', 'swap', 'token', mode='before')(_coerce_str_loose)

    class DependencySuggestionsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        device_id: str = ''
        upstream_id: str = ''
        _v0 = field_validator('action', 'device_id', 'upstream_id', mode='before')(_coerce_str_loose)

    class LldpSuggestionsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        device_id: str = ''
        peer_id: str = ''
        _v0 = field_validator('action', 'device_id', 'peer_id', mode='before')(_coerce_str_loose)

    class NetworkPositionsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        positions: str = ''
        _v0 = field_validator('positions', mode='before')(_coerce_str_loose)

    class TunnelAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        endpoints: Any = None

    class DeviceAllowlistRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        allowed_commands: Any = None

    class CmdLibraryAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cmd: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('cmd', 'description', 'name', mode='before')(_coerce_str_loose)

    class CmdLibraryUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cmd: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('cmd', 'description', 'name', mode='before')(_coerce_str_loose)

    class ScriptsAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('body', 'description', 'name', mode='before')(_coerce_str_loose)

    class ScriptsUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('body', 'description', 'name', mode='before')(_coerce_str_loose)

    class ExecBatchRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        confirm_dangerous: str = ''
        device_ids: str = ''
        script_id: str = ''
        _v0 = field_validator('confirm_dangerous', 'device_ids', 'script_id', mode='before')(_coerce_str_loose)

    class AiConfigSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        api_key: str = ''
        base_url: str = ''
        context: bool = False
        limits: str = ''
        privacy: bool = False
        provider: str = ''
        rag: str = ''
        _v0 = field_validator('api_key', 'base_url', 'limits', 'provider', 'rag', mode='before')(_coerce_str_loose)
        _v1 = field_validator('context', 'privacy', mode='before')(_coerce_bool_loose)

    class AiRagIndexMigrateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        target: str = ''
        _v0 = field_validator('target', mode='before')(_coerce_str_loose)

    class AiRagSearchRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        query: str = ''
        top_n: str = ''
        _v0 = field_validator('query', 'top_n', mode='before')(_coerce_str_loose)

    class AiChatRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        context: str = ''
        debug: str = ''
        max_tokens: str = ''
        messages: str = ''
        model_: str = Field(default='', alias='model')
        system: str = ''
        _v0 = field_validator('context', 'debug', 'max_tokens', 'messages', 'model_', 'system', mode='before')(_coerce_str_loose)

    class DeviceNetscanRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        subnet: str = ''
        _v0 = field_validator('subnet', mode='before')(_coerce_str_loose)

    class NetscanSchedulesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        interval_minutes: int = 60
        subnet: str = ''
        _v0 = field_validator('device_id', 'subnet', mode='before')(_coerce_str_loose)
        _v1 = field_validator('interval_minutes', mode='before')(_coerce_int_or(60))

    class DeviceQuarantineRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        quarantined: bool = False
        _v0 = field_validator('quarantined', mode='before')(_coerce_bool_loose)

    class DeviceRunbookRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        trigger: str = ''
        _v0 = field_validator('trigger', mode='before')(_coerce_str_loose)

    class AiCronRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        description: str = ''
        _v0 = field_validator('description', mode='before')(_coerce_str_loose)

    class MailwatchSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        dashboard: bool = False
        paths: str = ''
        threshold: str = ''
        _v0 = field_validator('dashboard', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('paths', 'threshold', mode='before')(_coerce_str_loose)

    class MonitoringProfilesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        script_ids: str = ''
        _v0 = field_validator('name', 'script_ids', mode='before')(_coerce_str_loose)

    class MonitoringProfileApplyRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_ids: Any = None
        profile_id: str = ''
        _v0 = field_validator('profile_id', mode='before')(_coerce_str_loose)

    class CustomScriptCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        assigned_devices: Any = None
        body: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('body', 'description', 'name', mode='before')(_coerce_str_loose)

    class CustomScriptUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        assigned_devices: str = ''
        body: str = ''
        description: str = ''
        name: str = ''
        _v0 = field_validator('assigned_devices', 'body', 'description', 'name', mode='before')(_coerce_str_loose)

    class ChecksToggleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        check: str = ''
        device_id: str = ''
        enabled: bool = False
        _v0 = field_validator('check', 'device_id', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', mode='before')(_coerce_bool_loose)

    class CustomChecksSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        id: str = ''
        name: str = ''
        param: str = ''
        target: str = ''
        target_kind: str = ''
        type: str = ''
        unit: str = ''
        watch_service: str = ''
        _v0 = field_validator('id', 'name', 'param', 'target', 'target_kind', 'type', 'unit', 'watch_service', mode='before')(_coerce_str_loose)

    class DashboardKindsSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        channel_routing: str = ''
        _v0 = field_validator('channel_routing', mode='before')(_coerce_str_loose)

    class IncidentsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        impact: str = ''
        status: str = ''
        title: str = ''
        _v0 = field_validator('body', 'impact', 'status', 'title', mode='before')(_coerce_str_loose)

    class IncidentUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        status: str = ''
        _v0 = field_validator('body', 'status', mode='before')(_coerce_str_loose)

    class StatusTokenRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_str_loose)

    class DriftProfilesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class DriftProfileEditRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        files: str = ''
        name: str = ''
        _v0 = field_validator('files', 'name', mode='before')(_coerce_str_loose)

    class DriftAssignRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        profile_id: str = ''
        scope_type: str = ''
        scope_value: str = ''
        _v0 = field_validator('profile_id', 'scope_type', 'scope_value', mode='before')(_coerce_str_loose)

    class DriftIgnoreRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        ignored: bool = False
        path: str = ''
        reason: str = ''
        _v0 = field_validator('ignored', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('path', 'reason', mode='before')(_coerce_str_loose)

    class DeviceDriftBaselineRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        all: bool = False
        paths: str = ''
        _v0 = field_validator('all', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('paths', mode='before')(_coerce_str_loose)

    class DriftFetchContentRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        paths: Any = None

    class RevokeSessionsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        username: str = ''
        _v0 = field_validator('username', mode='before')(_coerce_str_loose)

    class SatellitesCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        scanner: bool = False
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)
        _v1 = field_validator('scanner', mode='before')(_coerce_bool_loose)

    class SatelliteMonitorResultsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        results: str = ''
        _v0 = field_validator('results', mode='before')(_coerce_str_loose)

    class ScansCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        attestation: str = ''
        device_id: str = ''
        intensity: str = ''
        override_window: str = ''
        profile: str = ''
        satellite_id: str = ''
        scan_target_id: str = ''
        tool: str = ''
        vhost: str = ''
        _v0 = field_validator('attestation', 'device_id', 'intensity', 'override_window', 'profile', 'satellite_id', 'scan_target_id', 'tool', 'vhost', mode='before')(_coerce_str_loose)

    class ScanResultsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        error: str = ''
        findings: str = ''
        status: str = ''
        _v0 = field_validator('error', 'findings', 'status', mode='before')(_coerce_str_loose)

    class ScanSchedulesCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        attestation: str = ''
        cron: str = ''
        device_id: str = ''
        intensity: str = ''
        name: str = ''
        profile: str = ''
        satellite_id: str = ''
        scan_target_id: str = ''
        tool: str = ''
        _v0 = field_validator('attestation', 'cron', 'device_id', 'intensity', 'name', 'profile', 'satellite_id', 'scan_target_id', 'tool', mode='before')(_coerce_str_loose)

    class ClientErrorRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        col: str = ''
        line: str = ''
        message: str = ''
        source: str = ''
        stack: str = ''
        url: str = ''
        _v0 = field_validator('col', 'line', 'message', 'source', 'stack', 'url', mode='before')(_coerce_str_loose)

    class ApikeysUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        expires_at: str = ''
        ip_allow: str = ''
        name: str = ''
        rate_limit: int = 0
        role: str = ''
        rotate_after_days: int = 0
        scope: str = ''
        _v0 = field_validator('expires_at', 'ip_allow', 'name', 'role', 'scope', mode='before')(_coerce_str_loose)
        _v1 = field_validator('rate_limit', 'rotate_after_days', mode='before')(_coerce_int_or(0))

    class LongpollExecRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cmd: str = ''
        device_id: str = ''
        timeout: int = 90
        _v0 = field_validator('cmd', 'device_id', mode='before')(_coerce_str_loose)
        _v1 = field_validator('timeout', mode='before')(_coerce_int_or(90))

    class ComplianceRemediateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        check_id: str = ''
        device_id: str = ''
        _v0 = field_validator('check_id', 'device_id', mode='before')(_coerce_str_loose)

    class ScapScanRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        profile: str = ''
        _v0 = field_validator('profile', mode='before')(_coerce_str_loose)

    class ScapReportRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        available: bool = False
        available_profiles: str = ''
        counts: str = ''
        datastream: str = ''
        device_id: str = ''
        failed_rules: Any = None
        profile: str = ''
        reason: str = ''
        report_bytes: str = ''
        report_html_gz: str = ''
        score: str = ''
        token: str = ''
        _v0 = field_validator('available', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('available_profiles', 'counts', 'datastream', 'device_id', 'profile', 'reason', 'report_bytes', 'report_html_gz', 'score', 'token', mode='before')(_coerce_str_loose)

    class PatchSnapshotsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        _v0 = field_validator('name', mode='before')(_coerce_str_loose)

    class PatchSnapshotPromoteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        tag: str = ''
        _v0 = field_validator('tag', mode='before')(_coerce_str_loose)

    class PatchSnapshotEnforceRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class ReportScheduleSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cron: str = ''
        enabled: bool = False
        recipients: Any = None
        _v0 = field_validator('cron', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', mode='before')(_coerce_bool_loose)

    class WebauthnRegisterCompleteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        credential: str = ''
        name: str = ''
        _v0 = field_validator('credential', 'name', mode='before')(_coerce_str_loose)

    class WebauthnLoginCompleteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        credential: dict = {}
        remember_me: bool = False
        username: str = ''
        _v0 = field_validator('credential', mode='before')(_coerce_dict_loose)
        _v1 = field_validator('remember_me', mode='before')(_coerce_bool_loose)
        _v2 = field_validator('username', mode='before')(_coerce_str_loose)

    class AlertAckRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        note: str = ''
        _v0 = field_validator('note', mode='before')(_coerce_str_loose)

    class AlertResolveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        note: str = ''
        _v0 = field_validator('note', mode='before')(_coerce_str_loose)

    class AlertMutesRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        alert_id: str = ''
        device_id: str = ''
        device_name: str = ''
        event: str = ''
        hours: str = ''
        _v0 = field_validator('alert_id', 'device_id', 'device_name', 'event', 'hours', mode='before')(_coerce_str_loose)

    class AlertsBulkResolveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        ids: Any = None

    class AlertsBulkAckRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        ids: Any = None
        note: str = ''
        _v0 = field_validator('note', mode='before')(_coerce_str_loose)

    class InboundWebhookRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        body: str = ''
        links: str = ''
        severity: str = ''
        source: str = ''
        title: str = ''
        _v0 = field_validator('body', 'links', 'severity', 'source', 'title', mode='before')(_coerce_str_loose)

    class InboundWebhooksCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        kind: str = ''
        label: str = ''
        scope_device_id: str = ''
        scope_tag: str = ''
        _v0 = field_validator('kind', 'label', 'scope_device_id', 'scope_tag', mode='before')(_coerce_str_loose)

    class InboundWebhookToggleRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        label: str = ''
        scope_device_id: str = ''
        scope_tag: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('label', 'scope_device_id', 'scope_tag', mode='before')(_coerce_str_loose)

    class ConfirmationRejectRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        note: str = ''
        _v0 = field_validator('note', mode='before')(_coerce_str_loose)

    class ImageIgnoreAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        reason: str = ''
        ref: str = ''
        _v0 = field_validator('reason', 'ref', mode='before')(_coerce_str_loose)

    class ImageIgnoreRemoveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        ref: str = ''
        _v0 = field_validator('ref', mode='before')(_coerce_str_loose)

    class AppCatalogCustomAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        category: str = ''
        description: str = ''
        name: str = ''
        port: int = 0
        yaml: str = ''
        _v0 = field_validator('category', 'description', 'name', 'yaml', mode='before')(_coerce_str_loose)
        _v1 = field_validator('port', mode='before')(_coerce_int_or(0))

    class AppCatalogCustomDeleteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        id: str = ''
        _v0 = field_validator('id', mode='before')(_coerce_str_loose)

    class AppCatalogDeployRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        app_id: str = ''
        device_id: str = ''
        _v0 = field_validator('app_id', 'device_id', mode='before')(_coerce_str_loose)

    class ComposeStackCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        name: str = ''
        yaml: str = ''
        _v0 = field_validator('device_id', 'name', 'yaml', mode='before')(_coerce_str_loose)

    class ComposeStackActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        _v0 = field_validator('action', mode='before')(_coerce_str_loose)

    class ComposeFetchRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        stack_id: str = ''
        token: str = ''
        _v0 = field_validator('device_id', 'stack_id', 'token', mode='before')(_coerce_str_loose)

    class DeviceRouterosRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        password: str = ''
        port: str = ''
        username: str = ''
        verify: bool = False
        _v0 = field_validator('enabled', 'verify', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('password', 'port', 'username', mode='before')(_coerce_str_loose)

    class DeviceRouterosActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        arg: str = ''
        rule: str = ''
        _v0 = field_validator('action', 'arg', 'rule', mode='before')(_coerce_str_loose)

    class DeviceOpnsenseRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        api_key: str = ''
        api_secret: str = ''
        enabled: bool = False
        port: str = ''
        verify: bool = False
        _v0 = field_validator('api_key', 'api_secret', 'port', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', 'verify', mode='before')(_coerce_bool_loose)

    class DeviceOpnsenseActionRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        arg: str = ''
        rule: str = ''
        _v0 = field_validator('action', 'arg', 'rule', mode='before')(_coerce_str_loose)

    class DeviceSshRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        password: str = ''
        port: str = ''
        private_key: str = ''
        username: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('password', 'port', 'private_key', 'username', mode='before')(_coerce_str_loose)

    class DeviceSnmpRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        community: str = ''
        enabled: bool = False
        port: str = ''
        v3_auth_proto: str = ''
        v3_context: str = ''
        v3_priv_proto: str = ''
        v3_user: str = ''
        version: str = ''
        _v0 = field_validator('community', 'port', 'v3_auth_proto', 'v3_context', 'v3_priv_proto', 'v3_user', 'version', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', mode='before')(_coerce_bool_loose)

    class WebhookTestRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        id: str = ''
        _v0 = field_validator('id', mode='before')(_coerce_str_loose)

    class WebhookDlqRetryRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        all: bool = False
        id: str = ''
        _v0 = field_validator('all', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('id', mode='before')(_coerce_str_loose)

    class WebhookReplayRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        event: str = ''
        ts: int = 0
        _v0 = field_validator('event', mode='before')(_coerce_str_loose)
        _v1 = field_validator('ts', mode='before')(_coerce_int_or(0))

    class SmtpTestRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        recipient: str = ''
        _v0 = field_validator('recipient', mode='before')(_coerce_str_loose)

    class LdapTestUserRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        password: str = ''
        username: str = ''
        _v0 = field_validator('password', 'username', mode='before')(_coerce_str_loose)

    class PackagesSubmitRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        ecosystem_hint: dict = {}
        packages: Any = None
        pkg_manager: str = ''
        token: str = ''
        _v0 = field_validator('device_id', 'pkg_manager', 'token', mode='before')(_coerce_str_loose)
        _v1 = field_validator('ecosystem_hint', mode='before')(_coerce_dict_loose)

    class SoftwarePolicyRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        rules: str = ''
        _v0 = field_validator('rules', mode='before')(_coerce_str_loose)

    class ExposureMuteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        action: str = ''
        device_id: str = ''
        port: str = ''
        process: str = ''
        proto: str = ''
        _v0 = field_validator('action', 'device_id', 'port', 'process', 'proto', mode='before')(_coerce_str_loose)

    class SecretsMuteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        fingerprint: str = ''
        unmute: bool = False
        _v0 = field_validator('fingerprint', mode='before')(_coerce_str_loose)
        _v1 = field_validator('unmute', mode='before')(_coerce_bool_loose)

    class SecretsHostMuteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        unmute: bool = False
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)
        _v1 = field_validator('unmute', mode='before')(_coerce_bool_loose)

    class CveScanRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class CveCampaignsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cve_ids: Any = None
        kev_only: bool = False
        name: str = ''
        owner: str = ''
        severities: Any = None
        target_date: str = ''
        _v0 = field_validator('kev_only', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('name', 'owner', 'target_date', mode='before')(_coerce_str_loose)

    class CveCampaignRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        name: str = ''
        owner: str = ''
        target_date: str = ''
        _v0 = field_validator('name', 'owner', 'target_date', mode='before')(_coerce_str_loose)

    class MyNotifyPrefsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        clear_webhook: str = ''
        email: str = ''
        enabled: bool = False
        events: str = ''
        min_priority: int = 0
        scope_filter: str = ''
        webhook_url: str = ''
        _v0 = field_validator('clear_webhook', 'email', 'events', 'scope_filter', 'webhook_url', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v2 = field_validator('min_priority', mode='before')(_coerce_int_or(0))

    class ImportMonitorsRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        apply: str = ''
        content: str = ''
        format: str = ''
        _v0 = field_validator('apply', 'content', 'format', mode='before')(_coerce_str_loose)

    class CveIgnoreAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        reason: str = ''
        scope: str = ''
        vuln_id: str = ''
        _v0 = field_validator('reason', 'scope', 'vuln_id', mode='before')(_coerce_str_loose)

    class MetricsPushSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        enabled: bool = False
        interval: int = 60
        job: str = ''
        url: str = ''
        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('interval', mode='before')(_coerce_int_or(60))
        _v2 = field_validator('job', 'url', mode='before')(_coerce_str_loose)

    class GitopsSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        auth_header: str = ''
        enabled: bool = False
        interval: int = 900
        url: str = ''
        _v0 = field_validator('auth_header', 'url', mode='before')(_coerce_str_loose)
        _v1 = field_validator('enabled', mode='before')(_coerce_bool_loose)
        _v2 = field_validator('interval', mode='before')(_coerce_int_or(900))

    class MaintenanceAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        cron: str = ''
        duration: int = 0
        end: str = ''
        events: Any = None
        gate_exec: bool = False
        reason: str = ''
        scope: str = ''
        start: str = ''
        target: str = ''
        _v0 = field_validator('cron', 'end', 'reason', 'scope', 'start', 'target', mode='before')(_coerce_str_loose)
        _v1 = field_validator('duration', mode='before')(_coerce_int_or(0))
        _v2 = field_validator('gate_exec', mode='before')(_coerce_bool_loose)

    class ServicesConfigRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        log_watch: Any = None
        services_watched: Any = None

    class LogSubmitRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        token: str = ''
        units: dict = {}
        _v0 = field_validator('device_id', 'token', mode='before')(_coerce_str_loose)
        _v1 = field_validator('units', mode='before')(_coerce_dict_loose)

    class DeviceHostConfigPutRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        apply_enabled: str = ''
        enforce: str = ''
        _v0 = field_validator('apply_enabled', 'enforce', mode='before')(_coerce_str_loose)

    class HostConfigCollectAllRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        target: str = ''
        _v0 = field_validator('target', mode='before')(_coerce_str_loose)

    class DebugLogPostRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        entries: Any = None

    class IacRequestRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        categories: Any = None
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class IacGenerateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        categories: str = ''
        output_format: str = ''
        request_id: str = ''
        user_instructions: str = ''
        _v0 = field_validator('categories', 'output_format', 'request_id', 'user_instructions', mode='before')(_coerce_str_loose)

    class AiPromptsSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        key: str = ''
        text: str = ''
        _v0 = field_validator('key', 'text', mode='before')(_coerce_str_loose)

    class IgnoredAddRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        category: str = ''
        container: str = ''
        device_id: str = ''
        expires_at: str = ''
        id: str = ''
        key: str = ''
        label: str = ''
        _v0 = field_validator('category', 'container', 'device_id', 'expires_at', 'id', 'key', 'label', mode='before')(_coerce_str_loose)

    class IgnoredRemoveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        category: str = ''
        container: str = ''
        device_id: str = ''
        id: str = ''
        key: str = ''
        _v0 = field_validator('category', 'container', 'device_id', 'id', 'key', mode='before')(_coerce_str_loose)

    class AiParamsSaveRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        key: str = ''
        _v0 = field_validator('key', mode='before')(_coerce_str_loose)

    class AcmeDnsCredentialsSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        credentials: dict = {}
        provider: str = ''
        _v0 = field_validator('credentials', mode='before')(_coerce_dict_loose)
        _v1 = field_validator('provider', mode='before')(_coerce_str_loose)

    class DnsVaultCredsSetRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        credentials: dict = {}
        provider: str = ''
        _v0 = field_validator('credentials', mode='before')(_coerce_dict_loose)
        _v1 = field_validator('provider', mode='before')(_coerce_str_loose)

    class DnsImportFromAgentRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        device_id: str = ''
        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class DnsVaultImportRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        clear_plaintext: bool = False
        provider: str = ''
        _v0 = field_validator('clear_plaintext', mode='before')(_coerce_bool_loose)
        _v1 = field_validator('provider', mode='before')(_coerce_str_loose)

    class DnsRecordCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        provider: str = ''
        _v0 = field_validator('provider', mode='before')(_coerce_str_loose)

    class DnsRecordUpdateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        id: str = ''
        provider: str = ''
        _v0 = field_validator('id', 'provider', mode='before')(_coerce_str_loose)

    class DnsRecordDeleteRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        id: str = ''
        name: str = ''
        provider: str = ''
        type: str = ''
        _v0 = field_validator('id', 'name', 'provider', 'type', mode='before')(_coerce_str_loose)

    class AcmeIssueRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        alt_names: Any = None
        dns_provider: str = ''
        domain: str = ''
        key_length: str = ''
        _v0 = field_validator('dns_provider', 'domain', 'key_length', mode='before')(_coerce_str_loose)

    class MitigateInvestigateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        kind: str = ''
        target: str = ''
        _v0 = field_validator('kind', 'target', mode='before')(_coerce_str_loose)

    class MitigateFixRequest(BaseModel):
        model_config = ConfigDict(extra='ignore', protected_namespaces=())
        command: str = ''
        confirmation: str = ''
        kind: str = ''
        target: str = ''
        _v0 = field_validator('command', 'confirmation', 'kind', 'target', mode='before')(_coerce_str_loose)

    class AiExecProposeRequest(BaseModel):
        """handle_ai_exec_propose POST (v6.2.0). Both fields str-coerced to match
        the handler's `str(body.get(f) or '')`; the handler runs _validate_id on
        device_id and _sanitize_str on context.

        NOTE there is deliberately no `command` / `action` field: the caller does
        not get to name an action, and neither does the model. The executor selects
        from a server-built catalog by id, and that id is validated against it."""
        model_config = ConfigDict(extra='ignore')
        device_id: str = ''
        context: str = ''

        _v0 = field_validator('device_id', 'context', mode='before')(_coerce_str_loose)

    class QuoteCreateRequest(BaseModel):
        """handle_quotes POST (v6.2.0). site_id/notes are str-coerced; the handler
        validates site_id against SITES_FILE and requires >=1 line item itself.

        `line_items` is `Any`, not `list`: the handler does `body.get('line_items')
        or []` and then iterates with an isinstance guard per element, so a truthy
        non-list is already tolerated (the `list_or` shape). valid_until is `Any` —
        the handler int()s it inside a try/except down to 0."""
        model_config = ConfigDict(extra='ignore')
        site_id: str = ''
        notes: str = ''
        line_items: Any = None
        valid_until: Any = None

        _v0 = field_validator('site_id', 'notes', mode='before')(_coerce_str_loose)

    class QuoteUpdateRequest(BaseModel):
        """handle_quote_update POST (v6.2.0). The handler validates `status`
        against its own allowed tuple, so no Literal here (the two can't drift)."""
        model_config = ConfigDict(extra='ignore')
        status: str = ''

        _v0 = field_validator('status', mode='before')(_coerce_str_loose)

    class PiiScanNowRequest(BaseModel):
        """handle_pii_scan_now POST (v6.2.0). device_id is str-coerced to match
        `str(body.get('device_id') or '')`; the handler still runs _validate_id.
        Empty body == scan every agent host, so nothing may be required."""
        model_config = ConfigDict(extra='ignore')
        device_id: str = ''

        _v0 = field_validator('device_id', mode='before')(_coerce_str_loose)

    class DnsBlockingSetRequest(BaseModel):
        """handle_dns_blocking_set POST (v6.2.0). `enabled` is bool-coerced to
        match the handler's `bool(body.get(...))`.

        `seconds` is `Any`, NOT a bounded int: dns_control.clamp_seconds() already
        falls a non-numeric value back to the default and clamps the rest into
        range, so a bound here would 400 a body the handler handles fine — the
        model is an additive superset, never narrower."""
        model_config = ConfigDict(extra='ignore')
        enabled: bool = False
        seconds: Any = None

        _v0 = field_validator('enabled', mode='before')(_coerce_bool_loose)

    class VaultCheckoutRequest(BaseModel):
        """handle_vault_checkout POST (v6.2.0). device_id/cred_id/reason are
        str-coerced to match the handler's `str(body.get(f) or '')`; the handler
        still runs _validate_id + its own non-empty and reason checks.

        `hours` is deliberately `Any`, NOT a bounded float: the handler already
        try/excepts a non-numeric value down to the default and then CLAMPS into
        range (max(0.25, min(24, ...))). A float bound here would 400 a body the
        old code happily accepted — the model is an additive superset, never
        narrower."""
        model_config = ConfigDict(extra='ignore')
        device_id: str = ''
        cred_id: str = ''
        reason: str = ''
        hours: Any = None

        _v0 = field_validator('device_id', 'cred_id', 'reason', mode='before')(_coerce_str_loose)

else:
    # Placeholders so `request_models.UserCreateRequest` etc. always resolve as
    # an attribute at call sites -- validate() short-circuits on `_AVAILABLE`
    # before ever using the value, but the reference itself must not NameError.
    UserCreateRequest = None
    ApiKeyCreateRequest = None
    BillingPaymentWebhookRequest = None
    LitigationHoldSetRequest = None
    EnrollTokenCreateRequest = None
    TenantCreateRequest = None
    DeadmanCreateRequest = None
    DockerPruneRequest = None
    MaintenanceModeSetRequest = None
    StepUpVerifyRequest = None
    ServiceBaselinesRequest = None
    PushSubscribeRequest = None
    PushUnsubscribeRequest = None
    ContactCreateRequest = None
    ContactUpdateRequest = None
    PortalMagicLinkRequest = None
    PortalSessionRequest = None
    PortalTicketsRequest = None
    PortalTicketQueueDecideRequest = None
    PortalTicketRequest = None
    KbRequest = None
    KbArticleRequest = None
    LoginRequest = None
    DevicesBulkDeleteRequest = None
    DeviceTagsRequest = None
    DevicesBulkTagsRequest = None
    DeviceNotesRequest = None
    DeviceSaveBulkRequest = None
    DeviceMetricThresholdsRequest = None
    DeviceProfilesRequest = None
    DeviceProfileRequest = None
    DeviceProfileApplyRequest = None
    SmartGroupsRequest = None
    SmartGroupRequest = None
    RacksRequest = None
    RackRequest = None
    IpamSubnetsRequest = None
    IpamSubnetRequest = None
    TimeEntryUpdateRequest = None
    TimesheetWatchersRequest = None
    BillingConfigRequest = None
    InvoicesRequest = None
    InvoiceUpdateRequest = None
    SiteCreateRequest = None
    SiteUpdateRequest = None
    TenantUpdateRequest = None
    TenantBrandingRequest = None
    DeviceSiteRequest = None
    DeviceUserActionRequest = None
    DeviceFirewallActionRequest = None
    DeviceFirewallRuleRequest = None
    DeviceFilesRequest = None
    FilesArchiveStartRequest = None
    FilesArchiveCancelRequest = None
    FilesArchiveChunkRequest = None
    DeviceCronActionRequest = None
    DeviceStorageActionRequest = None
    DeviceStorageProvisionRequest = None
    DeviceFail2banActionRequest = None
    AutopatchCreateRequest = None
    AutopatchUpdateRequest = None
    AnsiblePlaybookCreateRequest = None
    AnsiblePlaybookUpdateRequest = None
    AnsiblePlaybookRunRequest = None
    DeviceGroupRequest = None
    DevicePollIntervalRequest = None
    DeviceIconRequest = None
    DeviceMonitoredRequest = None
    DeviceDecommissionRequest = None
    DeviceRequireConfirmationRequest = None
    DeviceComposeEnabledRequest = None
    WebtermAuthRequest = None
    WebtermSessionAuditRequest = None
    EnrollRegisterRequest = None
    DevicePduRequest = None
    DevicePowerControlRequest = None
    ServiceActionRequest = None
    ProcessKillRequest = None
    DeviceUpsDependencyRequest = None
    UpdateDeviceRequest = None
    WolRequest = None
    IntegrationsSaveRequest = None
    IntegrationTestRequest = None
    VirtPowerRequest = None
    VirtSnapshotActionRequest = None
    MonitorPauseRequest = None
    ConfigSaveRequest = None
    QueryBatchRequest = None
    QueryTemplateCreateRequest = None
    ScimUsersCollectionRequest = None
    ScimUserRequest = None
    ScimGroupRequest = None
    UserUpdateRequest = None
    RoleUpdateRequest = None
    UserPasswdRequest = None
    MeLangRequest = None
    TotpConfirmRequest = None
    TotpRegenerateCodesRequest = None
    TotpDisableRequest = None
    SigningSignRequest = None
    SigningToggleRequest = None
    TlsGenSelfSignedRequest = None
    TlsImportP12Request = None
    StorageBackendMigrateRequest = None
    SlaTargetsPutRequest = None
    ScheduleAddRequest = None
    ScheduleUpdateRequest = None
    CustomCmdRequest = None
    ProxmoxTestRequest = None
    ProxmoxLifecycleRequest = None
    CloudImportRequest = None
    ImageCveScanRequest = None
    SecretsScanNowRequest = None
    ProxmoxLxcCreateRequest = None
    ProxmoxQemuCreateRequest = None
    ProxmoxSnapshotActionRequest = None
    DeviceComposeActionRequest = None
    DeviceContainerActionRequest = None
    DmarcImapSaveRequest = None
    MailflowSaveRequest = None
    ResolverHealthAddRequest = None
    AgentlessCreateRequest = None
    DeviceConnectedToRequest = None
    DeviceDependsOnRequest = None
    RebootPlanRequest = None
    DeviceLiveSampleRequest = None
    DependencySuggestionsRequest = None
    LldpSuggestionsRequest = None
    NetworkPositionsRequest = None
    TunnelAddRequest = None
    DeviceAllowlistRequest = None
    CmdLibraryAddRequest = None
    CmdLibraryUpdateRequest = None
    ScriptsAddRequest = None
    ScriptsUpdateRequest = None
    ExecBatchRequest = None
    AiConfigSetRequest = None
    AiRagIndexMigrateRequest = None
    AiRagSearchRequest = None
    AiChatRequest = None
    DeviceNetscanRequest = None
    NetscanSchedulesRequest = None
    DeviceQuarantineRequest = None
    DeviceRunbookRequest = None
    AiCronRequest = None
    MailwatchSetRequest = None
    MonitoringProfilesRequest = None
    MonitoringProfileApplyRequest = None
    CustomScriptCreateRequest = None
    CustomScriptUpdateRequest = None
    ChecksToggleRequest = None
    CustomChecksSaveRequest = None
    DashboardKindsSetRequest = None
    IncidentsRequest = None
    IncidentUpdateRequest = None
    StatusTokenRequest = None
    DriftProfilesRequest = None
    DriftProfileEditRequest = None
    DriftAssignRequest = None
    DriftIgnoreRequest = None
    DeviceDriftBaselineRequest = None
    DriftFetchContentRequest = None
    RevokeSessionsRequest = None
    SatellitesCreateRequest = None
    SatelliteMonitorResultsRequest = None
    ScansCreateRequest = None
    ScanResultsRequest = None
    ScanSchedulesCreateRequest = None
    ClientErrorRequest = None
    ApikeysUpdateRequest = None
    LongpollExecRequest = None
    ComplianceRemediateRequest = None
    ScapScanRequest = None
    ScapReportRequest = None
    PatchSnapshotsRequest = None
    PatchSnapshotPromoteRequest = None
    PatchSnapshotEnforceRequest = None
    ReportScheduleSetRequest = None
    WebauthnRegisterCompleteRequest = None
    WebauthnLoginCompleteRequest = None
    AlertAckRequest = None
    AlertResolveRequest = None
    AlertMutesRequest = None
    AlertsBulkResolveRequest = None
    AlertsBulkAckRequest = None
    InboundWebhookRequest = None
    InboundWebhooksCreateRequest = None
    InboundWebhookToggleRequest = None
    ConfirmationRejectRequest = None
    ImageIgnoreAddRequest = None
    ImageIgnoreRemoveRequest = None
    AppCatalogCustomAddRequest = None
    AppCatalogCustomDeleteRequest = None
    AppCatalogDeployRequest = None
    ComposeStackCreateRequest = None
    ComposeStackActionRequest = None
    ComposeFetchRequest = None
    DeviceRouterosRequest = None
    DeviceRouterosActionRequest = None
    DeviceOpnsenseRequest = None
    DeviceOpnsenseActionRequest = None
    DeviceSshRequest = None
    DeviceSnmpRequest = None
    WebhookTestRequest = None
    WebhookDlqRetryRequest = None
    WebhookReplayRequest = None
    SmtpTestRequest = None
    LdapTestUserRequest = None
    PackagesSubmitRequest = None
    SoftwarePolicyRequest = None
    ExposureMuteRequest = None
    SecretsMuteRequest = None
    SecretsHostMuteRequest = None
    CveScanRequest = None
    CveCampaignsRequest = None
    CveCampaignRequest = None
    MyNotifyPrefsRequest = None
    ImportMonitorsRequest = None
    CveIgnoreAddRequest = None
    MetricsPushSetRequest = None
    GitopsSetRequest = None
    MaintenanceAddRequest = None
    ServicesConfigRequest = None
    LogSubmitRequest = None
    DeviceHostConfigPutRequest = None
    HostConfigCollectAllRequest = None
    DebugLogPostRequest = None
    IacRequestRequest = None
    IacGenerateRequest = None
    AiPromptsSaveRequest = None
    IgnoredAddRequest = None
    IgnoredRemoveRequest = None
    AiParamsSaveRequest = None
    AcmeDnsCredentialsSetRequest = None
    DnsVaultCredsSetRequest = None
    DnsImportFromAgentRequest = None
    DnsVaultImportRequest = None
    DnsRecordCreateRequest = None
    DnsRecordUpdateRequest = None
    DnsRecordDeleteRequest = None
    AcmeIssueRequest = None
    MitigateInvestigateRequest = None
    MitigateFixRequest = None
    VaultCheckoutRequest = None
    DnsBlockingSetRequest = None
    PiiScanNowRequest = None
    QuoteCreateRequest = None
    QuoteUpdateRequest = None
    AiExecProposeRequest = None


def validate(model_cls, body):
    """Returns (True, None) when pydantic is unavailable (caller's existing
    validation runs unchanged) or when the body validates; (False, message)
    on a validation failure -- caller should respond(400, {'error': message})."""
    if not _AVAILABLE:
        return True, None
    if not isinstance(body, dict):
        return False, 'request body must be a JSON object'
    try:
        model_cls(**body)
    except ValidationError as e:
        first = e.errors()[0]
        loc = '.'.join(str(p) for p in first.get('loc', ())) or '(body)'
        return False, f"{loc}: {first.get('msg', 'invalid value')}"
    return True, None
