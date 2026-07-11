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
    from pydantic import BaseModel, ConfigDict, ValidationError, field_validator
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
