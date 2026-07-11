"""Pydantic v2 request-body validation — OPTIONAL, pilot scope (docs/master-
improvement-scoping-internal.md #5). Matches the near-stdlib posture the rest
of the repo holds to: pydantic is not in the required dependency list
(packaging/requirements-server.txt), so every model here is guarded by
``available()`` the same way webauthn_auth.py/saml_auth.py gate their own
optional library.

Scope, deliberately narrow (a pilot, not a sweep): three small, genuinely
security-relevant handlers with clean, mostly-scalar request bodies —
handle_user_create (privilege-escalation target), handle_apikeys_create
(credential minting), handle_billing_payment_webhook (external-facing, money-
adjacent). NOT config-save-shaped monoliths (handle_config_save alone is
thousands of lines of `if 'key' in body` clauses) — those stay hand-rolled
until/unless a real sweep is scoped separately.

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
    from pydantic import BaseModel, ConfigDict, ValidationError
    _AVAILABLE = True
except Exception:  # library not installed -> pilot disabled, handlers unchanged
    _AVAILABLE = False
    BaseModel = object  # placeholder so class bodies below don't NameError


def available():
    return _AVAILABLE


if _AVAILABLE:

    class UserCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        username: str = ''
        password: str = ''
        role: str = 'admin'

    class ApiKeyCreateRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        name: str = ''
        role: str = 'admin'
        user: str = 'api'
        rate_limit: int = 0
        expires_at: int | None = None
        rotate_after_days: int = 0

    class BillingPaymentWebhookRequest(BaseModel):
        model_config = ConfigDict(extra='ignore')
        invoice_id: str = ''
        amount: float
        currency: str = ''
        provider: str = ''
        external_ref: str = ''
        kind: str = 'payment'

else:
    # Placeholders so `request_models.UserCreateRequest` etc. always resolve as
    # an attribute at call sites -- validate() short-circuits on `_AVAILABLE`
    # before ever using the value, but the reference itself must not NameError.
    UserCreateRequest = None
    ApiKeyCreateRequest = None
    BillingPaymentWebhookRequest = None


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
