"""WebAuthn / passkey ceremony helpers (v4.2.0 A1).

Thin wrapper over the vetted ``py_webauthn`` library — we never hand-roll the
crypto. The library is an OPTIONAL dependency: ``available()`` returns False when
it isn't installed, and the API handlers degrade gracefully (503) instead of
crashing. Bytes (credential id, public key, challenge) are stored/transported as
base64url strings.

Security note: this still requires the mandatory pre-prod security review — the
authorization model (which user a credential binds to, sign-count regression =
cloned-authenticator signal) is enforced by the caller in api.py.
"""

try:
    import webauthn as _wa
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    _AVAILABLE = True
except Exception:  # library not installed → feature disabled, app still runs
    _AVAILABLE = False


def available():
    return _AVAILABLE


def _b64u(b):
    return _wa.helpers.bytes_to_base64url(b)


def _from_b64u(s):
    return _wa.base64url_to_bytes(s)


def registration_options(rp_id, rp_name, user_id, user_name, exclude_ids=None):
    """Return (options_json_str, challenge_b64url). exclude_ids = already-registered
    credential ids (b64url) so the authenticator won't double-register."""
    excl = [PublicKeyCredentialDescriptor(id=_from_b64u(i)) for i in (exclude_ids or [])]
    opts = _wa.generate_registration_options(
        rp_id=rp_id, rp_name=rp_name,
        user_id=user_id.encode('utf-8') if isinstance(user_id, str) else user_id,
        user_name=user_name,
        exclude_credentials=excl,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    return _wa.options_to_json(opts), _b64u(opts.challenge)


def registration_verify(credential, challenge_b64u, origin, rp_id):
    """Verify a registration response. Returns {credential_id, public_key,
    sign_count} (all storable), or raises on failure."""
    v = _wa.verify_registration_response(
        credential=credential,
        expected_challenge=_from_b64u(challenge_b64u),
        expected_origin=origin,
        expected_rp_id=rp_id,
    )
    return {'credential_id': _b64u(v.credential_id),
            'public_key': _b64u(v.credential_public_key),
            'sign_count': int(v.sign_count)}


def authentication_options(rp_id, allow_ids=None):
    """Return (options_json_str, challenge_b64url). allow_ids = the user's
    registered credential ids (b64url)."""
    allow = [PublicKeyCredentialDescriptor(id=_from_b64u(i)) for i in (allow_ids or [])]
    opts = _wa.generate_authentication_options(rp_id=rp_id, allow_credentials=allow)
    return _wa.options_to_json(opts), _b64u(opts.challenge)


def authentication_verify(credential, challenge_b64u, origin, rp_id,
                          public_key_b64u, sign_count):
    """Verify an authentication assertion against a stored credential. Returns
    {credential_id, new_sign_count}, or raises on failure."""
    v = _wa.verify_authentication_response(
        credential=credential,
        expected_challenge=_from_b64u(challenge_b64u),
        expected_origin=origin,
        expected_rp_id=rp_id,
        credential_public_key=_from_b64u(public_key_b64u),
        credential_current_sign_count=int(sign_count),
    )
    return {'credential_id': _b64u(v.credential_id),
            'new_sign_count': int(v.new_sign_count)}
