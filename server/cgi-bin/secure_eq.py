"""Constant-time equality for secrets that never raises (7.4.9).

`hmac.compare_digest` raises TypeError when either argument is a `str` with a non-ASCII character. A token, a secret, a fingerprint
or a confirmation text that arrives in a request is an arbitrary string, so a call on the raw value turned a wrong credential into
a 500 (`"token": "é"` on /api/heartbeat and seven more agent routes, before any check had answered 403). The fuzz sweep found 20
call sites, all on `str`, and one helper in api.py that did it right (`_ct_token_eq`, used by two pages): a rule applied in two
places and missed in twenty.

`secure_eq(a, b)` compares the UTF-8 bytes. An empty or missing value is never equal to anything, which is what every caller wants
from a credential check, and a string that cannot be encoded (a lone surrogate) is simply not equal. Every comparison of a secret in
the server goes through it; tests/test_v749_hostile_input.py fails on a bare `compare_digest` anywhere else.
"""
import hmac


def _bytes(x):
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    return x.encode("utf-8", "strict")


def secure_eq(a, b):
    """True when `a` and `b` are the same non-empty text or bytes; compares in constant time and never raises."""
    if not a or not b:
        return False
    try:
        return hmac.compare_digest(_bytes(a), _bytes(b))
    except (UnicodeError, TypeError, ValueError, AttributeError):
        return False
