"""v6.1.1 (#5) — pure unit tests for request_models.py, the OPTIONAL pydantic
v2 request-body validation pilot. No API/storage harness needed here; the
handler-level wiring tests live in test_v310.py (user create, apikey create)
and test_v540_features.py::TestBillingPaymentWebhook (payment webhook).

These tests exercise the module directly against whatever pydantic state is
actually installed in this environment PLUS a forced-unavailable branch (via
monkeypatching request_models._AVAILABLE), so both code paths run regardless
of whether pydantic happens to be installed where the suite executes.
"""
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import request_models as rm  # noqa: E402


class TestAvailability(unittest.TestCase):
    def test_available_matches_real_import(self):
        try:
            import pydantic  # noqa: F401
            self.assertTrue(rm.available())
        except ImportError:
            self.assertFalse(rm.available())


class TestValidateWhenUnavailable(unittest.TestCase):
    """Force the "pydantic not installed" branch regardless of the real
    environment -- this must ALWAYS short-circuit to (True, None), meaning
    every call site's existing hand-rolled validation runs unchanged."""

    def setUp(self):
        self._orig = rm._AVAILABLE
        rm._AVAILABLE = False

    def tearDown(self):
        rm._AVAILABLE = self._orig

    def test_garbage_body_still_passes_through(self):
        ok, err = rm.validate(rm.UserCreateRequest, {'anything': 'goes', 'role': 123})
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_empty_body_passes_through(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {})
        self.assertTrue(ok)
        self.assertIsNone(err)


@unittest.skipUnless(rm.available(), "pydantic not installed in this environment")
class TestUserCreateRequestModel(unittest.TestCase):
    def test_valid_body_passes(self):
        ok, err = rm.validate(rm.UserCreateRequest,
                              {'username': 'alice', 'password': 'x', 'role': 'admin'})
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_defaults_apply_to_missing_fields(self):
        ok, err = rm.validate(rm.UserCreateRequest, {})
        self.assertTrue(ok, err)

    def test_non_string_role_coerced_not_rejected(self):
        # v6.1.1 (#5 follow-up, adversarial self-review): the OLD hand-rolled
        # code never type-checks `role` at all (a bare `==`/`in` comparison),
        # so a non-string role isn't a validation error there either -- it
        # just fails the real role-membership check downstream with its own
        # message. A strict pydantic `str` type here would have been STRICTER
        # than the code it's meant to only add a safety net on top of.
        ok, err = rm.validate(rm.UserCreateRequest,
                              {'username': 'alice', 'password': 'x', 'role': 123})
        self.assertTrue(ok, err)

    def test_list_username_coerced_not_rejected(self):
        # Matches _sanitize_str's str(v) coercion exactly (sanitize.py) --
        # the result ("['not', 'a', 'string']") then fails the real username
        # regex check in the handler itself, same as the old code's behavior.
        ok, err = rm.validate(rm.UserCreateRequest, {'username': ['not', 'a', 'string']})
        self.assertTrue(ok, err)

    def test_extra_field_tolerated_not_rejected(self):
        # extra='ignore', not 'forbid' -- see the module docstring for why
        # (rejecting previously-tolerated extra fields would be a breaking
        # change for existing API clients).
        ok, err = rm.validate(rm.UserCreateRequest,
                              {'username': 'alice', 'password': 'x',
                               'role': 'admin', 'some_future_field': 'whatever'})
        self.assertTrue(ok, err)

    def test_non_dict_body_rejected(self):
        ok, err = rm.validate(rm.UserCreateRequest, ['not', 'a', 'dict'])
        self.assertFalse(ok)
        self.assertIn('object', err)


@unittest.skipUnless(rm.available(), "pydantic not installed in this environment")
class TestApiKeyCreateRequestModel(unittest.TestCase):
    def test_valid_body_passes(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest,
                              {'name': 'k1', 'role': 'admin', 'rate_limit': 100})
        self.assertTrue(ok, err)

    def test_non_numeric_rate_limit_rejected(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': 'lots'})
        self.assertFalse(ok)
        self.assertIn('rate_limit', err)

    def test_numeric_string_rate_limit_coerces(self):
        # Matches the existing int(body.get('rate_limit') or 0) coercion
        # behavior -- a numeric-looking string is not a type error.
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': '50'})
        self.assertTrue(ok, err)

    def test_expires_at_accepts_none(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'expires_at': None})
        self.assertTrue(ok, err)

    def test_expires_at_rejects_non_numeric_string(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'expires_at': 'someday'})
        self.assertFalse(ok)

    # ── v6.1.1 (#5 follow-up, adversarial self-review) ──────────────────────
    # Regression guardrails: the FIRST version of this pilot had plain
    # `int`/`str` type annotations with no coercion, which silently rejected
    # several inputs the OLD hand-rolled validation had always accepted --
    # exactly the "unchanged when pydantic is present" contract this module's
    # own docstring promises. Each case below is a real request shape a
    # third-party API client relying on the documented tolerant contract
    # could plausibly send.
    def test_null_rate_limit_accepted_as_zero(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': None})
        self.assertTrue(ok, err)

    def test_empty_string_rate_limit_accepted_as_zero(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': ''})
        self.assertTrue(ok, err)

    def test_fractional_float_rate_limit_truncates_not_rejects(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': 5.9})
        self.assertTrue(ok, err)

    def test_fractional_float_expires_at_truncates_not_rejects(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest,
                              {'name': 'k1', 'expires_at': 1735689600.9})
        self.assertTrue(ok, err)

    def test_numeric_name_coerced_not_rejected(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 12345})
        self.assertTrue(ok, err)

    def test_non_string_role_coerced_not_rejected(self):
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'role': 42})
        self.assertTrue(ok, err)

    def test_garbage_rate_limit_still_rejected(self):
        # Sanity check the coercion isn't SO loose it swallows real garbage.
        ok, err = rm.validate(rm.ApiKeyCreateRequest, {'name': 'k1', 'rate_limit': [1, 2]})
        self.assertFalse(ok)


@unittest.skipUnless(rm.available(), "pydantic not installed in this environment")
class TestBillingPaymentWebhookRequestModel(unittest.TestCase):
    def test_valid_body_passes(self):
        ok, err = rm.validate(rm.BillingPaymentWebhookRequest,
                              {'invoice_id': 'inv1', 'amount': 100.0})
        self.assertTrue(ok, err)

    def test_missing_amount_rejected(self):
        # amount has no default -- required, matching the existing
        # float(body.get('amount')) call which already raises on None.
        ok, err = rm.validate(rm.BillingPaymentWebhookRequest, {'invoice_id': 'inv1'})
        self.assertFalse(ok)
        self.assertIn('amount', err)

    def test_non_numeric_amount_rejected(self):
        ok, err = rm.validate(rm.BillingPaymentWebhookRequest,
                              {'invoice_id': 'inv1', 'amount': 'lots of money'})
        self.assertFalse(ok)

    def test_numeric_string_amount_coerces(self):
        ok, err = rm.validate(rm.BillingPaymentWebhookRequest,
                              {'invoice_id': 'inv1', 'amount': '99.50'})
        self.assertTrue(ok, err)


if __name__ == "__main__":
    unittest.main()
