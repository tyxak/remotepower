"""v6.1.3 — JIT credential checkout (gap item #14, reframed).

Full PAM is out of scope. But "who CAN reveal this credential" → "who has ACTIVE,
justified, EXPIRING access to it right now" is the useful half, and it is a small
step from the vault we already have.

The load-bearing constraint: **the server never holds the vault key.** The
passphrase is entered in the browser, the derived key is returned to it and
replayed as an `X-RP-Vault-Key` header on every operation (cmdb_vault.py:10-12).
So a "checkout" cannot lease key MATERIAL server-side without inverting that
design. This is an AUTHORIZATION grant that gates the reveal HANDLER, while the
browser still supplies the key.

Distinct from break-glass, which is unchanged:
  break-glass = TWO-PERSON, one-shot, 15 min, for creds flagged `break_glass`
  checkout    = SELF-service, N-hour window, reusable within it, opt-in
A checkout never substitutes for break-glass — a flagged credential needs both.

TESTING NOTE (the false-green classes in CLAUDE.md): every test below DRIVES the
real handler against a real vault and a real encrypted credential. An earlier
draft of this file asserted on the *source text* of the reveal handler — which
would have passed just as happily had the gate been a no-op. Where a gate is
under test, only `verify_token` (identity) is stubbed; `require_admin_auth` runs
for real, so a handler with no gate at all fails here rather than passing.
`_cmdb_get_request_key` IS stubbed — that is the transport-level header parse
(the browser supplies the key on every call), not the authorization gate.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-co-"))

_PASSPHRASE = "correct horse battery staple"
_PLAINTEXT = "s3cr3t-ipmi-password"
_DEV = "d1"
_CRED = "cred_a1b2c3"
_CRED2 = "cred_d4e5f6"


def _fresh_api():
    d = tempfile.mkdtemp(prefix="rp-v613-co-")
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_v613_co", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Case(unittest.TestCase):
    """A real vault, a real encrypted credential, a real device."""

    def setUp(self):
        self.api = api = _fresh_api()
        self.audits = []
        self.captured = {}
        self.body = {}
        self.role = "admin"
        self.actor = "alice"

        def _respond(status, data=None):
            self.captured["status"] = status
            self.captured["data"] = data
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.audit_log = lambda actor, action, **kw: self.audits.append((actor, action, kw))
        api.fire_webhook = lambda ev, pl=None: None
        api._get_client_ip = lambda: "10.0.0.1"
        api.get_json_obj = lambda: self.body
        api.method = lambda: "POST"
        # Identity only — the real require_admin_auth/_or_auditor gates still run.
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda tok: (self.actor, self.role)

        # A real vault + a real AES-GCM credential.
        meta = api.cmdb_vault.setup_vault(_PASSPHRASE)
        api.save(api.CMDB_VAULT_FILE, meta)
        self.key = api.cmdb_vault.derive_key_from_meta(_PASSPHRASE, meta)
        api._cmdb_get_request_key = lambda: self.key   # the browser's header
        blob = api.cmdb_vault.encrypt(self.key, _PLAINTEXT)
        blob2 = api.cmdb_vault.encrypt(self.key, "other-secret")
        api.save(api.CMDB_FILE, {_DEV: {"credentials": [
            dict(blob, id=_CRED, label="IPMI"),
            dict(blob2, id=_CRED2, label="Switch"),
        ]}})
        api.save(api.DEVICES_FILE, {_DEV: {"hostname": "host1"}})
        api.save(api.CONFIG_FILE, {"vault_checkout_required": True})
        api._LOAD_CACHE.clear()

    # — drivers —————————————————————————————————————————————————————————
    def reveal(self, cred=_CRED, body=None):
        self.body = body if body is not None else {}
        self.captured = {}
        try:
            self.api.handle_cmdb_credentials_reveal(_DEV, cred)
        except self.api.HTTPError:
            pass
        return self.captured

    def checkout(self, body):
        self.body = body
        self.captured = {}
        try:
            self.api.handle_vault_checkout()
        except self.api.HTTPError:
            pass
        return self.captured

    def listing(self):
        self.captured = {}
        self.api.method = lambda: "GET"
        try:
            self.api.handle_vault_checkouts_list()
        except self.api.HTTPError:
            pass
        self.api.method = lambda: "POST"
        return self.captured

    def revoke(self, cid):
        self.captured = {}
        try:
            self.api.handle_vault_checkout_revoke(cid)
        except self.api.HTTPError:
            pass
        return self.captured

    def _grant(self, **kw):
        r = self.checkout(dict({"device_id": _DEV, "cred_id": _CRED,
                                "reason": "incident 42"}, **kw))
        return (r.get("data") or {}).get("id")


class TestRevealIsGatedForReal(_Case):
    """The whole feature is worthless if the reveal handler doesn't enforce it."""

    def test_reveal_without_a_checkout_is_refused(self):
        r = self.reveal()
        self.assertEqual(403, r["status"])
        self.assertTrue(r["data"].get("checkout_required"))

    def test_a_refused_reveal_leaks_no_plaintext(self):
        """The point of the gate. Asserted on the actual response body."""
        r = self.reveal()
        self.assertNotIn(_PLAINTEXT, repr(r["data"]))

    def test_reveal_after_a_real_checkout_returns_the_plaintext(self):
        """End-to-end: check out, then reveal, and get the real decrypted secret
        back — proving the gate opens as well as closes."""
        self._grant()
        r = self.reveal()
        self.assertEqual(200, r["status"])
        self.assertEqual(_PLAINTEXT, r["data"].get("password"))

    def test_a_checkout_is_scoped_to_one_credential(self):
        """A window on one credential must not open every other one."""
        self._grant(cred_id=_CRED)
        self.assertEqual(200, self.reveal(_CRED)["status"])
        self.assertEqual(403, self.reveal(_CRED2)["status"])

    def test_a_checkout_is_scoped_to_one_person(self):
        """Alice checking a credential out must not grant Bob access to it."""
        self._grant()
        self.assertEqual(200, self.reveal()["status"])
        self.actor = "bob"
        r = self.reveal()
        self.assertEqual(403, r["status"])
        self.assertTrue(r["data"].get("checkout_required"))

    def test_an_expired_checkout_is_dead_immediately(self):
        """Expiry is evaluated at READ time, not by a pruning sweep — a lapsed
        grant is dead the moment it lapses. A sweep that had not yet run would
        otherwise silently extend everyone's access."""
        cid = self._grant()
        store = self.api.load(self.api.VAULT_CHECKOUTS_FILE)
        store[cid]["expires_at"] = int(time.time()) - 1
        self.api.save(self.api.VAULT_CHECKOUTS_FILE, store)
        self.api._LOAD_CACHE.clear()
        # The record is still physically present...
        self.assertIn(cid, self.api._checkouts_load())
        # ...and the reveal is still refused.
        self.assertEqual(403, self.reveal()["status"])

    def test_gate_is_off_by_default(self):
        """Turning this on by default would lock every admin out of every
        credential on upgrade until they checked one out."""
        self.api.save(self.api.CONFIG_FILE, {})
        self.api._LOAD_CACHE.clear()
        self.assertFalse(self.api._checkout_required())
        self.assertEqual(200, self.reveal()["status"])

    def test_a_refused_reveal_is_audited(self):
        """A refused reveal is exactly as interesting as a successful one."""
        self.reveal()
        self.assertTrue(any(a == "cmdb_credential_reveal_denied"
                            for _, a, _ in self.audits))


class TestCheckoutIsAFloorNotACeiling(_Case):
    """A checkout must never substitute for the break-glass two-person rule."""

    def setUp(self):
        super().setUp()
        store = self.api.load(self.api.CMDB_FILE)
        store[_DEV]["credentials"][0]["break_glass"] = True
        self.api.save(self.api.CMDB_FILE, store)
        self.api._LOAD_CACHE.clear()

    def test_break_glass_still_applies_to_a_checked_out_credential(self):
        """With an ACTIVE checkout in hand, a break-glass credential must STILL
        demand its second admin — the checkout gate sits after break-glass, never
        instead of it. If this regresses, a checkout silently becomes a way to
        bypass the two-person rule."""
        self._grant()
        r = self.reveal()
        self.assertNotEqual(200, r["status"])
        self.assertTrue(r["data"].get("break_glass"))
        self.assertNotIn(_PLAINTEXT, repr(r["data"]))


class TestCheckoutHandler(_Case):
    def test_a_non_admin_cannot_check_out(self):
        """Only verify_token is stubbed — require_admin_auth runs for real, so a
        handler with no gate at all fails this test rather than passing it."""
        self.role = "viewer"
        r = self.checkout({"device_id": _DEV, "cred_id": _CRED, "reason": "x"})
        self.assertEqual(403, r["status"])

    def test_a_reason_is_required(self):
        """An unreasoned checkout is just a slower reveal — the reason IS the
        audit value."""
        r = self.checkout({"device_id": _DEV, "cred_id": _CRED, "reason": "  "})
        self.assertEqual(400, r["status"])

    def test_an_unknown_device_404s_rather_than_403s(self):
        """Never confirm that an id you cannot see exists."""
        r = self.checkout({"device_id": "nope", "cred_id": _CRED, "reason": "x"})
        self.assertEqual(404, r["status"])

    def test_the_window_is_bounded(self):
        """A 10-year checkout is standing access wearing a costume."""
        r = self.checkout({"device_id": _DEV, "cred_id": _CRED, "reason": "x",
                           "hours": 99999})
        self.assertLessEqual(r["data"]["expires_in"],
                             self.api._CHECKOUT_MAX_HOURS * 3600 + 5)

    def test_a_garbage_hours_value_falls_back_rather_than_500ing(self):
        """The pydantic model must not narrow what the handler already tolerated."""
        r = self.checkout({"device_id": _DEV, "cred_id": _CRED, "reason": "x",
                           "hours": "not-a-number"})
        self.assertEqual(200, r["status"])
        self.assertGreater(r["data"]["expires_in"], 0)

    def test_the_grant_records_who_and_why(self):
        cid = self._grant(reason="incident 42")
        rec = self.api._checkouts_load()[cid]
        self.assertEqual("alice", rec["actor"])
        self.assertEqual("incident 42", rec["reason"])
        self.assertTrue(any(a == "cmdb_vault_checkout" for _, a, _ in self.audits))


class TestVisibility(_Case):
    def test_live_grants_are_listed(self):
        """Standing access becoming *visible*, dated, expiring access is the
        entire point of the feature."""
        self._grant()
        rows = self.listing()["data"]["checkouts"]
        self.assertEqual(1, len(rows))
        self.assertEqual("alice", rows[0]["actor"])
        self.assertEqual("incident 42", rows[0]["reason"])

    def test_expired_grants_are_not_listed(self):
        cid = self._grant()
        store = self.api.load(self.api.VAULT_CHECKOUTS_FILE)
        store[cid]["expires_at"] = int(time.time()) - 1
        self.api.save(self.api.VAULT_CHECKOUTS_FILE, store)
        self.api._LOAD_CACHE.clear()
        self.assertEqual([], self.listing()["data"]["checkouts"])

    def test_the_auditor_role_can_see_who_holds_access(self):
        """The oversight role must be able to read this — that is the point —
        while still revealing nothing."""
        self._grant()
        self.role = "auditor"
        self.actor = "auditor1"
        r = self.listing()
        self.assertEqual(200, r["status"])
        self.assertEqual(1, len(r["data"]["checkouts"]))
        self.assertNotIn(_PLAINTEXT, repr(r["data"]))

    def test_a_viewer_cannot_see_who_holds_access(self):
        self.role = "viewer"
        self.assertEqual(403, self.listing()["status"])


class TestRevocation(_Case):
    def test_revoke_ends_the_window_early(self):
        self._grant()
        self.assertEqual(200, self.reveal()["status"])
        cid = self.listing()["data"]["checkouts"][0]["id"]
        self.assertEqual(200, self.revoke(cid)["status"])
        self.assertEqual(403, self.reveal()["status"])

    def test_revoking_an_unknown_grant_404s(self):
        self.assertEqual(404, self.revoke("co_nope")["status"])

    def test_a_revocation_is_audited(self):
        cid = self._grant()
        self.revoke(cid)
        self.assertTrue(any(a == "cmdb_vault_checkout_revoked"
                            for _, a, _ in self.audits))


if __name__ == "__main__":
    unittest.main()
