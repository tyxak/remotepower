"""v6.1.3 — Quotes (gap item #16).

A quote is the mirror image of an invoice: an invoice looks BACKWARD (derived from
logged time), a quote looks FORWARD (hand-authored) and, when accepted, becomes an
invoice.

The tests that matter are the ones that protect the CUSTOMER, because a billing
module's worst bugs all have the same victim:

  * A quote converts EXACTLY ONCE. A double-click must not bill someone twice.
  * Only an ACCEPTED quote converts. Invoicing a draft or declined quote bills
    someone for work they never agreed to.
  * The invoice SNAPSHOTS the quote's numbers. A VAT change between acceptance and
    invoicing must not silently re-price an agreed deal.
  * An expired quote cannot be accepted, and expiry is evaluated at READ time — a
    sweep that hadn't run must not let someone accept last Tuesday's price.
  * An accepted quote does NOT expire out from under the customer. The deal is done.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import billing as billing_mod       # noqa: E402


class TestQuoteStatusLogic(unittest.TestCase):
    """Pure logic — no server needed."""

    def setUp(self):
        self.now = int(time.time())

    def test_a_lapsed_quote_is_expired_at_read_time(self):
        """Not 'expired once a sweep rewrites it' — expired the moment it lapses.
        A sweep that had not yet run would otherwise let a customer accept a price
        that expired last Tuesday."""
        q = {"status": "sent", "valid_until": self.now - 1}
        self.assertEqual("expired", billing_mod.quote_effective_status(q, self.now))

    def test_a_live_quote_keeps_its_status(self):
        q = {"status": "sent", "valid_until": self.now + 3600}
        self.assertEqual("sent", billing_mod.quote_effective_status(q, self.now))

    def test_a_quote_with_no_expiry_never_expires(self):
        q = {"status": "sent", "valid_until": 0}
        self.assertEqual("sent", billing_mod.quote_effective_status(q, self.now))

    def test_an_accepted_quote_does_not_expire(self):
        """TERMINAL. A customer who accepted in time must not have the deal lapse
        out from under them because an admin was slow to invoice it."""
        q = {"status": "accepted", "valid_until": self.now - 99999}
        self.assertEqual("accepted", billing_mod.quote_effective_status(q, self.now))

    def test_only_an_accepted_quote_can_convert(self):
        for status in ("draft", "sent", "declined"):
            ok, why = billing_mod.quote_can_convert({"status": status}, self.now)
            self.assertFalse(ok, status)
            self.assertIn("accepted", why)

    def test_an_already_invoiced_quote_cannot_convert_again(self):
        ok, why = billing_mod.quote_can_convert(
            {"status": "accepted", "invoice_id": "inv_1"}, self.now)
        self.assertFalse(ok)
        self.assertIn("already", why)

    def test_an_accepted_quote_converts(self):
        ok, _ = billing_mod.quote_can_convert({"status": "accepted"}, self.now)
        self.assertTrue(ok)

    def test_the_money_maths_is_shared_with_invoices(self):
        """Two subtly different VAT calculations in one product is a bug waiting to
        be found by a customer. Quotes reuse invoice_totals."""
        items = [{"amount": 100.0}, {"amount": 50.0}]
        self.assertEqual((150.0, 30.0, 180.0),
                         billing_mod.invoice_totals(items, 20.0))


class TestQuoteHandlers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v613-q-")
        spec = importlib.util.spec_from_file_location("api_v613_q", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        self.captured = {}
        self.body = {}
        self.role = "admin"
        self.audits = []
        self._method = "POST"

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.audit_log = lambda a, act, *rest, **kw: self.audits.append(act)
        api.get_json_obj = lambda: self.body
        api.method = lambda: self._method
        api._env = lambda k, d='': ''
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda t: ("alice", self.role)
        api.save(api.QUOTES_FILE, {})
        api.save(api.INVOICES_FILE, {})
        api.save(api.SITES_FILE, {"s1": {"name": "Acme Ltd"}})
        api.save(api.BILLING_FILE, {"currency": "GBP", "default_vat": 20.0})
        api._LOAD_CACHE.clear()

    # — drivers —
    def _call(self, fn, *args, method="POST", **body):
        self._method = method
        self.body = body
        self.captured = {}
        try:
            fn(*args)
        except self.api.HTTPError:
            pass
        return self.captured

    def create(self, **kw):
        body = dict({"site_id": "s1",
                     "line_items": [{"label": "Install", "qty": 2, "unit": 100.0}]},
                    **kw)
        return self._call(self.api.handle_quotes, **body)

    def set_status(self, qid, status):
        return self._call(self.api.handle_quote_update, qid, status=status)

    def convert(self, qid):
        return self._call(self.api.handle_quote_convert, qid)

    def get(self, qid):
        return self._call(self.api.handle_quote_get, qid, method="GET")

    def invoices(self):
        return (self.api.load(self.api.INVOICES_FILE) or {}).get("invoices") or []

    def _accepted_quote(self):
        qid = self.create()["data"]["id"]
        self.set_status(qid, "accepted")
        return qid

    # — creation —
    def test_a_quote_is_created_with_totals(self):
        r = self.create()
        self.assertEqual(200, r["status"])
        self.assertEqual(240.0, r["data"]["total"])    # 2 x 100 + 20% VAT
        self.assertTrue(r["data"]["number"].startswith("Q-"))

    def test_a_quote_needs_a_line_item(self):
        self.assertEqual(400, self.create(line_items=[])["status"])

    def test_a_quote_needs_a_real_site(self):
        self.assertEqual(400, self.create(site_id="nope")["status"])

    def test_a_non_admin_cannot_create_a_quote(self):
        """Only verify_token is stubbed — the real require_admin_auth runs."""
        self.role = "viewer"
        self.assertEqual(403, self.create()["status"])

    # — lifecycle —
    def test_status_moves_through_the_lifecycle(self):
        qid = self.create()["data"]["id"]
        for s in ("sent", "accepted"):
            self.assertEqual(200, self.set_status(qid, s)["status"])
        self.assertEqual("accepted", self.get(qid)["data"]["quote"]["status"])

    def test_expired_cannot_be_set_by_hand(self):
        """`expired` is DERIVED, never set — otherwise a caller could hand-wave a
        quote into a state the conversion rules depend on."""
        qid = self.create()["data"]["id"]
        self.assertEqual(400, self.set_status(qid, "expired")["status"])
        self.assertEqual(400, self.set_status(qid, "invoiced")["status"])

    def test_an_expired_quote_cannot_be_accepted(self):
        """Accepting a lapsed quote honours a price that expired last Tuesday."""
        qid = self.create(valid_until=int(time.time()) - 1)["data"]["id"]
        r = self.set_status(qid, "accepted")
        self.assertEqual(400, r["status"])
        self.assertIn("expired", r["data"]["error"])

    def test_a_lapsed_quote_reads_as_expired_with_no_sweep(self):
        qid = self.create(valid_until=int(time.time()) - 1)["data"]["id"]
        self.assertEqual("expired", self.get(qid)["data"]["quote"]["status"])

    # — conversion: the money-critical part —
    def test_an_accepted_quote_becomes_an_invoice(self):
        qid = self._accepted_quote()
        r = self.convert(qid)
        self.assertEqual(200, r["status"])
        invs = self.invoices()
        self.assertEqual(1, len(invs))
        self.assertEqual(240.0, invs[0]["total"])
        self.assertEqual(qid, invs[0]["quote_id"])     # provenance

    def test_A_QUOTE_CONVERTS_EXACTLY_ONCE(self):
        """The worst bug a billing module can have is billing a customer twice.
        The claim is stamped under the SAME lock that checks it, so a second
        request loses the race."""
        qid = self._accepted_quote()
        self.assertEqual(200, self.convert(qid)["status"])
        second = self.convert(qid)
        self.assertEqual(400, second["status"])
        self.assertIn("already", second["data"]["error"])
        self.assertEqual(1, len(self.invoices()))      # still exactly one

    def test_a_draft_quote_cannot_be_invoiced(self):
        """Billing someone for work they never agreed to."""
        qid = self.create()["data"]["id"]
        r = self.convert(qid)
        self.assertEqual(400, r["status"])
        self.assertEqual([], self.invoices())

    def test_a_declined_quote_cannot_be_invoiced(self):
        qid = self.create()["data"]["id"]
        self.set_status(qid, "declined")
        self.assertEqual(400, self.convert(qid)["status"])
        self.assertEqual([], self.invoices())

    def test_the_invoice_snapshots_the_agreed_numbers(self):
        """A VAT change between acceptance and invoicing must NOT silently re-price
        an agreed deal. The customer accepted 20% VAT; they get 20% VAT."""
        qid = self._accepted_quote()
        # The rate card changes after acceptance…
        self.api.save(self.api.BILLING_FILE, {"currency": "GBP", "default_vat": 99.0})
        self.api._LOAD_CACHE.clear()
        self.convert(qid)
        inv = self.invoices()[0]
        self.assertEqual(20.0, inv["vat_rate"])        # …the invoice honours the deal
        self.assertEqual(240.0, inv["total"])

    def test_an_invoiced_quote_is_frozen(self):
        """Re-opening it would let someone 'decline' work already billed."""
        qid = self._accepted_quote()
        self.convert(qid)
        self.assertEqual(400, self.set_status(qid, "declined")["status"])

    def test_a_non_admin_cannot_convert(self):
        qid = self._accepted_quote()
        self.role = "viewer"
        self.assertEqual(403, self.convert(qid)["status"])
        self.assertEqual([], self.invoices())

    def test_convert_404s_an_unknown_quote(self):
        self.assertEqual(404, self.convert("qte_nope")["status"])

    def test_conversion_is_audited(self):
        self.convert(self._accepted_quote())
        self.assertIn("quote_convert", self.audits)


class TestModuleGate(unittest.TestCase):
    def test_quotes_ride_the_billing_kill_switch(self):
        """A new route under a gated module that isn't in its prefix tuple silently
        escapes the kill switch — billing off would still serve quotes."""
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-qg-"))
        spec = importlib.util.spec_from_file_location("api_v613_qg", _CGI / "api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        _key, _default, prefixes = api._MODULES["billing"]
        self.assertIn("/api/quotes", prefixes)


if __name__ == "__main__":
    unittest.main()
