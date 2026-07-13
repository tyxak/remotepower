"""v6.1.3 — PII / regulated-data scan (gap item #13).

"Where is our regulated data?" — the GDPR/PCI question no amount of monitoring
answers. Agent-side bounded walk (the secrets-scan pattern), server-side inventory.

THE PROPERTY THIS WHOLE FILE EXISTS TO DEFEND:

    The matched value NEVER leaves the host. Not raw, not redacted, NOT HASHED.

A PII scanner that ships PII into its own database is not a control; it is a
second breach with a nicer UI. And hashing does not save you: unlike an API key,
the things this looks for are LOW-ENTROPY — there are only 10^9 possible US SSNs,
and a card number is pinned by BIN + Luhn. A rainbow table over either is minutes
of work, so a "fingerprint" would be a reversible copy of the PII in disguise.
(This is exactly why `secret_findings` MAY fingerprint and this may not: an API
key is high-entropy, so its hash reveals nothing.)

So: the agent tests assert no value in the payload, and the server tests assert
that even a MALICIOUS agent posting a value cannot get one into the store — the
server rebuilds each entry from four known-safe fields rather than filtering out
bad ones.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

# Real values planted in the fixtures — every one must be absent from every
# payload and every store, always.
_EMAIL = "alice@example.com"
_CARD = "4111111111111111"        # a valid Luhn test card
_SSN = "123-45-6789"
_IBAN = "GB82WEST12345698765432"


def _agent():
    spec = importlib.util.spec_from_file_location(
        "rp_agent_pii", _ROOT / "client" / "remotepower-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestLuhn(unittest.TestCase):
    """Without Luhn, EVERY 16-digit number — an order id, a timestamp, a serial —
    reads as a credit card, and the operator learns to ignore the whole report."""

    def setUp(self):
        self.ag = _agent()

    def test_a_real_card_number_passes(self):
        for good in ("4111111111111111", "5500005555555559", "378282246310005"):
            self.assertTrue(self.ag._luhn_ok(good), good)

    def test_a_number_that_merely_looks_like_one_fails(self):
        for bad in ("4111111111111112", "1234567890123456", "1699999999999999"):
            self.assertFalse(self.ag._luhn_ok(bad), bad)

    def test_too_short_fails(self):
        self.assertFalse(self.ag._luhn_ok("42"))

    def test_non_digits_fail(self):
        self.assertFalse(self.ag._luhn_ok("4111-1111-1111-1111"))


class TestAgentScan(unittest.TestCase):
    def setUp(self):
        self.ag = _agent()
        self.dir = tempfile.mkdtemp(prefix="rp-pii-")
        Path(self.dir, "customers.csv").write_text(
            f"name,email,card,ssn,iban\n"
            f"Alice,{_EMAIL},{_CARD},{_SSN},{_IBAN}\n")
        # Long numbers that are NOT cards, plus a config-ish file.
        Path(self.dir, "orders.txt").write_text(
            "order 4111111111111112 (bad luhn)\nts 1699999999999999\n")

    def scan(self):
        return self.ag.collect_pii_findings(paths=[self.dir])

    def test_it_finds_each_kind(self):
        kinds = {f["kind"] for f in self.scan()}
        self.assertEqual({"email", "credit_card", "ssn", "iban"}, kinds)

    def test_THE_VALUE_NEVER_LEAVES_THE_HOST(self):
        """The single most important assertion in this file."""
        blob = json.dumps(self.scan())
        for value in (_EMAIL, _CARD, _SSN, _IBAN):
            self.assertNotIn(value, blob)

    def test_no_preview_and_no_fingerprint_field_at_all(self):
        """Not 'we redact the preview' — there IS no preview, and no hash. A hash
        of a low-entropy identifier is a reversible copy of it."""
        for f in self.scan():
            self.assertEqual({"path", "kind", "count", "lines"}, set(f))

    def test_a_long_number_is_not_reported_as_a_card(self):
        """orders.txt holds a bad-Luhn 16-digit number and a 16-digit timestamp.
        Neither is a card, and reporting them would poison the whole report."""
        paths = {f["path"] for f in self.scan() if f["kind"] == "credit_card"}
        self.assertFalse(any(p.endswith("orders.txt") for p in paths))

    def test_it_reports_which_file_and_which_lines(self):
        """Everything an operator needs to go and look — and nothing an attacker
        who pops the RemotePower server can use."""
        card = next(f for f in self.scan() if f["kind"] == "credit_card")
        self.assertTrue(card["path"].endswith("customers.csv"))
        self.assertEqual(1, card["count"])
        self.assertEqual([2], card["lines"])

    def test_it_is_bounded(self):
        """A pathological tree must not wedge the heartbeat."""
        for i in range(50):
            Path(self.dir, f"f{i}.txt").write_text(f"user{i}@example.com\n")
        self.assertLessEqual(len(self.ag.collect_pii_findings(
            paths=[self.dir], max_findings=5)), 5)

    def test_a_missing_path_is_not_an_error(self):
        self.assertEqual([], self.ag.collect_pii_findings(paths=["/nonexistent-xyz"]))


class TestServerIngest(unittest.TestCase):
    """The server does not TRUST the agent's promise — it re-enforces it."""

    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v613-pii-")
        spec = importlib.util.spec_from_file_location("api_v613_pii", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        self.api.save(self.api.PII_FILE, {})
        self.api._LOAD_CACHE.clear()

    def stored(self, dev="d1"):
        return (self.api.load(self.api.PII_FILE) or {}).get(dev, {}).get("findings", [])

    def test_a_normal_finding_is_stored(self):
        self.api._ingest_pii_findings("d1", [
            {"path": "/srv/data/x.csv", "kind": "ssn", "count": 3, "lines": [2, 5]},
        ])
        self.assertEqual(
            [{"path": "/srv/data/x.csv", "kind": "ssn", "count": 3, "lines": [2, 5]}],
            self.stored())

    def test_A_MALICIOUS_AGENT_CANNOT_SMUGGLE_A_VALUE_INTO_THE_STORE(self):
        """The server rebuilds each entry from four known-safe fields — a
        whitelist, not a blacklist — so ANY extra key a tampered or future agent
        sends is structurally incapable of being persisted. If this ever regresses,
        RemotePower's own database becomes the PII breach."""
        self.api._ingest_pii_findings("d1", [{
            "path": "/srv/data/x.csv", "kind": "ssn", "count": 1, "lines": [2],
            "preview": _SSN,             # a "helpful" redacted preview
            "value": _CARD,              # the raw thing
            "fingerprint": "deadbeef",   # a reversible hash of a low-entropy id
            "raw": _EMAIL,
        }])
        blob = json.dumps(self.api.load(self.api.PII_FILE))
        for value in (_SSN, _CARD, _EMAIL, "deadbeef"):
            self.assertNotIn(value, blob)
        self.assertEqual({"path", "kind", "count", "lines"}, set(self.stored()[0]))

    def test_an_unknown_kind_is_dropped_not_guessed(self):
        self.api._ingest_pii_findings("d1", [
            {"path": "/x", "kind": "passport_scan", "count": 1},
            {"path": "/y", "kind": "email", "count": 1},
        ])
        self.assertEqual(["email"], [f["kind"] for f in self.stored()])

    def test_a_zero_count_finding_is_dropped(self):
        self.api._ingest_pii_findings("d1", [{"path": "/x", "kind": "email", "count": 0}])
        self.assertEqual([], self.stored())

    def test_garbage_does_not_raise(self):
        for junk in (None, "nope", 42, [1, 2], [{"no": "path"}], [{"path": "/x"}]):
            self.api._ingest_pii_findings("d1", junk)   # must not raise

    def test_the_per_host_cap_holds(self):
        self.api._ingest_pii_findings("d1", [
            {"path": f"/f{i}", "kind": "email", "count": 1} for i in range(1000)])
        self.assertLessEqual(len(self.stored()), self.api._PII_MAX_PER_HOST)


class TestPiiHandlers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v613-piih-")
        spec = importlib.util.spec_from_file_location("api_v613_piih", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        self.captured = {}
        self.body = {}
        self.role = "admin"
        self.audits = []

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.audit_log = lambda a, act, **kw: self.audits.append(act)
        api.get_json_obj = lambda: self.body
        api.method = lambda: "POST"
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda t: ("alice", self.role)
        api.save(api.CONFIG_FILE, {"pii_scan_enabled": True})
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01"}, "d2": {"name": "db01"}})
        api.save(api.PII_FILE, {"d1": {"ts": 1, "findings": [
            {"path": "/srv/a.csv", "kind": "ssn", "count": 5, "lines": [1]},
            {"path": "/srv/a.csv", "kind": "email", "count": 2, "lines": [1]},
        ]}})
        api._LOAD_CACHE.clear()

    def _list(self):
        self.captured = {}
        self.api.method = lambda: "GET"
        try:
            self.api.handle_pii_list()
        except self.api.HTTPError:
            pass
        self.api.method = lambda: "POST"
        return self.captured.get("data") or {}

    def _scan(self, **body):
        self.body = body
        self.captured = {}
        try:
            self.api.handle_pii_scan_now()
        except self.api.HTTPError:
            pass
        return self.captured

    def test_the_inventory_rolls_up_by_kind(self):
        d = self._list()
        self.assertEqual(1, d["scanned_hosts"])
        self.assertEqual({"ssn": 5, "email": 2}, d["hosts"][0]["by_kind"])
        self.assertEqual(1, d["hosts"][0]["files"])   # both kinds, one file
        self.assertEqual(5, d["totals"]["ssn"])

    def test_scope_filtering_goes_through_scope_filter_devices(self):
        """A fleet aggregate gated only on `_caller_scope()` leaks the estate to a
        tenant admin (whose role scope is None) — the v6.1.1 class, found 6×."""
        called = {}
        real = self.api._scope_filter_devices
        self.api._scope_filter_devices = lambda devs, scope=None: (
            called.setdefault("yes", True), {})[1]
        try:
            d = self._list()
        finally:
            self.api._scope_filter_devices = real
        self.assertTrue(called.get("yes"))
        self.assertEqual([], d["hosts"])     # other tenant's host is invisible

    def test_scan_now_queues_the_one_shot_flag(self):
        """Without a server set-site the only trigger would be the 24h cadence —
        the 'feature that can never fire on demand' shape."""
        r = self._scan()
        self.assertEqual(200, r["status"])
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertTrue(devs["d1"]["force_pii_scan"])
        self.assertTrue(devs["d2"]["force_pii_scan"])
        self.assertIn("pii_scan_queued", self.audits)

    def test_scan_now_can_target_one_host(self):
        self._scan(device_id="d1")
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertTrue(devs["d1"].get("force_pii_scan"))
        self.assertFalse(devs["d2"].get("force_pii_scan"))

    def test_scan_now_refuses_when_the_feature_is_off(self):
        self.api.save(self.api.CONFIG_FILE, {})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(400, self._scan()["status"])

    def test_scan_now_404s_an_unknown_device(self):
        self.assertEqual(404, self._scan(device_id="nope")["status"])

    def test_a_read_only_role_cannot_queue_a_scan(self):
        """Only verify_token is stubbed — the real require_write_role runs, so a
        handler with no gate fails here rather than passing."""
        self.role = "viewer"
        self.assertEqual(403, self._scan()["status"])


if __name__ == "__main__":
    unittest.main()
