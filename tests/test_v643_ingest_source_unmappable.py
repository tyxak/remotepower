"""v6.4.3: alert on an ingest token that is wired to nothing.

`remotepower-syslogd` and `remotepower-flowd` both map an incoming datagram to a
token by the sender's SOURCE IP, looked up against the enrolled DEVICE's `ip`.
A token whose device has no `ip`, whose device was deleted, or that is disabled
is dropped from that map — every packet it was meant to catch is discarded, and
the only place that said so was a card on the Server status page. Silent data
loss reported on a page nobody has open during an outage is not a control.

This is a per-TOKEN alert, so it has to satisfy the whole per-resource contract
or it fails in one of three quiet ways (CLAUDE.md, rule 3c):

  * without `token_id` in `_ALERT_IDENTITY_FIELDS`, two dead tokens on one
    server coalesce into ONE alert row;
  * without `token_id` in the `_record_alert` payload whitelist, the recovery
    has nothing to match on and the alert sits open forever;
  * without a `sub_match` branch, the recovery clears EVERY open row for the
    server, including tokens that are still broken.

So the tests below drive the real `_record_alert` → `_auto_resolve_alerts` path.
A hand-built {'payload': {...}} dict bypasses both the whitelist and the
coalescing identity and gives a false green.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"

sys.path.insert(0, str(_ROOT / "tests"))
import apisrc  # noqa: E402

_SRC = apisrc.api_source()

_EVENT = "ingest_source_unmappable"
_RECOVER = "ingest_source_mapped"


def _fresh_api():
    """A private api module on its own data dir — these tests write alerts."""
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
    spec = importlib.util.spec_from_file_location("api_unmappable", str(_CGI / "api.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["api_unmappable"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestTheEventIsDeclaredEverywhereItHasToBe(unittest.TestCase):
    """One missing registry = an event that fires into a void."""

    def test_both_events_are_in_the_registry(self):
        for ev in (_EVENT, _RECOVER):
            self.assertIn(f"'{ev}': dict(", _SRC, f"{ev} is not in EVENT_REGISTRY")

    def test_the_recovery_resolves_the_firing_event(self):
        self.assertRegex(_SRC, rf"resolves=\('{_EVENT}',\)")

    def test_the_discriminator_is_an_identity_field(self):
        """Without this, two dead tokens on one server become one alert row."""
        block = re.search(r"_ALERT_IDENTITY_FIELDS = \((.*?)\n\)", _SRC, re.S)
        self.assertIsNotNone(block)
        self.assertIn("'token_id'", block.group(1))

    def test_the_discriminator_is_in_the_record_alert_whitelist(self):
        """Without this it is never STORED, so the recovery cannot match it and
        the alert stays open forever."""
        import srcpin

        body = srcpin.py_function(_SRC, "_record_alert")
        keys = re.search(r"for key in \((.*?)\):", body, re.S)
        self.assertIsNotNone(keys, "the _record_alert whitelist moved")
        self.assertIn("'token_id'", keys.group(1))

    def test_the_recovery_has_a_sub_match_branch(self):
        """Without it, one token recovering clears every other dead token's
        alert on the same server."""
        import srcpin

        body = srcpin.py_function(_SRC, "_auto_resolve_alerts")
        self.assertIn(_RECOVER, body)
        self.assertIn("token_id", body)

    def test_the_frontend_knows_both_events(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        for ev in (_EVENT, _RECOVER):
            self.assertIn(f"'{ev}'", js, f"{ev} missing from app.js (FLEET_EVENTS / routing)")


class TestTheAlertCoalescingContract(unittest.TestCase):
    """The three quiet failure modes, driven through the real path."""

    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.ALERTS_FILE, {"alerts": []})
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)

    def _fire(self, ev, token_id, label="fw01"):
        self.api._record_alert(
            ev,
            {
                "name": "rp-server",
                "token_id": token_id,
                "label": label,
                "detail": f"{label} is wired to nothing",
            },
        )

    def _open(self):
        rows = (self.api.load(self.api.ALERTS_FILE) or {}).get("alerts") or []
        # NB: the store marks resolution with `resolved_at`, not `resolved` —
        # filtering on the wrong key makes every "it was cleared" assertion
        # vacuous, which is how the first draft of this file passed.
        return [a for a in rows if not a.get("resolved_at") and a.get("event") == _EVENT]

    def test_two_dead_tokens_are_two_alerts(self):
        self._fire(_EVENT, "t1", "fw01")
        self._fire(_EVENT, "t2", "rtr2")
        self.assertEqual(
            2,
            len(self._open()),
            "two tokens wired to nothing coalesced into one alert row — "
            "token_id is not discriminating the identity",
        )

    def test_the_token_id_is_actually_stored(self):
        self._fire(_EVENT, "t1")
        self.assertEqual("t1", (self._open()[0].get("payload") or {}).get("token_id"))

    def test_fixing_one_leaves_the_other_open(self):
        self._fire(_EVENT, "t1", "fw01")
        self._fire(_EVENT, "t2", "rtr2")
        self.api.fire_webhook(_RECOVER, {"name": "rp-server", "token_id": "t1", "label": "fw01"})
        still = self._open()
        self.assertEqual(
            ["t2"],
            [(a.get("payload") or {}).get("token_id") for a in still],
            "recovering one token cleared the other token's alert too",
        )

    def test_fixing_it_closes_its_own_alert(self):
        """Positive control: the recovery must actually work, or the test above
        passes for the wrong reason."""
        self._fire(_EVENT, "t1", "fw01")
        self.assertEqual(1, len(self._open()))
        self.api.fire_webhook(_RECOVER, {"name": "rp-server", "token_id": "t1", "label": "fw01"})
        self.assertEqual(0, len(self._open()))


class TestTheSweepFiresIt(unittest.TestCase):
    """The end that matters: does anything ever CALL it."""

    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.ALERTS_FILE, {"alerts": []})

    def _reopen_cadence(self):
        api = self.api
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.pop("last_sidecar_watch", None)
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _run(self, tokens, devices):
        api = self.api
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": tokens})
        api.save(api.DEVICES_FILE, devices)
        api.save(api.SIDECAR_STATE_FILE, {})
        for f in (api.INBOUND_WEBHOOKS_FILE, api.DEVICES_FILE, api.SIDECAR_STATE_FILE):
            api._invalidate_load_cache(f)
        self._reopen_cadence()
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **kw: fired.append((ev, p or {}))
        try:
            api.run_sidecar_watch_if_due()
        finally:
            api.fire_webhook = real
        return fired

    def test_a_source_with_no_device_ip_raises_the_alert(self):
        fired = self._run(
            [{"id": "s1", "kind": "syslog", "label": "fw01", "scope_device_id": "d1"}],
            {"d1": {"name": "fw01"}},
        )
        evs = [e for e, _p in fired if e == _EVENT]
        self.assertEqual(1, len(evs), f"the sweep did not fire {_EVENT}; it fired {fired!r}")
        payload = [p for e, p in fired if e == _EVENT][0]
        self.assertEqual("s1", payload.get("token_id"))
        self.assertIn("fw01", json.dumps(payload))

    def test_a_healthy_source_fires_nothing(self):
        """Positive control on the negative direction."""
        fired = self._run(
            [{"id": "s1", "kind": "syslog", "label": "fw01", "scope_device_id": "d1"}],
            {"d1": {"name": "fw01", "ip": "10.0.0.1"}},
        )
        self.assertEqual([], [e for e, _p in fired if e in (_EVENT, _RECOVER)])

    def test_it_is_edge_triggered_not_every_sweep(self):
        """A per-tick re-fire is an alert storm and defeats the coalescing."""
        toks = [{"id": "s1", "kind": "syslog", "label": "fw01", "scope_device_id": "d1"}]
        devs = {"d1": {"name": "fw01"}}
        self._run(toks, devs)
        api = self.api
        # Clear the cadence claim, or the second call returns at the due check
        # and "it did not re-fire" is true for the wrong reason.
        self._reopen_cadence()
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **kw: fired.append((ev, p or {}))
        try:
            api.run_sidecar_watch_if_due()
        finally:
            api.fire_webhook = real
        self.assertEqual([], [e for e, _p in fired if e == _EVENT])

    def test_fixing_the_device_ip_clears_it(self):
        toks = [{"id": "s1", "kind": "syslog", "label": "fw01", "scope_device_id": "d1"}]
        self._run(toks, {"d1": {"name": "fw01"}})
        api = self.api
        api.save(api.DEVICES_FILE, {"d1": {"name": "fw01", "ip": "10.0.0.1"}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.SIDECAR_STATE_FILE)
        self._reopen_cadence()
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **kw: fired.append((ev, p or {}))
        try:
            api.run_sidecar_watch_if_due()
        finally:
            api.fire_webhook = real
        self.assertIn(_RECOVER, [e for e, _p in fired])

    def test_a_disabled_token_is_not_reported_as_broken(self):
        """Deliberately switching a token off is an operator decision, not a
        fault — alerting on it would train people to ignore the event."""
        fired = self._run(
            [
                {
                    "id": "s1",
                    "kind": "syslog",
                    "label": "fw01",
                    "scope_device_id": "d1",
                    "enabled": False,
                }
            ],
            {"d1": {"name": "fw01"}},
        )
        self.assertEqual([], [e for e, _p in fired if e == _EVENT])


if __name__ == "__main__":
    unittest.main()
