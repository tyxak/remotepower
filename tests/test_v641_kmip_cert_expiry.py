#!/usr/bin/env python3
"""v6.4.1 guardrail: the KMIP server's own PKI expiry warns before it bites.

The agent cert-file sweep covers certificates ON a host. The KMIP CA and the
per-client certificates this server issues have no agent to report them, so
they were the one expiry nothing watched — and the consequence is sharper than
a normal cert: when a client certificate lapses, that appliance silently stops
being able to fetch its keys and its encrypted volumes fail to mount on the
next reboot. There was no signal until someone rebooted a NAS.

Drives the REAL sweep (`run_kmip_cert_check_if_due`) against the real store,
including the edge-trigger and auto-resolve contract. Runs under both backends.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class TestKmipCertExpiry(unittest.TestCase):
    def setUp(self):
        self.fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        self.addCleanup(lambda: setattr(api, "fire_webhook", self._orig_fire))
        api.save(api.CONFIG_FILE, {"cert_file_expiring_days": 21})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _store(self, *, enabled=True, ca_days=3000, clients=(), last_run=0,
               alerted=()):
        now = int(time.time())
        api.save(api.KMIP_FILE, {
            "enabled": enabled,
            "ca": {"not_after": now + ca_days * 86400},
            "clients": {f"c{i}": {"name": n, "not_after": now + d * 86400,
                                  "revoked": rev}
                        for i, (n, d, rev) in enumerate(clients)},
            "_cert_check": {"last_run": last_run, "alerted": list(alerted)},
        })
        api._invalidate_load_cache(api.KMIP_FILE)

    def test_silent_when_kmip_is_off(self):
        self._store(enabled=False, clients=[("nas", 2, False)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(self.fired, [], "must not fire when KMIP is disabled")

    def test_silent_when_nothing_is_near_expiry(self):
        self._store(clients=[("nas", 400, False), ("dsm", 900, False)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(self.fired, [])

    def test_fires_for_an_expiring_client_cert(self):
        self._store(clients=[("nas", 5, False), ("dsm", 900, False)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(len(self.fired), 1, self.fired)
        ev, pl = self.fired[0]
        self.assertEqual(ev, "kmip_cert_expiring")
        self.assertEqual(pl["subject"], "nas")
        self.assertLessEqual(pl["days"], 5)
        self.assertEqual(pl["count"], 1)

    def test_revoked_client_is_ignored(self):
        # A revoked client cannot fetch keys anyway — warning about its expiry
        # would be pure noise.
        self._store(clients=[("retired", 2, True)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(self.fired, [], "revoked clients must not warn")

    def test_expiring_ca_is_caught_too(self):
        self._store(ca_days=10, clients=[("nas", 900, False)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0][1]["subject"], "CA")

    def test_edge_triggered_not_every_run(self):
        self._store(clients=[("nas", 5, False)])
        api.run_kmip_cert_check_if_due()
        self.assertEqual(len(self.fired), 1)
        # Second run with the same set and the interval elapsed: no re-fire.
        st = api.load(api.KMIP_FILE)
        st["_cert_check"]["last_run"] = 0
        api.save(api.KMIP_FILE, st)
        api._invalidate_load_cache(api.KMIP_FILE)
        api.run_kmip_cert_check_if_due()
        self.assertEqual(len(self.fired), 1, "must be edge-triggered")

    def test_auto_resolves_when_renewed(self):
        # Previously alerted, now nothing expiring → the recover event fires so
        # the open alert closes instead of lingering forever.
        self._store(clients=[("nas", 900, False)], alerted=["nas"])
        api.run_kmip_cert_check_if_due()
        self.assertEqual([e for e, _ in self.fired], ["kmip_cert_renewed"])

    def test_respects_the_interval(self):
        self._store(clients=[("nas", 5, False)], last_run=int(time.time()))
        api.run_kmip_cert_check_if_due()
        self.assertEqual(self.fired, [], "must not run before the interval")

    def test_registry_wiring(self):
        # The recover event must resolve the firing one, and both must carry a
        # kind that exists in the channel matrix or routing silently drops them.
        self.assertIn("kmip_cert_expiring", api.EVENT_REGISTRY)
        self.assertIn("kmip_cert_renewed", api.EVENT_REGISTRY)
        self.assertIn("kmip_cert_expiring",
                      api.EVENT_REGISTRY["kmip_cert_renewed"]["resolves"])
        kinds = {k for (k, _l, _g) in api.CHANNEL_KIND_DEFS}
        for ev in ("kmip_cert_expiring", "kmip_cert_renewed"):
            self.assertIn(api.EVENT_REGISTRY[ev]["kind"], kinds, ev)
        # Alertable: a severity key is what puts it in the inbox at all.
        self.assertEqual(api.EVENT_REGISTRY["kmip_cert_expiring"]["severity"],
                         "high")

    def test_in_both_cadence_registries(self):
        # The external scheduler's CADENCE is a SECOND registry — a sweep in
        # main() but not there never runs on an out-of-band scheduler deploy.
        import inspect
        self.assertIn("run_kmip_cert_check_if_due", inspect.getsource(api.main))
        sched = (_ROOT / "server" / "cgi-bin" / "scheduler.py").read_text()
        self.assertIn("run_kmip_cert_check_if_due", sched)


if __name__ == "__main__":
    unittest.main(verbosity=2)
