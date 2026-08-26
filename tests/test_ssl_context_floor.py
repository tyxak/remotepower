#!/usr/bin/env python3
"""_get_ssl_context() must RAISE the outbound TLS floor, never lower it.

The function used to assign `ctx.minimum_version = TLSv1_2` unconditionally.
`ssl.create_default_context()` honours OpenSSL's `MinProtocol` from
openssl.cnf, so on a host the operator pinned to TLSv1.3 that assignment
handed back a TLS 1.2-capable context — silently undoing their hardening.

It also broke monitoring. Lowering the floor puts TLS 1.2 back in the
ClientHello's supported_versions, which changes the JA3/JA4 fingerprint;
Cloudflare Bot Fight Mode answered the resulting handshake with a 403 and
`cf-mitigated: challenge`. Every monitor aimed at a Cloudflare-fronted host
read as permanently down, while curl and plain urllib against the same URL
returned 200 — measured 6/6 in both directions on a live host.

The test simulates the hardened host by patching create_default_context, so it
fails on ANY machine rather than only where the system default is already
strict. A test that asserts `>= TLSv1_2` alone would pass against the old code
everywhere and prove nothing.
"""
import os
import ssl
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestOutboundTLSFloor(unittest.TestCase):

    def test_never_lowers_a_stricter_system_default(self):
        """The regression itself: a TLSv1.3-pinned host must stay pinned."""
        real = ssl.create_default_context   # bind before patching, or recurse

        def hardened():
            c = real()
            c.minimum_version = ssl.TLSVersion.TLSv1_3
            return c

        with mock.patch.object(ssl, "create_default_context", hardened):
            ctx = api._get_ssl_context()
        self.assertEqual(
            ctx.minimum_version, ssl.TLSVersion.TLSv1_3,
            "_get_ssl_context() downgraded a TLSv1.3 system floor to "
            f"{ctx.minimum_version!r}. Raise the floor, never assign it: "
            "openssl.cnf MinProtocol reaches us through "
            "create_default_context(), and overriding it both weakens the "
            "operator's hardening and alters the JA3 fingerprint enough for "
            "Cloudflare Bot Fight Mode to 403 every outbound probe.")

    def test_still_raises_a_slack_system_default(self):
        """The original v4.1.0 intent must survive: no TLS 1.0/1.1 outbound."""
        real = ssl.create_default_context   # bind before patching, or recurse

        def slack():
            c = real()
            # TLSv1 is deprecated in the stdlib and that is the point — it is
            # what a permissive system default looks like. Silenced so the
            # suite does not carry a warning on every run for a value we are
            # asserting gets rejected.
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                c.minimum_version = ssl.TLSVersion.TLSv1
            return c

        with mock.patch.object(ssl, "create_default_context", slack):
            ctx = api._get_ssl_context()
        self.assertGreaterEqual(
            ctx.minimum_version, ssl.TLSVersion.TLSv1_2,
            "_get_ssl_context() must still lift a permissive system default "
            "up to TLS 1.2 — that is what the guard was added for.")

    def test_unpatched_context_is_sane(self):
        """Control: the real thing verifies certs and is at least TLS 1.2."""
        ctx = api._get_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertGreaterEqual(
            ctx.minimum_version, ssl.create_default_context().minimum_version,
            "the returned context is weaker than this host's own default")


if __name__ == "__main__":
    unittest.main()
