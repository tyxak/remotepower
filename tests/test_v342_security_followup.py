"""
Regression tests for the two v3.4.2 security follow-ups:

  * _oidc_assert_safe_url — SSRF guard on OIDC back-channel fetches (discovery
    doc + token endpoint). Blocks non-http(s) and link-local / cloud-metadata
    targets; allows RFC1918 and loopback so internal / dev IdPs keep working.
  * _batch_match_record — a re-issued install that was de-duplicated against an
    already-completed identical command must resolve from the prior run instead
    of hanging 'pending' forever, while a command still waiting in the queue
    stays pending until its own run lands.

Pure stdlib ``unittest`` (no pytest) so it runs under both
``python -m unittest discover`` (used by ``make dist``) and pytest.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class TestOidcSsrfGuard(unittest.TestCase):
    def test_blocks_metadata_and_linklocal(self):
        for url in ("http://169.254.169.254/.well-known/openid-configuration",  # AWS/GCP/Azure metadata
                    "https://169.254.169.254/token",                            # link-local over https
                    "http://0.0.0.0/"):                                         # unspecified
            with self.subTest(url=url), self.assertRaises(ValueError):
                api._oidc_assert_safe_url(url, "OIDC issuer")

    def test_blocks_non_http(self):
        for url in ("ftp://idp.example.com/", "file:///etc/passwd",
                    "gopher://10.0.0.1/", ""):
            with self.subTest(url=url), self.assertRaises(ValueError):
                api._oidc_assert_safe_url(url)

    def test_allows_internal_and_public(self):
        # Legitimate IdP locations for a LAN product — must NOT raise. IP literals
        # so getaddrinfo resolves them offline (no DNS / network in the test).
        for url in ("http://10.0.0.5/.well-known/openid-configuration",  # RFC1918 internal IdP
                    "https://192.168.1.10/token",                         # RFC1918
                    "http://127.0.0.1:8443/",                             # loopback dev IdP
                    "https://8.8.8.8/"):                                  # public IP literal
            with self.subTest(url=url):
                api._oidc_assert_safe_url(url, "OIDC issuer")


_KEY = "exec:apt-get install -y nginx"


class TestBatchMatchRecord(unittest.TestCase):
    def test_returns_record_after_created(self):
        rec = api._batch_match_record(
            [{"cmd": _KEY, "ts": 1000, "rc": 0, "output": "ok"}], _KEY,
            created=900, still_queued=False)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["rc"], 0)

    def test_pending_while_still_queued(self):
        # Only a prior run exists (ts < created) and the command is still queued,
        # so a fresh run is coming — stay pending.
        rec = api._batch_match_record(
            [{"cmd": _KEY, "ts": 500, "rc": 0}], _KEY, created=900, still_queued=True)
        self.assertIsNone(rec)

    def test_resolves_from_prior_run_when_dedup(self):
        # De-dup case: a prior run exists (ts < created) and the command is NOT
        # queued anymore (de-duplicated, won't run again) — resolve from it
        # instead of hanging pending forever.
        rec = api._batch_match_record(
            [{"cmd": _KEY, "ts": 500, "rc": 0, "output": "already newest version"}],
            _KEY, created=900, still_queued=False)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["ts"], 500)

    def test_none_when_never_ran(self):
        # No matching output and not queued → genuinely never ran → pending.
        self.assertIsNone(api._batch_match_record([], _KEY, created=900, still_queued=False))

    def test_prefers_newest_after_created(self):
        outs = [
            {"cmd": _KEY, "ts": 500, "rc": 0},
            {"cmd": _KEY, "ts": 1000, "rc": 0},
            {"cmd": _KEY, "ts": 1500, "rc": 1},   # newest at/after created
        ]
        rec = api._batch_match_record(outs, _KEY, created=900, still_queued=False)
        self.assertEqual(rec["ts"], 1500)
        self.assertEqual(rec["rc"], 1)


if __name__ == "__main__":
    unittest.main()
