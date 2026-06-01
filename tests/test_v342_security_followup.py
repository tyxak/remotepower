"""
Regression tests for the two v3.4.2 security follow-ups:

  * _oidc_assert_safe_url — SSRF guard on OIDC back-channel fetches (discovery
    doc + token endpoint). Blocks non-http(s) and link-local / cloud-metadata
    targets; allows RFC1918 and loopback so internal / dev IdPs keep working.
  * _batch_match_record — a re-issued install that was de-duplicated against an
    already-completed identical command must resolve from the prior run instead
    of hanging 'pending' forever, while a command still waiting in the queue
    stays pending until its own run lands.

Harness: import api.py as a module with its data dir pointed at a throwaway tmp
dir (mirrors tests/test_authz_mitigate_scope.py).
"""
import importlib.util
import os
import sys
import tempfile
import pathlib
import pytest

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

REPO = pathlib.Path(__file__).resolve().parents[1]
APIPY = REPO / "server" / "cgi-bin" / "api.py"

spec = importlib.util.spec_from_file_location("rp_api_secfollowup", APIPY)
api = importlib.util.module_from_spec(spec)
sys.modules["rp_api_secfollowup"] = api
spec.loader.exec_module(api)


# ── OIDC SSRF guard ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/.well-known/openid-configuration",  # AWS/GCP/Azure metadata
    "https://169.254.169.254/token",                            # link-local over https
    "http://0.0.0.0/",                                          # unspecified
])
def test_oidc_url_blocks_metadata_and_linklocal(url):
    with pytest.raises(ValueError):
        api._oidc_assert_safe_url(url, "OIDC issuer")


@pytest.mark.parametrize("url", [
    "ftp://idp.example.com/",      # non-http scheme
    "file:///etc/passwd",          # non-http scheme
    "gopher://10.0.0.1/",          # non-http scheme
    "",                            # empty
])
def test_oidc_url_blocks_non_http(url):
    with pytest.raises(ValueError):
        api._oidc_assert_safe_url(url)


@pytest.mark.parametrize("url", [
    "http://10.0.0.5/.well-known/openid-configuration",  # RFC1918 internal IdP — allowed
    "https://192.168.1.10/token",                         # RFC1918 — allowed
    "http://127.0.0.1:8443/",                             # loopback dev IdP — allowed
    "https://8.8.8.8/",                                   # public IP literal — allowed
])
def test_oidc_url_allows_internal_and_public(url):
    # Must not raise — these are legitimate IdP locations for a LAN product.
    api._oidc_assert_safe_url(url, "OIDC issuer")


# ── batch / install job de-dup resolution ────────────────────────────────────
KEY = "exec:apt-get install -y nginx"


def test_batch_match_returns_record_after_created():
    outs = [{"cmd": KEY, "ts": 1000, "rc": 0, "output": "ok"}]
    rec = api._batch_match_record(outs, KEY, created=900, still_queued=False)
    assert rec is not None and rec["rc"] == 0


def test_batch_match_pending_while_still_queued():
    # Only a prior run exists (ts < created) and the command is still queued, so
    # a fresh run is coming — stay pending.
    outs = [{"cmd": KEY, "ts": 500, "rc": 0, "output": "ok"}]
    rec = api._batch_match_record(outs, KEY, created=900, still_queued=True)
    assert rec is None


def test_batch_match_resolves_from_prior_run_when_dedup():
    # The de-dup case: a prior run exists (ts < created) and the command is NOT
    # queued anymore (it was de-duplicated and won't run again) — resolve from
    # the prior run instead of hanging pending forever.
    outs = [{"cmd": KEY, "ts": 500, "rc": 0, "output": "already newest version"}]
    rec = api._batch_match_record(outs, KEY, created=900, still_queued=False)
    assert rec is not None and rec["ts"] == 500


def test_batch_match_none_when_never_ran():
    # No matching output at all and not queued → genuinely never ran → pending.
    assert api._batch_match_record([], KEY, created=900, still_queued=False) is None


def test_batch_match_prefers_newest_after_created():
    outs = [
        {"cmd": KEY, "ts": 500, "rc": 0},
        {"cmd": KEY, "ts": 1000, "rc": 0},
        {"cmd": KEY, "ts": 1500, "rc": 1},   # newest at/after created
    ]
    rec = api._batch_match_record(outs, KEY, created=900, still_queued=False)
    assert rec["ts"] == 1500 and rec["rc"] == 1
