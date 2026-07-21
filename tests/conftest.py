"""pytest-only guards for the parallel suite (`make test-fast`).

unittest discover (the CI runner) never loads this file — it only affects
pytest runs, where xdist workers exposed a dangerous leak class:

Several test files `os.environ.pop('RP_DATA_DIR', None)` in their cleanup.
Any module that execs api.py AFTER that in the same worker process falls back
to the REAL `/var/lib/remotepower` — on a box where that is writable, the
suite would write into (or wipe state of) a live install; where it isn't,
you get the PermissionError flakes that made test-fast untrustworthy
(test_v247's 13 errors, 2026-07-19).

The guard is module-scoped: every module starts with RP_DATA_DIR set (a
fresh scratch dir if nothing else set one), and a module that pops or
overwrites the var can never leak that change into the NEXT module.
"""

import os
import sys
import tempfile

import pytest


@pytest.fixture(autouse=True, scope="module")
def _rp_data_dir_guard():
    prev = os.environ.get("RP_DATA_DIR")
    if not prev:
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-xdist-")
    yield
    if prev is not None:
        os.environ["RP_DATA_DIR"] = prev
    elif not os.environ.get("RP_DATA_DIR"):
        # The module popped it and there was no prior value: re-arm a fresh
        # scratch dir rather than leaving the /var/lib fallback exposed.
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-xdist-")


# ── v6.3.1: CGI request-env leak guard ───────────────────────────────────────
# Many handler tests drive api.main()/handlers by writing CGI-style request
# vars straight into os.environ (REQUEST_METHOD, PATH_INFO, QUERY_STRING,
# CONTENT_LENGTH, HTTP_X_TOKEN, REMOTE_ADDR, X-Forwarded-For, …) and never
# clean them up — api._env() reads os.environ, so a value one module leaves
# behind bleeds into the NEXT module's request-reading tests in the same xdist
# worker. That is the rotating-victim flake class (keyip's IP allowlist,
# forecast's GET check, authz_smoke's viewer 403 — all read request env; the
# culprit differs run-to-run because loadfile groups files differently).
#
# The guard snapshots every request-scoped env key before each module and
# restores that exact snapshot after: keys the module ADDED are deleted (so the
# next module starts clean), keys it CHANGED are reset. Module-scoped and
# restore-to-prior, mirroring the RP_DATA_DIR guard above. Within-module env
# use is untouched (a module's own setUp still sets what it needs). Like that
# guard, unittest discover never loads this — it is a pytest/xdist-only net.
_REQUEST_ENV_EXACT = (
    "REQUEST_METHOD", "PATH_INFO", "QUERY_STRING", "CONTENT_LENGTH",
    "CONTENT_TYPE", "REMOTE_ADDR", "SCRIPT_NAME", "SERVER_NAME",
    "SERVER_PORT", "HTTPS", "REQUEST_URI",
    # v6.3.1: the storage-backend selector. Several test files set
    # RP_STORAGE_BACKEND=sqlite (via a _load_api helper) and don't restore it,
    # so a later module in the same worker exec's/reads api under the wrong
    # backend against a SHARED sqlite DB carrying another test's config — which
    # is how test_v612_host_signals saw a stale `unit_flap_restarts` and fired.
    # Snapshot+restore it here (paired with the _BACKEND_CACHE reset below).
    "RP_STORAGE_BACKEND", "RP_PG_DSN",
)


def _request_env_keys():
    keys = {str(k) for k in _REQUEST_ENV_EXACT}
    keys.update(k for k in os.environ if k.startswith("HTTP_"))
    return keys


@pytest.fixture(autouse=True, scope="module")
def _request_env_guard():
    keys = _request_env_keys()
    snap = {k: os.environ[k] for k in keys if k in os.environ}
    yield
    # Re-scan: the module may have ADDED request keys (e.g. a new HTTP_* header)
    # not present in the pre-snapshot — those must be removed, not just reset.
    for k in _request_env_keys():
        if k in snap:
            os.environ[k] = snap[k]
        else:
            os.environ.pop(k, None)

# ── v6.3.1: shared-`api` storage-key + auth-fn leak guard ────────────────────
# The rotating-victim xdist flake (keyip / forecast / authz_smoke / v247 / … —
# a DIFFERENT single victim each run, all serially green) is a cross-module
# STATE leak, the sibling of the request-env class above. Many handler tests do
# `import api` (the SHARED module) and repoint a storage-key global
# (api.CONFIG_FILE = tmp/…) or stub an auth/transport fn (api.verify_token = …)
# in setUp, but don't restore it. The next module in the same worker then reads
# the leaked pointer/stub: e.g. keyip's verify_token reads CONFIG_FILE for the
# IP-allowlist check but only sets APIKEYS_FILE, so a leaked CONFIG_FILE with
# ip_allowlist_enabled flips its result.
#
# This guard snapshots — for the SHARED api module only (isolated importlib
# instances aren't in sys.modules['api'], and their patches don't leak) — every
# `*_FILE` / DATA_DIR storage-key global plus the leak-prone auth/transport
# functions before each module, and restores that snapshot after. Keys/attrs a
# module ADDED are handled by the value comparison; module-scope means a
# module's own setUp/tearDown patching within its tests is untouched — only what
# escapes the module boundary is cleaned. It also clears api._LOAD_CACHE at both
# ends so a stale cached blob can't bleed across modules. pytest/xdist-only.
_API_GUARD_FNS = (
    "verify_token", "require_auth", "require_admin_auth", "require_write_role",
    "require_perm", "get_token_from_request", "get_json_obj", "get_json_body",
    "respond", "method", "_env", "_get_client_ip", "_caller_scope",
    "audit_log", "fire_webhook", "log_command",
)


def _api_guard_names(api):
    names = {str(n) for n in _API_GUARD_FNS}
    names.add("DATA_DIR")
    names.update(n for n in dir(api) if n.endswith("_FILE"))
    return names


@pytest.fixture(autouse=True, scope="module")
def _api_shared_state_guard():
    api = sys.modules.get("api")
    if api is None:
        yield
        return
    names = _api_guard_names(api)
    snap = {n: getattr(api, n) for n in names if hasattr(api, n)}
    # v6.3.1: also snapshot the resolved storage backend. A module that flipped
    # RP_STORAGE_BACKEND (restored by the env guard) still leaves api's memoised
    # _BACKEND_CACHE pointing at the wrong backend until reset — so reset it at
    # both ends and let the next read re-resolve from the (restored) env.
    _had_backend_cache = hasattr(api, "_BACKEND_CACHE")
    _cache = getattr(api, "_LOAD_CACHE", None)
    for _c in (_cache,):
        if hasattr(_c, "clear"):
            try:
                _c.clear()
            except Exception:
                pass
    if _had_backend_cache:
        try:
            api._BACKEND_CACHE = None
        except Exception:
            pass
    yield
    for n, v in snap.items():
        try:
            setattr(api, n, v)
        except Exception:
            pass
    if hasattr(_cache, "clear"):
        try:
            _cache.clear()
        except Exception:
            pass
    if _had_backend_cache:
        try:
            api._BACKEND_CACHE = None
        except Exception:
            pass
