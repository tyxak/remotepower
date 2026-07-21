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
