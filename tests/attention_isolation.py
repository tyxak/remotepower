"""Isolate every store the Needs-Attention digest reads.

`_compute_attention()` reads ~18 `DATA_DIR`-relative stores. Tests that exercise
the digest have historically repointed only the two or three they seed, leaving
the rest aimed at the shared per-worker data dir — so a neighbouring module's
leftovers (an alert mute, a TLS result, a container status) land in the digest
and the assertions fail depending on which test ran first.

That is a real order-dependent failure, not flake, and it alternates: on one
`make test-fast` run `test_v247.TestAttentionDigest` fails, on the next
`test_v612_bugfixes.TestMutedAlertsLiftHealth` does. `make test` never sees it —
`unittest discover` is deterministic — which is exactly why it survived.

Use `isolate(api, tmpdir)` in setUp. `test_every_digest_store_is_isolated` below
fails if `_compute_attention` starts reading a store this helper does not cover,
so the list cannot silently fall behind the code.

v7.0.3: that guard read only the stores named INSIDE `_compute_attention`, and
the digest reads six more through helpers it calls — `_drift_state_ro`,
`_log_alert_evidence` and the four inside `_compute_fleet_reliability`. So six
stores stayed pointed at the shared per-worker data dir while the list looked
complete, and a neighbouring module leaving drift state for a device id as
common as `d1` put a drift row in a digest the test expected to be empty. The
guard walks the call graph now: a population derived from one function body was
the thing that went stale, not the rule.
"""

import ast
import re
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"

# Every *_FILE the digest reads, plus the mute store its filter consults and the
# digest's own cache file. Kept as names so `isolate` works against any api
# module instance a test has exec'd.
DIGEST_STORES = (
    "ACME_STATE_FILE", "AFTER_HOURS_FILE", "ALERTS_FILE", "ALERT_MUTES_FILE",
    "APIKEYS_FILE", "AV_FILE", "BRUTE_FORCE_FILE", "CONFIG_FILE",
    "CONTAINERS_FILE", "CVE_FINDINGS_FILE", "CVE_IGNORE_FILE", "DEVICES_FILE",
    "FLEET_EVENTS_FILE", "HARDWARE_FILE", "METRICS_HIST_FILE", "MON_HIST_FILE",
    "PACKAGES_FILE", "SERVICES_FILE", "TLS_RESULTS_FILE", "TLS_TARGETS_FILE",
    # v7.0.3: reached through a helper rather than named in the digest itself.
    # DRIFT_STATE_FILE via _drift_state_ro, LOG_WATCH_FILE via
    # _log_alert_evidence, the rest via _compute_fleet_reliability.
    "DRIFT_STATE_FILE", "HEALTH_HIST_FILE", "LOG_WATCH_FILE",
    "POSTURE_STATE_FILE", "SMART_HIST_FILE", "UPTIME_FILE",
)


def isolate(api, tmpdir):
    """Repoint every digest input at `tmpdir` and clear the digest's cache.

    Returns the {name: original} map so a test can restore in tearDown — worth
    doing, because these are module globals on a shared api instance.
    """
    tmpdir = Path(tmpdir)
    saved = {}
    for name in DIGEST_STORES:
        if not hasattr(api, name):
            continue                      # a store this build doesn't have
        saved[name] = getattr(api, name)
        setattr(api, name, tmpdir / Path(str(getattr(api, name))).name)
    try:
        api.save(api._attention_cache_file(), {})
    except Exception:
        pass
    # v7.0.3: the reliability rollup has its own file-backed cache in the shared
    # data dir, exactly like the digest's. Repointing the stores it reads does
    # nothing while a neighbour's cached rows are still served from disk.
    try:
        api.save(api._reliability_cache_file(), {})
    except Exception:
        pass
    try:
        api._invalidate_load_cache(None)
    except Exception:
        pass
    # The mute set is memoised on mtime; force a rebuild against the new path.
    try:
        api._ALERT_MUTE_SET_CACHE.update({"mtime": None, "set": frozenset(),
                                          "cset": frozenset(), "checked": 0})
    except Exception:
        pass
    return saved


def restore(api, saved):
    for name, value in (saved or {}).items():
        setattr(api, name, value)


_STORE_RE = re.compile(r"\b([A-Z][A-Z0-9_]*_FILE)\b")
_MAX_DEPTH = 5

# Not digest inputs, and repointing them would break the thing under test.
# Named rather than filtered out silently: an exemption with a reason gets
# re-read, a narrowed population regex does not.
NOT_A_DIGEST_INPUT = {
    # Read to decide WHICH storage backend to use, before any store exists.
    # It is a real file on disk under every backend; move it and the api module
    # picks a different backend than the test is running against.
    "STORAGE_MARKER_FILE",
}


def _api_functions():
    tree = ast.parse((_CGI / "api.py").read_text())
    return {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def digest_stores_in_source(fns=None, root="_compute_attention"):
    """Every `*_FILE` the digest reads, following the calls it makes.

    Bounded at `_MAX_DEPTH` so a deep helper chain cannot make the walk
    unbounded; every store found so far sits within two hops.
    """
    fns = fns or _api_functions()
    found, seen = set(), set()

    def walk(name, depth):
        if name in seen or name not in fns or depth > _MAX_DEPTH:
            return
        seen.add(name)
        body = ast.unparse(fns[name])
        found.update(_STORE_RE.findall(body))
        for node in ast.walk(fns[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                walk(node.func.id, depth + 1)

    walk(root, 0)
    return found - NOT_A_DIGEST_INPUT


class TestDigestStoreListIsComplete(unittest.TestCase):
    """If the digest gains a store, this list has to gain it too — otherwise the
    isolation quietly stops being isolation and the flake returns under a
    different test's name."""

    def test_every_digest_store_is_isolated(self):
        missing = sorted(digest_stores_in_source() - set(DIGEST_STORES))
        self.assertEqual(
            missing, [],
            "the Needs-Attention digest reads stores this helper does not "
            "isolate; add them to DIGEST_STORES or the order-dependent "
            "failures come back")

    def test_the_walk_actually_follows_calls(self):
        """The control. A walk that stops at the first function body reports a
        smaller set and still passes the check above, which is how six stores
        stayed invisible — so assert the walk reaches past the entry point, and
        name one store that is only reachable through a helper."""
        fns = _api_functions()
        direct = set(_STORE_RE.findall(ast.unparse(fns["_compute_attention"])))
        transitive = digest_stores_in_source(fns)
        self.assertGreater(
            len(transitive), len(direct),
            "the call-graph walk found no store beyond _compute_attention's own "
            "body — it is not following calls any more")
        self.assertIn(
            "DRIFT_STATE_FILE", transitive - direct,
            "DRIFT_STATE_FILE is read via _drift_state_ro, not named in the "
            "digest; if the walk stops seeing it, the walk is broken")


if __name__ == "__main__":
    unittest.main()
