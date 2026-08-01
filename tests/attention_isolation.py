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


class TestDigestStoreListIsComplete(unittest.TestCase):
    """If `_compute_attention` gains a store, this list has to gain it too —
    otherwise the isolation quietly stops being isolation and the flake returns
    under a different test's name."""

    def test_every_digest_store_is_isolated(self):
        src = (_CGI / "api.py").read_text()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_compute_attention")
        read = set(re.findall(r"\b([A-Z][A-Z0-9_]*_FILE)\b", ast.unparse(fn)))
        missing = sorted(read - set(DIGEST_STORES))
        self.assertEqual(
            missing, [],
            "_compute_attention reads stores this helper does not isolate; add "
            "them to DIGEST_STORES or the order-dependent failures come back")


if __name__ == "__main__":
    unittest.main()
