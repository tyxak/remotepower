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
