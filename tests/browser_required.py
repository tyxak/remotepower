#!/usr/bin/env python3
"""Turn "no browser here" from a silent pass into a decision.

Four gates need a real Chromium — the rendered box-overflow walk, the dialog
walk, the icon-to-label gap measurement, and the accessibility sweep. Each of
them self-skips when playwright or the browser is missing, which is correct on a
contributor's laptop and is the whole problem everywhere else: the production CI
dep list installs no playwright and no axe-core, so all four skip there, every
time. They run only on a dev box that happens to have Chromium.

That is the same shape as the Postgres gate before `RP_PG_REQUIRE`: a suite
whose absence looked identical to its success. This is the same remedy, and
deliberately so — set `RP_BROWSER_REQUIRE=1` and a missing browser becomes a
FAILURE rather than a skip.

Why a flag instead of just adding playwright to the CI dep list: the four gates
each boot a seeded stack and drive a browser, which is minutes of wall clock and
a browser download per run. Whether prod CI should pay that is the maintainer's
call, not a decision to smuggle in via a requirements line. What is NOT a
judgement call is that the skip should be visible where it matters, and
`make pre-release` — the pre-tag gate, run on a box that does have Chromium —
sets the flag, so a release can no longer be cut while these four quietly
measured nothing.
"""
import os
import unittest


def _required():
    return (os.environ.get('RP_BROWSER_REQUIRE', '') or '').strip().lower() in (
        '1', 'true', 'yes', 'on')


def skip_or_fail(reason):
    """Skip, unless RP_BROWSER_REQUIRE says a browser must be available.

    Raises unittest.SkipTest normally, and a plain AssertionError when the flag
    is set — the caller is in setUpClass, so an AssertionError fails the class
    loudly instead of quietly removing it from the run.
    """
    if _required():
        raise AssertionError(
            f'RP_BROWSER_REQUIRE is set and the browser gate cannot run: '
            f'{reason}. This suite measures what no source check can see, so a '
            f'skip here is a release cut with four gates switched off. Install '
            f'playwright and `playwright install chromium`, or unset the flag '
            f'deliberately.')
    raise unittest.SkipTest(reason)
