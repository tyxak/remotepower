"""Ratchet guardrail: new handler SUBSYSTEMS must land in a bound *_handlers.py
module, not be appended to the api.py monolith.

Why this exists: for years new handlers were tacked onto api.py because that was
the path of least resistance, and the file grew until a periodic "split api.py"
housekeeping task became necessary (the same treadmill the app.js → app-*.js page
split fought on the frontend). This test removes the treadmill by making the
monolith's inline-handler count a RATCHET that can only go DOWN:

  - Adding a new inline ``def handle_x(`` to api.py pushes the count over the
    ceiling and FAILS here — the nudge to scaffold a module instead
    (``tools/new-handler-module.py <name> "<desc>"``). A handler defined in a
    ``*_handlers.py`` bound module does NOT count (it isn't in api.py), so the
    module path is unblocked.
  - EXTRACTING a subsystem into a module lowers the real count; LOWER the
    ceiling to match in the same commit (that's the ratchet tightening).
  - The escape hatch is deliberate: if a handler genuinely belongs on the core
    spine (dispatch/config/device/heartbeat), you consciously raise CEILING by
    the exact number with a one-line justification here. Raising it should be
    rare and reviewed — the default answer to "where does this new subsystem go"
    is a module.

Companion: tests/apisrc.py auto-globs ``*_handlers.py`` so source-pin tests see
moved code unchanged; ``tools/new-handler-module.py`` scaffolds the boilerplate +
prints the api.py wiring block.
"""
import re
import unittest
from pathlib import Path

_API = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'

# The number of top-level ``def handle_*`` definitions inline in api.py.
# RATCHET: only ever lower this (when you extract a subsystem into a bound
# module). Do NOT raise it to make room for a new subsystem — scaffold a module
# with tools/new-handler-module.py instead. (Raise ONLY for a deliberate
# core-spine handler, with a justification comment.)
INLINE_HANDLER_CEILING = 659


class TestApiHandlerRatchet(unittest.TestCase):
    def _inline_handler_count(self) -> int:
        src = _API.read_text()
        return len(re.findall(r'^def handle_[A-Za-z0-9_]*\(', src, re.M))

    def test_inline_handler_count_does_not_exceed_ceiling(self):
        n = self._inline_handler_count()
        self.assertLessEqual(
            n, INLINE_HANDLER_CEILING,
            f'api.py has {n} inline handlers (ceiling {INLINE_HANDLER_CEILING}). '
            'A new handler SUBSYSTEM belongs in a bound *_handlers.py module, not '
            'inline in api.py — scaffold one with '
            'tools/new-handler-module.py <name> "<desc>". If a handler genuinely '
            'belongs on the core spine, raise INLINE_HANDLER_CEILING here by the '
            'exact count with a justification.')

    def test_ceiling_is_not_left_slack_after_an_extraction(self):
        # Keep the ratchet honest: the ceiling must track the real count within a
        # small buffer, so an extraction that lowers the count is matched by
        # lowering the ceiling (otherwise the ratchet silently loosens and stops
        # nudging). Buffer of 3 tolerates an in-progress core-spine addition.
        n = self._inline_handler_count()
        self.assertGreaterEqual(
            INLINE_HANDLER_CEILING, n,
            'ceiling below real count — raise not allowed without justification')
        self.assertLessEqual(
            INLINE_HANDLER_CEILING - n, 3,
            f'ceiling ({INLINE_HANDLER_CEILING}) is {INLINE_HANDLER_CEILING - n} '
            'above the real count — you extracted handlers but did not tighten '
            'the ratchet. Lower INLINE_HANDLER_CEILING to the new count.')


if __name__ == '__main__':
    unittest.main()
