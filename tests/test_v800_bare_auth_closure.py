#!/usr/bin/env python3
"""8.0.0: a handler gated only by `require_auth()` is looked at all the way down, not one call deep.

`tests/test_error_path_guards.py` keeps a reviewed list of the handlers that any signed-in role can call (a viewer included) and that change state. It follows ONE level of call
depth from the handler: its docstring explains why, since the full closure of `require_auth()` itself reaches storage (the session watermark `verify_token` writes). The rule it holds
was the one that let a viewer write the billing ledger, and it was found by going one frame deeper than the first detector did.

This file goes the rest of the way, with the part that made the full closure useless taken out: the functions that only do the caller's own bookkeeping (`require_*`, `verify_token`,
`audit_log`, the rate-limit and session helpers, `respond`, `load`) are neither followed nor counted as writers. Over the 286 handlers that call a bare `require_auth()` this finds 13 that reach a writer two or
more calls down and that the one-level detector cannot see. All 13 were read: nine are read-through caches and rollups, recomputed when the page is read; four ask the AI model for text
and write only the caller's own usage counter (the two that take a host id sit under `/api/devices/<id>/`, where `_enforce_device_scope()` runs before the handler). Each chain was
followed to the function that writes: the nine end in `_attention_payload`, which saves a rollup cache keyed by a fingerprint and a 10-second TTL; the four end in
`_ai_rate_limit_check`, which bumps `today:<user>` in the usage file. They are listed below with that reason; a fourteenth has to be read and added with its own.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_error_path_guards as g  # noqa: E402

# Functions that record the caller's own activity. Not followed, and never a "writer" for this rule.
_BOOKKEEPING = re.compile(
    r"^(require_|verify_token|_resolve_|audit_log|log_json|_log_|_rl_|_rate|rate_limit|_check_rate|_slow|get_token|respond|_env|load|_begin|_end|_request_id|_mint|_touch|_session_|_watermark|_tenant|_caller|_scope)")


def _function_table():
    table = {}
    for p in g._py_files():
        for fn in [n for n in ast.walk(ast.parse(p.read_text())) if isinstance(n, ast.FunctionDef)]:
            table.setdefault(fn.name, set()).update(g._called_names(fn))
    return table


def _writers(table):
    """Functions that reach a store write, directly or through other functions, without passing through bookkeeping."""
    writers = {n for n, calls in table.items() if calls & g._MUTATORS}
    changed = True
    while changed:
        changed = False
        for name, calls in table.items():
            if name in writers or _BOOKKEEPING.match(name):
                continue
            if any(c in writers and not _BOOKKEEPING.match(c) for c in calls):
                writers.add(name)
                changed = True
    return writers


def _bare_auth_handlers():
    out = []
    for p in g._py_files():
        for fn in [n for n in ast.walk(ast.parse(p.read_text())) if isinstance(n, ast.FunctionDef) and n.name.startswith("handle_")]:
            names = g._called_names(fn)
            if "require_auth" in names and not names & g._STRONGER_GATES:
                out.append((p.name, fn.name, names))
    return out


def _deeper_population():
    """Handlers gated only by a bare require_auth() that reach a writer through at least one more function, and that the one-level detector does not list."""
    one_level = g._bare_auth_mutating_handlers()
    writers = _writers(_function_table())
    return {(fname, name) for fname, name, names in _bare_auth_handlers() if (fname, name) not in one_level and _reaches_a_writer(names, writers)}


def _reaches_a_writer(callees, writers):
    """A handler that calls, besides its gate, a function that reaches a store write. Other handlers and bookkeeping are not followed."""
    return any(c in writers and not c.startswith("handle_") and not _BOOKKEEPING.match(c) for c in callees)


class TestTheClosureOfTheBareAuthRule(unittest.TestCase):
    REVIEWED = {
        # read-through caches and rollups, recomputed when the page is read; the write is a cache file, not authority the caller exercises
        "handle_alerts_list", "handle_attention", "handle_home", "handle_fleet_health", "handle_taxonomy_list", "handle_problems",
        "handle_fleet_report", "handle_site_report", "handle_fleet_chargeback",
        # ask the AI model for text; the only write is the usage counter and the audit line. handle_device_doc_draft and handle_device_runbook sit under
        # /api/devices/<id>/, so _enforce_device_scope() has already refused a host outside the caller's tenant or role scope; handle_ai_anomaly filters the
        # fleet it summarises with _scope_filter_devices(); handle_ai_cron sends no fleet data at all.
        "handle_ai_anomaly", "handle_ai_cron", "handle_device_doc_draft", "handle_device_runbook",
    }

    def test_every_handler_that_reaches_a_writer_further_down_has_been_read(self):
        population = _deeper_population()
        # Control: the detector is a name walk over a syntax tree; a rename of require_auth or of the storage helpers would empty it.
        self.assertGreaterEqual(len(population), 10, f"the deeper population collapsed to {len(population)}: the detector is measuring almost nothing")
        offenders = sorted(f"{f}: {n}" for f, n in population if n not in self.REVIEWED)
        self.assertEqual(offenders, [], "gated by a bare require_auth() and reaches a store write through a helper, so a viewer, an auditor or an MCP key can trigger "
                                        "it. Use require_write_role(), or read it and add it to REVIEWED with the reason:\n  " + "\n  ".join(offenders))

    def test_a_handler_that_no_longer_trips_the_detector_leaves_the_list(self):
        current = {n for _file, n in _deeper_population()}
        self.assertEqual(sorted(self.REVIEWED - current), [], "REVIEWED entries that no longer trip the detector: remove them")

    def test_the_detector_sees_what_the_one_level_walk_cannot(self):
        """Guard the guard, on source it is given: handle -> helper2 -> helper1 -> save() is invisible to the one-level rule and visible here, and a
        handler whose only extra call is bookkeeping is not flagged."""
        src = ("def handle_new():\n    require_auth()\n    return _helper2()\n"
               "def _helper2():\n    return _helper1()\n"
               "def _helper1():\n    save(FILE, {})\n"
               "def handle_cached():\n    require_auth()\n    return audit_log('x')\n"
               "def handle_direct():\n    require_auth()\n    save(FILE, {})\n")
        table = {}
        for fn in [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)]:
            table.setdefault(fn.name, set()).update(g._called_names(fn))
        writers = _writers(table)

        def one_level(name):                       # what tests/test_error_path_guards.py does
            wide = set(table[name])
            for nm in table[name]:
                if nm in table and not nm.startswith("handle_"):
                    wide |= table[nm]
            return bool(wide & g._MUTATORS)

        self.assertFalse(one_level("handle_new"), "the one-level walk is expected to miss this chain")
        self.assertTrue(_reaches_a_writer(table["handle_new"], writers))
        self.assertFalse(_reaches_a_writer(table["handle_cached"], writers))
        self.assertTrue(one_level("handle_direct"))   # the depth the existing ratchet already holds

if __name__ == "__main__":
    unittest.main()
