#!/usr/bin/env python3
"""Audit mode is worth exactly what its enumeration covers.

`/etc/remotepower/audit-mode` means "this agent reports, and changes nothing".
The agent's header carries a numbered list of the channels that honour it,
ending: "A new channel that writes to the host, spawns a process, or moves a
file belongs on this list with its own `_audit_mode()` check — the flag is only
worth what the enumeration is."

The list was kept by hand and the tests named functions one at a time, so three
appeared in neither. `collect_backup_verify` and `run_restore_drills` run
`restic -r <repo> check`, `borg check <repo>` and `tar -tf <repo>` as ROOT with
the repository taken from server-supplied config, and the second also creates
and deletes a directory tree. An operator who set audit mode and believed the
agent would run nothing was wrong about both.

So derive the population instead: every function `heartbeat()` calls with a
value that came from the server — the response body or the config it carries —
is a channel the server can drive. Each must either honour audit mode or be
exempt here with a reason. Read-only collectors are the bulk of the exemptions
and they are listed by name, because an undeclared exemption is
indistinguishable from a channel nobody has looked at.

Deriving "spawns a process" instead was tried first and is the wrong observable:
64 functions reachable from the heartbeat spawn one, and almost all are
collectors running a fixed argv (`uptime`, `smartctl`). What matters is whether
the SERVER chose the argument.
"""
import ast
import unittest
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py'
_ENTRY = 'heartbeat'

# How a server-supplied value enters heartbeat()'s locals.
_SERVER_SOURCES = ('resp.get', 'response.get', 'cfg.get', 'conf.get')

# Builtins and stdlib names that carry no channel meaning.
_NOT_CHANNELS = {
    'bool', 'int', 'str', 'len', 'list', 'set', 'dict', 'tuple', 'sorted',
    'sum', 'min', 'max', 'isinstance', 'any', 'all', 'float', 'print',
    'enumerate', 'zip', 'repr', 'abs', 'round', 'type', 'getattr', 'hasattr',
}

# Server-driven calls that do NOT need the gate, each with the reason.
# Audit mode is about changing the host; reading it is what the agent is for.
EXEMPT = {
    # ── read-only collectors, told WHAT to look at by the server ────────────
    'collect_backup_status': 'stats the configured paths; spawns nothing',
    'collect_disk_usage': 'walks the configured paths and reports sizes',
    'collect_image_cves': 'scans container images and reports findings',
    'collect_pii_findings': 'reads the configured paths, reports matches',
    'collect_secret_findings': 'reads the configured paths, reports matches',
    'compute_drift_report': 'hashes the watched files and reports differences',
    'count_mailbox_paths': 'counts files under the configured mail paths',
    'get_services': 'reads unit state for the watched services',
    'submit_unit_logs': 'reads journal lines for the named units and posts them',
    'run_iac_collection': 'reads host configuration and renders a description',
    'eval_agent_checks': 'evaluates file/job/log checks and reports results; '
                         'the one branch that ACTS (protect=quarantine) is '
                         'gated inside _eval_one_agent_check',
    '_canary_status': 'reports whether the canary files are intact',
    '_check_canaries': 'compares canary hashes; planting is _plant_canaries',
    '_watched_files_changed': 'compares hashes of the watched files',
    '_burst_live_samples': 'takes extra metric samples while a live view is open',
    # ── agent-owned bookkeeping, no host path involved ──────────────────────
    '_safe_state_write': 'writes under the agent state dir, never a host path',
    '_write_metrics_spool': 'writes the agent metric spool',
    '_spool_metric_sample': 'appends to the agent metric spool',
    '_stash_pending_cmd_output': 'stores a command result for the next beat',
    '_stable_hash': 'pure',
    'http_post': 'the transport back to the server',
    # ── the gates themselves ────────────────────────────────────────────────
    '_command_sig_ok': 'verifies a command signature; refusing is its job',
    '_strip_unsigned_protect': 'removes the acting half of an unsigned payload',
}


def _functions():
    tree = ast.parse(_AGENT.read_text(encoding='utf-8'))
    return {n.name: n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _server_derived_locals(fn):
    """Names in `fn` whose value came from the server, following assignments."""
    tainted = set()
    for _ in range(5):
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign):
                continue
            text = ast.unparse(node.value)
            from_server = any(m in text for m in _SERVER_SOURCES)
            from_tainted = any(isinstance(n, ast.Name) and n.id in tainted
                               for n in ast.walk(node.value))
            if from_server or from_tainted:
                for target in node.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            tainted.add(n.id)
    return tainted


def server_driven_calls(fns=None):
    """{callee: {locals it was passed}} for calls made with server data."""
    fns = fns or _functions()
    entry = fns[_ENTRY]
    tainted = _server_derived_locals(entry)
    out = {}
    for node in ast.walk(entry):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id in _NOT_CHANNELS:
            continue
        args = list(node.args) + [k.value for k in node.keywords]
        for arg in args:
            names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            if names & tainted:
                out.setdefault(node.func.id, set()).update(names & tainted)
    return out


def is_gated(name, fns=None):
    fns = fns or _functions()
    return name in fns and '_audit_mode' in ast.unparse(fns[name])


class TestEveryServerDrivenChannelIsGatedOrExempt(unittest.TestCase):

    def test_no_ungated_server_driven_channel(self):
        fns = _functions()
        ungated = sorted(name for name in server_driven_calls(fns)
                         if name in fns
                         and not is_gated(name, fns)
                         and name not in EXEMPT)
        self.assertEqual(
            ungated, [],
            'the heartbeat passes server-supplied data to these functions and '
            'they never consult /etc/remotepower/audit-mode. Add the check and '
            'the numbered entry in the agent header, or exempt them here with '
            f'the reason they cannot change the host: {ungated}')

    def test_the_backup_channels_are_gated(self):
        """Named, because these are the two the hand-kept list missed and the
        reason this file exists."""
        fns = _functions()
        for name in ('collect_backup_verify', 'run_restore_drills'):
            self.assertIn(name, fns, f'{name} has been renamed')
            self.assertTrue(is_gated(name, fns),
                            f'{name} runs a backup tool as root against a '
                            'server-supplied repository and must honour audit '
                            'mode')

    def test_the_header_enumeration_mentions_them(self):
        """The numbered list is what the next person reads before adding a
        channel. It has to agree with the code."""
        src = _AGENT.read_text()
        header = src[:src.index('def _audit_mode()')]
        for token in ('collect_backup_verify()', 'run_restore_drills()'):
            self.assertIn(token, header,
                          f'the audit-mode channel list does not mention {token}')

    def test_a_repository_argument_is_shape_checked(self):
        """The repo string reaches `restic -r <repo>` as root. `host_path()`
        only rewrites a string starting with `/`, so anything else went through
        untouched — including a leading `-`, which both tools read as an
        option rather than a repository."""
        fns = _functions()
        self.assertIn('_valid_backup_repo', fns)
        for name in ('collect_backup_verify', 'run_restore_drills'):
            self.assertIn('_valid_backup_repo', ast.unparse(fns[name]), name)


class TestTheDerivationIsHonest(unittest.TestCase):
    """Each assertion above is "this list is empty", which is also what a broken
    derivation produces."""

    def test_the_taint_walk_finds_the_server_locals(self):
        fns = _functions()
        tainted = _server_derived_locals(fns[_ENTRY])
        self.assertGreater(len(tainted), 20,
                           f'the taint walk collapsed: {sorted(tainted)}')
        for known in ('_backup_monitors', 'custom_scripts', 'agent_checks'):
            self.assertIn(known, tainted,
                          f'{known} comes straight from the heartbeat response '
                          'and the walk no longer sees it')

    def test_the_call_derivation_finds_the_known_channels(self):
        calls = server_driven_calls()
        for known in ('execute_command', 'run_custom_scripts',
                      'apply_host_config', 'collect_backup_verify',
                      'run_restore_drills', '_plant_canaries',
                      '_apply_guard_actions'):
            self.assertIn(known, calls,
                          f'{known} is a server-driven channel and the '
                          'derivation no longer sees it')
        self.assertGreater(len(calls), 15, sorted(calls))

    def test_the_gate_detector_separates_gated_from_ungated(self):
        fns = _functions()
        self.assertTrue(is_gated('_plant_canaries', fns),
                        'a known-gated function reads as ungated')
        self.assertFalse(is_gated('collect_backup_status', fns),
                         'a known-ungated function reads as gated, so the '
                         'population check would pass for the wrong reason')

    def test_every_exemption_names_a_function_that_exists(self):
        fns = _functions()
        missing = sorted(n for n in EXEMPT if n not in fns)
        self.assertEqual(missing, [],
                         f'exemption for a function that is gone: {missing}')

    def test_every_exemption_is_still_reachable_with_server_data(self):
        """An exemption for a call the heartbeat no longer makes is dead weight
        that makes the list look considered when it is stale."""
        calls = set(server_driven_calls())
        stale = sorted(n for n in EXEMPT if n not in calls)
        self.assertEqual(stale, [],
                         f'exemption for a call that is no longer made: {stale}')


if __name__ == '__main__':
    unittest.main()
