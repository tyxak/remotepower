#!/usr/bin/env python3
"""A muteable alert whose Needs-Attention item is unmuteable never lifts a score.

`_NA_MUTE_EVENTS` translates a Needs-Attention item's (kind, severity) — a UI
grouping — into the webhook event(s) that item represents, because mutes are
keyed by event and the two are separate namespaces. The map's own comment states
the stakes exactly: "an NA kind with NO _NA_MUTE_EVENTS row is UNMUTEABLE, and
an unmuteable item permanently depresses the host's (and the fleet's) health
score with no operator recourse."

Four kinds had no row while having everything a muteable kind needs: they are
emitted per host, they get a `device_id` like every other per-host item, and a
per-device alertable event exists for each. Muting the alert stopped the
notification and left the item standing, so the score never recovered — for a
known-and-accepted CVE backlog, a host deliberately pending a reboot, a paused
snapshot schedule, or a service someone has decided to leave stopped.

Rather than pin the four, this DERIVES the requirement: for every (kind,
severity) the digest can emit, if an alertable event of the same name exists in
EVENT_REGISTRY then that kind must have a row. New NA kinds are then covered
automatically, which is the failure mode here — the map is a second registry,
and this codebase's recurring bug is two registries drifting.

Kinds with no same-named event stay exempt and are listed with a reason, because
that is a real category: os_eol, cred_rotation, after_hours and the fleet-level
items have no per-device event to mute and never will.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-namute-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tests'))
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

from srcpin import py_function  # noqa: E402
import api  # noqa: E402

# Kinds with no per-device event, so nothing exists to key a mute on. Each needs
# a reason: an undeclared exemption is indistinguishable from one nobody checked.
EXEMPT = {
    'os_eol': 'end-of-life is a property of the OS release, not an event that '
              'fires per device',
    'cred_rotation': 'a due-date rollup, not a per-device alert',
    'after_hours': 'fleet-level policy observation with no device behind it',
    'apikey_rotation_due': 'fleet-level: API keys are not device-scoped',
    'proxmox_backup': 'reported per Proxmox job, with no per-device event',
    'acme': 'certificate lifecycle is tracked per certificate, not per device',
    'agent_integrity': 'no per-device integrity event exists; agent_stopped is a '
                       'different condition',
    'agent_version': 'informational version drift, with no alertable event',
    'ssh_key': 'the ssh_key_* events describe key CHANGES, not this posture item',
    'tls': 'certificate items are keyed to a certificate/endpoint, and the '
           'fleet-level ones resolve to no device at all',
    'monitor_down': 'monitors are not devices; the item resolves to no device_id',
}


def _emitted_pairs():
    """Every (kind, severity) `_compute_attention` can append, from its source.

    Walks each `items.append({...})` dict STRING-AWARE and brace-balanced rather
    than matching 'severity' and 'kind' as adjacent keys. The adjacency version
    of this silently missed a third of the kinds — including several with a
    matching event — which would have made the main assertion vacuous for
    exactly the cases it exists to catch. srcpin bounds the function itself,
    since it is ~54k characters and a guessed slice would stop covering it.
    """
    body = py_function(api_source(), '_compute_attention')
    pairs, i = set(), 0
    anchor = 'items.append({'
    while True:
        i = body.find(anchor, i)
        if i < 0:
            break
        st = i + len(anchor) - 1
        depth, j = 0, st
        while j < len(body):
            c = body[j]
            if c in '"\'':
                q, j = c, j + 1
                while j < len(body):
                    if body[j] == '\\':
                        j += 2
                        continue
                    if body[j] == q:
                        break
                    j += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        blob = body[st:j + 1]
        k = re.search(r"'kind'\s*:\s*'([a-z_]+)'", blob)
        if k:
            sevs = re.findall(r"'severity'\s*:\s*'([a-z]+)'", blob)
            for sev in (sevs or ['(dynamic)']):
                pairs.add((k.group(1), sev))
        i = j
    return pairs


def api_source():
    return (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()


class TestTheScanSeesTheDigest(unittest.TestCase):
    """Positive controls. Every assertion below is shaped 'nothing is missing',
    which is what a broken extraction produces too."""

    def test_the_digest_function_is_found_and_large(self):
        body = py_function(api_source(), '_compute_attention')
        self.assertGreater(len(body), 20000,
                           'srcpin returned a stub — the pair scan is blind')

    def test_the_scan_finds_a_known_kind(self):
        pairs = _emitted_pairs()
        self.assertIn(('offline', 'critical'), pairs,
                      'the scan cannot see a kind that certainly exists')
        self.assertGreater(len(pairs), 15, f'only {len(pairs)} pairs found')

    def test_the_registry_loaded(self):
        self.assertGreater(len(api.EVENT_REGISTRY), 100)


class TestEveryMuteableKindHasARow(unittest.TestCase):

    def test_every_emitted_kind_is_either_muteable_or_declared_unmuteable(self):
        """Every kind must be a DECISION, not an omission.

        An earlier version of this asked whether an event of the SAME NAME
        existed, and skipped the kind otherwise. That silently exempted exactly
        the cases worth catching: the kind is `cve` and the event is
        `cve_found`, the kind is `reboot` and the event is `reboot_required`,
        the kind is `snapshot` and the events are `snapshot_old` /
        `snapshot_stale`. Only `service_down` happened to match its event name,
        so the check was protecting one of the four rows it was written for —
        which the fail-demo showed, and which is why it is written this way now.

        So the rule is total: a kind is muteable, or it is in EXEMPT with a
        reason. A new NA kind fails until someone decides which, and that is the
        point — this map is a second registry, and two registries drifting is
        this codebase's most repeated bug.
        """
        mapped_kinds = {k for k, _ in api._NA_MUTE_EVENTS}
        undecided = sorted({kind for kind, _ in _emitted_pairs()
                            if kind not in mapped_kinds and kind not in EXEMPT})
        self.assertEqual(
            undecided, [],
            'These Needs-Attention kinds are neither muteable nor declared\n'
            'unmuteable. An item with no mute route permanently depresses its\n'
            "host's health score — and the fleet's, which is derived purely\n"
            'from NA items — with no operator recourse:\n'
            + '\n'.join(f'  {k}' for k in undecided))

    def test_severities_of_a_muteable_kind_are_all_covered(self):
        alertable = {k for k, v in api.EVENT_REGISTRY.items()
                     if isinstance(v, dict) and 'severity' in v}
        # Some items compute severity into a variable (service_down picks
        # critical vs warning from the unit state, log_alert from the rule), so
        # the source cannot tell us which literal severities they produce. For
        # those the honest requirement is that the KIND is represented in the
        # map at all — demanding a ('kind', '(dynamic)') key would only be
        # satisfiable by adding a row that matches nothing at runtime, which is
        # a test bending the product to fit its own limitation.
        mapped_kinds = {k for k, _ in api._NA_MUTE_EVENTS}
        missing = []
        for kind, sev in sorted(_emitted_pairs()):
            if kind in EXEMPT:
                continue
            if kind not in alertable:
                continue          # no same-named event to key a mute on
            if sev == '(dynamic)':
                if kind not in mapped_kinds:
                    missing.append((kind, 'any severity'))
            elif (kind, sev) not in api._NA_MUTE_EVENTS:
                missing.append((kind, sev))
        self.assertEqual(
            missing, [],
            'These Needs-Attention kinds have a per-device alertable event of\n'
            'the same name but no _NA_MUTE_EVENTS row, so muting the alert\n'
            'leaves the item standing and the health score never recovers:\n'
            + '\n'.join(f'  {k} / {s}' for k, s in missing))

    def test_every_mapped_event_exists(self):
        """The other direction: a row naming an event that no longer exists is a
        mute that can never match."""
        for key, events in api._NA_MUTE_EVENTS.items():
            for ev in events:
                self.assertIn(ev, api.EVENT_REGISTRY,
                              f'{key} maps to unknown event {ev!r}')

    def test_every_exemption_states_a_reason_and_is_still_emitted(self):
        emitted = {k for k, _ in _emitted_pairs()}
        for kind, why in EXEMPT.items():
            self.assertGreater(len(why), 25, f'{kind} exempt without a reason')
            self.assertIn(kind, emitted,
                          f'{kind} is exempt but the digest no longer emits it — '
                          'a stale exemption hides whatever takes its name next')


if __name__ == '__main__':
    unittest.main()
