#!/usr/bin/env python3
"""Autonomous remediation — the decision core. PURE logic, no api import.

This is the highest-stakes code in the product: everything it approves ends up
executing a command on somebody's production host. So the safety here is
MECHANICAL, not advisory — the caller cannot act unless `decide()` returns a
verdict of ACT, and `decide()` is a total function over an explicit policy.

Three properties this module exists to guarantee, each covered by a test that is
demonstrated to fail before it is trusted:

1. **Default deny.** An action class that is not in the policy's allow-list, or
   a mode that is not recognised, refuses. Adding a new action class does not
   silently enable it anywhere.
2. **Shadow cannot act.** In `shadow` mode `decide()` can only ever return
   SHADOW or REFUSE. There is no code path from shadow to ACT — not a flag that
   happens to be false, an early return keyed on the mode itself. That is what
   makes "run it for a quarter and grade it" a safe thing to tell an operator.
3. **Every refusal is machine-readable.** A verdict carries a `reason` code from
   a closed set, so the receipt ledger can be aggregated ("blocked 41 times for
   blast_radius") rather than being a pile of prose nobody reads.

WHY A SEPARATE PURE MODULE. The api.py handler layer is where request context,
storage and side effects live; mixing this logic in there would make the
interesting cases (no precedent, stale backup, cross-tenant device, blast radius
at exactly the threshold) reachable only through a booted stack. Here they are
plain function calls, so the tests can enumerate them.
"""

# ── verdicts ────────────────────────────────────────────────────────────────
ACT = 'act'            # execute now, through the signed/audited command path
ESCALATE = 'escalate'  # a human must approve first (four-eyes)
SHADOW = 'shadow'      # record what we WOULD do; touch nothing
REFUSE = 'refuse'      # do not act, and do not pretend we would

VERDICTS = (ACT, ESCALATE, SHADOW, REFUSE)

# Closed set of refusal reasons. A new reason must be added here, which is the
# point: it forces the UI and the aggregates to learn about it.
REASONS = (
    'module_off',            # the whole subsystem is disabled
    'mode_off',              # autonomy off for this tenant/action class
    'unknown_action',        # action class not recognised — default deny
    'action_not_allowed',    # recognised, but not in the policy allow-list
    'no_precedent',          # nothing in incident memory and no plan supplied
    'low_confidence',        # precedent exists but is too weak to act on
    'blast_radius',          # impact exceeds the policy threshold
    'no_verified_backup',    # destructive, and recovery is not proven
    'outside_window',        # outside the permitted maintenance window
    'tenant_mismatch',       # the device is not in the acting tenant
    'dry_run_failed',        # the simulation did not come back clean
    'rate_limited',          # too many actions in the window
    'needs_approval',        # policy demands a human for this class
    # v7.0.0: three refusals that exist because the alternative is a command
    # the target silently drops, or a malformed one it rejects — both of which
    # look like success from the server's side.
    'unsupported_platform',  # this action's verb is not implemented on that OS
    'missing_parameter',     # the alert does not say WHICH unit/container/pool
    'no_command_template',   # recognised action, nothing in this build runs it
    'ok',                    # no refusal — used on ACT/SHADOW verdicts
)

# ── action classes ──────────────────────────────────────────────────────────
# `destructive` means: it can lose state or take the host away. Those require a
# PROVEN-recoverable backup (a restore drill that actually restored and
# verified), not merely a backup that ran.
#
# `platforms` is the OS families whose AGENT can actually carry the action out.
# It is not decoration: the command channel implements a different subset of
# verbs per platform (`svc:` is Linux and Windows, `ps:` is Windows only), and
# an agent handed a verb it does not know returns success and does nothing.
# `tests/test_v700_action_catalog.py` derives the same matrix from api.py's
# `_VERB_OS_SUPPORT` and fails when this column and the command templates
# disagree — the two are edited in different files, which is exactly how they
# would otherwise drift apart.
#
# `label` is prose for the allow-list UI. The machine name is what the receipt
# and the policy carry; the label is only there so an operator ticking boxes
# does not have to infer what `clear_tmp` reaches for.
ACTION_CLASSES = {
    # ── service and container lifecycle ─────────────────────────────────────
    'restart_service':     {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux', 'windows'),
                            'label': 'Restart a failed or flapping service'},
    'start_service':       {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux', 'windows'),
                            'label': 'Start a service that has stopped'},
    'restart_timer':       {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Restart a failed systemd timer'},
    'restart_container':   {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux', 'windows'),
                            'label': 'Restart a container'},
    'start_container':     {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux', 'windows'),
                            'label': 'Start a stopped container'},

    # ── reclaiming disk, which is the most common recurring toil ────────────
    'clear_journal':       {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Vacuum the systemd journal to 3 days'},
    'rotate_logs':         {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Force a log rotation'},
    'clear_tmp':           {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Clean expired files from temporary directories'},
    'clear_package_cache': {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Clear the package manager cache'},
    'prune_container_images': {'destructive': False, 'default_allowed': False,
                               'platforms': ('linux',),
                               'label': 'Remove unused container images'},
    'trim_filesystem':     {'destructive': False, 'default_allowed': False,
                            'platforms': ('linux',),
                            'label': 'Discard unused blocks (fstrim)'},
    'clear_cache':         {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Drop reclaimable page cache'},

    # ── host services that fix themselves with a nudge ──────────────────────
    'resync_clock':        {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Re-synchronise the system clock'},
    'restart_resolver':    {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Restart the DNS resolver'},
    'flush_mail_queue':    {'destructive': False, 'default_allowed': True,
                            'platforms': ('linux',),
                            'label': 'Flush the outbound mail queue'},
    'update_av_definitions': {'destructive': False, 'default_allowed': True,
                              'platforms': ('linux', 'windows'),
                              'label': 'Update anti-virus definitions'},
    'start_scrub':         {'destructive': False, 'default_allowed': False,
                            'platforms': ('linux',),
                            'label': 'Start an overdue storage scrub'},

    # ── destructive: can lose state, or take the host away ──────────────────
    'kill_process':        {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux',),
                            'label': 'Terminate a runaway process'},
    'remount_rw':          {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux',),
                            'label': 'Remount a read-only filesystem read-write'},
    'restart_networking':  {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux',),
                            'label': 'Restart host networking'},
    'enable_firewall':     {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux', 'windows', 'darwin'),
                            'label': 'Turn the host firewall back on'},
    'reboot':              {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux', 'windows', 'darwin'),
                            'label': 'Reboot the host'},
    'patch':               {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux', 'windows', 'darwin'),
                            'label': 'Install pending updates'},
    'rotate_credential':   {'destructive': True,  'default_allowed': False,
                            'platforms': ('linux', 'windows', 'darwin'),
                            'label': 'Rotate an exposed or stale credential'},
}

MODES = ('off', 'shadow', 'enabled')

# Precedent below this success rate is not something to act on unattended.
MIN_PRECEDENT_CONFIDENCE = 0.7
MIN_PRECEDENT_SAMPLES = 2


class Decision(dict):
    """A verdict plus everything needed to explain it later.

    A dict subclass rather than a dataclass so it serialises into the receipt
    ledger and the API response with no adapter, and so a stored receipt from an
    older version still loads.
    """

    @property
    def verdict(self):
        return self.get('verdict')

    @property
    def acted(self):
        return self.get('verdict') == ACT


def _decision(verdict, reason, **extra):
    # NOT an assert. `python -O` strips asserts, and these two lines are the
    # only thing that keeps an unrecognised verdict or an undeclared reason out
    # of a receipt — in the module whose whole job is to be the mechanical gate
    # on executing commands against production hosts. A validation that a
    # command-line flag can remove is not a validation. (bandit B101 flagged
    # exactly this; it is not a false positive here.)
    if verdict not in VERDICTS:
        raise ValueError(f'unknown verdict {verdict!r} (expected one of {VERDICTS})')
    if reason not in REASONS:
        raise ValueError(
            f'undeclared reason {reason!r}. Add it to REASONS — the closed set '
            f'is what lets the receipts page aggregate refusals instead of '
            f'showing a pile of prose.')
    d = Decision(verdict=verdict, reason=reason)
    d.update(extra)
    return d


def default_policy():
    """The shipped default: the subsystem does nothing.

    Not `shadow` — OFF. An operator opts in to shadow, grades it, and only then
    opts in to acting. A default of shadow would start writing receipts about a
    fleet whose owner never asked, which is a smaller version of the same
    presumption.
    """
    return {
        'mode': 'off',
        'allowed_actions': [k for k, v in ACTION_CLASSES.items()
                            if v['default_allowed']],
        'max_blast_radius': 1,        # only a host nothing else depends on
        'require_verified_backup': True,
        'require_window': True,
        'max_actions_per_hour': 3,
        'approval_for_destructive': True,
    }


def normalize_policy(raw):
    """Merge a stored policy over the defaults, dropping anything unrecognised.

    Unknown action classes are DISCARDED rather than carried through: a policy
    written by a newer version, or by hand, must not be able to smuggle in an
    action this build has no safety analysis for.
    """
    p = default_policy()
    if isinstance(raw, dict):
        mode = raw.get('mode')
        if mode in MODES:
            p['mode'] = mode
        acts = raw.get('allowed_actions')
        if isinstance(acts, list):
            p['allowed_actions'] = [a for a in acts if a in ACTION_CLASSES]
        for key, cast in (('max_blast_radius', int), ('max_actions_per_hour', int)):
            try:
                if raw.get(key) is not None:
                    p[key] = max(0, cast(raw[key]))
            except (TypeError, ValueError):
                pass
        for key in ('require_verified_backup', 'require_window',
                    'approval_for_destructive'):
            if key in raw:
                p[key] = bool(raw[key])
    return p


def precedent_confidence(similar):
    """Turn prior incident outcomes into (confidence, sample_count, summary).

    Confidence is the share of prior incidents with this signature that a human
    or the advisor marked as actually resolved, weighted so an OPERATOR-confirmed
    outcome counts double an AI-authored one. The distinction matters: an AI
    verdict that was never contradicted is weaker evidence than a human writing
    "restarting nginx fixed it".

    Deliberately NOT a model call. The whole argument for acting is that this
    exact thing was fixed this exact way before, on this fleet.
    """
    if not similar:
        return 0.0, 0, ''
    total = 0.0
    good = 0.0
    action = None
    counts = {}
    for o in similar:
        if not isinstance(o, dict):
            continue
        w = 2.0 if o.get('source') == 'operator' else 1.0
        total += w
        res = str(o.get('resolution') or '').strip()
        if res and str(o.get('recommended_action') or '').strip():
            good += w
            key = str(o.get('recommended_action'))[:200]
            counts[key] = counts.get(key, 0) + w
    if total <= 0:
        return 0.0, 0, ''
    if counts:
        action = max(counts.items(), key=lambda kv: kv[1])[0]
    return (good / total), len(similar), (action or '')


def blast_radius(device_id, *, monitors=(), containers=(), status_services=(),
                 peers=(), redundancy_group=None, group_size=1):
    """How much goes dark if we act on this host.

    A count plus its components, so a refusal can say WHAT the impact was rather
    than only that it was too big. Redundancy discounts the score: taking one of
    three replicas is not the same as taking the only one, and a policy that
    could not tell them apart would either block everything or nothing.
    """
    m = len([x for x in monitors if x])
    c = len([x for x in containers if x])
    s = len([x for x in status_services if x])
    p = len([x for x in peers if x])
    raw = m + c + s + p
    redundant = bool(redundancy_group) and int(group_size or 1) > 1
    score = raw
    if redundant:
        # One of N healthy peers: the impact is real but bounded.
        score = max(1, int(round(raw / float(group_size))))
    return {
        'device_id': device_id,
        'score': score,
        'raw': raw,
        'monitors': m,
        'containers': c,
        'status_services': s,
        'peers': p,
        'redundant': redundant,
        'group_size': int(group_size or 1),
    }


def decide(*, action, policy, module_enabled, tenant_ok, radius,
           precedent_conf=0.0, precedent_samples=0, backup_verified=False,
           in_window=True, actions_this_hour=0, dry_run_ok=True,
           has_plan=False, os_family=None, plan_problem=None):
    """The whole safety envelope, as one total function.

    Order is deliberate: the cheapest and most absolute refusals come first, so a
    receipt for a disabled module never contains a blast-radius computation that
    would imply we looked at the fleet. Shadow is evaluated LAST among the
    "would we act" checks and short-circuits before any ACT can be returned —
    see property 2 in the module docstring.
    """
    if not module_enabled:
        return _decision(REFUSE, 'module_off')

    mode = policy.get('mode')
    if mode not in MODES or mode == 'off':
        return _decision(REFUSE, 'mode_off')

    if action not in ACTION_CLASSES:
        return _decision(REFUSE, 'unknown_action', action=action)

    if action not in (policy.get('allowed_actions') or []):
        return _decision(REFUSE, 'action_not_allowed', action=action)

    if not tenant_ok:
        return _decision(REFUSE, 'tenant_mismatch')

    spec = ACTION_CLASSES[action]

    # Can this host's agent even do it? A verb the agent does not implement
    # comes back as success having done nothing, so "we tried" would be a
    # fiction in the receipt. Refuse, and name the platform.
    plats = spec.get('platforms')
    if plats and os_family and os_family not in plats:
        return _decision(REFUSE, 'unsupported_platform', action=action,
                         os_family=os_family, supported=list(plats))

    # Could a concrete command be built at all? The caller resolves the alert's
    # payload into the template's parameters; when it cannot — the alert says a
    # service failed but not WHICH one — there is nothing honest to run.
    if plan_problem:
        return _decision(REFUSE, plan_problem, action=action)

    # Evidence: either this fleet has fixed this before, or a plan was drafted.
    if precedent_samples < MIN_PRECEDENT_SAMPLES and not has_plan:
        return _decision(REFUSE, 'no_precedent',
                         precedent_samples=precedent_samples)
    if precedent_samples >= MIN_PRECEDENT_SAMPLES and \
            precedent_conf < MIN_PRECEDENT_CONFIDENCE:
        return _decision(REFUSE, 'low_confidence',
                         precedent_confidence=round(precedent_conf, 3))

    max_radius = int(policy.get('max_blast_radius', 0))
    if int(radius.get('score', 0)) > max_radius:
        return _decision(REFUSE, 'blast_radius',
                         blast_radius=radius, limit=max_radius)

    if spec['destructive'] and policy.get('require_verified_backup') \
            and not backup_verified:
        return _decision(REFUSE, 'no_verified_backup', action=action)

    if policy.get('require_window') and not in_window:
        return _decision(REFUSE, 'outside_window')

    if int(actions_this_hour) >= int(policy.get('max_actions_per_hour', 0)):
        return _decision(REFUSE, 'rate_limited',
                         actions_this_hour=int(actions_this_hour))

    if not dry_run_ok:
        return _decision(REFUSE, 'dry_run_failed')

    # Everything a real action would have had to satisfy has now been satisfied.
    # In shadow mode we stop HERE — the receipt records a full, honest "this is
    # what would have happened", which is the entire value of shadow mode, and
    # there is no branch below that could reach ACT.
    if mode == 'shadow':
        return _decision(SHADOW, 'ok', action=action, blast_radius=radius,
                         precedent_confidence=round(precedent_conf, 3),
                         precedent_samples=precedent_samples)

    if spec['destructive'] and policy.get('approval_for_destructive'):
        return _decision(ESCALATE, 'needs_approval', action=action,
                         blast_radius=radius)

    return _decision(ACT, 'ok', action=action, blast_radius=radius,
                     precedent_confidence=round(precedent_conf, 3),
                     precedent_samples=precedent_samples)


def verification_failed(before, after):
    """Did the action make things worse, judged by the host's OWN checks?

    `before`/`after` are the check-status counts from the per-host checks engine.
    The rule is deliberately blunt: any increase in failing checks is a
    regression and triggers rollback. A model's opinion of whether it worked is
    not consulted — the checks engine already decides what "healthy" means for
    this host, and reusing it means autonomy cannot invent its own definition of
    success.
    """
    b = int((before or {}).get('failing', 0))
    a = int((after or {}).get('failing', 0))
    return a > b


def receipt(plan, decision, *, outcome=None, verified=None, rolled_back=False):
    """The artifact an operator, an auditor or a client actually reads.

    Deliberately self-contained: it carries the precedent and the blast radius
    that justified the decision, not a pointer to them, because the alert may be
    pruned and the fleet will have changed by the time anyone asks.
    """
    return {
        'ts': plan.get('ts'),
        'tenant': plan.get('tenant'),
        'device_id': plan.get('device_id'),
        'device_name': plan.get('device_name'),
        'trigger': plan.get('trigger'),
        'action': plan.get('action'),
        'command': plan.get('command'),
        'verdict': decision.get('verdict'),
        'reason': decision.get('reason'),
        'blast_radius': decision.get('blast_radius') or plan.get('blast_radius'),
        'precedent': {
            'confidence': decision.get('precedent_confidence'),
            'samples': decision.get('precedent_samples'),
            'action': plan.get('precedent_action'),
        },
        'dry_run': plan.get('dry_run'),
        'outcome': outcome,
        'verified': verified,
        'rolled_back': bool(rolled_back),
    }
