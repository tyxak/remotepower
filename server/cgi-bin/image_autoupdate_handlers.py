"""RemotePower — automatic container image updates: the sweep and the two routes (8.0.0).

What the policy allows, and whether an update worked, is the pure image_autoupdate.py. This module carries it out: it reads the Image updates rows
and the hosts, queues `compose:update:<dir>` the way the Update button of the Image updates tab does, and later reads what the host reported to say
whether it worked.

It queues through `_queue_command_batch`, the helper a sweep may call (the autonomy loop does): it carries maintenance mode, quarantine, audit mode,
the agent's support for the verb and change approval, so a refusal here is the one a person would have got, and a change that needs a second admin is
parked as a confirmation and followed until it is decided. Nothing is updated unless its image is on the policy's list, the policy is off by default,
and shadow mode records what it would have done without queueing anything.

With the policy's `rollback` on (off by default), an update that was verified as unhealthy is followed by `compose:rollback:<dir>`, which the agent runs
from the note it made of the images the update replaced. That is queued through the same helper, so it needs the same approval, and it is followed and
verified the same way: rolled back, or a rollback that failed, which is an alert. Hosts whose agent does not say it can roll back are not updated at all
while the policy promises one.

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers / rack_ipam_handlers pattern: api.py execs a PRIVATE instance and binds its own
``globals()`` here, so every api service is reached as ``A.<name>``.
"""
import time
import uuid

import image_autoupdate as IA
import time_periods as time_periods_mod


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None

ACTOR = 'image-autoupdate'
CADENCE_S = 300                  # how often the sweep looks: a registry digest moves slowly, a verification wants a report from the host
_SKIPPED_CAP = 20                # what the last-run record keeps of the updates it held back


def bind(api_globals):
    """Called once by api.py right after importing this module, with api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ── state ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _policy(cfg=None):
    return IA.stored_policy((cfg if cfg is not None else A._config_ro()).get('image_autoupdate'))


def _receipts(store):
    block = (store or {}).get('autoupdate')
    rows = block.get('receipts') if isinstance(block, dict) else None
    return [r for r in rows or [] if isinstance(r, dict)]


def _period_state(policy, now):
    """(active, note). No period is always active. A period that no longer exists is never active: a window that cannot be read is not a window."""
    pid = policy.get('period')
    if not pid:
        return True, ''
    period = A._period_by_id(pid)
    if not period:
        return False, 'the time period no longer exists'
    return bool(time_periods_mod.is_active(period, now)), ''


def _online(now):
    ttl = A.get_online_ttl()
    return lambda dev: (now - int(dev.get('last_seen') or 0)) < ttl


def _queue(dev_id, command):
    """(state, detail, confirmation_id). `refused` means nothing was queued and nothing is recorded: the next sweep asks again."""
    try:
        res = (A._queue_command_batch([dev_id], command, ACTOR) or {}).get(dev_id) or {}
    except Exception as exc:                          # a guard that raises (maintenance mode answers by raising), not one that returns
        body = getattr(exc, 'body', None)
        reason = body.get('error') if isinstance(body, dict) else None
        return 'refused', 'refused: %s' % str(reason or type(exc).__name__)[:120], ''
    if res.get('approval_required'):
        return 'awaiting_approval', 'waiting for a second admin to approve it', str(res.get('confirmation_id') or '')
    if not res.get('ok'):
        return 'refused', 'refused: %s' % str(res.get('error') or 'unknown')[:120], ''
    return 'queued', '', ''


# ── the sweep ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_image_autoupdate_if_due():
    """Follow what was queued, then queue what the policy allows now. Cheap when nothing is configured and nothing is waiting."""
    ro = A._config_ro()
    policy = _policy(ro)
    waiting = any(r.get('state') in IA.WAITING for r in _receipts(A._load_ro(A.IMAGE_UPDATES_FILE)))
    if policy['mode'] not in ('shadow', 'on') and not waiting:
        return
    now = int(time.time())
    if now - int(ro.get('last_image_autoupdate') or 0) < CADENCE_S:
        return
    A._claim_cadence_slot('last_image_autoupdate', now)
    _follow(policy, now)
    if policy['mode'] in ('shadow', 'on'):
        _apply(policy, now)


def _start_rollback(r, why, policy, now, devices):
    """The receipt fields for an update that was verified as unhealthy under a policy that rolls back: the rollback queued, parked for a second
    admin, or the reason there is none. `why` is what was wrong with the update; it stays on the receipt, because `detail` moves on."""
    base = {'verified_at': now, 'unhealthy_detail': why}
    if not IA.can_roll_back(devices.get(r.get('device_id'))):
        return dict(base, state='rollback_failed', detail='%s; no rollback: the agent on this host cannot roll back an update' % why)
    state, detail, cid = _queue(r.get('device_id'), 'compose:rollback:' + str(r.get('dir')))
    if state == 'refused':
        return dict(base, state='rollback_failed', detail='%s; no rollback: %s' % (why, detail.replace('refused: ', '', 1)))
    if state == 'awaiting_approval':
        return dict(base, state='rollback_awaiting_approval', rollback_confirmation_id=cid, detail='%s; a rollback waits for a second admin' % why)
    return dict(base, state='rolling_back', rollback_queued_at=now, rollback_verify_at=now + policy['verify_after_min'] * 60,
                detail='%s; rolling back to the previous image' % why)


def _follow(policy, now):
    """Decide the parked changes, then read the host's report for each update or rollback that was queued. An update that was verified as unhealthy is
    rolled back when the policy says so."""
    store = A.load(A.IMAGE_UPDATES_FILE) or {}
    receipts = _receipts(store)
    if not any(r.get('state') in IA.WAITING for r in receipts):
        return
    A._invalidate_load_cache(A.CONFIRMATIONS_FILE)
    parked = {str(c.get('id')): c for c in ((A.load(A.CONFIRMATIONS_FILE) or {}).get('confirmations') or []) if isinstance(c, dict)}
    containers = A.load(A.CONTAINERS_FILE) or {}
    devices = A.load(A.DEVICES_FILE) or {}
    minutes = policy['verify_after_min'] * 60
    changes = {}                                     # receipt id -> fields to set
    for r in receipts:
        rid, state0 = r.get('id'), r.get('state')
        before = r.get('unhealthy_detail') or ''
        if state0 == 'awaiting_approval':
            status = (parked.get(str(r.get('confirmation_id'))) or {}).get('status')
            if status == 'approved':
                changes[rid] = {'state': 'queued', 'queued_at': now, 'verify_at': now + minutes, 'detail': ''}
            elif status in ('rejected', 'expired', 'failed') or status is None:
                changes[rid] = {'state': 'declined', 'detail': 'the approval request was %s' % (status or 'removed'), 'verified_at': now}
        elif state0 == 'queued':
            state, detail = IA.verify(r, containers.get(r.get('device_id')), now)
            if state == 'unhealthy' and policy.get('rollback'):
                changes[rid] = _start_rollback(r, detail, policy, now, devices)
            elif state != 'pending':
                changes[rid] = {'state': state, 'detail': detail, 'verified_at': now}
        elif state0 == 'rollback_awaiting_approval':
            status = (parked.get(str(r.get('rollback_confirmation_id'))) or {}).get('status')
            if status == 'approved':
                changes[rid] = {'state': 'rolling_back', 'rollback_queued_at': now, 'rollback_verify_at': now + minutes,
                                'detail': '%s; rolling back to the previous image' % before}
            elif status in ('rejected', 'expired', 'failed') or status is None:
                changes[rid] = {'state': 'rollback_failed', 'verified_at': now,
                                'detail': '%s; no rollback: the approval request was %s' % (before, status or 'removed')}
        elif state0 == 'rolling_back':
            state, detail = IA.verify_rollback(r, containers.get(r.get('device_id')), now)
            if state == 'ok':
                changes[rid] = {'state': 'rolled_back', 'verified_at': now, 'detail': '%s; rolled back to the previous image' % before}
            elif state in ('failed', 'unverified'):
                changes[rid] = {'state': 'rollback_failed', 'verified_at': now, 'detail': '%s; the rollback did not work: %s' % (before, detail)}
    if not changes:
        return
    with A._LockedUpdate(A.IMAGE_UPDATES_FILE) as st:
        for r in _receipts(st):
            if r.get('id') in changes:
                r.update(changes[r['id']])
    for r in receipts:
        ch = changes.get(r.get('id'))
        if not ch:
            continue
        old, new = r.get('state'), ch['state']
        who = 'host=%s dir=%s' % (r.get('device_id'), r.get('dir'))
        if new == 'rolled_back':                      # good news: in the audit trail and on the card, not an alert
            A.audit_log(ACTOR, 'image_autoupdate_rolled_back', '%s images=%s' % (who, ', '.join(str(x) for x in (r.get('refs') or []))[:300]))
            continue
        if new in ('rolling_back', 'rollback_awaiting_approval'):
            if old != 'queued':
                continue                              # a rollback that was approved: the alert was the failed update, a while ago
            A.audit_log(ACTOR, 'image_autoupdate_failed', '%s %s: %s' % (who, new, ch['detail']))
            A.audit_log(ACTOR, 'image_autoupdate_rollback_' + ('queued' if new == 'rolling_back' else 'awaiting_approval'), who)
        elif new in ('not_updated', 'unhealthy', 'unverified', 'rollback_failed'):
            A.audit_log(ACTOR, 'image_autoupdate_failed', '%s %s: %s' % (who, new, ch['detail']))
        else:
            continue
        A.fire_webhook('image_autoupdate_failed', {'name': r.get('device_name') or r.get('device_id'), 'device_id': r.get('device_id'),
                                                   'label': ', '.join(str(x) for x in (r.get('refs') or []))[:300], 'detail': ch['detail'] or new})


def _apply(policy, now):
    """Queue (or, in shadow mode, only record) the updates the policy allows now, at most `max_hosts_per_run` of them."""
    store = A.load(A.IMAGE_UPDATES_FILE) or {}
    devices = A.load(A.DEVICES_FILE) or {}
    containers = A.load(A.CONTAINERS_FILE) or {}
    active, _note = _period_state(policy, now)
    decisions = IA.plan(A._image_update_view(), devices, policy, _receipts(store), period_active=active, online=_online(now))
    todo = [d for d in decisions if d['action'] == 'queue'][:policy['max_hosts_per_run']]
    held = [{'device': d['device_name'], 'dir': d['dir'], 'refs': d['refs'], 'reason': d['reason']} for d in decisions if d['action'] == 'skip'][:_SKIPPED_CAP]
    made = []
    for d in todo:
        items = [c for c in ((containers.get(d['device_id']) or {}).get('items') or []) if isinstance(c, dict) and c.get('compose_dir') == d['dir']]
        receipt = {'id': uuid.uuid4().hex[:12], 'ts': now, 'device_id': d['device_id'], 'device_name': d['device_name'], 'dir': d['dir'], 'refs': d['refs'],
                   'digests': d['digests'], 'fingerprint': d['fingerprint'], 'command': 'compose:update:' + d['dir'], 'mode': policy['mode'],
                   'before': {c.get('name'): int(c.get('restart_count') or 0) for c in items if c.get('name')},
                   # the digest each updated image had on this host, so a rollback can be checked against what it should be back on
                   'previous': {'%s:%s' % (c.get('image') or '', c.get('tag') or 'latest'): str(c.get('repo_digest') or '') for c in items
                                if '%s:%s' % (c.get('image') or '', c.get('tag') or 'latest') in d['digests'] and c.get('repo_digest')},
                   'queued_at': 0, 'verify_at': 0, 'state': 'shadow', 'detail': 'shadow mode: nothing was queued', 'confirmation_id': ''}
        if policy['mode'] == 'on':
            state, detail, cid = _queue(d['device_id'], receipt['command'])
            if state == 'refused':
                held.append({'device': d['device_name'], 'dir': d['dir'], 'refs': d['refs'], 'reason': detail})
                continue
            receipt.update(state=state, detail=detail, confirmation_id=cid)
            if state == 'queued':
                receipt.update(queued_at=now, verify_at=now + policy['verify_after_min'] * 60)
            A.audit_log(ACTOR, 'image_autoupdate_' + state, 'host=%s dir=%s images=%s' % (d['device_id'], d['dir'], ', '.join(d['refs'])[:300]))
        made.append(receipt)
    with A._LockedUpdate(A.IMAGE_UPDATES_FILE) as st:
        block = st.get('autoupdate')
        if not isinstance(block, dict):
            block = st['autoupdate'] = {}
        rows = [r for r in block.get('receipts') or [] if isinstance(r, dict)]
        block['receipts'] = (rows + made)[-IA.MAX_RECEIPTS:]
        block['last_run'] = {'ts': now, 'mode': policy['mode'], 'made': len(made), 'held': held}


# ── routes ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def handle_image_autoupdate_get():
    """GET /api/image-updates/auto — the policy, the recent receipts, what the policy would do now, and the time periods to choose from."""
    A.require_auth()
    now = int(time.time())
    cfg = A._config_ro()
    policy = _policy(cfg)
    store = A.load(A.IMAGE_UPDATES_FILE) or {}
    visible = A._confined_host_ids()                  # None: no confinement; else the ids of the caller's own hosts
    seen = (lambda dev_id: True) if visible is None else (lambda dev_id: dev_id in visible)
    active, note = _period_state(policy, now)
    preview = []
    if policy['mode'] in ('shadow', 'on'):
        decisions = IA.plan(A._image_update_view(), A.load(A.DEVICES_FILE) or {}, policy, _receipts(store), period_active=active, online=_online(now))
        preview = [d for d in decisions if seen(d['device_id'])][:50]
    receipts = [r for r in reversed(_receipts(store)) if seen(r.get('device_id'))][:50]
    block = store.get('autoupdate') if isinstance(store.get('autoupdate'), dict) else {}
    last_run = block.get('last_run') if isinstance(block.get('last_run'), dict) else None
    if last_run and visible is not None:
        devices = A.load(A.DEVICES_FILE) or {}
        names = {(devices.get(i) or {}).get('name') for i in visible}
        last_run = dict(last_run, held=[h for h in last_run.get('held') or [] if isinstance(h, dict) and h.get('device') in names])
    periods = [{'id': p.get('id'), 'name': p.get('name') or p.get('id')} for p in (cfg.get('time_periods') or []) if isinstance(p, dict) and p.get('id')]
    A.respond(200, {'policy': policy, 'receipts': receipts, 'preview': preview, 'last_run': last_run, 'periods': periods,
                    'period_active': active, 'period_note': note, 'cadence_s': CADENCE_S})


def handle_image_autoupdate_set():
    """POST /api/image-updates/auto — save the policy. The platform operator's, because it decides what an unattended loop may do to every host.

    Turning on (or changing a policy that is on) asks for a fresh sign-in, as the settings that decide who can do what do."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.ImageAutoupdateRequest)
    A._require_platform_operator('Image auto-update')
    current = _policy()
    policy, err = IA.clean_policy(body, base=current, period_exists=lambda pid: bool(A._period_by_id(pid)))
    if err:
        A.respond(400, {'error': err})
    actor = A.require_step_up() if policy['mode'] == 'on' else A.require_admin_auth()
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['image_autoupdate'] = policy
    A.audit_log(actor, 'image_autoupdate_set', 'mode=%s include=%d exclude=%d period=%s max_hosts=%d verify_after_min=%d rollback=%s' % (
        policy['mode'], len(policy['include']), len(policy['exclude']), policy['period'] or '-', policy['max_hosts_per_run'], policy['verify_after_min'],
        'on' if policy['rollback'] else 'off'))
    A.respond(200, {'ok': True, 'policy': policy})
