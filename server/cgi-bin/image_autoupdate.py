#!/usr/bin/env python3
"""Automatic container image updates (8.0.0): what the policy says, which updates it allows now, and whether one worked.

Pure: no storage, no clock, no request. image_autoupdate_handlers.py hands it the Image updates rows, the hosts, the saved receipts and the time,
and carries out what it decides.

An update here is the one the Update button of the Image updates tab queues: `compose:update:<dir>` on a host whose containers carry a compose
project directory, which pulls every image of that project and recreates what changed. That is why the unit is a PROJECT on a HOST, not an
image: an image on the list cannot be updated alone, and a project that also holds a stale image that is not on the list is left alone.

The policy is an allow-list. Nothing is updated unless its image reference (image:tag) matches an `include` pattern and no `exclude` pattern.
The mode is off, shadow (a receipt records what it would have done and nothing is queued) or on.

Stdlib only.
"""
import fnmatch
import hashlib
import re

MODES = ('off', 'shadow', 'on')
DEFAULT_POLICY = {'mode': 'off', 'include': [], 'exclude': [], 'period': '', 'max_hosts_per_run': 2, 'verify_after_min': 10}
MAX_PATTERNS = 50
MAX_PATTERN_LEN = 200
MAX_RECEIPTS = 200
VERIFY_GRACE_S = 1800            # after the time to look, how long to wait for a report from the host or for a health check to settle
RESTART_LOOP = 2                 # a container that restarted this often since the update is not healthy

# An image reference as a pattern: the characters of a reference, and the two glob characters. Lower case, because references compare so.
_PATTERN = re.compile(r'^[a-z0-9*?][a-z0-9._/:@*?-]*$')
_RUNNING = ('running', 'up ', 'up\t', 'ready')
_STOPPED = ('exited', 'stopped', 'dead', 'terminated')


def _patterns(value, what):
    """A list of patterns from a list or from text (one per line or comma-separated). Returns (list, error)."""
    if value is None:
        return [], None
    if isinstance(value, str):
        value = re.split(r'[\n,]+', value)
    if not isinstance(value, list):
        return None, '%s must be a list of image patterns' % what
    out = []
    for item in value:
        if not isinstance(item, str):
            return None, '%s must be a list of image patterns' % what
        p = item.strip().lower()
        if not p:
            continue
        if len(p) > MAX_PATTERN_LEN or not _PATTERN.match(p):
            return None, '%s: "%s" is not an image pattern (letters, digits, . _ / : @ - and the wildcards * and ?)' % (what, item.strip()[:60])
        if p not in out:
            out.append(p)
    if len(out) > MAX_PATTERNS:
        return None, '%s may hold at most %d patterns' % (what, MAX_PATTERNS)
    return out, None


def clean_policy(raw, base=None, period_exists=None):
    """The policy a request asks for, as it will be stored. Returns (policy, error). Keys that are not sent keep their value in `base`."""
    policy = dict(DEFAULT_POLICY, **(base or {}))
    if not isinstance(raw, dict):
        return None, 'the policy must be an object'
    if 'mode' in raw:
        mode = str(raw['mode']).strip().lower()
        if mode not in MODES:
            return None, 'mode must be off, shadow or on'
        policy['mode'] = mode
    for key in ('include', 'exclude'):
        if key in raw:
            value, err = _patterns(raw[key], key)
            if err:
                return None, err
            policy[key] = value
    if 'period' in raw:
        period = str(raw['period'] or '').strip()
        if len(period) > 64:
            return None, 'period is not a time period'
        if period and period_exists is not None and not period_exists(period):
            return None, 'period is not a time period'
        policy['period'] = period
    for key, lo, hi in (('max_hosts_per_run', 1, 10), ('verify_after_min', 5, 120)):
        if key in raw:
            v = raw[key]
            try:
                if isinstance(v, bool):
                    raise TypeError
                n = int(v)
            except (TypeError, ValueError, OverflowError):
                return None, '%s must be a whole number from %d to %d' % (key, lo, hi)
            if not lo <= n <= hi:
                return None, '%s must be a whole number from %d to %d' % (key, lo, hi)
            policy[key] = n
    if policy['mode'] == 'on' and not policy['include']:
        return None, 'on needs at least one image pattern in include: nothing is updated that is not on the list'
    return policy, None


def stored_policy(raw):
    """The policy as saved, read defensively. A value that is wrong in the stored document (a hand edit, a restore) is read as the default for that
    key alone, and a mode of on without a list reads as off: the loop never acts on a half-understood policy."""
    policy = dict(DEFAULT_POLICY)
    if not isinstance(raw, dict):
        return policy
    for key in ('include', 'exclude', 'period', 'max_hosts_per_run', 'verify_after_min'):
        if key in raw:
            one, err = clean_policy({key: raw[key]}, base=policy)
            if one is not None and err is None:
                policy = one
    mode = str(raw.get('mode', 'off')).strip().lower()
    if mode == 'shadow' or (mode == 'on' and policy['include']):
        policy['mode'] = mode
    return policy


def match(ref, patterns):
    low = str(ref or '').lower()
    return any(fnmatch.fnmatchcase(low, p) for p in patterns or [])


def fingerprint(refs_digests):
    """One short id for a set of images at the registry digests they were updated to, so an update is attempted once per release."""
    text = '|'.join('%s@%s' % (r, refs_digests[r]) for r in sorted(refs_digests))
    return hashlib.sha1(text.encode('utf-8')).hexdigest()[:16]


def _stale(local, registry):
    local, registry = str(local or '').strip(), str(registry or '').strip()
    return bool(registry and local and local != registry)


def plan(rows, devices, policy, receipts, period_active=True, online=None):
    """Which project updates the policy allows now, and why the others are held back.

    rows: the Image updates rows. devices: id -> host record. receipts: the saved receipts. Returns one decision per project on a host that has a
    stale image: {device_id, device_name, dir, refs, digests, containers, fingerprint, action: 'queue' | 'skip', reason}. A project that already has
    a receipt for the same images at the same digests is not listed at all: the receipt is its record.
    """
    if policy.get('mode') not in ('shadow', 'on'):
        return []
    include, exclude = policy.get('include') or [], policy.get('exclude') or []
    groups = {}
    for row in rows or []:
        if not isinstance(row, dict) or not row.get('update_available') or row.get('ignored') or row.get('local'):
            continue
        ref, digest = str(row.get('ref') or ''), str(row.get('registry_digest') or '')
        for h in row.get('hosts') or []:
            if not isinstance(h, dict) or not h.get('stale') or not h.get('compose_dir'):
                continue
            g = groups.setdefault((h.get('device_id'), h.get('compose_dir')), {'device_id': h.get('device_id'), 'device_name': h.get('device_name') or h.get('device_id'),
                                                                                'dir': h.get('compose_dir'), 'digests': {}, 'containers': []})
            g['digests'][ref] = digest
            if h.get('container') and h['container'] not in g['containers']:
                g['containers'].append(h['container'])
    seen = {(r.get('device_id'), r.get('dir'), r.get('fingerprint')) for r in receipts or [] if isinstance(r, dict)}
    out = []
    for key in sorted(groups, key=lambda k: (str(groups[k]['device_name']).lower(), str(k[1]))):
        g = groups[key]
        fp = fingerprint(g['digests'])
        if (g['device_id'], g['dir'], fp) in seen:
            continue
        refs = sorted(g['digests'])
        d = {'device_id': g['device_id'], 'device_name': g['device_name'], 'dir': g['dir'], 'refs': refs, 'digests': dict(g['digests']),
             'containers': sorted(g['containers']), 'fingerprint': fp, 'action': 'skip', 'reason': ''}
        dev = (devices or {}).get(g['device_id']) or {}
        blocked = next((r for r in refs if match(r, exclude)), None)
        unlisted = next((r for r in refs if not match(r, include)), None)
        if dev.get('agentless'):
            d['reason'] = 'agentless host'
        elif blocked:
            d['reason'] = 'excluded: %s' % blocked
        elif unlisted:
            d['reason'] = 'not on the list: %s' % unlisted
        elif not period_active:
            d['reason'] = 'outside the time period'
        elif online is not None and not online(dev):
            d['reason'] = 'host offline'
        else:
            d['action'] = 'queue'
        out.append(d)
    return out


def verify(receipt, rec, now):
    """Whether an update that was queued worked, from what the host reported since. Returns (state, detail).

    state is 'pending' (look again later), 'ok', 'not_updated' (a container still runs the old image after the host reported), 'unhealthy' (it runs
    the new image and is stopped, failing its health check or restarting in a loop) or 'unverified' (no usable report in the grace period).
    """
    if now < int(receipt.get('verify_at') or 0):
        return 'pending', ''
    late = now >= int(receipt.get('verify_at') or 0) + VERIFY_GRACE_S
    rec = rec if isinstance(rec, dict) else {}
    if int(rec.get('reported_at') or 0) <= int(receipt.get('queued_at') or 0):
        return ('unverified', 'the host reported nothing after the update was queued') if late else ('pending', '')
    digests = receipt.get('digests') or {}
    before = receipt.get('before') or {}
    mine = []
    for c in rec.get('items') or []:
        if not isinstance(c, dict) or c.get('compose_dir') != receipt.get('dir'):
            continue
        ref = '%s:%s' % (c.get('image') or '', c.get('tag') or 'latest')
        if ref in digests:
            mine.append((c, ref))
    if not mine:
        return ('unverified', 'none of the updated containers was in the next report') if late else ('pending', '')
    for c, ref in mine:
        if _stale(c.get('repo_digest'), digests[ref]):
            return 'not_updated', '%s still runs the old image of %s' % (c.get('name'), ref)
    settling = False
    for c, ref in mine:
        status = str(c.get('status') or '').lower()
        health = str(c.get('health') or '').lower()
        if any(t in status for t in _STOPPED) or not any(t in status for t in _RUNNING):
            return 'unhealthy', '%s is not running (%s)' % (c.get('name'), c.get('status') or 'no status')
        if health == 'unhealthy':
            return 'unhealthy', '%s is failing its health check' % c.get('name')
        if int(c.get('restart_count') or 0) - int(before.get(c.get('name'), 0) or 0) >= RESTART_LOOP:
            return 'unhealthy', '%s keeps restarting' % c.get('name')
        if health == 'starting':
            settling = True
    if settling:
        return ('unhealthy', 'a health check never settled') if late else ('pending', '')
    return 'ok', ''
