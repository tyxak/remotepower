"""RemotePower — webhook delivery log + dead-letter queue (DLQ) + event replay:
view/clear the delivery log, list/retry/clear permanently-failed deliveries, and
re-fire a past fleet event through the normal webhook path.

A bound-module carve-out following the dmarc/acme/netappliance pattern: api.py
execs a PRIVATE instance, binds its own ``globals()`` here (every api service
reached as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching
working), then re-imports the names back so the route table resolves unchanged.
The WEBHOOK_LOG_FILE / WEBHOOK_DLQ_FILE / FLEET_EVENTS_FILE constants + the
_dlq_retry_entry / _redact_url_to_host helpers + fire_webhook stay in api.py,
read via A. (fire_webhook is self-locking + defers correctly; replay calls it
outside any lock, unchanged).
"""


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


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


def handle_webhook_log():
    """Return the webhook delivery log."""
    A.require_admin_auth()
    wl = A.load(A.WEBHOOK_LOG_FILE)
    # v2.2.2: tolerate both the canonical {entries: [...]} shape AND
    # a bare list (older deployments, or hand-edited files). Reading
    # both is cheap; deciding to upgrade the format on read isn't —
    # operators may have other tooling assuming the bare-list shape,
    # so we just normalise for the response and leave disk alone.
    if isinstance(wl, list):
        entries = wl
    elif isinstance(wl, dict):
        entries = wl.get('entries', []) or []
    else:
        entries = []
    A.respond(200, list(reversed(entries)))


def handle_webhook_log_clear():
    """Clear the webhook delivery log."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE': A.respond(405, {'error': 'Method not allowed'})
    A.save(A.WEBHOOK_LOG_FILE, {'entries': []})
    A.audit_log(actor, 'clear_webhook_log', 'webhook log cleared')
    A.respond(200, {'ok': True})


def handle_webhook_dlq_list():
    """v5.0.0 (#R2): ``GET /api/webhook/dlq`` — permanently-failed webhook
    deliveries (newest first). The secret-bearing dest fields are scrubbed."""
    A.require_admin_auth()
    entries = (A.load(A.WEBHOOK_DLQ_FILE) or {}).get('entries', []) or []
    out = []
    for e in reversed(entries):
        d = dict(e)
        d.pop('dest', None)          # may carry tokens/keys — never echo it
        # The convenience top-level `url` embeds the secret for Slack/Discord/
        # Teams (token in the path) — same secret-bearing-URL-in-GET class as
        # the webhook_url→webhook_configured fix. Show host only, never the path.
        if d.get('url'):
            d['url'] = A._redact_url_to_host(d['url'])
        out.append(d)
    A.respond(200, out)


def handle_webhook_dlq_retry():
    """``POST /api/webhook/dlq/retry`` — re-dispatch one entry ({"id": "..."}) or
    all ({"all": true}). Successes are removed from the queue; failures stay with
    their attempt count bumped."""
    actor = A.require_admin_auth()
    if A.method() != 'POST': A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.WebhookDlqRetryRequest)
    want_all = bool(body.get('all'))
    one_id = str(body.get('id', '')).strip()
    if not want_all and not one_id:
        A.respond(400, {'error': 'pass {"id": ...} or {"all": true}'})
    entries = (A.load(A.WEBHOOK_DLQ_FILE) or {}).get('entries', []) or []
    targets = entries if want_all else [e for e in entries if e.get('id') == one_id]
    if not targets:
        A.respond(404, {'error': 'no matching dead-letter entry'})
    retried = succeeded = 0
    survived_ids = set()
    for e in targets:
        retried += 1
        if A._dlq_retry_entry(e):
            succeeded += 1
        else:
            survived_ids.add(e.get('id'))
    # Rebuild the queue under the lock against a FRESH load: drop the ones that
    # retried OK, and bump `attempts` on the survivors here (mutating the copies
    # we read above would be lost — the lock re-reads from disk).
    retried_ids = {e.get('id') for e in targets} - survived_ids
    with A._LockedUpdate(A.WEBHOOK_DLQ_FILE) as dlq:
        kept = []
        for e in (dlq.get('entries', []) or []):
            if e.get('id') in retried_ids:
                continue
            if e.get('id') in survived_ids:
                e['attempts'] = int(e.get('attempts', 1)) + 1
            kept.append(e)
        dlq['entries'] = kept
    A.audit_log(actor, 'webhook_dlq_retry',
                detail=f'retried={retried} ok={succeeded} all={want_all}')
    A.respond(200, {'ok': True, 'retried': retried, 'succeeded': succeeded,
                    'remaining': retried - succeeded})


def handle_webhook_dlq_clear():
    """``DELETE /api/webhook/dlq`` — empty the dead-letter queue."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE': A.respond(405, {'error': 'Method not allowed'})
    A.save(A.WEBHOOK_DLQ_FILE, {'entries': []})
    A.audit_log(actor, 'webhook_dlq_clear', 'webhook dead-letter queue cleared')
    A.respond(200, {'ok': True})


def handle_webhook_replay():
    """v5.0.0 (#R2): ``POST /api/webhook/replay`` {ts, event} — re-fire a past
    fleet event through the normal webhook path (filters + suppression apply, so
    it routes exactly as a fresh event would)."""
    actor = A.require_admin_auth()
    if A.method() != 'POST': A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.WebhookReplayRequest)
    ev = str(body.get('event', '')).strip()
    try:
        ts = int(body.get('ts', 0))
    except (TypeError, ValueError):
        ts = 0
    if not ev or not ts:
        A.respond(400, {'error': 'pass {"event": ..., "ts": ...} from the activity feed'})
    events = (A.load(A.FLEET_EVENTS_FILE) or {}).get('events', []) or []
    match = next((e for e in events
                  if e.get('event') == ev and int(e.get('ts', 0)) == ts), None)
    if not match:
        A.respond(404, {'error': 'no matching fleet event to replay'})
    payload = dict(match.get('payload') or {})
    payload['_replay'] = True
    A.fire_webhook(ev, payload)
    A.audit_log(actor, 'webhook_replay', detail=f'event={ev} ts={ts}')
    A.respond(200, {'ok': True, 'event': ev, 'ts': ts})
