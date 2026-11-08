// app-webhook-replay.js — send a past event through the notification channels again (8.0.0). Buildless classic script, fetched by the click dispatcher the first time the button is used.
//
// POST /api/webhook/replay {event, ts} has existed since 5.0.0: it re-fires an event of the activity feed through the normal webhook path, so the same channels, filters and mutes apply, and
// the people on those channels are told again. Nothing in the page called it. The Timeline has a button on each row that is a fleet event, for the platform operator (the server refuses a
// tenant's administrator, since the route reaches every tenant's events), and it asks first, because the other end is a person who will be notified.

async function timelineReplay(event, ts) {
  if (!event || !ts) return;
  const ok = await uiConfirm({
    title: 'Replay this event',
    message: 'It is sent again as a new event is: the same channels, filters and mutes apply, and the people on those channels are told again.',
    confirmText: 'Replay',
  });
  if (!ok) return;
  const r = await api('POST', '/webhook/replay', {event, ts}).catch(() => null);
  if (!r || r.error || r.ok === false) { failToast(r); return; }   // api() has already said why when the server answered; this is for a request that never did
  toast('Event replayed', 'success');
}
