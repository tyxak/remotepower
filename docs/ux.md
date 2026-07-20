# Working the interface

The v6.3.0 "Fl0wMatters" release turned a long list of small UI frictions
into one coherent set of interface behaviours. This guide collects them in
one place — everything here applies across the whole app unless noted.
Keyboard specifics live in [keyboard-shortcuts.md](keyboard-shortcuts.md).

## Undo instead of "are you sure?"

Low-risk deletes (contacts, links, command-library snippets, saved device
views) no longer interrupt with a confirmation dialog. The row disappears
immediately and the toast offers **Undo** for a few seconds. The delete is
*deferred*: the API call only fires when the toast expires, and Undo cancels
it outright — so an interrupted delete always fails toward "still there",
never silent loss. Closing the tab flushes pending deletes first.

Destructive fan-out operations (device removal, Docker prune, VM rollback,
alert purges) deliberately keep their explicit — sometimes typed —
confirmations. Undo is for the deletes you do ten times a day.

- **Topbar undo/redo arrows** (and `Ctrl/Cmd-Z`, `Ctrl-Shift-Z` outside form
  fields) drive a global undo stack. Everything undoable registers there as
  well as in its toast: deferred deletes, alert acknowledge, dashboard
  layout changes (including a full reset).
- **Right-click the undo arrow** for the history dropdown — undo several
  steps at once.
- **Alert actions are optimistic**: acknowledging (`a` in the inbox) flips
  the row instantly with a real server-side un-acknowledge behind Undo;
  Resolve flips optimistically and reverts with an error toast if the
  server declines.

## The notification center

The topbar bell replays the last 30 toasts of your session with timestamps,
so a missed "Failed" or "Saved" is recoverable. An unread dot appears when
something fired while the popover was closed. Session-only by design —
alerts and the audit log are the durable records. Pure form-validation nags
("Subject required") are deliberately excluded: they're feedback about a
field you were looking at, not events.

## Drafts that survive

The script editor and the KB editor autosave every keystroke to your
browser, keyed per object. Reopening with a differing draft offers
**Restore draft**; a successful save clears it. Losing a half-written
runbook to a mis-click is no longer possible.

## Configuration history and rollback

**Settings → Advanced → Configuration history** keeps the last 10 saved
configuration states (timestamp, who, which keys changed). Restore swaps
the live config for a snapshot — and the replaced state becomes a revision
itself, so a restore can always be undone. Listings never expose the stored
config bodies; restore is admin-only and audited.

## Tables

Every table managed by the shared controller has, in the pager row:
sortable headers (persisted per user), a substring filter with
**"N of M shown"** + one-click **Clear** whenever it hides rows (filters
persist across sessions — this is why), rows-per-page (15/50/100), **CSV
export** honouring the current filter and sort across all pages,
**column show/hide** (at least one column always stays visible),
copy-rows-as-JSON, and **Reset view**. Wide tables keep a sticky first
column when they scroll. Refreshed rows that changed flash briefly so a
live table shows *what* moved.

## Selection

Device batch selection supports **shift-click range select** (click one
checkbox, shift-click another — everything between follows, respecting the
active filter and sort in both densities), **Escape to clear** the
selection (only when no modal/drawer/palette owns the key), and a
select-all header checkbox that reflects reality — checked when everything
visible is selected, indeterminate on a partial selection.

## Navigation and recall

- **Per-alert deep links** — the link icon on an alert row copies
  `#alerts/<id>`; opening it lands on the inbox with that alert scrolled
  into view and highlighted. Made for tickets and chat.
- **Device deep links** — an open drawer's URL is `#device/<id>/<tab>`;
  paste it into a runbook and it opens straight there. `[` and `]` step
  between devices without closing the drawer.
- **Command palette scopes** — `>` limits to actions, `#` to devices.
  Recently-viewed devices lead the list; pinned (starred) devices lead
  everything.
- **"While you were away"** — refocusing a tab after 30+ minutes shows a
  one-line digest of what changed (new alerts, hosts gone offline).
- **Quiet-hours moon** in the topbar whenever a quiet-hours window is
  active, so "why didn't that page me?" has a visible answer.
- **Page-aware help** — `?` ends with a "This page" section: the current
  page's guide link and its specific keys.

## Charts

Sparklines fade under their line so trend direction reads at a glance.
Axis charts (Trends, forecasts) have a **hover crosshair**: a dashed line
snaps to the nearest data point and a tooltip shows every series' value
with the full timestamp. The device drawer's **Audit tab opens with a
posture radar** — each check group (core, resources, security, services,
hardware, …) is an axis scored by its share of healthy checks, so a host's
shape shows *where* it is weak before you read a single row.

## Sizing and comfort

**My Account → Display units** has an S/M/L interface scale that follows
you across tabs. Theme and accent changes apply to every open tab
immediately. On touch devices, pull-to-refresh re-runs the active page's
loader. All decorative motion (entrance staggers, count-ups, pulses) is
disabled under `prefers-reduced-motion`, and the whole app passes axe-core
with zero critical or serious violations on every page — enforced by a
test gate, not a one-time audit.
