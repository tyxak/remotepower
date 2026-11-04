# Problems

**Monitoring → Problems** is one list of what is wrong with the fleet, with each problem once.

Alerts, Needs Attention and Checks each describe trouble on a host by their own rules, and the same trouble can
sit in all three. A service fails, an alert fires, Needs Attention lists the failed unit and the Systemd units
check turns critical. Closing it in one place did not close it in the others, so it was hard to tell what was
still wrong. This page joins them.

## What a row is

A row is one kind of problem on one host. Everything that belongs to it hangs under it: the alerts, the Needs
Attention items and the failing checks. A host with two failed units is one row, with both alerts and the one
Needs Attention item under it. The same kind of problem on two hosts is two rows.

The join is by host and kind, and no finer, because Needs Attention and Checks name their resources only in text.
A finer key would be a text match that breaks whenever a list is cut ("+3 more") or one path is the start of
another.

The kind is the Needs Attention kind. An alert belongs to the kind of the Needs Attention item that the same
event raises (the one a mute of that event silences), a metric alert (CPU, memory, swap, disk) to the kind of its
metric, and a check to the kind it measures: the Systemd units check joins failed units, Reachability joins
offline, CVE joins CVE findings, and so on. Something none of these reach still gets a row of its own, so a
missing link hides nothing. A problem on no host (a certificate, an integration) joins its Needs Attention item
only when exactly one alert has that kind; with several there is nothing to tell which is which.

## The state

| State | What it means |
| --- | --- |
| **Failing** | An alert is open and the host still reports the problem, or the host reports it and no alert exists, or a recovery event closed the alert and the host still reports the problem. |
| **Resolved, still failing** | You resolved the alert, and the host's last report still shows the problem. |
| **Resolved, waiting for the host** | You resolved the alert, and the host has not reported since. Resolving an alert asks the host to report on its next poll, so this state is short. A host that was asked less than two minutes ago is not asked again, and a host without an agent is never asked; those hosts stay here until they report on their own. |
| **Alert open, no longer listed** | An alert is open, but Needs Attention and Checks no longer list the problem. The host may have recovered, or you may have ignored or snoozed the item or switched the check off. It closes when its recovery event arrives, or you can resolve it. |
| **Resolved** | Resolved, and the host does not report it. |
| **Recovered** | A recovery event closed it. |

An alert counts as resolved when a person closes it. A recovery event, a mute and the removal of a host do not count.

An open alert of a kind that neither Needs Attention nor Checks can show stays **Failing**: nobody can tell "the
host stopped reporting it" from "nothing looks", so the page does not claim the first.

## The page

The page opens on **Needs you**, the first four states. Resolved and recovered problems stay in the list for
seven days and show under **All states**.

- Four views sit above the table: **All problems**, **Alerts**, **Needs Attention** and **Checks**. Each shows
  how many active problems it holds. Alerts, Needs Attention and Checks are three filters of the one list: a
  problem that has an alert and a Needs Attention item is in both views, and one row in All.
- Four tiles count the states that need you. Click a tile to filter by it, and click it again to undo.
- Filter by state and by text. A view and a state filter work together.
- The **Where** buttons open the page a source lives on, for the actions that page has.
- **Updated** is the last thing that happened to one of the problem's alerts: raised, acknowledged or resolved. A
  problem that only Needs Attention or Checks list has no alert, so it shows when its host last reported it, and a
  dash when the host has not said when. Sorting by the column uses the same time.
- Checks you have switched off on a host, and hosts you do not monitor, are left out, as on the Checks page.

## What you can do to a problem

Every action uses the same request, and the same permission, as the page it comes from. The row only gathers
them in one place, so hiding a button for a role is a courtesy and the server asks again.

| Action | Who | What it does |
| --- | --- | --- |
| **Resolve** | Administrators | Closes every open alert of the problem at once. The Needs Attention item stays until the host's own report clears it, so a problem you resolved while the host still reports it reads **Resolved, still failing**. That is by design: a problem the host still reports should not read as fixed. |
| **History** | Everyone | Opens everything that happened to the problem: each alert raised (and how many times it came again), acknowledged and resolved, by whom and how, with the note. A resolved alert shows who closed it. |
| **Mute** | Administrators | Silences the events the problem stands for on its host, for the hours you enter or until you lift it under Monitoring → Tuning. Open alerts of those events are cleared. |
| **Snooze 24 h** | Administrators | Hides the problem's Needs Attention items for a day. They come back by themselves. |
| **Ignore** | Administrators | Hides the problem's Needs Attention items until you lift it, under Settings → Ignored items. |
| **Disable check** | Administrators | Switches off the failing checks of the problem on that host. They stay on the Checks page, switched off. |
| **Fix** | Roles that may run fixes on the host | Opens the same investigate dialog as Needs Attention and Alerts, for the host and the kind of problem. Only a problem with a playbook shows it. |

Mute, Snooze, Ignore and Disable check each show an **Undo** that puts back exactly what the action changed. One
action on a row covers everything that belongs to that row, so one Undo undoes all of it.

## On the other pages

Alerts, Needs Attention and Checks show the same state beside their own rows, so you do not have to open Problems
to learn what it says.

- **Alerts.** In the resolved view, an alert you closed shows **Still failing** beside "resolved by" when the host's
  last report still shows its problem, and **Waiting for the host** when it has not reported since. An open alert
  that Needs Attention and Checks no longer list shows **No longer listed**.
- **Needs Attention and Checks.** An item or a failing check whose host has alerts for the same kind of problem shows
  **Alert resolved, still failing** or **Alert resolved, waiting for the host** when someone closed the alert and the
  host has not caught up. A plain open alert is the normal case and gets no tag.
- **The bar.** Under its title, each of the three pages has the same bar as Problems: **All problems**, **Alerts**,
  **Needs Attention** and **Checks**, with the page you are on marked. On these pages each button opens that page.
  On Problems the same four are filters of the one list. Arriving at Problems from the sidebar or from one of these
  bars starts at all problems.

Resolve an alert on any of the four pages and the other three say so after their next refresh.

## API

`GET /api/problems` returns the same list. `state` is `active` (default), `all` or one state; `source` is `alert`,
`attention` or `check`; `device_id`, `q`, `days` (how far back a resolved alert counts, 7 by default, 30 at most),
`limit` (200 by default, 1,000 at most) and `offset` narrow it. `counts` covers everything the caller may see, before the filters, and carries
`active_sources`, the number of active problems each view holds. The list is filtered to the hosts the caller may
see.

Each row names what can be done to it, so a client does not have to guess: the alert ids that are open, the
events a mute would cover, the Needs Attention items with the key an ignore needs, the checks with the key a
switch-off needs, and the playbook a fix would open.

`GET /api/problems/history` returns the history of one problem, newest first. Pass the row's `device_id` and
`family`, and `detail` for a problem that has no host. `days` sets how far back it reads (90 by default, 365 at most).

The other pages carry the state too. `GET /api/alerts` adds `problem_state` (`host_clear`, `resolved_but_failing` or
`waiting_for_report`) to the alerts it applies to. `GET /api/attention?problems=1` and `GET /api/checks?problems=1`
add `problem` (`state`, `alerts_open`, `resolved_by`, `resolved_at`) to an item or a failing check whose host and
kind have alerts. Without the parameter nothing is built, so the dashboard card costs what it always did.

## Related

- [Alerts](alerts.md), [Needs Attention](attention.md) and [Checks](checks.md) are the three lists this page joins.
- [Tuning](alert-tuning.md) holds the mutes you lift.
