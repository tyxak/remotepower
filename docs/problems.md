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
| **Failing** | An alert is open and the host still reports the problem, or the host reports it and no alert exists. |
| **Resolved, still failing** | You resolved the alert, and the host's last report still shows the problem. |
| **Resolved, waiting for the host** | You resolved the alert, and the host has not reported since. Resolving an alert asks the host to report on its next poll, so this state is short. |
| **Host reports it clear** | An alert is open, but Needs Attention and Checks no longer show the problem. It closes when its recovery event arrives, or you can resolve it. |
| **Resolved** | Resolved, and the host does not report it. |
| **Recovered** | A recovery event closed it. |

"By hand" means a person closed it. A recovery event, a mute and the removal of a host do not count.

An open alert of a kind that neither Needs Attention nor Checks can show stays **Failing**: nobody can tell "the
host stopped reporting it" from "nothing looks", so the page does not claim the first.

## The page

The page opens on **Needs you**, the first four states. Resolved and recovered problems stay in the list for
seven days and show under **All states**.

- Four tiles count the states that need you. Click a tile to filter by it, and click it again to undo.
- Filter by state, by where the problem shows (Alerts, Needs Attention, Checks) and by text.
- The **Where** buttons open the page a source lives on, for the actions that page has.
- **Resolve** (administrators) closes every open alert of a problem at once. The Needs Attention item stays until
  the host's own report clears it, so a problem you resolved while the host still reports it reads **Resolved,
  still failing**. That is by design: a problem the host still reports should not read as fixed.

Checks you have switched off on a host, and hosts you do not monitor, are left out, as on the Checks page.

## API

`GET /api/problems` returns the same list. `state` is `active` (default), `all` or one state; `source` is `alert`,
`attention` or `check`; `device_id`, `q`, `days` (how far back a resolved alert counts, 7 by default, 30 at most),
`limit` and `offset` narrow it. `counts` covers everything the caller may see, before the filters. The list is
filtered to the hosts the caller may see.
