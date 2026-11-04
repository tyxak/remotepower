# Finding your way around

RemotePower has a lot of pages, grouped into twelve domains in the sidebar. This page covers the four ways to get to one, and when each is the right one.

## All pages: the map

The **All pages** button at the top of the sidebar opens a single screen with every page of the twelve domains on it, grouped by domain, each with a one-line description of what it answers. Type to filter; Enter opens the first match.

Use it when you do not yet know what the thing you want is called. The sidebar shows only the domains you opened, and the command palette needs a search term, so neither helps when the question is "what is even in here?".

The list is built from the sidebar itself, so it is never out of date, and a page your installation has switched off is simply not in it.

## The sidebar

Dashboard, Hosts, Alerts and Tickets sit at the top. Below them are twelve domains: Fleet, Monitoring, Hardware, Security, Compliance, Patching, Automation, Scheduling, Access, Backups, Business and Admin. Inside a domain the pages are listed alphabetically, except that Needs Attention is always first in Monitoring.

**More than one domain can be open at once.** Clicking a domain header toggles it, and the set is remembered. *Expand every sidebar group* (in the All pages dialog) opens all twelve, and closes them again into a tidy rail if they are already open.

Navigating to a page opens its domain, and leaves the other domains you opened exactly as they were.

**Star a page** to pin it to the top of the sidebar, above the domains. Your stars belong to your account, so they follow you to another browser.

## The command palette: `Ctrl-K` or `/`

For when you know what you want. It searches pages, hosts, open alerts, CVE findings, saved scripts and your recent commands, and it offers actions, so `reboot`, `terminal` or a hostname all work. Start with `>` to list actions only, or `#` to list hosts only. With the knowledge index on, it also finds tickets, KB articles, CMDB entries, contacts and the docs. It is the fastest route once the product is familiar. The full list is in [Keyboard shortcuts](keyboard-shortcuts.md#the-command-palette).

## The sidebar search box

Searches page titles *and the concepts they contain*: typing `SLA`, `cron` or `metrics` finds the page that handles them even when the word is not in its name. It also finds the Settings tabs, for example "Settings ▸ Notifications". Enter opens the first hit.

## Which to use

| You want to | Use |
|---|---|
| See what exists | **All pages** |
| Jump somewhere you know | **Ctrl-K** |
| Find the page that handles a concept | the sidebar **search box** |
| Return to the handful you use daily | **starred** entries |

## Not finding a page at all?

Some pages belong to optional modules. They are switched on or off under **Settings → Advanced → Optional modules**. A module that is off hides its nav entry *and* answers its whole API with a not-found, so the page is absent rather than merely hidden. These nine are optional:

| Module | On by default |
|---|---|
| Alerts | yes |
| Tickets | yes |
| Compliance | yes |
| Pentest | yes |
| Autonomous remediation | yes |
| Billing | no |
| Knowledge base | no |
| AI executor | no |
| SSH Gateway | no |

If the page you want belongs to a module that is off, turn it on there. If you are signed in with a restricted role, pages outside your permissions do not appear either.

## See also

- [Keyboard shortcuts](keyboard-shortcuts.md): the `g` jumps, the palette and the keys of each page.
- [Settings](settings.md): the tabs and where each option lives.
