# Security Advisory

**Security → Advisory** answers the question every other security page leaves
open.

The CVE page tells you which CVEs you have. Exposure tells you which ports are
open. Checks tells you what is failing. Risk gives you a score. Each is a good
answer to *"what is the state of X"* — but none of them answers the question an
operator actually has at 09:00 on a Monday:

> **What should I fix first, and why that rather than the other thing?**

The advisory is one prioritized list, spanning the whole stack from the
operating system up to the application, at whatever scope you care about.

## What it is built from

Nothing new is collected. The advisory is a *reading* of data RemotePower
already holds, which is why it is cheap to run on demand at any scope and never
scans or contacts anything:

| Layer | Sources |
|---|---|
| **Application** | Scanner findings (nuclei, nikto, wpscan) — a vulnerable CMS plugin, an exposed admin panel |
| **Exposure** | World-reachable listening ports, host firewall posture, TLS expiry |
| **OS** | Package CVEs, pending updates, pending reboot, end-of-life releases |
| **Identity** | sshd configuration, brute-force pressure |
| **Integrity** | Failing protect checks, Integrity Guard quarantine |

The application layer is the one host telemetry cannot see on its own: a
vulnerable plugin is not a package, does not appear in a distro CVE feed, and
does not open a new port. That is why scan findings are folded in here rather
than left on their own page.

## Scope

Build it for **the whole fleet**, a **group**, a **tag**, or a **single host**.
The scope is always filtered to what your role and tenant can see — a
host-scoped request for a device you cannot see returns "not found", not
"forbidden", so the advisory never reveals that a device exists.

## Reading the list

Each entry carries four things, and the order of the list is itself the answer:

- **Rank + severity + layer** — the list is sorted by severity, then by how many
  hosts are affected. A problem on thirty hosts outranks the same problem on
  one. Do not re-sort it; the order *is* the recommendation.
- **Why it matters** — the reason this is worth your morning, in plain terms.
- **Do this** — the concrete next action. If we can't name one, the finding
  doesn't appear.
- **Evidence** — the actual ports, packages, paths or config lines, so you can
  verify the claim instead of trusting it.

Identical findings across hosts are **grouped into one decision**: "23 hosts
have pending updates" is one thing to schedule, not 23 rows to read. The
affected hosts are listed underneath (bounded, with a count).

An empty advisory is a real result. If nothing critical or high comes out of the
collected data, the page says so rather than padding the list.

## The AI option

**Ask AI** sends the advisory to the configured AI advisor and asks it to
prioritize: what to fix first, why that order, and whether anything looks
systemic enough to deserve a fleet-wide fix rather than per-host work. It is
particularly good at spotting *chains* — an exposed service plus a weak identity
control is worse than either alone, and a severity label alone won't tell you
that.

**What is sent is redacted, on the server, before it leaves.** The model
receives only finding titles, layers, severities and host counts. It never
receives the evidence — no hostnames, paths, URLs, package names or matched log
content — because the configured provider may be off-box. That redaction happens
server-side deliberately: building the brief in the browser from the loaded
advisory would have shipped all of it.

The trade is that the model cannot invent specifics it was not given, which is
also why its answer is about *ordering and reasoning* rather than about your
individual hosts. The evidence stays on the page, where you already have it.

The same advisor is available from **AI → Insights** as a card, without a
preselected scope.

## Relationship to the other pages

| Page | Question it answers |
|---|---|
| **Advisory** | What should I fix first, and why? |
| [Risk](risk.md) | How bad is each asset, as a number? |
| [CVEs](cve.md) | Which known vulnerabilities do I have? |
| [Exposure](exposure.md) | What can the outside world reach? |
| [Protect](integrity-guard.md) | Has anything changed that shouldn't have? |
| [Pentest](security-scans.md) | What does an outsider see when they scan me? |

The advisory does not replace any of them — it reads all of them, and tells you
where to start.

## See also

- [integrity-guard.md](integrity-guard.md) — the integrity layer's checks and vault.
- [security-scans.md](security-scans.md) — running the scans that feed the application layer.
- [ai.md](ai.md) — configuring the AI provider, and what leaves the box.
