# Security Advisory

**Security → Advisory** answers the question every other security page leaves
open.

The CVE page tells you which CVEs you have. Exposure tells you which ports are
open. Checks tells you what is failing. Risk gives you a score. Each is a good
answer to *"what is the state of X"*, but none of them answers the question an
operator has at 09:00 on a Monday:

> **What should I fix first, and why that rather than the other thing?**

The advisory is one prioritized list that spans the stack from the operating
system up to the application, at the scope you choose.

## What it is built from

Nothing new is collected. The advisory reads data RemotePower already holds, so
it is cheap to run on demand at any scope and never scans or contacts anything.

| Layer | Sources |
|---|---|
| **Application** | Findings from the pentest scanners (Security → Pentest) with severity critical, high or medium: a vulnerable CMS plugin, an exposed admin panel. Informational findings are left out. |
| **Exposure** | World-reachable listening ports (ports you muted on the Exposure page are skipped), host firewall posture, and TLS certificates from the TLS monitor that are expired or expire within 14 days |
| **OS** | Package CVEs rated critical or high (the ignore list is applied, KEV-listed ones come first), pending updates and whether the host auto-patches, pending reboot, end-of-life releases, failing OpenSCAP benchmark rules, and Secure Boot when the Secure Boot check is switched on |
| **Identity** | sshd settings (root login, password login, empty passwords), brute-force pressure, authorized SSH keys on deprecated algorithms, local accounts with an empty password or one older than a year, and on Windows Defender tamper protection, UAC and Secure Boot |
| **Integrity** | Failing protect checks, Integrity Guard quarantine, tracked config files that drifted from their baseline, an agent binary whose hash does not match, and a refused unsigned agent update |
| **Data** | Credentials found in files by the [secret scan](secret-scan.md) (muted ones are left out), stale or missing backups, backups that are fresh but fail their integrity check or restore drill *(7.5.0)*, FileVault on macOS, BitLocker on Windows, and LUKS on Linux (only when you turn on the disk encryption check in Settings → Alerting) |

A critical or high CVE that is on CISA's **KEV** list makes its finding
critical and is listed first in the evidence. KEV membership means someone has
seen the CVE exploited, not just predicted. CVEs you accepted on the ignore
list do not appear at all.

The application layer is the one host telemetry cannot see on its own. A
vulnerable plugin is not a package, does not show up in a distribution CVE
feed, and does not open a new port. That is why scan findings are folded in
here instead of staying on their own page.

### What it does not include

A finding has to be answerable from stored state. A change such as "a new port
opened" or "an SSH key was added" is an *event*, and it already alerts as
`new_port_detected` or `ssh_key_added`. What the advisory reads from the same
data is the lasting part: how many services are world-reachable now, and which
authorized keys use a deprecated algorithm.

Config drift is listed as the **paths** that changed, never the captured diff.
A config file can carry a credential, and the Drift page shows the contents
behind its own view.

## Scope

Choose **Whole fleet**, **A specific host**, **A group** or **A tag**, then
click **Build advisory**. The scope is always cut down to what your role and
tenant can see. Asking for a host you cannot see returns "not found", not
"forbidden", so the advisory never reveals that a host exists.

TLS certificate findings do not belong to a host, so they appear at every scope.

## Reading the list

The page opens with four tiles (Critical, High, Medium, Hosts assessed) and
then one card per finding. The order of the cards is the answer, so do not
re-sort it. It goes by severity first and then by how many hosts are affected,
so a problem on thirty hosts outranks the same problem on one.

Each card carries:

- **Rank, severity and layer** at the top, with the number of affected hosts.
- **Why it matters**, in plain terms.
- **Do this**, the concrete next step. A finding with no concrete step does not
  appear.
- **Evidence**: the ports, packages, paths or config lines behind it (up to
  eight), so you can check the claim instead of trusting it.
- The affected hosts (the first 25, with the full count), where the data came
  from, and a link to the related guide.

Identical findings on several hosts are **grouped into one card**: "23 hosts
have pending updates" is one thing to schedule, not 23 rows to read. A group
takes the worst severity of its members.

An empty advisory is a real result. When nothing critical or high comes out of
the collected data, the page says so instead of padding the list.

## The AI option

**Ask AI** sends the advisory to your AI provider and asks it to prioritize:
what to fix first, why that order, and whether anything looks systemic enough
for a fleet-wide fix instead of per-host work. It is good at spotting *chains*.
An exposed service plus a weak identity control is worse than either alone, and
a severity label will not tell you that. AI has to be enabled under **Settings
→ AI assistant** first.

**What is sent is redacted on the server before it leaves.** The model gets
finding titles, layers, severities and host counts. It never gets the evidence:
no host names, paths, URLs, package names or matched log lines, because the
configured provider may be outside your network. Titles that would contain a
host name, a check name or a scanner's own text are replaced by a generic line.

The trade is that the model cannot invent specifics it was not given, so its
answer is about *ordering and reasoning* rather than about your individual
hosts. The evidence stays on the page, where you already have it.

The same advisor is on the **AI Assistant** page as a **Security advisory**
card in **AI Insights**, without a preselected scope.

## Relationship to the other pages

| Page | Question it answers |
|---|---|
| **Advisory** | What should I fix first, and why? |
| [Risk](risk.md) | How bad is each asset, as a number? |
| [CVEs](cve.md) | Which known vulnerabilities do I have? |
| [Exposure](exposure.md) | What can the outside world reach? |
| [Protect](integrity-guard.md) | Has anything changed that should not have? |
| [Pentest](security-scans.md) | What does an outsider see when they scan me? |

The advisory does not replace any of them. It reads all of them and tells you
where to start.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/security/advisory?scope=all\|host\|group\|tag&target=...` | Any signed-in user. `target` is required for every scope except `all`. |
| POST | `/api/security/advisory/brief` | `{scope, target}`. Returns the redacted text that Ask AI sends. |

## See also

- [integrity-guard.md](integrity-guard.md): the integrity layer's checks and vault.
- [security-scans.md](security-scans.md): running the scans that feed the application layer.
- [secret-scan.md](secret-scan.md): the scan behind the data layer's credential findings.
- [ai.md](ai.md): configuring the AI provider, and what leaves your network.
