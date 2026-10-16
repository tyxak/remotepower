# Alert parameters

*(v6.2.2 "Pu1seMatters")*

**Settings → Alert parameters** is the single home for every numeric threshold
that decides *when* RemotePower raises an alert and *how* it grades and colours a
host. Before this page these values were scattered across the code and the
config file — some editable in other Settings forms, many only reachable by
hand-editing `config.json`, and a few hard-coded. They now live in one place.

> This is **not** the same as **Monitoring → Tuning**. Tuning silences noisy
> alerts (per-host mutes); Alert parameters sets the numbers that make an alert
> fire in the first place. See [alert-tuning.md](alert-tuning.md).

## Finding a parameter

The page groups the thresholds into labelled sections (Monitors & freshness,
Network & time, Hardware & power, Certificates, Storage & backup, Health grade
cutoffs, Risk/Reliability levels, score weights, and more). A **filter box** at
the top narrows the list as you type — enter `tls`, `disk`, `temp`, `inode` or
`health` to jump straight to the matching fields.

Every field maps 1:1 to a key under `GET/POST /api/config`. Leaving a field
**blank** clears your override and restores the built-in default (shown as the
input's placeholder). Each section has its own **Save**.

## What you can tune

- **Firing thresholds** — the level at which a signal becomes an alert: NIC
  errors per interval, SNMP unreachable/dead counts, temperature °C, clock skew
  ms, pending-update count, controller disk-fill %, UPS battery/runtime, scrub
  and snapshot age, mail-queue depth, inode / file-descriptor / conntrack
  fullness, TLS and cert-file expiry days, contract / OS end-of-life days,
  AV-signature staleness, disk-fill forecast horizon, the Windows/macOS
  **CPU-busy warn/critical %** *(v6.4.0 — Linux uses per-device load-ratio
  thresholds in the device Thresholds modal instead)*, and more.
- **Laptop offline grace** *(v6.3.0, Reachability)* — extra hours of
  silence allowed before a **laptop-chassis** host becomes an offline
  candidate. Agents report their DMI chassis class; set this to a commute's
  worth of hours and a closed lid stops paging like a dead server, while
  servers keep the tight per-poll threshold. `0` (default) treats laptops
  like everything else.
- **Health grade cutoffs** — the score boundaries for **good / fair / poor /
  critical** (default 90 / 70 / 40). The dashboard paints the fleet score ring
  and the per-device heat-map at exactly these boundaries, so the colours always
  match your grades.
- **Risk & reliability levels** — the score cutoffs for the critical/high/medium
  risk badges and the "likely to fail" reliability card.
- **Score weights** — how much each signal contributes to a host's health, risk
  and reliability score (e.g. how many points an offline host or a failing disk
  costs). Set a weight to **0** to ignore that factor entirely.
- **Forecast & CVE tuning** — the disk-fill forecast R² floor and the CVSS score
  bands that classify a vulnerability as critical / high / medium.

## The sections

The sections in the order the page shows them. Each field's built-in default is
its placeholder: leave a field blank to keep the default.

### Monitors & freshness

How many failures in a row, or how stale the data, before a monitor pages.
Higher values ride out brief blips; lower values page sooner.

Fields: SNMP unreachable after, SNMP dead after, Metric alert after, Container
data stale (s).

### Network & time

When interface errors and clock drift count as a problem.

Fields: NIC error floor, Clock skew (ms).

### Hardware & power

Temperature, UPS and the controller's own disk headroom.

Fields: Temperature (°C), UPS battery (%), UPS runtime (s, 0=off), Server disk
(used %, 0=off).

### Patching & capacity

How many pending updates are a finding, and how many hosts one incident must
touch to count as fleet-wide.

Fields: Pending updates, Incident device count.

### Storage & backup

How old a pool scrub, a snapshot or a backup may get, and how long a flow
exporter may stay silent.

Fields: Scrub overdue (days), Snapshot stale (days, 0=off), Proxmox snapshot
(days), Flow export silence (seconds), Proxmox backup stale (days).

### Server health

Raises `health_degraded` once when a host's health score drops below the value,
and `health_recovered` when it comes back. Set it to 0 to switch it off.

Fields: Alert below score (0=off).

### Health grade cutoffs

The score at or above which a host is good, fair or poor; below poor it is
critical. The dashboard colours the score at the same boundaries. Keep them
descending.

Fields: Good ≥ (green), Fair ≥ (amber), Poor ≥ (orange).

### Risk levels

The risk score at or above which an asset is critical, high or medium on the
Risk Assessment page; below medium it is low. Keep them descending.

Fields: Critical ≥ (red), High ≥ (amber), Medium ≥.

### Reliability levels

The failure-likelihood score at or above which a host is critical, high or
medium. A host above medium raises the "likely to fail" Needs-Attention card and
an alert, so a low value here becomes noise. Keep them descending.

Fields: Critical ≥, High ≥, Medium ≥.

### Capacity limits

How full the inode, file-descriptor and connection-tracking tables may get
before a warning and a critical alert. A host's own threshold override wins.

Fields: Inode warn %, Inode crit %, File-descriptor warn %, File-descriptor
crit %, Conntrack warn %, Conntrack crit %.

### Reachability

How many failed checks in a row before a host, a resolver or an IP-reputation
result pages, and how long a laptop may be silent first.

Fields: Offline after N missed polls, Laptop offline grace (hours), Resolver down
after N fails, IP-reputation confirm scans.

### Certificates

How many days before expiry a certificate warns and goes critical. The TLS
values apply to monitored TLS targets that set none of their own; the cert-file
value is for the certificates found on hosts.

Fields: TLS expiry warn (days), TLS expiry crit (days), Cert-file expiring
(days), CT poll fails → backoff.

### Lifecycle

Date-based windows for contracts, OS end of life and antivirus signatures, and
a few related limits.

Fields: Contract expiry warn (days), Contract expiry soon (days), OS end-of-life
soon (days), AV signature stale (days), Gateway latency high (ms, 0=off),
Battery health low (%, 0=off), Defender sig warn (days), CPU busy warn %
(Windows/macOS), CPU busy critical % (Windows/macOS).

### Thermal & GPU

The temperatures at which the Thermal and GPU pages call a sensor hot or
critical. Critical also feeds the overheating factors of the risk and
reliability scores. Keep critical above hot.

Fields: Sensor hot ≥ (°C), Sensor critical ≥ (°C), GPU hot ≥ (°C).

### Disk wear & SMART

Predictive disk-health limits: SSD and NVMe wear, the bad-sector count treated
as critical, how close a medium-risk disk's predicted failure must be before it
alerts, and the smallest ECC error increase that fires `ecc_errors`.

Fields: Wear warn %, Wear high %, Realloc/pending critical (sectors),
Medium-risk ETA window (days), ECC min delta (0=any).

### Health score weights

The points one Needs-Attention item takes off a host's 0–100 health score, by
severity. Set one to 0 to stop that severity counting.

Fields: Critical item, Warning item, Info item.

### Risk score weights

The points each posture or security signal adds to a host's 0–100 risk score,
one field per signal. Signals marked "(each)" count every occurrence and may be
capped. Set one to 0 to leave that signal out.

### Reliability score weights

The points each signal adds to a host's 0–100 failure-likelihood score, one
field per signal. Some are capped. Set one to 0 to leave that signal out.

### Capacity & forecast

The days-to-full at which a disk's fill forecast warns or goes critical (the same
verdict everywhere: Needs-Attention, the Checks page and the disk-health
colour), the pending-update count that warns, and how long a host counts as
recently out of memory after an OOM kill.

Fields: Disk fill ETA crit ≤ (days), Disk fill ETA warn ≤ (days), Pending
updates warn ≥, Recent-OOM window (s).

### Containers & SNMP

How many container restarts alert or mark a container as restarting, and the
fleet's default SNMP CPU limits. A device's own threshold override wins.

Fields: Restart delta ≥ (alert), Restart count ≥ (restarting), SNMP CPU warn %,
SNMP CPU crit %.

### Monitoring cadence

How long a short-lived Needs-Attention item stays, the after-hours window, how
many failed pings make an agentless host offline, how many GitHub issues one poll
may open, how far a metric must fall back before it counts as recovered, and the
shortest time a host counts as online.

Fields: NA event TTL (hours), After-hours window (hours), Agentless ping fails →
offline, GitHub issues per poll, Metric recovery buffer (pts), Min online TTL
(s, flap floor).

### Compliance & CIS

The windows the compliance report looks back over, the CIS disk and swap
ceilings, and the lowest DMARC pass rate that counts.

Fields: Compliance TLS expiring (days), Compliance lookback (days), CIS disk
under %, CIS swap under %, DMARC min pass %.

### RemotePower self-health

What turns the top bar's health pill for the RemotePower server itself: load
above cores times the ratio, memory use, and the share of hosts online.

Fields: High-load ratio (× cores), Memory warn %, Devices online warn %.

### Reliability tuning

When a host counts as unstable (returns to online within a window), the reboot
and wear limits that feed the failure-likelihood score, and how much history is
kept.

Fields: Unstable returns ≥, Unstable window (days), Reboot churn ≥, Wear high %
(reliability), Monitor checks kept, Command history rows kept.

## Notes

- Grade and level cutoffs are **clamped to stay descending** — a fat-fingered
  config (e.g. *good* below *fair*) can't invert the ladder.
- The cutoffs used by the dashboard are delivered by the server with each page
  load, so there is one source of truth; the browser never re-hardcodes them.
- Defaults are conservative and match the product's long-standing behaviour, so
  an untouched install behaves exactly as before.

*Related:* [alert-tuning.md](alert-tuning.md) · [alerts.md](alerts.md) ·
[monitors.md](monitors.md) · [settings.md](settings.md)

## Preview impact *(v6.4.2)*

Every field on this page applies **fleet-wide the moment you save**, and the
checks engine recomputes for every host on the next read. Dropping
`disk_warn_percent` from 90 to 80 on a 400-host fleet is a hundred simultaneous
new breaches, a Needs-Attention avalanche and a paging storm — and the only way
back is Settings → Advanced → Configuration history.

**Preview impact** answers the question first. It recomputes every host's
checks against the values currently in the form — without saving anything — and
reports which checks would start breaching, which would stop, how many hosts
each affects, and a few example hostnames.

- It drives the **real** checks engine against the proposed config, not a
  separate copy of the rules. A preview that disagreed with what actually
  happens would be worse than no preview.
- Only hosts within your role scope are counted.
- Alerts **already open** are not resolved by a threshold change. They clear on
  their own recover events, or by muting them under Monitoring → Tuning — so a
  preview showing "40 host-checks would stop breaching" is about future firing,
  not about the inbox emptying.

`POST /api/config/threshold-preview` takes the same body as `POST /api/config`.
