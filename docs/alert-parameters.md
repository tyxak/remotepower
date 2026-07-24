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

## Notes

- Grade and level cutoffs are **clamped to stay descending** — a fat-fingered
  config (e.g. *good* below *fair*) can't invert the ladder.
- The cutoffs used by the dashboard are delivered by the server with each page
  load, so there is one source of truth; the browser never re-hardcodes them.
- Defaults are conservative and match the product's long-standing behaviour, so
  an untouched install behaves exactly as before.

*Related:* [alert-tuning.md](alert-tuning.md) · [alerts.md](alerts.md) ·
[monitors.md](monitors.md) · [settings.md](settings.md)
