# Alert parameters

**Settings → Alert parameters** is the single home for every numeric threshold
that decides *when* RemotePower raises an alert and *how* it grades and colours a
host. There are well over a hundred fields, grouped into labelled sections.

> This is **not** the same as **Monitoring → Tuning**. Tuning silences noisy alerts
> (per-host mutes). Alert parameters sets the numbers that make an alert fire in the
> first place. See [alert-tuning.md](alert-tuning.md).

## Finding and changing a parameter

- A **filter box** at the top narrows the list as you type. Enter `tls`, `disk`,
  `temp`, `inode` or `health` to jump to the matching fields.
- **Changed only** hides every field that still has its default, so you see just your
  overrides. A field you have changed gets an accent edge and a small reset button.
- Large values get a reading aid next to them, for example "about 180 days" beside a
  figure in hours.
- Every field maps 1:1 to a key under `GET/POST /api/config`.
- Leaving a field **blank** clears your override and restores the built-in default.
  The default is the input's placeholder, and the lists below show it in square
  brackets.
- Every section has a **Save** button, and they all do the same thing: they save the
  whole page at once. A value that is not a number stops the save, marks the field
  and moves focus to it, so nothing is saved by accident.

## What you can tune

- **Firing thresholds.** The level at which a signal becomes an alert: NIC errors per
  interval, SNMP unreachable counts, temperature in °C, clock skew in ms, pending
  updates, the server's own disk-fill %, UPS battery and runtime, scrub and snapshot
  age, inode, file-descriptor and conntrack fullness, TLS and certificate-file expiry
  days, contract and OS end-of-life days, antivirus signature age, the disk-fill
  forecast horizon, the Windows and macOS **CPU-busy warn and critical %** (Linux uses
  per-host load-ratio thresholds in the host's Metric thresholds instead), and more.
- **Laptop offline grace.** Extra hours of silence allowed before a **laptop-chassis**
  host becomes an offline candidate. Agents report their chassis class. Set this to a
  commute's worth of hours and a closed lid stops paging like a dead server, while
  servers keep the tight per-poll threshold. `0` (the default) treats laptops like
  everything else.
- **Health grade cutoffs.** The score boundaries for **good, fair, poor** and
  **critical** (default 90, 70 and 40). The dashboard paints the fleet score ring and
  the per-host heat map at exactly these boundaries, so the colours always match your
  grades.
- **Risk and reliability levels.** The score cutoffs for the critical, high and medium
  risk badges and the "likely to fail" reliability card.
- **Score weights.** How much each signal contributes to a host's health, risk and
  reliability score, for example how many points an offline host or a failing disk
  costs. Set a weight to **0** to ignore that factor.
- **Forecast and CVE tuning.** The disk-fill forecast R² floor, the memory, swap and
  CPU-load forecast lines, the reliability trend cutoffs, and the CVSS score bands that
  classify a vulnerability as critical, high or medium.

## The sections

The sections in the order the page shows them. In each list, the number in square
brackets is the built-in default. Leave a field blank to keep it. A default of `0` is
"off" where the label says so.

### Monitors & freshness

How many failures in a row, or how stale the data, before a monitor pages. Higher
values ride out brief blips. Lower values page sooner.

Fields: SNMP unreachable after [2], SNMP dead after [72], Metric alert after [1],
Container data stale (s) [900].

### Network & time

When interface errors and clock drift count as a problem.

Fields: NIC error floor [5], NIC drop floor [blank], Clock skew (ms) [1000].

The NIC floors count new errors or drops on one interface between two reports. Errors
point to a failing cable, a dirty SFP or a dying switch port, so the error floor is
low. Drops rise with traffic on a healthy interface (a media server can drop dozens of
packets a second while it streams), so they can have a floor of their own.

- Leave the drop floor blank and errors and drops are added together against the error
  floor.
- Set it and they are judged apart: errors against the error floor, drops against the
  drop floor.
- 0 turns drop alerts off.

A host can have its own floors under Metric thresholds. When a report is late because
the server was down, the counts are scaled back to what a normal gap would have
collected, so a restart does not look like a burst.

### Hardware & power

Temperature, UPS and the controller's own disk headroom.

Fields: Temperature (°C) [85], UPS battery (%) [20], UPS runtime (s, 0=off) [180],
Server disk (used %, 0=off) [85].

### Patching & capacity

How many pending updates are a finding, and how many hosts one incident must touch to
count as fleet-wide.

Fields: Pending updates [10], Incident host count [5].

### Storage & backup

How old a pool scrub, a snapshot or a backup may get, and how long a flow exporter may
stay silent.

Fields: Scrub overdue (days) [35], Snapshot stale (days, 0=off) [0], Proxmox snapshot
(days) [7], Flow export silence (seconds) [10800], Proxmox backup stale (days) [7].

### Server health

Raises `health_degraded` once when a host's health score drops below the value, and
`health_recovered` when it comes back. Set it to 0 to switch it off.

Fields: Alert below score (0=off) [0].

### Health grade cutoffs

The score at or above which a host is good, fair or poor. Below poor it is critical.
The dashboard colours the score at the same boundaries. Keep them descending.

Fields: Good ≥ (green) [90], Fair ≥ (amber) [70], Poor ≥ (orange) [40].

### Risk levels

The risk score at or above which an asset is critical, high or medium on the Risk
page. Below medium it is low. Keep them descending.

Fields: Critical ≥ (red) [80], High ≥ (amber) [50], Medium ≥ [20].

### Reliability levels

The failure-likelihood score at or above which a host is critical, high or medium. A
host above medium raises the "likely to fail" Needs-Attention card and an alert, so a
low value here becomes noise. Keep them descending.

Fields: Critical ≥ [70], High ≥ [45], Medium ≥ [20].

### Capacity limits

How full the inode, file-descriptor and connection-tracking tables may get before a
warning and a critical alert. A host's own threshold override wins.

Fields: Inode warn % [85], Inode crit % [95], File-descriptor warn % [80],
File-descriptor crit % [95], Conntrack warn % [80], Conntrack crit % [95].

### Disk activity

How busy a disk may be, as a share of the time it has a request in flight, and how many
reports in a row it has to stay over a line before an alert. Both lines are off at 0. A
host's own line under Metric thresholds wins. See [disk-health.md](disk-health.md).

Fields: Disk busy warn % [0], Disk busy crit % [0], Reports in a row [5].

### CPU time

How much of the CPU time may go to waiting for storage (**I/O wait**) or to the hypervisor
(**steal**), and how many reports in a row a host has to stay over a line before an alert.
The load average cannot tell either from real work, so a host that looks busy because its
disk is slow, or because other guests on the same hypervisor take its CPU, is not told
apart from one that is computing. All four lines are off at 0. A host's own lines under
Metric thresholds win. The alert is a metric warning or critical with the kind **I/O wait**
or **Steal**, and it closes when the share falls below the line. The host's menu shows the
shares in **System info → CPU time**, and the host's **Metrics** window draws them over the last
two days.

Fields: I/O wait warn % [0], I/O wait crit % [0], Steal warn % [0], Steal crit % [0],
Reports in a row [3].

### Drive temperature

How warm a drive may get, in °C, before an alert. Hard disks, SATA SSDs and NVMe drives
each have a warning and a critical line of their own, and the last pair is for any other
drive. All eight are off at 0. A host's own lines under Metric thresholds win over these,
and a drive's own lines on the Hardware tab win over both.

The Thermal page and the risk score hold a drive to the same lines. The page shows the
critical line as the threshold with the headroom under it, and flags the host when a
drive is over its line, even if another sensor is hotter. A drive with no line is held
to the fleet's hot and critical temperatures, as every other sensor is. The sensors of a
drive's own chip follow the lines too: `nvme-*` sensors the NVMe lines, and
`drivetemp-*` sensors the lines of the disk they read (the lines for any other drive
when the disk is not known). See [disk-health.md](disk-health.md) and
[thermal.md](thermal.md).

Fields: Hard disk warn °C [0], Hard disk crit °C [0], SATA SSD warn °C [0], SATA SSD
crit °C [0], NVMe warn °C [0], NVMe crit °C [0], Any other drive warn °C [0], Any other
drive crit °C [0].

### Reachability

How many failed checks in a row before a host, a resolver or an IP-reputation result
pages, and how long a laptop may be silent first.

Fields: Offline after N missed polls [5], Laptop offline grace (hours) [0], Resolver
down after N fails [2], IP-reputation confirm scans [2].

### Certificates

How many days before expiry a certificate warns and goes critical. The TLS values apply
to monitored TLS targets that set none of their own. The cert-file value is for the
certificates found on hosts.

Fields: TLS expiry warn (days) [14], TLS expiry crit (days) [3], Cert-file expiring
(days) [21], CT poll fails → backoff [3].

### Lifecycle

Date-based windows for contracts, OS end of life and antivirus signatures, and a few
related limits.

Fields: Contract expiry warn (days) [30], Contract expiry soon (days) [90], OS
end-of-life soon (days) [90], AV signature stale (days) [7], Gateway latency high (ms,
0=off) [150], Battery health low (%, 0=off) [50], Defender sig warn (days) [3], CPU busy
warn % (Windows/macOS) [85], CPU busy critical % (Windows/macOS) [95].

### Thermal & GPU

The temperatures at which the Thermal and GPU pages call a sensor hot or critical.
Critical also feeds the overheating factors of the risk and reliability scores. Keep
critical above hot.

Fields: Sensor hot ≥ (°C) [75], Sensor critical ≥ (°C) [85], GPU hot ≥ (°C) [85].

### Disk wear & SMART

Predictive disk-health limits: SSD and NVMe wear, the bad-sector count treated as
critical, how close a medium-risk disk's predicted failure must be before it alerts,
and the smallest ECC error increase that fires `ecc_errors`.

Fields: Wear warn % [80], Wear high % [90], Realloc/pending critical (sectors) [100],
Medium-risk ETA window (days) [180], ECC min delta (0=any) [0].

### Health score weights

The points one Needs-Attention item takes off a host's 0 to 100 health score, by
severity. Set one to 0 to stop that severity counting.

Fields: Critical item [25], Warning item [8], Info item [2].

### Risk score weights

The points each posture or security signal adds to a host's 0 to 100 risk score, one
field per signal (offline 25, a critical CVE 8, the firewall off 14, and so on).
Signals marked "(each)" count every occurrence and may be capped. Set one to 0 to leave
that signal out.

### Reliability score weights

The points each signal adds to a host's 0 to 100 failure-likelihood score, one field
per signal (a failing SMART status 40, growing reallocated sectors 25, and so on). Some
are capped. Set one to 0 to leave that signal out.

### Capacity & forecast

The days-to-full at which a disk's fill forecast warns or goes critical (the same
verdict everywhere: Needs Attention, the Checks page and the disk-health colour), the
pending-update count that warns, and how long a host counts as recently out of memory
after an OOM kill.

Fields: Disk fill ETA crit ≤ (days) [7], Disk fill ETA warn ≤ (days) [21], Pending
updates warn ≥ [20], Recent-OOM window (s) [86400].

### Containers & SNMP

How many container restarts alert or mark a container as restarting, and the fleet's
default SNMP CPU limits. A host's own threshold override wins.

Fields: Restart delta ≥ (alert) [1], Restart count ≥ (restarting) [5], SNMP CPU warn %
[75], SNMP CPU crit % [90].

### Monitoring cadence

How long a short-lived Needs-Attention item stays, the after-hours window, how many
failed pings make an agentless host offline, how many GitHub issues one poll may open,
how far a metric must fall back before it counts as recovered, and the shortest time a
host counts as online.

Fields: NA event TTL (hours) [24], After-hours window (hours) [24], Agentless ping
fails → offline [2], GitHub issues per poll [10], Metric recovery buffer (pts) [5], Min
online TTL (s, flap floor) [150].

### Compliance & CIS

The windows the compliance report looks back over, the CIS disk and swap ceilings, and
the lowest DMARC pass rate that counts.

Fields: Compliance TLS expiring (days) [21], Compliance lookback (days) [30], CIS disk
under % [90], CIS swap under % [80], DMARC min pass % [100].

### RemotePower self-health

What turns the top bar's health pill for the RemotePower server itself: load above cores
times the ratio, memory use, and the share of hosts online.

Fields: High-load ratio (× cores) [2], Memory warn % [90], Hosts online warn % [80].

### Reliability tuning

When a host counts as unstable (returns to online within a window), the reboot and wear
limits that feed the failure-likelihood score, and how much history is kept.

Fields: Unstable returns ≥ [3], Unstable window (days) [7], Reboot churn ≥ [3], Wear
high % (reliability) [85], Monitor checks kept [300], Command history rows kept [200].

### Forecast & CVE tuning

Decimal thresholds: the R² floor below which a disk-fill date is not projected, the
saturation ceiling and forecast floor for memory, swap and CPU load, the daily trends
that mark a disk or host as getting worse, and the CVSS score bands.

- A **ceiling** is the level that counts as a problem. A **floor** is the level below
  which RemotePower does not project, so a host that is nowhere near trouble does not
  get a date.
- **Realloc growth/day** and **Health decline/day** are the trends that raise the
  reliability score.
- The **CVSS** fields set where a score becomes critical, high or medium.

Fields: Disk-fill R² floor [0.5], Memory saturation ceiling % [90], Memory forecast
floor % [60], Swap saturation ceiling % [80], Swap forecast floor % [5], CPU load
saturation ceiling % [100], CPU load forecast floor % [50], Realloc growth/day [0.05],
Health decline/day [0.5], CVSS ≥ critical [9.0], CVSS ≥ high [7.0], CVSS ≥ medium [4.0].

## Notes

- Grade and level cutoffs are **clamped to stay descending**. A slip such as *good* below
  *fair* cannot invert the ladder.
- The server delivers the cutoffs the dashboard uses with each page load, so there is one
  source of truth and the browser never re-hardcodes them.
- Defaults are conservative, so an untouched install behaves as the product always has.
- Hosts can override many of these with their own **Metric thresholds** in the host
  drawer. The host's value wins.

*Related:* [alert-tuning.md](alert-tuning.md) · [alerts.md](alerts.md) ·
[monitors.md](monitors.md) · [settings.md](settings.md)

## Preview impact

Every field on this page applies **fleet-wide the moment you save**, and the checks
engine recomputes for every host on the next read. Dropping `disk_warn_percent` from 90
to 80 on a 400-host fleet is a hundred simultaneous new breaches, a Needs-Attention
avalanche and a paging storm. The way back is **Settings → Advanced → Configuration
history**, which restores the previous configuration.

**Preview impact** answers the question first. It recomputes every host's checks against
the values currently in the form, without saving anything, and reports which checks would
start breaching, which would stop, how many hosts each affects, and a few example host
names.

- It drives the **real** checks engine against the proposed values, not a separate copy
  of the rules.
- **It only covers the thresholds the checks engine reads.** Many parameters fire through
  the metric, risk, scoring or attention engines. The preview lists those separately as
  "could not be previewed here", so "no host-check changes state" is never a promise that
  the change is harmless. Review those by hand.
- Only hosts within your role scope are counted.
- Alerts **already open** are not resolved by a threshold change. They clear on their own
  recover events, or by muting them under Monitoring → Tuning. A preview showing "40
  host-checks would stop breaching" is about future firing, not about the inbox emptying.

`POST /api/config/threshold-preview` takes the same body as `POST /api/config` and
returns `changed`, `newly_breaching`, `newly_passing`, `evaluated` and `not_evaluated`.
