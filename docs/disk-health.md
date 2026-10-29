# Predictive Health

**Hardware → Predictive Health** surfaces hardware that is *predicted* to be
at risk before it fails — most urgent first:

- **Disks** — the reactive SMART verdict plus trends in reallocated and
  pending sectors, and SSD wear level. A disk whose reallocated count is
  *growing* ranks above one with a static count.
- **Unstable hosts** — hosts restarting unusually often (reboot-frequency
  anomaly), which often precedes PSU/RAM/thermal failure.

Tracked/unstable disk state also appears in the host drawer's SMART view.
Unmonitored hosts are shown and flagged; only monitored hosts raise the
`disk_predict_fail` alert.

## Naming your disks *(v7.4.3)*

A host with eleven drives, several of the same model, lists them as `/dev/sda` to
`/dev/sdk`, and the letters can change after a reboot or a controller change. Give a
drive a name and it keeps it. Open the host, go to the **Audit** tab, expand **Health &
hardware** and fill in **Disk names** under the SMART table.

- The name is kept against the drive's **serial number**, so it follows the drive when
  its letter changes. A disk that reports no serial number cannot be named.
- It appears where the letter was: in the SMART table, on this page, in the *SMART
  failure* and *Disk predicted to fail* alerts (`Pool disk 2 (/dev/sdd, sn WD-1234)`),
  in Needs attention and in the reasons on the reliability card. The letter and the
  serial always stay next to the name.
- Administrators and roles with an action permission can set names. Everyone who can
  see the host sees them.
- An empty box removes the name. Deleting a host deletes its names. A drive that moves
  to another host starts without a name there.
- From a script: `PUT /api/devices/{id}/disk-names` with
  `{"names": {"<serial>": "<name>"}}`. A serial the host does not report is left out and
  listed under `ignored`.

## Disk I/O *(v7.4.3)*

Which drive is saturated, or slow? The Linux agent reads the kernel's disk counters on
every report and works out, for each whole disk and each RAID array, how much of the
interval it had a request in flight, how much it read and wrote, how many requests it
served and how long a request took on average. Partitions, logical volumes, loop, RAM and
optical drives are left out, so a volume is not counted twice with its disk. At most 32
disks are listed, the busiest first.

Open the host, go to the **Audit** tab, expand **Health & hardware** and look at **Disk
I/O**. Each disk has a row with a trend of the last hour, and a disk you named (see above)
shows its name. The busy figure turns amber or red when the disk is over a line.

### An alert for a disk that stays busy

A drive pinned at 100% for minutes often shows up here before SMART changes: a failing
disk, a stuck scrub or a runaway job. Set the lines under **Settings → Alert parameters →
Disk activity**:

- **Disk busy warn %** and **Disk busy crit %**. Both are off at 0. With only a warning
  line the disk never goes critical. With only a critical line, that line is also the
  warning.
- **Reports in a row** (5 unless you change it). A disk has to be over the line this many
  reports in a row, so a scrub or a backup that pins it for one minute does not alert.

A host can have lines of its own under **Metric thresholds** in its menu (1 to 99). Its
line wins over the fleet's, and an empty box follows the fleet.

You get one alert for each disk (`metric_warning` or `metric_critical`, with the disk as
its target). It closes when the disk drops under the line, when you turn the line off and
when the disk is no longer reported. It is muted, held by a maintenance window and listed
in Needs attention like the other disk problems. A report that carries no disk figures,
from an agent that does not send them, neither alerts nor closes anything.

From a script: `GET /api/devices/{id}/hardware` has a `diskio` list with the latest
reading, the last 60 samples and the lines for each disk.

## Temperature lines for each drive *(v7.4.4)*

A hard disk, a SATA SSD and an NVMe drive run at different temperatures, so one pair of
numbers cannot suit all three. Set a warning line and a critical line, in °C, and a drive
that reaches one raises an alert.

Before this release a drive's temperature was judged only by the fleet's hot and critical
pair (75 and 85 °C unless you changed them), in the risk score and on the Thermal page, and
no alert came from it. That has not changed: the risk score and the Thermal page still judge
every sensor, drives included, against that pair. The lines on this page add the alert, the
colour of the *Temp* column in the SMART table and a line in Needs attention.

### Which line applies

For the warning line and for the critical line, one at a time, the first of these that holds
a number wins:

1. **The drive's own line,** kept against its serial number, so it follows the drive when
   its letter changes. Administrators set it on the host's Hardware tab, in the two boxes
   beside the drive's name.
2. **The host's line for the drive's type** (hard disk, SATA SSD or NVMe), under **Metric
   thresholds** in the host's menu.
3. **The host's line for any drive,** in the same place.
4. **The fleet's line for the drive's type,** under **Settings → Alert parameters → Drive
   temperature**.
5. **The fleet's line for any other drive,** in the same place.

So a host that sets only a warning line keeps the fleet's critical line, and an empty box
follows the level below it, shown in grey. Every line is off until you set it, and a drive
with no line anywhere is not judged, so an upgrade alerts on nothing new. With only a
warning line a drive never goes critical; with only a critical line, that line is also the
warning. A warning line above the critical one, which two levels can produce between them,
is brought down to it.

A hard disk at 45 and 50, a SATA SSD at 65 and 70 and an NVMe drive at 70 and 80 is four
numbers in the fleet's section and nothing on the hosts.

### How a drive's type is found

The Linux agent reads it from `smartctl`: a spindle speed in `Rotation Rate` is a hard disk,
*Solid State Device* is a SATA SSD, and a drive at `/dev/nvme*` is NVMe. The type shows next
to the drive's serial number in the names box. An older Linux agent says nothing, and the
server then tells an NVMe drive by its name. A drive whose type cannot be told, such as one
behind a USB bridge that does not pass the line on, uses the lines for any other drive. The
Windows agent does not send a type yet, so its drives use those too; macOS hosts report no
SMART data.

### The alert

A drive over a line raises one alert for that drive (`metric_warning` or `metric_critical`,
with the serial number as its target), for example *Drive Pool disk 2 (/dev/sdd, sn WD-1234)
CRITICAL on nas01: 52°C*. It is judged on every hardware report, about every five minutes, so
an alert can arrive that much after the drive crosses the line.

- It closes when the drive drops far enough under the warning line: the nearer of five
  degrees and a tenth of the line, the rule the other metrics use, so a drive hovering at the
  line does not open and close it.
- A drive that is asleep reports no temperature and keeps whatever alert it had. A reading
  of 0 or above 150 is noise and is ignored.
- A drive missing from three reports in a row is taken to be gone and its alert closes.
  Turning the lines off closes it on the next report.
- It is muted, held by a maintenance window and listed in Needs attention like the other
  disk problems. Renaming the drive while it is hot does not leave the alert open.

### From a script

- `PATCH /api/devices/{id}/metric-thresholds` takes `drivetemp_warn_c` and `drivetemp_crit_c`
  (any drive) and the same with `hdd`, `ssd` or `nvme` after `drivetemp_`, each 1 to 150
  with the warning below the critical line. A `null` removes one. `drivetemp_per_serial` is
  `{"<serial>": {"warn": 45, "crit": 50}}`; it changes the drives it names and leaves the
  rest, and `null` for a drive, or for one of its numbers, removes it. A host keeps at most
  128. **Reset to defaults** in the host's Metric thresholds removes all of this host's lines.
- `GET /api/devices/{id}/hardware` gives each drive a `lines` object: its `media`, the `warn`
  and `crit` it is held to (`null` for none), what it would `inherit` and its `own` lines.
- The fleet's lines are the eight `drivetemp_*_c` keys of `POST /api/config`; 0 or empty is off.

## Host reliability prediction *(v6.2.0)*

The page's third card, **Hosts likely to fail**, folds every failure signal into
one composite score per host (0–100, higher = more likely to fail) with an
explainable factor breakdown — each factor names itself, its point contribution
and why.

### Reliability is not risk

RemotePower carries two 0–100 scores and they answer different questions:

| Score | Question | Inputs |
|---|---|---|
| **Risk** (`/api/risk`) | *How exposed is this host?* | CVEs, world-open ports, policy violations, EOL, lifecycle |
| **Reliability** (`/api/reliability`) | *How likely is it to **break**?* | dying hardware |

They are separate. A fully-patched server with a failing disk is
**low-risk and low-reliability** — merging the two into one number would hide
exactly that host.

### What feeds it

No new collection: every input was already being stored.

| Signal | Source | Contribution |
|---|---|---|
| SMART verdict | `hardware.json` | the drive says it is failing — believe it |
| Reallocated sectors **growing** | `smart_history.json` (~6 months daily) | the predictive one: a disk with 4 reallocated sectors that has had 4 for a year is fine; one that went 0 → 4 this month is on its way out |
| Pending sectors / wear / NVMe spare | `hardware.json` | remap pressure, spent endurance |
| ECC memory errors | posture state | an **uncorrectable** error means the DIMM could *not* fix it — scored far above a corrected one |
| Reboot churn | `uptime.json` | a box that keeps coming back has been going away |
| Health-score trajectory | `health_history.json` (~6 months daily) | is this host getting *worse*? |
| Thermals, recent OOM | `hardware.json`, sysinfo | heat kills hardware |

Only **high** and **critical** hosts raise a Needs-Attention card. A low bar
becomes noise, and a noisy predictor is one people learn to ignore — which is
worse than no predictor at all. The card is muteable.

### What is *not* scored

**Unit flapping.** `services.json` keeps systemd's `NRestarts` as a *cumulative*
counter and stores only the latest value — the flap **delta** the `unit_flapping`
event fires on is computed in flight and never persisted. Scoring on
`restarts > 0` would mark every host that ever deployed a service as failing,
while a crash-looping unit that reset its counter scored zero. An
honest omission beats a confidently wrong number; persisting a daily delta would
make this a real factor.
