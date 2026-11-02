# Predictive Health

**Hardware → Predictive Health** surfaces hardware that is *predicted* to be
at risk before it fails, most urgent first. It has three cards:

- **Disks at risk** lists a disk with its risk, wear, an ETA once there is enough history,
  and the signals behind the rating. It combines the SMART verdict with trends in
  reallocated and pending sectors and the SSD wear level. A disk whose reallocated count is
  *growing* ranks above one with a static count.
- **Frequently restarting hosts** lists hosts that restart unusually often (restarts in the
  last seven days, and the last boot reason). Repeated restarts often come before a power
  supply, memory or thermal failure.
- **Hosts likely to fail** gives each host one score that folds every failure signal together
  (see [Host reliability prediction](#host-reliability-prediction)).

The same disk state shows in the host drawer's SMART table (**Audit → Health & hardware**).
Unmonitored hosts are shown and flagged, but only monitored hosts raise the
`disk_predict_fail` alert.

## Naming your disks

A host with eleven drives, several of the same model, lists them as `/dev/sda` to
`/dev/sdk`, and the letters can change after a reboot or a controller change. Give a
drive a name and it keeps it. Open the host, go to the **Audit** tab, expand **Health &
hardware**, fill in **Disk names** under the SMART table and click **Save names**
(administrators see **Save names and lines**).

- The name is kept against the drive's **serial number**, so it follows the drive when
  its letter changes. A disk that reports no serial number cannot be named.
- It appears where the letter was: in the SMART table, on this page, in the *SMART
  failure* and *Disk predicted to fail* alerts (`Pool disk 2 (/dev/sdd, sn WD-1234)`),
  in Needs attention and in the reasons on the reliability card. The letter and the
  serial always stay next to the name.
- Administrators and roles with an action permission can set names. Everyone who can
  see the host sees them. Without that permission the form is not shown.
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
I/O**. Each disk has a row with a trend of its last 60 reports, and a disk you named (see
above) shows its name. The busy figure turns amber or red when the disk is over a line.

**How often it moves.** The agent sends this with its system information, which goes with
every tenth poll: about every 10 minutes at the default poll interval. So each figure is an
average over the gap between two reports, and the table says so under its heading
("average over the last 10 min, reported 4 min ago"). A burst of I/O that is over in a
minute barely shows, and a disk that is busy now does not move the table until the next
report. The trend holds 60 reports, about 10 hours at that rate. Monitor → Host metrics
says the same about its own figures, with "Reported 7m ago" under each host's name.

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

The lines give you the alert, the colour of the *Temp* column in the SMART table, a line in
Needs attention, and the drive's place on the [Thermal](thermal.md) page and in the risk score.
A drive with no line at any level is judged by the fleet's hot and critical pair for sensors
(75 and 85 °C unless you changed them under **Settings → Alert parameters → Thermal & GPU**), and
raises no alert. The sensors of a drive's own chip follow the same lines: see
[Thermal health](thermal.md#a-drives-own-sensors-and-limits-that-are-not-limits).

### Which line applies

For the warning line and for the critical line, one at a time, the first of these that holds
a number wins:

1. **The drive's own line,** kept against its serial number, so it follows the drive when
   its letter changes. Administrators set it in **Disk names** (host → **Audit** →
   **Health & hardware**), in the **Warn** and **Crit** boxes beside the drive.
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

The hardware sensor of a disk read by the `drivetemp` driver is held to the same lines as the
disk's own SMART reading. The agent names the disk behind the sensor, and the sensor takes
that disk's lines, including a line kept against its serial number. See
[thermal.md](thermal.md#a-drives-own-sensors-and-limits-that-are-not-limits).

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

## Host reliability prediction

The page's third card, **Hosts likely to fail**, folds every failure signal into
one composite score per host (0–100, higher means more likely to fail) with a
factor breakdown. Each factor names itself, its points and why.

The levels are **critical** from 70, **high** from 45 and **medium** from 20 by default.
Change them under **Settings → Alert parameters → Reliability levels**, and the weight of each
factor under **Reliability score weights**.

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
| SMART verdict | The host's hardware report | The drive says it is failing. RemotePower believes it. |
| Reallocated sectors **growing** | Daily SMART history (about 6 months) | The predictive one. A disk with 4 reallocated sectors that has had 4 for a year is fine. One that went 0 → 4 this month is on its way out. |
| Pending sectors, wear, NVMe spare | The host's hardware report | Remap pressure and spent endurance |
| ECC memory errors | The host's memory error counters | An **uncorrectable** error means the DIMM could *not* fix it. It scores far above a corrected one. |
| Reboot churn | Uptime history | A box that keeps coming back has been going away. |
| Health-score trajectory | Daily health-score history (about 6 months) | Is this host getting *worse*? |
| Thermals, recent OOM | Hardware report and system information | Heat kills hardware. |

Only **high** and **critical** hosts raise a Needs Attention card. A low bar
becomes noise, and a noisy predictor is one people learn to ignore, which is
worse than no predictor at all. You can mute the card. Hosts you do not monitor are scored
but raise no card.

### What is *not* scored

**Unit flapping.** The service data keeps systemd's `NRestarts` as a *cumulative*
counter and stores only the latest value. The flap **delta** that the `unit_flapping`
event fires on is worked out as it arrives and never saved. Scoring on
`restarts > 0` would mark every host that ever deployed a service as failing,
while a crash-looping unit that reset its counter scored zero. An
omission is better than a confidently wrong number.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| A drive has no name box | It reports no serial number (typical behind some RAID controllers and USB bridges), or you lack permission. Only administrators and roles with an action permission see the form. |
| The Disk I/O table is missing | Only the Linux agent sends it. Wait for the next system-information report (about 10 minutes at the default poll interval). |
| A drive over its line did not alert | Check that the host is monitored, that a line is set at some level, and that the drive is awake. A sleeping drive reports no temperature. |
| The temperature alert came late | It is judged on each hardware report, about every five minutes. |
| A drive's type shows nothing | An older Linux agent sends no type. Update the agent, or the server guesses from the name (`/dev/nvme*`). |
| A host looks fine but scores high on reliability | Open the **Why** column. Reboot churn and a falling health score count even when the disks are healthy. |

## See also

[thermal.md](thermal.md), [storage.md](storage.md), [alert-parameters.md](alert-parameters.md),
[risk.md](risk.md), [forecast.md](forecast.md).
