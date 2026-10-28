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
