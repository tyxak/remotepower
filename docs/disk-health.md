# Predictive health

**Hardware → Predictive health** surfaces hardware that is *predicted* to be
at risk before it fails — most urgent first:

- **Disks** — the reactive SMART verdict plus trends in reallocated and
  pending sectors, and SSD wear level. A disk whose reallocated count is
  *growing* ranks above one with a static count.
- **Unstable hosts** — hosts restarting unusually often (reboot-frequency
  anomaly), which often precedes PSU/RAM/thermal failure.

Tracked/unstable disk state also appears in the device drawer's SMART view.
Unmonitored hosts are shown and flagged; only monitored hosts raise the
`disk_predict_fail` alert.

## Device reliability prediction *(v6.1.3)*

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

They are deliberately separate. A fully-patched server with a failing disk is
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

### What is deliberately *not* scored

**Unit flapping.** `services.json` keeps systemd's `NRestarts` as a *cumulative*
counter and stores only the latest value — the flap **delta** the `unit_flapping`
event fires on is computed in flight and never persisted. Scoring on
`restarts > 0` would mark every host that ever deployed a service as failing,
while a genuinely crash-looping unit that reset its counter scored zero. An
honest omission beats a confidently wrong number; persisting a daily delta would
make this a real factor.
