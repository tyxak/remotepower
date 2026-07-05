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
`disk_failure_predicted` alert.
