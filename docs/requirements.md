# System requirements

Minimum and recommended hardware for the **server**, plus what a managed
**agent** costs on the hosts it watches. These are architecture-grounded
estimates (what each component actually does), not lab-benchmarked
certified numbers — watch real usage on your box (Server status page →
Serving & runtime panel, or plain `top`/`free`) and adjust from there.

## Server

The default single-node install (`install-server.sh` / `docker compose up`,
no flags) runs five things on one box: nginx, the gunicorn/Flask app server,
PostgreSQL, an out-of-band maintenance scheduler, and a co-located scanner
satellite (nmap/nikto/nuclei/lynis, etc.).

| Tier | vCPU | RAM | Disk | Backend | Fits |
|---|---|---|---|---|---|
| **Minimum** (small homelab) | 1–2 | 2 GB | 10 GB | SQLite or flat JSON (`--no-postgres`) | a handful of devices |
| **Recommended** (default) | 2–4 | 4 GB | 20–40 GB | PostgreSQL (default) | ≤200 devices out of the box, no tuning needed |
| **Recommended, tuned** (same box) | 2–4 | 4 GB | 20–40 GB | PostgreSQL | 200–1,000 devices — raise the poll interval + gunicorn worker/thread count, no new hardware ([scaling.md](scaling.md) Steps 1–3) |
| **Heavy fleet** (1,000+) | see below | see below | single-digit GB+ with retention tuned | PostgreSQL (+ HA) | still single-box-capable up to ~5,000 on strong-enough hardware; see [scaling.md](scaling.md) |

This is a genuinely capable default, not a toy: [scaling.md](scaling.md)'s
own words are "[Postgres + poll interval] alone carries most fleets to
several thousand agents on a single node" — the same one box in the
**Recommended** row above, just with the interval and worker/thread knobs
turned. Going multi-node/HA is a later-stage optimization for real scale
(5,000+, or specific latency/availability requirements), not something a
"few hundred devices" homelab or SMB fleet needs to reach for. Use
**[scaling.md](scaling.md)'s capacity table** for the exact fleet-size →
tuning-step mapping once you're past a few hundred devices.

### Where that comes from, per component

- **gunicorn (`--workers 4 --threads 8` default)** — each worker is a real
  process; count on roughly 100–150 MB resident per worker with Flask + the
  app's imports loaded, so ~500 MB–1 GB for the app server at the default
  worker count. `scaling.md`'s rule of thumb (workers ≈ CPU cores) is why the
  recommended tier assumes 2–4 cores — fewer workers on a 1–2 core box is
  fine for a small homelab fleet, just lower request concurrency.
- **PostgreSQL** — comfortable in a few hundred MB of `shared_buffers` at
  homelab/SMB scale; data on disk stays small with sane retention (see
  `scaling.md` Step 6) — low hundreds of MB for a few dozen devices, growing
  with fleet size and how long you keep metric history/logs/audit trail.
  Skip it entirely (`--no-postgres`) on the smallest installs — the flat
  JSON/SQLite backend has no separate daemon or shared-buffer footprint.
- **nginx** — negligible, a few tens of MB.
- **Scheduler** (`remotepower-scheduler.service`) — a lightweight Python
  process, idle between cadence sweeps; tens of MB.
- **Scanner satellite** — idle most of the time; CPU spikes during a
  scheduled scan window (nmap/nuclei/lynis are the heavy moments, not a
  steady-state cost). Give it real CPU headroom if you scan a large fleet
  on an aggressive schedule; a homelab-sized scan window is brief.
- **Disk growth** is retention-driven, not fleet-size-driven per se —
  `metric_samples_retention_days` and the other retention caps (Settings →
  Data retention) bound it directly. 30–90 days of metric history is
  typical; shrink the window on tight disk.

Optional extras (webterm daemon, the experimental agent push-channel
daemon — see [push.md](push.md)) each add one more lightweight async
process if you install them; neither is part of the default stack.

## Agent

The agent is a small, mostly-stdlib Python script polling the server every
60 seconds by default — it is not a monitoring-agent-with-a-database. On a
managed host it's effectively free: idle CPU between polls, a handful of MB
of RAM, no persistent daemon overhead beyond one Python process. The
occasional heavier operations (a full package/CVE scan, an OpenSCAP
compliance run, an image-CVE trivy scan) are opt-in, scheduled, and run as
short-lived spikes on the *managed host itself* — they don't touch the
server's own resource budget above.

## Client browser

Nothing unusual — a modern browser tab. No build step, no heavy JS
framework; the dashboard is vanilla JS.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
