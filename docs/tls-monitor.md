# TLS / DNS expiry monitor

*Introduced in v1.11.0.*

A lightweight watchlist of `(hostname, port)` pairs the server probes
periodically. Each probe records cert expiry, issuer, subject, SAN
list, DNS A/AAAA records, and any errors at the DNS / TLS / verify
layers. Threshold-based alerting via the existing webhook plumbing.
Stdlib-only — no extra dependency beyond what's already in
RemotePower.

---

## Adding a target

On the TLS / DNS page, click **+ Add target**:

- **Hostname** — required, normalised to lowercase
- **Port** — defaults to 443
- **Warn (days)** — show as amber when this close to expiry. Default 14.
- **Critical (days)** — show as red. Default 3. Cannot exceed warn.
- **Label** — optional, free text. Used in alert messages.

The target gets an opaque `tls_<hex>` ID. Until the first probe
runs, the row's status is "unknown" and most fields are blank.

Click **Scan now** to run a synchronous probe immediately, or wait
for the next scheduled probe — the server re-probes each target
automatically about every 6 hours (bounded to 10 targets / 15 s per
sweep pass, so large watchlists drain over a few passes).

---

## How probing works

For each target, the server runs:

1. **DNS lookup** — `getaddrinfo(host, None, SOCK_STREAM)`. The
   resolved A/AAAA addresses are stored. Failures become
   `dns_error` and stop further work for that target.
2. **TCP connect** — to `host:port` with a 5s timeout.
3. **TLS handshake** — wrapped socket with `check_hostname=False`,
   `verify_mode=CERT_NONE` so we get the cert even if it doesn't
   match the hostname or has a broken chain. 5s timeout.
4. **Cert parsing** — extract notAfter, issuer, subject, SAN.
5. **Verification pass** — separate handshake with the system
   trust store. Errors here become `verify_error` (rather than
   `tls_error`) so you can distinguish "cert is expired" from
   "cert is fine but issued by an internal CA."

Each probe is bounded at ~10 seconds in the worst case (5s connect
+ 5s handshake) plus a separate verification pass of similar cost.
For 200 targets that's potentially ~30 minutes synchronously,
which is why the cron model exists — `Scan now` is fine for ad-hoc
checks but you don't want to fire it from the dashboard with a
huge target list.

---

## Statuses

The page displays one of:

- **● ok** (green) — cert valid, more days left than warn threshold
- **● warn** (amber) — within warn but more than crit days
- **● critical** (red) — within crit days
- **● error** (red) — DNS failure, connection failure, or
  unparseable cert

The verification pass's outcome shows separately as a
`verify_error` field in the detail modal but doesn't change the
overall status — it's possible to have a perfectly valid
self-signed cert with `verify_error: "self signed certificate"`,
and that's fine if you're using internal CAs deliberately.

---

## API

`GET /api/tls/targets` — joined view, watchlist + last results:

```json
[
  {
    "id": "tls_abc123",
    "host": "remotepower.example.com",
    "port": 443,
    "label": "",
    "warn_days": 14,
    "crit_days": 3,
    "last_check": 1714377550,
    "expires_at": 1722000000,
    "days_left": 88,
    "status": "ok",
    "addresses": ["192.0.2.10"],
    "issuer": "CN=Let's Encrypt R3, O=Let's Encrypt, C=US",
    "subject": "CN=remotepower.example.com",
    "san": ["remotepower.example.com"],
    "dns_error": "",
    "tls_error": "",
    "verify_error": ""
  }
]
```

Sorted by status (critical / warning first), then alphabetically
by host.

`POST /api/tls/targets`:

```json
{"host": "example.com", "port": 443, "warn_days": 14, "crit_days": 3, "label": ""}
```

Returns `{"ok": true, "id": "tls_<hex>"}`.

`DELETE /api/tls/targets/{id}` — removes from the watchlist and
deletes any cached result for that ID.

`POST /api/tls/scan` — probes every target synchronously. Returns
`{"ok": true, "scanned": <int>}`. Admin only because it triggers
N outbound connections from the server. Audit-logged as
`tls_scan` with the target count.

---

## Scheduling

The server schedules probes itself: `run_tls_scan_if_due()` rides the
same maintenance cadence as every other monitor (it runs opportunistically
on request traffic, or from the out-of-band scheduler when that is
enabled). Each target is re-probed once its last result is older than
6 hours; threshold-crossing targets fire the `tls_expiry` webhook/alert
edge-triggered, honouring the per-target warn/critical days.

No cron entry is required.

## CT watch (certificate-transparency monitoring)

The TLS page also carries a **CT watch** card: a list of domains polled
against [crt.sh](https://crt.sh)'s Certificate-Transparency index (~6h
cadence, same opportunistic scheduling as the expiry probes). It answers a
different question than expiry monitoring: **"was a certificate issued for my
domain that I didn't request?"** — the signal for compromised DNS, a leaked
ACME account, rogue CA issuance, or shadow-IT wildcards.

- One domain per line; empty list = feature off. Saved in config
  (`ct_watch_domains`), no separate store to manage.
- The **first successful check per domain baselines silently** (every
  historical cert is marked seen, no alerts). After that, any unseen
  certificate raises a `ct_new_certificate` alert (medium) carrying the
  domain, issuer, CN and serial.
- crt.sh is slow and occasionally down: a domain that fails 3 checks in a row
  backs off for 24 h, and each sweep polls at most 3 domains inside a strict
  wall-clock budget so the cadence can't stall request traffic.
- Alert storms are capped — a bulk reissue produces at most 20 events per
  sweep; the rest are still recorded as seen.

Expected noise: normal Let's Encrypt renewals appear as new issuance. If a
domain renews often, that's a few alerts per quarter — mute the pair from the
alert if you only care about unexpected issuers.

## Cron / systemd (optional, legacy)

The standalone `remotepower-tls-check` runner predates the built-in
schedule. Keep it only if the server receives zero traffic for long
stretches AND you don't run the out-of-band scheduler. Suggested cron
entry every 6 hours:

```
0 */6 * * * www-data /var/www/remotepower/cgi-bin/remotepower-tls-check
```

Or as a systemd timer in
`/etc/systemd/system/remotepower-tls-check.timer`:

```ini
[Unit]
Description=RemotePower TLS expiry probe

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

with the corresponding service unit:

```ini
[Unit]
Description=RemotePower TLS expiry probe
After=network-online.target

[Service]
Type=oneshot
User=www-data
ExecStart=/usr/bin/python3 /var/www/remotepower/cgi-bin/remotepower-tls-check
Environment=RP_DATA_DIR=/var/lib/remotepower
StandardOutput=journal
StandardError=journal
```

Then `systemctl enable --now remotepower-tls-check.timer`.

The script exits 0 on success or partial failure — it logs issues
to stderr but doesn't fail the cron job. Check the journal
(`journalctl -u remotepower-tls-check`) for output.

---

## Internal vs. external probing

The server probes from its own network position. That works fine
for any target reachable from there — public internet hosts,
cloud-hosted services, anything visible to the RemotePower box.

For internal-only certs (a `.lan` host on a different subnet, an
IPMI cert on a management VLAN the server can't reach), the probe
will fail with a connect error. There's no agent-based probe in
v1.11.0; the workaround is either:

- Make the host reachable from the RemotePower server (VLAN
  routing, jump host, whatever)
- Put a separate RemotePower instance on the internal network and
  query its `/api/tls/targets` endpoint from your monitoring
- Run the probe script on a different machine that does have
  network access (it's portable — just needs `tls_targets.json`
  in `RP_DATA_DIR` on whichever box runs it)

A "designated probe agent" feature, where one chosen agent does
the TLS probes for an internal subnet, was discussed for v1.11.0
and deferred. May come back if there's demand.

---

## Troubleshooting

**"DNS lookup failed."** Check from the server's command line:
`getent hosts your-target.example.com`. Same view as the probe.

**"connection failed: [Errno 111] Connection refused."** Either
the host is down, the port is wrong (default 443 — non-HTTPS
services need an explicit port), or a firewall is in the way.

**"TLS error: ..." but the host works in browsers.** Most often
the host requires SNI for a non-default vhost. The probe sends
SNI by default (passes `server_hostname=host`), so this should
work; if it doesn't, the cert chain might require an
intermediate the system trust store doesn't know about.

**"verification failed: self signed certificate in certificate
chain"** for an internal CA. Expected — the probe still records
the expiry just fine. The page shows green for the expiry status
because the cert is valid; the verification error appears in the
detail modal as a separate amber-coloured note.

**"Days left" is negative.** The cert has expired. The status
should already be `critical`, but the days_left field shows the
actual gap so you know how long it's been. (-3 means three days
ago.)

**Scan timed out from the dashboard.** With many targets, "Scan
now" takes longer than the fcgiwrap timeout (typically 30s).
Either trigger the cron script directly via SSH, or split the
watchlist and run partial scans.
