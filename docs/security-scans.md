# Pentest — how to run an authorized scan

Security Scans let you run a real vulnerability scan (nuclei / nikto / nmap)
against a host or website **you own**, and see the findings in the dashboard.

It is **white-hat only**: you can only scan hosts that are enrolled in
RemotePower, or domains/IPs whose ownership you have proven. The target is
always decided by the server — never typed into a scan freehand.

There are two one-time things to set up, then scanning is **3 clicks**.

---

## What you need

- An **admin** login (or a role with the **scan** permission).
- One spare Linux machine to act as the **scanner** (a small VM is fine). It
  needs **Docker** (or Podman) installed and network access to your targets.
  This keeps the scanning tools off your production hosts.

> Why a separate machine? The scanning tools are heavy and security-sensitive,
> so they live on one dedicated "scanner satellite", not on every server.

---

## Part 1 — Set up the scanner (one time, ~5 minutes)

### Step 1. Create a scanner token

1. In RemotePower, go to **Settings → API Keys** and create a key (role:
   **admin**). Copy it.
2. On any machine with `curl`, run this — replace `YOUR-SERVER` and `YOUR-API-KEY`:

   ```bash
   curl -s -X POST https://YOUR-SERVER/api/satellites \
     -H "X-Token: YOUR-API-KEY" \
     -H "Content-Type: application/json" \
     -d '{"name":"scanner-1","scanner":true}'
   ```

3. The reply contains a **token**. Copy it — it is shown only once:

   ```json
   {"ok": true, "id": "…", "token": "AbC123…", "scanner": true, "note": "…"}
   ```

### Step 2. Start the scanner

On your spare scanner machine (the one with Docker):

1. Copy the file `client/remotepower-scanner.py` from RemotePower onto it.
2. Run it — paste the token from Step 1:

   ```bash
   RP_SERVER_URL=https://YOUR-SERVER \
   RP_SATELLITE_TOKEN=PASTE-THE-TOKEN-HERE \
   python3 remotepower-scanner.py
   ```

3. You should see:

   ```
   [scanner] RemotePower scanner satellite v4.3.0 → https://YOUR-SERVER (runner=docker)
   ```

That's it — leave it running. It quietly waits for scan jobs. (To keep it
running forever, see **Run the scanner as a service** at the bottom.)

---

## Part 2 — Scan an enrolled host (the easy path, 3 clicks)

1. In the sidebar, open **Security → Pentest**.
2. **Search and pick the device** in the device search box (type a name, IP, or group).
3. **Pick a tool** (`nuclei` is the default and a good first choice).
4. Click **Queue scan**.

A row appears in the table with status **queued**. Within a few seconds the
scanner picks it up (**running**), and when it finishes the status becomes
**done** with finding counts (Crit / High / Med / Low).

5. Click the row (or **View**) to read the findings.

You're done. That is the whole loop.

---

## Part 3 — Scan a website / domain you own

Domains that aren't enrolled hosts need a **one-time ownership check** first
(the same idea as proving a domain to a TLS certificate authority).

1. On the **Pentest** page, find the **Verified web targets** box.
2. Type your domain or IP (e.g. `example.com`) and click **Add target**.
3. RemotePower shows you **two proofs** — do **either one**:

   - **DNS:** add a TXT record
     `_remotepower-scan-auth.example.com` with the value shown
     (a `rpscan-…` string), **or**
   - **File:** put the shown `rpscan-…` string in a file at
     `https://example.com/.well-known/remotepower-scan-authorization.txt`

4. Once the record/file is live, click **Verify**. The target flips to
   **verified**.
5. Click **Scan** next to the verified target. Findings show up exactly like
   Part 2.

> You only verify a target once. After that you can scan it whenever you like.

---

## Part 4 — Reading findings

Each finding shows a **severity**, a **title**, the **rule** that fired, and the
**evidence** (where it was found). Findings are sorted worst-first.

- **Critical / High** findings also raise an **alert** (Alerts inbox) and fire
  any notification channels you've configured (Slack, email, etc.), and appear
  in the dashboard activity feed.
- **Medium / Low / Info** findings stay on the Pentest page only — they won't
  page you.

The four stat cards at the top of the page show fleet-wide totals: how many
scans you've run, total Critical and High findings, and how many scans are
currently running or queued.

---

## On-host audit (lynis) — no scanner satellite needed

The tools above scan a host *from the network*. There's also an **on-host audit**
(`lynis`) that runs *inside* an enrolled host — checking local hardening (file
permissions, sshd/PAM config, sysctl, accounts) that a network scan can't see.

It's the easiest one to use: it runs on the host's **own agent**, so you don't
need a scanner satellite at all.

1. On the **Pentest** page, pick the device.
2. Set **Tool** to **lynis (on-host audit)**.
3. Click **Queue scan**.

The host's agent runs lynis (read-only) on its next check-in and reports the
findings back — warnings show as `medium`, suggestions as `low`. The host needs
`lynis` installed (`apt install lynis` / `dnf install lynis`); if it isn't, the
scan comes back `failed` with that note.

## Active (intrusive) scans — use with care

Everything above is **passive** (safe to run anytime). RemotePower also has an
**active** profile that runs heavier tools (`zap`, `wapiti`) and intrusive
checks — it **sends attack traffic** and can disrupt a fragile target. Because of
that, active scans have two extra guardrails:

1. On the Pentest page, set **Profile** to **active (intrusive)**.
2. Tick **"I'm authorized to actively scan this target"** (required — the scan is
   refused without it, and your name + time are recorded on the scan).
3. For an **enrolled host**, an active scan only runs during a **maintenance
   window** (open one under Monitoring → Maintenance) — or tick **"run now
   (override maintenance window)"** to proceed immediately. This stops a fragile
   production box from being fuzzed at peak hours.

Verified domains have no maintenance window, so for those the authorization tick
is all that's needed.

> Active scanning is powerful. Only run it against systems you operate, ideally
> in a maintenance window, and expect noise/load on the target.

## Troubleshooting

| What you see | What it means / fix |
|---|---|
| Scan stays **queued** forever | The scanner isn't running, or can't reach the server. Check Part 1 Step 2 is still running and `RP_SERVER_URL` is correct. |
| Status **failed**, error `runner not found: docker` | Docker isn't installed on the scanner machine. Install Docker, or set `RP_SCAN_RUNNER=nuclei` to use a locally-installed tool binary. |
| **"device address is in a blocked class"** when queueing | The host's address is loopback/link-local/cloud-metadata — those are blocked on purpose. Scan a host with a real LAN/public address. |
| **"scan target not found or not ownership-verified"** | You tried to scan a domain before clicking **Verify** (Part 3, step 4). |
| Verify keeps failing | The DNS TXT record hasn't propagated yet (wait a few minutes), or the `/.well-known` file isn't reachable over HTTP/HTTPS. Double-check the exact value matches. |
| Findings show `failed` with a timeout | The scan exceeded its time budget. Raise it: `RP_SCAN_TIMEOUT=1800` (seconds) on the scanner. |
| You don't see the **Pentest** page | Your role lacks the **scan** permission. Ask an admin (Settings → Roles). |

---

## Reference

**Tools:**
Passive profile — `nuclei` (templated web/network checks), `nikto` (web-server
misconfig), `nmap` (open ports + safe NSE scripts). Active profile adds `zap`
(full active web scan) and `wapiti` (web fuzzer), plus intrusive variants of the
others. `lynis` is an **on-host audit** (runs on the device's agent, not a
satellite — see above). See **Active (intrusive) scans** for the guardrails.

**Scanner environment variables** (set when starting the scanner):

| Variable | Default | Purpose |
|---|---|---|
| `RP_SERVER_URL` | — (required) | Your RemotePower URL |
| `RP_SATELLITE_TOKEN` | — (required) | The scanner token from Part 1 |
| `RP_SCAN_RUNNER` | `docker` | `docker`, `podman`, or a local binary name |
| `RP_SCAN_RATELIMIT` | `50` | Max requests/sec (be gentle on the target) |
| `RP_SCAN_TIMEOUT` | `900` | Per-scan time budget, seconds |
| `RP_SCAN_POLL_SECS` | `15` | How often it checks for new jobs |
| `RP_CA_BUNDLE` | — | Extra CA bundle if your server uses an internal CA |

**Run the scanner as a service** (so it survives reboots) —
`/etc/systemd/system/remotepower-scanner.service`:

```ini
[Unit]
Description=RemotePower scanner satellite
After=network-online.target docker.service

[Service]
Environment=RP_SERVER_URL=https://YOUR-SERVER
Environment=RP_SATELLITE_TOKEN=PASTE-THE-TOKEN-HERE
ExecStart=/usr/bin/python3 /opt/remotepower/remotepower-scanner.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then: `sudo systemctl enable --now remotepower-scanner`.

**Scripted install** — `packaging/scanner-setup.sh` does the above for you
(installs the script, writes the env file + systemd unit, enables it):

```bash
sudo RP_SERVER_URL=https://YOUR-SERVER RP_SATELLITE_TOKEN='…' \
    bash packaging/scanner-setup.sh
```

**Co-located on the server itself** — `install-server.sh` installs a scanner
satellite on the same node by default (single-node "enterprise" installs;
`--no-scanner` to opt out). It mints its own token directly and runs
`RP_SCAN_RUNNER=nuclei` against localhost, skipping the Docker-socket
requirement above entirely (no docker/podman needed — see
`packaging/scanner-setup.sh`'s header for why). This trades the isolation
this doc recommends (a separate machine) for a one-command install; the
standalone paths above remain the better-isolated option for anything beyond
a lab/small-fleet install.

---

## Is this safe / legal to run?

Yes, when used as intended: you may only scan assets you own and operate.
RemotePower enforces this for you — enrolled hosts are implicitly yours, and any
other target must pass the ownership check in Part 3. The server decides the
exact address that gets scanned; a scan can never be pointed at an arbitrary
third-party host. Every scan is recorded in the **Audit Log** (who, what, when).

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
