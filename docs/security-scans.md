# Pentest — how to run an authorized scan

**Security → Pentest** runs real vulnerability scans (nuclei, nikto, nmap,
wpscan, and the active-only zap and wapiti) against a host or website **you
own**, and shows the findings in the dashboard.

It is **white-hat only**. You can scan hosts that are enrolled in RemotePower,
or domains and IPs whose ownership you have proven. The server decides the
target. A scan is never pointed at an address you type in freehand.

There are two one-time things to set up. After that a scan takes a few clicks.

---

## What you need

- A login that may queue scans: an **admin**, or a role with the **scan**
  permission (Admin → Users & Roles → Custom roles). Adding and verifying web
  targets (Part 3) is admin-only.
- One spare Linux machine to act as the **scanner** (a small VM is fine). It
  needs **Docker** (or Podman) and network access to your targets. This keeps
  the scanning tools off your production hosts.

> Why a separate machine? The scanning tools are heavy and security-sensitive,
> so they live on a dedicated "scanner satellite", not on every server.

---

## Part 1 — Set up the scanner (one time, about 5 minutes)

### Step 1. Create a scanner token

1. In RemotePower, open **Admin → API Keys**, click **New key** and create a key
   with the **admin** role. Copy it.
2. On any machine with `curl`, run this. Replace `YOUR-SERVER` and
   `YOUR-API-KEY`:

   ```bash
   curl -s -X POST https://YOUR-SERVER/api/satellites \
     -H "X-Token: YOUR-API-KEY" \
     -H "Content-Type: application/json" \
     -d '{"name":"scanner-1","scanner":true}'
   ```

3. The reply contains a **token**. Copy it. It is shown only once:

   ```json
   {"ok": true, "id": "…", "token": "AbC123…", "scanner": true, "note": "…"}
   ```

The **New satellite** button under Settings → Integrations → Relay satellites
makes a relay for agents, not a scanner. Use the call above for a scanner.
RemotePower keeps up to 50 satellites.

### Step 2. Start the scanner

On the scanner machine (the one with Docker), either run the installer script,
which sets up a service for you:

```bash
sudo RP_SERVER_URL=https://YOUR-SERVER \
     RP_SATELLITE_TOKEN='PASTE-THE-TOKEN-HERE' \
     bash packaging/scanner-setup.sh
```

or run the worker by hand:

1. Copy `client/remotepower-scanner.py` from RemotePower onto the machine.
2. Run it with the token from Step 1:

   ```bash
   RP_SERVER_URL=https://YOUR-SERVER \
   RP_SATELLITE_TOKEN=PASTE-THE-TOKEN-HERE \
   python3 remotepower-scanner.py
   ```

3. You should see a line like this:

   ```
   [scanner] RemotePower scanner satellite v4.4.0 → https://YOUR-SERVER (runner=docker)
   ```

Leave it running. It waits for scan jobs and checks for new ones every 15
seconds. To keep it running across reboots, see **Run the scanner as a service**
in the reference below.

---

## Part 2 — Scan an enrolled host

1. In the sidebar, open **Security → Pentest**.
2. **Search and pick the host** in the host box (type a name, IP, group or tag,
   then click the match). Typing a name alone does not select it.
3. **Pick a tool**. `nuclei` is the default and a good first choice.
4. Click **Queue scan**.

A row appears in the table with status **queued**. Within about 15 seconds the
scanner picks it up (**running**). When it finishes the status becomes **done**,
with finding counts per severity (Crit, High, Med, Low, Info).

5. Click the row (or **View**) to read the findings.

That is the whole loop. The other controls in the toolbar:

| Control | What it does |
|---|---|
| **Tool** | `nuclei`, `nikto`, `nmap`, `wpscan (WordPress)`, `zap (active)`, `wapiti (active)`, **All tools** (one scan per tool in the chosen profile), or `lynis (on-host audit)`. |
| **Profile** | **passive** is safe to run any time. **active (intrusive)** sends attack traffic. See [Active scans](#active-intrusive-scans--use-with-care). |
| **Intensity** | **quick** is fast and shallow (nuclei reports medium and above, nmap checks the top 100 ports, nikto and wapiti stop after 3 minutes, zap runs its baseline). **full** is thorough (every severity, every port, the whole time budget, zap's full scan). |
| **vhost** | Scan a hostname on this host instead of its bare IP. It must be a verified web target (see Part 3). |
| **Any scanner satellite** | Pin the scan to one scanner, for example the one on the target's network segment. |
| **Clear** | Removes every finished scan (done, failed, cancelled) and its findings. Queued and running scans stay. |

The scan runs against the address the host last reported. A host with no known
address, or one whose address is loopback, link-local or a cloud-metadata
address, cannot be scanned. RemotePower keeps the 500 newest scans and drops
the oldest finished ones to make room.

---

## Part 3 — Scan a website or domain you own

Domains that are not enrolled hosts need a **one-time ownership check** first,
the same idea as proving a domain to a certificate authority. Only an admin can
add and verify targets, and only a role that is not limited to certain hosts can
scan them.

1. On the **Pentest** page, find the **Verified web targets** box.
2. Type your domain or IP (for example `example.com`) and click **Add target**.
3. RemotePower shows you **two proofs**. Do **either one**:

   - **DNS:** add a TXT record `_remotepower-scan-auth.example.com` with the
     value shown (an `rpscan-…` string), **or**
   - **File:** put the shown `rpscan-…` string in a file at
     `https://example.com/.well-known/remotepower-scan-authorization.txt`
     (plain HTTP is tried too, and redirects are not followed).

   An IP address has no DNS proof, so use the file.

4. Once the record or file is live, click **Verify**. The target flips to
   **verified**. DNS verification needs the `dnspython` package on the server.
   Without it, use the file proof.
5. Click **Scan** next to the verified target. Findings show up exactly like
   Part 2. **Schedule** sets up a recurring scan for it.

> You only verify a target once. After that you can scan it whenever you like.
> RemotePower keeps up to 200 targets.

---

## Part 4 — Reading findings

Each finding shows a **severity**, a **title**, the **rule** that fired, and the
**evidence** (where it was found). Findings are sorted worst first. A lynis
audit also shows its **Hardening index** (0 to 100) at the top.

A scan that finishes with no findings says what ran and what zero means for that
tool. A scan that did not complete shows **failed**, with the reason in the
tooltip of the status cell. Hover it.

**Alerts.** A scan you start yourself never raises an alert, because you are
already looking at the result. A **scheduled** scan that finishes with findings
raises a low-priority `scan_finding` alert in the Alerts inbox ("Scan findings
on web01: 1 critical, 3 high") and notifies the channels you enabled for that
event. You can switch it off under Settings → Notifications → Per-event
toggles. Findings of any severity are on the Pentest page either way.

The four cards at the top show totals across the scans you can see: running or
queued scans, critical findings, high findings, and the number of scans.
Critical and High findings from here also feed the [Security
Advisory](security-advisory.md), together with medium ones.

---

## Scheduled scans

The **Scheduled scans** box on the Pentest page repeats a scan on a cron. Pick
the host (or use a verified target's **Schedule** button), choose the tool,
profile and intensity in the toolbar, enter a five-field cron such as
`0 3 * * *` (daily at 03:00), and click **Add schedule**. Each schedule has
**Run now**, **Pause** or **Resume**, and a delete button. You can keep up to
100. A scheduled **active** scan needs the authorization tick when you create
it.

## Scheduled LAN discovery

The **Scheduled LAN discovery** box repeats a LAN scan from an enrolled host on
an interval, so the list of unmanaged hosts stays current. Pick the host in the
toolbar above, enter a subnet such as `192.168.1.0/24` and an interval (15 to
10080 minutes, default 60), and click **Add schedule**. Only admins can add or
remove these schedules, and you can keep up to 100. The hosts it finds appear
under **Fleet → Network → Unmanaged hosts on the LAN**, where **Add as host**
turns one into an agentless host.

---

## WordPress scanning (wpscan)

`wpscan` fingerprints a WordPress site and matches core, plugin and theme
versions against the WPScan vulnerability database.

**wpscan needs a hostname, not an IP.** WordPress answers on a vhost, so
scanning a host's bare address usually finds nothing. Select the enrolled host
that serves the site, then put the site's domain in the **vhost** box. The
scanner sends that as the `Host` header.

That vhost must be an **ownership-verified target** first. This is what stops a
host you own being used to scan somebody else's domain:

1. Under **Verified web targets**, add the domain.
2. Publish ONE of the two proofs it shows you: a DNS `TXT` record, or a file at
   the given path on the site.
3. Press **Verify**.

Once verified, the domain appears in the vhost box's suggestion list. You can
scan it either as a vhost on the enrolled host, or on its own with the target's
**Scan** button.

- **Passive** looks for vulnerable plugins and themes plus exposed config
  backups and database exports, using passive plugin detection.
- **Active** also lists **users** and probes plugin paths aggressively.
  Enumerable usernames are reported as a *medium* finding on their own. They
  are not a flaw, but they are the target list for the credential attack that
  starts most real WordPress compromises.
- **Password attacks are not available.** wpscan can brute-force logins. That
  is intrusive, trips account lockouts and floods the target's auth log, so
  RemotePower does not use it at any profile.

### The API token is needed to find vulnerabilities

Without a WPScan API token the scan still runs and still reports interesting
findings, but it **cannot match versions against the vulnerability database**.
It finds no vulnerabilities *whatever the state of the site*. A clean result in
that mode says nothing either way, so the scan detail view spells it out
instead of letting "0 findings" read as "safe".

On the **scanner machine**:

1. Get a free token at <https://wpscan.com/api>. The free tier allows a small
   number of API requests a day, enough for a handful of sites.
2. Add it to the scanner's environment file, which
   `packaging/scanner-setup.sh` creates at `/etc/remotepower/scanner.env`:

   ```
   RP_WPSCAN_API_TOKEN=<your-token>
   ```

   If you wrote the systemd unit by hand, add it there as another
   `Environment=` line.
3. `sudo systemctl restart remotepower-scanner`
4. Run the scan again.

The scanner reports with each result whether matching was available, so the scan
detail view tells you which mode a given run used. You never have to guess
whether an old clean result was a real one.

**Check that the token reached the process.** The scanner logs what it can do
when it starts:

```
journalctl -u remotepower-scanner -n 20 | grep capability
[scanner] capability wpscan_vuln_db: yes
```

If that says `NO` after you set the token, the variable is not reaching the
process. This usually means the unit was written by hand without an
`EnvironmentFile=/etc/remotepower/scanner.env` line (the example unit in the
reference below has one). Add that line, or put the token in the unit as an
`Environment=` line, then run
`sudo systemctl daemon-reload && sudo systemctl restart remotepower-scanner`.

### Keeping a scanner up to date

A scanner is a script copied onto another machine, so it does **not** update with
the server. Each one reports its version on every poll. The scanner list in the
scan form shows it next to the name and marks one that differs from the version
this server ships as **(outdated)**, with a hint under the form.

To upgrade, on the scanner machine:

```
sudo install -m 0755 remotepower-scanner.py /opt/remotepower/remotepower-scanner.py
sudo systemctl restart remotepower-scanner
```

A scanner showing "version unknown" is older than 4.4.0 (older ones do not
report a version) or has not polled since the server was updated.

### "Scan aborted" and "no findings"

wpscan exits cleanly and prints valid JSON when it gives up: the target is not
WordPress, a firewall blocked it, or the host was unreachable. RemotePower
reports those runs as **failed** with the reason, not as a clean scan. A
two-second scan that finds nothing is a signal, not an all-clear.

## On-host audit (lynis) — no scanner needed

The tools above scan a host *from the network*. The **on-host audit** (`lynis`)
runs *inside* an enrolled Linux host. It checks local hardening such as file
permissions, sshd and PAM settings, sysctl and accounts, which a network scan
cannot see.

It is the easiest one to use. It runs on the host's **own agent**, so you do
not need a scanner at all.

1. On the **Pentest** page, pick the host.
2. Set **Tool** to **lynis (on-host audit)**. Profile and intensity do not
   apply.
3. Click **Queue scan**.

The agent runs lynis (read-only) at its next check-in and reports back.
Warnings show as `medium`, suggestions as `low`, and the 0 to 100 hardening
index shows above the list. The host needs `lynis` installed (`apt install
lynis` or `dnf install lynis`). Without it the scan comes back `failed` with
that note. Audits run on **Linux** hosts only, and not from the containerized
agent, which would audit its own image instead of the Docker host.

## Active (intrusive) scans — use with care

Everything above is **passive** and safe to run any time. The **active**
profile runs heavier tools (`zap`, `wapiti`) and intrusive checks. It **sends
attack traffic** and can disrupt a fragile target. Because of that, active scans
have two extra guardrails:

1. On the Pentest page, set **Profile** to **active (intrusive)**. `zap` and
   `wapiti` are active-only and switch the profile for you.
2. Tick **"I'm authorized to actively scan this target"**. The scan is refused
   without it, and your name and the time are recorded on the scan.
3. For an **enrolled host**, an active scan only runs inside a **maintenance
   window** (open one under **Scheduling → Maintenance**). Or tick **"run now
   (override maintenance window)"** to go ahead immediately. This stops a
   fragile production box from being fuzzed at peak hours.

Verified domains have no maintenance window, so the authorization tick is all
they need.

> Active scanning is powerful. Only run it against systems you operate, ideally
> in a maintenance window, and expect noise and load on the target.

## Troubleshooting

| What you see | What it means / fix |
|---|---|
| Scan stays **queued** forever | No scanner is running, or it cannot reach the server. Check that Part 1 Step 2 is still running and `RP_SERVER_URL` is correct. If you pinned the scan to a scanner, it has to be that one. |
| Status **failed**, error `runner not found: docker` | Docker is not installed on the scanner machine. Install Docker or Podman, or set `RP_SCAN_RUNNER=nuclei` to use a locally installed binary. |
| Status **failed**, error `timed out — no result from the runner within 4h` | A scan that was claimed and never reported back is failed after four hours. Check that the scanner is still up. |
| **"host address is in a blocked class"** when queueing | The host's address is loopback, link-local or a cloud-metadata address. Those are blocked on purpose. Scan a host with a real LAN or public address. |
| **"host has no known address to scan"** | The agent has not reported an IP yet. Wait for its next heartbeat. |
| **"scan target not found or not ownership-verified"** | You tried to scan a domain before clicking **Verify** (Part 3, step 4). |
| **"active scan needs an active maintenance window"** | Open a maintenance window for the host, or tick "run now (override maintenance window)". |
| Verify keeps failing | The DNS TXT record has not propagated yet (wait a few minutes), or the `/.well-known` file is not reachable over HTTP or HTTPS. Check that the value matches exactly. |
| Findings show `failed` with a timeout | The scan exceeded its time budget. Raise it with `RP_SCAN_TIMEOUT=1800` (seconds) on the scanner. |
| The Pentest page stays empty | Your role lacks the **scan** permission. Ask an admin (Admin → Users & Roles). |

---

## Reference

**Tools.** Passive profile: `nuclei` (templated web and network checks),
`nikto` (web-server misconfiguration), `nmap` (open ports plus safe NSE
scripts) and `wpscan`. The active profile adds `zap` (full active web scan) and
`wapiti` (web fuzzer), plus intrusive variants of the others. `lynis` is an
**on-host audit** that runs on the host's agent, not on a scanner. See
**Active scans** for the guardrails. A scan keeps up to 1000 findings, and the
scanner sends at most 200 per scan by default.

**Scanner environment variables** (set when starting the scanner):

| Variable | Default | Purpose |
|---|---|---|
| `RP_SERVER_URL` | required | Your RemotePower URL |
| `RP_SATELLITE_TOKEN` | required | The scanner token from Part 1 |
| `RP_SCAN_RUNNER` | `docker` | `docker`, `podman`, or the name of a local binary |
| `RP_SCAN_RATELIMIT` | `50` | Requests per second for nuclei (be gentle on the target) |
| `RP_SCAN_TIMEOUT` | `900` | Per-scan time budget, in seconds |
| `RP_SCAN_POLL_SECS` | `15` | How often it checks for new jobs |
| `RP_SCAN_MAX_FINDINGS` | `200` | Most findings sent back for one scan |
| `RP_WPSCAN_API_TOKEN` | none | WPScan API token for vulnerability matching |
| `RP_CA_BUNDLE` | none | Extra CA bundle if your server uses an internal CA |
| `RP_NUCLEI_IMAGE`, `RP_NIKTO_IMAGE`, `RP_WPSCAN_IMAGE`, `RP_NMAP_IMAGE`, `RP_ZAP_IMAGE`, `RP_WAPITI_IMAGE` | built-in images | Use your own container image for a tool |

**Run the scanner as a service** (so it survives reboots), in
`/etc/systemd/system/remotepower-scanner.service`:

```ini
[Unit]
Description=RemotePower scanner satellite
After=network-online.target docker.service

[Service]
# Keep settings in ONE file so later additions (such as RP_WPSCAN_API_TOKEN) are
# picked up by a restart alone. The leading "-" starts the service even if the
# file is missing.
EnvironmentFile=-/etc/remotepower/scanner.env
Environment=RP_SERVER_URL=https://YOUR-SERVER
Environment=RP_SATELLITE_TOKEN=PASTE-THE-TOKEN-HERE
ExecStart=/usr/bin/python3 /opt/remotepower/remotepower-scanner.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then run `sudo systemctl enable --now remotepower-scanner`.

**Scripted install.** `packaging/scanner-setup.sh` does the above for you. It
installs the script, writes the environment file and a unit that runs as a
dedicated `remotepower-scan` user, and enables it. When Docker is the runner it
adds that user to the `docker` group. If neither Docker nor Podman is
installed and a `nuclei` binary is, it falls back to `RP_SCAN_RUNNER=nuclei`.

**Co-located on the server.** `install-server.sh` installs a scanner on the same
machine by default (`--no-scanner` to skip it). It mints its own token and
points the scanner at the server over loopback. In the Docker Compose setup, a
`scanner` service does the same but runs `nuclei` directly, without the Docker
socket, so only nuclei is available there. This trades the isolation this page
recommends (a separate machine) for a one-command install. A scanner on its own
machine is the better choice beyond a lab or small fleet.

---

## Is this safe and legal to run?

Yes, when you use it as intended: you may only scan assets you own and operate.
RemotePower enforces this for you. Enrolled hosts are yours by enrollment, and
any other target has to pass the ownership check in Part 3. The server decides
the exact address that gets scanned, so a scan can never be pointed at an
arbitrary third-party host. Every scan, schedule and verification is recorded in
the **Audit** log (who, what, when).

See also: [security-advisory.md](security-advisory.md) for how scan findings
feed the prioritized list, [maintenance.md](maintenance.md) for maintenance
windows, and [security.md](security.md) for the wider trust boundaries.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
