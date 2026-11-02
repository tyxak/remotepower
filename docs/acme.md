# ACME / Let's Encrypt

RemotePower shows the certificates that `acme.sh` manages on your hosts and lets you
issue, renew and revoke them from the dashboard. It does not run its own ACME client.
Renewals stay under the cron job that `acme.sh` installs on the host.

Only the Linux agent reads `acme.sh` state. The macOS and Windows agents do not.

## How it works

- **The agent scans, the server shows.** On each Linux host the agent looks for an
  `acme.sh` home in this order: `/root/.acme.sh`, the home of the user the agent runs
  as, then `/etc/acme.sh`. The first one that contains `acme.sh` wins. The agent reads
  every `<domain>/<domain>.conf` in it (up to 100 certificates per host) and reports
  them on its first poll after a restart and then every 60 polls, which is hourly at
  the default 60-second poll interval.
- **Private keys never leave the host.** The server stores metadata only: domain, alt
  names, challenge type, DNS provider, key length, created and next-renewal dates, the
  reload command and the file paths.
- **DNS-01 only.** RemotePower does not touch nginx, Apache or HTTP-01 plumbing, and
  you cannot pick another challenge type in the wizard.
- **Renewal is acme.sh's job.** The next-renewal date comes from `Le_NextRenewTime` in
  the certificate's own config. RemotePower adds a force-renew button for when you
  cannot wait.

## Where to find it

**Security → TLS / DNS.** The page has two parts: the TLS watchlist (see
[tls-monitor.md](tls-monitor.md)) and, below it, **ACME certificates**.

The table has one row per certificate:

| Column | What it shows |
|---|---|
| Host | The host that holds the certificate. |
| Domain | The primary domain. A star marks a wildcard and `+N SAN` counts the extra names. |
| Challenge | `DNS-01` for DNS challenges, otherwise the value `acme.sh` recorded. |
| Provider | The DNS provider, for example Cloudflare. |
| Created / Next renewal | Dates from the certificate's config. |
| Status | Days until renewal. Green for more than 14 days, amber for 4 to 14, red for 3 or fewer or overdue. Grey `no schedule` when `acme.sh` has no renewal time. |
| Actions | Force renew and Revoke and remove. |

Click a row for the certificate detail. Use the filter box to find a domain, host,
challenge or provider.

Hosts without `acme.sh` are left out, and a hint above the table says how many. A host
that has `acme.sh` but no certificates yet shows one row with **+ Issue** and
**Rescan**. **Rescan** asks the agent to scan again on its next heartbeat, which is
useful after you renewed or issued from the command line and do not want to wait up to
an hour.

## Issue a certificate

Click **+ Issue new cert**. The wizard has three steps.

1. **Domain.** Pick the host (only hosts with `acme.sh` are listed), type the primary
   domain, and tick **Also issue wildcard** to add `*.<domain>`. Add more names under
   **Additional SAN**, one per line. Pick a key length: RSA 4096 (the default), RSA 2048,
   ECDSA P-256 or ECDSA P-384.
2. **DNS provider.** The list comes from the server: Cloudflare, AWS Route 53, Gandi,
   DigitalOcean, Hurricane Electric, deSEC, Namecheap, NameSilo, OVH, RFC 2136, acme-dns,
   Hetzner and Porkbun.
3. **Confirm.** The wizard shows the `acme.sh --issue` command before it queues it. The
   first issuance can take one to three minutes while DNS propagates.

The command is queued on the host like any other command. It shows in the **Command
Queue** page until the host picks it up on its next heartbeat, and the action is
written to the audit log.

## DNS provider credentials

`acme.sh` needs an API token for your DNS provider. There are two ways to supply it:

- **On the host.** Export the token in the agent's environment or save it in the
  host's `account.conf`. Nothing is sent from RemotePower.
- **Centrally.** Click **DNS provider credentials** and fill in the fields for your
  provider. RemotePower stores them in the server configuration and never returns a
  saved value: the dialog marks a saved field `(set)` and keeps it when you leave the
  field blank. A provider's **Clear all** button removes them.

When a provider has stored credentials, the **issue** command carries them as
environment variables for that one command, so the host does not need its own
`account.conf` entry. The Command Queue page shows the values as `***REDACTED***`.
Force renew does not add credentials: `acme.sh` renews with what it saved on the host
when it first issued the certificate.

Saving credentials needs an instance admin. On an install with tenants, tenant admins
cannot change them.

You can also pull credentials the other way. On the **DNS** page, **Import from agent**
asks a host's agent to read the tokens saved in its `acme.sh` `account.conf` and move
them into the encrypted vault. See [dns.md](dns.md).

## Renew, revoke and logs

- **Force renew** queues `acme.sh --renew --force` for the domain. Let's Encrypt limits
  duplicate certificates to five per week, so use it sparingly.
- **Revoke and remove** queues `acme.sh --revoke` followed by `--remove`. It tells
  Let's Encrypt the certificate is no longer trusted and then deletes the local files.
  ECDSA certificates get `--ecc` automatically.
- **Detail dialog.** The **Overview** tab shows the status, alt names, the reload
  command (`Le_ReloadCmd`, decoded) and the file paths. **Timeline** lists issue, runs
  and the next renewal, newest first. **Logs** lists the captured output of every run
  that RemotePower queued, with the exit code and size. A log is capped at 256 KB.
- **Cancel** appears on an action that has no result yet. If the host has not picked
  the command up, it is removed from the queue and the action shows as cancelled. If
  the host already has it, RemotePower stops waiting, but the host may still finish the
  job and report a result later.
- **Ignore** deletes a log row and its record. Use it to clear an action that is stuck
  as pending, for example after the agent crashed mid-run. It does not change the
  certificate.

If the server cannot create the log file for an action, it queues the command anyway and
tells you in the toast that the Logs tab will stay empty.

## What is not supported

- **Must-staple / OCSP.** Not offered in the wizard.
- **HTTP-01 challenges** (standalone and webroot).
- **Installing `acme.sh`.** If a host has none, install it yourself.
- **Changing the reload hook.** RemotePower shows `Le_ReloadCmd` and never edits it.

## API

All routes are under `/api`. Reading needs a signed-in user (within their host scope);
everything that changes something needs an admin.

| Method | Path | Purpose |
|---|---|---|
| GET | `/acme` | Every host's certificates, plus the provider list. |
| GET | `/acme/<host_id>/<domain>` | One certificate and its 10 most recent action logs. |
| GET | `/acme/<host_id>/log/<action_id>` | The captured output of one action. |
| POST | `/acme/<host_id>/issue` | Queue an issue. Body: `domain`, `alt_names` (up to 20), `dns_provider`, `key_length` (`2048`, `3072`, `4096`, `ec-256` or `ec-384`; default `4096`). |
| POST | `/acme/<host_id>/<domain>/renew` | Queue a forced renewal. |
| POST | `/acme/<host_id>/<domain>/revoke` | Queue revoke and remove. |
| POST | `/acme/<host_id>/cancel/<action_id>` | Cancel a pending action. |
| POST | `/acme/<host_id>/ignore/<action_id>` | Delete an action's log row. |
| POST | `/devices/<host_id>/acme/force-rescan` | Scan on the next heartbeat. Linux hosts only. |
| GET | `/acme/dns-credentials` | The providers, their fields and which are set. Never the values. |
| POST | `/acme/dns-credentials` | Body: `provider` and `credentials`. A blank value keeps the saved one, `null` clears it. |

Every action is audit-logged (`acme_issue`, `acme_renew`, `acme_revoke`, `acme_cancel`,
`acme_ignore`, `acme_force_rescan`, `acme_dns_credentials_set`).

## Troubleshooting

- **"No hosts have reported any ACME state yet."** `acme.sh` is not installed in one of
  the three locations above, the host is not Linux, or the agent has not finished its
  first scan. Wait for the hourly scan, or restart the agent to scan on its first poll.
- **A certificate you just renewed still shows the old date.** The table shows the
  last scan, and **Refresh** only reloads what the server already has. Wait for the
  next hourly scan or call the force-rescan route. The **Rescan** button only appears
  on a host that has no certificates yet.
- **An action stays pending.** The command waits for the host's next heartbeat. If the
  host is offline it waits until the host is back. Cancel it, or ignore it if the agent
  never reported.
- **Issue fails with a DNS error.** Open the action's log. Most failures are a missing
  or wrongly scoped API token. Check **DNS provider credentials** or the token on the
  host.

## Under the hood

The server tags each queued command with `#acme:<action_id>#` so the output goes to the
per-certificate log instead of the generic command history. The agent returns the tag
inside the command it reports back, so the server accepts an optional `exec:` prefix
in front of it.

See also: [tls-monitor.md](tls-monitor.md) for the certificate watchlist,
[dns.md](dns.md) for the DNS dashboard that shares the credential store,
[tls-selfsigned.md](tls-selfsigned.md) if you do not have a public hostname, and
[agent-commands.md](agent-commands.md) for how queued commands reach hosts.
