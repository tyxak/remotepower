# ACME / Let's Encrypt integration

RemotePower visualises and orchestrates `acme.sh`-managed certificates across the fleet.

## Architecture

- **Agent-driven scanning.** Each agent walks `~/.acme.sh/` (root's home, `$HOME`, or `/etc/acme.sh/` — first match wins), parses every `<domain>/<domain>.conf`, and reports state to the server. The scan happens on poll 1 (after agent restart) and every `ACME_CHECK_EVERY` polls (~hourly at default interval).
- **No credentials cross the wire.** DNS API tokens (Cloudflare etc.) stay on the device, in `~/.acme.sh/account.conf` or the agent's environment — same place acme.sh itself reads from.
- **Renewal stays under acme.sh's own cron.** RemotePower never schedules renewals; it just shows next-renewal from `Le_NextRenewTime` and offers a force-renew button.
- **DNS-01 only.** RemotePower never touches nginx/apache/HTTP-01 plumbing. v1 surfaces Cloudflare prominently; the provider dropdown lists Route53, DigitalOcean, deSEC, Hetzner, Porkbun, and more.

## State storage

- Per-device cert state: `/var/lib/remotepower/acme_state.json` (server-side, hard cap of 200 certs per device).
- Action logs (captured stdout from each acme.sh run): `/var/lib/remotepower/acme_logs/<safe_did>__<action_id>.log` (256 KB cap each).
- Action metadata sidecars: `<safe_did>__<action_id>.meta.json` carrying `action`, `domain`, `phase`, `queued_at`, `actor`, and once the command completes, `rc` + `done_at`.

## UI

Lives at **Security → TLS / DNS expiry**, below the existing watchlist.

- **Table view** — device, domain (with for wildcards, +N SAN count), challenge type, DNS provider, created date, next renewal, status pill (green ≥14d, amber ≤14d, red ≤3d or overdue), per-row ↻ Force-renew and Revoke buttons.
- **Issue wizard** — 3-step modal: domain (with wildcard checkbox and live `*.<domain>` preview) → DNS provider (with credential-location hints) → confirm (shows the exact `acme.sh --issue --dns dns_cf -d ...` command before queueing).
- **Per-cert detail modal** — Overview tab (status pills, SAN list, decoded `Le_ReloadCmd`, file paths), Timeline tab (issued + runs + next renewal, sorted desc, "View log" jump), Logs tab (recent captures with rc + size, click to view; pending actions get a Cancel button).

## Cancelling pending actions

Any action with no `rc` yet shows a ⊘ Cancel button. Two paths:

- **Removed from queue** — if the agent hasn't picked it up, the entry is removed from `CMDS_FILE` cleanly and meta gets `rc=-3`.
- **Already dispatched** — if the agent already grabbed it, RemotePower stops polling (meta gets `rc=-4`), but the agent may still complete the operation. If it does, the rc gets overwritten on next ingestion.

## What's intentionally not supported

- **must-staple / OCSP.** Let's Encrypt is sunsetting OCSP responses; certs issued with `--ocsp-must-staple` from now on would fail in stapled clients. Not exposed in the UI.
- **HTTP-01 challenges.** Both standalone and webroot are skipped to keep RemotePower out of nginx/apache config.
- **Auto-install of acme.sh.** If a device has no `~/.acme.sh/`, the UI shows "acme.sh not installed" — manual install only.
- **Reload hook override.** RemotePower displays `Le_ReloadCmd` (decoded from the `__ACME_BASE64__START_..._END_` markers) but never modifies it.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/acme` | Fleet view of all certs + provider catalog |
| GET | `/api/acme/<dev_id>/<domain>` | Single cert detail + last 10 action logs |
| POST | `/api/acme/<dev_id>/<domain>/renew` | Queue `acme.sh --renew --force` |
| POST | `/api/acme/<dev_id>/<domain>/revoke` | Queue `--revoke` + `--remove` |
| POST | `/api/acme/<dev_id>/issue` | Queue new cert issuance (DNS-01) |
| POST | `/api/acme/<dev_id>/cancel/<action_id>` | Cancel a pending action |
| GET | `/api/acme/<dev_id>/log/<action_id>` | Get captured stdout for one action |

All endpoints require admin auth.

## Wire-protocol notes for the curious

Server queues exec commands tagged with `#acme:<action_id>#` so the cmd_output ingestion can route the verbose stdout (cert chains, DNS exchanges, deploy hook output) to `ACME_LOGS_DIR` instead of cluttering the generic `cmd_output.json` history. The agent strips the tag before passing to the shell but **keeps it in the returned `cmd` field**. The server's tag regex accepts an optional `exec:` prefix (`^(?:exec:)?#acme:([a-zA-Z0-9_-]+)#(.*)$`) since the agent round-trips the full original command.
