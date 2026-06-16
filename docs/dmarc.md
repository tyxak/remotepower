# DMARC monitor

Track the email-authentication posture of your domains — **SPF**, **DKIM** and
**DMARC** — from the **DMARC** page (under Security in the sidebar). It's
**DNS-only**: no mailbox, no SMTP, no report ingestion. RemotePower reads the
published TXT records and grades them.

## What it checks

For each domain you add:

- **DMARC** — `_dmarc.<domain>`: the policy (`p=none` / `quarantine` / `reject`),
  `pct`, and whether an aggregate-report address (`rua=`) is set.
- **SPF** — `<domain>` TXT `v=spf1 …`: the `all` qualifier (`-all` hard-fail,
  `~all` soft-fail, `?all`/`+all` = effectively no protection).
- **DKIM** *(optional)* — `<selector>._domainkey.<domain>`: only checked when you
  give a selector (e.g. `google`, `default`, `s1`); confirms a public key is
  published.

## Grades

| Status | Meaning |
|--------|---------|
| **ok**   | Enforcing (`p=quarantine`/`reject`), `rua` set, SPF `-all`/`~all`. |
| **weak** | Enforcing, but with gaps (no `rua`, `pct<100`, soft SPF, missing DKIM). |
| **fail** | Not enforcing — no DMARC record, or `p=none`. The domain is spoofable. |

The page lists each domain with its grade and the specific findings. **Add
domain** prompts for the domain (and an optional DKIM selector); **Scan now**
re-checks every domain over DNS (fast, synchronous).

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET    | `/api/dmarc/targets` | list domains + last result |
| POST   | `/api/dmarc/targets` | add a domain (admin) |
| DELETE | `/api/dmarc/targets/{id}` | remove a domain (admin) |
| POST   | `/api/dmarc/scan` | re-check all now (admin) |

Stored in `dmarc_targets.json` / `dmarc_results.json` in the data dir.
