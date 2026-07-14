# Regulated-data (PII) scan

*"Where is our regulated data?"* — the GDPR/PCI question no amount of monitoring
answers. Opt-in, the agent walks configurable paths and reports which **files**
contain emails, card numbers, national IDs, IBANs or phone numbers. Results appear
on the **Compliance** page.

Works on Linux, Windows and macOS.

## The one rule that shapes everything

**The matched value never leaves the host — not raw, not redacted, and not
hashed.** Two reasons, and the second is the one people miss:

1. A PII scanner that ships PII into its own database is not a control; it is a
   second breach with a nicer UI.
2. **Hashing does not anonymise low-entropy data.** There are only ~10⁹ possible
   US national IDs, and a card number is pinned by its BIN plus the Luhn check. A
   rainbow table over either is minutes of work — so a "fingerprint" of a national
   ID is a *reversible copy* of it. (This is exactly why the sibling
   secrets-on-disk scan may fingerprint its matches — an API key is high-entropy —
   and this one may not.)

A finding therefore carries only: **which file, what kind, how many, which
lines.** Everything an operator needs to go and look, and nothing an attacker who
pops the RemotePower server can use. The server re-enforces this on ingest by
rebuilding each stored entry from those four known-safe fields — so even a
tampered agent cannot smuggle a value in.

Card matches are **Luhn-checked**: without that, every 16-digit order id and
timestamp reads as a credit card and the report becomes noise nobody trusts.

## Turn it on

Settings → Security → **Regulated-data scan (PII)**. Off by default (it walks the
filesystem). Optionally set custom roots; the defaults look where an
organisation's *data* lives (`/home`, `/srv`, `/var/www`, `/opt` — and the Windows
equivalents), **not** `/etc`, which is full of maintainer emails and would bury the
real hits.

## A report, not an alert

PII sitting in `/srv/data` is the expected state of a business, not an incident.
An event per finding would be pure alert fatigue and would train operators to mute
the one category they must not. So this fires nothing — it is an inventory, and it
reads as one. The incident case (a *leaked credential*) is still covered by the
`secret_exposed` alert.

## API

- `GET /api/pii` — the fleet's regulated-data inventory (counts + file paths only).
- `POST /api/pii/scan {device_id?}` — queue a one-shot scan (admin).

---

← [Back to docs index](README.md)
