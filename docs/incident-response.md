# Incident response — the RemotePower half

Your incident-response plan is yours; this page is the part of it that concerns
this control plane. It answers two questions an IR plan has to answer and usually
cannot: **what can RemotePower tell me during an incident**, and **what should I
do to RemotePower itself when the incident involves it.**

Nothing here is automated. An incident is a judgement call, and a tool that
quarantined hosts on its own would be its own incident.

---

## Case A — a managed host is compromised

**1. Contain the host without losing it.** Open the device drawer →
**Quarantine** (or `PATCH /api/devices/{id}/quarantine {"quarantined": true}`).
Queued commands are dropped server-side while quarantined and no new action can
be dispatched — but the agent keeps checking in, so you keep telemetry and do not
have to choose between containment and visibility. Poll-interval changes still
apply, deliberately, so you can slow a noisy host down. The toggle is admin-only
and audited.

Quarantine is **not** network isolation. It stops RemotePower from acting on the
host; it does nothing to the host's own connectivity. If you need the machine off
the network, that is a firewall or switch action.

**2. Establish what changed and when.** In rough order of usefulness:

| Where | What it gives you |
|---|---|
| The **Timeline** page, scoped to the device | Everything RemotePower observed for this host, in one ordered view. The device drawer and the command palette both deep-link into it. |
| Device drawer → **Audit** tab | Every action *RemotePower* took on this host, with the actor. This is the "was it us?" question, without leaving the device. |
| **Protect** (Integrity Guard) | File changes it caught and quarantined. Linux only. |
| Drift, listening ports, SSH-key baseline | What differs from the last known-good baseline, which is usually the fastest read. |
| **Command history** | What was executed through the product, by whom, with output. |

**3. Rotate what the host held.** A compromised host had its **device token**.
Re-enrolling issues a new one; deleting the device invalidates the old one along
with its telemetry. If the host carried credentials from the CMDB vault, treat
those as disclosed and rotate them at the source — RemotePower can tell you which
assets referenced it, but rotating a switch password is a switch action.

## Case B — the control plane itself is suspect

This is the case that needs deciding in advance, because half the tooling you
would reach for lives on the box in question.

**1. Preserve the evidence before you change anything.**

- Turn on **litigation hold** (Settings → Advanced → Maintenance) — one switch, stops every
  age-based purge across the audit log and all seven retention windows so that a
  scheduled sweep does not delete the window you care about while you work.
- Take a **full DR backup** (Settings → Backups) *before* remediating, and store
  it off the host. It contains the vault and integration secrets — treat it as
  the sensitive artifact it is.
- If audit **forwarding** to a SIEM is configured, the copy already off the box is
  the one to trust. A local log on a suspect host is evidence about the host, not
  from it.

**2. Cut off access.** Settings → Security → **Active sessions** lists every
login on the instance and revokes per user. Then rotate: API keys (the **API
keys** page), the enrollment token, and any integration secret an attacker with
config read could have taken. Note that `GET /api/config` withholds secrets even
from admins — it returns `*_set` booleans — so a stolen session is not
automatically a stolen secret set, but assume disclosure if the host itself was
reached.

**3. Understand the blast radius.** Every device token lives on this host, so a
full compromise of the control plane is a compromise of the ability to run
commands on the fleet. The audit log is hash-chained, so a tampered entry is
detectable — verify the chain rather than assuming the log is intact or assuming
it is not.

## Case C — RemotePower is wrong, not compromised

Worth separating, because it is far more common and the response is different: a
storm of alerts usually means a threshold or an upstream dependency, not an
intrusion. Before declaring an incident:

- **Alerts → Tuning** shows the noisiest alerts and sources. A single rule
  producing most of the volume is a tuning problem.
- The **self** page (control-plane health) separates "the fleet is broken" from
  "this server is broken" — they look identical from the dashboard.
- Alert **correlation** already tags symptoms under a root cause; a hundred
  service alerts under one `device_offline` is one incident, not a hundred.

---

## Prepare these before you need them

- **Decide who declares an incident** and make sure they have an account that
  survives the incident — an admin whose only MFA is a passkey on a lost laptop
  is a bad day.
- **Configure audit forwarding.** Everything in Case B gets easier when a copy is
  already elsewhere, and it is the single highest-value preparation on this page.
- **Run a restore drill.** The backup you have never restored is a hypothesis.
- **Know your `RP_BACKUP_PASSPHRASE`,** and know that RemotePower cannot recover
  it. An encrypted backup you cannot open is not a backup.
- **Write down the escalation path** in Contacts / on-call so it is reachable
  from the product during an incident rather than from a wiki that may be on the
  affected host.

---

← [Back to docs index](README.md) · [Security controls](security.md) ·
[Access review](access-review.md) · [Data retention](data-retention.md) ·
[Alert tuning](alert-tuning.md)
