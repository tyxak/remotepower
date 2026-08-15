# Governed AI executor

The AI can **propose** a remediation for a host. It executes nothing on its own.
This is the considered opposite of the "autonomous AI operator" pitch: the design
assumes the model is **fully prompt-injected by a hostile log line**, and makes
the worst case still safe.

Off by default. It is an optional module (`ai_exec`) — when disabled, the whole
`/api/ai-exec` prefix returns 404 at the dispatcher, not just a hidden nav.

## Turn it on

Settings → Advanced → enable **AI executor**. It needs an AI provider configured
(Settings → AI assistant) and at least one saved script or a registered playbook fix, since
that is the only thing it may act on.

## The three constraints

Everything the executor can do is bounded by three rules that compose gates the
product already had.

### 1. The model returns an ID, never a command

The executor may only **select** from a server-built catalog of artifacts a human
already wrote — your **saved scripts** and **registered playbook fixes**. The
model answers with an id from that catalog; anything not in it is refused and
audited. A completely compromised model can, at worst, pick *a different script
you wrote yourself*. It cannot author shell.

`GET /api/ai-exec/catalog` returns the entire action space — read it to see, in
one place, everything your AI could ever propose.

### 2. A human always approves

A proposal is an ordinary entry in the **confirmations ledger**, so it inherits
for free: the TTL, the tenant filter, **separation of duties** (the proposer
cannot approve their own change when `change_approval_no_self` is on), the audit
trail with `ai_host` / `ai_prompt` attribution, and the existing approve/reject
UI. Approve it in **Confirmations**; only then does it run — through the same
command gate as every other action (maintenance mode, quarantine, audit mode).

### 3. What you approve is what runs

The proposal pins a SHA-256 of the script body it was built from. At approval the
body is re-resolved from the live store and re-hashed; if another admin edited the
script in between, execution is **refused** rather than quietly running something
the approver never saw.

## Using it

`POST /api/ai-exec/propose {device_id, context}` — the model reads the host, the
problem you describe, and the catalog, and picks at most one action (or NONE). The
response is a pending confirmation id. Nothing has run.

## What it is not

Not autonomy, and nothing here becomes autonomous by configuration. This flow
always stops at a pending confirmation; a person approves or it does not happen.

Selective autonomy and closed-loop outcome reporting DO exist, as a separate,
separately-gated feature — see [autonomy.md](autonomy.md). That loop acts only
on precedent from resolved incidents, only on action classes you have
explicitly allow-listed, and starts every tenant at `off`. It is
not reachable from here: proposing one action for a person to approve and
running a class of actions unattended are different powers, and conflating
their switches is how one becomes the other by accident.

Phase 0 is the whole shippable increment of *this* flow — and it is strictly
safer than the older mitigate flow, which executed on a typed `RUN` with no
second pair of eyes.

---

← [Back to docs index](README.md)
