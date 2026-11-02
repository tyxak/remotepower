# Governed AI executor

The AI can **propose** a remediation for a host. It executes nothing on its own.
This is the opposite of the "autonomous AI operator" idea: the design assumes the
model is **fully prompt-injected by a hostile log line**, and makes the worst case
still safe.

Off by default. It is an optional module (`ai_exec`). When it is off, the whole
`/api/ai-exec` prefix returns 404 at the dispatcher, not just a hidden menu entry.

## Turn it on

Go to **Settings → Advanced → Optional modules** and tick **AI executor**. It needs an
AI provider (**Settings → AI assistant**) and at least one saved script or built-in
remediation playbook, since that is all it may act on.

## The three constraints

Everything the executor can do is bounded by three rules that compose gates the
product already had.

### 1. The model returns an ID, never a command

The executor may only **select** from a server-built catalog of artifacts a human
already wrote: your **saved scripts** (`script:<id>`, up to 200) and the product's
**built-in remediation playbooks** that carry a fix command (`playbook:<name>`). A
script with an empty body is left out. The model answers with an id from that catalog;
anything not in it is refused and audited as `ai_exec_rejected`. A completely
compromised model can, at worst, pick *a different script you wrote yourself*. It
cannot author shell.

`GET /api/ai-exec/catalog` returns the entire action space. Read it to see, in one
place, everything your AI could ever propose. Each entry also shows the SHA-256 of the
body it would run.

### 2. A human always approves

A proposal is an ordinary entry in the **confirmations ledger**, so it inherits the
expiry time, the tenant filter, **separation of duties** (the proposer cannot approve
their own change when `change_approval_no_self` is on), the audit trail with `ai_host`
and `ai_prompt` attribution, and the existing approve and reject screen. Approve it on
the **Confirmations** page. Only then does it run, through the same command gate as
every other action (maintenance mode, quarantine and audit mode). If the host is
inside one of those states when you approve, the proposal stays pending so you can
try again once the block clears.

### 3. What you approve is what runs

The proposal pins a SHA-256 of the script body it was built from. At approval the
body is re-resolved from the live store and re-hashed. If another admin edited the
script in between, or deleted it, execution is **refused** rather than quietly running
something the approver never saw. Propose it again to get a fresh proposal.

## Using it

- **From an alert.** Run **AI triage** on an alert. When the verdict names a host and
  a recommended action, the result has a **Propose fix (governed executor)** button.
  It sends the alert and the verdict as the problem description.
- **From the API.** `POST /api/ai-exec/propose {device_id, context}`. `context` is
  free text, up to 4,000 characters. You need a role that can change things (viewer
  roles cannot propose), and the host must be one you can see.

The model reads the host name, your description and the catalog, and picks at most one
action, or `NONE`. The prompt tells it to answer `NONE` rather than pick a poor match,
because a wrong action costs more than no action. A proposal answers `202` with a pending confirmation id and
nothing has run. If nothing in the catalog fits, you get `proposed: false` and a short
summary instead.

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

This flow is safer than the older mitigate flow, which runs on a typed `RUN` with no
second pair of eyes.

See also: [ai.md](ai.md) for the assistant and its providers,
[mitigation.md](mitigation.md) for the investigate-and-fix dialog, and
[automations.md](automations.md) for rules that run scripts without a model in the loop.

---

← [Back to docs index](README.md)
