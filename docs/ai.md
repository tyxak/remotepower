# AI assistant

An optional link to a language model. It explains outputs, diagnoses problems,
prioritises patches, drafts scripts, writes fleet reports and answers free-form
questions. **It is off by default.** An admin turns it on under **Settings → AI
assistant**.

Nothing leaves your network unless you enable a cloud provider. For a fully
self-hosted setup with no external calls, pick Ollama or LocalAI and point it at a
server on your own network.

## Providers

Seven providers sit behind four adapters. They all go through one `/api/ai/chat`
endpoint and use only the Python standard library, so there are no extra packages to
install.

| Provider | Network egress | API key needed? | Adapter |
|---|---|---|---|
| **Ollama** (local) | None, runs on your network | No | OpenAI-compatible |
| **LocalAI** (local) | None, runs on your network | No | OpenAI-compatible |
| **opencode** (local) | None, runs on your network | Optional (HTTP basic) | opencode REST session server |
| **openclaw** (local) | None, runs on your network | Optional (gateway token) | openclaw WebSocket-RPC gateway |
| **Anthropic** (Claude) | api.anthropic.com | Yes | `/v1/messages` |
| **OpenAI** (ChatGPT) | api.openai.com | Yes | OpenAI-compatible |
| **DeepSeek** | api.deepseek.com | Yes | OpenAI-compatible |

**opencode** and **openclaw** are locally run agentic coding backends. opencode is
driven through its `serve` REST API (create a session, post the prompt, read the
reply). openclaw is driven over its control WebSocket (JSON-RPC `connect` and
`chat.send`). Both are best-effort. Point the **Base URL** at your running instance
(`http://localhost:4096` and `ws://localhost:18789` by default), supply a token only if
the instance asks for one, and set the **Model** to `providerID/modelID` to route
opencode's own backend. The same connect-time SSRF guard that protects every other
outbound call applies, so private and loopback peers are blocked unless you opt into
insecure mode.

The adapter redacts hostnames, IP addresses and secret-shaped strings before the bytes
leave the Python process (see [Privacy toggles](#privacy-toggles)). It cannot stop a
provider from seeing what you send. The only way to rule that out is to run the model
locally.

## Setting it up

1. **Settings → AI assistant**: set **Enabled** to On.
2. Pick a **Provider**. Optionally enter a **Model** (leave it blank for the provider's
   default).
3. For cloud providers, paste your **API key**. For Ollama or LocalAI, leave it blank.
4. Optionally override the **Base URL**, for example `http://10.0.0.2:11434/v1` for an
   Ollama server on another machine.
5. Set the **Privacy** toggles and the **Limits** (below).
6. Click **Test connection**. A success message means the provider answered a tiny
   request. A failure message names the problem.
7. Save. The AI buttons across the dashboard now work for every signed-in user.

### Default models per provider

If you leave the Model field blank, these are used:

| Provider | Default model |
|---|---|
| Ollama | `llama3.1:8b` |
| LocalAI | `gpt-3.5-turbo` |
| opencode | the server's own configured default |
| openclaw | the gateway's own configured default |
| Anthropic | `claude-3-5-sonnet-latest` |
| OpenAI | `gpt-4o-mini` |
| DeepSeek | `deepseek-chat` |

On the AI Assistant page you can pick another model for one conversation with the model
picker above the chat.

### Slow local models and nginx

Local thinking models (smallthinker, qwq, deepseek-r1) can spend 60 to 180 seconds
generating a reply. nginx's default `proxy_read_timeout` is 60 seconds, so it closes the
connection first and the browser sees a 504 Gateway Timeout. The app server waits up to
five minutes. For nginx, add a per-location block:

```nginx
location /api/ai/ {
 proxy_pass http://127.0.0.1:8090;
 proxy_set_header Host $host;
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 proxy_set_header X-Forwarded-Proto $scheme;
 proxy_read_timeout 300s;
 proxy_send_timeout 300s;
}
```

This block must appear **before** any catch-all `location ^~ /api/` block in the same
server stanza, because nginx routes on the first match. Run
`sudo nginx -t && sudo systemctl reload nginx` after editing.

### Thinking models (Ollama and others)

A thinking model reasons before it answers, and the reasoning counts against the token
limit. A small local model can spend the whole allowance thinking and return nothing,
so you wait a couple of minutes for an empty reply.

Set **Reasoning effort** to **None** under **Settings → AI assistant** to turn thinking
off. RemotePower then sends `reasoning_effort: "none"` with every request to an
OpenAI-compatible provider (OpenAI, DeepSeek, Ollama and LocalAI). Ollama only stops a
thinking model when it gets that field. A `/no_think` line in the prompt does not do it.

| Reasoning effort | What is sent |
|---|---|
| Provider default | Nothing. The model behaves as it did before. |
| None | `reasoning_effort: "none"` |
| Low, Medium, High | `reasoning_effort` with that value |

A single prompt can have its own value: open **Prompt customization**, then the prompt's
**Fine-tuning**. It wins over the setting above. **Use the global setting** follows
Settings again.

Anthropic, opencode and openclaw have no such field. The row is hidden for them and
nothing is sent.

If a reply is empty because the model reached the token limit first, RemotePower says so
and names this setting, instead of showing an empty box.

## What the model is told about your fleet

Under **Settings → AI assistant → Context awareness** three switches control what
travels with every request: a short note about what RemotePower is, a **fleet
snapshot**, and per-question retrieval (see [rag.md](rag.md)). The snapshot is a count
line, then one line per host with its name, OS, package manager, online state, group and
your own notes.

A host also names its **notable conditions**: high CPU, memory or disk, a pending
reboot, failed units, mount problems, an inactive host firewall, unencrypted disks, an
unsynchronised clock, quarantined files, or the agent's own "my metrics are limited"
signal. Two things about that:

- **A healthy host adds nothing.** Conditions appear only when they cross the same
  thresholds the product already alerts on, so a fleet that is fine costs no extra
  tokens and never shows the model a "problem" your own pages call fine.
- **Each host names at most four.** One very sick machine must not crowd the rest of the
  fleet out of a bounded prompt.

Anything beyond that comes from retrieval, which runs per question. The snapshot is what
the model knows before it retrieves anything.

The privacy toggles below apply to the snapshot exactly as they apply to everything else.
With **Send hostnames** off, the host names in it are redacted too.

## Privacy toggles

Under **Settings → AI assistant → Privacy**.

| Toggle | Default | Effect when off |
|---|---|---|
| Send hostnames (FQDNs) | **Off** | Any FQDN-shaped token becomes `<HOST>` |
| Send IP addresses | **Off** | IPv4 becomes `<IP>`, IPv6 becomes `<IPv6>` |
| Send journal / log content | **Off** | Journal text is **not** sent at all (only summaries) |
| Send command output | **On** | (Turning it off would defeat the Explain buttons.) |

### Always redacted (no toggle)

These are stripped from every request whatever your toggles say, because they should
never reach an AI provider:

- Bearer tokens: `Bearer <16+ characters>` becomes `Bearer <REDACTED>`.
- AWS access keys: `AKIA[0-9A-Z]{16}` becomes `<REDACTED-AWS>`.
- Long hex strings: any run of 32 or more hex characters becomes `<REDACTED-HEX>`.

This is regex-based, not real data-loss prevention. It works on common cases and does not
catch arbitrary secret formats. Where data sensitivity matters, run Ollama locally.

## Rate limiting

Two limits, both per user, both under **Settings → AI assistant → Limits**:

- **Max tokens per response** caps the model's output length (default 4000, up to
  16000). Lower is faster and cheaper but may truncate long replies.
- **Daily requests per user** caps the number of `/api/ai/chat` calls per UTC day per
  username (default 100). Set it to **0** for unlimited.

The daily counter resets at midnight UTC. It lives in `ai_usage.json`, which is cleaned
up daily so it does not grow. The buttons ask for a shorter reply than the global cap
(roughly 800 to 2000 tokens, more for a generated script) so a short answer does not wait
for a long one. The per-button value is a ceiling under your global cap, never a way past
it.

## AI Insights hub

The **AI Assistant** page (sidebar, Admin group) hosts a grid of **AI Insights**: 34
one-click reports and advisors that run a focused prompt against your fleet, with
retrieval and fleet context attached. They fall into five groups:

- **Proactive**: daily fleet briefing, log-anomaly digest, alert-noise tuning,
  predictive maintenance, automation suggestions.
- **Incident**: incident root cause, group related alerts, change-risk review.
- **Natural language to config**: fleet query as a filter, a monitor from a sentence,
  reverse IaC (Ansible from a host's live state). These return a structured draft for
  you to review.
- **Planning**: CVE remediation plan, patch prioritisation, compliance remediation plan,
  capacity and cost forecast, backup and DR readiness, billing review.
- **Advisors**: security advisory, TLS and certificate triage, CVE prioritisation,
  investigate the top alert, firewall auditor, DNS hygiene, email deliverability,
  homelab assistant, supply-chain and SBOM questions, host one-pager, remote-access
  review, helpdesk triage, virtualization hygiene, IaC review, drift triage, access and
  credential review, network dependency review.

A card marked with an input first asks for a target: a host, a zone, a CVE, or a command
to review. Every Insight is a tunable prompt (**Settings → AI assistant → Prompt
customization**), rate-limited and redaction-aware like the inline buttons below. Many
pages also carry a small **AI review** button that opens the matching Insight in place.

## Diagnose from logs

For the "something is wrong on this host but I don't know where" moment, the host drawer
has **Diagnose from logs**:

1. **Collect** sets a one-shot flag. On its next heartbeat the agent snapshots
   `/var/log/*` and `/var/log/*/*`: only files modified in the last 24 hours, skipping
   compressed, binary and rotated files, with at most a 12 KB tail per file, 40 files and
   256 KB in total, ranked by error density and recency. Windows agents sweep the last 24
   hours of Error and Warning entries in the System and Application event logs instead.
   macOS sweeps `/var/log`.
2. At ingest the server **re-caps every size and redacts credential material**
   line by line (`password=…`, `Authorization: Bearer …`, `api_key: …`,
   `https://user:pass@…` become `[REDACTED]`). One sweep is kept per host, and you can
   browse the per-file tails in the dialog.
3. **Diagnose** sends an excerpt of at most 48 KB (highest-scoring files first) to your
   provider under the `log_sweep_rca` prompt and shows the verdict, per-file findings
   and next steps.

**Consent.** Like the mitigate flow, this is an explicit action. Log content goes to the
provider only when you click Diagnose, and the dialog says so. The `send_journal` toggle
governs automatic context, not this button.

Endpoints: `POST /api/devices/{id}/log-sweep/run` (admin),
`GET /api/devices/{id}/log-sweep`, and `POST /api/devices/{id}/log-sweep/diagnose`
(a role that can change things).

## Agentic alert triage

The alert inbox's **Triage** action (`POST /api/alerts/{id}/ai-triage`) runs a bounded
investigation. The model asks for evidence through a fixed menu of **read-only,
host-scoped tools**: a host summary, the journal tail, watched services, the host's other
open alerts, recent command output, a regex search over the six-hour log buffer, and the
latest log sweep. Each round it answers in strict JSON with one tool call or a final
verdict. It gets at most 4 tool calls, and every result is clipped and secret-redacted.

The verdict holds a root cause, a confidence, evidence lines, a recommended action and,
when the evidence suggests an adversary, **proof-labelled MITRE ATT&CK techniques**
(observed, inferred or theoretical, never a claim of certainty). It is stored on the alert
with the tool trail and reopens from the **AI verdict** badge on the row. The model
**never executes anything**. Acting on a verdict stays on the approval-gated paths
(mitigate playbooks and the [governed AI executor](ai-executor.md)). Alert IDs from
another tenant or outside your scope return 404. The row's **Quick investigate** action is
the lighter one-shot version: an explanation and suggested fixes with no stored verdict.

**Automatic triage (opt-in, off by default).** **Settings → AI assistant → Automatic
alert triage** runs the same loop on new open alerts from the maintenance cadence: one
alert per tick, above a minimum severity (High by default), with a daily run cap (20 by
default). Those verdicts are marked `by: auto`. With the out-of-band scheduler the
provider's latency never touches the request path. Without it, the request that picks up
an alert pays that latency, which is why the feature ships off. It sends alert evidence
automatically, including the host's recent journal, hostname and IP, to your provider for
every matching alert, so prefer a local model for this.

**Feedback.** Every verdict offers thumbs up and down (`POST
/api/alerts/{id}/ai-triage/feedback`). The totals appear in `GET /api/ai/stats`.

**From verdict to fix.** With the AI executor module on, the verdict dialog gets a
**Propose fix (governed executor)** button. The model picks from your saved actions only,
and a person approves on the Confirmations page before anything runs. A ticket opened
from a triaged alert carries the verdict in its first note.

The log-sweep evidence tool provisions itself: when the sweep is missing or older than 30
minutes, the server requests a new one so the next run has fresh evidence.

Both prompt keys, `log_sweep_rca` and `alert_triage`, are tunable under **Prompt
customization**.

## Inline AI buttons

AI buttons sit next to the thing they explain, so you rarely need the AI page for them.
They are visible to every signed-in user once the feature is on, and the rate limits
apply per user.

| Where | Button | What gets sent |
|---|---|---|
| Alerts, row actions | **Triage**, **Quick investigate** | The alert, and for Triage the tool trail above |
| Host drawer | **Investigate** | System info, recent journal lines and recent commands |
| Host drawer, failed units | **AI diagnose** | Unit names, state and recent log lines |
| Host drawer, unhealthy container | AI icon | The container's state and logs |
| Host drawer, command output | **Explain output** | The command, its output and the host name |
| Containers, log view | **Explain logs** | The log lines on screen |
| TLS / DNS, warning and critical rows | AI icon | Host, port, expiry, issuer and STARTTLS type |
| CVEs, a finding | AI triage | CVE ID, package, version, summary and host |
| Firewall, a host's rules | **AI audit** | The ruleset |
| Drift, a diff | **Explain drift** | What changed |
| Compliance, a control | AI icon | The control and its status |
| Forecast, a mount | AI icon | The mount's fill trend |
| Exposure, a world-reachable port | AI icon | Port, protocol and process |
| Scripts, edit dialog | **Generate from prompt**, **Explain**, **Audit for risks** | Your description, or the script body |

Generated scripts go through the same dry-run and dangerous-pattern checks as a script
you wrote yourself. There is no special trusted path for AI output.

## The AI Assistant page

Three things on one page.

### Provider status

For Ollama and LocalAI it shows the provider name and base URL, whether it is reachable,
the server version, and the **currently loaded models** with their VRAM use and expiry.
For cloud providers it shows the provider and base URL with a "reachable" mark that only
means an API key is configured. A real round trip would spend an API call on every page
load, so use **Test connection** for that. **Refresh** reloads these figures.

### Model picker

A dropdown above the chat, filled from the provider's own listing: Ollama's `/api/tags`
(name, size, parameter count), `/v1/models` for LocalAI, OpenAI and DeepSeek, and a
built-in list for Anthropic. Choosing a model overrides the default for this conversation
only.

### Free-form chat

Multi-turn chat, with Ctrl or Cmd plus Enter to send. The conversation is kept in your
browser's local storage (the last 40 messages) and is not synced to the server or to
other people. It is gone if you clear browser storage. The server's audit log records that
a request happened and its token counts, never the content.

## Endpoints

Any signed-in user can call these, except the config and test routes, which are
admin-only. On an install with tenants, only a platform operator can save provider
settings.

```
GET  /api/ai/config   current config, API key masked
POST /api/ai/config   admin, validated, audit-logged
POST /api/ai/chat     main chat endpoint
POST /api/ai/test     admin, one-word smoke test
GET  /api/ai/models   models the provider lists
GET  /api/ai/stats    provider info, version, loaded models, triage feedback
```

### POST /api/ai/chat

```json
{
 "messages": [{"role": "user|assistant|system", "content": "..."}, ...],
 "system": "explain_output | find_problem | ... | <literal>",
 "context": "optional free-form label for audit log",
 "max_tokens": 1500,
 "model": "optional override of the configured model"
}
```

`system` takes either a key from the prompt registry or a literal prompt (up to 16 KB).
Keys are looked up first. `model` is limited to 1 to 200 characters, and anything else is
ignored. `max_tokens` is capped at your configured per-response limit: a client can ask
for less but not more.

### Prompt registry

The registry holds 70 prompts (`SYSTEM_PROMPTS` in `ai_provider.py`), for example
`explain_output`, `find_problem`, `explain_script`, `audit_script`, `generate_script`,
`triage_cve`, `investigate_device`, `explain_alert`, `free_form`, `diagnose_service`,
`explain_tls`, `prioritise_patches` and `explain_container_logs`. Each Insight card maps
to one key, and every key is editable under **Settings → AI assistant → Prompt
customization**. See [features.md](features.md) for the full list of advisors.

## Storage

- **API key.** Stored in `config.json` under `ai.api_key`. The file is mode 0600 and owned
  by the app-server user. `GET /api/ai/config` (admin only) returns the key masked, as
  bullets followed by its last four characters. If you set `RP_CONFIG_KEY`, secret fields
  in the stored configuration are encrypted (see [security.md](security.md)).
- **Rate-limit counters.** `ai_usage.json`, one entry per day and user, cleaned up daily.
- **Audit log.** Each `/api/ai/chat` call adds an entry with the provider, model, token
  counts, elapsed time, context label and rate-limit position. **The prompt and the
  response are not logged**, so the log does not become a second copy of your data.

## Troubleshooting

### "AI is disabled. Configure in Settings → AI assistant."

The Enabled switch is off. Turn it on, configure a provider and save.

### "Network error: SyntaxError: JSON.parse: unexpected character"

Almost always nginx's `proxy_read_timeout` cutting off a slow request before the model
answers. Add the `location /api/ai/` block above and reload nginx.

### "Daily AI request cap reached (N/M)"

You have hit your own daily limit. Wait for midnight UTC or raise the cap under
**Settings → AI assistant → Limits**.

### "HTTP 401: invalid_api_key" or "HTTP 403"

The cloud provider rejected the key. Paste it again in Settings. The field is blank while
the key is masked, so type to overwrite it. Anthropic keys start with `sk-ant-`, and OpenAI
and DeepSeek keys start with `sk-`.

### "URLError: timed out" on every chat

The app server cannot reach the provider. For Ollama at `10.0.0.2`, check that the server
can resolve and reach that address. In a container, or behind tight egress firewalling,
the app-server process may not have a network path.

### "The model reached the token limit before it wrote an answer"

A thinking model used its whole allowance reasoning and had none left for the answer. Set
**Reasoning effort** to **None** under **Settings → AI assistant**, or for one prompt under
its **Fine-tuning**. You can also raise the token limit, which is slower and holds the GPU
for longer. See "Thinking models" above.

### "Test connection succeeds but real chats fail"

The test asks for 8 tokens, and a real chat can ask for thousands. On a slow local model
the longer generation trips nginx's 60-second timeout. Raise `proxy_read_timeout` to 300
seconds as shown above.

### Heartbeat noise in the server log

Routine heartbeat and lock-wait lines are silent by default. Set `RP_LOG_HEARTBEATS=1` or
`RP_LOG_LOCK_WAITS=1` in the app server's environment to turn them back on for
diagnostics. Offline and online transitions always log.

## What's not in scope

- **Streaming responses.** The gain is small for replies that take 1 to 30 seconds, and
  buffering in the app server and nginx complicates it. Requests are synchronous.
- **Cross-user conversation sync.** AI page conversations are per browser, which keeps the
  privacy surface small.
- **Token cost tracking.** The audit log records `tokens_in` and `tokens_out` per call.
  There is no dashboard summary of them yet.
- **Vault storage for the API key.** A mode-0600 `config.json` is enough for a self-hosted
  single-tenant server. A vault would make sense once you need per-user keys or rotation.

See also: [rag.md](rag.md) for the knowledge index, [ai-executor.md](ai-executor.md) for
governed remediation, [autonomy.md](autonomy.md) for unattended actions, and
[mitigation.md](mitigation.md) for the investigate-and-fix dialog.
