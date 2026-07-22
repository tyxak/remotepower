# AI assistant

*(v2.1.3 introduced this feature; v2.1.4 added the standalone page; v2.1.5 added markdown rendering, more buttons, fixed a few bugs)*

Optional integration with an LLM provider for explaining outputs,
diagnosing problems, prioritising patches, generating scripts, and
free-form chat. **Disabled by default**; an admin opts in through
Settings → AI assistant.

Nothing leaves the building unless you explicitly enable a cloud
provider. If you want a fully self-hosted setup with no external
calls, pick Ollama or LocalAI and point at a server on your own
network.

## Providers

Seven providers behind four adapters. All wire to a single
`/api/ai/chat` endpoint, pure stdlib (`urllib.request` for HTTP, a
minimal RFC-6455 client for openclaw's WebSocket) — no new pip
dependencies.

| Provider | Network egress | API key needed? | Adapter |
|---|---|---|---|
| **Ollama** (local) | None — runs on your network | No | OpenAI-compatible |
| **LocalAI** (local) | None — runs on your network | No | OpenAI-compatible |
| **opencode** (local) | None — runs on your network | Optional (HTTP-basic) | opencode REST session server |
| **openclaw** (local) | None — runs on your network | Optional (gateway token) | openclaw WebSocket-RPC gateway |
| **Anthropic** (Claude) | api.anthropic.com | Yes | `/v1/messages` |
| **OpenAI** (ChatGPT) | api.openai.com | Yes | OpenAI-compatible |
| **DeepSeek** | api.deepseek.com | Yes | OpenAI-compatible |

**opencode** and **openclaw** *(v5.8.0)* are locally-run agentic
coding backends. opencode is driven through its `serve` REST API
(create a session, POST the prompt, read the reply); openclaw is
driven over its control WebSocket (JSON-RPC `connect` + `chat.send`).
Both are best-effort/experimental — point the **Base URL** at your
running instance (`http://localhost:4096` / `ws://localhost:18789` by
default), supply a token only if the instance requires one, and the
same connect-time SSRF guard used for every other outbound call
applies (private/loopback peers are blocked unless you opt into
insecure mode). Set the **Model** to `providerID/modelID` to route
opencode's own backend.

For the "what does my privacy posture look like?" question, the
adapter applies regex-based redaction before the bytes leave the
Python process. That covers hostnames, IPs, and a handful of
secret-shaped patterns (bearer tokens, AWS access keys, long hex).
See [Privacy toggles](#privacy-toggles) below for what's redacted
when. Pre-redaction interception by the model provider is, of
course, not something we can prevent — the only way to make that
moot is to run the model locally.

## Setting it up

1. **Settings → AI assistant** → toggle **Enabled** to On.
2. Pick a **Provider**, optionally enter a **Model** name (leave
 blank for the provider's default).
3. For cloud providers, paste your **API key**. For Ollama or
 LocalAI, leave it blank.
4. Optionally override the **Base URL** if you're running Ollama
 at a non-default address (e.g. `http://10.0.0.2:11434/v1`).
5. Set **Privacy** toggles (see below) and **Limits**.
6. Click ** Test connection** to verify. A success message means
 the provider responded with a tiny 8-token reply. A failure
 message names the problem.
7. Save settings. The buttons across the dashboard are now
 active for every authenticated user.

### Default models per provider

If you leave the Model field blank, these are used:

| Provider | Default model |
|---|---|
| Ollama | `llama3.1:8b` |
| LocalAI | `gpt-3.5-turbo` |
| opencode | *(the server's own configured default)* |
| openclaw | *(the gateway's own configured default)* |
| Anthropic | `claude-3-5-sonnet-latest` |
| OpenAI | `gpt-4o-mini` |
| DeepSeek | `deepseek-chat` |

You can override per-conversation on the standalone AI page (model
picker dropdown above the chat).

### Slow local models and nginx

Local thinking models (smallthinker, qwq, deepseek-r1) can spend
60–180 seconds generating a response. nginx's default
`proxy_read_timeout` of 60s will close the connection before
that, and the browser sees a 504 Gateway Timeout. The HTTP timeout
on the Python side was bumped to 5 minutes in v2.1.4; for nginx
you must add a per-location block:

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

This block must appear **before** any catch-all `location ^~ /api/`
block in the same server stanza — nginx routes on first match.
`sudo nginx -t && sudo systemctl reload nginx` after editing.

## Privacy toggles

Located under Settings → AI assistant → **Privacy**.

| Toggle | Default | Effect when off |
|---|---|---|
| Send hostnames (FQDNs) | **Off** | Any FQDN-shaped token becomes `<HOST>` |
| Send IP addresses | **Off** | IPv4 → `<IP>`, IPv6 → `<IPv6>` |
| Send journal / log content | **Off** | Journal text is **not** sent at all (only summaries) |
| Send command output | **On** | (Off would defeat the Explain button) |

### Always-redacted (no toggle)

These are stripped from every request regardless of your toggles
because they should never reach an AI provider, even on a fully
permissive deployment:

- Bearer tokens: `Bearer <16+ chars>` → `Bearer <REDACTED>`
- AWS access keys: `AKIA[0-9A-Z]{16}` → `<REDACTED-AWS>`
- Long hex strings: any 32+ char hex sequence → `<REDACTED-HEX>`

Regex-based, not real DLP — works on common cases, doesn't catch
arbitrary secret formats. For operations where data sensitivity
matters, the right answer is to run Ollama locally.

## Rate limiting

Two limits, both per user, both in Settings → AI assistant →
**Limits**:

- **Max tokens per response** — caps the model's output length
 (default 4000; max 16000). Lower = faster + cheaper but may
 truncate long responses.
- **Daily requests per user** — caps the number of `/api/ai/chat`
 calls per UTC day per username (default 100). Set to **0** for
 unlimited.

The daily counter resets at midnight UTC. The bookkeeping lives in
`ai_usage.json`; the file is GC'd nightly so it doesn't grow.

Per-button max_tokens overrides are also applied client-side so a
30-line Explain doesn't sit waiting for 4000 tokens to generate:

| Button | Client max_tokens |
|---|---|
| Explain alert | 800 |
| Explain TLS / Triage CVE | 800–1000 |
| Explain command output / Find the problem / Explain script | 1500 |
| Investigate device / Audit script / Prioritise patches | 2000 |
| Generate script | 4000 |

The server still respects your configured global cap — the
per-button value is a *floor*, not a *raise*.

## AI Insights hub

The **AI Assistant** page hosts an **AI Insights** grid — one-click reports
and advisors that run a focused system prompt against your fleet with RAG +
fleet context attached automatically. They fall into five groups:

- **Proactive** — daily fleet briefing, log-anomaly digest, alert-noise tuning,
  predictive-maintenance narrative.
- **Incident** — root-cause narrative, group-related-alerts, pre-run
  change-risk review.
- **Natural language → config** — fleet query → filter, monitor/check from a
  sentence, reverse-IaC (Ansible from a host's live state). These return a
  structured draft (JSON / YAML) for you to review.
- **Planning** — CVE remediation plan, compliance remediation plan, capacity &
  cost forecast, backup/DR-readiness.
- **Advisors** — firewall auditor, DNS hygiene, email deliverability, homelab
  integration assistant, supply-chain/SBOM Q&A, host one-pager, remote-access
  (WG Access VPN) review.

Cards marked with an input prompt you for a target (a host, zone, CVE, or a
command to review) first. Every Insight is a tunable prompt
(Settings → AI → Prompts), rate-limited and redaction-aware like the inline
Explain/Investigate buttons below. The firewall auditor is also reachable as an
**AI audit** button on each host in the Firewall page.

## Hail-mary log sweep — "Diagnose from logs" *(v6.4.0)*

For the *"something is wrong on this host but I don't know where"* moment,
the device drawer has **Diagnose from logs**:

1. **Collect** sets a one-shot `force_log_sweep` flag; on its next heartbeat
   the agent snapshots `/var/log/*` and `/var/log/*/*` — only files modified
   in the last 24 h, compressed/binary/rotated files skipped, at most 12 KB
   tail per file, 40 files, 256 KB total, ranked by **error density +
   recency**. (Windows agents sweep the last 24 h of Error/Warning
   System/Application event-log entries instead; macOS sweeps `/var/log`.)
2. At ingest the server **re-caps every size and redacts credential
   material** line-by-line (`password=…`, `Authorization: Bearer …`,
   `api_key: …`, `https://user:pass@…` → `[REDACTED]`). One sweep is kept
   per device; you can browse the per-file tails in the modal.
3. **Diagnose** sends a ≤48 KB excerpt (highest-scored files first) to your
   configured provider under the `log_sweep_rca` prompt and renders the
   verdict, per-file findings and next steps.

**Consent model:** like the mitigate flow, this is an *explicit action* —
log content is sent to the AI provider only when you click Diagnose, and the
modal says so. The ambient `send_journal` privacy toggle governs automatic
context, not this button.

Endpoints: `POST /api/devices/{id}/log-sweep/run` (admin),
`GET /api/devices/{id}/log-sweep`, `POST /api/devices/{id}/log-sweep/diagnose`
(write role).

## Agentic alert triage *(v6.4.0)*

The alert inbox's **Triage** action (`POST /api/alerts/{id}/ai-triage`) runs a
bounded investigate loop: instead of answering from a static context blob, the
model requests evidence through a fixed menu of **read-only, device-scoped
tools** — device summary, journal tail, watched services, the host's other
open alerts, recent command output, a regex search over the 6 h log buffer,
and the latest hail-mary sweep — replying with strict JSON (one tool call or
a final verdict) each round, hard-capped at 4 tool calls, every tool result
clipped and secret-redacted.

The verdict (root cause, confidence, evidence lines, recommended action, and —
when the evidence genuinely suggests adversary behaviour — **proof-labelled
MITRE ATT&CK techniques**: observed / inferred / theoretical, never a claim of
certainty) and the tool trail are stored on the alert and reopen from the
**AI verdict** badge on the row. The model **never executes anything** — acting on a verdict
stays on the existing approval-gated paths (mitigate playbooks, the governed
AI executor). Cross-tenant or out-of-scope alert ids 404.

**Automatic triage (opt-in, off by default).** Settings → AI Assistant →
*Automatic alert triage* runs the same loop on new open alerts from the
maintenance cadence: one alert per tick, a severity floor (default High and
up), and a daily run cap (default 20). Verdicts store as `by: auto`. With
the out-of-band scheduler the provider latency never touches the request
path; without it, the tick that picks an alert pays it in-request — which is
why the feature ships off.

**Feedback.** Every verdict offers 👍/👎 (`POST
/api/alerts/{id}/ai-triage/feedback`); aggregates ride `GET /api/ai/stats`.

**From verdict to fix.** With the AI-executor module enabled, the verdict
modal's *Propose fix (governed executor)* button turns the verdict into an
executor proposal — the model picks from operator-authored saved actions
only, and a human approves in Confirmations before anything runs. Tickets
opened from a triaged alert carry the verdict in their seeded note.

The `log_sweep` evidence tool is self-provisioning: a missing or stale
(>30 min) sweep makes the server set `force_log_sweep` itself so the next
run has fresh evidence.

Both prompt keys (`log_sweep_rca`, `alert_triage`) are tunable under
Settings → AI → Prompts.

## button inventory

| Location | Label | What gets sent |
|---|---|---|
| Device dropdown (⋯ menu) | ** Investigate** | sysinfo + last 30 journal lines + last 10 commands |
| Device detail → Command output | ** Explain** | command + output + device name |
| Device detail → Journal panel | ** Find the problem** | error/warning lines with 2-line context, or last 50 lines |
| Services → service detail | ** Diagnose** *(failed services only)* | unit name + state + last 30 log lines |
| TLS → table row | ** Triage** *(warning/critical/error only)* | host + port + expiry + issuer + starttls type |
| Patches → table row | ** Prioritise** *(devices with pending updates only)* | upgradable package list from latest apt/dnf check |
| CVEs → finding row | ** Triage** | CVE id + package + version + summary + device |
| Notifications → webhook log row | ** Explain** | event type + raw detail |
| Scripts → edit modal | ** Generate from prompt** | natural-language description |
| Scripts → edit modal | ** Explain** | the script body |
| Scripts → edit modal | ** Audit for risks** | the script body |
| Help → AI Assistant page | (free-form chat) | full conversation history (local to browser) |

Generated scripts go through the same dry-run + dangerous-pattern
detection as a human-written one — there's no special AI-trusted
path. The buttons are visible to every authenticated user once
the feature is enabled; rate limits apply per-user.

## The AI Assistant page (Help → AI Assistant)

Three things on one page:

### Provider status header

For Ollama and LocalAI ("local providers"), shows:

- Provider name + base URL
- Reachability indicator (● Reachable / ● Unreachable / ● Error)
- Server version (Ollama: from `/api/version`)
- **Currently-loaded models** with VRAM use + expiry time (Ollama:
 from `/api/ps`)

For cloud providers (Anthropic, OpenAI, DeepSeek), shows the
configured provider + base URL + a "reachable" indicator that's
just `bool(api_key configured)` — a real round-trip would burn an
API call on every page load, so the Test Connection button is the
right place for that.

The **Refresh** button re-fetches stats without reloading the page.

### Model picker

Above the chat, a dropdown populated from the provider's own
listing:

- **Ollama** → `GET /api/tags` — name + size + parameter count
- **LocalAI / OpenAI / DeepSeek** → `GET /v1/models`
- **Anthropic** → hardcoded fallback (no `/v1/models` endpoint)

Selecting a model overrides the configured default for this
conversation only. Useful when comparing models that are both
loaded into Ollama at the same time.

### Free-form chat

Multi-turn, Ctrl/+Enter to send. Conversation history persists in
**localStorage** in your browser — last 40 messages, capped to keep
request size bounded. Clearing the conversation wipes the local
history; the server-side audit log of individual requests is
untouched, by design (logs grow forever, and they'd reproduce the
privacy redaction problem at storage layer).

**Conversation is local to the browser.** Not synced across users,
not visible to other sessions, gone if you clear browser storage.
The audit log records that requests happened with token counts; it
doesn't record content.

## Endpoints

All require authentication (any logged-in user — except config
which is admin-only).

```
GET /api/ai/config — current config, api_key masked
POST /api/ai/config — admin, validated, audit-logged
POST /api/ai/chat — main chat endpoint
POST /api/ai/test — admin, "say OK" smoke test
GET /api/ai/models — list available models from the provider
GET /api/ai/stats — provider info, version, loaded models
```

### POST /api/ai/chat — body shape

```json
{
 "messages": [{"role": "user|assistant|system", "content": "..."}, ...],
 "system": "explain_output | find_problem | ... | <literal>",
 "context": "optional free-form label for audit log",
 "max_tokens": 1500,
 "model": "optional override of the configured model"
}
```

The `system` field accepts either a key from the system prompt
registry (full list below) or a literal prompt string (bounded to
16 KB). Keys are looked up first, so the client stays simple.

The `model` field is bounded to 1–200 chars; anything else is
ignored — defence against a client sending 50 KB as the model name.

The `max_tokens` field is capped to the configured per-response
limit; a client can request less but not more.

### System prompt registry

Keys live in `server/cgi-bin/ai_provider.py::SYSTEM_PROMPTS`:

```
explain_output — command output
find_problem — journal slice
explain_script — script body
audit_script — script body, security focus
generate_script — natural language → bash
triage_cve — CVE id + package context
investigate_device — device snapshot
explain_alert — webhook payload
free_form — generic, used by the AI page
diagnose_service — failed systemd unit + logs
explain_tls — certificate expiry / renewal
prioritise_patches — pending updates list
explain_container_logs — docker / podman logs
… and many more
```

The registry has grown well past those originals — it now backs
dozens of advisor cards across the proactive, incident, planning,
natural-language-config and advisors categories (see the **AI Insights
hub** section above, and `features.md` for the full, current set). Each
card in the AI Insights grid maps to one `SYSTEM_PROMPTS` key, and every
key is editable under **Settings → AI → Prompts**.

## Storage

- **API key**: cleartext in `config.json` under `cfg['ai']['api_key']`.
 The file is mode 0600 owned by the app-server user. Operators who need
 stronger storage can swap in `cmdb_vault` later — there's a hook
 point in `_ai_cfg()`.
- **Rate-limit counters**: `ai_usage.json`, one key per `<date>:<user>`,
 garbage-collected daily.
- **Audit log**: every `/api/ai/chat` call appends an entry to the
 audit log with provider, model, token counts, elapsed time,
 context label, and rate-limit position. **Content is not logged**
 — neither the prompt nor the response. That's deliberate.

## Troubleshooting

### "AI is disabled. Configure in Settings → AI."

The Enabled toggle in Settings → AI assistant is off. Turn it on,
configure a provider, save.

### "Network error: SyntaxError: JSON.parse: unexpected character"

Almost always nginx's `proxy_read_timeout` cutting off a slow
request before the model responds. Add the `location /api/ai/`
block above and reload nginx. v2.1.4+ replaces this generic error
with a more specific message that tells you exactly which fix to
try.

### "Daily AI request cap reached (N/M)"

You've hit your own daily rate limit. Either wait for midnight UTC
or bump the cap in Settings → AI assistant → Limits.

### "HTTP 401: invalid_api_key" / "HTTP 403"

Cloud provider rejected your API key. Re-paste it in Settings (the
field is blank when masked — type to overwrite). For Anthropic
specifically, keys start with `sk-ant-`; for OpenAI, `sk-`; for
DeepSeek, `sk-`.

### "URLError: timed out" on every chat

The provider hostname is unreachable from the app server. For
Ollama at `10.0.0.2`, check that the server can resolve and reach
that address — if you're running RemotePower in a container or
behind tight egress firewalling, the app-server process may not have the
network path.

### "Test connection succeeds but real chats fail"

This was the canonical 2.1.3→2.1.4 bug. Test uses `max_tokens=8`
(fast), real chats use up to 4000. On slow local models, the
60–180 second generation tripped nginx's 60s timeout. Fixed in
2.1.4 by lowering per-button max_tokens and bumping the Python
timeout to 5 min, but you still need to bump nginx's
`proxy_read_timeout` to 300s as shown above.

### Heartbeat noise in `error.log`

Unrelated to AI but commonly noticed at the same time. v2.1.5
silences routine heartbeat and lock-wait logs by default; set
`RP_LOG_HEARTBEATS=1` or `RP_LOG_LOCK_WAITS=1` in the app-server
environment to re-enable for diagnostics. OFFLINE/ONLINE
transitions stay unconditional.

## What's not in scope

These are deliberately deferred. Each one is a real feature, none
of them are in this release:

- **Tool calls / agent mode.** Letting the model query
 `/api/devices` etc. is interesting but needs a separate
 Settings toggle and a read-only action allowlist. Queued.
- **Streaming responses.** Visible benefit small for 1–30s
 requests; complications with app-server buffering and nginx
 buffering large. Sync request/response only.
- **Saved prompts / templates.** The inline buttons cover the
 bulk of use. A library of named prompts could come later.
- **Cross-user conversation sync.** AI page conversations are
 per-browser by design — keeps the privacy surface clean. If
 you want a shared scratchpad, that's a different feature.
- **Token cost tracking.** Audit log captures `tokens_in` and
 `tokens_out` per call; a dashboard summary across them would
 be nice but isn't here yet.
- **cmdb_vault integration for the API key.** Mode-0600
 `config.json` is good enough for a self-hosted single-tenant
 box. Vault makes sense once you want per-user key scoping or
 rotation.
