# MCP server: natural-language fleet queries

RemotePower ships an [MCP](https://modelcontextprotocol.io)
(Model Context Protocol) server in `mcp/remotepower-mcp.py`. Once
connected to an MCP-compatible AI host (Claude Desktop, Cursor,
VS Code Copilot, etc.), you can query the fleet in plain English:

> *Which of my hosts have pending security updates?*
>
> *Show me the recent journal entries for mail01.*
>
> *Is the SSH config on web01 still at its baseline?*
>
> *Which hosts need a reboot?*

The AI host invokes the appropriate RemotePower API endpoints,
formats the result, and answers naturally. No dashboard click
required.

## The architecture

```
 +---------------+            +----------------------+
 | AI host (this |            |  RemotePower server  |
 | runs on your  |<---------->|  (HTTPS / API)       |
 | laptop)       |   HTTPS    |                      |
 +---------------+            +----------------------+
         ^
         | stdio JSON-RPC 2.0
         v
 +-----------------+
 | This MCP server |
 | (stdlib Python) |
 +-----------------+
```

**The MCP server runs on your laptop, not on the RemotePower server.** The AI
host (for example Claude Desktop) starts it as a subprocess and exchanges
JSON-RPC 2.0 messages over stdin and stdout. The MCP server makes HTTPS calls to
RemotePower's REST API on behalf of the AI, using a token you provision.

This split is important for the security story:

- Credentials live on **your** laptop, in your AI host's config
  (a plain JSON file).
- They never travel to the AI provider. Only the tool *results* do.
- The MCP server speaks to your RemotePower instance over HTTPS
  with normal token auth and no special privileges.

## Setup

### 1. Generate an API token

In the dashboard: **Admin → API Keys → New key**.
Give it a name like `mcp-laptop`. Choose the role `Viewer` for a strictly
read-only key, or `MCP` if you also want the five guarded write tools. **The
role is the switch.** You can change it later with the key's **Edit** button, and
the token stays the same. Copy the token. It is shown once and not recoverable. If
you lose it, generate a new one.

While you are in the dialog, consider these:

- **Host scope** confines the key to some groups, tags or sites, so the AI can
  only see and act on those hosts.
- **Source IP allowlist** rejects the key from any other address. Use your
  laptop's or VPN's egress IP.
- **Expires** and **Rate limit** cap how long and how fast the key works.

### 2. Copy the MCP server to your laptop

`remotepower-mcp.py` is in the `mcp/` folder of the RemotePower release archive
and of the repository. Copy that one file to your laptop and make it executable:

```bash
chmod +x ~/remotepower-mcp.py
```

It is a single self-contained Python file that uses only the standard library.
It is tested with Python 3.10 and newer.

### 3. Configure your AI host

#### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on
Windows (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "remotepower": {
      "command": "python3",
      "args": ["/Users/you/remotepower-mcp.py"],
      "env": {
        "REMOTEPOWER_URL": "https://remotepower.example.com",
        "REMOTEPOWER_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

Restart Claude Desktop. The tool icon at the bottom of the chat input shows
**remotepower** with its tools enabled.

| Variable | Meaning |
|---|---|
| `REMOTEPOWER_URL` | The base URL of your RemotePower server. |
| `REMOTEPOWER_TOKEN` | The API token from step 1. |
| `REMOTEPOWER_VERIFY_SSL` | Set to `0` to accept a self-signed certificate. The default is to verify. |
| `MCP_CLIENT_NAME` | Optional. The name of your AI host, such as `claude-desktop`. It is recorded in the audit log and shown on the Confirmations page. The default is `mcp-client`. |

#### Cursor / VS Code Copilot / others

Same JSON shape. Refer to your host's MCP server documentation
for where the config file lives. Every MCP-compliant host
supports the same `command + args + env` setup.

### 4. Verify

Open a chat and ask: *"What hosts are in my RemotePower fleet?"*

The host should show a "tool use" indicator and return a list of your hosts.

## The hosted endpoint (read-only, off by default)

The local bridge above runs on your laptop. RemotePower can also answer the Model Context Protocol itself, at `POST /api/mcp`, so an AI host that
can send a custom header connects straight to the server with no file to copy. It is **read-only**, and it is **off** until you switch it on:
**Settings → Advanced → Optional modules → MCP endpoint**. While it is off the address answers 404.

Make an API key as in step 1 and give it the role `Viewer`. The key's own limits apply to the endpoint exactly as they apply to the dashboard:
its host scope, its allowed addresses, its expiry and its rate limit, and a tenant sees only its own hosts. The endpoint holds no permission of
its own. Each question a tool asks runs as an ordinary read of the REST API, as that key, in the same checks that serve the dashboard. Every
message counts against the key's rate limit, and a tool that reads a host's page counts the read as well.

| Host | How to connect |
|---|---|
| Claude Code | `claude mcp add --transport http remotepower https://your-server/api/mcp --header "Authorization: Bearer YOUR-KEY"` |
| Cursor | In `mcp.json`: `{"mcpServers": {"remotepower": {"url": "https://your-server/api/mcp", "headers": {"Authorization": "Bearer YOUR-KEY"}}}}` |
| VS Code | In `.vscode/mcp.json`: `{"servers": {"remotepower": {"type": "http", "url": "https://your-server/api/mcp", "headers": {"Authorization": "Bearer YOUR-KEY"}}}}` |

A host that only offers a sign-in screen for connectors (the connector lists of Claude.ai and of Claude Desktop expect OAuth) cannot use it, because the
endpoint takes a key and offers no OAuth. Use the local bridge there.

**What it offers.** Eight tools with the same names, descriptions and arguments as the bridge: `list_alerts`, `get_attention`, `list_devices`,
`get_device`, `get_services`, `get_containers`, `get_cves` and `get_patches`. The five write tools are not offered over HTTP: they act on the fleet, and
the confirmation and attribution they carry belong to the local bridge. The other read tools of the bridge (`get_journal`, `get_drift`,
`get_recent_commands`, `get_runbook`, `get_tls`, `get_snmp_data`, `search_devices` and `search_fleet`) are left for a later release. A tool answer is
cut when it is longer than 60,000 characters, from the end, and says so.

**What it does and does not do.** It answers one JSON-RPC message with one JSON answer (the plain form of the streamable HTTP transport). It issues
no session, streams nothing and sends nothing on its own, so `GET /api/mcp` and `DELETE /api/mcp` answer 405. It speaks protocol versions
`2025-06-18`, `2025-03-26` and `2024-11-05`. A request that comes from another web page (it carries an `Origin` that is not this server's) is refused
by the same check that guards every other POST.

**What is recorded.** Each `tools/call` is a line in the audit log (`mcp_http_call`) with the tool and its arguments, under the name of the key's
user. The key itself is not written anywhere.

**Behind a proxy.** The proxy must pass the `Authorization` header on. The shipped nginx configuration does.

## Available tools

**21 tools — 16 read, 5 guarded write.** Each takes a small JSON arguments
object; the AI host generates these from your natural-language question. The
read tools are always available; the five write tools work only for a key
with role `mcp` (see *Guarded write tools* below).

| Tool | What it returns |
|---|---|
| `list_alerts` | The Alerts inbox: open, acknowledged or resolved alerts, newest first, with severity, host, when it first fired, who acked it, and the correlation flags (root cause, collateral, declared incident). The right first call for "what is wrong right now?", because `list_devices` only shows up or down. |
| `get_attention` | The needs-attention digest: everything the fleet wants looked at, ranked, including things that never became an alert, such as stale backups, expiring certificates, drifted config and posture gaps. Broader than `list_alerts`, and the better call for "what should I work on?" |
| `list_devices` | Every host with status, OS, group, tags, IP |
| `get_device` | Full detail for one host (name match) |
| `get_journal` | Recent systemd journal entries |
| `get_services` | Watched systemd unit states |
| `get_containers` | Docker / Podman container state |
| `get_cves` | CVE findings (per-host or fleet-wide) |
| `get_drift` | Configuration drift (per-host or fleet-wide) |
| `get_recent_commands` | Recent commands run on a host |
| `get_runbook` | The AI-generated host runbook, or `exists: false` if none has been generated yet |
| `get_patches` | Pending OS package updates |
| `get_tls` | TLS / DNS expiry watchlist |
| `get_snmp_data` | SNMP data collected from a network appliance / host |
| `search_devices` | Free-text search by name / OS / group / tags / notes |
| `search_fleet` | RAG retrieval across all fleet state, CMDB, runbooks, history, and docs. One call for broad or cross-host questions ("worst CVEs in the fleet", "which hosts need a reboot"). Returns ranked, cited chunks including fleet-wide rollups. |

> `search_fleet` is the bridge between MCP and the RAG knowledge index: where
> the granular `get_*` tools each fetch one host's structured record,
> `search_fleet` answers a natural-language question in one shot and lets the
> fleet rollups (worst CVEs, pending reboots, drift, cert expiry) do the
> aggregation the model would otherwise have to do by hand. It needs the
> knowledge index to be switched on (**Settings → AI assistant → Knowledge
> index (RAG)**). The index is not split by host or tenant, so `search_fleet`
> refuses a key that has a host scope, and any key under tenant isolation, with
> a 403. Those keys use the `get_*` tools.

The five **write tools** are reachable only by a key whose role is `mcp`:

| Write tool | What it does |
|---|---|
| `acknowledge_alert` | Acknowledge one open alert, with an optional note. It cannot resolve an alert. |
| `reboot_device` | Queue a reboot for one host, with an optional reason |
| `run_saved_script` | Run a script **from the saved library** (by id), never an arbitrary command. Takes an optional reason |
| `force_package_scan` | Ask an agent to push its installed-package list now |
| `force_acme_rescan` | Re-check a host's ACME / TLS / DNS expiry now |

Every write call is gated by the token's role and host scope, and is
recorded in the audit log alongside the AI host name and the reason the model
gave (a default such as `reboot web01` when it gives none).

### Host-name resolution

The tools accept friendly names. The MCP server does:

1. **Exact match**: `mail01` matches a host named `mail01`.
2. **Prefix match**: `web01` matches `web01.example.com`
   if there is only one host starting with it.
3. **Substring match**: `web` matches `web01.example.com`
   if there is only one host containing it.
4. **Ambiguous**: `web` raises an error if it matches multiple
   hosts, and the model is told to ask for more specifics.

You can also pass full names. The matching is conservative: it
only auto-disambiguates when there is exactly one match. The read tools ignore
case. The write tools match case exactly, and they also accept a host id.

## Guarded write tools, and what is still absent

The five write tools (`acknowledge_alert`, `reboot_device`, `run_saved_script`,
`force_package_scan` and `force_acme_rescan`) ship with the guard rails an LLM
acting on a fleet needs:

- **A server-side allow-list, compiled in.** The set of callable write actions
  is a fixed list in the server, not something a request can widen. Anything
  outside it is refused with the allowed set echoed back. The AI host's own
  "Allow this tool to run?" consent prompt is **not** the control; the server is.
- **Role-gated, and admins are excluded too.** Only a key created with role
  `mcp` reaches these endpoints. An *admin* key is rejected here as
  well, because admins have their own direct endpoints. Anything in the audit log
  that came through this path is unambiguously AI-initiated rather than a human
  clicking a button.
- **Pre-saved actions only.** `run_saved_script` runs a script from the library
  by id. There is **no `run_command`** and **no `edit_device`**, so the model can
  never assemble an arbitrary shell command.
- **An approval step for the destructive two.** `reboot_device` and
  `run_saved_script` do not run at once on a host that has *require
  confirmation* set, which is the default for every host. The call returns a
  confirmation id and waits for an admin to approve it. See *Approving a
  request* below. The other three run immediately, because they change nothing
  on the host.
- **Per-token roles + scope.** Write calls are checked against the token's role
  permissions and host scope, just like any other action.
- **Audit logging.** Every write call is recorded with the AI host name and the
  reason the model gave for it.

So the worst outcome of a confused model is bounded: it can reboot a host or run
a vetted library script you already trust, and with confirmation on, only after
you approve. It can never run an arbitrary command or shut a box down off-script.
If you want a purely read-only assistant, create the key with role `viewer`; all
five write tools then refuse it.

### Approving a request

Open **Automation → Confirmations** (the page is titled *MCP Confirmations*).
Each pending request shows the host, the action, who asked, the reason the model
gave and the AI host (the **Source** column). **Approve** runs it and **Reject**
discards it. A request that nobody decides expires after one hour and raises the
*MCP confirmation expired without operator decision* event. **Clear resolved**
tidies the list. The same page also holds the other changes that wait for a second
person, such as changes parked by change approval and AI remediation proposals.
For those the **Source** column reads *operator* when no AI host sent them.

Only admins see the page. A key acts as the user who created it, so by default
the admin who created the key cannot approve its requests: another admin has to.
To allow it, untick **Requester cannot approve their own change** under
**Settings → Security → Change approval (maker-checker)**.

A host with *require confirmation* turned off runs `reboot_device` and
`run_saved_script` at once. Turn it off only for hosts where you trust the AI
workflow, never for production. There is no switch for it in the UI yet: an admin
sets it with `PATCH /api/devices/{id}/require_confirmation` and
`{"require_confirmation": false}`.

## Security model

| Concern | Mitigation |
|---|---|
| Token leakage | Stored in your AI host's config file, never sent to the LLM provider. Scoped to its role and host scope; generate one per laptop and revoke any time. Lock it to your IP with a source allowlist. |
| Prompt injection | Tool *outputs* contain operator-controlled text (host names, notes, journal entries). A malicious note could try to "instruct" the AI. Read tools are bounded (worst case: a confused summary); write tools are limited to the five compiled-in, pre-saved actions above, and the destructive two wait for your approval, so an injected instruction still can't run an arbitrary command. Use a `viewer`-role key for a read-only assistant. |
| Self-signed TLS | Set `REMOTEPOWER_VERIFY_SSL=0` in the MCP env if you must, but prefer to install your CA's root cert in the laptop's trust store. |
| Data sensitivity | Tool results go to the AI provider behind your AI host. The privacy settings under Settings → AI assistant control RemotePower's own assistant, not a separate AI host. When in doubt, run a local model (Ollama) as the AI host. |

## Troubleshooting

### "Tool error: REMOTEPOWER_URL not set"

Your AI host's config doesn't have the env vars set, or they're
empty strings. Re-check the JSON config and restart the host.

### "Tool error: Network error reaching …"

The MCP server can't reach the RemotePower URL from your laptop.
Common causes: VPN not connected, a misspelt host name, corporate proxy.

### "HTTP 301" or "HTTP 302" on every tool

The URL redirects, for example from `http://` to `https://`. The MCP server does
not follow redirects, so that its token is never sent to another address. Put the
final `https://` address in `REMOTEPOWER_URL`.

### "HTTP 401" on every tool

The API token was rejected. Either it's wrong, or it was revoked,
or its expiry passed, or you are calling from an address outside the key's
source allowlist. Generate a new key or fix the allowlist.

### "HTTP 403" on a tool that *should* work

The key's role or host scope does not allow the call. A `viewer` key cannot use
the write tools, an `admin` key cannot either, a key with a host scope cannot use
`search_fleet`, and a host outside the key's scope answers as if it did not exist.
Check the role and the host scope on **Admin → API Keys**.

### A write tool answers "pending confirmation"

That is the approval step working. Approve the request on **Automation →
Confirmations**, see *Approving a request* above.

### Tools show up in Claude Desktop but every call hangs

The MCP server is being spawned but stdin/stdout aren't flowing.
Try running it manually to verify it starts:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  | REMOTEPOWER_URL=https://remotepower.example.com \
    REMOTEPOWER_TOKEN=your-api-token \
    python3 ~/remotepower-mcp.py
```

You should get a JSON response on stdout within a second. If you
don't, check Python is installed and on `PATH`.

### Claude Desktop says "MCP server quit unexpectedly"

Check `~/Library/Logs/Claude/mcp*.log` (macOS) or the equivalent
location on your OS. Most often it's a Python syntax error from
an edit, or an unhandled exception in a tool. Stack traces from
the server go to stderr, which Claude Desktop captures into those
logs.

## A note on the protocol

The local bridge speaks MCP version **`2024-11-05`** over stdio. The hosted endpoint is described above. It offers tools only,
not resources or prompts. The server will move to a newer version when a host
needs one.

## See also

- [Model Context Protocol](https://modelcontextprotocol.io): the protocol and its spec.
- [AI assistant](ai.md): the assistant built into RemotePower (dashboard buttons and the AI page), which is a different feature.
- [API reference](api.md): the REST API the MCP server calls.
- [Knowledge index](rag.md): what `search_fleet` searches.
