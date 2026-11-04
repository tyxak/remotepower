# RAG over your infrastructure

RemotePower's AI assistant retrieves relevant facts from *your* fleet and
injects them into every request, so answers reference your hosts, your
conventions, and your current state instead of generic Linux knowledge.

This is "Level-2/3 RAG" in the ladder the codebase has documented since
v2.1.7: Level-1 is the static project + fleet preamble (`ai_context.py`);
Level-2 is lexical retrieval over your corpus; Level-3 is optional
embeddings. v3.4.0 ships both 2 and 3.

## Design at a glance

- **Pure stdlib.** No faiss / chromadb / numpy. BM25 runs over a hand-built
  inverted index; cosine similarity is a plain Python dot product. At this
  tool's scale (low thousands of chunks) that's sub-millisecond lexical and
  tens of milliseconds for a full cosine sweep.
- **Lexical-first.** BM25 is the always-on base and works with every
  provider, including Anthropic (which has no embeddings endpoint).
- **Embeddings optional.** When the provider supports embeddings
  (OpenAI / Ollama / LocalAI) and you enable them, semantic search is fused
  with lexical via Reciprocal Rank Fusion. Vectors are cached by content
  hash, so a reindex only re-embeds chunks whose text changed.
- **Fails safe.** Any retrieval error is swallowed — a RAG problem can
  never break the chat path.

## What gets indexed

**34 sources**, each an individual checkbox under Settings → AI assistant → Knowledge
index. All are on by default except **Metrics**. The credentials vault is
never indexed by any of them.

| Source | Contents | Notes |
|---|---|---|
| **Docs & runbooks** | Product Markdown docs + per-host AI runbooks | docs deployed to `/var/lib/remotepower/docs/` |
| **Live state** | Per host: summary (incl. IP/hostname/MAC), resources (CPU/RAM/disk/uptime), listening ports, patch & reboot status, config drift, watched services, **open alerts**, **local TLS cert expiry**, CVEs, containers, **Docker disk use** *(7.5.0)*, storage pools with the date of the newest snapshot and, on ZFS, the cache hit ratio and the datasets that hold the most space (sizes to two figures, so a few megabytes do not rewrite the chunk) *(7.5.0)*, SNMP | one chunk per `(host, facet)` |
| **Fleet rollups** | Cross-host summaries: worst CVEs, **all open (unresolved) alerts worst-first**, hosts with pending updates / pending reboot, drifted hosts, certs expiring soon | answers "which hosts have X?" / "what is alerting?" |
| **CMDB** | Asset metadata + per-asset Markdown docs | **credentials vault never indexed** |
| **History** | Recent commands, alerts, fleet events | bounded by count + age; redaction applied |
| **Firewall** | Per host: host-firewall posture (nftables/iptables/ufw/firewalld — active, rule counts, policy) + fail2ban jails/bans, and a fleet "no active firewall" rollup. Also Threat Intel: each host's attackers with reputation and block state, SSH-gateway sessions, and the edge feeds' state, the Cloudflare IP list and the addresses only the edge saw | rule **counts**, never raw rules/counters; public attacker addresses, not fleet data |
| **Integrations** | Homelab software-integration health (Pi-hole, TrueNAS, *arr, …) + a down/degraded rollup | fleet-scoped; secrets never indexed |
| **Backups** | Per host: backup freshness (which watched paths are stale, age) + a fleet "stale backups" rollup | answers "are X's backups current?" |
| **Email & DNS** | DMARC/SPF/DKIM posture per domain, DNSBL/IP-reputation status, and DNS-resolver health — grounds the *email-deliverability* and *DNS-hygiene* AI advisors | admin-configured posture, no PII |
| **Security posture** | Fleet security-control posture: mutual-TLS coverage (which hosts pin a client certificate), at-rest backup-encryption status, agents in read-only audit mode, and break-glass / maintenance-mode state — lets the AI answer "is backup encryption on?" or "what's our mTLS coverage?" | control-plane summary, no secrets (passphrases/keys are never touched) |
| **Compliance** | Per-framework control pass/fail (CIS, PCI, HIPAA, SOC 2) and the hosts driving each failure | scores + control ids |
| **Network map** | The declared topology (uplinks and dependencies), the site/subnet layout, unmanaged hosts seen on the LAN, and the **observed** topology — LLDP neighbours as the switches themselves report them, plus each host's actual outbound peers. Unenrolled neighbours (switches, APs) are included, since they appear nowhere else | grounds "what talks to X?" and "what is X physically plugged into?" |
| **Tickets & KB** | Built-in helpdesk tickets (subject, status, priority) and knowledge-base articles | ticket bodies + KB prose |
| **Scripts** | Saved custom scripts: name, description and body (secret-scrubbed before indexing) | `KEY=secret`/token values redacted |
| **Provisioning & rollouts** | Infrastructure blueprints and staged-rollout state (rings, health gates) | operator-authored |
| **Contacts, incidents & maintenance** | On-call/vendor contacts, incident timelines, and scheduled maintenance windows | free-text secret-scrubbed |
| **Metrics** | Custom Prometheus-textfile metrics and their recent trend per host | numeric, name-validated; **the one source off by default** |
| **WG Access (VPN)** | WireGuard-based remote-access clients/tunnels and their connection state | no key material |
| **Config drift** | Per host: which tracked config files are currently drifted (ignored ones excluded), plus a "which hosts have drift?" rollup | file **paths** and status, never the captured diff |
| **Container-image CVEs** | Per host: per-image critical/high counts from the image scanner, so "prioritise my CVEs" sees the container layer and not just host packages | counts + image names |
| **OpenSCAP results** | Per-host baseline scan score, profile, pass/fail counts and the failing rule ids | grounds the compliance/hardening advisors |
| **Security findings** | On-disk secret findings (rule + path + count), the PII inventory (kind counts + paths) and AV/EDR tool state | **value-free by construction** — never a preview, fingerprint or matched value |
| **Hardware inventory** | Per host: SMART disk health, GPU telemetry, UPS/power, kernel/livepatch reboot-needed, board temperature and privileged-account posture, plus what the host is: the system maker and model and its installed memory (module count, total, kind and speed) *(7.5.0)* | models, states and counts — no secrets, and no serial numbers |
| **Incident memory** | Resolved-incident outcomes — what actually fixed similar incidents on *this* fleet | event names + resolution summaries, already value-free |
| **Automation rules** | Existing automation rules: name, trigger and action **type**, enabled state — so the rule-suggestion advisor stops proposing what you already have | never action bodies (a webhook URL or command can embed a credential) |
| **Applied remediations** | The auto-remediation ledger: what the guarded executor tried and whether it cleared the alert | rule + host + status, no action bodies |
| **Config-revision history** | Server-config change history — when, and by whom | **metadata only**, never the config values |
| **Privileged-command trail** | Per host: the recent sudo/root command trail, for access review and RCA | commands already redacted at ingest |
| **Controller self-observability** | RemotePower's own maintenance-sweep health — "did feature X stop running?" | sweep names, timings, last error |
| **Billing & time** | Invoice / quote / time-entry counts and totals by status, plus overdue | summary level only |
| **Physical & IPAM inventory** | Sites, racks, subnets and warranty state — "which rack is host X in", capacity and out-of-warranty planning | operator-authored metadata |

Fleet rollups come with **Live state**, they have no checkbox of their own. Three
rows cover more than one checkbox: **Tickets & KB** (tickets, knowledge base),
**Provisioning & rollouts** (blueprints, staged rollouts) and **Contacts, incidents &
maintenance** (three checkboxes). The per-host runbooks belong to **Docs & runbooks**.

Each chunk carries a stable id (e.g. `live/<host id>#cves`) that doubles as its
citation key, plus a freshness timestamp.

## Configuration (Settings → AI assistant → Knowledge index)

| Setting | Default | Meaning |
|---|---|---|
| Enable the knowledge index | on | Master switch for indexing + retrieval |
| Sources | all on except **metrics** | Which of the 34 sources to index — each is an individual checkbox. Only the long-retention metrics series is off by default (it is noisy and the largest); everything else is cheap and no-PII |
| Use embeddings | off | Semantic rerank. The box is greyed out when the embedding provider has no embeddings endpoint. The page notes whether embeddings stay local (Ollama, LocalAI) or send the indexed text to the provider (OpenAI) |
| Embedding model | provider default | `text-embedding-3-small` for OpenAI, `nomic-embed-text` for Ollama, `text-embedding-ada-002` for LocalAI |
| Embedding provider, base URL and API key | same as chat | Optional. Run embeddings on a different service than chat (OpenAI, Ollama or LocalAI), for example a separate GPU box. The chat key is never sent to a different service. The embedding key is masked after you save it; type `__clear__` to remove it |
| Max chunks per question | 8 | Upper bound on injected chunks (1 to 30) |
| History: keep last N days | 14 | Age cutoff for the history source (0 to 3650) |
| `reindex_min_interval_sec` | 600 | Throttle: lazy rebuild at most once per this many seconds (0 to 86400). Set through `POST /api/ai/config`, there is no box for it |
| `max_chars` | 6000 | Size budget for the chunks injected into one question (200 to 20000). Set through `POST /api/ai/config`, there is no box for it |
| Retrieve relevant infrastructure context per question (RAG) | on | Per-query injection into chat (Context awareness) |

The index rebuilds **lazily** on chat when an enabled source file is newer
than the last build — but at most once per `reindex_min_interval_sec`
(default 10 min), so a fleet whose `devices.json` bumps every heartbeat
doesn't rebuild (and, with embeddings on, re-embed volatile chunks) on
every chat. The manual **Rebuild index** button bypasses the throttle. A rebuild
embeds at most 2,000 new chunks; the rest are embedded by the next rebuild.
Volatile current-usage metrics (load, CPU %, memory %) live in their own
`#metrics` chunk so they never destabilise the stable specs/summary chunks.

## Privacy

- The encrypted credentials vault is excluded by key — metadata and docs
  only, never secrets.
- History chunks are redacted at index time using your AI privacy toggles
  (hostnames / IPs / secret-shaped tokens), so sensitive content is scrubbed
  before it reaches the index or, with embeddings on, a cloud provider.
- Embeddings egress is **opt-in** and off by default for cloud providers.
  Run a local Ollama embedding model to keep semantic search fully on-prem.
- The index is built from every host and is not scoped per role or tenant, so it is
  only used for full-access callers. In chat, a role limited to some groups, tags or
  sites and a user of a tenant get no retrieved context. `POST /api/ai/rag/search`
  answers them 403. With tenancy on, all of `/api/ai/rag/*` belongs to the platform
  operator.

## Endpoints

```
GET  /api/ai/rag/status     # freshness, chunk + embedding counts        (signed in)
POST /api/ai/rag/reindex     # rebuild corpus + index                     (admin)
POST /api/ai/rag/search      # standalone retrieval, no LLM call           (full access)
     body: {"query": "...", "top_n": 6}
POST /api/ai/rag/index-backend/migrate   # move the index, see below      (admin)
     body: {"target": "json" | "postgres"}
```

`/search` takes a query of up to 2,000 characters and `top_n` from 1 to 30 (the
**Max chunks per question** setting when you leave it out). It powers the
**Knowledge search** box under Settings → AI assistant: see which chunks a question
pulls in, each with its title, source and a 600-character excerpt, before trusting
an answer — no tokens spent. The same search runs in the command palette
(<kbd>Ctrl</kbd>/<kbd>Cmd</kbd>-<kbd>K</kbd>).

## Where the index lives

By default the index is a file in the data directory (`rag_index.json`). When the
storage backend is Postgres, **Settings → AI assistant → Knowledge index (RAG)** also
shows **Move index to Postgres (pgvector)**. It stores the chunks and their embeddings
in the database instead of the file and rebuilds the whole index there, which can take
a while with embeddings on. Keep the tab open until it finishes. The database needs
the pgvector extension. If the application role cannot create it, the page shows the
statement a database admin has to run once (`CREATE EXTENSION vector;`). If the write
to Postgres fails, the index stays in the file and the page says so. **Move index back to JSON** reverses it and drops the table. Only an
administrator of the installation can do either. The status line under the buttons
says which store holds the index.

## How retrieval is scored

1. **Lexical (BM25, k1=1.2, b=0.75).** A technical-token-preserving
   tokenizer keeps `CVE-2024-3094`, IPs, and version strings searchable
   while dropping stopwords.
2. **Semantic (optional).** The query is embedded once; cosine similarity
   ranks chunks. For corpora over ~2000 chunks, cosine reranks the lexical
   prefilter rather than sweeping everything.
3. **Fusion.** Reciprocal Rank Fusion (k=60) combines the two ranked lists —
   rank-based, so no score normalisation between unbounded BM25 and
   bounded cosine.

## Limitations

- Lexical search has no stemming, so "disk" won't match the indexed token
  "disks". Enable embeddings for paraphrase/semantic recall.
- Embeddings require OpenAI, Ollama or LocalAI, either as the chat provider or as
  the separate embedding provider. Anthropic, DeepSeek, OpenCode and OpenClaw have
  no embeddings endpoint, so with one of them as the chat provider search stays
  lexical-only unless you set one of those three as the embedding provider.
