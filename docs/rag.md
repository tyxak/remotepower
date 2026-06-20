# RAG over your infrastructure

RemotePower's AI assistant retrieves relevant facts from *your* fleet and
injects them into every request, so answers reference your devices, your
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

| Source | Contents | Notes |
|---|---|---|
| **Docs & runbooks** | Product Markdown docs + per-device AI runbooks | docs deployed to `/var/lib/remotepower/docs/` |
| **Live state** | Per device: summary (incl. IP/hostname/MAC), resources (CPU/RAM/disk/uptime), listening ports, patch & reboot status, config drift, watched services, **open alerts**, **local TLS cert expiry**, CVEs, containers, SNMP | one chunk per `(device, facet)` |
| **Fleet rollups** | Cross-host summaries: worst CVEs, **all open (unresolved) alerts worst-first**, hosts with pending updates / pending reboot, drifted hosts, certs expiring soon | answers "which hosts have X?" / "what is alerting?" |
| **CMDB** | Asset metadata + per-asset Markdown docs | **credentials vault never indexed** |
| **History** | Recent commands, alerts, fleet events | bounded by count + age; redaction applied |
| **Firewall** | Per device: host-firewall posture (nftables/iptables/ufw/firewalld — active, rule counts, policy) + fail2ban jails/bans, and a fleet "no active firewall" rollup | rule **counts**, never raw rules/counters |
| **Integrations** | Homelab software-integration health (Pi-hole, TrueNAS, *arr, …) + a down/degraded rollup | fleet-scoped; secrets never indexed |
| **Backups** | Per device: backup freshness (which watched paths are stale, age) + a fleet "stale backups" rollup | answers "are X's backups current?" |
| **Email & DNS** | DMARC/SPF/DKIM posture per domain, DNSBL/IP-reputation status, and DNS-resolver health — grounds the *email-deliverability* and *DNS-hygiene* AI advisors | admin-configured posture, no PII |

Each chunk carries a stable id (e.g. `live/web01#cves`) that doubles as its
citation key, plus a freshness timestamp.

## Configuration (Settings → AI → Knowledge index)

| Setting | Default | Meaning |
|---|---|---|
| Enable the knowledge index | on | Master switch for indexing + retrieval |
| Sources | docs, live, cmdb on; history off | Which sources to index |
| Use embeddings | off | Semantic rerank; pre-checked for local providers |
| Embedding model | provider default | e.g. `text-embedding-3-small`, `nomic-embed-text` |
| Max chunks per question | 6 | Upper bound on injected chunks |
| History: keep last N days | 14 | Age cutoff for the history source |
| `reindex_min_interval_sec` | 600 | Throttle: lazy rebuild at most once per this many seconds |
| Retrieve context per question (RAG) | on | Per-query injection into chat (Context awareness) |

The index rebuilds **lazily** on chat when an enabled source file is newer
than the last build — but at most once per `reindex_min_interval_sec`
(default 10 min), so a fleet whose `devices.json` bumps every heartbeat
doesn't rebuild (and, with embeddings on, re-embed volatile chunks) on
every chat. The manual **Rebuild index** button bypasses the throttle.
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

## Endpoints

```
GET  /api/ai/rag/status     # freshness, chunk + embedding counts        (auth)
POST /api/ai/rag/reindex     # rebuild corpus + index                     (admin)
POST /api/ai/rag/search      # standalone retrieval, no LLM call           (auth)
     body: {"query": "...", "top_n": 6}
```

`/search` powers the **Test retrieval** box in Settings: see exactly which
chunks a question pulls in, with scores and citations, before trusting an
answer — no tokens spent.

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
- Embeddings require an embedding-capable provider; Anthropic and DeepSeek
  have no embeddings endpoint today (lexical-only there).
