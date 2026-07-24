"""
RemotePower RAG index — v3.4.0

Level-2/3 RAG: retrieval over the operator's actual infrastructure.

The roadmap for this module was written into ai_context.py back at
v2.1.7: Level-1 was a hand-curated always-true preamble; Level-2 is
"keyword retrieval over docs/"; Level-3 is "embeddings only if that
still falls short". This module implements both Level-2 and Level-3
in one place, with Level-2 (lexical BM25) as the always-on base and
Level-3 (embeddings) as an optional rerank layer.

Design constraints that shaped every decision here:

  * Pure stdlib. RAG indexing itself takes no pip deps, so there is no
    faiss / chromadb / numpy. BM25 runs
    over a hand-built inverted index; cosine similarity is a plain
    Python dot product. At the scale this tool targets (~10 devices,
    a few dozen docs → low thousands of chunks) that is sub-millisecond
    for lexical and tens of milliseconds for a full cosine sweep.

  * Anthropic — the default provider — has no embeddings endpoint.
    So lexical retrieval MUST stand on its own; embeddings are layered
    in only when an embedding-capable provider (OpenAI / Ollama /
    LocalAI) is configured. When both signals are present we fuse them
    with Reciprocal Rank Fusion rather than trusting either alone.

  * This module is pure and side-effect free. It does NOT read the
    data-source JSON files, does NOT import ai_provider, and does NOT
    persist itself. The caller (api.py) owns all I/O: it loads the
    source files, hands already-shaped data to the corpus builders,
    calls ai_provider.embed for vectors, and persists the index dict
    via its own load()/save() helpers (which give us locking + .bak).
    That keeps this module trivially unit-testable with plain dicts.

Public surface used by api.py:

  tokenize(text)                          → list[str]
  chunk_markdown(text, ...)               → list[(heading_path, chunk)]
  make_doc(...)                           → one normalized doc dict
  build_docs_corpus(files)                → list[doc]
  build_runbooks_corpus(runbooks)         → list[doc]
  build_cmdb_corpus(cmdb_store)           → list[doc]   (vault excluded)
  build_live_state_corpus(devices, ...)   → list[doc]
  build_history_corpus(...)               → list[doc]
  InfraIndex                              → build / search / persist
"""

import re
import math
import hashlib


# ── Tokenisation ─────────────────────────────────────────────────────────────
#
# A naive `\w+` tokenizer destroys exactly the tokens an operator
# searches for: CVE-2024-3094 becomes "cve 2024 3094", 192.168.1.10
# becomes four numbers, nginx-1.25.3 loses its version. So we extract
# "rich" tokens that keep internal . - _ / : + and, for any rich token
# that carries those separators, ALSO emit its alphanumeric sub-pieces.
# That way "CVE-2024-3094" matches a query for "cve" or "3094" or the
# exact id, and "nginx/1.25.3" matches "nginx" and "1.25.3".

_RICH_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:+\-]*[A-Za-z0-9]|[A-Za-z0-9]")
_SUBSPLIT_RE = re.compile(r"[._/:+\-]+")

# A deliberately small stopword set. We only strip these from the
# *simple* alphanumeric tokens — rich/technical tokens are always kept,
# because "in", "on", "up" can be substrings of real signal but the
# bare words carry none. Keeping the list short avoids dropping words
# that matter in an ops context ("down", "fail", "error" stay).
_STOPWORDS = frozenset("""
a an and are as at be by for from has have in into is it its of on
or that the their then there these this to was were will with
""".split())


def tokenize(text):
    """Lowercase, technical-token-preserving tokenizer.

    Returns a list (not a set) so the caller can count term frequency.
    Rich tokens are kept whole AND split into sub-pieces for recall.
    Stopwords are dropped only from bare alphanumeric tokens.
    """
    if not text:
        return []
    out = []
    for m in _RICH_TOKEN_RE.finditer(text.lower()):
        tok = m.group(0)
        has_sep = bool(_SUBSPLIT_RE.search(tok))
        if has_sep:
            # Keep the whole technical token (exact-match recall) ...
            if len(tok) >= 2:
                out.append(tok)
            # ... and its pieces (partial recall).
            for piece in _SUBSPLIT_RE.split(tok):
                if len(piece) >= 2 and piece not in _STOPWORDS:
                    out.append(piece)
        else:
            if len(tok) >= 2 and tok not in _STOPWORDS:
                out.append(tok)
    return out


# ── Markdown chunking ────────────────────────────────────────────────────────

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")


def _slug(text, fallback='section'):
    s = re.sub(r"[^a-z0-9]+", "-", (text or '').lower()).strip("-")
    return s[:60] or fallback


def chunk_markdown(text, max_chars=1200):
    """Split Markdown into (heading_path, chunk_text) pairs.

    Splits on ATX headings (#..######). A section longer than max_chars
    is further split on blank-line paragraph boundaries so no single
    chunk blows the per-chunk budget. Heading path is the breadcrumb of
    enclosing headings ("Install > Debian"), which becomes useful chunk
    title context for retrieval and citations.

    Returns [] for empty input. A document with no headings yields one
    or more chunks under the empty heading path "".
    """
    if not text or not text.strip():
        return []
    lines = text.splitlines()
    # Build sections: each is (heading_path, body_lines)
    sections = []
    stack = []          # list of (level, title)
    cur_body = []

    def _flush():
        if cur_body and any(l.strip() for l in cur_body):
            path = ' > '.join(t for _, t in stack)
            sections.append((path, '\n'.join(cur_body).strip()))

    for line in lines:
        hm = _HEADING_RE.match(line)
        if hm:
            _flush()
            cur_body = []
            level = len(hm.group(1))
            title = hm.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            # Heading text itself is useful retrieval signal — seed the body
            cur_body.append(title)
        else:
            cur_body.append(line)
    _flush()

    if not sections:
        sections = [('', text.strip())]

    # Enforce the per-chunk size budget by paragraph splitting.
    out = []
    for path, body in sections:
        if len(body) <= max_chars:
            out.append((path, body))
            continue
        para = []
        size = 0
        for block in re.split(r"\n\s*\n", body):
            block = block.strip()
            if not block:
                continue
            if size + len(block) > max_chars and para:
                out.append((path, '\n\n'.join(para)))
                para, size = [], 0
            para.append(block)
            size += len(block) + 2
        if para:
            out.append((path, '\n\n'.join(para)))
    return out


# ── Document model ───────────────────────────────────────────────────────────

def _hash(text):
    return hashlib.sha256((text or '').encode('utf-8', 'replace')).hexdigest()[:16]


def make_doc(doc_id, source, dtype, text, title=None, device=None, ts=0, meta=None):
    """Build one normalized corpus document.

    doc_id   stable id, also the citation key (e.g. "live/web01#cves")
    source   one of: docs | live_state | cmdb | history
    dtype    finer type for UI grouping (e.g. "device_cves", "doc_md")
    text     the searchable/embeddable body
    title    human label for citations
    device   device id/name if device-scoped, else None
    ts       freshness epoch seconds (0 = unknown / static)
    """
    text = (text or '').strip()
    return {
        'id':     doc_id,
        'source': source,
        'type':   dtype,
        'device': device,
        'title':  title or doc_id,
        'text':   text,
        'ts':     int(ts or 0),
        'hash':   _hash(text),
        'meta':   meta or {},
    }


# ── Corpus builders ──────────────────────────────────────────────────────────
#
# Each builder takes already-loaded, in-memory data (never a file path)
# and returns a list of docs. api.py owns the file reads and the shape
# knowledge for the live stores; these builders stay defensive about
# missing/odd shapes so a single malformed record can't sink a reindex.

def _dedup_id(base, seen):
    """Make `base` unique within `seen` by appending ~2, ~3, … on collision.

    A single heading split into multiple chunks (long section) would otherwise
    emit the same `docs/<doc>#<slug>` id for each chunk — they'd overwrite each
    other in the index (`_by_id`) and violate the pgvector PRIMARY KEY, silently
    losing content. Mutates `seen`."""
    if base not in seen:
        seen.add(base)
        return base
    i = 2
    while f"{base}~{i}" in seen:
        i += 1
    nid = f"{base}~{i}"
    seen.add(nid)
    return nid


def device_focus_tokens(dev_id):
    """The query tokens that should 'focus' a search on this device: the full
    id plus its first hostname label (shared domain labels excluded). Same rule
    the JSON index uses internally — exposed so the Postgres path can match
    identically."""
    low = str(dev_id).lower()
    return {t for t in (low, low.split('.')[0]) if len(t) >= 2}


def focus_devices_for_query(query, device_ids):
    """Device ids a query explicitly names (by id or short hostname). Shared by
    the JSON/SQLite index and the Postgres path so single-host focus behaves
    identically on every backend."""
    qset = set(tokenize(query or ''))
    if not qset:
        return set()
    return {dev for dev in (device_ids or [])
            if device_focus_tokens(dev) & qset}


def build_docs_corpus(files):
    """files: iterable of (name, markdown_text) — product docs + manuals."""
    docs = []
    for name, text in (files or []):
        seen = set()
        for path, chunk in chunk_markdown(text):
            sec = _slug(path) if path else 'body'
            title = f"{name}" + (f" — {path}" if path else "")
            docs.append(make_doc(
                _dedup_id(f"docs/{name}#{sec}", seen), 'docs', 'doc_md', chunk,
                title=title, meta={'doc': name, 'heading': path}))
    return docs


def build_runbooks_corpus(runbooks, resolve_device=None):
    """runbooks: dict device_id -> {'content': markdown, 'generated_at': ts}.

    resolve_device: optional callable mapping the runbook store key to the
    SAME canonical device id the live-state corpus uses. The runbook/CMDB
    stores are keyed by the internal device id, but live_state keys by the
    device's name/hostname when the record carries no embedded id (the shape a
    storage migration produced). Without this remap the runbook's `device`
    won't match the host's live chunks, so naming the host never surfaces its
    runbook — the "no documentation for X" bug.
    """
    resolve = resolve_device or (lambda k: k)
    docs = []
    if not isinstance(runbooks, dict):
        return docs
    for dev_id, rec in runbooks.items():
        if not isinstance(rec, dict):
            continue
        dev = resolve(dev_id) or dev_id
        content = rec.get('content') or rec.get('markdown') or rec.get('text') or ''
        ts = rec.get('generated_at') or rec.get('updated_at') or 0
        seen = set()
        for path, chunk in chunk_markdown(content):
            sec = _slug(path) if path else 'body'
            docs.append(make_doc(
                _dedup_id(f"runbook/{dev}#{sec}", seen), 'docs', 'runbook', chunk,
                title=f"Runbook: {dev}" + (f" — {path}" if path else ""),
                device=dev, ts=ts, meta={'heading': path}))
    return docs


# Field names that must NEVER be indexed. The credentials vault is
# AES-GCM encrypted at rest (cmdb_vault.py); even though what lands in
# cmdb.json is ciphertext, we exclude the whole subtree by name so a
# future plaintext field or a decrypted cache can't silently leak into
# the prompt (and, worse, into a cloud embedding request).
_CMDB_SECRET_KEYS = frozenset({'credentials', 'secrets', 'vault', 'password',
                               'passwords', 'fields',
                               # v5.8.0 (bughunt): a CMDB `licenses[].key` is a
                               # software license / activation key — a sensitive
                               # credential-like string that must not reach the
                               # embedding corpus (and, with a cloud provider,
                               # go off-box). `key` is too generic for the
                               # substring set (pubkey/key_id/…), so it lives in
                               # this CMDB-scoped exact-match set.
                               'key'})
# Substrings that mark a field as secret-bearing, matched case-insensitively
# against the key NAME. Broader than an exact set (which missed api_key / token /
# passphrase / private_key / community / …) so an operator-added plaintext field
# like `api_key: sk_live_…` can never be embedded into the vector store or sent
# to a cloud embedding provider.
_SECRET_SUBSTR = ('secret', 'password', 'passwd', 'token', 'api_key', 'apikey',
                  'passphrase', 'private_key', 'privatekey', 'community',
                  'bearer', 'webhook', 'vault', 'cred')


def _is_secret_key(name):
    """True if a field name looks secret-bearing (case-insensitive substring)."""
    n = str(name).lower()
    return any(s in n for s in _SECRET_SUBSTR)


def build_cmdb_corpus(cmdb_store, resolve_device=None):
    """cmdb_store: dict device_id -> record. Indexes asset metadata and
    per-asset Markdown docs. The credentials vault is excluded by key.

    resolve_device: see build_runbooks_corpus — maps the CMDB store key to the
    canonical device id live_state uses, so CMDB metadata/docs associate with
    the right host when queried by name."""
    resolve = resolve_device or (lambda k: k)
    docs = []
    if not isinstance(cmdb_store, dict):
        return docs
    for store_key, rec in cmdb_store.items():
        if not isinstance(rec, dict):
            continue
        dev_id = resolve(store_key) or store_key
        # Asset metadata: everything except secret subtrees and the docs
        # list (handled separately below).
        meta_lines = []
        for k, v in rec.items():
            if k in _CMDB_SECRET_KEYS or _is_secret_key(k) or k == 'docs' or k == 'documentation':
                continue
            if v in (None, '', [], {}):
                continue
            if isinstance(v, (list, tuple)):
                # v5.8.0 (bughunt): a list of DICTS (licenses, contacts, custom
                # facets, …) must have its ITEM sub-keys secret-filtered too — the
                # old `str(x)` embedded each dict verbatim, so a secret-/key-named
                # sub-field leaked into the corpus (and, with a cloud embedding
                # provider, off-box). Mirror the dict branch + _format_facet.
                parts = []
                for x in v:
                    if isinstance(x, dict):
                        parts.append(', '.join(
                            f"{kk}={vv}" for kk, vv in x.items()
                            if not isinstance(vv, (list, dict))
                            and kk not in _CMDB_SECRET_KEYS and not _is_secret_key(kk)))
                    else:
                        parts.append(str(x))
                v = '; '.join(p for p in parts if p)
            elif isinstance(v, dict):
                v = ', '.join(f"{kk}={vv}" for kk, vv in v.items()
                              if kk not in _CMDB_SECRET_KEYS and not _is_secret_key(kk))
            meta_lines.append(f"{k}: {v}")
        if meta_lines:
            docs.append(make_doc(
                f"cmdb/{dev_id}#meta", 'cmdb', 'cmdb_asset',
                f"CMDB asset {dev_id}\n" + '\n'.join(meta_lines),
                title=f"CMDB: {dev_id}", device=dev_id,
                ts=rec.get('updated_at') or 0))
        # Per-asset Markdown docs.
        for d in (rec.get('docs') or []):
            if not isinstance(d, dict):
                continue
            body = _scrub_script_body(d.get('body') or '')  # SEC v6.4.0: scrub inline secrets
            did = d.get('id') or _slug(d.get('title', ''))
            seen = set()
            for path, chunk in chunk_markdown(body):
                sec = _slug(path) if path else 'body'
                title = d.get('title') or 'doc'
                docs.append(make_doc(
                    _dedup_id(f"cmdb/{dev_id}/doc/{did}#{sec}", seen), 'cmdb', 'cmdb_doc', chunk,
                    title=f"CMDB doc ({dev_id}): {title}", device=dev_id,
                    ts=d.get('updated_at') or 0, meta={'heading': path}))
    return docs


def _format_facet(data, max_items=40):
    """Render an arbitrary live-state value into compact, readable lines.

    Retrieval and embedding quality both suffer from raw JSON, so we
    flatten lists of dicts into 'k=v, k=v' lines and dicts into 'k: v'.
    Bounded by max_items so a 500-container host can't bloat one chunk.
    """
    if data is None:
        return ''
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, (int, float, bool)):
        return str(data)
    lines = []
    if isinstance(data, dict):
        for k, v in data.items():
            if _is_secret_key(k):
                continue   # never emit a secret-named field into the corpus
            if isinstance(v, (list, dict)):
                v = _format_facet(v, max_items)
                lines.append(f"{k}:\n{v}")
            else:
                lines.append(f"{k}: {v}")
    elif isinstance(data, (list, tuple)):
        for item in data[:max_items]:
            if isinstance(item, dict):
                lines.append(', '.join(f"{k}={v}" for k, v in item.items()
                                       if not isinstance(v, (list, dict)) and not _is_secret_key(k)))
            else:
                lines.append(str(item))
        if len(data) > max_items:
            lines.append(f"... ({len(data) - max_items} more)")
    return '\n'.join(l for l in lines if l)


def _format_mounts(mounts):
    """Render per-mount capacity rows (path + %used + sizes + flags).

    The heartbeat sanitizer stores per-mount data under `sysinfo.mounts`
    (list of {path, used_gb, total_gb, fstype, percent?, inode_percent?,
    ro?, network?, server?, stalled?}); it also tolerates the legacy
    `{mount, percent}` shape a few callers/tests still use. Defensive
    about odd items since load() may hand us anything.
    """
    lines = []
    for m in (mounts or [])[:60]:
        if not isinstance(m, dict):
            continue
        path = m.get('path') or m.get('mount') or ''
        if not path:
            continue
        parts = [str(path)]
        pct = m.get('percent')
        if isinstance(pct, (int, float)):
            parts.append(f"{pct}% used")
        used, total = m.get('used_gb'), m.get('total_gb')
        if isinstance(total, (int, float)) and total:
            parts.append(f"{used if isinstance(used, (int, float)) else 0}/{total} GB")
        ipct = m.get('inode_percent')
        if isinstance(ipct, (int, float)):
            parts.append(f"inodes {ipct}%")
        if m.get('ro'):
            parts.append("read-only")
        if m.get('stalled'):
            parts.append("STALLED")
        if m.get('network'):
            srv = m.get('server') or ''
            parts.append("network share" + (f" {srv}" if srv else ""))
        fs = m.get('fstype')
        if fs:
            parts.append(str(fs))
        lines.append(" — ".join(parts))
    return '\n'.join(lines)


def build_live_state_corpus(devices, facets=None, now=0):
    """Build per-(device, facet) chunks of current fleet state.

    devices : iterable of device dicts (from devices.json values).
    facets  : optional dict device_id -> {facet_name -> data} for state
              that lives outside the device record (cves, patches,
              containers, tls, snmp). Whatever the caller supplies gets
              its own chunk; missing facets are simply skipped.
    """
    docs = []
    facets = facets or {}
    # Fleet-wide aggregates, collected during the per-device pass and emitted
    # as rollup chunks afterwards so cross-fleet questions ("which hosts need
    # a reboot / have pending updates / have drifted?") have a single chunk to
    # retrieve instead of relying on the model to fan out over every device.
    reboot_hosts = []
    patch_hosts = []
    drift_hosts = []
    for dev in (devices or []):
        if not isinstance(dev, dict):
            continue
        dev_id = dev.get('id') or dev.get('name')
        if not dev_id:
            continue
        name = dev.get('name', dev_id)
        ts = dev.get('last_seen') or now or 0

        # Summary chunk from the device record + sysinfo. We deliberately
        # index only *stable* fields here — os, kernel, platform, group,
        # tags, notes. Volatile telemetry (uptime, load, cpu_percent,
        # memory) is excluded: it churns the embedding cache on every
        # heartbeat for no retrieval value (a bare current load number is
        # noise, and live metrics are better answered from the dashboard
        # than from a stale index). Disk usage gets its own hardware chunk.
        si = dev.get('sysinfo') or {}
        summary = [f"Device {name} (id {dev_id})"]
        # Network identity — the operator routinely asks "what IP / hostname
        # does X have". These are stable enough to embed (an IP changes far
        # less often than load/cpu) and are exactly what a who/where question
        # needs. NOTE: at chat time ai_provider.chat still redacts IPs/
        # hostnames per the AI privacy toggles, so the model only sees them
        # when 'send_ips' / 'send_hostnames' are enabled; the Test-retrieval
        # box (no provider) always shows them.
        for k in ('hostname', 'fqdn', 'ip', 'host', 'mac'):
            v = dev.get(k)
            if v:
                summary.append(f"{k}: {v}")
        for k in ('os', 'os_pretty', 'group'):
            if dev.get(k):
                summary.append(f"{k}: {dev[k]}")
        for k in ('kernel', 'platform', 'os_pretty'):
            if si.get(k):
                summary.append(f"{k}: {si[k]}")
        if dev.get('tags'):
            summary.append("tags: " + ', '.join(map(str, dev['tags'])))
        if (dev.get('notes') or '').strip():
            summary.append("notes: " + dev['notes'].strip())
        docs.append(make_doc(
            f"live/{dev_id}#summary", 'live_state', 'device_summary',
            '\n'.join(summary), title=f"{name} — summary", device=dev_id, ts=ts))

        # Disks / hardware from sysinfo. The heartbeat sanitizer stores
        # per-mount capacity under `sysinfo.mounts` (NOT `disks` — that key is
        # never persisted, so reading it here left the disk-capacity chunk
        # permanently dead; the only disk fact reaching the AI was the single
        # root `disk_percent` in the metrics chunk). Read `mounts` (the real
        # field); fall back to a legacy `disks` list if a caller supplies one.
        mounts = si.get('mounts')
        disk_body = _format_mounts(mounts) if isinstance(mounts, list) else ''
        if not disk_body and si.get('disks'):
            disk_body = _format_facet(si.get('disks'))
        if disk_body.strip():
            docs.append(make_doc(
                f"live/{dev_id}#hardware", 'live_state', 'device_hardware',
                f"{name} disk / filesystem capacity (per-mount %used, sizes, "
                f"inode use, read-only / stalled / network mounts):\n"
                + disk_body,
                title=f"{name} — hardware", device=dev_id, ts=ts))

        # Listening ports from sysinfo. The agent already collects these
        # (sysinfo.listening_ports); indexing them answers "what ports are
        # listening on X" from real data instead of the model suggesting
        # `ss`/`netstat`. Ports are stable enough to embed (a service's
        # listen set rarely changes between heartbeats). We do NOT index
        # top_processes — those are as volatile as load/cpu (see summary).
        if si.get('listening_ports'):
            docs.append(make_doc(
                f"live/{dev_id}#ports", 'live_state', 'device_ports',
                f"{name} listening ports (open TCP/UDP sockets):\n"
                + _format_facet(si.get('listening_ports')),
                title=f"{name} — listening ports", device=dev_id, ts=ts))

        # Resources / specs — stable hardware + capacity facts the operator
        # asks about ("how much memory/disk/cpu does X have", "how long has
        # X been up"). Totals are stable; we keep current free/percent out of
        # the embedded text (volatile, see the summary note).
        # Stable specs only. Note: uptime_seconds is intentionally NOT here —
        # it increments every heartbeat, so it would change the chunk hash
        # constantly and re-embed it each rebuild. boot_time is the stable
        # anchor (uptime = now - boot_time, which the model can compute).
        res = []
        for label, key in (('cpu', 'cpu'), ('cpu cores', 'cores'),
                           ('cpu cores', 'cpu_count'),
                           ('total memory (MB)', 'mem_total_mb'),
                           ('total disk (GB)', 'disk_total_gb'),
                           ('boot time', 'boot_time'),
                           ('last boot', 'last_boot')):
            v = si.get(key)
            if v not in (None, '', 0):
                res.append(f"{label}: {v}")
        if res:
            docs.append(make_doc(
                f"live/{dev_id}#resources", 'live_state', 'device_resources',
                f"{name} resources / hardware specs:\n" + '\n'.join(res),
                title=f"{name} — resources", device=dev_id, ts=ts))

        # Current resource usage — volatile (changes every heartbeat). Kept in
        # its own small chunk so it doesn't destabilise the stable specs/
        # summary chunks; the reindex throttle (api side) bounds how often
        # this re-embeds when embeddings are enabled.
        usage = []
        for label, key in (('load average', 'loadavg'),
                           ('cpu usage %', 'cpu_percent'),
                           ('memory usage %', 'mem_percent'),
                           ('swap usage %', 'swap_percent'),
                           ('disk usage %', 'disk_percent'),
                           # Saturation signals that cause hard-to-debug outages
                           # — index them so the AI can answer "is X running out
                           # of file descriptors / conntrack entries?".
                           ('open file descriptors %', 'fd_percent'),
                           ('conntrack table %', 'conntrack_percent')):
            v = si.get(key)
            if v not in (None, ''):
                usage.append(f"{label}: {v}")
        if usage:
            docs.append(make_doc(
                f"live/{dev_id}#metrics", 'live_state', 'device_metrics',
                f"{name} current resource usage (load, CPU, memory, swap, "
                f"disk):\n" + '\n'.join(usage),
                title=f"{name} — current usage", device=dev_id, ts=ts))

        # Mount problems (stalled NFS, read-only remounts, missing mounts) — a
        # high-value reliability signal the agent already reports. Index it so
        # "which hosts have a stalled / failed mount?" answers from real data
        # instead of the model punting to a tool call.
        mi = si.get('mount_issues')
        if mi:
            docs.append(make_doc(
                f"live/{dev_id}#mountissues", 'live_state', 'device_mount_issues',
                f"{name} mount problems (stalled / read-only / missing mounts):\n"
                + _format_facet(mi),
                title=f"{name} — mount issues", device=dev_id, ts=ts))

        # Failing custom checks — index only the non-OK ones so "which checks
        # are failing on X" is answerable from the corpus. The heartbeat
        # sanitizer stores `custom_check_results` as a DICT (check-id -> {status,
        # output}, status ∈ ok/warning/critical/unknown), NOT a list — reading it
        # as a list left this chunk permanently dead. Handle both shapes.
        ccr = si.get('custom_check_results')
        failing = []
        _not_ok = ('ok', 'pass', 'passing', 'up', '')
        if isinstance(ccr, dict):
            for cid, res in ccr.items():
                if not isinstance(res, dict):
                    continue
                if str(res.get('status', '')).lower() in _not_ok:
                    continue
                failing.append({'check': cid, 'status': res.get('status', ''),
                                'output': res.get('output', '')})
        elif isinstance(ccr, list):
            failing = [c for c in ccr if isinstance(c, dict)
                       and str(c.get('status', '')).lower() not in _not_ok]
        if failing:
            docs.append(make_doc(
                f"live/{dev_id}#checks", 'live_state', 'device_checks',
                f"{name} failing custom checks:\n" + _format_facet(failing),
                title=f"{name} — failing checks", device=dev_id, ts=ts))

        # ── Host posture facts — degraded pools, failed units/timers, DIMM ECC
        # errors, clock skew, gateway reachability, OOM kills, mail-queue depth,
        # and Windows security posture. The operator sees these in the drawer /
        # Storage page but the AI corpus had none of them. All are numeric/enum
        # control-plane signals (no free text / no secret risk). Defensive about
        # shape since load() may hand us anything.

        # Storage / RAID pool health (zfs/mdadm/btrfs) — "which pools are
        # degraded / have scrubs overdue?". Degraded is derived from `state`
        # (there is no explicit boolean); scrub is a free string; last_snapshot
        # is an epoch (0 = the pool has NO snapshots).
        sh = si.get('storage_health')
        if isinstance(sh, list):
            pool_lines = []
            for p in sh[:40]:
                if not isinstance(p, dict):
                    continue
                nm = p.get('name')
                if not nm:
                    continue
                state = str(p.get('state', '') or '')
                degraded = state.lower() not in (
                    'online', 'healthy', 'ok', 'active', 'clean', '')
                parts = [str(nm)]
                if p.get('kind'):
                    parts.append(str(p['kind']))
                if state:
                    parts.append(f"state {state}"
                                 + (" (DEGRADED)" if degraded else ""))
                cap = p.get('capacity')
                if isinstance(cap, int):
                    parts.append(f"{cap}% full")
                if p.get('scrub'):
                    parts.append(f"scrub: {p['scrub']}")
                ls = p.get('last_snapshot')
                if isinstance(ls, int):
                    parts.append("no snapshots" if ls == 0
                                 else f"last snapshot epoch {ls}")
                pool_lines.append(" — ".join(parts))
            if pool_lines:
                docs.append(make_doc(
                    f"live/{dev_id}#storage", 'live_state', 'device_storage',
                    f"{name} storage / RAID pool health (zfs/mdadm/btrfs — pool "
                    f"state, degraded pools, scrub status, snapshot age):\n"
                    + '\n'.join(pool_lines),
                    title=f"{name} — storage health", device=dev_id, ts=ts))

        posture = []
        fu = si.get('failed_units')
        if isinstance(fu, list):
            _fu = [str(u) for u in fu[:50] if u]
            if _fu:
                posture.append("failed systemd units: " + ', '.join(_fu))
        tm = si.get('timers')
        if isinstance(tm, list):
            _ft = [str(t.get('unit')) for t in tm
                   if isinstance(t, dict) and t.get('failed') and t.get('unit')]
            if _ft:
                posture.append("failed systemd timers: " + ', '.join(_ft[:50]))
        ecc = si.get('ecc')
        if isinstance(ecc, dict) and (ecc.get('ce') or ecc.get('ue')):
            posture.append(
                f"ECC memory errors: {ecc.get('ce', 0)} correctable, "
                f"{ecc.get('ue', 0)} uncorrectable"
                + (f" across {ecc.get('controllers')} controller(s)"
                   if ecc.get('controllers') else ""))
        clk = si.get('clock')
        if isinstance(clk, dict) and (clk.get('skewed') or clk.get('synced') is False):
            off = clk.get('offset_ms')
            posture.append(
                "clock skew / NTP unsynchronised"
                + (f", offset {off} ms" if isinstance(off, (int, float)) else "")
                + (" (not synced)" if clk.get('synced') is False else ""))
        gw = si.get('gateway')
        if isinstance(gw, dict):
            gw_ip = gw.get('ip', '') or ''
            if gw.get('reachable') is False:
                posture.append((f"default gateway {gw_ip} UNREACHABLE").strip())
            else:
                lat = gw.get('latency_ms')
                if isinstance(lat, (int, float)):
                    posture.append(
                        (f"default gateway {gw_ip} latency {lat} ms").strip())
        oom = si.get('last_oom_ts')
        if isinstance(oom, (int, float)) and oom > 0:
            proc = si.get('last_oom_proc')
            posture.append(f"most recent OOM kill: epoch {int(oom)}"
                           + (f" (process {proc})" if proc else ""))
        mq = si.get('mailq')
        if isinstance(mq, int) and mq > 0:
            posture.append(f"mail queue depth: {mq}")
        wp = si.get('win_posture')
        if isinstance(wp, dict):
            wl = []
            if 'defender_realtime' in wp:
                wl.append("Defender real-time protection: "
                          + ("on" if wp.get('defender_realtime') else "OFF"))
            if isinstance(wp.get('defender_sig_age_days'), (int, float)):
                wl.append(f"Defender signature age: {wp['defender_sig_age_days']}d")
            for b in (wp.get('bitlocker') or []):
                if isinstance(b, dict) and b.get('mount'):
                    wl.append(f"BitLocker {b.get('mount')}: {b.get('status', '')}")
            for f in (wp.get('firewall') or []):
                if isinstance(f, dict) and f.get('name'):
                    wl.append(f"firewall {f.get('name')}: "
                              + ("on" if f.get('enabled') else "OFF"))
            if wp.get('wu_service'):
                wl.append(f"Windows Update service: {wp['wu_service']}")
            if wl:
                posture.append("Windows security posture:\n  " + '\n  '.join(wl))
        # v6.4.0: macOS posture parity with Windows.
        mp = si.get('mac_posture')
        if isinstance(mp, dict):
            ml = []
            for _k, _lbl in (('filevault', 'FileVault disk encryption'),
                             ('firewall', 'application firewall'),
                             ('gatekeeper', 'Gatekeeper'),
                             ('sip', 'System Integrity Protection')):
                if isinstance(mp.get(_k), bool):
                    ml.append(f"{_lbl}: " + ("on" if mp[_k] else "OFF"))
            if isinstance(mp.get('auto_security_update'), bool):
                ml.append("automatic security updates: "
                          + ("on" if mp['auto_security_update'] else "off"))
            if ml:
                posture.append("macOS security posture:\n  " + '\n  '.join(ml))
        if posture:
            docs.append(make_doc(
                f"live/{dev_id}#posture", 'live_state', 'device_posture',
                f"{name} host posture (failed systemd units/timers, ECC memory "
                f"errors, clock skew, default-gateway reachability, OOM kills, "
                f"mail-queue depth"
                + (", Windows security" if isinstance(wp, dict) else "")
                + "):\n" + '\n'.join(posture),
                title=f"{name} — posture", device=dev_id, ts=ts))

        # Running process NAMES (the unique set, sorted for a stable chunk hash)
        # — answers "is nginx / postgres running on X" without a tool call. We
        # index the name set (stable) NOT top_processes (CPU-sorted, volatile).
        pn = si.get('proc_names')
        if isinstance(pn, (list, tuple, set)):
            pnames = sorted({str(p) for p in pn if p})[:120]
            if pnames:
                docs.append(make_doc(
                    f"live/{dev_id}#processes", 'live_state', 'device_processes',
                    f"{name} running process names:\n" + ', '.join(pnames),
                    title=f"{name} — processes", device=dev_id, ts=ts))

        # Patch / reboot status. `upgradable` is a pending-update count on the
        # device record; reboot_required comes from sysinfo. Both answer
        # high-value operational questions and feed the fleet rollups below.
        upgradable = dev.get('upgradable')
        reboot_required = bool(si.get('reboot_required'))
        patch_lines = []
        if isinstance(upgradable, int):
            patch_lines.append(f"pending package updates: {upgradable}")
            if upgradable > 0:
                patch_hosts.append((name, upgradable))
        # v6.2.2: vendor-flagged SECURITY update count (apt -security / dnf
        # --security / arch-audit), stored under sysinfo.packages.security_updates
        # — a higher-priority signal than the raw upgradable total.
        _pkg = si.get('packages')
        _pkg = _pkg if isinstance(_pkg, dict) else {}
        sec_updates = _pkg.get('security_updates')
        if isinstance(sec_updates, int) and sec_updates >= 0:
            patch_lines.append(f"vendor security updates pending: {sec_updates}")
        if dev.get('patch_status'):
            patch_lines.append(f"patch status: {dev['patch_status']}")
        if _pkg.get('manager'):
            patch_lines.append(f"package manager: {_pkg['manager']}")
        if reboot_required:
            patch_lines.append("reboot required: yes"
                               + (f" ({si.get('reboot_reason')})"
                                  if si.get('reboot_reason') else ""))
            reboot_hosts.append(name)
        if patch_lines:
            docs.append(make_doc(
                f"live/{dev_id}#patches", 'live_state', 'device_patches',
                f"{name} patch & reboot status:\n" + '\n'.join(patch_lines),
                title=f"{name} — patches", device=dev_id, ts=ts))

        # Configuration drift — files that differ from their captured baseline.
        drift = dev.get('drift_state') or {}
        drifted = [f for f, st in drift.items()
                   if isinstance(st, dict) and st.get('status') == 'drifted'
                   and not st.get('ignored')]
        if drifted:
            drift_hosts.append((name, len(drifted)))
            docs.append(make_doc(
                f"live/{dev_id}#drift", 'live_state', 'device_drift',
                f"{name} config drift — config files that have drifted / "
                f"changed from their captured baseline:\n"
                + '\n'.join(f"- {f}" for f in drifted[:50]),
                title=f"{name} — config drift", device=dev_id, ts=ts))

        # Inline device facets that live on the record itself.
        inline = {
            'services': dev.get('services_watched_state') or dev.get('services'),
            'journal':  (dev.get('journal') or [])[-30:] or None,
        }
        # Caller-supplied external facets win / extend.
        ext = facets.get(dev_id) or {}
        for fname, fdata in list(inline.items()) + list(ext.items()):
            if not fdata:
                continue
            body = _format_facet(fdata)
            if not body.strip():
                continue
            docs.append(make_doc(
                f"live/{dev_id}#{fname}", 'live_state', f'device_{fname}',
                f"{name} {fname}:\n{body}",
                title=f"{name} — {fname}", device=dev_id, ts=ts))

    # Fleet-wide CVE rollup. Cross-fleet aggregate questions ("what are the
    # worst CVEs in the fleet?") have no single device to focus on, so the
    # per-device #cves chunks don't surface well and the model ends up
    # punting to the get_cves tool. A single rollup chunk of the worst
    # (critical + high) CVEs across every host gives the model authoritative
    # data to answer from directly. Built from the caller-supplied `cves`
    # facets so the shape knowledge stays in one place.
    worst = []
    for dev_id, f in (facets or {}).items():
        for c in (f.get('cves') or []):
            if not isinstance(c, dict):
                continue
            sev = str(c.get('severity', '')).lower()
            if sev in ('critical', 'high'):
                worst.append((sev, dev_id,
                              c.get('id') or c.get('cve_id') or '?',
                              c.get('package') or c.get('pkg') or ''))
    if worst:
        rank = {'critical': 0, 'high': 1}
        worst.sort(key=lambda x: (rank.get(x[0], 9), x[1]))
        n_crit = sum(1 for w in worst if w[0] == 'critical')
        lines = [f"- {dev}: {cid} ({sev}{' in ' + pkg if pkg else ''})"
                 for sev, dev, cid, pkg in worst[:80]]
        text = ("Fleet CVE summary — the worst (critical and high severity) "
                f"vulnerabilities / CVEs across the whole fleet "
                f"({n_crit} critical, {len(worst) - n_crit} high):\n"
                + '\n'.join(lines))
        docs.append(make_doc(
            "live/_fleet#cves", 'live_state', 'fleet_cves', text,
            title="Fleet CVE summary (worst CVEs)", device=None, ts=now))

    # Fleet patch & reboot rollup — "which hosts have pending updates / need a
    # reboot?" Both are common cross-fleet questions with no single device.
    if patch_hosts or reboot_hosts:
        parts = []
        if patch_hosts:
            patch_hosts.sort(key=lambda x: x[1], reverse=True)
            parts.append("Hosts with pending package updates (most first):\n"
                         + '\n'.join(f"- {n}: {c} pending update"
                                     f"{'s' if c != 1 else ''}"
                                     for n, c in patch_hosts))
        if reboot_hosts:
            parts.append("Hosts that require a reboot:\n"
                         + '\n'.join(f"- {n}" for n in sorted(reboot_hosts)))
        docs.append(make_doc(
            "live/_fleet#patches", 'live_state', 'fleet_patches',
            "Fleet patch & reboot status — pending package updates and "
            "pending reboots across the fleet:\n" + '\n\n'.join(parts),
            title="Fleet patch & reboot status", device=None, ts=now))

    # Fleet config-drift rollup — "which hosts have drifted from baseline?"
    if drift_hosts:
        drift_hosts.sort(key=lambda x: x[1], reverse=True)
        docs.append(make_doc(
            "live/_fleet#drift", 'live_state', 'fleet_drift',
            "Fleet configuration drift — hosts with config files changed "
            "from their captured baseline:\n"
            + '\n'.join(f"- {n}: {c} drifted file{'s' if c != 1 else ''}"
                        for n, c in drift_hosts),
            title="Fleet config drift", device=None, ts=now))
    return docs


def build_history_corpus(commands=None, alerts=None, events=None,
                         limits=None, redactor=None, now=0):
    """Recent operational history: commands, alerts, fleet events.

    Bounded hard by `limits` and intentionally lossy — this is the most
    sensitive and most voluminous source. `redactor`, if given, is a
    callable applied to each rendered chunk before it is stored, so the
    operator's AI privacy settings are honoured at index time (not just
    at prompt-assembly time).
    """
    limits = limits or {}
    max_cmds = int(limits.get('commands_per_device', 20))
    max_age = int(limits.get('max_age_days', 14)) * 86400
    cutoff = (now - max_age) if (now and max_age) else 0
    docs = []

    def _emit(doc_id, dtype, title, text, device=None, ts=0):
        if redactor:
            text = redactor(text)
        if text and text.strip():
            docs.append(make_doc(doc_id, 'history', dtype, text,
                                  title=title, device=device, ts=ts))

    # Commands: dict device_id -> list[entry] OR flat list with device field.
    if isinstance(commands, dict):
        for dev_id, entries in commands.items():
            entries = [e for e in (entries or []) if isinstance(e, dict)]
            entries = [e for e in entries
                       if (e.get('ts') or e.get('time') or 0) >= cutoff]
            entries = sorted(entries,
                             key=lambda e: e.get('ts') or e.get('time') or 0,
                             reverse=True)[:max_cmds]
            if not entries:
                continue
            body = _format_facet([
                {'cmd': e.get('cmd') or e.get('command') or '',
                 'rc': e.get('rc', e.get('exit_code', '')),
                 'when': e.get('ts') or e.get('time') or ''}
                for e in entries])
            _emit(f"history/{dev_id}#commands", 'commands',
                  f"Recent commands: {dev_id}", body, device=dev_id,
                  ts=entries[0].get('ts') or entries[0].get('time') or 0)

    # Alerts + fleet events: flat lists.
    for label, rows, dtype in (('alerts', alerts, 'alert'),
                               ('events', events, 'fleet_event')):
        rows = [r for r in (rows or []) if isinstance(r, dict)]
        rows = [r for r in rows if (r.get('ts') or r.get('time') or 0) >= cutoff]
        rows = sorted(rows, key=lambda r: r.get('ts') or r.get('time') or 0,
                      reverse=True)[:200]
        if not rows:
            continue
        body = _format_facet([
            {k: r.get(k) for k in ('type', 'severity', 'device', 'message',
                                   'event', 'state') if r.get(k)}
            for r in rows])
        _emit(f"history/_{label}", dtype, f"Recent {label}", body,
              ts=rows[0].get('ts') or rows[0].get('time') or 0)
    return docs


def build_drift_corpus(devices, now=0):
    """v4.1.0: per-device config-drift detail + a fleet rollup.

    `devices` is a list of device records; each may carry a `drift_state` map
    (file_path -> {status, ignored, ...}) as stored on the device. Only files
    currently `drifted` (and not ignored) are emitted — answers "what config has
    drifted on host X?" and "which hosts have drift?".
    """
    docs = []
    drifted_hosts = []
    for d in (devices or []):
        if not isinstance(d, dict):
            continue
        dev_id = d.get('id') or d.get('name')
        if not dev_id:
            continue
        name = d.get('name') or dev_id
        drift = d.get('drift_state') or {}
        files = sorted(f for f, st in drift.items()
                       if isinstance(st, dict) and st.get('status') == 'drifted'
                       and not st.get('ignored'))
        if not files:
            continue
        drifted_hosts.append(name)
        body = (f"{name} configuration drift — {len(files)} file(s) diverged "
                f"from baseline:\n" + '\n'.join(f"- {f}" for f in files[:80]))
        docs.append(make_doc(f"drift/{dev_id}", 'drift', 'device_drift', body,
                             title=f"Config drift: {name}", device=dev_id, ts=now))
    if drifted_hosts:
        docs.append(make_doc(
            'drift/_fleet', 'drift', 'fleet_drift',
            f"Fleet config drift — {len(drifted_hosts)} host(s) have drifted "
            "config files: " + ', '.join(sorted(drifted_hosts)[:200]),
            title='Fleet config drift', ts=now))
    return docs


def build_firewall_corpus(devices, now=0):
    """v4.10.0: per-device host-firewall posture + fail2ban jails, plus a fleet
    'no active firewall' rollup. Answers "what's the firewall on host X?",
    "which hosts have no firewall?", "is fail2ban running on X?". Device-scoped.

    Reads each device's `sysinfo.firewall` (backends with active/rules/policy)
    and `sysinfo.fail2ban` (jails + banned counts).
    """
    docs = []
    no_fw = []
    for d in (devices or []):
        if not isinstance(d, dict):
            continue
        dev_id = d.get('id') or d.get('name')
        if not dev_id:
            continue
        name = d.get('name') or dev_id
        si = d.get('sysinfo') or {}
        fw = si.get('firewall') or {}
        f2b = si.get('fail2ban') or {}
        bes = [b for b in (fw.get('backends') or [])
               if isinstance(b, dict) and b.get('present')]
        if not bes and not f2b.get('available'):
            continue
        active = fw.get('active')
        lines = []
        for b in bes:
            st = ('active' if b.get('active') else
                  ('inactive' if b.get('active') is False else 'unknown'))
            extra = []
            if b.get('policy'):
                extra.append(f"policy {b['policy']}")
            if b.get('default'):
                extra.append(str(b['default']))
            lines.append(f"- {b.get('name')}: {st}, {b.get('rules', 0)} rule(s)"
                         + (f" ({'; '.join(extra)})" if extra else ''))
        if active is False:
            no_fw.append(name)
        head = ('active' if active else
                ('INACTIVE (no active host firewall)' if active is False
                 else 'state unknown'))
        body = f"{name} host firewall — {head}:\n" + '\n'.join(lines)
        if f2b.get('available'):
            jails = [j for j in (f2b.get('jails') or []) if isinstance(j, dict)]
            tot = sum(int(j.get('banned_count', 0) or 0) for j in jails)
            jn = ', '.join(j.get('name', '') for j in jails)[:300]
            body += (f"\nfail2ban: {len(jails)} jail(s), {tot} banned IP(s)"
                     + (f" — jails: {jn}" if jn else ''))
        docs.append(make_doc(f"firewall/{dev_id}", 'firewall', 'device_firewall',
                             body, title=f"Firewall: {name}", device=dev_id, ts=now))
    if no_fw:
        docs.append(make_doc(
            'firewall/_fleet', 'firewall', 'fleet_firewall',
            f"Hosts with NO active host firewall ({len(no_fw)}): "
            + ', '.join(sorted(no_fw)[:200]),
            title='Fleet — hosts without an active firewall', ts=now))
    return docs


def build_integrations_corpus(latest, now=0):
    """v4.10.0: homelab software-integration health (Pi-hole / TrueNAS / UniFi /
    *arr / …) for the RAG. `latest` is integrations_state['latest'] = {id:
    result}, each result {label, type, status, detail}. Fleet-scoped (these are
    services, not devices). Answers "which integrations are down?".
    """
    docs = []
    rows, down = [], []
    for key, r in (latest.items() if isinstance(latest, dict) else []):
        if not isinstance(r, dict):
            continue
        label = r.get('label') or key
        rtype = r.get('type', '')
        status = r.get('status', '')
        detail = (r.get('detail') or '')[:200]
        rows.append(f"- {label} ({rtype}): {status}"
                    + (f" — {detail}" if detail else ''))
        if status in ('warning', 'critical'):
            down.append(f"{label} ({status})")
    if not rows:
        return docs
    docs.append(make_doc(
        'integrations/_all', 'integrations', 'integrations_health',
        f"Homelab integrations — {len(rows)} monitored:\n"
        + '\n'.join(sorted(rows)[:120]),
        title='Homelab integrations health', ts=now))
    if down:
        docs.append(make_doc(
            'integrations/_down', 'integrations', 'integrations_down',
            f"Integrations needing attention ({len(down)}): "
            + ', '.join(sorted(down)[:120]),
            title='Integrations down / degraded', ts=now))
    return docs


def build_backups_corpus(state, monitors, resolve_device=None, now=0):
    """v4.10.0: per-device backup freshness + a fleet 'stale backups' rollup.
    `state` = backup_state.json keyed `"{dev_id}:{path}" -> {ok, age_h}`;
    `monitors` = cfg['backup_monitors'] (for labels). Device-scoped via the
    canonical-id resolver so it associates with the host's other chunks.
    """
    resolve = resolve_device or (lambda x: x)
    mon_by_path = {m.get('path'): m for m in (monitors or [])
                   if isinstance(m, dict)}
    by_dev = {}
    for key, st in (state.items() if isinstance(state, dict) else []):
        if not isinstance(st, dict) or ':' not in key:
            continue
        raw_dev, path = key.split(':', 1)
        dev = resolve(raw_dev) or raw_dev
        by_dev.setdefault(dev, []).append((path, st))
    docs = []
    stale_hosts = []
    for dev, items in by_dev.items():
        lines, any_stale = [], False
        for path, st in sorted(items):
            mon = mon_by_path.get(path) or {}
            label = mon.get('label') or path
            ok = bool(st.get('ok'))
            age = st.get('age_h')
            if not ok:
                any_stale = True
            lines.append(f"- {label}: {'OK' if ok else 'STALE'}"
                         + (f", {age}h old" if age is not None else ''))
        if any_stale:
            stale_hosts.append(str(dev))
        body = (f"{dev} backups — {len(items)} watched path(s):\n"
                + '\n'.join(lines[:80]))
        docs.append(make_doc(f"backups/{dev}", 'backups', 'device_backups', body,
                             title=f"Backups: {dev}", device=dev, ts=now))
    if stale_hosts:
        docs.append(make_doc(
            'backups/_fleet', 'backups', 'fleet_backups',
            f"Hosts with STALE backups ({len(stale_hosts)}): "
            + ', '.join(sorted(stale_hosts)[:200]),
            title='Fleet — stale backups', ts=now))
    return docs


def build_dns_email_corpus(dmarc=None, reputation=None, resolver=None, now=0):
    """v4.10.0: email-deliverability + DNS-hygiene posture for the AI advisors.

    Indexes DMARC/SPF/DKIM grades per domain (dmarc_results.json), DNSBL / IP
    reputation (ip_reputation_results.json) and DNS resolver health
    (resolver_health_results.json) — the exact data the `email_deliverability`
    and `dns_hygiene` insight cards ask the model about, which previously had no
    corpus to ground their answers. All admin-configured posture, no PII.
    Defensive about store shape (dict-of-id or list).
    """
    docs = []
    _seq = lambda x: list(x.values()) if isinstance(x, dict) else (x if isinstance(x, list) else [])
    # ── DMARC / SPF / DKIM per domain ──
    dm = _seq(dmarc)
    for r in dm:
        if not isinstance(r, dict):
            continue
        domain = r.get('domain') or '?'
        status = r.get('status') or 'unknown'
        pol = (r.get('dmarc') or {}).get('policy') or r.get('policy') or '—'
        spf = (r.get('spf') or {})
        dkim = (r.get('dkim') or {})
        reasons = r.get('reasons') or []
        body = (f"Email authentication for {domain}: overall status {status}.\n"
                f"- DMARC policy: p={pol}\n"
                f"- SPF: {spf.get('record') or spf.get('status') or spf.get('found') or 'n/a'}\n"
                f"- DKIM: {dkim.get('selector') or dkim.get('status') or dkim.get('found') or 'n/a'}\n"
                + (("Issues: " + '; '.join(str(x) for x in reasons[:8])) if reasons else ''))
        docs.append(make_doc(f"email/{domain}", 'dns_email', 'email_auth', body,
                             title=f"Email auth: {domain}", ts=now))
    # ── IP reputation (DNSBL) ──
    rp = _seq(reputation)
    listed = []
    for r in rp:
        if not isinstance(r, dict):
            continue
        ip = r.get('ip') or '?'
        label = r.get('label') or ''
        lc = r.get('listed_count') or 0
        on = ', '.join(z.get('name', '?') for z in (r.get('listed_on') or []) if isinstance(z, dict))
        state = (f"LISTED on {lc} blocklist(s) ({on})" if lc else 'clean')
        if r.get('errors'):
            state += f"; {len(r['errors'])} blocklist(s) unreachable"
        if lc:
            listed.append(f"{ip}{(' ' + label) if label else ''}: {on}")
        docs.append(make_doc(f"reputation/{ip}", 'dns_email', 'ip_reputation',
                             f"IP reputation for {ip} {label}: {state}.",
                             title=f"IP reputation: {ip}", ts=now))
    if listed:
        docs.append(make_doc('reputation/_fleet', 'dns_email', 'fleet_reputation',
                             "Blacklisted IPs: " + ' | '.join(listed[:100]),
                             title='Fleet — blacklisted IPs', ts=now))
    # ── DNS resolver health ──
    rs = _seq(resolver)
    rlines = []
    for r in rs:
        if not isinstance(r, dict):
            continue
        srv = r.get('resolver') or r.get('server') or r.get('target') or '?'
        healthy = r.get('healthy')
        lat = r.get('latency_ms')
        st = (('healthy' if healthy else 'UNHEALTHY') if healthy is not None
              else (r.get('status') or '?'))
        rlines.append(f"- {srv}: {st}" + (f", {lat}ms" if isinstance(lat, (int, float)) else ''))
    if rlines:
        docs.append(make_doc('dns/resolvers', 'dns_email', 'resolver_health',
                             "DNS resolver health:\n" + '\n'.join(rlines[:60]),
                             title='DNS resolver health', ts=now))
    return docs


def build_posture_corpus(config=None, devices=None, backup=None, now=0,
                         breakglass_creds=0):
    """v5.0.0: fleet SECURITY-CONTROL posture for the AI advisors — grounds
    answers to "is backup encryption on?", "what's our mutual-TLS coverage?",
    "how many agents are in read-only audit mode?", "is maintenance mode on?".

    These are control-plane settings that live across config + per-device flags
    and previously had no corpus, so the model had nothing to cite. Pure summary
    of admin-configured posture — no secrets (passphrases/keys never touched).
    Defensive about store shape (devices: dict-of-id or list; config/backup: dict).
    """
    cfg = config if isinstance(config, dict) else {}
    devs = (list(devices.values()) if isinstance(devices, dict)
            else (devices if isinstance(devices, list) else []))
    bk = backup if isinstance(backup, dict) else {}
    docs = []

    # ── Mutual-TLS agent authentication ──
    mtls_on = bool(cfg.get('require_agent_mtls'))
    pinned = [d.get('name') or d.get('id') for d in devs
              if isinstance(d, dict) and (d.get('mtls_fingerprint') or '').strip()]
    total = sum(1 for d in devs if isinstance(d, dict))
    mtls_body = (
        f"Mutual-TLS agent authentication is "
        f"{'ENFORCED fleet-wide' if mtls_on else 'NOT enforced (off)'}.\n"
        f"- Devices with a pinned client-certificate fingerprint: "
        f"{len(pinned)} of {total}.")
    if pinned:
        mtls_body += "\n- Pinned hosts: " + ', '.join(sorted(map(str, pinned))[:200])
    docs.append(make_doc('posture/mtls', 'posture', 'posture_mtls', mtls_body,
                         title='Security posture — mutual TLS', ts=now))

    # ── At-rest backup encryption ──
    enc_armed = bool(bk.get('encryption_armed'))
    enc_avail = bk.get('encryption_available')
    enc_body = (
        "Disaster-recovery backup encryption (AES-256-GCM) is "
        f"{'ARMED — backups are encrypted at rest' if enc_armed else 'NOT armed (backups stored in clear)'}.\n"
        f"- Crypto library available on the server: "
        f"{'yes' if enc_avail else ('no' if enc_avail is False else 'unknown')}.")
    docs.append(make_doc('posture/backup_encryption', 'posture', 'posture_backup_enc',
                         enc_body, title='Security posture — backup encryption', ts=now))

    # ── Read-only audit mode (agents) ──
    audit_hosts = [d.get('name') or d.get('id') for d in devs
                   if isinstance(d, dict) and (d.get('sysinfo') or {}).get('audit_mode')]
    if audit_hosts:
        docs.append(make_doc(
            'posture/audit_mode', 'posture', 'posture_audit_mode',
            f"Agents in read-only AUDIT mode (refuse all commands): "
            f"{len(audit_hosts)} — " + ', '.join(sorted(map(str, audit_hosts))[:200]),
            title='Security posture — agents in audit mode', ts=now))

    # ── Control-plane state (break-glass + maintenance) ──
    # Break-glass is a per-credential flag (CMDB vault), not a global toggle —
    # the caller counts the credentials marked break-glass and passes it here.
    bg_n = int(breakglass_creds or 0)
    mm = cfg.get('maintenance_mode') or {}
    mm_on = bool(mm.get('enabled')) if isinstance(mm, dict) else bool(mm)
    docs.append(make_doc(
        'posture/control_plane', 'posture', 'posture_control_plane',
        ("Control-plane safeguards:\n"
         f"- Two-person break-glass approval for credential reveals: "
         f"{f'enabled on {bg_n} credential(s)' if bg_n else 'not enabled on any credential'}.\n"
         f"- Maintenance mode (pauses command dispatch): "
         f"{'ON' if mm_on else 'off'}."),
        title='Security posture — control plane', ts=now))
    return docs


def build_compliance_corpus(report, now=0):
    """v4.1.0: a compliance report → one chunk per framework (score + the
    FAILING controls with evidence/remediation) plus an overall summary.

    `report` is the dict from compliance.build_report: {frameworks: {fw:
    {label, pass, fail, na, score, controls: [{id,title,status,evidence,
    remediation}]}}, summary: {pass,fail,na,total}}.
    """
    if not isinstance(report, dict):
        return []
    docs = []
    for fw, fwdata in (report.get('frameworks') or {}).items():
        if not isinstance(fwdata, dict):
            continue
        label = fwdata.get('label', fw)
        score = fwdata.get('score')
        head = (f"{label} compliance — score "
                f"{score if score is not None else 'n/a'}"
                f"{'%' if score is not None else ''} "
                f"({fwdata.get('pass', 0)} pass / {fwdata.get('fail', 0)} fail / "
                f"{fwdata.get('na', 0)} n/a).")
        fails = [c for c in (fwdata.get('controls') or [])
                 if isinstance(c, dict) and c.get('status') == 'fail']
        if fails:
            lines = []
            for c in fails[:60]:
                line = f"- [{c.get('id')}] {c.get('title')}: {c.get('evidence', '')}"
                if c.get('remediation'):
                    line += f" → fix: {c.get('remediation')}"
                lines.append(line)
            body = head + "\nFailing controls:\n" + '\n'.join(lines)
        else:
            body = head + "\nNo failing controls."
        docs.append(make_doc(f"compliance/{fw}", 'compliance',
                             'framework_compliance', body,
                             title=f"{label} compliance", ts=now))
    summary = report.get('summary') or {}
    if summary:
        docs.append(make_doc(
            'compliance/_summary', 'compliance', 'compliance_summary',
            f"Overall compliance — {summary.get('pass', 0)} pass / "
            f"{summary.get('fail', 0)} fail / {summary.get('na', 0)} n/a "
            f"across {summary.get('total', 0)} controls.",
            title='Compliance summary', ts=now))
    return docs


def build_fleet_rollups_corpus(rollups, now=0):
    """v4.1.0: one chunk per fleet-wide 'which hosts match X' rollup, mirroring
    the Fleet Query dimensions so the AI can answer those questions in plain
    English ("which hosts are on UPS battery / have high CPU / SMART-failed?").

    `rollups` is a list of {label, hosts:[str]} computed by the caller (which owns
    the cross-store reads). Empty dimensions are skipped.
    """
    docs = []
    for r in (rollups or []):
        if not isinstance(r, dict):
            continue
        label = r.get('label')
        hosts = r.get('hosts') or []
        if not label or not hosts:
            continue
        body = (f"Hosts with {label} ({len(hosts)}): " + ', '.join(str(h) for h in hosts[:200]))
        docs.append(make_doc(f"fleet/{_slug(label)}", 'live_state', 'fleet_rollup',
                             body, title=f"Fleet: {label}", ts=now))
    return docs


def build_metrics_corpus(summaries, now=0):
    """v4.1.0: per-device resource-usage TREND summaries.

    `summaries` is a list of {device, name, text} dicts already computed by the
    caller, which owns the time-series read (the SQLite/Postgres `metric_range`
    long-retention table, or the JSON metrics window). Numeric series are
    summarised to avg/peak text upstream — deliberately NOT raw samples, which
    would churn the embedding cache and pollute lexical search — so the index can
    answer "which hosts trended high CPU last week?".
    """
    docs = []
    for s in (summaries or []):
        if not isinstance(s, dict):
            continue
        dev_id = s.get('device')
        text = (s.get('text') or '').strip()
        if not dev_id or not text:
            continue
        docs.append(make_doc(f"metrics/{dev_id}", 'metrics', 'device_metrics',
                             text, title=f"Resource trends: {s.get('name') or dev_id}",
                             device=dev_id, ts=now))
    return docs


def build_vpn_corpus(store, now=0):
    """v5.2.0: WG Access (WireGuard road-warrior VPN) posture for the RAG.

    `store` is the VPN_FILE dict {'tunnels': [...]}. Fleet-scoped (the hub IS the
    RP host, like integrations — not a device). Answers "who has road-warrior VPN
    access?", "is anyone connected right now?", "what can VPN clients reach?",
    "which tunnels/clients expire soon?". NO secrets — public addresses, reach
    scope and connection state only (private keys never reach the server, and the
    hub/peer public keys are deliberately omitted as noise).
    """
    docs = []
    tunnels = (store or {}).get('tunnels', []) if isinstance(store, dict) else []
    if not isinstance(tunnels, list) or not tunnels:
        return docs
    rollup, expiring = [], []
    total_clients = total_connected = 0
    for t in tunnels:
        if not isinstance(t, dict):
            continue
        name = t.get('name') or t.get('id') or '?'
        clients = [c for c in (t.get('clients') or []) if isinstance(c, dict)]
        connected = sum(1 for c in clients
                        if c.get('last_handshake')
                        and (now - int(c.get('last_handshake') or 0)) <= 180)
        total_clients += len(clients)
        total_connected += connected
        if t.get('allow_internet'):
            reach = 'full tunnel (internet egress)'
        else:
            rst = t.get('reach_scope_type') or 'none'
            reach = ('dashboard only' if rst in ('none', '')
                     else (f"entire fleet" if rst == 'all'
                           else f"{rst} {t.get('reach_scope_value', '')}".strip()))
        state = 'enabled' if t.get('enabled', True) else 'DISABLED'
        rollup.append(
            f"- {name}: {state}, reach = {reach}; "
            f"{len(clients)} client(s), {connected} connected now")
        lines = []
        for c in sorted(clients, key=lambda x: x.get('name', '')):
            age = (now - int(c.get('last_handshake') or 0)) if c.get('last_handshake') else None
            st = ('connected' if age is not None and age <= 180
                  else ('idle' if age is not None and age <= 3600 else 'offline'))
            ep = c.get('endpoint') or ''
            lines.append(
                f"  - {c.get('name', '?')} ({c.get('address', '?')}): {st}"
                + (f", from {ep}" if ep else '')
                + ('' if c.get('enabled', True) else ', disabled'))
            if c.get('expires_at'):
                left = int(c['expires_at']) - now
                if 0 < left <= 7 * 86400:
                    expiring.append(f"client {c.get('name', '?')} on {name}")
        if t.get('expires_at'):
            left = int(t['expires_at']) - now
            if 0 < left <= 7 * 86400:
                expiring.append(f"tunnel {name}")
        body = (f"VPN tunnel '{name}' — {state}, reach: {reach}, "
                f"DNS: {t.get('dns') or 'default'}, port {t.get('listen_port', 0)}.\n"
                + (("Clients:\n" + '\n'.join(lines[:120])) if lines
                   else "No clients."))
        docs.append(make_doc(
            f"vpn/{t.get('id') or name}", 'vpn', 'vpn_tunnel', body,
            title=f"WG Access tunnel: {name}", ts=now))
    docs.append(make_doc(
        'vpn/_fleet', 'vpn', 'vpn_rollup',
        f"WG Access (WireGuard road-warrior VPN) — {len(rollup)} tunnel(s), "
        f"{total_clients} client(s), {total_connected} connected now:\n"
        + '\n'.join(rollup[:120]),
        title='WG Access overview', ts=now))
    if expiring:
        docs.append(make_doc(
            'vpn/_expiring', 'vpn', 'vpn_expiring',
            f"WG Access access expiring within 7 days ({len(expiring)}): "
            + ', '.join(sorted(set(expiring))[:120]),
            title='WG Access expiring soon', ts=now))
    return docs


def build_tickets_corpus(store, resolve_device=None, now=0):
    """v5.3.0: built-in helpdesk tickets for the RAG. `store` is the TICKETS_FILE
    dict {'tickets': [...]}. Grounds answers like "what tickets are open for host
    X?", "what's breaching SLA?", "who is working what?". OPEN tickets get a doc
    each plus a fleet rollup; closed tickets are summarized only (count), not
    individually indexed. Caller should only invoke this when the ticket system is
    enabled."""
    docs = []
    tickets = (store or {}).get('tickets', []) if isinstance(store, dict) else []
    if not isinstance(tickets, list) or not tickets:
        return docs
    OPEN = ('ongoing', 'pending_customer', 'pending_internal')
    PRIO = {1: 'P1 Major', 2: 'P2 Critical', 3: 'P3 Warning', 4: 'P4 Low'}
    open_t = [t for t in tickets if isinstance(t, dict) and t.get('status') in OPEN]
    rollup, by_prio = [], {}
    for t in sorted(open_t, key=lambda x: int(x.get('priority') or 4)):
        num = t.get('number')
        rp = f"#RP{int(num or 0):06d}"
        pr = int(t.get('priority') or 4)
        by_prio[pr] = by_prio.get(pr, 0) + 1
        dev = t.get('device_name') or ''
        who = t.get('assignee') or 'unassigned'
        grp = t.get('group') or ''
        age_h = int((now - int(t.get('created_at') or now)) / 3600)
        msgs = [m for m in (t.get('messages') or []) if isinstance(m, dict)]
        snippet = (_scrub_script_body(str(msgs[-1].get('body') or ''))[:200]).replace('\n', ' ') if msgs else ''  # SEC v6.4.0
        body = (f"Ticket {rp}: {t.get('subject', '')}\n"
                f"Type {t.get('type', 'incident')}, {PRIO.get(pr, 'P4')}, "
                f"status {t.get('status', '')}.\n"
                f"Assignee: {who}" + (f", group {grp}" if grp else '') + ".\n"
                + (f"Affected host: {dev}.\n" if dev else '')
                + f"Open for ~{age_h}h."
                + (f"\nLast message: {snippet}" if snippet else ''))
        rollup.append(f"- {rp} [{PRIO.get(pr, 'P4')}] {t.get('subject', '')[:80]} "
                      f"— {t.get('status', '')}, {who}" + (f", {dev}" if dev else ''))
        docs.append(make_doc(
            f"ticket/{t.get('id') or num}", 'tickets', 'ticket', body,
            title=f"Ticket {rp}: {t.get('subject', '')[:80]}",
            ts=int(t.get('updated_at') or now)))
    closed = sum(1 for t in tickets
                 if isinstance(t, dict) and t.get('status') in ('resolved', 'closed'))
    prio_summary = ', '.join(f"{by_prio[p]}×{PRIO.get(p, 'P4')}"
                             for p in sorted(by_prio)) or 'none'
    docs.append(make_doc(
        'tickets/_fleet', 'tickets', 'ticket_rollup',
        f"Helpdesk: {len(open_t)} open ticket(s) ({prio_summary}), {closed} closed.\n"
        + '\n'.join(rollup[:200]),
        title='Helpdesk overview', ts=now))
    return docs


def build_kb_corpus(store, now=0):
    """v5.6.0: operator-authored knowledge-base articles for the RAG. `store` is
    the KB_FILE dict {'articles': [...]}. Each article (SOP / how-to / runbook)
    becomes one doc so the model can answer "how do we …?" with your own docs,
    plus a fleet rollup of titles. Caller should only invoke this when the KB is
    enabled."""
    docs = []
    articles = (store or {}).get('articles', []) if isinstance(store, dict) else []
    if not isinstance(articles, list) or not articles:
        return docs
    index = []
    for a in articles:
        if not isinstance(a, dict):
            continue
        aid = a.get('id') or ''
        title = str(a.get('title') or 'Untitled')
        cat = str(a.get('category') or '')
        tags = a.get('tags') or []
        tagline = (', '.join(str(t) for t in tags)) if isinstance(tags, list) else ''
        body = _scrub_script_body(str(a.get('body') or ''))[:8000]  # SEC v6.4.0: scrub inline secrets before embedding
        head = f"Knowledge-base article: {title}\n"
        if cat:
            head += f"Category: {cat}\n"
        if tagline:
            head += f"Tags: {tagline}\n"
        docs.append(make_doc(
            f"kb/{aid}", 'kb', 'kb_article', head + "\n" + body,
            title=f"KB: {title[:80]}", ts=int(a.get('updated_at') or now)))
        index.append(f"- {title[:80]}" + (f" [{cat}]" if cat else ''))
    docs.append(make_doc(
        'kb/_index', 'kb', 'kb_index',
        f"Knowledge base: {len(index)} article(s).\n" + '\n'.join(index[:300]),
        title='Knowledge base index', ts=now))
    return docs


# v6.2.2: line-level secret scrubber for script bodies before they enter the
# RAG corpus. Unlike CMDB/KB free-form fields (where the SECRET is a whole
# named field we can drop), a script body is code with secrets INLINE, so a
# key-name filter is not enough — we redact secret-named ASSIGNMENTS and
# always-on token SHAPES per line. Best-effort (a determined operator can still
# hardcode an unusual secret), so the safe framing is: names + descriptions are
# indexed verbatim, bodies are scrubbed. Operators who need a hard guarantee run
# a local embedding model (no egress) — same posture as ai_provider.redact.
_SCRIPT_SECRET_ASSIGN_RE = re.compile(
    # KEY=value / KEY: value where KEY contains a secret word. The prefix is
    # OPTIONAL (so a bare PASSWORD= matches, not just DB_PASSWORD=). Deliberately
    # NOT matching the short ambiguous words auth/pat/pwd — they false-hit real
    # env vars (PATH, PWD, AUTHOR); the precise words below cover the real cases
    # (an AUTH_TOKEN is caught by 'token').
    r'(?im)^(\s*(?:export\s+)?[A-Za-z0-9_]*'
    r'(?:password|passwd|secret|token|api[_-]?key|apikey|passphrase|'
    r'private[_-]?key|access[_-]?key|client[_-]?secret|bearer|credential)'
    r'[A-Za-z0-9_]*)\s*([:=])\s*\S.*$')
_SCRIPT_BEARER_RE = re.compile(r'(?i)(bearer\s+)[A-Za-z0-9._\-/+=]{16,}')
_SCRIPT_AWS_RE = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_SCRIPT_LONGHEX_RE = re.compile(r'\b[0-9a-fA-F]{32,}\b')
_SCRIPT_B64_RE = re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b')


def _scrub_script_body(body):
    """Redact inline secrets from a script body before RAG embedding."""
    if not isinstance(body, str) or not body:
        return ''
    out = _SCRIPT_SECRET_ASSIGN_RE.sub(r'\1\2 <REDACTED-SECRET>', body)
    out = _SCRIPT_BEARER_RE.sub(r'\1<REDACTED>', out)
    out = _SCRIPT_AWS_RE.sub('<REDACTED-AWS>', out)
    out = _SCRIPT_LONGHEX_RE.sub('<REDACTED-HEX>', out)
    out = _SCRIPT_B64_RE.sub('<REDACTED-TOKEN>', out)
    return out


def build_scripts_corpus(store, now=0):
    """v6.2.2: the operator's saved custom scripts for the RAG, so the model can
    answer "what automation do we have?", "which script does X?", "is there a
    script for Y?". `store` is CUSTOM_SCRIPTS_FILE {'scripts': [...]} with
    id/name/description/body. Names + descriptions index verbatim; BODIES pass
    through _scrub_script_body first (inline secrets redacted) — script bodies
    are the one RAG input where a credential can hide in free text, so this is
    the deliberate difference from the other builders."""
    docs = []
    scripts = (store or {}).get('scripts', []) if isinstance(store, dict) else []
    if not isinstance(scripts, list) or not scripts:
        return docs
    index = []
    for s in scripts:
        if not isinstance(s, dict):
            continue
        sid = s.get('id') or ''
        name = str(s.get('name') or 'script')
        desc = str(s.get('description') or '')
        body = _scrub_script_body(str(s.get('body') or ''))[:6000]
        lines = [f"Custom script: {name}"]
        if desc:
            lines.append(f"Description: {desc}")
        if body:
            lines.append("Body (secrets redacted):\n" + body)
        docs.append(make_doc(
            f"scripts/{sid}", 'scripts', 'custom_script', '\n'.join(lines),
            title=f"Script: {name[:80]}", ts=int(s.get('updated_at') or now)))
        index.append(f"- {name[:70]}" + (f": {desc[:80]}" if desc else ''))
    docs.append(make_doc(
        'scripts/_index', 'scripts', 'scripts_index',
        f"Custom scripts: {len(index)} saved.\n" + '\n'.join(index[:300]),
        title='Custom scripts index', ts=now))
    return docs


def build_contacts_corpus(store, now=0):
    """v6.2.2: the internal contact directory (team phonebook) for the RAG, so
    the model can answer "who do I call about host X / vendor Y / this site?".
    `store` is CONTACTS_FILE {'contacts': [...]} with fixed fields
    (name/role/company/email/phone/notes/site). One doc per contact plus a
    rollup index. Fields are structured (not free-form facets), so no cloud
    secret can hide in a key name — but `notes` is operator free text, so it is
    passed through the same _is_secret_key guard the CMDB/KB builders use."""
    docs = []
    contacts = (store or {}).get('contacts', []) if isinstance(store, dict) else []
    if not isinstance(contacts, list) or not contacts:
        return docs
    index = []
    for c in contacts:
        if not isinstance(c, dict):
            continue
        cid = c.get('id') or ''
        name = str(c.get('name') or 'Unnamed')
        role = str(c.get('role') or '')
        company = str(c.get('company') or '')
        email = str(c.get('email') or '')
        phone = str(c.get('phone') or '')
        site = str(c.get('site') or '')
        notes = str(c.get('notes') or '')[:2000]
        # notes is free text an operator might paste a credential into. The old
        # `_is_secret_key('notes')` guard was dead (a KEY-name test on a fixed
        # non-secret name → always False). Value-scrub instead: redact secret-
        # looking tokens (KEY=secret, bearer, AWS, long hex/base64) the same way
        # script bodies are scrubbed before embedding / (cloud) off-box.
        if notes:
            notes = _scrub_script_body(notes)
        lines = [f"Contact: {name}"]
        if role:
            lines.append(f"Role: {role}")
        if company:
            lines.append(f"Company: {company}")
        if email:
            lines.append(f"Email: {email}")
        if phone:
            lines.append(f"Phone: {phone}")
        if site:
            lines.append(f"Site: {site}")
        if notes:
            lines.append(f"Notes: {notes}")
        docs.append(make_doc(
            f"contacts/{cid}", 'contacts', 'contact', '\n'.join(lines),
            title=f"Contact: {name[:80]}", ts=int(c.get('updated_at') or now)))
        _bits = name + (f", {role}" if role else '') + (f" @ {company}" if company else '')
        index.append(f"- {_bits[:100]}" + (f" [{site}]" if site else ''))
    docs.append(make_doc(
        'contacts/_index', 'contacts', 'contacts_index',
        f"Contact directory: {len(index)} contact(s).\n" + '\n'.join(index[:300]),
        title='Contact directory index', ts=now))
    return docs


def build_maintenance_corpus(store, now=0):
    """v6.2.2: maintenance windows for the RAG, so the model can answer "is
    anything in maintenance now?", "what's scheduled?", "why is host X's alert
    suppressed?". `store` is MAINT_FILE {'windows': [...]}. Each window has an
    operator `reason`, a scope (match_type/pattern or all-fleet) and start/end
    or a recurring cron. Defensive on shape (every field via .get). One doc per
    window plus a rollup. Operator-authored scheduling text — no secrets."""
    docs = []
    windows = (store or {}).get('windows', []) if isinstance(store, dict) else []
    if not isinstance(windows, list) or not windows:
        return docs
    index = []
    for w in windows:
        if not isinstance(w, dict):
            continue
        wid = w.get('id') or ''
        reason = _scrub_script_body(str(w.get('reason') or 'Maintenance window'))  # SEC v6.4.0
        mtype = str(w.get('match_type') or 'all')
        pattern = str(w.get('pattern') or '')
        scope = 'whole fleet' if mtype == 'all' else f'{mtype} {pattern}'.strip()
        cron = str(w.get('cron') or '')
        start = w.get('start')
        lines = [f"Maintenance window: {reason}", f"Scope: {scope}"]
        if cron:
            lines.append(f"Recurring: {cron}")
        elif start:
            lines.append(f"Starts: {start}")
        if w.get('suppress_alerts'):
            lines.append("Suppresses alerts while active.")
        if w.get('block_commands'):
            lines.append("Blocks command execution while active.")
        docs.append(make_doc(
            f"maintenance/{wid}", 'maintenance', 'maint_window', '\n'.join(lines),
            title=f"Maintenance: {reason[:70]}", ts=int(w.get('created') or now)))
        index.append(f"- {reason[:70]} ({scope})" + (f" cron:{cron}" if cron else ''))
    docs.append(make_doc(
        'maintenance/_index', 'maintenance', 'maintenance_index',
        f"Maintenance windows: {len(index)} defined.\n" + '\n'.join(index[:300]),
        title='Maintenance windows index', ts=now))
    return docs


def build_incidents_corpus(store, now=0):
    """v6.2.2: operator-posted status-page incidents for the RAG, so the model
    can answer "what incidents have we had?", "is anything ongoing?", "what was
    the last major outage?". `store` is INCIDENTS_FILE {'incidents': [...]} with
    id/title/impact/status and an updates timeline. One doc per incident (title,
    impact, status, and the running update log) plus a rollup index. All
    operator-authored public status text — no secrets by construction."""
    docs = []
    incidents = (store or {}).get('incidents', []) if isinstance(store, dict) else []
    if not isinstance(incidents, list) or not incidents:
        return docs
    index = []
    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        iid = inc.get('id') or ''
        title = str(inc.get('title') or 'Incident')
        impact = str(inc.get('impact') or 'minor')
        status = str(inc.get('status') or '')
        lines = [f"Status-page incident: {title}",
                 f"Impact: {impact}", f"Status: {status}"]
        for u in (inc.get('updates') or [])[:40]:
            if isinstance(u, dict) and (u.get('body') or u.get('status')):
                lines.append(f"- [{u.get('status', '')}] {_scrub_script_body(str(u.get('body') or ''))[:500]}")  # SEC v6.4.0
        docs.append(make_doc(
            f"incidents/{iid}", 'incidents', 'incident', '\n'.join(lines),
            title=f"Incident: {title[:80]}",
            ts=int(inc.get('updated_at') or inc.get('created_at') or now)))
        index.append(f"- {title[:80]} [{impact}/{status}]")
    docs.append(make_doc(
        'incidents/_index', 'incidents', 'incidents_index',
        f"Status-page incidents: {len(index)} total.\n" + '\n'.join(index[:300]),
        title='Incidents index', ts=now))
    return docs


def build_provisioning_corpus(store, now=0):
    """v5.6.0: infrastructure-provisioning blueprints (IaC) for the RAG. `store`
    is the PROVISION_FILE dict {'blueprints': [...]}. Each blueprint (Terraform /
    cloud-init / Ansible / iPXE) becomes one doc — name, type, folder, declared
    variables, and the last plan/apply/destroy status — so the AI can answer
    "what's our IaC coverage?", "which blueprint deploys X?", "did the last apply
    fail?". Blueprint BODIES and secret values are NOT included (only names). Only
    invoke when provisioning is enabled."""
    docs = []
    bps = (store or {}).get('blueprints', []) if isinstance(store, dict) else []
    if not isinstance(bps, list) or not bps:
        return docs
    index = []
    _RC = {0: 'ok', None: 'not run'}
    for b in bps:
        if not isinstance(b, dict):
            continue
        bid = b.get('id') or ''
        name = str(b.get('name') or 'Untitled')
        typ = str(b.get('type') or '')
        folder = str(b.get('folder') or '')
        vars = b.get('variables') or []
        vnames = ', '.join(
            str(v.get('name')) + ('*' if isinstance(v, dict) and v.get('secret') else '')
            for v in vars if isinstance(v, dict) and v.get('name')) if isinstance(vars, list) else ''
        last_op = str(b.get('last_op') or 'none')
        last_rc = b.get('last_rc')
        status = _RC.get(last_rc, f'exit {last_rc}') if not isinstance(last_rc, bool) else str(last_rc)
        head = (f"Provisioning blueprint: {name}\nType: {typ or 'unknown'}\n"
                f"Folder: {folder or '(root)'}\nVariables: {vnames or 'none'}\n"
                f"Last operation: {last_op} ({status})")
        docs.append(make_doc(
            f"prov/{bid}", 'provisioning', 'blueprint', head,
            title=f"Blueprint: {name[:70]}", ts=int(b.get('last_run') or now)))
        index.append(f"- {name[:70]} [{typ}] last:{last_op}/{status}")
    docs.append(make_doc(
        'prov/_index', 'provisioning', 'blueprint_index',
        f"Provisioning: {len(index)} blueprint(s).\n" + '\n'.join(index[:300]),
        title='Provisioning blueprints index', ts=now))
    return docs


def build_rollouts_corpus(store, now=0):
    """v5.6.0: staged script/config rollouts for the RAG. `store` is the
    ROLLOUTS_FILE dict {'rollouts': [{id,name,action,rings,rings_state,state,...}]}.
    Each rollout becomes one doc — name, action, canary->pilot->broad ring progress
    and whether it halted — so the AI can answer "what rollouts are in flight?" and
    "did the last rollout halt and why?"."""
    docs = []
    rolls = (store or {}).get('rollouts', []) if isinstance(store, dict) else []
    if not isinstance(rolls, list) or not rolls:
        return docs
    index = []
    for r in rolls:
        if not isinstance(r, dict):
            continue
        rid = r.get('id') or ''
        name = str(r.get('name') or 'Untitled')
        action = str(r.get('action') or '')
        state = str(r.get('state') or '')
        rings = r.get('rings') or []
        rstate = r.get('rings_state') or []
        nrings = len(rings) if isinstance(rings, list) else 0
        done = sum(1 for s in rstate if isinstance(s, dict) and s.get('done')) if isinstance(rstate, list) else 0
        head = (f"Rollout: {name}\nAction: {action or 'unknown'}\nState: {state or 'unknown'}\n"
                f"Rings: {done}/{nrings} completed")
        docs.append(make_doc(
            f"rollout/{rid}", 'rollouts', 'rollout', head,
            title=f"Rollout: {name[:70]}", ts=int(r.get('updated_at') or r.get('created_at') or now)))
        index.append(f"- {name[:70]} [{action}] {state} {done}/{nrings}")
    docs.append(make_doc(
        'rollout/_index', 'rollouts', 'rollout_index',
        f"Rollouts: {len(index)} rollout(s).\n" + '\n'.join(index[:300]),
        title='Rollouts index', ts=now))
    return docs


def build_network_map_corpus(links, discovery, now=0):
    """v5.6.0: network topology + unmanaged-host discovery for the RAG. `links` is
    the LINKS_FILE list (records carrying `connected_to`); `discovery` is the
    DISCOVERY_FILE (hosts agents saw on the LAN that aren't enrolled). Feeds the
    unmonitored-visibility principle — the AI can answer "what depends on host X?"
    and "what's on our network we aren't monitoring?"."""
    docs = []
    deps = []
    if isinstance(links, list):
        for rec in links:
            if isinstance(rec, dict) and rec.get('connected_to'):
                deps.append(f"- {rec.get('device_id') or rec.get('id') or '?'} -> {rec.get('connected_to')}")
    if deps:
        docs.append(make_doc(
            'netmap/deps', 'network_map', 'dependencies',
            f"Device dependency links ({len(deps)}):\n" + '\n'.join(deps[:300]),
            title='Network dependency links', ts=now))
    # Unmanaged hosts discovered on the LAN.
    seen = []
    disc = discovery if isinstance(discovery, dict) else {}
    for host, info in list(disc.items())[:400]:
        if not isinstance(info, dict):
            continue
        ip = info.get('ip') or host
        name = info.get('hostname') or info.get('name') or ''
        seen.append(f"- {ip}" + (f" ({name})" if name else ''))
    if seen:
        docs.append(make_doc(
            'netmap/unmanaged', 'network_map', 'unmanaged_hosts',
            f"Unmanaged hosts seen on the LAN ({len(seen)}) — not enrolled in "
            f"RemotePower:\n" + '\n'.join(seen[:300]),
            title='Unmanaged LAN hosts', ts=now))
    return docs


def build_incident_memory_corpus(store, now=0):
    """v6.3.1: resolved-incident outcome memory for the RAG, so incident_rca /
    investigate_alert / triage answers are grounded in what actually fixed
    similar incidents on THIS fleet. `store` is INCIDENT_MEMORY_FILE
    {'outcomes': [...]} — already value-free (event names, kinds, resolution
    summaries), captured by the auto-triage harvester."""
    docs = []
    outcomes = (store or {}).get('outcomes') if isinstance(store, dict) else None
    if not isinstance(outcomes, list) or not outcomes:
        return docs
    lines = []
    for o in outcomes[-200:]:
        if not isinstance(o, dict):
            continue
        ev = str(o.get('event') or o.get('kind') or 'incident')
        dev = str(o.get('device_name') or o.get('device_id') or '')
        how = str(o.get('resolution') or o.get('summary') or o.get('how') or '')[:300]
        rate = o.get('rating')
        lines.append(f"- {ev}" + (f" on {dev}" if dev else '')
                     + (f": {how}" if how else '')
                     + (f" [triage rated {rate}]" if rate in ('up', 'down') else ''))
    if lines:
        docs.append(make_doc(
            'incident_memory/outcomes', 'incident_memory', 'incident_outcomes',
            f"Resolved-incident outcome memory ({len(lines)} recent) — how past "
            "alerts on this fleet were actually resolved:\n" + '\n'.join(lines),
            title='Resolved incident outcomes', ts=now))
    return docs


def build_image_cves_corpus(store, devices=None, now=0):
    """v6.3.1: container-image CVE summaries (trivy) for the RAG — the CVE
    advisors previously only saw HOST package CVEs, so 'prioritise my CVEs'
    answers ignored the container layer entirely. `store` is IMAGE_CVE_FILE
    {dev_id: {'ts', 'images': [{'image', 'critical', 'high', ...}]}}."""
    docs = []
    if not isinstance(store, dict) or not store:
        return docs
    devices = devices if isinstance(devices, dict) else {}
    lines = []
    for dev_id, rec in list(store.items())[:300]:
        if not isinstance(rec, dict):
            continue
        dname = (devices.get(dev_id) or {}).get('name') or dev_id
        for img in (rec.get('images') or [])[:50]:
            if not isinstance(img, dict):
                continue
            crit = int(img.get('critical') or 0)
            high = int(img.get('high') or 0)
            if not (crit or high):
                continue
            lines.append(f"- {img.get('image', '?')} on {dname}: "
                         f"{crit} critical, {high} high")
    if lines:
        docs.append(make_doc(
            'image_cves/summary', 'image_cves', 'image_cves',
            f"Container-image CVE findings (trivy; images with critical/high "
            f"vulnerabilities, {len(lines)} rows):\n" + '\n'.join(lines[:400]),
            title='Container-image CVEs', ts=now))
    return docs


def build_scap_corpus(store, devices=None, now=0):
    """v6.3.1: OpenSCAP/USG baseline scan results for the RAG — grounds
    compliance / hardening advisors in the real per-host scores and failing
    rules. `store` is SCAP_FILE {dev_id: {ts, profile, score, pass, fail,
    failed_rules[], available, reason}}."""
    docs = []
    if not isinstance(store, dict) or not store:
        return docs
    devices = devices if isinstance(devices, dict) else {}
    lines = []
    for dev_id, rec in list(store.items())[:300]:
        if not isinstance(rec, dict):
            continue
        dname = (devices.get(dev_id) or {}).get('name') or dev_id
        if not rec.get('available'):
            continue
        top = ', '.join(str(r)[:60] for r in (rec.get('failed_rules') or [])[:5])
        lines.append(f"- {dname}: profile {rec.get('profile', '?')}, "
                     f"score {rec.get('score', '?')}%, "
                     f"{rec.get('pass', '?')} pass / {rec.get('fail', '?')} fail"
                     + (f"; top failing: {top}" if top else ''))
    if lines:
        docs.append(make_doc(
            'scap/summary', 'scap', 'scap_results',
            f"OpenSCAP hardening-baseline scan results ({len(lines)} hosts):\n"
            + '\n'.join(lines),
            title='OpenSCAP baseline results', ts=now))
    return docs


def build_security_findings_corpus(secrets, pii, av, devices=None, now=0):
    """v6.3.1: on-disk secret findings + PII inventory + AV posture for the RAG,
    so security_advisory / access_review can answer from real findings. STRICTLY
    value-free by construction: secrets → rule + path + count (never preview or
    fingerprint), PII → kind counts + paths, AV → tool state. The stores are
    already value-free server-side; this builder narrows them further."""
    docs = []
    devices = devices if isinstance(devices, dict) else {}

    def _name(d):
        return (devices.get(d) or {}).get('name') or d

    sec_lines = []
    for dev_id, rec in (secrets.items() if isinstance(secrets, dict) else []):
        if not isinstance(rec, dict):
            continue
        finds = [f for f in (rec.get('findings') or []) if isinstance(f, dict)]
        if not finds:
            continue
        by_rule = {}
        for f in finds[:200]:
            by_rule.setdefault(str(f.get('rule') or 'secret'), []).append(str(f.get('path') or ''))
        det = '; '.join(f"{r}×{len(ps)} (e.g. {ps[0]})" for r, ps in list(by_rule.items())[:6])
        sec_lines.append(f"- {_name(dev_id)}: {len(finds)} finding(s) — {det}")
    if sec_lines:
        docs.append(make_doc(
            'security/secrets', 'security_findings', 'secret_findings',
            f"On-disk secret-scan findings ({len(sec_lines)} hosts; rule + file "
            "path only, values are never stored):\n" + '\n'.join(sec_lines[:200]),
            title='Secret-scan findings', ts=now))
    pii_lines = []
    for dev_id, rec in (pii.items() if isinstance(pii, dict) else []):
        if not isinstance(rec, dict):
            continue
        finds = [f for f in (rec.get('findings') or []) if isinstance(f, dict)]
        if not finds:
            continue
        by_kind = {}
        for f in finds[:200]:
            by_kind[str(f.get('kind') or '?')] = by_kind.get(str(f.get('kind') or '?'), 0) + int(f.get('count') or 0)
        det = ', '.join(f"{k}: {n}" for k, n in by_kind.items())
        pii_lines.append(f"- {_name(dev_id)}: {det}")
    if pii_lines:
        docs.append(make_doc(
            'security/pii', 'security_findings', 'pii_findings',
            f"Regulated-data (PII) inventory ({len(pii_lines)} hosts; match "
            "counts by kind, no values):\n" + '\n'.join(pii_lines[:200]),
            title='PII inventory', ts=now))
    av_lines = []
    for dev_id, rec in (av.items() if isinstance(av, dict) else []):
        if not isinstance(rec, dict):
            continue
        bits = []
        for tool, t in rec.items():
            if not isinstance(t, dict) or not t.get('installed'):
                continue
            b = tool
            if t.get('infected'):
                b += f" INFECTED×{t['infected']}"
            if isinstance(t.get('db_age_days'), int) and t['db_age_days'] > 7:
                b += f" (defs {t['db_age_days']}d old)"
            if t.get('realtime_enabled') is False:
                b += " (realtime OFF)"
            bits.append(b)
        if bits:
            av_lines.append(f"- {_name(dev_id)}: {', '.join(bits)}")
    if av_lines:
        docs.append(make_doc(
            'security/av', 'security_findings', 'av_posture',
            f"Endpoint AV/malware posture ({len(av_lines)} hosts):\n"
            + '\n'.join(av_lines[:300]),
            title='AV posture', ts=now))
    return docs


def build_automation_rules_corpus(store, now=0):
    """v6.3.1: existing automation rules for the RAG — automation_suggest could
    see event history but not what automation ALREADY exists, so it kept
    proposing rules the operator already had. Surfaces name / trigger / action
    TYPES / enabled state only — never action bodies (a webhook URL or command
    string can embed a credential)."""
    docs = []
    rules = (store or {}).get('rules') if isinstance(store, dict) else None
    if not isinstance(rules, list) or not rules:
        return docs
    lines = []
    for r in rules[:200]:
        if not isinstance(r, dict):
            continue
        acts = ', '.join(sorted({str(a.get('type') or a.get('action') or '?')
                                 for a in (r.get('actions') or []) if isinstance(a, dict)})) or '—'
        lines.append(f"- {str(r.get('name') or r.get('id') or 'rule')[:80]}: "
                     f"on {str(r.get('event') or r.get('trigger') or 'event')[:60]} "
                     f"→ {acts}"
                     + ('' if r.get('enabled', True) else ' [disabled]')
                     + (f" (fired {int(r.get('fire_count') or 0)}×)" if r.get('fire_count') else ''))
    if lines:
        docs.append(make_doc(
            'automation/rules', 'automation_rules', 'automation_rules',
            f"Configured automation rules ({len(lines)}):\n" + '\n'.join(lines),
            title='Automation rules', ts=now))
    return docs


def build_hardware_corpus(store, devices=None, now=0):
    """v6.4.0: per-device hardware health for the RAG — SMART disk health, GPU
    telemetry, UPS/power, kernel/livepatch (reboot-needed), board temperature,
    and privileged-account posture. All of this is collected, persisted
    (HARDWARE_FILE via _ingest_hardware), alerted and shown in the drawer, but
    was entirely AI-blind — the model could not answer "what's the SMART wear on
    web01", "does host X need a kernel reboot", "UPS runtime", "who has sudo".
    One chunk per device with any hardware signal. No secrets (models, states,
    counts, usernames — usernames are already visible fleet inventory)."""
    docs = []
    if not isinstance(store, dict) or not store:
        return docs
    devices = devices if isinstance(devices, dict) else {}
    for dev_id, rec in list(store.items())[:400]:
        if not isinstance(rec, dict):
            continue
        dname = (devices.get(dev_id) or {}).get('name') or dev_id
        lines = []
        # SMART / disk health.
        smart = rec.get('smart')
        disks = smart if isinstance(smart, list) else (
            smart.get('disks') if isinstance(smart, dict) else None)
        if rec.get('_smart_failed'):
            failed = rec.get('_smart_failed_devs') or []
            lines.append("SMART: FAILING" + (f" on {', '.join(map(str, failed[:6]))}" if failed else ''))
        if isinstance(disks, list):
            for d in disks[:8]:
                if not isinstance(d, dict):
                    continue
                bits = []
                nm = d.get('disk') or d.get('name') or d.get('model') or 'disk'
                if d.get('wear_pct') is not None:
                    bits.append(f"wear {d['wear_pct']}%")
                if d.get('spare_pct') is not None:
                    bits.append(f"spare {d['spare_pct']}%")
                if d.get('temperature_c') is not None:
                    bits.append(f"{d['temperature_c']}°C")
                if d.get('reallocated'):
                    bits.append(f"realloc {d['reallocated']}")
                if bits:
                    lines.append(f"disk {nm}: " + ', '.join(bits))
        # Kernel / livepatch.
        kern = rec.get('kernel')
        if isinstance(kern, dict):
            if kern.get('reboot_for_kernel') or kern.get('reboot_required') or rec.get('_kernel_old'):
                lines.append("kernel: reboot needed for a newer installed kernel"
                             + (f" (running {kern.get('running')}, latest {kern.get('latest_installed')})"
                                if kern.get('running') else ''))
            lp = kern.get('livepatch')
            if isinstance(lp, dict) and lp.get('running') is False:
                lines.append("livepatch: not running")
        # UPS / power. v6.4.0 (BUG): `ups` is a LIST of per-UPS dicts keyed
        # `status`/`battery_pct`/`runtime_s` (see api.py _ingest, agent
        # get_ups_status) — this read it as a single dict with a `state` key, so
        # the detailed UPS line was DEAD and only the _ups_on_battery bool
        # fallback ever surfaced. Iterate the list with the real field names.
        ups = rec.get('ups')
        _ups_emitted = False
        if isinstance(ups, list):
            for u in ups:
                if not isinstance(u, dict):
                    continue
                st = u.get('status') or ''
                if st or u.get('battery_pct') is not None:
                    nm = u.get('name') or 'UPS'
                    lines.append(f"UPS {nm}: {st or '?'}"
                                 + (f", battery {u['battery_pct']}%" if u.get('battery_pct') is not None else '')
                                 + (f", runtime {u.get('runtime_s')}s" if u.get('runtime_s') is not None else ''))
                    _ups_emitted = True
        if not _ups_emitted and rec.get('_ups_on_battery'):
            lines.append("UPS: ON BATTERY")
        # v6.4.0: laptop battery health — collected in device sysinfo (a list of
        # per-battery {percent,cycles,health_pct,status}) and alerted on wear
        # (battery_health_low), but AI-blind. Surface it so "which laptops have a
        # worn battery" is answerable from the corpus.
        _bat = (devices.get(dev_id) or {}).get('sysinfo', {}).get('battery')
        if isinstance(_bat, list):
            for b in _bat[:4]:
                if not isinstance(b, dict):
                    continue
                bits = []
                if b.get('health_pct') is not None:
                    bits.append(f"health {b['health_pct']}%")
                if b.get('cycles') is not None:
                    bits.append(f"{b['cycles']} cycles")
                if b.get('percent') is not None:
                    bits.append(f"charge {b['percent']}%")
                if bits:
                    lines.append(f"battery {b.get('name') or ''}: ".replace(' :', ':')
                                 + ', '.join(bits))
        # GPUs.
        gpus = rec.get('gpus')
        if isinstance(gpus, list):
            for g in gpus[:4]:
                if not isinstance(g, dict):
                    continue
                lines.append(f"GPU {g.get('model', g.get('name', 'gpu'))}: "
                             + ', '.join(filter(None, [
                                 f"util {g['util']}%" if g.get('util') is not None else '',
                                 f"{g['temp_c']}°C" if g.get('temp_c') is not None else ''])) or f"GPU {g.get('model', 'gpu')}")
        # Temperature flag.
        if rec.get('_temp_high'):
            lines.append("board/CPU temperature: HIGH")
        # v6.4.0: auto-update posture — "which hosts patch themselves" is a real
        # fleet question ("0 pending" means different things on a self-patching
        # vs a manual box). Surfaced in the drawer + advisor; enrich the RAG chunk
        # too — but only for a host that ALREADY has a notable-hardware chunk, so
        # this stays a "notable signals" corpus and does not emit a chunk per
        # (otherwise-healthy) fleet member.
        if lines:
            _au = (devices.get(dev_id) or {}).get('sysinfo', {}).get('autoupdate')
            if isinstance(_au, dict):
                if _au.get('enabled'):
                    lines.append(f"auto-patching: on ({_au.get('mechanism') or 'enabled'})")
                else:
                    lines.append("auto-patching: off (manual patching only)")
        # Privileged accounts.
        priv = rec.get('_priv_users') or (rec.get('accounts') or {}).get('privileged') \
            if isinstance(rec.get('accounts'), dict) else rec.get('_priv_users')
        if isinstance(priv, list) and priv:
            lines.append(f"privileged (root-equivalent) accounts: {', '.join(map(str, priv[:12]))}")
        if lines:
            docs.append(make_doc(
                f"live/{dev_id}#hardware", 'live_state', 'device_hardware',
                f"Hardware health for {dname}:\n" + '\n'.join(lines),
                title=f"{dname} hardware", device=dev_id, ts=int(rec.get('collected_at') or now)))
    return docs


def build_billing_corpus(invoices, quotes, time_entries, now=0):
    """v6.4.0: invoice / quote / time-entry summary for the RAG so the
    `billing_review` advisor is grounded instead of hallucinating — it had NO
    backing data. Summary-level only (counts + totals by status, overdue list);
    no line-item detail beyond what the operator already authored."""
    docs = []
    inv = (invoices or {}).get('invoices') if isinstance(invoices, dict) else None
    q = (quotes or {}).get('quotes') if isinstance(quotes, dict) else None
    te = (time_entries or {}).get('entries') if isinstance(time_entries, dict) else None
    lines = []
    if isinstance(inv, list) and inv:
        by_status, overdue = {}, []
        for i in inv:
            if not isinstance(i, dict):
                continue
            st = str(i.get('status') or 'draft')
            by_status[st] = by_status.get(st, 0) + 1
            if st in ('sent', 'overdue') and i.get('due_ts') and i['due_ts'] < now:
                overdue.append(f"#{i.get('number', i.get('id', '?'))}"
                               + (f" {i.get('amount')}" if i.get('amount') is not None else ''))
        lines.append("Invoices by status: "
                     + ', '.join(f"{k}: {v}" for k, v in sorted(by_status.items())))
        if overdue:
            lines.append(f"Overdue invoices ({len(overdue)}): " + ', '.join(overdue[:20]))
    if isinstance(q, list) and q:
        qs = {}
        for x in q:
            if isinstance(x, dict):
                qs[str(x.get('status') or 'draft')] = qs.get(str(x.get('status') or 'draft'), 0) + 1
        lines.append("Quotes by status: " + ', '.join(f"{k}: {v}" for k, v in sorted(qs.items())))
    if isinstance(te, list) and te:
        _unbilled = sum(1 for e in te if isinstance(e, dict) and not e.get('invoiced'))
        lines.append(f"Time entries: {len(te)} total, {_unbilled} not yet invoiced")
    if lines:
        docs.append(make_doc(
            'billing/summary', 'billing', 'billing_summary',
            "Billing snapshot (invoices, quotes, unbilled time):\n" + '\n'.join(lines),
            title='Billing summary', ts=now))
    return docs


def build_remediations_corpus(store, now=0):
    """v6.4.0: the auto-remediation attempt ledger for the RAG — grounds
    incident_rca / automation_suggest in what the guarded executor actually TRIED
    and whether it worked ('did the auto-fix clear the alert', 'what's flapping').
    No secrets (rule + device names + status/reason only, no action bodies)."""
    docs = []
    attempts = (store or {}).get('attempts') if isinstance(store, dict) else None
    if not isinstance(attempts, list) or not attempts:
        return docs
    lines = []
    for a in attempts[-200:]:
        if not isinstance(a, dict):
            continue
        lines.append(f"- {a.get('rule_name', 'rule')} on {a.get('device_name', a.get('device_id', '?'))} "
                     f"(trigger {a.get('event', '?')}): {a.get('status', '?')}"
                     + (f" — {a.get('reason')}" if a.get('reason') else ''))
    if lines:
        docs.append(make_doc(
            'remediations/ledger', 'remediations', 'remediation_ledger',
            f"Auto-remediation attempts ({len(lines)} recent):\n" + '\n'.join(lines),
            title='Auto-remediation ledger', ts=now))
    return docs


def build_config_revisions_corpus(store, now=0):
    """v6.4.0: server-config change history for the RAG — grounds change_risk /
    drift_review / 'what config changed and when / who'. Metadata only (ts +
    user), never the config values themselves (secrets live there)."""
    docs = []
    revs = (store or {}).get('revisions') if isinstance(store, dict) else None
    if not isinstance(revs, list) or not revs:
        return docs
    lines = []
    for r in revs[-40:]:
        if not isinstance(r, dict):
            continue
        _t = int(r.get('ts') or 0)
        lines.append(f"- config saved by {r.get('user') or 'unknown'}"
                     + (f" at ts {_t}" if _t else ''))
    if lines:
        docs.append(make_doc(
            'config/revisions', 'config_revisions', 'config_revisions',
            f"Recent server-configuration changes ({len(lines)}, who + when; "
            "values not included):\n" + '\n'.join(lines),
            title='Config change history', ts=now))
    return docs


def build_sudo_corpus(store, devices=None, now=0):
    """v6.4.0: the per-device privileged-command (sudo) trail for the RAG —
    grounds access_review and incident RCA ("who ran what as root on X").
    Commands are already redacted at ingest (_redact_sudo_command)."""
    docs = []
    if not isinstance(store, dict) or not store:
        return docs
    devices = devices if isinstance(devices, dict) else {}
    lines = []
    for dev_id, evs in list(store.items())[:300]:
        if not isinstance(evs, list) or not evs:
            continue
        dname = (devices.get(dev_id) or {}).get('name') or dev_id
        for e in evs[-8:]:
            if isinstance(e, dict) and e.get('command'):
                who = e.get('user') or e.get('by') or ''
                lines.append(f"- {dname}: {who + ': ' if who else ''}{str(e.get('command'))[:200]}")
    if lines:
        docs.append(make_doc(
            'access/sudo', 'sudo_log', 'sudo_trail',
            f"Recent privileged (sudo) commands across the fleet ({len(lines)}):\n"
            + '\n'.join(lines[:400]),
            title='Privileged-command trail', ts=now))
    return docs


def build_self_obs_corpus(store, now=0):
    """v6.4.0: the controller's own maintenance-sweep health for the RAG —
    grounds "is RemotePower itself healthy / did feature X stop running"."""
    docs = []
    sweeps = (store or {}).get('sweeps') if isinstance(store, dict) else None
    if not isinstance(sweeps, dict) or not sweeps:
        return docs
    lines = []
    for name, s in sorted(sweeps.items()):
        if not isinstance(s, dict):
            continue
        bit = name
        if s.get('last_error'):
            bit += f" — LAST ERROR: {str(s.get('last_error'))[:120]}"
        elif s.get('last_ok'):
            bit += " — ok"
        lines.append(f"- {bit}")
    if lines:
        docs.append(make_doc(
            'self/observability', 'self_obs', 'self_observability',
            f"RemotePower's own maintenance sweeps ({len(lines)}) — last run / "
            "recent errors:\n" + '\n'.join(lines),
            title='Controller self-observability', ts=now))
    return docs


def build_inventory_corpus(sites, racks, subnets, warranty, devices=None, now=0):
    """v6.4.0: physical + IPAM inventory for the RAG — grounds "which rack/
    subnet/site is host X in", capacity questions, and out-of-warranty planning.
    All operator-authored inventory metadata; no secrets."""
    docs = []
    devices = devices if isinstance(devices, dict) else {}
    lines = []
    if isinstance(sites, dict) and sites:
        lines.append("Sites: " + ', '.join(
            str((v or {}).get('name') or k) for k, v in list(sites.items())[:50]))
    if isinstance(racks, dict) and racks:
        lines.append(f"Racks ({len(racks)}): " + ', '.join(
            str((v or {}).get('name') or k) for k, v in list(racks.items())[:50]))
    if isinstance(subnets, dict) and subnets:
        _sn = []
        for k, v in list(subnets.items())[:80]:
            if isinstance(v, dict):
                _sn.append(f"{v.get('cidr', k)}" + (f" ({v.get('name')})" if v.get('name') else ''))
        if _sn:
            lines.append(f"Subnets ({len(_sn)}): " + ', '.join(_sn))
    if isinstance(warranty, dict) and warranty:
        _w = []
        for serial, v in list(warranty.items())[:80]:
            if isinstance(v, dict) and v.get('expiry'):
                _w.append(f"{serial}: warranty/EOL {v.get('expiry')}")
        if _w:
            lines.append(f"Warranty/EOL ({len(_w)}):\n  " + '\n  '.join(_w[:60]))
    if lines:
        docs.append(make_doc(
            'inventory/physical', 'inventory', 'physical_inventory',
            "Physical + IPAM inventory (sites, racks, subnets, warranty):\n"
            + '\n'.join(lines),
            title='Physical / IPAM inventory', ts=now))
    return docs


# ── Vector helpers ───────────────────────────────────────────────────────────

def cosine(a, b):
    """Cosine similarity of two equal-length vectors. 0.0 on degenerate
    input (empty, mismatched length, or a zero vector)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def rrf_fuse(rank_lists, k=60):
    """Reciprocal Rank Fusion over several ranked id lists.

    score(id) = sum over lists of 1/(k + rank), rank starting at 1.
    Returns {id: score}. RRF is rank-based so it needs no score
    normalisation between the (unbounded) BM25 scores and the [-1,1]
    cosine scores — which is exactly why we use it instead of a
    weighted sum of raw scores.
    """
    scores = {}
    for ranked in rank_lists:
        for rank, doc_id in enumerate(ranked, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


# ── The index ────────────────────────────────────────────────────────────────

# Above this many chunks we stop sweeping cosine over the entire corpus
# and instead rerank only the lexical prefilter. Below it, a full sweep
# is cheap and gives embeddings a chance to surface docs the lexical
# stage missed entirely.
_FULL_COSINE_MAX_DOCS = 2000

# BM25 parameters. The textbook defaults; our corpus is too small to
# justify tuning them.
_BM25_K1 = 1.2
_BM25_B = 0.75


class InfraIndex:
    """Lexical (BM25) index with an optional embedding rerank layer.

    Persisted as a plain dict via to_dict()/from_dict(); api.py writes
    that through its own load()/save(). Embedding vectors are cached by
    content hash so a reindex only re-embeds chunks whose text changed.
    """

    def __init__(self):
        self.docs = []                 # list of doc dicts
        self._by_id = {}               # id -> doc
        self._postings = {}            # term -> {doc_id: tf}
        self._doc_len = {}             # doc_id -> token count
        self._avgdl = 0.0
        self._n = 0
        self.emb_cache = {}            # content_hash -> {'v': [...]}
        self.emb_model = ''            # model that produced the cached vectors
        self.emb_fingerprint = ''      # provider|base_url|model the cache belongs to
        self.built_at = 0
        self._device_tokens = {}       # dev_id -> set of identifying tokens

    # -- construction ----------------------------------------------------------

    def _index_device_tokens(self):
        """Map each device-scoped chunk's device id to the query tokens that
        should "focus" on it: the full id plus its first hostname label.

        We deliberately exclude shared labels like the domain (`tvipper`,
        `com`) — those would make every `*.tvipper.com` device match a query
        that merely contains "com". The short hostname (`tviweb01`) and the
        full id are specific enough to be a reliable focus signal.
        """
        self._device_tokens = {}
        for d in self.docs:
            dev = d.get('device')
            if not dev:
                continue
            if dev in self._device_tokens:
                continue
            low = str(dev).lower()
            toks = {low, low.split('.')[0]}
            self._device_tokens[dev] = {t for t in toks if len(t) >= 2}

    def build(self, docs, built_at=0):
        """(Re)build the lexical index from a list of docs. Embedding
        cache is preserved across rebuilds (keyed by content hash)."""
        self.docs = [d for d in docs if d.get('text')]
        self._by_id = {d['id']: d for d in self.docs}
        self._postings = {}
        self._doc_len = {}
        total = 0
        for d in self.docs:
            toks = tokenize(d['text'])
            self._doc_len[d['id']] = len(toks)
            total += len(toks)
            tf = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            for t, c in tf.items():
                self._postings.setdefault(t, {})[d['id']] = c
        self._n = len(self.docs)
        self._avgdl = (total / self._n) if self._n else 0.0
        self.built_at = int(built_at or 0)
        self._index_device_tokens()
        # Drop cache entries for chunks that no longer exist, so the file
        # doesn't grow unbounded across many reindexes.
        live = {d['hash'] for d in self.docs}
        self.emb_cache = {h: v for h, v in self.emb_cache.items() if h in live}
        return self

    # -- embeddings ------------------------------------------------------------

    def missing_embeddings(self, fingerprint=''):
        """Return [(hash, text)] for chunks not yet embedded. The caller
        embeds these (deduped by hash) and feeds the result back via
        set_embeddings().

        `fingerprint` identifies the embedding space (provider/base_url/model)
        the caller will embed with. When it differs from the space that
        produced the cached vectors, those vectors live in a different (and
        possibly different-dimension) space; mixing them makes cosine() return
        0.0 on a dimension mismatch and silently collapses semantic search to
        lexical-only. So on a change the whole cache is dropped and every chunk
        re-embedded. Called without a fingerprint the cache is left untouched."""
        if fingerprint:
            if self.emb_fingerprint and self.emb_fingerprint != fingerprint:
                self.emb_cache = {}
                self.emb_model = ''
            self.emb_fingerprint = fingerprint
        seen = set()
        out = []
        for d in self.docs:
            h = d['hash']
            if h in self.emb_cache or h in seen:
                continue
            seen.add(h)
            out.append((h, d['text']))
        return out

    def set_embeddings(self, hash_to_vec, model=''):
        """Merge freshly computed vectors into the cache."""
        for h, v in (hash_to_vec or {}).items():
            if v:
                self.emb_cache[h] = {'v': list(v)}
        if model:
            self.emb_model = model

    def has_embeddings(self):
        return bool(self.emb_cache)

    # -- search ----------------------------------------------------------------

    def _bm25_search(self, qtokens, top_n):
        if not qtokens or not self._n:
            return []
        qset = list(dict.fromkeys(qtokens))      # unique, order-preserving
        scores = {}
        for term in qset:
            postings = self._postings.get(term)
            if not postings:
                continue
            df = len(postings)
            # BM25 idf with the +1 inside the log to keep it non-negative.
            idf = math.log(1 + (self._n - df + 0.5) / (df + 0.5))
            for doc_id, tf in postings.items():
                dl = self._doc_len.get(doc_id, 0)
                denom = tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * dl / (self._avgdl or 1))
                scores[doc_id] = scores.get(doc_id, 0.0) + idf * (tf * (_BM25_K1 + 1)) / (denom or 1)
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:top_n]

    def _semantic_rank(self, candidate_ids, query_vec, top_n):
        sims = []
        for doc_id in candidate_ids:
            doc = self._by_id.get(doc_id)
            if not doc:
                continue
            ent = self.emb_cache.get(doc['hash'])
            if not ent:
                continue
            sims.append((doc_id, cosine(query_vec, ent['v'])))
        sims.sort(key=lambda kv: kv[1], reverse=True)
        return sims[:top_n]

    def _focus_devices(self, qtokens):
        """Devices the query explicitly names (by id or short hostname).
        Returns a set of device ids — empty when the query isn't about a
        specific host."""
        if not self._device_tokens:
            return set()
        qset = set(qtokens)
        return {dev for dev, toks in self._device_tokens.items() if toks & qset}

    # A bonus that dwarfs any RRF score (~1/61 max per list) so a named
    # device's own chunks always sort above generic matches, while their
    # relative order (by underlying relevance) is preserved.
    _FOCUS_BONUS = 1.0
    # Upper bound on chunks returned when the query is about a single host, so
    # one busy host (hundreds of containers/ports chunks) can't blow the budget;
    # the per-host chunk count is small in practice (~6-12 facets).
    _FOCUS_MAX_CHUNKS = 16

    def search(self, query, top_n=6, query_vec=None, prefilter_n=50):
        """Return up to top_n doc dicts most relevant to `query`.

        Scoring is rank-based (RRF) so lexical and optional semantic signals
        combine without normalising raw scores. When the query names a
        specific device, that device's chunks are boosted to the top — a
        "what is web01 doing / what IP does web01 have" question should be
        answered from web01's own state, not from whichever product doc
        happens to share a word with the query.
        """
        qtokens = tokenize(query)
        lex = self._bm25_search(qtokens, top_n=max(top_n, prefilter_n))
        lex_ids = [doc_id for doc_id, _ in lex]

        if query_vec and self.emb_cache:
            if self._n <= _FULL_COSINE_MAX_DOCS:
                candidates = [d['id'] for d in self.docs]
            else:
                # Large corpus: rerank the lexical prefilter only.
                candidates = lex_ids or [d['id'] for d in self.docs[:prefilter_n]]
            sem = self._semantic_rank(candidates, query_vec, top_n=max(top_n, prefilter_n))
            sem_ids = [doc_id for doc_id, _ in sem]
            score = rrf_fuse([lex_ids, sem_ids])
        else:
            # Rank-based lexical score, so the focus bonus is comparable to
            # the RRF path above (both ~1/(60+rank)).
            score = {doc_id: 1.0 / (60 + rank)
                     for rank, doc_id in enumerate(lex_ids, start=1)}

        focus = self._focus_devices(qtokens)
        if focus:
            for doc_id in list(score):
                doc = self._by_id.get(doc_id)
                if doc and doc.get('device') in focus:
                    score[doc_id] += self._FOCUS_BONUS
            # Surface the named device's chunks even if a particular facet
            # didn't lexically match the rest of the query.
            for doc in self.docs:
                if doc.get('device') in focus and doc['id'] not in score:
                    score[doc['id']] = self._FOCUS_BONUS
            # Single-host question ("tell me everything about web01", "summarise
            # its docs", "what's its purpose") → return that host's WHOLE
            # picture, not just top_n general hits. Without this the per-host
            # summary/services/containers/cmdb/docs/runbook chunks compete for a
            # handful of slots and the answer reads as "no docs / no services".
            if len(focus) == 1:
                dev_chunks = sum(1 for d in self.docs if d.get('device') in focus)
                top_n = min(self._FOCUS_MAX_CHUNKS, max(top_n, dev_chunks))

        ranked_ids = sorted(score, key=lambda i: score[i], reverse=True)[:top_n]
        return [self._by_id[i] for i in ranked_ids if i in self._by_id]

    # -- stats / persistence ---------------------------------------------------

    def stats(self):
        by_source = {}
        for d in self.docs:
            by_source[d['source']] = by_source.get(d['source'], 0) + 1
        return {
            'docs':       self._n,
            'terms':      len(self._postings),
            'embedded':   len(self.emb_cache),
            'emb_model':  self.emb_model,
            'by_source':  by_source,
            'built_at':   self.built_at,
        }

    def to_dict(self):
        return {
            'v':         1,
            'built_at':  self.built_at,
            'avgdl':     self._avgdl,
            'n':         self._n,
            'docs':      self.docs,
            'postings':  self._postings,
            'doc_len':   self._doc_len,
            'emb_cache': self.emb_cache,
            'emb_model': self.emb_model,
            'emb_fingerprint': self.emb_fingerprint,
        }

    @classmethod
    def from_dict(cls, data):
        idx = cls()
        if not isinstance(data, dict):
            return idx
        idx.docs = data.get('docs') or []
        idx._by_id = {d['id']: d for d in idx.docs if isinstance(d, dict) and 'id' in d}
        idx._postings = data.get('postings') or {}
        idx._doc_len = data.get('doc_len') or {}
        idx._avgdl = data.get('avgdl') or 0.0
        idx._n = data.get('n') or len(idx.docs)
        idx.emb_cache = data.get('emb_cache') or {}
        idx.emb_model = data.get('emb_model') or ''
        idx.emb_fingerprint = data.get('emb_fingerprint') or ''
        idx.built_at = data.get('built_at') or 0
        idx._index_device_tokens()     # derived, not persisted
        return idx
