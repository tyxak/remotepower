"""
RemotePower AI provider abstraction.

Single endpoint `/api/ai/chat` dispatches to one of:

  * OpenAICompatible  — covers ChatGPT, DeepSeek, Ollama, LocalAI, and
                        anything else speaking /v1/chat/completions.
  * AnthropicProvider — Claude. Different request/response shape so it
                        gets its own adapter.

Provider config lives in CONFIG_FILE under cfg['ai']:

    cfg['ai'] = {
        'enabled':   True | False,
        'provider':  'anthropic' | 'openai' | 'deepseek' | 'ollama' | 'localai',
        'model':     'claude-3-5-sonnet-latest',
        'base_url':  '...' (optional override),
        'api_key':   '...' (cleartext-on-disk in CONFIG_FILE — the file
                            is mode 0600 and owned by the CGI user. For
                            stronger storage, plug in cmdb_vault later.),
        'privacy': {
            'send_hostnames':    False,
            'send_ips':          False,
            'send_journal':      False,
            'send_cmd_output':   True,
        },
        'limits': {
            'max_tokens_per_response':  4000,
            'max_requests_per_user_day': 100,
        },
    }

Design notes:

* All HTTP calls go through urllib.request — no external deps. The
  rest of the codebase is hostile to pip-installed packages so we
  keep it that way here too.
* No streaming. Sync request/response only. Streaming through CGI is
  possible but the user-visible benefit is small compared to the
  buffering / proxy / nginx-buffering / cgi-buffering complications.
* No tool calls. The bigger product question (agent mode, read-only
  API access from the LLM) is queued for a later release behind a
  separate Settings toggle.
* Failures return a structured dict {ok: False, error: str}. The
  caller decides whether to surface raw or wrapped.
"""

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request


# ── Constants ──────────────────────────────────────────────────────────────

PROVIDER_OPENAI    = 'openai'      # ChatGPT
PROVIDER_DEEPSEEK  = 'deepseek'
PROVIDER_OLLAMA    = 'ollama'
PROVIDER_LOCALAI   = 'localai'
PROVIDER_ANTHROPIC = 'anthropic'   # Claude
VALID_PROVIDERS = (PROVIDER_OPENAI, PROVIDER_DEEPSEEK, PROVIDER_OLLAMA,
                   PROVIDER_LOCALAI, PROVIDER_ANTHROPIC)

# Default endpoint per provider. base_url in cfg overrides.
DEFAULT_BASE_URLS = {
    PROVIDER_OPENAI:    'https://api.openai.com/v1',
    PROVIDER_DEEPSEEK:  'https://api.deepseek.com/v1',
    PROVIDER_OLLAMA:    'http://localhost:11434/v1',
    PROVIDER_LOCALAI:   'http://localhost:8080/v1',
    PROVIDER_ANTHROPIC: 'https://api.anthropic.com/v1',
}

# Sensible default model per provider. Operators usually override this.
# We pick "current general-purpose, not the most expensive flagship".
DEFAULT_MODELS = {
    PROVIDER_OPENAI:    'gpt-4o-mini',
    PROVIDER_DEEPSEEK:  'deepseek-chat',
    PROVIDER_OLLAMA:    'llama3.1:8b',
    PROVIDER_LOCALAI:   'gpt-3.5-turbo',          # whatever the user has loaded
    PROVIDER_ANTHROPIC: 'claude-3-5-sonnet-latest',
}

# Bounds. Cloud provider costs are real; the operator can lift these in
# their config but the defaults should prevent a runaway loop from
# producing a memorable invoice.
MAX_MESSAGES        = 50
MAX_MESSAGE_BYTES   = 32 * 1024
MAX_TOTAL_BYTES     = 96 * 1024
# v2.1.4: bumped from 60 → 300. Local thinking models (smallthinker,
# qwq, deepseek-r1, etc.) can chew on a prompt for 60-180 seconds
# before the first token comes back. The bottleneck on a self-hosted
# box isn't network — it's GPU/CPU inference — so a generous timeout
# is the right call. Note: nginx's fastcgi_read_timeout defaults to 60s
# and will close the upstream connection before this timeout fires.
# Operators using a slow local model should set, in their nginx server
# block:
#     location /api/ai/ {
#         fastcgi_read_timeout 300s;
#         fastcgi_send_timeout 300s;
#         (...)
#     }
HTTP_TIMEOUT_S      = 300    # 5 min — slow local models can take a while


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects — a 3xx from a DNS-rebound LLM endpoint
    must not replay the API key (Authorization header) to an attacker URL."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


# v5.x SSRF: the set-time pre-flight blocks obvious local/metadata targets, but a
# saved cloud base_url is re-resolved on every call — a DNS-rebinding window where
# the API key could be replayed to 169.254.169.254 / loopback. Guard the peer IP
# at connect (mirrors proxmox_client._ssrf_opener; cloud calls are HTTPS, so the
# HTTPS handler is the right chokepoint). Local providers (ollama/localai) use
# plain HTTP and never hit this; an internal self-signed HTTPS endpoint sets
# insecure_ssl, which relaxes the loopback block (metadata/link-local stay blocked).
import http.client as _httpclient


def _peer_ip_blocked(ip_str, allow_loopback=False):
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_link_local or ip.is_unspecified:   # 169.254.169.254 metadata, 0.0.0.0
        return True
    return bool(ip.is_loopback) and not allow_loopback


def _ssrf_opener(ctx, allow_loopback=False):
    class _GuardConn(_httpclient.HTTPSConnection):
        def connect(self):
            super().connect()
            try:
                peer = self.sock.getpeername()[0]
            except (OSError, AttributeError, IndexError):
                return
            if _peer_ip_blocked(peer, allow_loopback):
                self.close()
                raise OSError(f'SSRF guard: AI endpoint peer {peer} is a blocked address')

    class _GuardHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_GuardConn, req, context=ctx)

    return urllib.request.build_opener(_NoRedirect, _GuardHTTPSHandler())


# ── Redaction ──────────────────────────────────────────────────────────────

# Cheap regex-based redaction for hostnames / IPs / common secret-shaped
# tokens. Operators who need real DLP should disable the cloud providers
# and run Ollama locally — this is best-effort, not a guarantee.

_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')
# Hostname-shaped tokens: at least one dot, alphanumeric + hyphen labels.
# We don't try to identify "is this hostname mine" — we redact anything
# that looks fqdn-shaped, which over-redacts but is safe.
_FQDN_RE = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}\.){1,5}[a-zA-Z]{2,24})\b')
# Tokens that look like secrets (long base64-ish or hex strings, and
# bearer tokens). Always redacted regardless of privacy toggle.
_BEARER_RE = re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9._\-/+=]{16,}')
_LONG_HEX_RE = re.compile(r'\b[0-9a-fA-F]{32,}\b')
_AWS_KEY_RE = re.compile(r'\bAKIA[0-9A-Z]{16}\b')


def redact(text, privacy):
    """Apply privacy-toggle redaction to user-supplied text before it
    leaves the building. `privacy` is the cfg['ai']['privacy'] dict.

    Always redacted (regardless of toggles): bearer tokens, AWS access
    keys, long hex strings.
    """
    if not isinstance(text, str):
        return text
    out = text
    # Always-on safety: secret-shaped tokens. These should never reach
    # an AI provider even on a fully-opt-in deployment.
    out = _BEARER_RE.sub(r'\1<REDACTED>', out)
    out = _AWS_KEY_RE.sub('<REDACTED-AWS>', out)
    out = _LONG_HEX_RE.sub('<REDACTED-HEX>', out)
    if not privacy.get('send_ips', False):
        out = _IPV4_RE.sub('<IP>', out)
        out = _IPV6_RE.sub('<IPv6>', out)
    if not privacy.get('send_hostnames', False):
        out = _FQDN_RE.sub('<HOST>', out)
    return out


def redact_messages(messages, privacy):
    """Return a new messages list with content redacted per privacy."""
    out = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        new = dict(m)
        if isinstance(new.get('content'), str):
            new['content'] = redact(new['content'], privacy)
        out.append(new)
    return out


# ── Validation ─────────────────────────────────────────────────────────────

def validate_config(cfg):
    """Return (ok, error_msg). Doesn't modify cfg."""
    if not isinstance(cfg, dict):
        return False, 'cfg must be a dict'
    if not cfg.get('enabled'):
        return True, None  # disabled config is always "valid"
    provider = cfg.get('provider')
    if provider not in VALID_PROVIDERS:
        return False, f'provider must be one of {list(VALID_PROVIDERS)}'
    # Cloud providers need an API key. Local providers (ollama, localai)
    # are OK without one — they typically don't require auth.
    if provider in (PROVIDER_OPENAI, PROVIDER_DEEPSEEK, PROVIDER_ANTHROPIC):
        if not cfg.get('api_key'):
            return False, f'{provider} requires api_key'
    return True, None


def validate_messages(messages):
    """Caller-supplied messages list — guardrails on shape and size."""
    if not isinstance(messages, list):
        return False, 'messages must be a list'
    if not (1 <= len(messages) <= MAX_MESSAGES):
        return False, f'messages must contain 1..{MAX_MESSAGES} entries'
    total = 0
    for i, m in enumerate(messages):
        if not isinstance(m, dict):
            return False, f'messages[{i}] must be a dict'
        role = m.get('role')
        if role not in ('user', 'assistant', 'system'):
            return False, f'messages[{i}].role must be user|assistant|system'
        content = m.get('content', '')
        if not isinstance(content, str):
            return False, f'messages[{i}].content must be a string'
        if len(content.encode('utf-8')) > MAX_MESSAGE_BYTES:
            return False, f'messages[{i}].content too large (>{MAX_MESSAGE_BYTES} bytes)'
        total += len(content.encode('utf-8'))
    if total > MAX_TOTAL_BYTES:
        return False, f'total content too large (>{MAX_TOTAL_BYTES} bytes)'
    return True, None


# ── Provider adapters ──────────────────────────────────────────────────────

def _http_post_json(url, headers, body, timeout=HTTP_TIMEOUT_S, insecure_ssl=False):
    """Pure-stdlib HTTP POST returning (status, parsed-json-or-str).

    Distinguished from the rest of api.py's HTTP helpers so we can
    set a longer timeout for AI calls without affecting the rest.

    v3.0.4: bugfix — `insecure_ssl` is now an explicit parameter
    rather than a reference to a closed-over `cfg` that never
    existed. The previous code (`if cfg.get('insecure_ssl'):`)
    raised NameError on every call into the OpenAI-compat or
    Anthropic chat path, returning a 500 to the operator. The
    fault was latent in v3.0.2 (the change that "honoured" the
    flag) and only fired the first time a v3.0.2+ install
    actually called chat_*. Callers pass cfg.get('insecure_ssl')
    explicitly.
    """
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header('Content-Type', 'application/json')
    # BOTH check_hostname and verify_mode must be relaxed together,
    # otherwise the strict hostname check rejects before verify_mode
    # is consulted (matches proxmox_client.py).
    ctx = ssl.create_default_context()
    if insecure_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        # Do NOT follow redirects: an LLM / OpenAI-compatible endpoint never
        # legitimately 3xx's, and a redirect from a DNS-rebound base_url would
        # replay the API key (Authorization header) to an attacker-chosen host.
        # Any 3xx becomes an error. (SSRF hardening — set-time pre-flight already
        # blocks the obvious local/metadata targets.)
        opener = _ssrf_opener(ctx, allow_loopback=insecure_ssl)
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(2 * 1024 * 1024))  # 2 MB cap
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read(64 * 1024))
        except Exception:
            body = {'error': str(e)}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {'error': f'URLError: {e.reason}'}
    except Exception as e:
        return 0, {'error': f'{type(e).__name__}: {e}'}


def chat_openai_compatible(cfg, messages, system, max_tokens,
                            temperature=None, top_p=None, num_ctx=None):
    """OpenAI-compatible /v1/chat/completions. Used for OpenAI itself,
    DeepSeek, Ollama, LocalAI, and most "OpenAI-compatible" forks.

    v2.1.9 note on num_ctx for Ollama:
    --------------------------------
    Ollama's OpenAI-compat endpoint defaults to a 2048-token context
    window unless num_ctx is explicitly set in `options`. With a
    2048-token cap, a typical RemotePower runbook snapshot (4-8K
    tokens of structured JSON) gets truncated mid-content and the
    model fills in the missing parts from imagination — the exact
    hallucination bug an operator reported on v2.1.8 ("the runbook
    talks about firewall rules and DNS lookups that aren't in my
    data"). We pass num_ctx via the body to lift this cap. Real
    OpenAI / DeepSeek ignore the field (the OpenAI API is lenient
    about unknown keys); Ollama and LocalAI honour it.

    v3.0.1: per-call override for temperature, top_p, num_ctx.
    """
    provider = cfg['provider']
    base = (cfg.get('base_url') or DEFAULT_BASE_URLS[provider]).rstrip('/')
    model = cfg.get('model') or DEFAULT_MODELS[provider]
    url = f'{base}/chat/completions'
    payload_messages = []
    if system:
        payload_messages.append({'role': 'system', 'content': system})
    payload_messages.extend(messages)
    body = {
        'model':      model,
        'messages':   payload_messages,
        'max_tokens': max_tokens,
        'stream':     False,
    }
    # v3.0.1: only emit tuning fields the caller set explicitly. None means
    # "use provider default" — never invent a value.
    if temperature is not None:
        body['temperature'] = max(0.0, min(float(temperature), 2.0))
    if top_p is not None:
        body['top_p']       = max(0.0, min(float(top_p), 1.0))
    # Ollama / LocalAI specifically benefit from an explicit num_ctx —
    # without it, Ollama caps the input window at 2048 tokens, which is
    # too small for any non-trivial runbook or investigation. 16384 is
    # comfortable for ~80% of inputs we send and supported by most
    # locally-runnable models. v3.0.1: per-call override wins; falls back
    # to 16384 for local providers that benefit from it.
    if provider in (PROVIDER_OLLAMA, PROVIDER_LOCALAI):
        effective_ctx = int(num_ctx) if num_ctx else 16384
        body['options'] = {'num_ctx': max(512, min(effective_ctx, 131072))}
    headers = {}
    if cfg.get('api_key'):
        headers['Authorization'] = f"Bearer {cfg['api_key']}"
    status, resp = _http_post_json(url, headers, body,
                                    insecure_ssl=bool(cfg.get('insecure_ssl')))
    if status == 200 and isinstance(resp, dict):
        try:
            text = resp['choices'][0]['message']['content']
            usage = resp.get('usage', {}) or {}
            return {
                'ok':       True,
                'text':     text,
                'model':    resp.get('model', model),
                'tokens_in':  usage.get('prompt_tokens', 0),
                'tokens_out': usage.get('completion_tokens', 0),
            }
        except (KeyError, IndexError, TypeError):
            return {'ok': False, 'error': f'unexpected response shape: {str(resp)[:200]}'}
    err_msg = resp.get('error') if isinstance(resp, dict) else None
    if isinstance(err_msg, dict):
        err_msg = err_msg.get('message') or str(err_msg)
    return {'ok': False, 'error': f'HTTP {status}: {err_msg or "unknown"}'}


def chat_anthropic(cfg, messages, system, max_tokens, temperature=None, top_p=None):
    """Anthropic /v1/messages. Different shape from OpenAI:
    - system is a top-level field, not a message
    - response is content[0].text, not choices[0].message.content
    - usage keys are input_tokens / output_tokens

    v3.0.1: per-call temperature and top_p — num_ctx is N/A for Anthropic.
    """
    base = (cfg.get('base_url') or DEFAULT_BASE_URLS[PROVIDER_ANTHROPIC]).rstrip('/')
    model = cfg.get('model') or DEFAULT_MODELS[PROVIDER_ANTHROPIC]
    url = f'{base}/messages'
    body = {
        'model':      model,
        'messages':   messages,   # already user/assistant only; system goes elsewhere
        'max_tokens': max_tokens,
    }
    if temperature is not None:
        body['temperature'] = max(0.0, min(float(temperature), 1.0))   # Anthropic caps at 1.0
    if top_p is not None:
        body['top_p']       = max(0.0, min(float(top_p), 1.0))
    if system:
        body['system'] = system
    headers = {
        'x-api-key':         cfg.get('api_key', ''),
        'anthropic-version': '2023-06-01',
    }
    status, resp = _http_post_json(url, headers, body,
                                    insecure_ssl=bool(cfg.get('insecure_ssl')))
    if status == 200 and isinstance(resp, dict):
        try:
            # content is a list of blocks; first text block is our answer
            text = ''
            for block in resp.get('content', []) or []:
                if isinstance(block, dict) and block.get('type') == 'text':
                    text = block.get('text', '')
                    break
            usage = resp.get('usage', {}) or {}
            return {
                'ok':         True,
                'text':       text,
                'model':      resp.get('model', model),
                'tokens_in':  usage.get('input_tokens', 0),
                'tokens_out': usage.get('output_tokens', 0),
            }
        except (KeyError, IndexError, TypeError):
            return {'ok': False, 'error': f'unexpected response shape: {str(resp)[:200]}'}
    err_msg = resp.get('error') if isinstance(resp, dict) else None
    if isinstance(err_msg, dict):
        err_msg = err_msg.get('message') or str(err_msg)
    return {'ok': False, 'error': f'HTTP {status}: {err_msg or "unknown"}'}


def chat(cfg, messages, system=None, max_tokens=None, model=None,
         temperature=None, top_p=None, num_ctx=None):
    """Dispatch to the right adapter. cfg is cfg['ai'] (already validated).

    `model` overrides cfg['model'] for this one request — used by the AI
    page's per-conversation model selector so a user can pick a different
    model without changing the global default.

    v3.0.1: per-call generation params:
      - temperature  (0.0 - 2.0)   - randomness; lower = more deterministic
      - top_p        (0.0 - 1.0)   - nucleus sampling
      - num_ctx      (int)         - context window override (Ollama/LocalAI only)
    None means "let the provider use its default" — we don't fabricate values.

    Returns: {ok: bool, text: str, model: str, tokens_in: int,
              tokens_out: int}  on success
             {ok: False, error: str}  on failure
    """
    if not cfg.get('enabled'):
        return {'ok': False, 'error': 'AI is disabled in settings'}
    provider = cfg.get('provider')
    if provider not in VALID_PROVIDERS:
        return {'ok': False, 'error': f'unknown provider {provider!r}'}
    max_tokens = max_tokens or cfg.get('limits', {}).get('max_tokens_per_response', 4000)
    max_tokens = max(1, min(int(max_tokens), 16000))
    # Caller-supplied model override applies for this request only.
    if model:
        cfg = dict(cfg)        # shallow copy — don't mutate the caller's dict
        cfg['model'] = model
    # Apply redaction before sending. Empty privacy dict = redact everything
    # by default (most conservative; operator opts in to send hostnames/IPs).
    privacy = cfg.get('privacy', {}) or {}
    safe_messages = redact_messages(messages, privacy)
    safe_system = redact(system, privacy) if system else system
    if provider == PROVIDER_ANTHROPIC:
        return chat_anthropic(cfg, safe_messages, safe_system, max_tokens,
                              temperature=temperature, top_p=top_p)
    else:
        return chat_openai_compatible(cfg, safe_messages, safe_system, max_tokens,
                                      temperature=temperature, top_p=top_p,
                                      num_ctx=num_ctx)


# ── Embeddings (v3.4.0: Level-3 RAG) ───────────────────────────────────────
#
# Only the OpenAI-compatible providers expose an embeddings endpoint.
# Anthropic has none (operators who want semantic search on an Anthropic
# deployment run a local Ollama embedding model alongside it). DeepSeek's
# API likewise has no /embeddings route today, so we treat it as
# unsupported rather than send a request that 404s. The RAG layer falls
# back to lexical-only retrieval whenever embeddings are unavailable, so
# this is a graceful degrade, not a hard failure.

EMBEDDING_PROVIDERS = (PROVIDER_OPENAI, PROVIDER_OLLAMA, PROVIDER_LOCALAI)

# Per-provider default embedding model. Operators override via
# cfg['rag']['embedding_model']. Ollama's nomic-embed-text is the most
# common locally-pulled embedding model; LocalAI mirrors the OpenAI name
# of whatever the operator has loaded.
DEFAULT_EMBED_MODELS = {
    PROVIDER_OPENAI:  'text-embedding-3-small',
    PROVIDER_OLLAMA:  'nomic-embed-text',
    PROVIDER_LOCALAI: 'text-embedding-ada-002',
}

# A single embed request is bounded so one reindex of a large fleet can't
# build a multi-megabyte POST body. api.py batches above this.
MAX_EMBED_INPUTS = 64
MAX_EMBED_INPUT_BYTES = 8 * 1024


def embedding_cfg(cfg):
    """Resolve the *effective* provider config used for embeddings.

    By default embeddings reuse the chat provider verbatim, but operators can
    point them at a different service (issue #11) — e.g. chat on one LocalAI box
    and embeddings on a separate, less-contested GPU box — via the optional
    rag.embedding_{provider,base_url,api_key} overrides. Returns a synthetic
    provider cfg suitable for embed() / embedding_fingerprint() / supports_
    embeddings().

    Inherit rules (intentionally conservative — never replay the chat key to a
    different endpoint):
      * no overrides set            → return `cfg` unchanged (back-compat).
      * embedding_base_url set       → use it; key only from embedding_api_key.
      * embedding_provider == chat   → inherit chat base_url + api_key unless a
        per-embedding value is given.
      * different embedding_provider → use provider default endpoint; key only
        from embedding_api_key.
    """
    rag = cfg.get('rag') or {}
    eprov = (rag.get('embedding_provider') or '').strip()
    ebase = (rag.get('embedding_base_url') or '').strip()
    ekey  = rag.get('embedding_api_key') or ''
    if not eprov and not ebase and not ekey:
        return cfg
    prov = eprov or cfg.get('provider')
    out = {
        'provider':     prov,
        'privacy':      cfg.get('privacy', {}),
        'insecure_ssl': cfg.get('insecure_ssl'),
        'rag':          {'embedding_model': rag.get('embedding_model', '')},
    }
    same_provider = (prov == cfg.get('provider'))
    if ebase:
        out['base_url'] = ebase
    elif same_provider:
        out['base_url'] = cfg.get('base_url') or ''
    if ekey:
        out['api_key'] = ekey
    elif same_provider and not ebase:
        out['api_key'] = cfg.get('api_key', '')
    return out


def supports_embeddings(cfg):
    """True if the effective embedding provider can produce embeddings.
    Resolves the rag.embedding_provider override (issue #11), so semantic
    search can be available even when the *chat* provider has no embeddings
    endpoint (e.g. Anthropic chat + LocalAI embeddings)."""
    return embedding_cfg(cfg).get('provider') in EMBEDDING_PROVIDERS


def embedding_fingerprint(cfg):
    """Identity of the embedding space the current config produces vectors in:
    provider + base URL + model. When any of these changes, cached vectors are
    from a different (possibly different-dimension) space and must not be
    reused. Resolves the embedding-service override, so re-pointing embeddings
    at a different endpoint/model correctly invalidates the cache. Resolution
    mirrors embed(). Empty when the provider can't embed."""
    ecfg = embedding_cfg(cfg)
    provider = ecfg.get('provider')
    if provider not in EMBEDDING_PROVIDERS:
        return ''
    base = (ecfg.get('base_url') or DEFAULT_BASE_URLS.get(provider, '')).rstrip('/')
    mdl = (ecfg.get('rag') or {}).get('embedding_model') or DEFAULT_EMBED_MODELS.get(provider, '')
    return f'{provider}|{base}|{mdl}'


def embed(cfg, texts, model=None):
    """Embed a list of strings via the configured provider's OpenAI-compatible
    /embeddings endpoint.

    Returns {ok: True, vectors: [[float,...], ...], model, dim} on success —
    `vectors` is aligned 1:1 with `texts`. On failure or for a provider with
    no embeddings endpoint, returns {ok: False, error}.

    Note: embeddings carry the *content* of indexed chunks to the provider.
    For cloud providers that is real data egress, which is why api.py gates
    embedding generation behind an explicit, off-by-default-for-cloud toggle.
    Redaction is applied here too, defence-in-depth, so a chunk that slipped
    past index-time redaction still gets scrubbed before egress.
    """
    # Resolve the embedding service (may differ from the chat provider — #11).
    ecfg = embedding_cfg(cfg)
    provider = ecfg.get('provider')
    if provider not in EMBEDDING_PROVIDERS:
        return {'ok': False, 'error': f'{provider} has no embeddings endpoint'}
    if not isinstance(texts, list) or not texts:
        return {'ok': False, 'error': 'texts must be a non-empty list'}
    if len(texts) > MAX_EMBED_INPUTS:
        return {'ok': False, 'error': f'too many inputs (max {MAX_EMBED_INPUTS})'}

    privacy = ecfg.get('privacy', {}) or {}
    safe = [redact(str(t), privacy)[:MAX_EMBED_INPUT_BYTES] for t in texts]

    base = (ecfg.get('base_url') or DEFAULT_BASE_URLS[provider]).rstrip('/')
    mdl = model or (ecfg.get('rag') or {}).get('embedding_model') \
        or DEFAULT_EMBED_MODELS[provider]
    url = f'{base}/embeddings'
    headers = {}
    if ecfg.get('api_key'):
        headers['Authorization'] = f"Bearer {ecfg['api_key']}"
    status, resp = _http_post_json(url, headers, {'model': mdl, 'input': safe},
                                   insecure_ssl=bool(ecfg.get('insecure_ssl')))
    if status == 200 and isinstance(resp, dict):
        try:
            # OpenAI returns data out of order in theory; sort by index.
            rows = sorted(resp['data'], key=lambda d: d.get('index', 0))
            vectors = [r['embedding'] for r in rows]
            if len(vectors) != len(texts):
                return {'ok': False, 'error': 'embedding count mismatch'}
            return {'ok': True, 'vectors': vectors,
                    'model': resp.get('model', mdl),
                    'dim': len(vectors[0]) if vectors and vectors[0] else 0}
        except (KeyError, IndexError, TypeError):
            return {'ok': False, 'error': f'unexpected response shape: {str(resp)[:200]}'}
    err_msg = resp.get('error') if isinstance(resp, dict) else None
    if isinstance(err_msg, dict):
        err_msg = err_msg.get('message') or str(err_msg)
    return {'ok': False, 'error': f'HTTP {status}: {err_msg or "unknown"}'}


# ── Provider introspection (v2.1.4 follow-up to v2.1.3 AI launch) ──────────
#
# Used by the AI page (custom chat) to populate a model picker and surface
# basic operational state. Ollama has rich introspection (/api/tags,
# /api/ps, /api/version); LocalAI / OpenAI / DeepSeek speak the
# OpenAI-compat /v1/models endpoint; Anthropic ships a hardcoded list.

def _http_get_json(url, headers=None, timeout=10, insecure_ssl=False):
    """GET + parse JSON. Same error shape as _http_post_json. Short
    timeout — if /api/tags hangs, the provider has bigger problems.

    v3.0.4: matching insecure_ssl param so callers can opt out of
    cert verification on self-signed LAN endpoints. Default False
    (strict) — opt-in only.
    """
    req = urllib.request.Request(url, method='GET')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    if insecure_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        # v4.8.0 (SSRF): refuse 3xx redirects (matches _http_post_json) so a
        # provider base_url that passed the set-time preflight can't 302 us to
        # loopback / cloud-metadata and replay the Authorization header there.
        # v5.x: also recheck the peer IP at connect (DNS-rebinding window).
        opener = _ssrf_opener(ctx, allow_loopback=insecure_ssl)
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read(64 * 1024))
        except Exception:
            body = {'error': str(e)}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {'error': f'URLError: {e.reason}'}
    except Exception as e:
        return 0, {'error': f'{type(e).__name__}: {e}'}


# Hardcoded model fallback for cloud providers. The Anthropic list is
# authoritative since they don't expose /v1/models; the others fall
# back here only when the live fetch fails. Operators can always type
# a custom model name into the Settings page.
CLOUD_MODELS = {
    PROVIDER_ANTHROPIC: [
        'claude-opus-4-5',
        'claude-sonnet-4-5',
        'claude-haiku-4-5',
        'claude-3-5-sonnet-latest',
        'claude-3-5-haiku-latest',
        'claude-3-opus-latest',
    ],
    PROVIDER_OPENAI: [
        'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo',
        'o1', 'o1-mini',
    ],
    PROVIDER_DEEPSEEK: [
        'deepseek-chat', 'deepseek-reasoner',
    ],
}


def _ollama_root(cfg):
    """Ollama's /api/* endpoints live at the root, not under /v1/. Strip
    a trailing /v1 if the operator pasted the OpenAI-compat URL."""
    base = (cfg.get('base_url') or DEFAULT_BASE_URLS[PROVIDER_OLLAMA]).rstrip('/')
    if base.endswith('/v1'):
        base = base[:-3]
    return base


def list_models(cfg):
    """Return {ok, models: [{name, size_bytes?, ...}, ...]} for the
    configured provider. Extra fields are best-effort."""
    if not cfg.get('enabled'):
        return {'ok': False, 'error': 'AI is disabled'}
    provider = cfg.get('provider')
    if provider == PROVIDER_OLLAMA:
        status, resp = _http_get_json(f'{_ollama_root(cfg)}/api/tags')
        if status == 200 and isinstance(resp, dict):
            out = []
            for m in resp.get('models', []) or []:
                details = m.get('details') or {}
                out.append({
                    'name':       m.get('name', ''),
                    'size_bytes': m.get('size', 0),
                    'modified':   m.get('modified_at', ''),
                    'family':     details.get('family', ''),
                    'param_size': details.get('parameter_size', ''),
                })
            return {'ok': True, 'models': out}
        return {'ok': False, 'error': f'HTTP {status}: {resp.get("error", "?")}'}
    if provider in (PROVIDER_LOCALAI, PROVIDER_OPENAI, PROVIDER_DEEPSEEK):
        base = (cfg.get('base_url') or DEFAULT_BASE_URLS[provider]).rstrip('/')
        headers = {}
        if cfg.get('api_key'):
            headers['Authorization'] = f"Bearer {cfg['api_key']}"
        status, resp = _http_get_json(f'{base}/models', headers=headers)
        if status == 200 and isinstance(resp, dict):
            out = [{'name': m.get('id', ''),
                    'modified': m.get('created', '')}
                   for m in (resp.get('data') or []) if m.get('id')]
            return {'ok': True, 'models': out}
        # Live fetch failed — fall back to hardcoded list so the UI still
        # has something to show. Surface the live error as 'note'.
        if provider in CLOUD_MODELS:
            return {'ok': True,
                    'models': [{'name': m} for m in CLOUD_MODELS[provider]],
                    'note': f'live fetch failed ({resp.get("error", status)}); '
                            f'showing fallback list'}
        return {'ok': False, 'error': f'HTTP {status}: {resp.get("error", "?")}'}
    if provider == PROVIDER_ANTHROPIC:
        return {'ok': True, 'models': [{'name': m} for m in CLOUD_MODELS[provider]]}
    return {'ok': False, 'error': f'unknown provider {provider!r}'}


def provider_stats(cfg):
    """Return {ok, provider, version?, loaded_models?, reachable, ...}.
    Used by the AI page's status header."""
    if not cfg.get('enabled'):
        return {'ok': False, 'error': 'AI is disabled'}
    provider = cfg.get('provider')
    out = {
        'ok':       True,
        'provider': provider,
        'base_url': cfg.get('base_url') or DEFAULT_BASE_URLS.get(provider, ''),
        'model':    cfg.get('model') or DEFAULT_MODELS.get(provider, ''),
        'local':    provider in (PROVIDER_OLLAMA, PROVIDER_LOCALAI),
    }
    if provider == PROVIDER_OLLAMA:
        root = _ollama_root(cfg)
        status, ver = _http_get_json(f'{root}/api/version', timeout=5)
        if status == 200 and isinstance(ver, dict):
            out['version'] = ver.get('version', '?')
        status, ps = _http_get_json(f'{root}/api/ps', timeout=5)
        if status == 200 and isinstance(ps, dict):
            loaded = []
            for m in ps.get('models', []) or []:
                vram_mb = round((m.get('size_vram') or 0) / (1024 * 1024))
                loaded.append({
                    'name':       m.get('name', ''),
                    'vram_mb':    vram_mb,
                    'expires_at': m.get('expires_at', ''),
                })
            out['loaded_models'] = loaded
        out['reachable'] = 'version' in out or 'loaded_models' in out
    elif provider == PROVIDER_LOCALAI:
        base = (cfg.get('base_url') or DEFAULT_BASE_URLS[provider]).rstrip('/')
        status, _ = _http_get_json(f'{base}/models', timeout=5)
        out['reachable'] = (status == 200)
    else:
        # Cloud providers: liveness == "API key configured". A real
        # round-trip costs tokens, the Test Connection button is the
        # right place for that.
        out['reachable'] = bool(cfg.get('api_key'))
    return out


# ── System prompts for the inline buttons ──────────────────────────────────
#
# Centralised so the wording can evolve without poking around in api.py.
# Each one is short and operator-flavoured: ask for explanation, not
# hand-holding; ask for a one-paragraph answer, not a tutorial.

SYSTEM_PROMPTS = {
    'free_form': (
        "You are a Linux operations assistant for a DevOps engineer. "
        "Be concise, accurate, and avoid filler. The user is operating a "
        "fleet of Linux servers via a self-hosted management tool. "
        "Default to short, direct answers; expand only when asked."
    ),
    'explain_output': (
        "You are a Linux operations assistant for a DevOps engineer. "
        "Given the output of a shell command, explain in 1–3 short "
        "paragraphs what the command did and what the output means. "
        "Call out anything anomalous or worth investigating. Use plain "
        "language. Don't pad with reminders or disclaimers."
    ),
    'find_problem': (
        "You are a Linux operations assistant. Given a slice of journald / "
        "log output, identify the actual problem (if any), state it in "
        "one sentence, then list 2–4 things to check next. If there's no "
        "problem, say so plainly."
    ),
    'explain_script': (
        "You are a Linux operations assistant. Given a bash script, "
        "explain what it does step by step, then identify any "
        "side-effects, missing safety nets (set -euo pipefail, error "
        "handling), or assumptions about the target environment."
    ),
    'audit_script': (
        "You are a security-focused Linux operations assistant. Audit "
        "the provided bash script for: destructive commands without "
        "confirmation, command injection vectors, missing input "
        "validation, race conditions, secrets in plaintext, overly broad "
        "permissions, and supply-chain risks (curl|bash, etc.). Return "
        "a numbered list of findings ordered by severity. Be specific: "
        "quote the line and explain the risk. If the script is clean, "
        "say so."
    ),
    'generate_script': (
        "You are a Linux operations assistant. Generate a single bash "
        "script that does what the user asks. Start with "
        "#!/usr/bin/env bash and set -euo pipefail. Add brief comments "
        "for non-obvious steps. Don't include backticks, markdown "
        "fences, or any non-script text — output the script and only "
        "the script. The script will be reviewed and dry-run before "
        "execution."
    ),
    'triage_cve': (
        "You are a security operations assistant. Given a CVE and the "
        "context of a single host that has the affected package, "
        "assess: (1) actual exposure given the host's role and "
        "exposed services, (2) priority (low / medium / high / "
        "critical), (3) recommended action. Keep it under 6 short "
        "lines. No filler."
    ),
    'investigate_device': (
        "You are a Linux operations assistant. Given a snapshot of a "
        "device's recent state (metrics, journal tail, recent "
        "commands), identify anything anomalous and what to check "
        "next. 3–5 short bullet points. If nothing's wrong, say so."
    ),
    'explain_alert': (
        "You are a Linux operations assistant. Given a webhook alert "
        "payload (event type, device, raw details), rewrite it as a "
        "single short paragraph an on-call engineer can understand in "
        "5 seconds. Include severity assessment."
    ),
    'routeros_firewall_rule': (
        "You translate a plain-English request into ONE MikroTik RouterOS "
        "firewall-filter rule. Output ONLY a single JSON object — no prose, "
        "no markdown fences. Allowed keys: chain, action, src-address, "
        "dst-address, protocol, dst-port, src-port, in-interface, "
        "out-interface, connection-state, comment. `chain` and `action` are "
        "required (chain is usually input/forward/output; action is usually "
        "accept/drop/reject). Add a short `comment`. Do NOT set `disabled` — "
        "the rule is created disabled for human review. If the request is "
        "ambiguous or dangerous, still return your best single rule and note "
        "the assumption in the comment."
    ),
    'routeros_firewall_explain': (
        "You are a network-security assistant. Given a MikroTik RouterOS "
        "firewall ruleset (filter/NAT rules in order), explain in plain "
        "language what it does, the overall posture (default-drop vs "
        "default-accept), and flag anything risky — accept-all rules, "
        "management services exposed to WAN, rules shadowed by earlier ones, "
        "or disabled rules that look load-bearing. Be concise and ordered by "
        "importance."
    ),
    'investigate_alert': (
        "You are a Linux operations assistant helping an on-call "
        "engineer triage a single monitoring alert. Given the alert's "
        "severity, event type, affected device, timestamp, and raw "
        "details, respond with: (1) one sentence on what the alert "
        "means, (2) the most likely cause, (3) 2-4 concrete next "
        "steps or commands to verify and resolve it. Prefer real "
        "commands (systemctl, journalctl, dig, ss, df, etc.) over "
        "generic advice. Be specific and actionable. No filler, no "
        "disclaimers."
    ),
    # v2.1.5: new surfaces.
    'diagnose_service': (
        "You are a Linux operations assistant. Given a systemd service "
        "in a failed or degraded state, plus a tail of its journal, "
        "identify the most likely cause in one sentence, list 2-4 "
        "concrete commands to verify the diagnosis, and recommend a "
        "fix. Be specific about systemctl / journalctl / config-file "
        "actions. Don't hand-wave."
    ),
    'explain_tls': (
        "You are an operations assistant focused on TLS / certificate "
        "lifecycle. Given a certificate's expiry date, issuer, and "
        "host context, assess: (1) urgency given current time, (2) the "
        "renewal path most likely to apply (certbot / acme.sh / "
        "manual / vendor-managed), and (3) any DNS / DANE / TLSA "
        "considerations that might break on renewal. Keep it under 6 "
        "short lines. No filler."
    ),
    'prioritise_patches': (
        "You are a Linux operations assistant. Given a list of pending "
        "package updates for a host, identify which ones are likely "
        "security-relevant vs routine (based on package names — "
        "kernel / openssh / openssl / sudo / glibc are typically "
        "security-relevant). Recommend an order to apply them in, "
        "noting which need a reboot. Keep it short."
    ),
    'prioritise_cves': (
        "You are a security operations assistant. Given a list of CVE "
        "findings for a single host (severity, CVE id, affected package, "
        "installed version, and fixed version when known), produce a "
        "short ranked remediation plan: which to fix first and why — "
        "weigh severity, whether a fix is actually available, and likely "
        "exposure. Group findings that a single package upgrade clears, "
        "and flag any that need a reboot. A ranked list, no filler."
    ),
    'explain_container_logs': (
        "You are an operations assistant. Given a container's recent "
        "logs (typically Docker or Podman), identify what the "
        "container is doing, whether it's healthy, and any errors or "
        "warnings worth investigating. Don't speculate about overall "
        "system architecture from logs alone."
    ),
    # v2.1.7→v2.1.9: device runbook generation. Long-form, structured.
    # v2.1.9 rewrite — the v2.1.7 prompt had 8 verbose sections and an
    # implicit "follow this format" assumption. Large frontier models
    # followed it; smaller coder-tuned models (qwen2.5-coder:14b,
    # codestral, deepseek-coder) ignored the structure and just
    # summarised whatever JSON they could see, often inventing details
    # to pad the gaps. New approach: shorter prompt, fewer sections,
    # explicit "use only the snapshot" rule, and tell the model what
    # to do when data is missing instead of letting it improvise.
    'generate_runbook': (
        "Write a brief operations runbook for the Linux server "
        "described in the snapshot below.\n"
        "\n"
        "CRITICAL RULES:\n"
        "- Use ONLY information from the snapshot. Do NOT invent "
        "services, ports, firewall rules, DNS configurations, or "
        "anything else not explicitly present in the data.\n"
        "- If a section has no relevant data in the snapshot, write "
        "\"No data captured.\" Do not fabricate.\n"
        "- Do not summarise the snapshot structure. Write a runbook "
        "for an operator, not a description of the JSON.\n"
        "- Keep the whole document under 800 words. Plain Markdown, "
        "no HTML, no front matter.\n"
        "\n"
        "Use exactly this structure:\n"
        "\n"
        "## Purpose\n"
        "One short paragraph: what this host is, based on its name, "
        "OS, group, tags, notes, and watched services. Be specific "
        "(\"mail server running Postfix\") if the evidence supports "
        "it; say \"role unclear\" if it doesn't. Do not guess from "
        "the hostname alone.\n"
        "\n"
        "## Current state\n"
        "Online/offline status, agent version, OS version, uptime "
        "if shown. Skip any field that isn't in the snapshot.\n"
        "\n"
        "## Watched services\n"
        "List the watched systemd units from the snapshot's "
        "`services` field and their current state. If none, write "
        "\"No services watched.\"\n"
        "\n"
        "## Containers\n"
        "List containers from the snapshot's `containers` field "
        "with name, image, and state. If empty, write \"No "
        "containers reported.\"\n"
        "\n"
        "## Recent activity\n"
        "Up to 5 bullets summarising the snapshot's recent_commands "
        "and recent_journal. If both are empty, write \"No recent "
        "activity in snapshot.\"\n"
        "\n"
        "## Health & risks\n"
        "Summarise cve_findings (count, highest severity, any "
        "fixed-version available) and patch_status. If "
        "cve_findings is empty and patch_status looks clean, write "
        "\"No risks flagged in this snapshot.\" Do not invent CVEs.\n"
        "\n"
        "## Operating notes\n"
        "Practical hints grounded in the snapshot. Examples: \"to "
        "restart nginx, run systemctl restart nginx\" (only if "
        "nginx is in the watched services list). Skip notes that "
        "would require knowledge you don't have."
    ),
    # v3.0.0: IaC Generator
    'iac_generate': (
        "You are a code generator that outputs Infrastructure-as-Code "
        "as raw text. You NEVER use markdown, NEVER add preamble or "
        "explanations, and NEVER wrap output in ``` fences. Your entire "
        "response goes between <<<BEGIN_IAC>>> and <<<END_IAC>>> markers "
        "and consists of valid syntactically-correct code that can be "
        "saved directly to a file."
    ),
    # v3.0.1: Mitigation prompts. Each is paired with diagnostic output and
    # asked to suggest ONE concrete fix command, wrapped in BEGIN_FIX /
    # END_FIX markers so the server can extract it deterministically.
    'mitigate_cpu': (
        "You are a Linux performance engineer triaging a CPU pressure alert. "
        "You will be shown `top` + `ps` output. Identify the single dominant "
        "consumer and propose ONE specific command that would lower load — "
        "could be `systemctl restart <unit>`, `renice +10 -p <pid>`, "
        "`kill <pid>` for runaway processes, or NONE if the load looks "
        "legitimate. Never propose `kill -9` without naming the specific PID "
        "and explaining the risk. Wrap the proposed command between BEGIN_FIX "
        "and END_FIX on their own lines."
    ),
    'mitigate_memory': (
        "You are a Linux performance engineer triaging memory pressure. "
        "You will be shown `free`, top-by-mem, and `/proc/meminfo`. Identify "
        "whether this is a memory leak, cache pressure (mostly fine), or a "
        "legitimate working set. Propose ONE fix: restart a leaking service, "
        "drop caches via `sync && echo 3 > /proc/sys/vm/drop_caches` (only if "
        "you can justify it), or NONE if no action helps. Wrap the proposed "
        "command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_disk': (
        "You are a Linux storage engineer triaging a disk-pressure alert. "
        "You will be shown `df`, `du` of the largest directories, and the "
        "biggest files. Identify whether the pressure is logs, package "
        "caches, app data, or genuine growth. Propose ONE specific cleanup "
        "command — `journalctl --vacuum-time=7d`, `apt clean`, deleting a "
        "specific path, etc. Never propose `rm -rf` on user data without "
        "explicit naming and a warning. Wrap the proposed command between "
        "BEGIN_FIX and END_FIX."
    ),
    'mitigate_service': (
        "You are a Linux SRE triaging a failing service. You will be shown "
        "`systemctl status` and the last 100 journal lines. Identify the "
        "root cause in ONE sentence (config error, dependency, port "
        "conflict, OOM kill, etc.) then propose ONE specific shell command "
        "to address it. Prefer reversible actions (`systemctl restart`) "
        "over irreversible ones. If the cause is a config file error, the "
        "fix command might be a `vi` invocation — that's fine, the user "
        "will run it interactively. Wrap the proposed command between "
        "BEGIN_FIX and END_FIX."
    ),
    'mitigate_failed_units': (
        "You are a Linux SRE triaging failed systemd units. You will be shown "
        "`systemctl --failed` and, for each failed unit, its status and recent "
        "journal lines. Identify in ONE sentence the most likely root cause of "
        "the PRIMARY failure (config error, missing dependency, port conflict, "
        "OOM kill, missing binary/file, etc.). Propose ONE specific shell "
        "command to address it — prefer reversible actions (`systemctl restart "
        "<unit>`, `systemctl reset-failed <unit>`) and target the specific unit "
        "by name; never restart everything blindly. If the cause is a config "
        "error, a `vi`/`journalctl` invocation is fine (the user runs it "
        "interactively). Wrap the proposed command between BEGIN_FIX and "
        "END_FIX."
    ),
    'mitigate_patches': (
        "You are a Linux SRE triaging pending package updates. You will be "
        "shown the upgradable list and reboot-required state. Briefly assess "
        "the risk and urgency. Propose ONE command — typically the system "
        "upgrade itself — or NONE if you'd recommend deferring. If reboot "
        "is required after upgrade, mention it but DO NOT include `reboot` "
        "in the fix command (RemotePower has a separate reboot flow). Wrap "
        "the proposed command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_cve': (
        "You are a Linux security engineer triaging outstanding CVE findings. "
        "You will be shown the OS, the pending security updates, and the "
        "kernel version. Identify in ONE sentence whether the exposure is "
        "closable by available updates. Propose ONE command — typically the "
        "package-manager security upgrade (e.g. `apt-get -y upgrade`, "
        "`dnf -y --security upgrade`) — or NONE if no fix is available yet. "
        "If a reboot is needed (kernel update), mention it but DO NOT put "
        "`reboot` in the fix (RemotePower has a separate reboot flow). Wrap "
        "the proposed command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_container': (
        "You are a container/SRE engineer triaging a stopped or restarting "
        "container. You will be shown the container list and, for non-running "
        "ones, their exit code, restart count, OOM flag, and recent logs. "
        "Identify the most likely cause in ONE sentence (crash loop, OOM, bad "
        "config/image, dependency). Propose ONE specific command — usually "
        "`docker restart <name>` / `podman restart <name>`, or a logs/inspect "
        "command if more data is needed — or NONE if manual judgement is "
        "required. Be conservative; do not propose removing data volumes. Wrap "
        "the proposed command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_av': (
        "You are a Linux security engineer triaging an endpoint AV/malware "
        "alert. You will be shown ClamAV signature-DB age + version and recent "
        "rkhunter warnings. Decide in ONE sentence whether this is a stale "
        "signature database (update needed), benign rkhunter noise (common "
        "false positives — package updates changing file hashes), or a genuine "
        "indicator that warrants investigation. Propose ONE command — typically "
        "`freshclam` to refresh signatures, or `rkhunter --propupd` after "
        "verifying changes are legitimate — or NONE if a human must inspect the "
        "warnings first. Never propose deleting files. Wrap the proposed command "
        "between BEGIN_FIX and END_FIX."
    ),
    'mitigate_agent_version': (
        "You are an SRE triaging a RemotePower agent that is older than the "
        "server. You will be shown the running agent version and its service "
        "status. State in ONE sentence whether an update is safe to apply now. "
        "The agent updates through RemotePower's own update flow (device drawer "
        "-> Update agent), so DO NOT propose a manual download/install command — "
        "recommend the update action instead, or NONE if the service looks "
        "unhealthy and needs inspection first. Wrap any proposed diagnostic "
        "command between BEGIN_FIX and END_FIX (or omit the fix block)."
    ),
    'mitigate_os_eol': (
        "You are a Linux platform engineer triaging a host on an end-of-life OS. "
        "You will be shown /etc/os-release, the kernel, and any available "
        "release-upgrade path. State in ONE sentence the EOL exposure and the "
        "target release to move to. Propose ONE command to BEGIN the upgrade "
        "where it's safe and non-interactive (e.g. `do-release-upgrade`), or "
        "NONE if it needs a planned maintenance window / manual steps. Never "
        "propose an unattended in-place major upgrade on a production box without "
        "calling out the risk. Wrap the command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_hardware': (
        "You are a hardware/storage engineer triaging a SMART or kernel hardware "
        "alert. You will be shown per-disk SMART health + attributes, disk/IO "
        "errors from dmesg, and the block-device list. Identify in ONE sentence "
        "which device is failing and the key indicator (reallocated/pending "
        "sectors, CRC errors, NVMe wear, medium errors). Recommend the action "
        "(plan a replacement, back up now, run an extended self-test). Propose at "
        "most ONE diagnostic command (e.g. `smartctl -t long /dev/sdX`) — never a "
        "destructive one. Wrap it between BEGIN_FIX and END_FIX, or omit it."
    ),
    'mitigate_backup': (
        "You are an SRE triaging a stale or missing backup. You will be shown "
        "free disk space, recent backup files, backup cron jobs/timers, and "
        "whether restic/borg are present. Identify the most likely reason the "
        "backup didn't run or is stale (full disk, failed/disabled timer, tool "
        "missing, wrong path). Propose ONE command to investigate or re-run the "
        "backup (e.g. run the backup timer/unit, or the backup command) — or "
        "NONE if manual judgement is needed. Never propose deleting existing "
        "backups. Wrap the command between BEGIN_FIX and END_FIX."
    ),
    'mitigate_ssh_key': (
        "You are a security engineer triaging a newly-added SSH authorized key. "
        "You will be shown the authorized_keys files, recent logins, and "
        "accepted-publickey auth-log lines. Assess in ONE sentence whether the "
        "new key looks legitimate (matches an expected admin/automation) or "
        "suspicious (unknown comment, unexpected user, odd login source). If "
        "suspicious, recommend removing it and rotating — but DO NOT propose a "
        "blind delete command without naming the exact key/line, since a wrong "
        "removal can lock out admins. Wrap any command between BEGIN_FIX and "
        "END_FIX, or omit it and advise manual review."
    ),
    'mitigate_new_port': (
        "You are a security engineer triaging a newly-opened listening port. You "
        "will be shown listening sockets with their owning process and the top "
        "processes. Identify in ONE sentence what is listening and whether it's "
        "expected (a known service) or suspicious (unexpected binary, high port, "
        "bound to 0.0.0.0). If suspicious, recommend investigating the process "
        "before killing it. Propose at most ONE non-destructive command (e.g. "
        "`ls -l /proc/<pid>/exe`, `systemctl status <unit>`). Wrap it between "
        "BEGIN_FIX and END_FIX, or omit it."
    ),
    'mitigate_agent_integrity': (
        "You are an SRE/security engineer triaging a RemotePower agent whose "
        "binary hash does not match the published build (possible tamper, "
        "corruption, or partial update). You will be shown the agent binary "
        "listing/hash and its service status. State in ONE sentence the most "
        "likely cause. The safe remedy is to re-install the canonical signed "
        "build via RemotePower's update flow — recommend that rather than a "
        "manual download. If tamper is plausible, advise isolating the host "
        "(quarantine) first. Wrap any diagnostic command between BEGIN_FIX and "
        "END_FIX, or omit it."
    ),
    'mitigate_log': (
        "You are a Linux SRE triaging a log-pattern alert. You will be shown "
        "recent error-level journal entries and any failed systemd units. "
        "Identify the most likely underlying problem in ONE sentence. Propose "
        "ONE command to investigate or remediate (e.g. `systemctl restart "
        "<unit>`, or a focused `journalctl -u <unit>` to dig deeper) — or NONE "
        "if the log noise is benign. Prefer reversible actions. Wrap the command "
        "between BEGIN_FIX and END_FIX."
    ),

    # ── v4.10.0: 20 new AI features ──────────────────────────────────────────
    # Proactive / scheduled
    'ai_briefing': (
        "You are RemotePower's fleet briefing assistant. Using the attached "
        "fleet context and retrieved state, write a concise daily operations "
        "briefing: (1) what needs attention now — open critical/high alerts, "
        "hosts offline, KEV-listed CVEs; (2) what changed recently — new "
        "alerts, newly-resolved, fresh config drift, backups gone stale; "
        "(3) a one-line fleet-health verdict. Group by severity, lead with the "
        "most urgent, scannable bullets, no preamble. If the fleet is healthy, "
        "say so in one line."
    ),
    'log_anomaly': (
        "You are a Linux log-analysis assistant. Given recent journal output "
        "across watched units, identify what is abnormal or new: error/warning "
        "spikes, novel message patterns, repeated failures, signs of an "
        "incident. Cluster related lines; ignore routine noise. Output 3–6 "
        "bullets, each naming the unit/host and the concern. If nothing "
        "notable, say so."
    ),
    'alert_tuning': (
        "You are an alerting-hygiene advisor. Given recent alert history, "
        "resolution stats (MTTR/MTTA) and mute patterns, recommend concrete "
        "noise-reduction changes: thresholds to raise, events to mute on "
        "specific hosts, dependency links to add so a downstream alert is "
        "suppressed when its parent is down. For each, give the host/event and "
        "the specific change. Prioritise the noisiest signals. Be specific, "
        "not generic."
    ),
    'predict_maintenance': (
        "You are a hardware-reliability advisor. Given SMART attributes/trends, "
        "disk restart frequency and SSD/NVMe endurance across the fleet, "
        "identify hardware likely to fail and a rough timeframe. Cite the "
        "specific signal (rising reallocated/pending sectors, CRC errors, "
        "endurance %, power-on hours). Recommend replace/monitor per device. "
        "Only flag genuine risk; if nothing is degrading, say so."
    ),
    # Incident reasoning
    'incident_rca': (
        "You are an incident-analysis assistant. Given a correlated incident — "
        "a root-cause event and its symptom alerts — plus the affected hosts' "
        "recent state, write a brief root-cause analysis: what happened, the "
        "likely cause, the order/timeline of events, the blast radius (which "
        "hosts/services), and the recommended fix and follow-ups. Distinguish "
        "root cause from symptoms. A few short paragraphs."
    ),
    'alert_group': (
        "You are an alert-correlation assistant. Given the current open alerts "
        "across the fleet, group them into likely-distinct incidents (alerts "
        "sharing a root cause, host or service). For each group: a one-line "
        "incident title, the member alerts, and the most probable common "
        "cause. List truly-independent alerts separately. Short grouped list."
    ),
    'change_risk': (
        "You are a change-safety reviewer. Given a command or script about to "
        "run on a host (and the host's role/state), assess the risk BEFORE it "
        "runs: could it disconnect you (firewall/SSH/network changes), restart "
        "or stop critical services, cause data loss, or affect production? "
        "State a risk level (low/medium/high), the specific hazard, and a safer "
        "alternative or precaution. If clearly safe, say low risk in one line. "
        "Do not refuse — assess."
    ),
    # Natural-language → config (output strict JSON / IaC markers)
    'nl_fleet_query': (
        "You translate a plain-English fleet question into a structured filter "
        "over RemotePower's fleet dimensions. Output ONLY a JSON object — no "
        "prose, no fences. Shape: {\"description\": \"<restated query>\", "
        "\"filters\": [{\"field\": \"<dimension>\", \"op\": "
        "\"gt|lt|eq|contains|is\", \"value\": <v>}]}. Fields include: os, "
        "group, tag, online, cpu_pct, mem_pct, disk_pct, upgradable, "
        "reboot_required, drift, cve_high, exposed_world, last_seen_days. "
        "Combine with implicit AND. If a concept doesn't map to a field, put it "
        "in description and omit the filter."
    ),
    'nl_monitor': (
        "You translate a plain-English monitoring request into RemotePower "
        "monitor/check definitions. Output ONLY a JSON object — no prose, no "
        "fences. Shape: {\"monitors\": [{\"type\": \"icmp|tcp|http|dns\", "
        "\"target\": \"<host/url>\", \"label\": \"...\"}], \"checks\": "
        "[{\"type\": \"process|port\", \"value\": \"...\", \"label\": "
        "\"...\"}], \"notes\": \"<assumptions>\"}. Pick the simplest type that "
        "satisfies the intent. If a port/url/host is implied but not given, "
        "state the assumption in notes. Omit empty arrays."
    ),
    'reverse_iac': (
        "You are an infrastructure-as-code generator. Given a host's current "
        "live state (packages, services, users/keys, firewall, config), produce "
        "an idempotent Ansible role (tasks/main.yml) that would reproduce it on "
        "a fresh host. Use standard modules (apt/dnf, service, user, "
        "ufw/iptables, copy/template). Emit ONLY the YAML between "
        "<<<BEGIN_IAC>>> and <<<END_IAC>>> markers. Note anything you couldn't "
        "faithfully reproduce as a YAML comment."
    ),
    # Planning & remediation
    'cve_patch_plan': (
        "You are a vulnerability-remediation planner. Given the fleet's CVE "
        "findings (with KEV/EPSS ranking and fixed-version hints), pending "
        "patches and maintenance windows, produce a staged remediation plan: "
        "order work by real-world risk (KEV first, then high EPSS/CVSS), group "
        "fixes by host/package, and propose a canary → pilot → broad rollout "
        "with which hosts in each wave. Note any CVE with no fix. Name CVEs, "
        "packages and hosts."
    ),
    'compliance_plan': (
        "You are a compliance-remediation planner. Given a framework's failing "
        "controls across the fleet, produce a fleet-wide remediation plan: the "
        "distinct changes needed, each with the controls it satisfies, the "
        "hosts affected, an effort/impact estimate, and — where possible — the "
        "concrete fix (a host-config setting or a shell command). Order by "
        "impact-per-effort. Group changes that can be applied together."
    ),
    'capacity_forecast': (
        "You are a capacity-planning advisor. Given resource trends over time "
        "(CPU, memory, disk per mount, growth rates) and power/energy data, "
        "write a forward-looking capacity narrative: which hosts will hit "
        "limits and roughly when (disk-full dates, memory-pressure trend), "
        "what's growing fastest, and a recommendation (resize, add storage, "
        "rebalance). Cite the trend behind each call. Flag only real concerns."
    ),
    'dr_readiness': (
        "You are a backup and disaster-recovery advisor. Given the fleet's "
        "backup freshness (watched paths, age, stale flags), schedules and VM "
        "snapshot recency, assess DR readiness: which hosts/paths are "
        "unprotected or stale, which jobs look broken, and the gaps that would "
        "hurt in a recovery. Give a short readiness verdict and a prioritised "
        "list of fixes."
    ),
    # Domain advisors
    'firewall_audit': (
        "You are a firewall-hardening reviewer. Given a host's firewall "
        "ruleset (nftables/iptables/ufw/firewalld) and its exposed services, "
        "audit it: flag rules that are redundant, shadowed (never reached), "
        "overly broad (e.g. SSH open to the world), or missing (a "
        "world-exposed port with no restriction). Recommend a tightened "
        "ruleset or specific rule changes. Note if the host has no active "
        "firewall. Be specific to the rules shown."
    ),
    'dns_hygiene': (
        "You are a DNS-hygiene advisor. Given a zone's records plus "
        "resolve/propagation and resolver-health data, flag problems: dangling "
        "CNAMEs, missing or weak SPF/DMARC/DKIM/CAA, NS inconsistency between "
        "providers and authoritative, records not yet propagated, and risky "
        "TTLs (too low, or too high before a planned migration). Recommend the "
        "specific record changes."
    ),
    'email_deliverability': (
        "You are an email-deliverability advisor. Given DMARC/SPF/DKIM posture, "
        "DMARC RUA aggregate-report tallies (which sources pass/fail SPF and "
        "DKIM) and DNSBL listing status, assess deliverability: identify a "
        "too-permissive or broken SPF, sources failing alignment, a weak DMARC "
        "policy (p=none) and any blacklisted sending IP. Recommend the specific "
        "DNS/policy fixes, in priority order."
    ),
    'integration_assist': (
        "You are a homelab assistant. Using the attached homelab-integration "
        "health (Pi-hole, TrueNAS, *arr, download clients, media servers, etc.) "
        "and host telemetry, answer the operator's question about their "
        "self-hosted services — what's down or degraded, likely causes, and "
        "what to check. Cross-reference the host a service runs on when "
        "relevant. Concise and practical."
    ),
    'supply_chain': (
        "You are a software supply-chain analyst. Using the fleet's "
        "software/package inventory (SBOM), CVE findings and exposure data, "
        "answer the operator's supply-chain question — e.g. exposure to a "
        "specific CVE or package: which hosts run the affected version, whether "
        "it's reachable/exposed, and the remediation. If a VEX status "
        "(not-affected/fixed) is known, state it. Be precise about versions and "
        "host counts."
    ),
    'host_profile': (
        "You are an operations assistant. Produce a concise one-page profile of "
        "a single host from the attached context: its role/purpose (from CMDB), "
        "current health and risk, notable open issues (CVEs, drift, failed "
        "services, stale backups, expiring certs) and what it depends on / what "
        "depends on it. Write it as a standing reference an engineer could read "
        "to understand the host in 30 seconds. Neutral tone; lead with role and "
        "health."
    ),
    'remote_access': (
        "You are a remote-access (VPN) reviewer. Given the WG Access "
        "(WireGuard road-warrior VPN) posture — tunnels with their reach scope "
        "(dashboard-only / fleet / site / group / tag), full- vs split-tunnel, "
        "their clients, who is connected now, last-handshake age, and any TTL "
        "expiry — review it for risk and hygiene. Flag over-broad reach scopes "
        "(a tunnel that can reach more of the fleet than it needs), full-tunnel "
        "egress where split would do, disabled tunnels that still have clients, "
        "stale/never-connected clients that should be revoked, and access "
        "expiring soon. Recommend concrete tightening. Be specific to the "
        "tunnels and clients shown."
    ),
}
