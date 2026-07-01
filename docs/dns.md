# DNS

**Admin → DNS** is a read/write DNS control plane: edit zone records through your
provider's API, resolve names live to confirm changes propagated, and monitor
that the names you care about keep resolving.

## Records

Pick a **provider** and **zone**, and the records table lists Name, Type,
Content, TTL and flags. **+ New record**, inline **edit** and **delete** operate
directly against the provider's API. Supported providers:

| Provider | Notes |
| --- | --- |
| **Cloudflare** | proxied flag supported |
| **DigitalOcean** | |
| **Hetzner** | |
| **deSEC** | |
| **Porkbun** | |

All providers normalise to a common record shape (`{id, type, name, content, ttl,
priority, proxied}`), so the UI is identical whichever you use.

### Credentials

The DNS dashboard reuses the **same scoped API tokens as ACME DNS-01**
(`acme_dns_credentials`): set a provider token once under Settings → ACME and both
subsystems use it. For stronger at-rest handling you can:

- **Import to the encrypted vault** — move a plaintext token into the CMDB vault
  (AES-GCM), optionally clearing the plaintext copy. Vault reads need the
  `X-RP-Vault-Key` header (never stored).
- **Import from an agent** — if `acme.sh` runs on an enrolled host, ask its agent
  to harvest its local provider credentials into the vault.

## Resolve & propagation

- **Resolve** a name/type live against several vetted public resolvers
  (Cloudflare, Google, Quad9, OpenDNS) and against the zone's authoritative
  nameservers — so you can see a mismatch immediately after an edit.
- **Check propagation** polls the public resolvers and reports how many already
  serve the expected value.

Queries are input-validated (RFC-1123 names, an allowlisted record-type set) and
SSRF-guarded — authoritative-nameserver lookups refuse private/loopback/reserved
IPs.

## Resolver health monitor

Register the names that matter (your apex, MX, key A/AAAA records) and RemotePower
re-resolves them on a cadence at multiple public resolvers, tracking latency,
NXDOMAIN and failure counts. A name that stops resolving raises
**`resolver_unhealthy`** (after a couple of confirming checks to avoid flapping),
and **`resolver_recovered`** when it comes back. The table shows Health, Latency,
which resolvers answered, and the last-checked time.

## Boundaries

- **ACME** (see [acme.md](acme.md)) uses the same credential store for DNS-01
  certificate issuance (`_acme-challenge` records) — this page manages the rest of
  the zone.
- **Email posture** (see [dmarc.md](dmarc.md)) *reads* SPF/DKIM/DMARC records and
  ingests DMARC reports; edit those records here.

## Permissions

- Reading providers/zones/records and running resolve/propagation queries needs
  normal authentication.
- **Creating, updating or deleting records**, all vault and agent-import
  operations, and managing resolver-health targets are **admin-only** and
  audit-logged.
