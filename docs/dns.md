# DNS

**Access → DNS** is a read/write DNS control plane. You edit zone records through your
provider's API, resolve names live to confirm that changes propagated, and monitor
that the names you care about keep resolving.

## Records

Pick a **provider** and **zone**, and the records table lists Name, Type,
Content, TTL and flags. **+ New record**, and the edit and delete buttons on each row, work
directly against the provider's API. A record can be of type A, AAAA, CNAME, TXT, MX, NS, SRV
or CAA. A delete waits for the undo window to close before it reaches the provider, so you can
take it back. Supported providers:

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

The DNS page reuses the **same scoped API tokens as ACME DNS-01**. Set a provider token once
under **Security → TLS / DNS → ACME certificates → DNS provider credentials** and both
certificate issuance and this page use it (see [acme.md](acme.md)). Without a vault the
tokens sit in the server's configuration, so for stronger handling at rest, set up the
[CMDB](cmdb.md) vault (**Fleet → CMDB**). A bar above the records table then offers:

- **Unlock vault** and **Lock**. While the vault is unlocked, the page sends your vault key with
  each request (the `X-RP-Vault-Key` header). The server never stores it.
- **Import from config**: move a plaintext token into the encrypted vault (AES-GCM) and
  optionally clear the plaintext copy.
- **Enter token manually**: store a token in the vault directly.
- **Import from agent**: search for an enrolled host whose `acme.sh` holds your DNS
  credentials, and its agent sends them into the vault. The agent must run as root.

## Resolve & propagation

- **Resolve** (in the *Resolve / dig* card) asks a name and type live against four public
  resolvers (Cloudflare, Google, Quad9, OpenDNS) and against the zone's authoritative
  nameservers, so you see a mismatch immediately after an edit. It can resolve A, AAAA, CNAME, MX,
  TXT, NS, SOA, CAA, SRV and PTR.
- **Check propagation** polls the public resolvers and reports how many already
  serve the expected value.

Queries are input-validated (RFC-1123 names, an allowlisted record-type set) and
SSRF-guarded — authoritative-nameserver lookups refuse private/loopback/reserved
IPs.

## Resolver health monitor

Register the names that matter (your apex, MX, key A/AAAA records) with **+ Monitor name**. You
can monitor up to 200. RemotePower re-resolves them every 15 minutes at several public
resolvers, tracking latency, NXDOMAIN and failure counts. **Check now** runs a check at once
(it skips a name checked in the last 30 seconds). A name that stops resolving raises
**`resolver_unhealthy`** after 2 failed checks in a row, so one blip does not page you.
Change the number under **Settings → Alert parameters → Reachability → Resolver down after N
fails**. **`resolver_recovered`** resolves it when the name answers again. The table shows
health, latency, which resolvers answered and the last-checked time.

## Boundaries

- **ACME** (see [acme.md](acme.md)) uses the same credential store for DNS-01
  certificate issuance (`_acme-challenge` records). This page manages the rest of
  the zone.
- **Email posture** (see [dmarc.md](dmarc.md)) *reads* SPF, DKIM and DMARC records and
  ingests DMARC reports. Edit those records here.
- **Domain and certificate expiry** are watched on **Security → TLS / DNS** (see
  [tls-monitor.md](tls-monitor.md)).

## Permissions

- Reading providers/zones/records and running resolve/propagation queries needs
  normal authentication.
- **Creating, updating or deleting records**, all vault and agent-import
  operations, and managing resolver-health targets are **admin-only** and
  audit-logged.

## API

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/dns/providers` | Providers and which have a token |
| GET | `/api/dns/zones` | Zones of a provider |
| GET | `/api/dns/records` | Records of a zone |
| POST | `/api/dns/records` | Create a record (admin) |
| POST | `/api/dns/records/update` | Change a record (admin) |
| POST | `/api/dns/records/delete` | Delete a record (admin) |
| GET | `/api/dns/resolve` | Resolve a name and type live |
| GET | `/api/dns/propagation` | Check how far a value has spread |
| GET, POST | `/api/resolver-health/targets` | List and add monitored names (add is admin) |
| DELETE | `/api/resolver-health/targets/{id}` | Stop monitoring a name (admin) |
| POST | `/api/resolver-health/scan` | Check all now (admin) |
| POST | `/api/dns/vault-credentials`, `/api/dns/vault-credentials/import` | Store or import a token in the vault (admin) |
| POST | `/api/dns/import-from-agent` | Ask an agent to send its `acme.sh` credentials into the vault (admin) |

## Troubleshooting

| Problem | What to check |
| --- | --- |
| The provider list is empty | No token is stored yet. Add one under **Security → TLS / DNS → DNS provider credentials**. |
| A zone list or record list fails | The token may lack the zone-read or DNS-edit scope. Create it with the scopes the provider's docs name for DNS edits. |
| Propagation never completes | Check the record's TTL. Resolvers cache the old value until it expires. |
| *Import from agent* finds nothing | The agent must run as root on a host that has `acme.sh` with DNS credentials. |
| `resolver_unhealthy` for a name that works | Some resolvers rate-limit or block cloud-hosted servers. The status line shows which ones answered. |

## With multi-tenancy

The DNS providers, their zones and records, and the credentials behind them belong to the organisation that runs the installation. With tenant isolation on, only the platform operator can open or change them.

## See also

[acme.md](acme.md), [tls-monitor.md](tls-monitor.md), [dmarc.md](dmarc.md),
[dns-control.md](dns-control.md), [cmdb.md](cmdb.md).
