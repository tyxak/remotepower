# Relay satellites — reaching agents in segmented networks

A **satellite** is a tiny authenticated relay you run inside a network segment
that can't reach the central RemotePower server directly (a DMZ, a remote site,
an isolated VLAN). Agents in that segment talk to the satellite; the satellite
forwards their `/api/*` traffic to the central server.

```
agent ──(https)──▶ satellite ──https──▶ RemotePower server
```

Two independent identities ride along: the **agent's device token** still
authenticates the device end-to-end (the satellite never sees a usable
credential it could impersonate the device with), and the **satellite token**
identifies *which relay* the traffic came through — so you can see and revoke a
satellite independently of its agents.

The relay is `client/remotepower-satellite.py` — standard-library only, no
dependencies.

---

## Add a satellite

### 1. Mint a satellite token (on the server UI)
**Settings → Integrations → Relay satellites → New satellite.** The token is
shown once — copy it. Each satellite gets its own token.

### 2. Install the relay (on the satellite host, inside the segment)
Use the script (installs a hardened systemd service):

```bash
sudo RP_UPSTREAM=https://remote.example.com \
     RP_SATELLITE_TOKEN='<token-from-step-1>' \
     bash packaging/satellite-setup.sh
```

That listens on `0.0.0.0:8800` and forwards to the server. **Encrypt the
agent→satellite hop** by giving it a cert (strongly recommended — see below):

```bash
# you have a cert the agents trust (internal CA or Let's Encrypt):
sudo RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='…' \
     RP_TLS_CERT=/etc/ssl/sat.crt RP_TLS_KEY=/etc/ssl/sat.key \
     bash packaging/satellite-setup.sh

# or a quick self-signed cert for an internal hostname:
sudo RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='…' \
     bash packaging/satellite-setup.sh --self-signed satellite.internal
```

Manual run (no systemd) is just the env + the script:
```bash
RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='…' \
RP_TLS_CERT=/etc/ssl/sat.crt RP_TLS_KEY=/etc/ssl/sat.key \
python3 client/remotepower-satellite.py
```

### 3. Point that segment's agents at the satellite
Set each agent's **server URL** to the satellite instead of the central server:

```bash
# HTTPS satellite (recommended):
sudo remotepower-agent enroll --server https://satellite.internal:8800 --pin 123456
# plaintext satellite (trusted LAN only):
sudo remotepower-agent enroll --server http://10.20.0.2:8800 --pin 123456
```

If the satellite uses a **private/self-signed** cert, tell the agent to trust
its CA (no verification weakening):

```bash
# add the CA to the OS trust store (preferred), or point the agent at it:
RP_CA_BUNDLE=/etc/remotepower/satellite-ca.crt   # set in the agent's environment/unit
```

### 4. Verify
- Satellite health: `curl -k https://<satellite>:8800/satellite/health` → `{"ok":true}`
- The agents enrolled through it appear in the fleet as normal.
- The satellite is listed under **Settings → Integrations → Relay satellites**
  with its last-seen time.

### Revoke
Delete the satellite in the UI — its token stops being accepted immediately.
The agents behind it keep their own device tokens; re-point them at another
satellite or the server.

---

## Encryption posture (make every hop TLS)

| Hop | How to encrypt |
|-----|----------------|
| agent → satellite | `RP_TLS_CERT` + `RP_TLS_KEY` on the satellite → agents use `https://…:8800`. Use a cert the agents trust (internal CA / LE); for self-signed, give agents `RP_CA_BUNDLE`. |
| satellite → server | HTTPS automatically whenever `RP_UPSTREAM` is `https://` (the default). The satellite verifies the server cert unless `RP_UPSTREAM_INSECURE=1`. |
| device token | end-to-end: the agent's bearer token rides inside the (TLS) request; the satellite relays it but can't mint its own. |

Only run the agent→satellite hop in plaintext on a trusted segment LAN — the
relay prints a warning when it starts without a cert.

## Agent push channel through a satellite *(v6.1.2)*

The opt-in [agent push channel](push.md) — a wake-only "poll now" nudge that cuts
command-dispatch latency — works through a satellite. The relay byte-tunnels the
WebSocket for the single path `/api/push/connect`, and only when the request is a
real upgrade (it is not a general WS proxy). The handshake and the agent's device
token pass through untouched, so the push daemon's own token check stays the auth
that matters end to end; the satellite adds its `X-RP-Satellite` token to the
upgrade exactly as it does to every relayed API call.

Nothing to configure — turn `push_enabled` on and relayed agents pick it up on
their next heartbeat. Before v6.1.2 the relay could not carry an `Upgrade`, so
these agents silently never got a nudge (they just kept polling on their normal
cadence, which is the channel's designed fallback — nothing broke, but push was
effectively a direct-agents-only feature).

If the satellite listens over **plain HTTP**, note that the agent picks its
WebSocket scheme from its server URL (`ws://` here, `wss://` for HTTPS). Agents
older than v6.1.2 hard-coded `wss://` and cannot connect to a plaintext satellite
at all.

See also: [scaling.md](scaling.md) (where satellites fit in a large fleet),
[install.md](install.md), [agentless-devices.md](agentless-devices.md).
