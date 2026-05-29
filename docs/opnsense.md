# OPNsense firewall management

RemotePower can view and manage an OPNsense firewall's rules over the
OPNsense REST API — the direct counterpart to the RouterOS/MikroTik
integration. Add the firewall as an **agentless device**, enable OPNsense
in the device drawer, and you get a firewall card that can **view, add,
enable/disable, and delete** filter rules and outbound (source) NAT rules.

## Setup

1. **Create an API key/secret** in OPNsense: System → Access → Users →
   pick (or create) a user scoped to the firewall pages → **API keys** →
   `+` to generate. OPNsense downloads an `apikey.txt` containing the key
   and secret.
2. In RemotePower, open the agentless device → **Audit → OPNsense**.
3. Tick **Enable OPNsense API**, paste the **API key** and **API secret**,
   set the port (default `443`), and **Save**. The secret is stored
   write-only — it's never returned to the browser; leave the field blank
   on later edits to keep the existing one.
4. Click **Load firewall** to view and manage rules.

TLS verification is **off** by default (OPNsense ships a self-signed cert;
the trust model is "LAN + API credentials", the same posture as the
RouterOS integration). Install a trusted cert and the integration still
works.

## What you can do

| | Filter rules | NAT rules (outbound / source) |
|---|---|---|
| View | ✓ | ✓ |
| Add | ✓ (pass / block / reject) | ✓ (target / target-port) |
| Enable / disable | ✓ | ✓ |
| Delete | ✓ | ✓ |

**New rules are created disabled.** As with RouterOS, an added rule lands
disabled so you can review it in the table before enabling it — a wrong
rule can't lock you out the moment you click Add. Every change is followed
by an `apply` so it takes effect on the live ruleset.

## API endpoints used

All under `https://<host>/api`, HTTP Basic auth (`api_key`:`api_secret`):

- Filter: `firewall/filter/{searchRule, addRule, delRule/{uuid}, toggleRule/{uuid}/{0|1}}`
- NAT (outbound/source): `firewall/source_nat/{searchRule, addRule, delRule/{uuid}, toggleRule/{uuid}/{0|1}}`
- Apply: `firewall/filter/apply`

Reference: <https://docs.opnsense.org/development/api.html>

## Security model

- **Admin-only + audited.** Every add/delete/toggle goes through an
  admin-only endpoint and is written to the audit log (`device_opnsense_action`).
- **Per-device opt-in.** Nothing reaches a firewall until you enable
  OPNsense on that specific device and store its credentials.
- **Field allow-list.** Added rules are restricted to a whitelist of
  OPNsense rule fields, so a crafted (or AI-drafted) rule can't smuggle in
  arbitrary attributes.
- **Write-only secret.** The API secret is never returned by the API; the
  UI shows only whether one is stored.

## Notes / limitations

- "NAT" here is **outbound (source) NAT** via the firewall plugin's
  `source_nat` controller — the well-supported API surface. Port-forward
  (destination NAT) follows the identical add/delete/toggle contract under
  `firewall/d_nat` and can be added the same way if needed.
- The firewall plugin API is part of OPNsense core on current releases.
