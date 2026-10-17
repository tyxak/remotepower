# OPNsense

RemotePower works with an OPNsense firewall in three separate ways. Use any of
them.

| You want to | RemotePower uses | Section |
|---|---|---|
| See and edit the firewall's rules | the OPNsense API | [Manage rules](#manage-rules-over-the-api) |
| Collect the firewall's logs | syslog sent to RemotePower | [Send the logs](#send-the-firewalls-logs) |
| See what is talking to what | NetFlow sent to RemotePower | [Send traffic records](#send-traffic-records-netflow) |

OPNsense menu paths in this guide use OPNsense's own arrow, ‣, to keep them
apart from RemotePower's **Settings →** paths. Field names differ a little
between OPNsense releases; the settings are the same.

## Add the firewall to RemotePower

All three start from one host record.

1. Go to **Hosts** and click **+ Agentless host**.
2. Give it a name, set **Type** to *Firewall*, and fill in **IP**.

For the API, the IP is where RemotePower connects. For logs and traffic it
matters more: it is how RemotePower knows a packet came from this firewall. It
has to be the address the firewall **sends from**, which on a firewall with
several interfaces is the one that leads to the RemotePower server. See [Which
address does the firewall send from?](inbound-tokens.md#which-address-does-the-firewall-send-from)

## Send the firewall's logs

OPNsense sends its logs as plain UDP syslog. **There is nothing to paste into
OPNsense**: not the token and not a URL. RemotePower matches the packets to the
firewall by IP address, and the token stays on the server. [How that works](inbound-tokens.md#syslog-and-netflow-where-the-token-goes)

1. **Install the syslog receiver on the RemotePower server**, once. Run the
   installer with `--with-syslogd`, or follow the [three manual
   commands](syslog.md#installing-the-listener). Then
   `systemctl status remotepower-syslogd` should say *active*, and
   `sudo ss -lun | grep 5514` should show it listening. Open UDP 5514 on the
   server's firewall for the OPNsense address. The Docker image does not include
   the receiver.
2. **Create a Syslog token.** In RemotePower, go to **Settings → Integrations →
   Inbound webhooks**, click **New token**, set **Type** to *Syslog ingestion*,
   and under **Pin to host** choose the firewall. Do not copy the token
   anywhere. Its type must be *syslog*: an *alert* token does not receive logs.
3. **Tell OPNsense where to send.** Go to **System ‣ Settings ‣ Logging**, open
   the **Targets** tab (it is called **Remote** in some releases), and add a
   target:

   | Field | Value |
   |---|---|
   | Transport | UDP (IPv4). The receiver speaks neither TCP nor TLS, and not IPv6 |
   | Applications | Empty sends everything. To send only the firewall's rule log, choose `filterlog` |
   | Levels, Facilities | Leave as they are, or narrow them |
   | Hostname | The RemotePower server's own IP address. A hostname that sits behind a proxy such as Cloudflare will not work, because UDP does not pass through it |
   | Port | `5514` |

   Save and apply. OPNsense logs a packet only when the rule that handles it
   has logging on, so an empty `filterlog` can also mean the rules are not
   logging.
4. **Check that it arrives.** On the OPNsense shell (SSH, menu option 8), which
   is FreeBSD and takes different flags from Linux:

   ```
   logger -h 192.0.2.10 -P 5514 -t remotepower-test "hello from opnsense"
   ```

   Within a few seconds the token's **Hits** goes up, and the line appears on the
   firewall's **Logs** tab. If it does not, the
   [symptoms table](inbound-tokens.md#reading-the-symptoms) matches what you see
   on the server to what to change. The most common cause is that the host's IP
   is not the address the packets come from; the server's journal names that
   address (`journalctl -u remotepower-syslogd -n 20`).

Once logs arrive, [log-watch.md](log-watch.md) shows how to alert on them.
[Firewall sources](firewall-sources.md) shows how to have Threat intel read the
same logs for port scans, Suricata and CrowdSec alerts and failed sign-ins, and
report the addresses behind them.

## Send traffic records (NetFlow)

NetFlow shows which hosts talk to which, and how much, as a live view on the
firewall's host drawer. It is not a log and it does not carry one. The steps
mirror the logs:

1. **Install the flow receiver** on the RemotePower server: run the installer
   with `--with-flowd`, or follow the [manual steps](flow.md#setup). It listens
   on UDP 2055. Open that port for the OPNsense address.
2. **Create a NetFlow/IPFIX token** pinned to the same firewall host. One
   host can carry a syslog token and a NetFlow token side by side.
3. **Turn on the exporter in OPNsense.** Go to **Reporting ‣ NetFlow**, choose the
   interfaces to watch, set the version to *IPFIX* (NetFlow v9 also works), and
   add RemotePower as the destination: the server's address and port 2055, in
   the form `192.0.2.10:2055`. Save and apply.
4. **Check.** Open the firewall in **Hosts** and look for the **Network flows**
   card. The **Server status** page lists a *Flow receiver* row that says whether
   it is running and how many exporters it can receive from.

The firewall sees only the traffic it routes. A conversation between two hosts
on the same VLAN does not pass through it and does not appear. [flow.md](flow.md)
explains what the view keeps and for how long.

## Manage rules over the API

RemotePower can view and manage the firewall's rules over the OPNsense REST API
— the direct counterpart to the RouterOS/MikroTik integration. With the
firewall added as above, you get a card that can **view, add, enable/disable,
and delete** filter rules and outbound (source) NAT rules.

### Setup

1. **Create an API key/secret** in OPNsense: System ‣ Access ‣ Users →
   pick (or create) a user scoped to the firewall pages → **API keys** →
   `+` to generate. OPNsense downloads an `apikey.txt` containing the key
   and secret.
2. In RemotePower, open the agentless host → **Audit → OPNsense**.
3. Tick **Enable OPNsense API**, paste the **API key** and **API secret**,
   set the port (default `443`), and **Save**. The secret is stored
   write-only — it's never returned to the browser; leave the field blank
   on later edits to keep the existing one.
4. Click **Load firewall** to view and manage rules.

TLS verification is **off** by default (OPNsense ships a self-signed cert;
the trust model is "LAN + API credentials", the same posture as the
RouterOS integration). Install a trusted cert and the integration still
works.

### What you can do

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

### API endpoints used

All under `https://<host>/api`, HTTP Basic auth (`api_key`:`api_secret`):

- Filter: `firewall/filter/{searchRule, addRule, delRule/{uuid}, toggleRule/{uuid}/{0|1}}`
- NAT (outbound/source): `firewall/source_nat/{searchRule, addRule, delRule/{uuid}, toggleRule/{uuid}/{0|1}}`
- Apply: `firewall/filter/apply`

Reference: <https://docs.opnsense.org/development/api.html>

### Security model

- **Admin-only + audited.** Every add/delete/toggle goes through an
  admin-only endpoint and is written to the audit log (`device_opnsense_action`).
- **Per-host opt-in.** Nothing reaches a firewall until you enable
  OPNsense on that specific host and store its credentials.
- **Field allow-list.** Added rules are restricted to a whitelist of
  OPNsense rule fields, so a crafted (or AI-drafted) rule can't smuggle in
  arbitrary attributes.
- **Write-only secret.** The API secret is never returned by the API; the
  UI shows only whether one is stored.

### Notes / limitations

- "NAT" here is **outbound (source) NAT** via the firewall plugin's
  `source_nat` controller — the well-supported API surface. Port-forward
  (destination NAT) follows the identical add/delete/toggle contract under
  `firewall/d_nat` and can be added the same way if needed.
- The firewall plugin API is part of OPNsense core on current releases.
