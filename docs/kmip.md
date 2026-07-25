# KMIP key server

Storage appliances that encrypt data — a Synology NAS, a TrueNAS box, a vSphere
cluster — need somewhere to keep the encryption keys. Keeping them on the same
appliance that holds the encrypted data defeats much of the point: whoever walks
off with the box gets the lock and the key together. The industry answer is
**KMIP** (Key Management Interoperability Protocol), the OASIS standard those
appliances speak to an external key manager.

RemotePower ships one. It is **off by default** and runs as a separate,
sandboxed sidecar service, so nothing listens until you ask for it.

> **Read this before you enable it.** Once an appliance stores its keys here, it
> needs this server reachable **at its own boot time** to mount encrypted
> storage. Never run the KMIP server on a machine that depends on it to unlock —
> a NAS that keeps its keys on a VM hosted by that same NAS will not come back
> from a reboot. Export a recovery bundle (below) before you rely on it.

## What speaks to it

| Client | What it stores here |
|---|---|
| **Synology DSM** 7.2+ | Encrypted shared-folder / volume key vault |
| **TrueNAS** (CORE / SCALE) | SED passwords and ZFS dataset keys |
| **VMware vSphere** 7+ | VM encryption and vTPM keys (as a Standard key provider) |
| Any KMIP 1.0–1.4 client | Generic symmetric keys, secret data, opaque objects |

Supported operations: Discover Versions, Query, Create, Register, Get, Get
Attributes, Get Attribute List, Locate, Activate, Revoke, Destroy — the subset
these appliances actually use. Object types: symmetric keys, secret data,
opaque objects.

## How it fits together

Three pieces, deliberately separated:

- **`remotepower-kmipd`** — the listener (tcp/5696). It terminates mutual TLS
  and parses the KMIP wire format. It holds no keys, no database access and no
  master key; it is a protocol shim and nothing more.
- **The RemotePower API** — owns everything that matters: the certificate
  authority, the key objects, encryption at rest, the client registry and the
  activity log. The sidecar reaches it over loopback with a shared secret.
- **The Security → KMIP page** — where you enable the server, issue client
  certificates, watch the activity log and export recovery bundles.

That split is why the sidecar's systemd unit can run under `DynamicUser=yes`
with no access to the data directory at all.

## Install the sidecar

Either pass the flag at install time:

```
sudo ./install-server.sh --with-kmip
```

or, on an existing server, open **Security → KMIP → Install sidecar** and run
the commands it prints. They write the shared secret to
`/etc/remotepower/kmipd.env` (mode 0600, root-owned — systemd reads it as root
to start the daemon, so it needs no wider access), install the daemon and start
it. The server records the same secret internally, so the app never has to read
that file.

Then in the UI: **Security → KMIP → Server settings** → tick *KMIP server
enabled*, set the hostname or IP your appliances will use, and save. That first
save generates the master key, a private certificate authority and the server
certificate.

## Add a client

**Security → KMIP → Add client** runs a three-step wizard:

1. **Appliance** — pick the type (Synology DSM, TrueNAS, vSphere, generic),
   give it a name, and — recommended — enter the appliance's **own** hostname
   or IP. That address is written into its certificate, which some appliances
   verify; leaving it blank still produces a valid certificate.
2. **Credentials** — download `ca.crt`, `client.crt` and `client.key`. The
   private key is shown **once** and never stored on the server.
3. **Connect** — per-appliance setup steps, and the page waits for the client's
   first connection so you can confirm it worked before walking away.

If a client certificate is ever lost, use **Re-issue** on the client row. It
mints a fresh certificate and key under the *same* client identity, so the
appliance keeps access to every key it already stored. **Revoke** cuts an
appliance off; the sidecar refuses it within 30 seconds.

Each appliance can only read its own keys. One compromised NAS certificate
cannot fetch another appliance's volume keys.

## Certificate details

Useful if you are comparing against another KMIP setup or debugging an import:

| | CA | Server | Client |
|---|---|---|---|
| Key | RSA 3072 | RSA 2048 | RSA 2048 |
| Validity | 10 years | 4 years | 5 years |
| Basic constraints | `CA:TRUE` (no path-length limit) | `CA:FALSE` | `CA:FALSE` |
| Extended key usage | — | `serverAuth, clientAuth` | `serverAuth, clientAuth` |
| SAN | — | configured hostnames + IPs | the appliance's address (or a label from its name) |
| Key identifiers | SKI + self-referential AKI | SKI + AKI → CA | SKI + AKI → CA |

Both leaf certificates carry **both** extended key usages. KMIP mutual TLS
blurs the client/server roles and appliances expect both — this matches the
community `kmip-server-dsm` setup that Synology users run successfully. The CA
deliberately carries **no path-length constraint**: a self-signed root with
`pathlen:0` is read by some appliances (DSM included) as an intermediate, and
then refused as a trust anchor.

Private keys are PKCS#8 PEM (`BEGIN PRIVATE KEY`). Everything is issued
in-process with the `cryptography` library — no `openssl` binary required.

## Security model

- **Mutual TLS is mandatory.** A client must present a certificate signed by
  this server's KMIP CA, and its SHA-256 fingerprint must match a registered,
  non-revoked client. Both the sidecar and the API re-check identity — the API
  verifies again on every single operation, so a stale sidecar cache cannot
  authorize a revoked client.
- **Keys are encrypted at rest** with AES-256-GCM, using the same primitives as
  the credential vault, under a dedicated 32-byte master key stored `0600` at
  `/var/lib/remotepower/kmip_master.key`.
- **That master key is deliberately excluded from scheduled backups.** Your
  normal backups therefore contain the key objects as ciphertext with no way to
  decrypt them — which is the point. The master key travels only inside a
  recovery bundle (below).
- **Key material never leaves through the admin API.** The inventory shows
  metadata only; the raw bytes are returned solely to an authenticated KMIP
  client answering a Get.
- **Everything is logged.** Connections, authentication failures, every KMIP
  operation, and every admin action (enable, issue, revoke, re-issue, destroy,
  export, import) land in the activity log on the page, with admin actions also
  written to the main audit log.
- KMIP administration is restricted to **global administrators**; it is host
  infrastructure and is not tenant-scoped.

## Synology DSM, step by step

DSM needs the certificate installed in one place and referenced in another, and
its import dialog's field names do not match what you would expect. Requires
**DSM 7.2-64570** or newer.

1. **Control Panel → Security → Certificate** → **Add** → *Add a new
   certificate* → Description `KMIP` → *Import certificate*.
2. Fill the three fields with the wizard's downloads:
   - **Private Key** → `client.key`
   - **Certificate** → `client.crt`
   - **Intermediate Certificate** → `ca.crt`

   DSM labels that third field *Intermediate Certificate*. The CA goes there
   anyway — DSM is not asking for a real intermediate, and seeing your root
   land in a field called "intermediate" is expected, not a mistake.
3. Click **Settings** and select the newly imported certificate for **KMIP**.
4. Switch to the **KMIP** tab and configure **Remote Key Client**: the hostname
   and port of this server, and **`ca.crt` again** for *Certificate Authority*.
   The same file is used twice — once as part of the identity in step 2, once
   as the trust anchor here.
5. Move a shared folder's key across: **Control Panel → Shared Folder →
   Encryption → Key Manager**.

If DSM reports errors, `sudo journalctl -u kmip.service -ef` on the NAS is the
matching log to this server's activity page.

## How Synology DSM differs from plain KMIP

Worth knowing if you are comparing this against the KMIP specification or
another server:

- **DSM negotiates legacy TLS.** The community `kmip-server-dsm` setup pins
  `TLS_RSA_WITH_AES_256_CBC_SHA256` — an RSA key-exchange, CBC-mode suite with
  no forward secrecy, which modern OpenSSL disables by default. RemotePower
  ships the modern suites; if an appliance cannot negotiate, set
  `RP_KMIP_LEGACY_CIPHERS=1` in `/etc/remotepower/kmipd.env` and restart the
  sidecar. It is opt-in because it weakens the listener, and the activity log
  points you at it when a handshake fails on ciphers.
- **Both certificates need both extended key usages.** KMIP mutual TLS blurs
  the client/server roles, so the working DSM setup issues
  `serverAuth, clientAuth` on the server *and* the client certificate. This
  server does the same.
- **The client certificate's SAN should be the appliance's own address.** DSM
  setups encode `IP:<NAS address>`; the Add-client wizard asks for it.
- **The CA must present as a root.** DSM refuses a CA that looks like an
  intermediate — one carrying `pathlen:0` or lacking a self-referential
  Authority Key Identifier. Ours is a proper self-signed root.
- **Ownership is per client.** PyKMIP-based setups use an `ALLOW_OWNER` policy
  so an object is only reachable by the identity that created it. RemotePower
  enforces the same rule, keyed on the client certificate's SHA-256
  fingerprint rather than its Common Name — stricter, since a fingerprint
  cannot be spoofed by re-using a name.
- **DSM stores a key vault, not individual keys.** From the server's side it is
  ordinary Register/Get/Locate traffic; nothing DSM-specific is required.

## Recovery — do this before you depend on it

**Security → KMIP → Export bundle** produces a single passphrase-encrypted file
(`.rpkmip`, AES-256-GCM with PBKDF2-SHA256) containing the master key, the CA,
the issued client certificates and every stored key object. It is everything
needed to rebuild this key server on new hardware.

Export a bundle after setup, and again whenever you add clients or keys. Store
it **off this machine** — and specifically not on an appliance that unlocks
against this server, which would be a circular dependency exactly like the one
warned about at the top.

To restore, use **Restore bundle** on a fresh install. If the server already
holds keys you must confirm the replacement explicitly; nothing is overwritten
silently. Because client identities travel inside the bundle, appliances keep
working after a restore without re-issuing certificates.

Losing both the server and the bundle means the encrypted data on every client
is unrecoverable. There is no back door — that is what makes the design worth
anything.

## Removing it / starting over

**Security → KMIP → Remove and start over** wipes the server side: the master
key, the CA, every client registration and every stored key object. It requires
you to type `REMOVE KMIP` (checked on the server, not just in the browser) and
is written to the audit log. Anything still relying on this server for its
encryption keys becomes unrecoverable unless you exported a recovery bundle
first.

That resets the application's state but cannot remove the sidecar service, so
finish as root:

```
sudo systemctl disable --now remotepower-kmipd
sudo rm -f /usr/local/bin/remotepower-kmipd \
           /etc/systemd/system/remotepower-kmipd.service \
           /etc/remotepower/kmipd.env
sudo systemctl daemon-reload
```

On the appliance, delete the KMIP certificate and its Remote Key Client entry —
otherwise it keeps trying to reach a server that no longer answers. On Synology
that is Control Panel → Security → Certificate (delete the `KMIP` entry) and the
KMIP tab.

> **Before removing anything, move any encrypted volume's key back off the
> remote vault.** A NAS whose key vault lives here will not mount its encrypted
> storage once this server is gone. On DSM: Control Panel → Shared Folder →
> Encryption → Key Manager.

To reinstall, follow *Install the sidecar* above. Everything is regenerated from
scratch — a new master key, a new CA, new client certificates — so any files
previously copied to an appliance must be replaced with the new ones.

## Watching it

- **Security → KMIP** — server state, sidecar check-in, clients, stored keys and
  the activity log.
- **`rp status` / `rp tui`** — the `remotepower-kmipd` component row plus an
  **INGEST & KEYS** block with client, key and recent-failure counts. Run it
  with `sudo` (the data directory is `0700`).
- **Checks catalog** — apply *RemotePower KMIP key server running* to the host
  tagged `rp-server` to alert when the listener stops. Worth doing if any
  appliance depends on it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Sidecar won't start, log says the secret is missing | `/etc/remotepower/kmipd.env` absent — re-run the install snippet |
| Page says the file exists but cannot be read | The env file is there but the app user can't read it and nothing is stored in the config. Re-run the install snippet; it records the secret server-side so file permissions stop mattering |
| Journal shows `control plane REJECTED our secret (403)` | The value in `kmipd.env` differs from the one the server holds — re-run the install snippet, then restart the service |
| Page says "has not checked in" | The daemon polls every 30s, so allow that long after a start. If it persists, check `journalctl -u remotepower-kmipd` for the 403 above or a loopback connection error |
| Appliance reports a TLS/handshake error | Wrong `ca.crt`, or the client certificate was revoked — check the activity log for an `auth fail` row |
| Client connects but finds no keys | Keys belong to the client that stored them; a re-issued certificate keeps its keys, a *new* client starts empty |
| Journal: `tlsv1 alert unknown ca` | The appliance rejected **our** server certificate — it has not been given `ca.crt`. Upload it into the appliance's trusted-CA store |
| Journal: `certificate verify failed: self-signed certificate in certificate chain` | The appliance presented a certificate **we** did not issue — it is sending its own default cert instead of the wizard's `client.crt`, or `client.crt` was never installed |
| Journal: `wrong version number` | Something connected without TLS — a port scan or health check, or a client pointed at a plaintext KMIP port. Harmless unless it is your appliance |
| Journal: `unable to get local issuer certificate` | The appliance holds a `client.crt` signed by a **different** CA — usually an old one kept after the CA was re-issued. Download the files again and reinstall all three |
| Journal: `no shared cipher` / `handshake failure` | The appliance offers only legacy suites. Set `RP_KMIP_LEGACY_CIPHERS=1` in `/etc/remotepower/kmipd.env` and restart the sidecar |
| Appliance boots without mounting encrypted volumes | The key server was unreachable at boot — that is the availability coupling described at the top |

## See also

- [security.md](security.md) — the wider security model and review history
- [backups.md](backups.md) — the scheduled backups that carry KMIP ciphertext
- [cli.md](cli.md) — `rp status` / `rp tui`, including the INGEST & KEYS block
