# CMDB & Credential Vault

*Introduced in v1.9.0.*

This is the documentation for the CMDB feature: per-asset metadata,
Markdown documentation, and an encrypted credential vault. If you came
here because you forgot the vault passphrase, jump to
[Disaster recovery](#disaster-recovery). The news is not good but at
least it's quick.

---

## What this is

Every enrolled device gets an optional metadata layer on top of the
existing `devices.json` record. You can tag it with an asset ID
(your inventory tag, sticker on the chassis, whatever), describe what
it actually does (`web`, `db`, `dc`, `logging`), point at its
hypervisor's web UI, and write a slab of Markdown documentation —
runbooks, history, "this NAS pretends to be off but isn't," that kind
of thing.

Underneath that, you can store credentials. Multiple per asset:
`root`, IPMI, the web admin panel for that one router from 2014, the
service account nobody remembers creating. The passwords are encrypted
at rest. The metadata around them — labels, usernames, notes — stays
plaintext so the search box still works.

The vault is opt-in. The metadata layer is not — it's just always
there, ready to fill in.

---

## The metadata layer

Open the **CMDB** tab in the sidebar. Every enrolled device appears in
the table, even ones with nothing filled in yet. Click **Open** on a
row to edit:

- **Asset ID** — free text, max 64 chars, charset `[A-Za-z0-9_-]`.
  Whatever your inventory system calls this box.
- **Server function** — what the box does. Free text but charset is
  `[A-Za-z0-9 _\-/]`. The dropdown above the table autocompletes from
  values you've already used, so once you've typed `web` once, all
  your web servers can pick it from a list. Common values that emerge
  in practice: `web`, `db`, `cache`, `dc`, `logging`, `monitoring`,
  `proxy`, `mail`, `dns`, `nas`.
- **Hypervisor URL** — optional. Must start with `http://` or
  `https://`. Rendered as a click-through link in the asset table so
  you can jump straight to the VM console.
- **SSH port** *(v1.10.0)* — defaults to 22. Used by the SSH-link
  buttons that appear next to each credential in the Credentials
  tab. Validated 1–65535. Empty or 0 resets to the default.
- **Documentation** — Markdown, up to 64 KB per asset. The editor has
  Edit and Preview tabs. Headings (`#`, `##`, `###`), lists (`- `),
  code (`` ` ``), bold (`**x**`), italic (`*x*`), and links
  (`[text](https://…)`) all render. Anything more exotic stays as
  literal text — this is a renderer for runbooks, not a CMS.

The search box at the top filters across name, hostname, asset ID,
function, IP, MAC, group, tags, and the documentation body. The
dropdown next to it filters by exact server function.

None of this is sensitive. The vault is a separate concern.

---

## The vault — what it is, and what it isn't

The vault is the storage backend for credentials. The crypto is
**AES-GCM 256-bit** for the actual encryption, with keys derived from
a passphrase via **PBKDF2-SHA256** at 600 000 iterations and a 32-byte
random salt per vault. Each individual encryption uses a fresh 12-byte
nonce.

There's a single shared passphrase, not one per user. This was a
deliberate choice: a CMDB credential is shared infrastructure — if
three admins all need to be able to look up the IPMI password at 2 AM,
they need a shared key, not three separate vaults of the same data.
The model is closer to a team password manager than to GPG.

The passphrase is **never persisted on the server**. When an admin
unlocks the vault, the server runs PBKDF2, returns the resulting
32-byte key as hex to the browser, and forgets the passphrase
immediately. The browser holds the key in a single closure variable
in JS memory. It's cleared on logout, page reload, or the **Lock**
button. Every credential operation that needs the key sends it back
in an `X-RP-Vault-Key` header. The server validates it against a
small encrypted "canary" blob in `cmdb_vault.json`, which means a bad
key gets rejected before it ever touches a real credential.

### What the threat model actually covers

Stop me if you've heard this one: someone gets read access to
`/var/lib/remotepower/cmdb.json`. Maybe a backup leaked, maybe a
misconfigured Nginx alias served it as static content, maybe the
filesystem was cloned. Without the passphrase, every password in that
file is a sealed AES-GCM blob. The salt and KDF params are public —
that's how `cmdb_vault.json` works — but PBKDF2 at 600k iterations
makes brute-forcing a strong passphrase computationally annoying
enough to be impractical for anything you'd plausibly call "a
homelab." If your passphrase is `password123`, no amount of crypto
will save you and we should probably talk.

### What it does *not* cover

A compromised running server is game over. If an attacker gets RCE on
the server itself, they can wait for any admin to unlock the vault and
sniff the key out of memory, or out of the next request. The vault
defends data at rest, not data in motion through a hostile process.
This is not a unique flaw of the vault — every secret manager has the
same property — but it's worth being honest about. Lock the vault
when you're done with it.

A compromised browser is also game over for that user's session: the
key is sitting in a JS variable. Same caveat as any web app handling
sensitive data. Don't share your laptop with people you wouldn't share
the passphrase with.

---

## Setting up the vault

In the UI: open the CMDB page. The status bar at the top will say the
vault isn't configured yet, with a **Set up vault** button. Click it,
pick a passphrase, confirm, done. The vault unlocks itself
automatically after setup so you don't have to immediately re-enter
what you just typed.

Passphrase requirements: 12-256 characters, must contain at least two
of {lowercase, uppercase, digit, symbol}. Use a passphrase manager.
Use a real one. The dictionary attack on PBKDF2 is `~600k×` slower
than a normal password, but if your passphrase is four words from a
1000-word vocabulary list, the math still works out badly for you in
the long run.

From the API:

```bash
curl -sSf -X POST https://your-server/api/cmdb/vault/setup \
  -H "X-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"correct horse battery staple-but-actually-strong"}' \
  | jq
```

Response:

```json
{ "ok": true, "key": "a1b2c3...64-hex-chars-total" }
```

That `key` value is what subsequent credential calls send back as
`X-RP-Vault-Key`. The browser does this for you; if you're scripting,
hold it in a shell variable for the lifetime of your script and don't
log it.

---

## Daily operations

### Adding a credential

UI: open an asset, switch to the **Credentials** tab, click **+ Add
credential**. Enter the label (`root`, `ipmi`, etc.), username,
password, and an optional note. Save.

Curl, assuming `$KEY` holds the hex key from unlock:

```bash
curl -sSf -X POST https://your-server/api/cmdb/dev-abc123/credentials \
  -H "X-Token: $TOKEN" \
  -H "X-RP-Vault-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "label":    "root",
        "username": "root",
        "password": "hunter2",
        "note":     "console only, no sshd"
      }'
```

The response gives you back a `cred_<hex>` ID. Keep it if you plan to
update or reveal that exact credential later — though the UI will
list them all anyway.

### Revealing a credential

UI: in the credentials list, click **Reveal**. The plaintext shows in
a modal with **Copy** buttons next to the username and password
fields. Closing the modal wipes the values out of the DOM (they're
still in JS memory until garbage collection, but they're not sitting
in attribute strings any more).

Every reveal is logged. The audit log entry includes the actor, the
asset, the credential label, and the source IP. If you need to know
who looked at the IPMI password last Thursday, the answer is in the
audit log.

### SSH from a credential *(v1.10.0)*

Each credential row has two extra buttons: **SSH** opens an
`ssh://user@host:port` URI in your default handler (PuTTY on
Windows, Terminal/iTerm on macOS, configurable on Linux). **Copy**
puts the equivalent `ssh user@host -p port` command on your
clipboard.

The host comes from the asset's hostname (or IP if hostname is
empty), the port from the asset's `ssh_port` field, the username
from the credential. The password is **not** in the URI — that
deliberate. Passwords in `ssh://` URIs end up in browser history,
process listings, and shell history, so the password stays in the
reveal modal where it's at least audit-logged when accessed.

If your terminal handler doesn't support `ssh://` URIs (some Linux
desktop environments don't out of the box), the Copy button is the
fallback. Paste into a terminal, type your password when prompted.

Curl:

```bash
curl -sSf -X POST \
  "https://your-server/api/cmdb/dev-abc123/credentials/cred_xxxxx/reveal" \
  -H "X-Token: $TOKEN" \
  -H "X-RP-Vault-Key: $KEY" | jq
```

### Editing

The same modal handles edits. If you change *only* metadata (label,
username, note) the vault key isn't required — those fields aren't
encrypted. If you change the password, the new value gets re-encrypted
under the current key, so you need an unlocked vault for that path.

### Deleting

Hard delete. The encrypted blob is removed from `cmdb.json` on save.
The audit log keeps the `cmdb_credential_delete` entry, but the
ciphertext itself is gone. There's no trash can.

---

## Rotating the passphrase

If a passphrase needs to change — admin left the team, you suspect
it's been seen, you just want to be tidy — the **Rotate passphrase**
button on the CMDB page handles it. Old passphrase, new passphrase,
confirm. The server:

1. Verifies the old passphrase against the canary.
2. Derives a new key from the new passphrase.
3. Walks every credential in `cmdb.json`, decrypts with the old key,
   re-encrypts with the new key, in memory.
4. Writes the new vault metadata first, then the new credential file.
5. Records `cmdb_vault_change` in the audit log with the rotated
   credential count.

If a credential fails to decrypt during rotation (corrupt entry —
shouldn't happen, but here we are), it's dropped and a
`cmdb_vault_change_drop` entry is written so you can see what was
lost. Your old backup still has the original ciphertext if you need
to recover it.

The rotation is atomic in the sense that a crash mid-rotation leaves
the vault recoverable with the old passphrase: the credential file is
written last, so a partial write doesn't strand you with a new vault
file pointing at credentials encrypted under the old key.

Curl:

```bash
curl -sSf -X POST https://your-server/api/cmdb/vault/change \
  -H "X-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_passphrase":"OLD_PASS","new_passphrase":"NEW_PASS"}'
```

---

## Backups

`/var/lib/remotepower/cmdb.json` and `/var/lib/remotepower/cmdb_vault.json`
back up like everything else. Neither file contains the passphrase or
the derived key — `cmdb_vault.json` is just KDF parameters and the
canary blob, and `cmdb.json` is metadata plus AES-GCM ciphertexts.

This means **the backups are useless without the passphrase**. That's
the design. Make sure the passphrase is recorded somewhere safe and
separate — ideally in a different password manager that isn't itself
hosted on the server you're trying to back up. Putting the vault
passphrase in the documentation field of the asset that hosts the
vault would be funny but unhelpful.

The standard backup endpoint (`/api/backup`) includes both files.

---

## Disaster recovery

> "I forgot the passphrase."

Then you can't recover the credentials. There is no master key, no
recovery code, no backdoor, and no support ticket that ends with
"good news, we found it." The whole point of the design is that the
server cannot decrypt without the passphrase, and we mean it.

What you can do:

1. Delete `cmdb_vault.json` and `cmdb.json`.
2. Run `setup` again with a new passphrase.
3. Re-enter the credentials from your other source of truth (you do
   have one, right?).

The asset metadata in `cmdb.json` (asset_id, server_function,
hypervisor_url, documentation) is *not* encrypted. If you want to
preserve that while resetting only the credentials, edit `cmdb.json`
manually and remove just the `credentials` arrays from each record.
Then re-setup the vault and re-enter passwords.

> "I forgot the passphrase but I have a backup from yesterday."

The backup contains the same encrypted blobs. The passphrase is what
you don't have. Same answer as above. Sorry.

---

## API reference

All paths are under `/api`. Auth is the same `X-Token` header used
everywhere else. Vault key is `X-RP-Vault-Key` (hex, 64 chars).

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET    | `/cmdb` | any | List assets. `?q=…` and `?function=…` filters. |
| GET    | `/cmdb/{device_id}` | any | Asset detail. Credentials redacted to metadata only. |
| PUT    | `/cmdb/{device_id}` | any | Patch `asset_id`, `server_function`, `hypervisor_url`, `documentation`. Send only the fields you want to change. |
| GET    | `/cmdb/server-functions` | any | Distinct server_function values, sorted, for autocomplete. |
| GET    | `/cmdb/vault/status` | any | `{configured, kdf, iterations, created_at, created_by}`. |
| POST   | `/cmdb/vault/setup` | admin | One-shot. 409 if already configured. Body: `{passphrase}`. Returns `{key}`. |
| POST   | `/cmdb/vault/unlock` | any | Body: `{passphrase}`. Returns `{key}` on success, 403 on bad pass (with audit). |
| POST   | `/cmdb/vault/change` | admin | Body: `{old_passphrase, new_passphrase}`. Returns `{key, rotated}`. |
| GET    | `/cmdb/{device_id}/credentials` | any | Metadata only — never returns ciphertext or plaintext. |
| POST   | `/cmdb/{device_id}/credentials` | admin + key | Body: `{label, username, password, note}`. Returns `{id}`. |
| PUT    | `/cmdb/{device_id}/credentials/{cred_id}` | admin (+ key if password changes) | Send only changed fields. |
| DELETE | `/cmdb/{device_id}/credentials/{cred_id}` | admin | Hard delete. |
| POST   | `/cmdb/{device_id}/credentials/{cred_id}/reveal` | admin + key | Returns plaintext. **Audit-logged.** |

### Status codes worth knowing

- `401` with body `{"code": "vault_locked"}` — the vault is configured
  but no `X-RP-Vault-Key` header was sent. The browser handles this
  by prompting to unlock; scripts should re-unlock and retry.
- `401` without a code — actual auth failure. The browser will log
  out.
- `403` with body `{"code": "vault_key_invalid"}` — the key in the
  header doesn't match the canary. Usually means the vault was
  rotated since you unlocked. Re-unlock.
- `409` `vault_not_configured` — calling a credential endpoint before
  `setup`.
- `409` on `/setup` — already configured. Use `/change` to rotate
  instead.

---

## Audit log entries

Searchable from the Audit page in the UI. The actions added by v1.9.0:

| Action | Triggered by | Notable detail |
|--------|--------------|----------------|
| `cmdb_update` | metadata save | `device=…  fields=asset_id,documentation,…` |
| `cmdb_vault_setup` | vault creation | `kdf=pbkdf2-sha256` |
| `cmdb_vault_unlock` | successful unlock | source IP recorded |
| `cmdb_vault_unlock_failed` | bad passphrase | source IP recorded |
| `cmdb_vault_change` | rotation | `rotated_credentials=N` |
| `cmdb_vault_change_failed` | bad old passphrase on rotate | — |
| `cmdb_vault_change_drop` | unrecoverable cred during rotation | `device=… cred=… reason=decrypt_failed` |
| `cmdb_credential_add` | new cred | `device=… cred=… label=…` |
| `cmdb_credential_update` | edit | `fields=label,password,…` |
| `cmdb_credential_delete` | delete | — |
| `cmdb_credential_reveal` | plaintext returned | label included; source IP recorded |
| `cmdb_credential_reveal_failed` | decrypt failed despite valid key | usually means rotation desync |

The `_reveal` action is the one to grep for during incident response.

---

## File formats

### `cmdb.json`

```json
{
  "dev-abc123": {
    "asset_id":        "ASSET-00042",
    "server_function": "web",
    "hypervisor_url":  "https://esx1.local/",
    "documentation":   "# web-1\n\nServes the public-facing app...",
    "credentials": [
      {
        "id":         "cred_a1b2c3d4e5f60718",
        "label":      "root",
        "username":   "root",
        "note":       "console only",
        "nonce":      "0123456789abcdef01234567",
        "ct":         "deadbeef…aes-gcm-ciphertext-with-tag…",
        "created_by": "admin",
        "created_at": 1714200000,
        "updated_by": "admin",
        "updated_at": 1714200000
      }
    ],
    "updated_by": "admin",
    "updated_at": 1714200000
  }
}
```

`nonce` is hex-encoded 12 bytes. `ct` is hex-encoded AES-GCM
ciphertext including the auth tag. Everything else is plaintext.

### `cmdb_vault.json`

```json
{
  "kdf":           "pbkdf2-sha256",
  "iterations":    600000,
  "salt":          "32-bytes-of-hex-…",
  "canary_nonce":  "12-bytes-of-hex-…",
  "canary_ct":     "encrypted-canary-bytes-…",
  "created_at":    1714200000,
  "created_by":    "admin",
  "rotated_at":    1714300000,
  "rotated_by":    "admin"
}
```

No passphrase, no derived key, no plaintext anywhere. This file is
safe to back up alongside the rest.

---

## Limits

- 64 KB Markdown documentation per asset
- 25 credentials per asset
- 1 KB max password length (you should not have a 1 KB password)
- 64-char labels, 128-char usernames, 512-char notes
- `server_function`: 64 chars, charset `[A-Za-z0-9 _\-/]`
- Vault passphrase: 12–256 chars, ≥2 character classes

The 25-credentials cap is per-asset and arbitrary. If you legitimately
need more, the constant lives at `MAX_CMDB_CREDS` in `api.py` —
nothing's load-bearing about the number.

---

## Troubleshooting

**"vault not installed"** — the `cryptography` Python package is
missing. Re-run `install-server.sh`, or install it directly:
`pip3 install cryptography --break-system-packages` on Debian/Ubuntu/
Fedora, or `pip install cryptography` on Arch. The CMDB metadata
features keep working without it; only the credential endpoints fail.

**"invalid vault key" after a rotation** — the browser is still
holding the old derived key. Click **Lock**, then **Unlock** with the
new passphrase.

**Credentials list is empty but the count says 3** — usually means
the vault is configured but locked. Unlock it. The list endpoint
itself doesn't require a key, but if a previous response was cached
or the page was opened before unlock, refresh the asset modal.

**Rotation reports `dropped=N` for `N>0`** — `N` credentials had
ciphertext that didn't decrypt under the old key. Either someone
hand-edited `cmdb.json`, or a previous rotation crashed at exactly the
wrong moment. Check `cmdb_vault_change_drop` audit entries to see
which assets and which credential IDs. If you have a backup from
before the desync, restoring just those credentials from the old
file's `nonce`/`ct` is straightforward — the old passphrase still
decrypts them.

**Documentation preview looks wrong** — the renderer is deliberately
small. It supports headings, lists, code, bold, italic, and links.
Tables, images, and HTML blocks don't render — they show as escaped
text. This is on purpose: a richer renderer would mean an XSS audit
surface for what is essentially a text field.

---

## Implementation notes

If you want to read the code, the entry points are:

- `server/cgi-bin/cmdb_vault.py` — all the crypto. Lazy
  `cryptography` import, KDF, encrypt/decrypt, canary verification,
  passphrase validation. Self-contained, no `api.py` imports.
- `server/cgi-bin/api.py` — handlers and routing. Search for the
  comment `# ─── v1.9.0: CMDB ──` to find the section. Routes are
  declared in `main()` near the bottom in most-specific-first order
  so `/vault/status` doesn't get eaten by the generic
  `/cmdb/{device_id}` route.
- `server/html/index.html` — the UI. Search for `// ── v1.9.0: CMDB`
  for the JS, and `id="page-cmdb"` for the page markup. The vault key
  lives in the closure variable `_cmdbVaultKey`.
- `tests/test_v190.py` — 32 tests covering the lot. A reasonable
  starting point if you want to know what something is supposed to
  do.

The choice of PBKDF2 over Argon2id was pragmatic: PBKDF2 is in the
Python stdlib via `cryptography.hazmat.primitives.kdf.pbkdf2`, which
we already need for AES-GCM, and 600k iterations is the current OWASP
baseline. Argon2id would be marginally better but pulls in
`argon2-cffi` and the latency tradeoffs at homelab scale aren't
meaningful. If a future version moves to Argon2id, the `kdf` field in
`cmdb_vault.json` is there specifically so old vaults can still be
opened — the field is not decorative.
