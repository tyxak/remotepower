# Changelog

## v1.11.6 - 2026-05-03

### Bug fixes

**Audit log filter input had a duplicate event listener.** The `<input id="audit-filter-text">` had an inline `oninput="renderAuditLog()"` that fought with the listener `tableCtl.register()` had already attached. The race meant: on every keystroke, the inline handler re-rendered against the *previous* filter value (the one already in `_uiPrefs`), then tableCtl's listener captured the *new* value into prefs but the render had already happened. End result was a one-character lag, and after Clear-then-type-into-filter the data looked like nothing changed.

Fixed by removing the inline handler and adding a `refresh:` callback to `tableCtl.register({...})`. Pages that compose multiple filters (audit log's free-text + action dropdown is the only case today) supply their own re-render function; tableCtl calls it instead of the default `render(name, _lastRows)`. The same hook flows through sort changes, so multi-filter tables behave consistently for both filtering and sorting.

If you saw "clear history is broken" on the audit page or command history page in v1.11.5, this is the fix. The Clear button itself was always working — the visible symptom was that filter state from before the clear stayed sticky, so the table looked unchanged.

### New features

**Patch report got sortable column headers.** Click any column header to sort ascending; click again for descending; click a third time to clear. Patches kept its existing 3-control filter chain (text + group dropdown + device dropdown) — that filter system is bespoke and complex enough that wiring it through tableCtl's substring matcher would lose features. We added the sort wiring on top via tableCtl's `match: () => true` mode and a `refresh: () => renderPatchTable()` callback so the page composes both pipelines cleanly.

**Maintenance windows page got filter + sort.** New `<input id="maint-filter">` above the table (substring match across reason, scope, target, when, events, status). Headers wired up sortable via tableCtl. Same UX as the other tables.

**Filter + sort added to the admin tables: Users, API Keys, Command Library.** All three were inline one-liner functions in v1.11.5; refactored into the now-standard register-helper pattern. Each has a per-column `getColumns` that exposes sortable values (created timestamps, role strings, names) so headers sort correctly. Filter is substring across name/role/user-or-equivalent.

**"Minimal" density mode on the Devices grid — one device per row.** New 4th option in the Devices toolbar density toggle, alongside Compact / Comfortable / Spacious. Each device renders as a single horizontal row (~32px tall) with icon, name, hostname, status badge, and inline meta (OS, IP, Version, Poll/Enrolled). The colored top stripe on standard cards becomes a left border. Built for fleets where you want to scan 50+ devices at a glance without scrolling.

Responsive breakpoints drop the lower-priority meta items as the viewport narrows: Poll/Enrolled goes first (≤1100px), Version next (≤880px), then IP and the hostname (≤700px). The dropdown menu, status badge, and device actions all keep working — no markup change in `renderDevices()`, just CSS overrides on `.devices-grid.dens-minimal`.

### Schema additions

- `UI_DENSITY_VALUES` extends from `('compact', 'comfortable', 'spacious')` to `('minimal', 'compact', 'comfortable', 'spacious')`. `UI_DENSITY_DEFAULT` stays `'comfortable'` — minimal is opt-in.
- `tableCtl.register({...})` accepts a new optional `refresh` callback. When set, both filter-input changes and column-header clicks call `refresh()` instead of the default `render(name, _lastRows)`. Pages that expose multiple filters (free-text + dropdown) or layered filtering (patches' 3 controls) use this to compose pipelines without dropping into tableCtl's substring-only world.

### Tests

**425 passing** (420 from v1.11.5 + 5 new in `test_v1115.py`'s `TestMinimalDensityMode` class). Coverage: minimal-density round-trip through POST /api/ui-prefs, `'minimal' in UI_DENSITY_VALUES`, default unchanged at `'comfortable'`, regression checks for the existing three modes, and the allowlist still rejects unknown values like `'ultracompact'`.

### Compatibility

Drop-in upgrade from v1.11.5. No new dependencies, no nginx changes, no data migration. Existing user records keep their `'compact'`/`'comfortable'`/`'spacious'` density values intact. The new 4-button toggle renders selecting the user's existing 3-mode value correctly. Refresh the browser after deploying.

### Known limitations

- **Minimal mode is Devices-only for now.** The other tables remain in their existing card/table layouts. The `densityCtl` infrastructure is generic, so any table can opt in by adding the matching CSS — but I didn't proactively add it to every page because most of them are already tabular and have nowhere denser to go.
- **Patches and Audit retain their dropdown filters separately.** They aren't part of the persisted filter pref, so changing the dropdown selection isn't remembered across reloads. Substring filter and sort are persisted as before. If you want dropdown persistence too, that's a v1.11.7 follow-up.
- **The "stack" multi-column sort tooltip** isn't shown anywhere obvious. Users have to know about shift+click. Adding a small `?` hint near the column headers is on the v1.11.7 list.

---

## v1.11.5 - 2026-05-03

### New features

**Filter + sort on every fleet table.** Each of the main category pages — Devices, Services, CVE Findings, Containers, Monitor, TLS, Patches, Audit Log, Command History, Schedule, Maintenance — now has a substring filter input above the table. Click any column header to sort ascending; click again to flip to descending; click a third time to clear. Hold shift and click a second header to sort by it as a secondary key (priority shown as a small superscript). State persists per user — log in on a different browser, your filter and sort survive.

**Density toggle on the Devices grid.** Three modes — Compact, Comfortable (default), Spacious — picked via a small segmented control in the Devices toolbar. Compact halves the card padding, shrinks fonts, and tightens the grid gap; Spacious goes the other way for users on very large displays. Persists per user.

**Per-user UI preferences endpoint.** New `/api/ui-prefs` (GET / POST / DELETE). Stores density, filter strings, and multi-column sort state under the user's record in `users.json`. Schema sanitised on the server side — unknown fields are dropped, lengths capped, total payload bounded at 16 KB. Whole-document replacement (not patch) on POST so two tabs can't merge-conflict each other.

### How this is built

- **Server** — minimal: one new sanitiser function (`_sanitise_ui_prefs`), three thin handlers, three new routes. Stored under `users[username]['ui_prefs']` so password changes / user deletes automatically clean up the prefs.
- **Frontend** — two new helpers in `index.html`: `tableCtl` and `densityCtl`. Pages register a tbody with a column map and a row builder; the helper handles filter, sort, empty-state, and persistence. Existing inline render code refactored to use the helper. Server-roundtrip on every keystroke would be silly when filtering 50 rows, so filtering and sorting are fully client-side; only the pref values themselves go to the server, debounced 600 ms.
- **Empty-state messaging** — pages now distinguish "no data at all" from "no rows match the filter" so users don't think their fleet is empty when they typed `xyz` into the filter.

### Caps and limits (server-side)

- `MAX_UI_PREFS_BYTES = 16 * 1024` — total per user
- `MAX_UI_PREFS_FILTER_LEN = 256` — per-filter string
- `MAX_UI_PREFS_SORT_KEYS = 5` — multi-column sort depth
- `MAX_UI_PREFS_TABLES = 50` — distinct tables we'll remember prefs for

### New endpoints

- `GET /api/ui-prefs` — current user's stored prefs (returns `{}` if none).
- `POST /api/ui-prefs` — replace current user's prefs. Body is the full document; whatever's not in the body is gone after the request. Returns `{ok, prefs}` with the sanitised version.
- `DELETE /api/ui-prefs` — wipe current user's prefs.

### Modified data files

- `users.json` — entries gain an optional `ui_prefs` field. Old user records without it work fine; the field is created lazily on first POST. Removed automatically when `DELETE /api/users/{name}` runs (no extra cleanup code needed — the field lives inside the user record).

### Tests

**420 passing** (397 from v1.11.4 + 23 new in `test_v1115.py`). Coverage:

- `_sanitise_ui_prefs` — non-dict input returns `{}`; valid density round-trips; invalid density dropped; filter strings truncated to cap; sort lists capped to 5 keys; invalid sort directions default to `asc`; unknown table fields stripped silently; table names with `/` `\` `..` characters sanitised; empty-after-sanitisation table names dropped; >50 tables capped at 50; payloads exceeding 16 KB total return `{}` (no partial save); realistic round-trip preserved.
- `GET /api/ui-prefs` — returns `{}` for fresh user; returns persisted dict after POST.
- `POST /api/ui-prefs` — replaces (not merges) on subsequent calls; sanitises input; rejects non-object body with 400; requires auth; rejects wrong HTTP method with 405.
- `DELETE /api/ui-prefs` — clears stored prefs; subsequent GET returns `{}`; method check.
- Per-user isolation — User A's prefs invisible to User B and vice versa.

### Compatibility

Drop-in upgrade from v1.11.4. No new dependencies. No nginx changes. No data migration — `users.json` records without a `ui_prefs` field work identically to before. Older clients that don't know about `/api/ui-prefs` simply don't see filter/sort persistence; the fallback in the frontend gracefully proceeds with empty prefs if the endpoint returns nothing.

The frontend is the same `index.html` file — no new build step, no Node, no bundler. Refresh the browser after deploying.

### Known limitations

- **Devices density only — for now.** The other tables (services / CVEs / monitor / etc.) all sort and filter, but they don't yet have the three-mode density toggle. The plumbing is there (`densityCtl` works for any table name) but I haven't added the controls or CSS to those pages. Easy follow-up if you want it.
- **Filter is substring only.** No regex, no field-scoped filters (`name:foo group:prod`). The dropdown filters that already exist on some pages (status, group, severity) keep working as before; this change is additive.
- **Sort is in-memory only.** Loading 10,000 audit log entries and sorting them is fine in the browser, but loading 100,000 might lag on weak hardware. Pagination lives in the API for the audit log already; if you really hit that, we'd need server-side sorting. Not for v1.11.5.
- **Two tabs racing.** Whole-document replacement means if you have two tabs open and change filter in one, the other tab's older state could overwrite it on its next save. Compare-and-swap would fix this but adds complexity for a workflow nobody seems to actually have. Filed under "if it becomes a problem."

---

## v1.11.4 - 2026-05-03

### Bug fixes

**Container data went stale and never refreshed.** The agent's container-listing path silently skipped sending the heartbeat field whenever the list was empty (`if items: payload['containers'] = items`). Hosts that went from "1 container running" to "0 containers running" — daemon restarts, transient `docker ps` failures, or just somebody running `docker stop` on the last container — never overwrote the server's stored list. The Containers page kept rendering whatever last non-empty snapshot the agent had reported, in some cases for days.

Fixed by always sending the (possibly empty) list when a runtime is installed on the host. The server's existing ingest path (`api.py:1643`) already handled empty lists correctly — the bug was purely on the agent side. Hosts with no runtime installed at all still skip the field entirely, so we don't pollute `containers.json` with empty rows for machines that never had Docker.

If your dashboard currently shows ancient container snapshots, the fix takes effect on the first heartbeat after the agent self-updates (≤1 hour, or push from the dashboard ↺ button).

### New features

**Container alerts.** Three new webhook events:

- `container_stopped` — fires when a previously-running container is gone or its status flipped from running to exited/dead/terminated. Detected by diffing each heartbeat against the previous one.
- `container_restarting` — fires when a container's `restart_count` climbed by 1 or more since the last report. Mainly useful for Kubernetes pods (Docker `ps` doesn't expose restart counts without `inspect`).
- `containers_stale` — fires when a device hasn't sent fresh container data within `container_stale_ttl` seconds (default 900s = 15 min). Fired once per stale period; auto-resets when fresh data arrives. Skipped for already-offline devices (the existing `device_offline` webhook covers those) and for devices with `monitored=false`.

All three default to enabled, respect the existing per-event toggle in Settings → Notifications, and route through the same `fire_webhook()` machinery — so they work with Ntfy, Gotify, Pushover, Slack, Discord, and generic JSON receivers without further wiring. Discord embeds use red for stopped, amber for restarting / stale.

**Stale-data UI indicators.** The Containers page tags each row with an amber `STALE` pill and dims the row when its last heartbeat is over the TTL. The per-device modal shows a banner explaining what stale means and suggesting `journalctl -u remotepower-agent` as the first place to look.

### New config keys

- `container_stale_ttl` — seconds before a device's container data is considered stale. Default 900 (15 min). Range 300–86400. Floors at 300s at read time even if the stored value is lower (prevents alert-storms from misconfiguration).

### New endpoints / response fields

- `GET /api/containers` — each entry now includes `is_stale: bool`.
- `GET /api/devices/{id}/containers` — response now includes `is_stale: bool` and `stale_ttl: int`.
- `DELETE /api/devices/{id}/containers` — admin-only. Clears the stored container snapshot for one device. The agent will repopulate on its next heartbeat (~5 min). Useful when (a) decommissioning a device but keeping the device record, (b) you've deliberately removed containers via `docker rm` and don't want to wait for the next heartbeat to refresh, or (c) you want to re-arm the `containers_stale` webhook after acknowledging an old stale alert (the notified flag is also cleared). Returns `{ok, cleared}` where `cleared` is true if there was actually an entry to remove.
- `POST /api/config` — accepts `container_stale_ttl` (300–86400 seconds).

### Modified behaviour

- `DELETE /api/devices/{id}` — also cleans up `containers.json` and the `containers_stale_notified` flag for the deleted device. Pre-v1.11.4 these orphans lingered indefinitely; if you re-enrolled a device with the same id, you'd inherit ghost container data from its previous life. (Cleanup is best-effort: if any of the cleanup steps throws, the device delete still succeeds.)

### Modified data files

- `config.json` — gains `container_stale_ttl` (optional, defaults to 900) and `containers_stale_notified` (internal — tracks which devices already received a stale-alert, cleared on fresh report). Both fields are stripped from `GET /api/config` responses where appropriate.

### Webhook event registry order

The three new events are inserted between `log_alert` and `command_queued` in the `WEBHOOK_EVENTS` tuple. The Settings page renders toggles in tuple order, so the new events appear at the bottom of the alert section above the audit-trail section.

### Tests

**397 passing** (362 from v1.11.3 + 35 new in `test_v1114.py`). Coverage:

- `containers.is_stale` — boundary cases (zero timestamp, just under/over threshold, garbage input, default TTL constant).
- `process_container_report` — first-report-no-fire, container-vanished, status-flip-to-exited, already-stopped-stays-quiet, restart-count-delta, no-restart-no-fire.
- The empty-list bugfix end-to-end: a heartbeat with `containers: []` clears previously-stored entries.
- `check_container_webhooks` — fresh-report-quiet, stale-report-fires-once, offline-device-skipped, unmonitored-device-skipped, notified-flag-deduplication.
- API responses expose `is_stale` and `stale_ttl` correctly.
- Heartbeat clears `containers_stale_notified` on fresh report (closes the loop).
- `get_container_stale_ttl` floors at 300s, clamps garbage to default.
- `DELETE /api/devices/{id}/containers` — happy path, idempotency, 404 on unknown device, admin-required.
- `DELETE /api/devices/{id}` cleans up `containers.json` and the stale-notified flag (no orphan leaks on re-enrollment).
- One contract test (`test_v184.test_expected_event_set`) updated to reflect the three new webhook events.

### Compatibility

Drop-in upgrade from v1.11.3. No new dependencies. No nginx changes. No data migration — the new config key has a default, the new internal `containers_stale_notified` field is created lazily on first stale alert, and devices with no `is_stale` field in older clients will simply not show the badge until they self-update.

The webhook payload schema for `container_stopped` and `container_restarting` is new (no v1.11.3 listener can have been built against it), so no breakage there. Existing webhook receivers will start seeing extra event types, which Ntfy / Gotify / Slack / Discord all handle gracefully (each event has its own title and tags).

### Known limitations

- **Restart-count alerts are essentially Kubernetes-only.** The agent reads `docker ps` output, which doesn't include restart counts. Adding `docker inspect` per container would be one syscall per container per heartbeat — fine for 5 containers, painful for 50. If you really want Docker restart alerts, run `docker events` to a separate log shipper.
- **`container_stopped` can't distinguish "stopped" from "removed and recreated quickly".** If a container restart happens between heartbeats so the new instance has a different ID but the same name, we see the old one disappear and the new one appear — and we fire `container_stopped` for the disappearance. In practice this is an alert for "something restarted suspiciously" which is usually what you want anyway, but be aware.
- **No history.** Container state is overwritten on every heartbeat. Webhook log retains the alerts (`webhook_log.json`, last 100 entries), but if you need full timeline, point Prometheus at `/metrics` and let it do its thing.

---

## v1.11.3 - 2026-04-30

### New features

**STARTTLS support in the TLS monitor.** Probe SMTP / IMAP / POP3 / LDAP services that upgrade to TLS via a plaintext negotiation step rather than running TLS from byte zero. Adds an "Auto-detect from port" option (default for new targets — port 25 / 587 / 2525 → SMTP; 143 → IMAP; 110 → POP3; 389 → LDAP; everything else → direct TLS). Each protocol can also be picked explicitly for non-standard ports.

The big one this unblocks: **DANE/TLSA checks against mail servers**. DANE was originally designed for SMTP, and most DANE-published TLSA records out there are for `_25._tcp.mail.example.com`. The v1.11.2 DANE feature couldn't actually probe these because it spoke immediate TLS to port 25. Now it can.

### What works, what doesn't

- ✓ SMTP STARTTLS — EHLO + STARTTLS handshake, full reply parsing
- ✓ IMAP STARTTLS — A001 STARTTLS command, reply parsed for OK
- ✓ POP3 STLS — STLS command, reply parsed for +OK
- ✓ LDAP StartTLS — extended request OID 1.3.6.1.4.1.1466.20037, hand-encoded BER (no `ldap3` dependency)
- ✓ Auto-detect for the well-known ports listed above
- ✗ XMPP (`<starttls/>`) — not implemented; rare in homelab use
- ✗ FTP `AUTH TLS` — not implemented; rare and FTP-over-TLS adoption is low
- ✗ NNTP STARTTLS — not implemented

If you have a service speaking one of the unsupported protocols and want it added, the handler pattern is small: ~15 lines in `tls_monitor.py` per protocol. PRs welcome.

### Modified endpoints

- `POST /api/tls/targets` — accepts new `starttls` field (`"auto"` / `"none"` / `"smtp"` / `"imap"` / `"pop3"` / `"ldap"`)
- `GET /api/tls/targets` — response includes the resolved `starttls` value per target

### Modified data files

- `tls_targets.json` — gains optional `starttls` field. Records without it default to `"auto"` on next read, which means **v1.11.2 targets at port 25 / 587 / 143 / 110 / 389 will start working correctly without any manual reconfiguration**.

### UI changes

- New "STARTTLS protocol" dropdown in the Add TLS target modal
- TLS list table shows a small `SMTP` / `IMAP` / `POP3` / `LDAP` badge in the host column when the protocol isn't `none`
- Detail modal shows a STARTTLS row when a non-none protocol is in use

### Tests

**362 passing** (347 from v1.11.2 + 15 new). New tests cover: parse_target STARTTLS validation and auto-detection across all six well-known ports, default-to-auto behaviour for missing field (backwards compatibility), invalid-protocol rejection, end-to-end probe against a local SMTP-with-STARTTLS server (full handshake), end-to-end IMAP, end-to-end POP3, server-refusal-of-STARTTLS landing in `tls_error` cleanly, direct-TLS on a STARTTLS port failing without crashing.

The end-to-end tests spin up real socket servers in threads with self-signed certs minted in-memory — so the bytes the prober actually sends through the STARTTLS handshakes are tested for real, not just the field-validation logic.

### Compatibility

Drop-in upgrade from v1.11.2. Existing targets without the `starttls` field default to `auto` on next read — meaning targets at port 25 / 587 / 143 / 110 / 389 that were previously **broken** (immediate TLS on a STARTTLS port) will start **working** automatically. Direct-TLS targets at port 443 / 465 / 993 / etc. continue to work exactly as before.

No new dependencies. No new request headers. No nginx changes.

### Known limitations

- The SMTP STARTTLS handler sends the SNI hostname in EHLO. Some pedantic servers reject EHLO from an IP-shaped argument. This shouldn't matter for normal use (you'd rarely set `host` to a bare IP for an SMTP target — that breaks the cert hostname match anyway), but worth knowing.
- LDAP StartTLS uses a hand-encoded BER message rather than `ldap3`. The encoded bytes are correct for LDAPv3 ExtendedRequest with the standard StartTLS OID, but unusual LDAP servers that require additional pre-StartTLS setup (binding, sending a different MessageID, etc.) won't work. PRs welcome.
- The connection timeout is shared across the STARTTLS handshake and the TLS handshake (5+5 seconds, same as v1.11.2). A slow SMTP server doing greylist delays could blow this budget. Bump `CONNECT_TIMEOUT_S` and `HANDSHAKE_TIMEOUT_S` in `tls_monitor.py` if needed.

---

## v1.11.2 - 2026-04-30

### New features

**Shared link dashboard.** New "Links" page in the sidebar — a simple bookmark dashboard, shared across admins. Card grid grouped by category. Each link has title, URL, optional description, optional category (defaults to "Uncategorised"), and an internal/external scope flag. Internal links (LAN-only, behind VPN) get an amber dashed border; external links get an accent solid border — same colour language as the network map. Click any card to open in a new tab; "Edit mode" toggle reveals edit/delete buttons. Free-text search and scope filter at the top.

**TLS monitor: connect address override.** New optional `connect_address` field on TLS targets. Connect to a specific IP while sending the configured hostname as SNI. Useful for probing internal certs by IP when DNS doesn't resolve from the server's network position. Empty = "use hostname for DNS lookup" (the v1.11.0 behaviour). The detail modal shows a "via &lt;address&gt;" line when overridden, and the row gets a small subtitle in the host column.

**TLS monitor: DANE/TLSA checks.** New optional `dane_check` flag per target. When enabled, looks up `_PORT._tcp.HOSTNAME` for TLSA records via DNSSEC, validates the AD flag on the response, and compares the cert against the published records. Status reported as one of `ok` / `missing` / `insecure` / `mismatch` / `error`. Without DNSSEC, records are explicitly NOT trusted (status = `insecure`) — DANE without DNSSEC is theatre. Detail modal shows the published TLSA records (usage / selector / matching_type / data) for debugging.

**TLS monitor: hostname-vs-cert match.** Now reported separately from full-chain verification. Lets you distinguish "wrong cert" from "right cert, wrong IP" when probing by `connect_address`. Wildcard handling per RFC 6125; falls back to the cert CN when SANs are absent (legacy certs).

### New endpoints

- `GET /api/links` — list + distinct-category summary
- `POST /api/links` — admin creates a link
- `PUT /api/links/{id}` — admin updates
- `DELETE /api/links/{id}` — admin deletes

### Modified endpoints

- `POST /api/tls/targets` — accepts `connect_address` and `dane_check`
- `GET /api/tls/targets` — response now includes the new fields plus DANE result, hostname match, connect_address echo

### New / modified data files

- `links.json` — new file, keyed by `lnk_<hex>` IDs
- `tls_targets.json` — gains `connect_address` (string) and `dane_check` (bool) on records that opt in
- `tls_results.json` — gains `connect_address`, `hostname_match`, `dane_status`, `dane_records`, `dane_error`

### New dependency

- `dnspython` — only required for DANE checks. The TLS expiry monitor and everything else still work without it. `install-server.sh` adds it via pip with a distro-package fallback (`python3-dnspython` / `python3-dns` / `python-dnspython`); Dockerfile pulls it via pip.

### Tests

**347 passing** (319 from v1.11.1 + 28 new). New tests cover: link CRUD with URL/scope validation (rejects javascript:/ftp://, oversize, quote-injected URLs), parse_target backwards compatibility plus connect_address and dane_check, hostname matching (exact SAN, wildcard, CN fallback, case-insensitive, empty inputs), TLSA cert matching across selector × matching_type combinations using a real in-memory generated cert, and DANE check shape consistency.

### Compatibility

Drop-in upgrade from v1.11.1. Existing TLS targets without `connect_address`/`dane_check` continue to work unchanged. Records without DANE simply don't get checked — status field reads `not_checked`. No new request headers; no nginx changes.

### Known limitations

- DANE checks query the system resolver. If your `/etc/resolv.conf` points at a non-DNSSEC-validating resolver, all checks return `insecure` regardless of the upstream DNS. For Fedora server use systemd-resolved with DNSSEC=allow-downgrade or yes; for Debian/Ubuntu unbound is the easy choice.
- The DANE checker only compares against the leaf cert, not the chain. So `usage=2` (DANE-TA, trust-anchor) records that point at a CA cert will report `mismatch` even when valid. Most homelab DANE setups use `usage=3` (DANE-EE, end-entity) which is what we handle correctly.
- The connect-address feature only changes where we connect — it does NOT change SNI. The hostname is always sent as SNI in the handshake, and the cert is parsed from whatever the server presents. Probing `192.168.1.1` with `host=router.lan` gets you the cert your router serves for `router.lan`.

---

## v1.11.1 - 2026-04-30

### New features

**Network map: drag to reposition + persist.** Click and drag any node to move it. Positions are saved to the server (per-device `pos_x`/`pos_y` fields) and survive refresh. Debounced save (400ms) batches multi-node drags into a single API call. New "Reset positions" button reverts everything to the auto-layout.

**Network map: tunnels.** A second kind of edge — peer links between two devices, drawn as dashed amber lines. Use them for VPN tunnels, site-to-site links, or anything else that isn't physical wiring. New "Tunnels" button on the Network page opens a modal to add/remove. No protocol/type/label complexity in this release — just "these two devices have a tunnel."

### New endpoints

- `PUT /api/network-map/positions` — batch save, accepts `null` to clear
- `GET /api/network-map/tunnels` — list (filters dangling endpoints)
- `POST /api/network-map/tunnels` — add (normalises endpoint order, rejects duplicates)
- `DELETE /api/network-map/tunnels/{id}` — remove

### Modified endpoints

- `GET /api/network-map` — response now includes `pos_x`/`pos_y` per node and a top-level `tunnels` array

### New / modified data files

- `tunnels.json` — new file, keyed by `tun_<hex>` IDs
- `devices.json` — gains `pos_x`/`pos_y` (optional ints) on records the user has dragged

### Tests

**319 passing** (303 from v1.11.0 + 16 new). New tests cover position batch save / clear / validation, position out-of-range rejection, unknown-device skipping, network-map surfacing of positions, tunnel add / canonical ordering / duplicate detection in either direction, self-tunnel rejection, unknown-endpoint rejection, wrong-shape rejection, delete + 404, and dangling-endpoint filtering.

### Compatibility

Drop-in upgrade from v1.11.0. Existing devices without `pos_x`/`pos_y` fall back to the auto-layout exactly as before. No new request headers, no nginx changes.

---

## v1.11.0 - 2026-04-29

### New features

**Containers (Docker / Podman / Kubernetes)** — visibility-only
- New sibling module `containers.py`: validation, normalisation, summarise()
- Agent detects Docker, Podman, and kubectl independently; each runtime is probed in a try/except so a stuck or absent runtime can't break the heartbeat
- Agent posts a normalised list of up to 100 entries every 5 polls (~5 minutes at default cadence)
- Server stores last-seen list per device (overwrite on every heartbeat — no history)
- New "Containers" page in the sidebar shows fleet-wide overview with per-device drill-down: image, tag, status, restart count, ports, runtime, namespace
- Read-only — no start/stop/exec/logs. That's Portainer's job. RemotePower's job is "what's running and is it healthy"
- Endpoints: `GET /api/containers` (fleet overview), `GET /api/devices/{id}/containers` (full list)

**Network map** — manual topology view
- New `connected_to: <device_id>` field on every device record
- New "Network" page renders a force-laid-out node-and-edge graph; nodes coloured by online status, outlined by agent vs. agentless
- "Edit links" modal lets admins set the `connected_to` for every device in one place; saves them in batch
- Endpoints: `GET /api/network-map`, `PUT /api/devices/{id}/connected-to`
- Agentless devices included automatically once they exist

**Agentless devices** — track what can't run an agent
- New `POST /api/devices/agentless` creates a device record with `agentless: True`, no token, no heartbeat
- Same CMDB metadata, same vault credentials, same SSH-link feature as agented devices
- 15 device types validated server-side: switch, router, firewall, AP, printer, camera, IPMI, UPS, PDU, NAS, IoT, smart plug, phone, other
- Online status is whatever the user sets it to (`manual_status: True/False`); no probing
- "+ Agentless device" button in the Devices page toolbar
- Endpoints: `POST /api/devices/agentless`

**TLS / DNS expiry monitor** — server-side cron-driven probes
- New sibling module `tls_monitor.py`: stdlib-only TLS probe, DNS resolution check, status thresholds
- Each probe: TCP connect (5s timeout), TLS handshake (5s timeout), parse cert, separate verification pass against system trust store
- Watchlist + last-result storage in `tls_targets.json` and `tls_results.json`
- Default thresholds: warn at 14 days, critical at 3 days; per-target overrides
- New cron runner `cgi-bin/remotepower-tls-check` for periodic scanning (recommended: every 6 hours)
- New "TLS / DNS" page lists targets with status colour, days-left, expiry date, issuer, last check
- Detail modal shows full cert info: issuer, subject, SAN, DNS A/AAAA, all error states
- Endpoints: `GET /api/tls/targets`, `POST /api/tls/targets`, `DELETE /api/tls/targets/{id}`, `POST /api/tls/scan`

### Internal / fixes

- **Dockerfile fixed**: was only copying `api.py`, missing all sibling modules since v1.9.0 (`cmdb_vault`, `cve_scanner`, etc.). Now copies the entire `server/cgi-bin/` directory. Docker deployments of v1.9.0 and v1.10.0 had a broken CMDB feature; this is the fix.
- **install-server.sh fixed**: was also only installing `api.py`, missing all sibling modules. Now auto-discovers all `.py` files plus the v1.11.0 helper scripts.
- **deploy-server.sh** updated to deploy the new `remotepower-tls-check` cron helper alongside the Python modules.
- Container output cap on the agent already allowed 256 KB for upgrade commands (v1.10.0); container listings are tiny by comparison and use the standard 4 KB cap.

### New files

- `server/cgi-bin/containers.py` — container normalisation
- `server/cgi-bin/tls_monitor.py` — TLS/DNS probe logic
- `server/cgi-bin/remotepower-tls-check` — cron runner
- `tests/test_v1110.py` — 33 new tests across 7 test classes

### New / modified data files

- `containers.json` — keyed by device_id, last-seen list per device (state, not history)
- `tls_targets.json` — watchlist, keyed by `tls_<hex>` IDs
- `tls_results.json` — last probe result per target ID
- `devices.json` — gains `agentless: bool`, `connected_to: <device_id>`, `device_type: str`, `manual_status: bool` on relevant records (backwards-compatible: missing fields default to empty)

### Tests

**Full suite: 301 passing, 0 failing** (268 from v1.10.0 + 33 new). New tests cover containers normalisation + summarise + caps, TLS target validation + thresholds + days-until-expiry, heartbeat acceptance and overwrite behaviour, container endpoints, network map shape + edge dropping, connected-to validation (self-link, nonexistent target, clearing), agentless device creation + validation + flag surfacing, TLS targets CRUD.

### Compatibility

- v1.10.0 servers/agents are forwards-compatible with v1.11.0 servers/agents in either direction
- Existing devices.json records work unmodified (new fields default to empty)
- Containers feature requires v1.11.0 agent to populate (older agents simply don't post the field)
- TLS monitor requires no agent involvement
- No new request headers — existing nginx config works unchanged

### Suggested cron / systemd timer

```
0 */6 * * * www-data /var/www/remotepower/cgi-bin/remotepower-tls-check
```

Or as a systemd timer in `/etc/systemd/system/remotepower-tls-check.timer`:

```ini
[Unit]
Description=RemotePower TLS expiry probe

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
```

---

## v1.10.0 - 2026-04-29

### New features

**Swagger / OpenAPI** — interactive API documentation
- New `openapi_spec.py` sibling module: hand-written OpenAPI 3.1 spec covering 22 endpoints across 7 tags (Auth, Devices, Commands, CMDB, Vault, Credentials, Reporting)
- `GET /api/openapi.json` returns the spec (auth-gated)
- New page `/swagger.html` renders Swagger UI from a pinned CDN with the user's session token auto-injected so "Try it out" works without re-authenticating
- "API Docs" link in the sidebar

**SSH link from credentials** — connect directly from the web UI
- New per-asset `ssh_port` field in CMDB record (default 22, validated 1-65535)
- Each credential row in the Credentials tab gets an SSH button: clickable `ssh://user@host:port` URI for handlers that support it (PuTTY, iTerm, Terminal.app), plus a "Copy" button that copies `ssh user@host -p port` to the clipboard
- Password is **never** included in the URI — it stays in the reveal modal where it belongs

**OS icons on Devices and CMDB pages**
- Two icons total: Linux (Tux) and Windows. Inline SVG, uses `currentColor` so it inherits the surrounding text colour
- Linux detection covers Ubuntu, Debian, Fedora, RHEL/Rocky/CentOS/AlmaLinux, Arch, CachyOS, Manjaro, Alpine, openSUSE, Mint, Pop!_OS, Gentoo, Slackware, NixOS, plus any agent string containing "linux" or "gnu"
- Windows detection covers any agent string containing "windows", "microsoft", "win10", or "win11"
- Anything else gets a question-mark glyph so detection failures are visually obvious rather than silent
- Icons appear on the device card OS field and the CMDB asset table name column

**Update history** — see what `apt`/`dnf`/`pacman` actually said
- New `update_logs.json` rolling buffer, capped at 10 runs per device
- `GET /api/devices/{id}/update-logs` endpoint surfaces the history
- Heartbeat handler dual-routes upgrade output: lands in both `cmd_output.json` (existing) and `update_logs.json` (new)
- "Update history" link added to the device dropdown menu opens a modal with collapsed/expanded run output, exit codes, durations, and per-run package manager
- Agent: bumped output cap from 4 KB to 256 KB for upgrade commands so `apt -y upgrade` output isn't truncated mid-package

**Audit log filtering**
- Free-text search box matches across actor / action / detail
- Action-type dropdown auto-populated from the distinct actions in the data
- Both filters work client-side; data is loaded once per page visit

### Code quality / "enterprise-ish" pass

- New `pyproject.toml` configures `black` (line length 100), `isort` (black profile), and `mypy` (strict on `cmdb_vault` and `openapi_spec`, permissive on the legacy `api.py` until a separate refactor)
- New `Makefile` with `make test`, `make lint`, `make format`, `make typecheck`, `make check`, `make install-dev`, `make clean`
- `HTTPError` exception pattern replaces `respond(); sys.exit(0)` — handlers are now testable as plain function calls; no more `SystemExit` shenanigans in test helpers (the legacy helpers monkey-patched `respond` and continue to work)
- Type hints + Google-style docstrings on the v1.9.0 CMDB handlers and the new v1.10.0 endpoints
- `cmdb_vault.py` and `openapi_spec.py` pass strict mypy + black + isort

### Bonus / smaller items

- **Sysinfo trim on CMDB GET** — `_trim_sysinfo()` reduces the per-asset payload from 50+ KB to under 1 KB by whitelisting just the fields the modal actually displays
- Type hints on `cmdb_vault.py`'s public surface tightened: `validate_passphrase` now declares `'str | None'`, `_crypto` declares `tuple` return
- **Deploy fixes**: `deploy-server.sh` and `install-server.sh` now auto-discover all `server/html/*.html` files (was hardcoded to `index.html`); the Dockerfile copies the whole `server/html/` directory. Without this, the new `swagger.html` would not be deployed and the API Docs page would 404.
- **Swagger token fix**: the Swagger UI page reads the session token from the correct `localStorage.rp_token` / `sessionStorage.rp_token` key (was reading non-existent `remotepower-token` keys, causing every visitor to see "Not logged in" even when authenticated on the dashboard).

### New endpoints

- `GET /api/openapi.json` — OpenAPI 3.1 spec
- `GET /api/devices/{device_id}/update-logs` — rolling buffer of upgrade output

### Modified endpoints

- `PUT /api/cmdb/{device_id}` — accepts new `ssh_port` field
- `GET /api/cmdb` — response includes `ssh_port`
- `GET /api/cmdb/{device_id}` — response includes `ssh_port`; `sysinfo` now trimmed

### New files

- `server/cgi-bin/openapi_spec.py` — handwritten OpenAPI 3.1 spec
- `server/html/swagger.html` — Swagger UI page
- `pyproject.toml` — black/isort/mypy config
- `Makefile` — developer convenience targets
- `tests/test_v1100.py` — 24 new tests across 6 classes

### Tests

**Full suite: 268 passing, 0 failing** (244 from v1.9.0 + 24 new). The new tests cover: `HTTPError` raising and rendering, ssh_port default + validation + persistence + list surfacing, sysinfo trim (whitelist + non-dict input), update logs (empty / runs in order / 404 / capacity cap), OpenAPI spec building (structural validity, security schemes, critical endpoints documented, fresh objects), and tooling files exist.

### Compatibility

- **Backwards-compatible.** v1.9.0 servers work with v1.10.0 clients and vice versa. CMDB records without `ssh_port` are backfilled with the default at GET time.
- **Agent compatibility.** v1.10.0 agents are required only if you want the full 256 KB upgrade output cap; older agents work fine but truncate at 4 KB.
- **Data files.** `update_logs.json` is created lazily on first heartbeat with `cmd_output` matching an upgrade command. No migration needed.

### Known limitations

- Update logs are populated only after the next heartbeat (~60s). No live streaming — that's a separate feature involving long-polling or SSE that wasn't worth the complexity for this release.
- Swagger UI assets load from CDN. On fully-offline servers the page falls back to a plain-text "raw spec is at /api/openapi.json" message.
- `make lint` only checks the v1.10.0 baseline files. Full-codebase formatting is deferred to avoid an unreviewable diff in this release.

---

## v1.9.0 - 2026-04-27

### New features

**CMDB — Configuration Management Database** — per-asset metadata and encrypted credentials, scoped to enrolled devices
- New "CMDB" page in the sidebar nav, between Devices and Monitor
- Per-asset fields: free-text **asset_id** (inventory tag), **server_function** (web, db, dc, …) with autocomplete from existing fleet values, optional **hypervisor_url** rendered as link, and **Markdown documentation** (≤64 KB) with edit/preview tabs
- Search box filters across name, asset_id, IP, function, and documentation; function dropdown narrows by exact match
- Asset table joins `devices.json` with the new `cmdb.json` — every enrolled device implicitly has an empty CMDB record, no separate enrollment step

**Encrypted credential vault** — multiple credentials per asset (root, service accounts, IPMI, …)
- Symmetric crypto: **AES-GCM 256-bit**, key derived via **PBKDF2-SHA256** with 600 000 iterations (OWASP 2023 minimum), 32-byte random salt, 12-byte random nonce per encryption
- **Shared admin passphrase** — set once, all admins use the same passphrase; rotation re-encrypts every credential atomically
- Passphrase is **never persisted server-side**: admin enters it via the unlock modal, server returns the derived key, browser holds it in a single closure variable in JS memory and clears it on logout, page reload, or explicit "Lock" button
- Subsequent credential ops send the key in an `X-RP-Vault-Key` request header
- Encrypted canary blob in `cmdb_vault.json` lets the server verify a candidate key without touching real credentials
- Per-credential metadata (label, username, note) is plaintext for searchability; only the password is encrypted; revealed credentials never appear in `cmdb.json` outbound responses
- **Reveal is admin-only and audit-logged** with actor, source IP, asset, credential label
- Hard caps: 25 credentials per asset, 1 KB max password, 64-char labels, 128-char usernames, 512-char notes
- All vault crypto lives in `cmdb_vault.py` (sibling module, lazy `cryptography` import) — the rest of the API stays alive even if `cryptography` is missing

### New endpoints

- `GET    /api/cmdb` — list assets joined with CMDB metadata; `?q=` and `?function=` filters; credentials returned as count only
- `GET    /api/cmdb/{device_id}` — full asset detail (credentials redacted)
- `PUT    /api/cmdb/{device_id}` — patch asset_id / server_function / hypervisor_url / documentation
- `GET    /api/cmdb/server-functions` — distinct server_function values for the autocomplete datalist
- `GET    /api/cmdb/vault/status` — vault configured? KDF? created_at/by?
- `POST   /api/cmdb/vault/setup` — admin; one-shot, fails 409 if already configured; returns derived key
- `POST   /api/cmdb/vault/unlock` — any auth user; returns derived key on success, 403 + audit on bad passphrase
- `POST   /api/cmdb/vault/change` — admin; rotates passphrase and re-encrypts all credentials atomically
- `GET    /api/cmdb/{device_id}/credentials` — metadata only (no ciphertext, no plaintext)
- `POST   /api/cmdb/{device_id}/credentials` — admin + `X-RP-Vault-Key`; encrypt and store
- `PUT    /api/cmdb/{device_id}/credentials/{cred_id}` — admin; key required only if password is changing
- `DELETE /api/cmdb/{device_id}/credentials/{cred_id}` — admin
- `POST   /api/cmdb/{device_id}/credentials/{cred_id}/reveal` — admin + key, **audit-logged**, returns plaintext

### New data files

- `cmdb.json` — keyed by device_id; per-asset record with metadata, documentation, and credentials list (each credential is `{id, label, username, note, nonce, ct, created_by/at, updated_by/at}`)
- `cmdb_vault.json` — vault metadata only: `{kdf, iterations, salt, canary_nonce, canary_ct, created_by/at, rotated_by/at}`. Contains zero plaintext, zero key material; safe to back up.

### New audit-log actions

`cmdb_update`, `cmdb_vault_setup`, `cmdb_vault_unlock`, `cmdb_vault_unlock_failed`, `cmdb_vault_change`, `cmdb_vault_change_failed`, `cmdb_vault_change_drop`, `cmdb_credential_add`, `cmdb_credential_update`, `cmdb_credential_delete`, `cmdb_credential_reveal`, `cmdb_credential_reveal_failed`

### New dependency

- `cryptography` (Python) — installed automatically by `install-server.sh` via pip with distro-package fallback (`python3-cryptography` on Debian/Ubuntu/Fedora, `python-cryptography` on Arch). Vault is the only feature that requires it; without it, asset metadata still works.

### Changed

- All version strings bumped to 1.9.0
- Sidebar gains a CMDB button (database icon) directly after Devices
- `install-server.sh` adds a cryptography install block mirroring the bcrypt/reportlab pattern

### Tests

**Full suite: 244 passing, 0 failing** (1 pre-existing skip). 32 new tests in `tests/test_v190.py` covering: PBKDF2 + AES-GCM round-trips, fresh-nonce-per-encrypt, canary verification, parse_key_header strictness, full vault lifecycle (setup → unlock → status → wrong passphrase → audit), asset CRUD (404s, asset_id charset, hypervisor URL scheme, oversized documentation), search filtering, credential add/list/update/delete/reveal, redaction of ciphertext from list endpoint, vault-locked vs auth-locked 401 distinction, max-credentials cap, and full passphrase rotation with credential re-encryption.

### Compatibility

- v1.8.x servers work with v1.9.0 clients (CMDB is server-side only — agent binary unchanged)
- v1.9.0 server starts cleanly on a v1.8.6 data directory: `cmdb.json` and `cmdb_vault.json` are created on first write
- Vault is opt-in: feature works in read-only mode (asset metadata only) until an admin calls `/api/cmdb/vault/setup`

---

## v1.8.6 - 2026-04-26

### New features

**SMTP / email notifications** — sibling channel to webhooks, same events, same maintenance suppression
- New SMTP section in Notifications tab: host/port/TLS mode/from/auth/recipients/test button
- Per-event email toggle in the existing event table (now has Webhook + Email columns)
- TLS modes: STARTTLS (587), implicit TLS (465), plain (25)
- Optional auth (empty username = no AUTH for localhost relays)
- Passwords masked in `GET /api/config`
- Email is opt-in per event by design (avoids inbox flood)

**LDAP / LDAPS authentication** — external auth source, falls back to local users.json
- New LDAP section in Security tab: URL, service account DN+password, search base, user filter, required group, admin group, TLS verify, timeout
- Two test buttons: "Test connection" (verifies service-account bind) and "Test user login" (full auth path)
- Local users tried first → LDAP unavailable never locks you out
- Auto-provisions new LDAP users into users.json with role from group membership
- Auto-promotes existing users to admin if they're in the admin group; never auto-demotes
- Required-group filter for "only members of this group can log in"
- Pure-Python `ldap3` library, imported lazily — not needed if you don't enable LDAP

### New endpoints

- `POST /api/smtp/test` — send test email, optional recipient override
- `POST /api/ldap/test` — verify service-account bind with body-as-config override
- `POST /api/ldap/test-user` — admin-only full auth path test, no session created

### Changed

- All version strings bumped to 1.8.6
- `fire_webhook()` is now the single dispatch point for both webhook and email channels — gates (per-event toggle, severity filter, maintenance suppression) run once
- `handle_login` gains LDAP fallback path; LDAP transient errors log to audit but present as invalid-credentials to the client
- Per-event email toggles in `email_events` config dict (parallel to `webhook_events`)

### New data files

None. New config keys live in `config.json`. Auto-provisioned LDAP users get extra metadata fields in `users.json`.

### Tests

**Full suite: 212 passing, 0 failing** (1 pre-existing skip). 30 new tests in `tests/test_v186.py` covering recipients parsing, email toggle semantics, SMTP input validation, email rendering, LDAP filter escaping, full LDAP auth paths (using `sys.modules` fake-ldap3 stub), required-group enforcement, and role mapping.

### Compatibility

- v1.8.5 servers work with v1.8.6 clients
- LDAP/SMTP off by default — no migration, no surprise behavior changes
- Agent binary unchanged from v1.8.5 except version string
- LDAP requires `pip3 install ldap3` (or `dnf install python3-ldap3`) only if enabled

---

## v1.8.5 - 2026-04-26

### Fixed

- **"Remember me" was a no-op**: client always saved the session token to `sessionStorage` regardless of checkbox state, so the browser threw away the token on close even though the server-side TTL was correctly 30 days. Particularly visible with 2FA enabled.
  - Now: checked → `localStorage` (persists across browser restarts), unchecked → `sessionStorage` (cleared with the tab)
  - `checkAuth()` (called on page load) now reads from both stores so a remembered session is recognized
  - `doLogout()` and login flow clear both stores so toggling modes doesn't leave stale state

### Changed

- All version strings bumped to 1.8.5
- Pure client-side fix — no server, agent, or data changes

### Tests

**Full suite: 182 passing, 0 failing** (1 pre-existing skip). No new tests; DOM behavior verified by hand.

### Compatibility

- v1.8.4 servers work with v1.8.5 clients. Agent binary identical except for its version string.

---

## v1.8.4 - 2026-04-25

### New features

**Settings reorganized into tabs.** General / Notifications / Security / Advanced. URL hash drives selection (`#settings/security` etc).

**Configurable runtime values** (previously hardcoded constants):
- **Server identity** — `server_name` shown in title bar, login page, webhook payloads
- **Default poll interval** for new agent enrollments (10–3600s)
- **Online TTL** — when a device counts as offline. Min 90s to prevent flap
- **CVE details cache TTL** — was 7 days hardcoded; now 1–90 days

**Per-event webhook toggles.** All 11 event types individually controllable from the Notifications tab:
- `device_offline`, `device_online`
- `monitor_down`, `monitor_up`
- `patch_alert` (threshold input embedded in row)
- `cve_found` (severity filter inline: `critical`/`high`/`medium`/`low`/`unknown`)
- `service_down`, `service_up`
- `log_alert`
- `command_queued`, `command_executed`

Disabled events log to webhook log as `"disabled"` so you can see what was suppressed.

**Remember-me on login.** Tickbox below password field. Two session lengths: short (default 24h) used when unchecked, long (default 30 days) when checked. Admin can pre-tick the box via `remember_me_default`.

Tokens now carry their own TTL in `tokens.json`. A long session won't get pruned by the cleanup of short ones. Legacy tokens fall back to the old global `TOKEN_TTL`.

### New endpoint

- `GET /api/public-info` — unauthenticated. Returns `server_name`, `server_version`, `remember_me_default`. Used by the login page to set the title and the remember-me checkbox initial state.

### New config keys

| Key | Default |
|-----|---------|
| `server_name` | `""` (renders "RemotePower") |
| `default_poll_interval` | 60 |
| `online_ttl` | 180 (min 90) |
| `cve_cache_days` | 7 |
| `webhook_events` | dict, all true |
| `cve_severity_filter` | `["critical", "high"]` |
| `session_ttl_short` | 86400 (24h) |
| `session_ttl_long` | 2592000 (30 days) |
| `remember_me_default` | false |

### Changed

- All version strings bumped to 1.8.4
- `ONLINE_TTL` constant replaced with `get_online_ttl()` helper. `DEFAULT_ONLINE_TTL` constant still exists for tests.
- `fire_webhook()` runs every event through `is_webhook_event_enabled()`; respects severity filter for `cve_found`
- `_detect_new_cve_and_fire_webhook()` uses configurable severity filter (no longer hardcoded `('critical', 'high')`)
- `handle_login` accepts `remember_me` in the body
- `verify_token` and `cleanup_tokens` honor per-token `ttl`

### Backward compatibility

All four legacy webhook flags (`offline_webhook_enabled`, `monitor_webhook_enabled`, `cve_webhook_enabled`, `service_webhook_enabled`) still work. When `webhook_events` is set, it takes precedence. Upgrades from 1.8.3 work seamlessly — saving the settings page once writes the new keys.

### Tests

34 new tests in `tests/test_v184.py` covering helpers, legacy-key migration, CVE severity filter, per-token TTL semantics, and the WEBHOOK_EVENTS contract. `tests/test_api.py` updated for the constant rename. **Full suite: 182 passing, 0 failing** (1 pre-existing skip).

---

## v1.8.3 - 2026-04-25

### Fixed

- **SSH/sshd alias on Debian/Ubuntu**: `journalctl` doesn't follow systemd unit aliases, so users who typed `sshd.service` (the RHEL-style name) got zero log lines on Debian even though state tracking worked. Agent now calls `systemctl show <unit> --property=Id` to resolve the canonical name before querying journalctl.

### New features

**Calendar — shared events page**
- Month-grid calendar at the new sidebar entry. Click a day to add an event; click an event pill to edit.
- Events have title, optional description, ISO-8601 start/end, all-day flag, and a 7-color palette (blue/green/amber/red/purple/teal/slate).
- Multi-day events span across days; busy days show "+N more".
- Fully shared — any authenticated user can create, edit, or delete.
- Endpoints: `GET/POST /api/calendar`, `PUT/DELETE /api/calendar/{id}`. Cap: 1000 events.

**Tasks — shared kanban board**
- Four-column board: Upcoming / Ongoing / Pending / Closed. Drag-and-drop between columns to change state (optimistic update, resyncs on server failure).
- Optional device linking — every task can be tied to one device, shown as a badge on the card.
- Filter the board by device (or "no device linked").
- Endpoints: `GET/POST /api/tasks`, `PUT/DELETE /api/tasks/{id}`. Cap: 500 tasks. PUT supports partial updates (e.g. just `{"state": "closed"}`).

### New data files

- `calendar.json` — shared events
- `tasks.json` — shared kanban tasks

### Changed

- All version strings bumped to 1.8.3
- Agent `get_services()` payload may include a `canonical` key per service when the user-supplied name is an alias
- Sidebar nav: new "Calendar" and "Tasks" entries between Schedule and the Tools section

### Tests

24 new tests in `tests/test_v183.py` covering calendar event validation, task validation (including state allowlist and partial updates), agent alias resolution with mocked systemctl, and handler wiring. **Full suite: 147 passing, 0 failing** (1 pre-existing skip).

### Compatibility

- v1.8.2 agents still work with a v1.8.3 server but won't benefit from the alias fix until they self-update
- No data format breakage; existing `services_watched` lists are unchanged
- New data files (`calendar.json`, `tasks.json`) are created on first write — no migration needed

---

## v1.8.2 - 2026-04-24

### Fixed

- **Log tail: quiet devices were invisible on the Logs page.** Agent skipped units that had no recent `journalctl` output, and skipped the whole submission if every unit was quiet. So a device watching nginx/sshd on an idle box never appeared in `log_watch.json`, indistinguishable from a dead agent.
  - Agent always includes every watched unit (empty list if quiet) and always POSTs when any unit is watched
  - Server preserves the unit key with empty array so the device appears as "watched, quiet in this window"
  - Live tail empty-state distinguishes three cases: no devices submitting, devices reporting but quiet, or filter matches nothing

### New features

**Fleet-wide log alert rules** — new tab on the Logs page. Rules defined centrally that apply to all devices.

- Wildcard `unit="*"` matches any unit on any device (catch-all for patterns like `OOMkilled`)
- Specific unit name matches that unit wherever it runs
- `handle_log_submit` evaluates per-device AND fleet-wide rules on every ingest
- Webhook payload gains `scope: "device" | "global"` so alerts are identifiable downstream
- Rules deduplicated by `(scope, unit, pattern)` — same rule text matching twice in one submission fires once

**Logs page UI**: per-device / fleet-wide tab switcher above the rules table. "+ Add rule" modal adapts to active tab (hides device picker for fleet-wide, shows wildcard hint).

### New endpoints

- `GET    /api/logs/rules/global` — list fleet-wide rules
- `POST   /api/logs/rules/global` — create a fleet-wide rule
- `DELETE /api/logs/rules/global/{id}` — remove a fleet-wide rule

### Changed

- Live tail polls every **30 seconds** (was 10s). Scroll-pause and PAUSED badge removed; uncheck "auto-scroll to newest" to read older lines.
- All version strings bumped to 1.8.2

### New data files

- `log_rules_global.json` — fleet-wide rules (created on first write)

### Tests

15 new tests in `tests/test_v182.py` — validation cases, empty-array handling, wildcard matching, dedupe semantics. Test_v181's version assertion loosened to `>= 1.8.1` to not break on future bumps. Full suite: **123 passing, 0 failing** (1 pre-existing skip).

### Compatibility

- All v1.8.1 agents **must update** to get the empty-submission fix, or their quiet units will remain invisible on the new server
- v1.8.0 agents work with a v1.8.2 server but don't benefit from the empty-array fix
- No schema changes to existing data files

---

## v1.8.1 - 2026-04-24

### New features

**Dedicated Logs page in the sidebar** — the v1.8.0 log tail feature was buried inside the service drill-down and had no UI for configuring alert rules. This release promotes logs to a first-class page with three widgets:

- **Live tail** — polls `/api/logs/tail` every 10s with incremental cursor; pauses auto-scroll when you scroll up, resumes when you return to the bottom; device + unit filters; severity color-coding (red for FATAL, orange for ERROR, amber for WARN)
- **Search** — regex search across the fleet's rolling 6-hour buffer, results grouped by device with collapsible sections
- **Alert rules table** — cross-fleet view of all `log_watch` rules with "+ Add rule" button; adding a rule auto-ensures the target unit is in `services_watched`

### New endpoints

- `GET /api/logs/tail?since=<ts>&device=<id>&unit=<n>&limit=<n>` — incremental fetch for live tail with monotonic cursor
- `GET /api/logs/rules` — cross-fleet aggregate of all log_watch rules

### Fixed

- Service drill-down now always shows "State history" and "Recent logs" sections, even when empty. Empty states include diagnostic hints ("Agent needs v1.8.0+ and journalctl access"). Previously the sections were silently omitted, which looked broken. (Reported post-v1.8.0.)
- "State history" and "Recent logs" sections now auto-expand when they have content

### Changed

- All version strings bumped to 1.8.1
- Line severity colouring in the tail uses word-boundary regex to avoid false positives on substrings like "error_count"

### Tests

108 passing, 0 failing (1 pre-existing skip). New tests: `tests/test_v181.py` covering log rules aggregation, tail filtering, and config round-trip.

### Compatibility

No agent changes. v1.8.0 agents work unchanged with v1.8.1 server.

---

## v1.8.0 - 2026-04-23

### New features

**Service monitoring (systemd)**
- Per-device `services_watched` list — agent calls `systemctl show` on every heartbeat for each watched unit and reports `ActiveState`, `SubState`, and `ActiveEnterTimestamp`
- Server tracks state per (device, unit) and records every transition (last 100 kept per unit)
- New webhook events `service_down` (priority 4) and `service_up` (priority 3) fire on state transitions
- New "Services" page in the dashboard — fleet matrix with up/down counts, per-device drill-down showing state history and recent logs per unit, inline config editor
- Watched-unit list is pushed from server to agent via heartbeat response — change what you monitor from the UI without restarting any agents

**Log tail + regex pattern alerts**
- Agent submits recent `journalctl -u <unit>` output to the server every 5 polls
- Server keeps a rolling per-device per-unit buffer, bounded at 6 hours and 2 MB per device
- Per-device `log_watch` rules — `[{unit, pattern, threshold}]` — where regex matches fire the new `log_alert` webhook event
- New `GET /api/logs/search?q=<regex>` endpoint does cross-device grep over the rolling buffer
- Log lines appear inline in the service drill-down so you can see *why* a service went red without SSH-ing in
- Deliberately not a log analytics platform — no indexing, no parsing, no retention policies. If you need Loki, run Loki

**Maintenance windows**
- Suppress webhook alerts during scheduled windows — device-specific, group-specific, or fleet-global
- One-shot windows (`start` + `end` ISO-8601) or recurring (`cron` + `duration` seconds)
- Optional per-window event allowlist — suppress only `patch_alert` during a maintenance window, or leave `device_offline` still firing
- Built-in lightweight cron evaluator (`*`, `*/N`, `a,b,c`, and literals; no ranges or named days)
- Suppression audit trail in `maint_suppressed.json` — always know why a webhook didn't fire
- New Prometheus metric `remotepower_maintenance_windows_active`

### New endpoints

- `GET  /api/services` — fleet-wide service state
- `GET  /api/devices/{id}/services` — per-device view with state history + log tails
- `GET/POST /api/devices/{id}/services/config` — manage watched units + log rules
- `POST /api/logs` — agent submits unit log lines (device-authenticated)
- `GET  /api/logs/search?q=<regex>` — cross-device log search
- `GET  /api/devices/{id}/logs` — full captured buffer for one device
- `GET  /api/maintenance` — list all windows + `active` flag
- `POST /api/maintenance` — create a window
- `DELETE /api/maintenance/{id}` — remove a window
- `GET  /api/maintenance/suppressions` — webhook suppression audit trail

### Changed

- All version strings bumped to 1.8.0
- `fire_webhook()` now runs every event through `in_maintenance()` before dispatching
- New config key: `service_webhook_enabled` (bool, default `true`)
- Heartbeat response extended with `services_watched` and `log_watch` so agents can react to config changes between polls
- Webhook helpers (`_webhook_message`, `_webhook_priority`, `_webhook_tags`) extended for `service_down`, `service_up`, and `log_alert`

### New data files

| File | Purpose |
|------|---------|
| `services.json` | Current service state per device |
| `service_history.json` | State transition log per (device, unit) |
| `log_watch.json` | Rolling log buffer per device + unit |
| `maintenance.json` | Defined windows |
| `maint_suppressed.json` | Audit trail of suppressed webhook events |

### Agent (Linux)

- `VERSION = '1.8.0'`
- New functions: `get_services()`, `_parse_systemd_timestamp()`, `get_unit_logs()`, `submit_unit_logs()`
- New constants: `SERVICE_CHECK_EVERY = 1`, `LOG_SUBMIT_EVERY = 5`, `LOG_LOOKBACK_SECONDS = 360`, `MAX_LOG_LINES_PER_UNIT = 100`
- Gracefully degrades on non-systemd hosts (reports nothing rather than crashing)

### Cleanup

- Fixed 4 pre-existing test failures in `tests/test_api.py` around `verify_token()` — tests were written for an older `str`-returning signature; function has returned `(username, role)` since v1.6.x
- Tidied residual comment fragment on `MAX_BODY_BYTES` from v1.7.0 buffer bump
- Minor deduplication in `_cron_match()`
- Added 24 new unit tests (`tests/test_v180.py`) covering cron evaluation, maintenance window matching, ISO parsing, service state processing, and the suppressible-events contract

### Test suite: 101 passing, 0 failing (1 pre-existing skip)

---

## v1.7.0 - 2026-04-23

### New features

**CVE Scanner (via OSV.dev)**
- New "CVEs" page in the dashboard showing aggregate severity counts (critical/high/medium/low) across the fleet, per-device breakdown, and per-vulnerability drill-down
- Agent enumerates installed packages (`dpkg-query` / `rpm` / `pacman` / `apk`) every 6 hours and submits via new `/api/packages` endpoint; hash-gated so it only resubmits when the package list actually changes
- Server queries OSV.dev's batch endpoint (up to 500 packages per request) and caches vulnerability details for 7 days
- Supported ecosystems: Debian, Ubuntu, Rocky Linux, AlmaLinux, Red Hat, Alpine, Arch Linux
- Fixed-version information shown in the drill-down when OSV provides it
- Ignore list: mark a CVE as accepted risk globally or for a specific device; ignored findings are excluded from counts and alerts but remain visible (dimmed)
- New webhook event `cve_found` fires (priority 5 — urgent) when new critical/high CVEs appear that weren't in the previous scan

**Prometheus `/metrics` endpoint**
- Standard Prometheus text exposition at `GET /api/metrics`
- Auth via session token or API key — Prometheus's native `bearer_token` scrape config works unchanged
- Device count, online state, cpu/mem/disk percentages, upgradable package counts, CVE findings by severity, monitor state, command queue depth, webhook delivery counters

### New endpoints

- `POST /api/packages` — agent submits installed package list (device-authenticated)
- `POST /api/cve/scan` — admin triggers CVE scan (one device or all)
- `GET  /api/cve/findings` — aggregate CVE report
- `GET  /api/devices/{id}/cve` — per-device CVE findings
- `GET  /api/cve/ignore` — list active ignore entries
- `POST /api/cve/ignore` — mark a CVE as accepted risk
- `DELETE /api/cve/ignore/{vuln_id}` — remove an ignore
- `GET  /api/metrics` — Prometheus scrape endpoint

### Changed

- All version strings bumped to 1.7.0 (server, Linux agent, Windows agent)
- Linux agent gains `PACKAGE_LIST_EVERY = 360` and `MAX_PACKAGES_SEND = 10000` constants
- Linux agent gains six new functions (`get_os_release`, `get_package_list`, `send_package_list`, three hash-cache helpers) + a sidecar file `/etc/remotepower/pkg_hash`
- Webhook event helpers extended for `cve_found`

### Config keys added

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cve_webhook_enabled` | bool | `true` | Whether to fire `cve_found` webhooks on new critical/high findings |

### New data files

- `packages.json` — per-device installed package list + hash
- `cve_findings.json` — per-device scan results
- `cve_ignore.json` — global/per-device CVE ignore list
- `cve_details_cache.json` — OSV vulnerability detail cache (7-day TTL)

### Notes

- Fedora is not reliably covered by OSV and is marked `unsupported`. Extend `cve_scanner.detect_ecosystem()` to add custom mappings.
- First-time CVE scan on a heavy Debian host can take 30–60 seconds while per-vulnerability details are hydrated; subsequent scans hit the cache and are near-instant.
- Windows agents submit no package data (OSV ecosystems don't cover Windows well). Windows devices show as `unsupported` in the CVE UI.
- Package list submission is bandwidth-efficient: ~120 KB per device per change event, zero bytes when nothing changed (hash-gated client-side).

---

## v1.6.0 - 2026-04-21

### New features

**Webhook overhaul**
- Webhook URL is now visible and editable in the Settings UI (previously hidden after save)
- Webhook payloads now include `title`, `message`, and `priority` fields for human-readable push notifications
- Push-compatible headers added: `X-Title`, `X-Priority`, `X-Tags` — works out of the box with Ntfy, Gotify, Pushover, Slack, and Discord
- Per-event emoji tags for Ntfy (`X-Tags` header) — e.g. `red_circle,computer` for offline, `warning,package` for patch alerts
- Per-event priority levels (3=normal, 4=high) for push services
- `User-Agent` header now includes server version (`RemotePower/1.6.0`)

**Monitor webhook alerts**
- New `monitor_down` event fires when a monitor target goes from up to down
- New `monitor_up` event fires when a monitor target recovers
- State-change tracking prevents duplicate alerts (only fires on transitions)
- Toggle on/off via Settings checkbox ("Monitor alerts")

**Offline webhook toggle**
- New toggle in Settings to enable/disable device offline/online webhook alerts
- Allows keeping the webhook URL configured for other events (patch alerts, commands, monitors) while disabling offline noise

**Patch alert improvements**
- Threshold can now be cleared (set to 0 or empty) to disable patch alerts via the UI
- Clearing the threshold also resets tracked alert state

### Changed

- `GET /api/config` now returns `webhook_url`, `offline_webhook_enabled`, and `monitor_webhook_enabled` (webhook URL was previously hidden from the API response)
- `POST /api/config` accepts `offline_webhook_enabled` (bool) and `monitor_webhook_enabled` (bool)
- `POST /api/config` accepts `patch_alert_threshold: 0` or `null` to clear the threshold
- Settings UI reorganised: "Webhooks" section replaces "Offline Webhook", with toggles and visible URL
- All version strings bumped to 1.6.0 (server, Linux agent, Windows agent, Dockerfile, docker-compose, README badge)
- Webhook `fire_webhook()` rewritten with richer payloads and push headers

### Config keys added

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `offline_webhook_enabled` | bool | `true` | Enable/disable device offline/online webhook alerts |
| `monitor_webhook_enabled` | bool | `true` | Enable/disable monitor up/down webhook alerts |
| `monitor_notified` | object | `{}` | Internal state tracking for monitor alert deduplication |

### Webhook events

| Event | Priority | When |
|-------|----------|------|
| `device_offline` | 4 (high) | Device misses heartbeats beyond ONLINE_TTL |
| `device_online` | 3 | Device comes back online |
| `monitor_down` | 4 (high) | Monitor target transitions from up to down |
| `monitor_up` | 3 | Monitor target recovers |
| `patch_alert` | 4 (high) | Device exceeds pending update threshold |
| `command_queued` | 3 | Command queued for a device |
| `command_executed` | 3 | Device reports command execution |

---

## v1.5.1 - 2026-04-20

### New features

**Windows agent**
- New `client/remotepower-agent.py` - full-featured Windows client agent
- Same heartbeat protocol and API as the Linux agent - enrolls the same way
- Power control via `shutdown.exe /s` and `/r` with 30-second grace period
- Patch info via Windows Update COM API (PowerShell)
- System journal via `wevtutil` (Windows System event log)
- CPU/RAM/disk metrics via psutil (optional, same as Linux)
- Boot reason tracking via `%ProgramData%\RemotePower\last_cmd.txt`
- Adjustable poll interval via config file (same mechanism as Linux)
- Runs as a Windows Service via NSSM, or interactively for testing
- `install-client.ps1` PowerShell installer: checks Python, installs psutil, enrolls, downloads NSSM, registers service
- Supports `enroll`, `re-enroll`, `status`, `integrity` subcommands
- Agent self-update is logged but not applied automatically on Windows (manual update recommended)

**Docker support**
- `Dockerfile` and `docker-compose.yml` for containerized server deployment
- Based on `python:3.12-slim` with nginx + fcgiwrap + bcrypt + reportlab
- Admin user created automatically via `RP_ADMIN_USER` / `RP_ADMIN_PASS` environment variables
- Data persisted in `/var/lib/remotepower` volume
- Healthcheck built in (HTTP probe every 60s)
- Docker-specific nginx config on port 8080 (put a reverse proxy in front for HTTPS)
- `docker/entrypoint.sh` handles fcgiwrap startup, user creation, and version config
- `.dockerignore` to keep image lean

### Changed

- Agent version bumped to 1.5.1
- Server version bumped to 1.5.1
- README updated with Windows client docs, Docker quick start, updated architecture diagram
- Platform badge updated to `Linux | Windows`
- File layout updated with new files

### New files

| File | Description |
|------|-------------|
| `client/remotepower-agent.py` | Windows agent (Python 3) |
| `install-client.ps1` | Windows client installer (PowerShell) |
| `Dockerfile` | Server container image |
| `docker-compose.yml` | Compose file for quick deployment |
| `.dockerignore` | Docker build exclusions |
| `docker/nginx-docker.conf` | Nginx config for Docker |
| `docker/entrypoint.sh` | Container entrypoint script |

---

## v1.5.0 - 2026-04-19

### New features

**Patch Report page**
- New Patches nav tab with dedicated patch overview across all devices
- Summary cards: total devices, fully patched, patches pending, total pending count, patch rate %
- Device table with per-device patch status, pkg manager, recent patch commands
- Export as CSV (`GET /api/patch-report/csv`)
- Export as XML (`GET /api/patch-report/xml`)
- Export as PDF (`GET /api/patch-report/pdf`) - formatted with ReportLab, color-coded status

**Audit log with IP tracking**
- New Audit Log nav tab showing security-relevant events
- Tracks: logins (success + failed), exec commands, session revocations, user-agent + source IP
- `GET /api/audit-log` endpoint (admin only)
- Stored in `audit_log.json` (last 500 entries)

**API key expiration**
- `POST /api/apikeys` now accepts optional `expires_at` (unix timestamp)
- Expired keys are silently rejected during authentication
- Keys without `expires_at` remain non-expiring (backward compatible)

**Bulk exec**
- `POST /api/exec` now accepts `device_ids`, `tag`, or `group` targets (same as shutdown/reboot)
- Run arbitrary commands across multiple devices in one API call
- Allowlist is checked per-device; partial failures return per-device results

**Increased exec timeout**
- Agent exec timeout raised from 30s to 300s (5 min) for long-running commands like `apt upgrade`

**Boot reason tracking**
- Agent records the last command before shutdown/reboot in `/tmp/remotepower-last-cmd`
- First heartbeat after restart includes `boot_reason` field
- Helps distinguish scheduled reboots from unexpected restarts

**Device search and filtering**
- Search bar on Devices page - filter by name, hostname, IP, OS, group, or tags
- Status filter dropdown (All / Online / Offline)
- Group filter dropdown (auto-populated from device groups)
- All filters combine with existing tag filter

**Browser notifications**
- Web Notifications API integration for device online/offline state changes
- Permission requested on first login; notifications fire on status transitions
- No server-side changes needed - purely client-side

**Session token revocation**
- `POST /api/sessions/revoke` - revoke all sessions or sessions for a specific user
- "Revoke all sessions" button on Audit Log page
- Admin-only; preserves the requester's current session when revoking all

**Two-Factor Authentication (TOTP)**
- TOTP-based 2FA compatible with Google Authenticator, Authy, etc.
- Setup flow: `POST /api/totp/setup` → scan secret → `POST /api/totp/confirm` with code
- Login prompts for authenticator code when 2FA is enabled
- Disable with password confirmation via `POST /api/totp/disable`
- Status check: `GET /api/totp/status`
- 2FA section added to Settings page with enable/disable UI

**Per-device patch report**
- `GET /api/patch-report/device/:id` - detailed patch info for a single device
- Includes patch command history, OS, uptime, agent version, metrics
- "Detail" button on each row in the Patches table opens a modal

**Clear history**
- Clear button on Command History page (`DELETE /api/history`)
- Clear button on Audit Log page (`DELETE /api/audit-log`)
- Both require admin role and are themselves audit-logged

**Filtered patch export**
- Group and device filter dropdowns on Patches page
- CSV/XML/PDF exports respect the active filter via `?group=X` and `?device_id=Y` query params
- Summary cards update live based on filtered set

### Changed
- `POST /api/exec` now supports batch targets (device_ids, tag, group) in addition to single device_id
- Agent exec timeout increased from 30s to 300s
- Agent sends `boot_reason` on first heartbeat after restart
- Audit events logged for logins, failed logins, exec commands, session revocations
- Patch percentage now excludes offline/no-data devices (only counts online with known state)
- Nav bar wraps on smaller screens, reduced padding for 11 tabs
- CSV/XML/PDF exports flush stdout properly for CGI binary output
- XML export produces valid well-formed XML

### New data files
- `audit_log.json` - security audit trail (last 500 entries)
- `sessions_meta.json` - session metadata for revocation tracking

### New API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/patch-report` | ✓ | Full patch report (JSON) |
| `GET` | `/api/patch-report/csv` | ✓ | Patch report as CSV download |
| `GET` | `/api/patch-report/xml` | ✓ | Patch report as XML download |
| `GET` | `/api/patch-report/pdf` | ✓ | Patch report as PDF download |
| `GET` | `/api/audit-log` | admin | Security audit log |
| `POST` | `/api/sessions/revoke` | admin | Revoke user sessions |
| `GET` | `/api/patch-report/device/:id` | ✓ | Per-device patch detail |
| `POST` | `/api/totp/setup` | ✓ | Generate TOTP secret |
| `POST` | `/api/totp/confirm` | ✓ | Confirm & enable 2FA |
| `POST` | `/api/totp/disable` | ✓ | Disable 2FA (requires password) |
| `GET` | `/api/totp/status` | ✓ | Check if 2FA is enabled |
| `DELETE` | `/api/history` | admin | Clear command history |
| `DELETE` | `/api/audit-log` | admin | Clear audit log |

---

## v1.4.0 - 2026-04-17

### New features

**Recurring scheduled commands**
- Schedule tab now accepts a cron expression (5-field: `min hour dom mon dow`) in addition to a one-shot datetime
- Recurring jobs stay in the queue and fire every time the cron expression matches (checked on every API request, minute precision)
- Dashboard shows `↻ <cron>` for recurring jobs vs a timestamp for one-shot jobs

**Batch commands (multi-device)**
- Click the device icon on any card to select it (turns into a checkmark)
- A batch action bar appears with Shut down all / Reboot all / Update all buttons
- API also accepts `device_ids: [...]`, `tag: "servers"`, or `group: "homelab"` on all command endpoints

**Device groups / namespaces**
- New `group` field per device (`PATCH /api/devices/:id/group`)
- Device grid sorts by group then name; group badge shown on the hostname line
- Batch commands can target an entire group

**Per-device notes**
- Free-text `notes` field per device (`PATCH /api/devices/:id/notes`, max 1024 chars)
- 📝 indicator on device name when notes are set; tooltip shows the text
- Dedicated Notes modal accessible from the device card

**Adjustable heartbeat interval per device**
- `PATCH /api/devices/:id/poll_interval` (10–3600 s)
- Server queues a `poll_interval:<n>` command; agent picks it up on next heartbeat and adjusts its sleep interval dynamically (no restart needed)
- Current interval shown in device meta row

**Agent health / offline reason**
- `offline_reason` field in device list: `missed_polls` (offline <5 min) vs `offline`
- `missed_polls` counter exposed in API and shown as an amber badge on offline cards
- Agent now reports `executed_command` field in heartbeat so the server can fire command-executed webhooks

**Re-enrollment without wipe**
- `sudo remotepower-agent re-enroll` sends the existing `device_id` in the registration payload
- Server detects a matching ID, updates the record in-place, and returns `reregistered: true`
- History, tags, group, and notes are all preserved on re-enroll

**Saved command library**
- New Command Library page (nav: Library) for named shell snippets
- `GET/POST /api/cmd-library`, `DELETE /api/cmd-library/:id`
- Exec modal now has a "pick from library" dropdown that pastes the command into the input
- Snippets shared across all admin users

**Command allowlist per device**
- `GET/POST /api/devices/:id/allowlist` - set an explicit list of allowed shell commands
- When non-empty, only listed commands can be run via exec on that device (403 otherwise)
- Empty list = unrestricted (backward-compatible with existing behaviour)
- Allowlist modal accessible from the device card (🔒 button)

**Basic metrics history (CPU / RAM / Disk)**
- Agent optionally collects `cpu_percent`, `mem_percent`, `disk_percent` via `psutil` (gracefully skipped if not installed)
- Server stores up to 1440 snapshots per device in `metrics.json` (roughly 24 h at 60 s intervals)
- Metrics modal per device with sparkline bars for CPU, RAM, and Disk
- New endpoint: `GET /api/devices/:id/metrics`

**Named API keys**
- New API Keys page (nav: API Keys)
- `GET/POST /api/apikeys`, `DELETE /api/apikeys/:id`
- Non-expiring keys authenticated via `X-Token` header (same as session tokens)
- Each key has a `role` (admin or viewer) - viewer keys are read-only
- Key value shown once at creation; not stored in any response thereafter

**Role-based access (viewer accounts)**
- Users now have a `role` field: `admin` (default) or `viewer`
- Viewer role: can see the dashboard, devices, sysinfo, history, monitor - but cannot queue commands, change config, manage users, or create API keys
- Role shown in Users table; role selector in Add User modal
- Login response now returns `role` and `username`

**Dashboard export / backup**
- `GET /api/export` streams a ZIP of all `*.json` data files (excluding `tokens.json`)
- "Export backup" button added to Settings page; uses fetch + blob for in-browser download

**Webhook on command execution**
- `command_queued` and `command_executed` webhook events added alongside the existing `device_offline`, `device_online`, and `patch_alert` events
- `command_executed` fires when the agent reports back that it ran a command (via the `executed_command` field in the heartbeat)

**Long-poll exec (terminal-in-browser foundation)**
- `POST /api/exec/wait` - queues an exec command and holds the HTTP connection open (default 90 s, max 120 s) polling for output
- When the agent's next heartbeat delivers the output, the response is flushed immediately
- Falls back with `timeout: true` if output doesn't arrive; client can then poll `/output` as before
- `longpoll.json` tracks pending waiters per device

**Digest endpoint**
- `GET /api/digest` - JSON summary: total/online/offline devices, total pending patches, last 10 commands
- Designed for cron-driven email digests or dashboard status boards; no polling infrastructure needed

**Agent integrity check**
- `sudo remotepower-agent integrity` - hashes the running binary, compares to server's known-good SHA-256
- Exits 0 if match, 1 if mismatch (suitable for cron alerting)

### Changed
- `GET /api/devices` response now includes `group`, `notes`, `offline_reason`, `missed_polls`, `poll_interval`
- `GET /api/users` response now includes `role` per user
- `POST /api/users` now accepts optional `role` field (default: `admin`)
- Login response now returns `role` and `username`
- Heartbeat response now includes `poll_interval` hint for the agent
- `_queue_command` now fires a `command_queued` webhook on every queued action
- `check_offline_webhooks` now fires `device_online` webhook when a device comes back
- Devices sorted by group then name (was: name only)
- Schedule table shows `↻ <cron>` for recurring jobs

### New data files
- `metrics.json` - per-device CPU/RAM/disk time-series (last 1440 points)
- `cmd_library.json` - saved command snippets
- `longpoll.json` - pending long-poll output slots
- `apikeys.json` - named API keys (key values stored here; never returned after creation)

### New API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `PATCH` | `/api/devices/:id/notes` | admin | Set device notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set device group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `GET` | `/api/devices/:id/metrics` | ✓ | CPU/RAM/disk time-series |
| `GET/POST` | `/api/devices/:id/allowlist` | admin | Get/set command allowlist |
| `GET` | `/api/cmd-library` | ✓ | List command snippets |
| `POST` | `/api/cmd-library` | admin | Add command snippet |
| `DELETE` | `/api/cmd-library/:id` | admin | Delete command snippet |
| `GET` | `/api/apikeys` | admin | List API keys (no values) |
| `POST` | `/api/apikeys` | admin | Create API key (value shown once) |
| `DELETE` | `/api/apikeys/:id` | admin | Delete API key |
| `GET` | `/api/export` | admin | Download ZIP backup |
| `GET` | `/api/digest` | ✓ | Summary for cron/email |
| `POST` | `/api/exec/wait` | admin | Long-poll exec (up to 120 s) |

---

## v1.3.1 - 2026-04-17

- Version bump; minor packaging fixes

---

## v1.3.0 - 2026-04-16

### New features
- Tag editor - set and edit device tags directly from the dashboard
- Tag group filtering - filter device grid by tag with one click
- Scheduled commands - queue shutdown or reboot at a specific date and time
- Custom shell commands - run arbitrary commands on devices, output returned via next heartbeat (~60s)
- Monitor history - uptime percentage, sparkline, last 50 check results per target
- Patch alert webhook - fires when a device exceeds a configurable pending update threshold
- Uptime tracking - online/offline state changes stored per device in uptime.json
- Command history page - every action logged with actor, device, and timestamp
- About page - server version, agent version, latest GitHub release check
- Dark/light mode toggle - persisted per browser in localStorage
- Force agent update from dashboard - queue update command like shutdown/reboot
- Network info - agent reports all interfaces, not just primary IP

### Fixed
- Nginx blocking PATCH method - tag API would return 405
- QUERY_STRING not forwarded to CGI - monitor history label lookup always returned empty
- Poller cadence was broken - sysinfo/journal now every 10 polls (~10min), patches every 180 polls (~3hr)
- First-poll sysinfo - agent now sends data immediately on startup instead of waiting
- Exec button shown on offline devices - now dimmed with tooltip
- Tag API existed but no UI to set tags
- Custom command output stored on server but never displayed

---

## v1.2.0 - 2026-04-16

### New features
- Agent self-update - SHA-256 verified, atomic replace, systemctl restart, no SSH needed
- Force update from dashboard - queue update command alongside shutdown/reboot
- Dark/light mode toggle
- Server version check against GitHub releases - amber banner when update available
- WoL unicast fix - sends to device's last known IP for routed/VPN networks, broadcast fallback

### Fixed
- Agent log file permission error when running as non-root
- Poller frequency - patches split from sysinfo (patches every 3hr, sysinfo every 10min)

---

## v1.1.2 - 2026-04-15
- Fixed agent self-update download URL (static file instead of CGI)
- Fixed agent log file permission for non-root users
- Reduced sysinfo/patch poll frequency to reduce load

## v1.1.1 - 2026-04-15
- Fixed agent log file permission for non-root users
- Fixed agent self-update download URL (static file instead of CGI)

## v1.1.0 - 2026-04-15
- bcrypt password hashing with silent SHA-256 auto-upgrade
- Wake-on-LAN support, MAC reported at enroll time
- Reboot command alongside shutdown
- Multiple admin users with full CRUD in dashboard
- Offline webhook (Ntfy/Gotify/Slack/Discord)
- Patch info via apt/dnf/pacman (dry-run only)
- Uptime + journalctl per device with noise filtering
- Ping/TCP/HTTP service monitoring from server
- Agent self-update - SHA-256 verified, atomic replace
- Multi-distro install scripts (apt/dnf/pacman)
- deploy-server.sh for fast redeploys

## v1.0.0 - 2026-04-14
- Initial release
- Remote shutdown over HTTPS
- PIN enrollment
- No inbound firewall rules on clients
- Flat JSON storage, Nginx + Python CGI
