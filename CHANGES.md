# Changelog

## v1.11.9 — 2026-05-06

### Fixed

**Minimal table extended past the right edge.** v1.11.7 set
`width: 100%` on the minimal table but no `table-layout: fixed`,
so browsers used auto layout and sized columns to fit the
longest content (e.g. "Debian GNU/Linux 12 (bookworm)") instead
of honouring the `max-width: 200px` on `<td>` cells. Result: the
table was a few pixels wider than the stats row and headers
above it.

Fix: added `table-layout: fixed`, set explicit widths on every
header column except OS (which stays auto and absorbs the
remaining space), removed the no-longer-useful `max-width` on
`<td>`. With fixed layout the table now sits exactly at the
container's content width and overflow is clipped via the
existing ellipsis rule.

### Tests

444 passing — unchanged. Pure CSS fix, no Python changes.


## v1.11.8 — 2026-05-06

### Fixed

**Monitor checks only ran when the dashboard was open.** Critical
since the monitor feature shipped. The `monitor_interval` config
existed but was never actually used by the server — checks ran
synchronously inside `GET /api/monitor`, so they only happened
when somebody loaded the Monitor page. `monitor_down` and
`monitor_up` webhooks miss the entire window when nobody is
browsing.

Fix: extracted the check logic into `_execute_monitor_checks()`
and added `run_monitors_if_due()` called from `main()` on every
CGI hit, gated on `monitor_interval` (60s floor). Agents
heartbeating every 60s trigger the dispatcher, which triggers
the monitor sweep, so monitors run on schedule as long as any
agent is alive.

Service monitoring was always real-time (rides every heartbeat)
and is unaffected.

**Dropdown menu clipped in minimal mode.** v1.11.7's
`overflow: hidden` on `.devices-minimal-wrap` clipped the ⋯
dropdown when it popped out of cells near the table edge. Fixed
with per-corner `border-radius` instead of overflow clipping,
plus z-index hoisting on the row containing an open dropdown via
`tr:has(.device-dropdown.active)`. Dropdown also re-anchored to
the right edge of the cell so it drops down-and-to-the-left
instead of pushing off the page.

### Tests

444 passing (433 from v1.11.7 + 11 new for periodic monitor
runner): gate logic (empty config, first call, within/past
interval, timestamp updates, back-to-back, sub-60s clamping),
webhook firing on transitions through the new path, no-double-
fire on persistent state.


## v1.11.7 — 2026-05-04

### Fixed

**Update history was always empty.** Critical bug shipped in
v1.10.0. The agent received the upgrade command, ran it, and
captured the output — but the result was assigned to a `payload`
dict *after* it had already been POSTed to the server. The next
loop iteration reset the dict and the data was discarded. Symptom:
`journalctl -u remotepower-agent` showed `Command output (rc=0):
...` correctly, but the dashboard's "Update history" panel said
"No update runs captured yet" forever.

Fix: agent now sends a dedicated minimal follow-up heartbeat right
after the command finishes, carrying just `device_id`, `token`,
`cmd_output`, and `executed_command`. Failed POSTs stash the
output to `/var/lib/remotepower-pending-cmd.json` for retry on the
next successful heartbeat.

The `command_executed` webhook had the same bug — same fix.

### Added

**Per-device "Upgrade packages" in the dropdown menu.**
Previously required selecting the device first or opening the
device modal. Now lives in the ⋯ menu on every device row,
between "Agent update" and "Update history".

**Minimal density rebuilt as a real `<table>`.** v1.11.6's
flex-row layout couldn't keep columns aligned across rows. Now
renders as a proper HTML table — Status / Name / Hostname / Group
/ OS / IP / Version / Last seen / Actions — with sortable
headers (asc / desc / clear; shift+click for secondary sort,
same UX as Services / CVEs / Containers tables). Responsive
breakpoints drop low-priority columns instead of letting them
overflow. The dropdown menu and all device actions work
identically to the cards path.

### Tests

433 passing (425 from v1.11.6 + 8 new for the cmd_output
follow-up flow): minimal payload acceptance, regression check on
no-cmd_output heartbeats, apt upgrade detector lands in
update_logs.json, ls/non-upgrade does not, three sequential
upgrades all captured, overflow trims oldest at the cap.

### Compatibility

Drop-in upgrade. Pre-v1.11.7 agents will still hit the bug —
agents must self-update to v1.11.7 for "Update history" to start
populating. Existing upgrade output that was lost on prior
versions cannot be recovered (the data never crossed the network).
From v1.11.7 forward, new upgrades are captured correctly.


## v1.11.6 — 2026-05-03

### Fixed

**Audit filter input lag.** The `<input id="audit-filter-text">`
had both an inline `oninput` and a listener attached by
`tableCtl.register()`, fighting each other. Result was a
one-keystroke lag and a confusing "nothing changed after Clear"
symptom. Fixed by removing the inline handler and adding a
`refresh:` hook to `tableCtl.register({...})` so pages that
compose multiple filters (free-text + action dropdown) re-render
through their own function rather than tableCtl's default. Same
hook flows through sort-header clicks.

### Added

**Patch report got sortable headers.** Existing 3-control filter
chain (text + group + device dropdown) keeps owning filtering;
sort layered on top via `match: () => true` and the new
`refresh:` hook.

**Maintenance windows got filter + sort.** New
`<input id="maint-filter">` above the table; header columns
wired sortable via tableCtl. Same UX as the other tables.

**Users, API Keys, Command Library got filter + sort.** All
three were inline one-liners in v1.11.5; refactored into the
register-helper pattern with per-column `getColumns` exposing
created timestamps, roles, and names as sortable values.

**Minimal density mode on the Devices grid — one device per
row.** New 4th option alongside Compact / Comfortable / Spacious.
~32px-tall horizontal row per device with icon, name, hostname,
status badge, and inline meta (OS, IP, Version, Poll/Enrolled).
The colored top stripe becomes a left border. Responsive
breakpoints drop lower-priority meta as the viewport narrows.
Built for scanning 50+ devices at a glance.

### Schema

- `UI_DENSITY_VALUES` extends to `('minimal', 'compact',
  'comfortable', 'spacious')`. Default stays `'comfortable'`.
- `tableCtl.register({...})` accepts a new optional `refresh:`
  callback used in place of the default re-render when set.

### Tests

425 passing (420 from v1.11.5 + 5 new for minimal density mode).
No regressions in the v1.11.4/5 suites.


## v1.11.5 — 2026-05-03

### Added

**Filter and sort on every fleet table.** Devices, Services, CVE
Findings, Containers, Monitor, TLS, Audit Log, Command History,
Schedule, and Maintenance all gained a substring filter input
above the table and clickable sortable column headers. First click
sorts ascending; second descending; third clears. Shift+click adds
a secondary sort key with a small superscript priority number.
The filter and sort state survive across reloads — they're
persisted per user via a new `/api/ui-prefs` endpoint.

**Density toggle on the Devices grid.** Three modes — Compact,
Comfortable (default), Spacious — accessible via a segmented
control in the Devices toolbar. Compact halves padding and
shrinks fonts; Spacious does the opposite. Per-user persistence.

**`/api/ui-prefs` endpoint.** GET reads, POST replaces (whole
document, not patch — avoids two-tab merge conflicts), DELETE
wipes. Stored as `users[username]['ui_prefs']` so it tags along
with user creation/deletion automatically. Sanitised server-side:
unknown fields silently stripped, filter strings capped to 256
chars, sort lists capped to 5 keys, total payload bounded at 16
KB. Three new constants: `UI_DENSITY_VALUES`, `UI_DENSITY_DEFAULT`,
`MAX_UI_PREFS_*`.

### Architecture

Two new vanilla-JS helpers in `index.html`: `tableCtl` (register
a tbody → get filter, sort, empty-state, and persistence) and
`densityCtl` (3-button segmented control with persistence). All
filtering and sorting is client-side; only pref values
roundtrip to the server, debounced 600 ms after the last change.
Logout flushes any pending save synchronously; `beforeunload` is
a fire-and-forget best-effort backup. Eight tables refactored to
use the helper.

### Tests

420 passing (397 from v1.11.4 + 23 new in `test_v1115.py`).
Coverage: sanitiser edge cases (empty input, unknown fields,
length caps, table-name path traversal, oversized payloads), all
three endpoint methods, per-user isolation, regression checks
against v1.11.4 functionality.

### Compatibility

Drop-in upgrade from v1.11.4. No new dependencies, no nginx
changes, no data migration. `users.json` records without the
`ui_prefs` field work identically to before; the field is
created lazily on first POST.


## v1.11.4 — 2026-05-03

### Fixed

**Container data went stale and never refreshed.** The agent's
container-listing path silently skipped sending the heartbeat
field whenever the list was empty (`if items:` gate). Hosts
going from "1 container" to "0 containers" — daemon restarts,
transient `docker ps` failures, or just the last container being
stopped — never overwrote the server's stored list. The
dashboard kept rendering whatever last non-empty snapshot the
agent had reported.

Fixed by always sending the (possibly empty) list when a runtime
is detected on the host. Hosts with no runtime installed at all
still skip entirely so we don't pollute `containers.json` with
empty rows.

### Added

**Container alerts.** Three new webhook events:

- `container_stopped` — running container is now gone or has a
  non-running status. Detected by diffing each heartbeat against
  the previous one, keyed on `(runtime, namespace, name)` so
  same-named containers in different k8s namespaces don't
  cross-fire.
- `container_restarting` — `restart_count` climbed by ≥1 since
  the last report. Mainly useful for Kubernetes pods (Docker
  `ps` doesn't expose this).
- `containers_stale` — no fresh report within
  `container_stale_ttl` (default 900s = 15 min). Fires once per
  stale period; auto-resets on fresh data. Suppressed for
  already-offline devices and unmonitored devices.

**Manual clear of stored container data.** `DELETE /api/devices/
{id}/containers` wipes one device's stored container snapshot
without affecting actual containers on the host. Useful for
decommissioning, forcing a redraw, or re-arming the
`containers_stale` webhook. UI button: "Clear data" in the
per-device modal.

**Stale-data UI indicators.** Amber `STALE` pill on Containers
overview rows, banner in the per-device modal explaining what
it means and where to look (`journalctl -u remotepower-agent`).

### Modified behaviour

- `DELETE /api/devices/{id}` now also cleans up the orphan
  `containers.json` entry and the `containers_stale_notified`
  flag. Pre-v1.11.4 these lingered and would resurrect on
  re-enrolment with the same id.

### Tests

397 passing (362 from v1.11.3 + 35 new in `test_v1114.py`).

---

## v1.11.0 — 2026-04-29

### Added

**Container awareness.** Every enrolled agent now detects Docker,
Podman, and Kubernetes pods independently — three try/except blocks
around three runtime probes, none of which can break the heartbeat
if a runtime is missing or stuck. Each runtime gets at most a
five-second timeout on its listing command. The agent normalises
output across all three (Docker's `--format '{{json .}}'` lines,
Podman's similar output, kubectl's `-o json` document) into a single
schema and posts a list of up to 100 entries every five polls,
roughly five minutes at the default cadence.

The server stores last-seen state, not history. Container state
changes too often for a rolling buffer to be useful, and "when did
this restart" is answered cheaply by the `restart_count` field
itself. A new "Containers" page in the sidebar shows fleet-wide
overview — device, OS, total/running/stopped counts, restart-flagged
counts (≥5 restarts is highlighted), and the runtimes present.
Click through to a per-device modal with image, tag, status,
namespace (for k8s), ports, and per-container restart count.

This is read-only by design. Start, stop, exec, logs — Portainer
exists, k9s exists, kubectl exists. RemotePower's job is "what's
running and is it healthy"; managing containers is a different
product entirely.

**Network map.** A new `connected_to: <device_id>` field on every
device, plus a "Network" page that renders the resulting graph as a
node-and-edge diagram. Manual topology only — no auto-discovery.
The user fills in "this switch is connected to that router" once,
and the graph reflects it. Nodes coloured by online status,
outlined by whether they're agent-driven or agentless. An "Edit
links" modal exposes a single table where every device's upstream
can be set in one place; changes save in batch.

The graph rendering is a small force-style layout that ships in
the SPA — no D3 dependency. It's not pretty for hundred-node
fleets, but the homelab/small-business audience tops out around 20
to 30 nodes where it works fine.

**Agentless devices.** Switches, APs, printers, IPMI cards,
cameras, smart plugs — all the infrastructure that can't run a
Python agent. A new `POST /api/devices/agentless` creates a device
record with `agentless: True`, no token, no heartbeat. Status is
whatever the user sets it to (`manual_status` field). Same CMDB
metadata, same vault credentials, same SSH link feature, same
documentation, same audit trail as agented devices — they're just
records the user maintains by hand. Fifteen device types are
validated server-side (switch, router, firewall, AP, printer,
camera, IPMI, UPS, PDU, NAS, IoT, smart plug, phone, plus "other"
as the safety valve). A "+ Agentless device" button on the Devices
page toolbar opens the create modal.

This is the first time RemotePower can model an entire homelab
rack rather than only the boxes that run Linux. It also makes the
network map useful — until you can model a switch, the topology
view has nowhere to root.

**TLS / DNS expiry monitor.** Server-side, cron-driven probes
against a configurable watchlist. Each probe does a TCP connect
(5s timeout) plus TLS handshake (5s timeout), parses the cert,
runs a separate verification pass against the system trust store,
and records DNS A/AAAA addresses. Errors at any layer become a
recorded result with the appropriate `dns_error`, `tls_error`, or
`verify_error` field rather than an exception — the next refresh
will retry.

Watchlist and results live in two flat files. Default thresholds
are 14-day warn / 3-day critical, overridable per target. A new
"TLS / DNS" page lists targets with status colour, days remaining,
issuer, and last-check timestamp; clicking a row opens a detail
modal with the full cert info (subject, SAN list, A/AAAA records).
"Scan now" runs the probe synchronously from the CGI; the
`remotepower-tls-check` helper script in `cgi-bin/` runs the same
code from cron or a systemd timer for the scheduled case.

The probe uses the Python stdlib's `ssl` module — no extra
dependency. The `cryptography` package was already pulled in for
the CMDB vault and would have been overkill here.

### Fixed

`Dockerfile` had a long-standing bug: it only copied `api.py` to
the container, missing every sibling module. This silently broke
the CMDB feature in Docker deployments since v1.9.0 (the import of
`cmdb_vault` would fail) and the OpenAPI page since v1.10.0 (same
for `openapi_spec`). v1.11.0 fixes the COPY directive to grab the
entire `server/cgi-bin/` directory.

`install-server.sh` had the same bug — only `api.py` was installed
on a fresh machine, sibling modules silently missing. Both v1.9.0
and v1.10.0 worked because users were typically using
`deploy-server.sh` (which already auto-discovered the modules) for
upgrades, but a fresh install via `install-server.sh` would have
been broken. v1.11.0 auto-discovers all `*.py` files in
`server/cgi-bin/` plus the new helper scripts.

These fixes ship with v1.11.0 but apply equally to anyone running
v1.9.0 or v1.10.0 in Docker — upgrading to v1.11.0 fixes the
silently-broken CMDB feature.

### New endpoints

```
GET    /api/containers                          fleet overview
GET    /api/devices/{id}/containers             per-device list
GET    /api/network-map                         nodes + edges for the map
PUT    /api/devices/{id}/connected-to           set upstream link
POST   /api/devices/agentless                   create manual device
GET    /api/tls/targets                         watchlist + last results
POST   /api/tls/targets                         add target
DELETE /api/tls/targets/{id}                    remove target
POST   /api/tls/scan                            probe all targets now
```

### New files

- `server/cgi-bin/containers.py` — container normalisation
- `server/cgi-bin/tls_monitor.py` — TLS/DNS probe logic
- `server/cgi-bin/remotepower-tls-check` — cron runner
- `tests/test_v1110.py` — 33 new tests
- `docs/containers.md`, `docs/network-map.md`, `docs/tls-monitor.md`,
  `docs/agentless-devices.md`

### New data files

- `containers.json` — `{device_id → {ts, items: [...]}}` last-seen state
- `tls_targets.json` — `{tls_<hex> → {host, port, label, warn_days, crit_days}}`
- `tls_results.json` — `{tls_<hex> → {checked_at, expires_at, issuer, ...}}`

### Modified data files

`devices.json` records gain four optional fields:
`agentless` (bool), `connected_to` (device_id), `device_type` (string),
`manual_status` (bool). Missing fields default to empty/False at
read time — fully backwards-compatible with v1.9.x and v1.10.x data.

### Tests

**301 passing.** The new test file covers containers module
(normalisation, runtime aliases, port caps, listing caps, garbage
input handling, summarisation), TLS module (target validation,
threshold logic, days-until-expiry math), heartbeat acceptance
(containers field, overwrite behaviour), container endpoints
(empty state, summary correctness, per-device retrieval, 404 on
unknown device), network map (graph shape, dangling-edge dropping,
self-link rejection, nonexistent-target rejection, clearing),
agentless creation (minimal, type validation, connected-to
validation, devices-list surfacing), and TLS endpoints (add,
delete, list with status, 404 on unknown).

### Compatibility

Forwards- and backwards-compatible in both directions between
v1.10.0 and v1.11.0. Servers running either version accept agents
running either version. Older agents don't populate the
`containers` field; older servers ignore it if posted. The new
fields on `devices.json` default to empty when missing, so
existing data files continue to work unmodified.

No new request headers — the existing nginx config works
unchanged. No new outbound connections from the agent (containers
listing is local-only). The TLS probe is server-initiated, so any
firewall rules controlling outbound from the RemotePower server
itself need to allow connections to the targets being probed.

### Suggested cron

A systemd timer or cron entry for the TLS probe, every six hours:

```
0 */6 * * * www-data /var/www/remotepower/cgi-bin/remotepower-tls-check
```

The probe is idempotent — running it more often is safe but
mostly wastes outbound connections. Less often is fine too;
"warn at 14 days" gives plenty of headroom for a daily probe
schedule if you prefer.

---

## v1.10.0 — 2026-04-29

### Added

**Swagger / OpenAPI documentation.** The full public API surface is now
documented in an OpenAPI 3.1 specification served at
`/api/openapi.json`. A new "API Docs" link in the sidebar opens
`/swagger.html`, a Swagger UI page that renders the spec and lets you
make real authenticated requests against your live server with a
single click — the page injects your existing session token into every
"Try it out" request, so there's no Authorize button to fiddle with.
The spec covers 22 endpoints across seven tags: Auth, Devices,
Commands, CMDB, Vault, Credentials, and Reporting. It's hand-written
rather than auto-generated from the CGI dispatch table, on the theory
that hand-written specs stay accurate where auto-generated ones drift
silently when handler internals change.

**SSH link from credentials.** Every credential row in the CMDB
Credentials tab gets two new buttons: a clickable `ssh://user@host:port`
link that opens in your default SSH-URI handler (PuTTY on Windows,
iTerm or Terminal.app on macOS, whatever you've configured on Linux),
and a Copy button that puts a plain `ssh user@host -p port` command
on your clipboard. The host comes from the asset's hostname (or IP if
hostname is empty), the port from a new per-asset `ssh_port` field
(default 22, validated 1-65535), and the username from the credential.
The password is **deliberately not** included in the URI — `ssh://`
URIs technically can carry one but that ends up in browser history
and process tables, so the password stays in the reveal modal where
it belongs.

**OS icons.** Both the Devices page and the CMDB asset table now show
a small inline-SVG icon next to each device's OS string. Two icons,
total: Tux for anything Linux-shaped (Ubuntu, Debian, Fedora,
RHEL/Rocky/CentOS, Arch, Alpine, openSUSE, Mint, NixOS, plus
anything containing "linux" or "gnu"), and a tile for Windows. Other
operating systems — macOS, BSD, exotic things — get a question-mark
glyph so detection failures are visible rather than silently shown
as a generic icon. The glyphs use `currentColor` so they inherit
the surrounding text colour.

**Update history.** The Patches feature has been a one-way street
since v1.7 — push an upgrade and hope. v1.10.0 captures the output.
The agent's exec output cap is bumped from 4 KB to 256 KB for
upgrade commands (`apt -y upgrade`, `dnf -y upgrade`, `pacman -Syu`)
so the output isn't truncated mid-package; the heartbeat handler
dual-routes that output into a new `update_logs.json` file with a
rolling buffer of the last 10 runs per device. The device dropdown
menu has a new "Update history" link that opens a modal showing each
run with timestamp, package manager, exit code, duration, and full
output (collapsed by default; the most recent expanded). New endpoint
`GET /api/devices/{id}/update-logs` for scripting access.

**Audit log filtering.** The audit log page gained two filter inputs:
a free-text search box that matches across actor, action, and detail,
and an action-type dropdown auto-populated from whatever actions
appear in the data. Both filters are client-side — the data is small
enough that server-side filtering would be over-engineering — and
combine: pick `cmdb_credential_reveal` from the dropdown to see
nothing but reveals, then type a username in the search box to narrow
to that admin's reveals.

### Code quality

This release introduces the project's first formal lint pipeline.
A new `pyproject.toml` configures `black` (100-char lines), `isort`
(black profile), and `mypy` (strict on the new modules
`cmdb_vault.py` and `openapi_spec.py`, permissive on the legacy
`api.py`). A new `Makefile` adds `make test`, `make lint`, `make
format`, `make typecheck`, `make check`, and `make install-dev`. The
`make lint` target is intentionally scoped to the v1.10.0 baseline
files — running black across the entire 5800-line `api.py` would
produce an unreviewable diff in this release; broadening the scope
is its own deliberate effort.

A small but meaningful cleanup: the long-standing `respond(); sys.exit(0)`
pattern is replaced by a proper `HTTPError(status, body)` exception
that bubbles up to a single handler at the top of `main()`. The
public behaviour is identical — same HTTP envelope, same status
codes, same JSON bodies — but handlers are now testable as plain
function calls without monkey-patching `sys.exit`. The legacy test
helpers continue to work because they monkey-patch `respond` at
import time and never see the exception. Tests added: 24 new in
`tests/test_v1100.py`, taking the suite from 244 to 268 passing.

The v1.9.0 CMDB handlers received type hints and Google-style
docstrings as the start of a wider documentation pass. Strict mypy
catches both flagged issues in `cmdb_vault.py` (a missing return
annotation on `_crypto`, an `Optional[str]` mis-typed as `str`).

### Bonus

`GET /api/cmdb/{device_id}` now trims the embedded `sysinfo` dict
from the heartbeat (50+ KB on rich systems) to nine whitelisted
fields totalling under 1 KB. The CMDB modal only displays
CPU/RAM/disk/uptime headlines anyway; trimming makes the modal pop
open instantly even on assets with elaborate sysinfo.

### New endpoints

```
GET  /api/openapi.json                         OpenAPI 3.1 spec
GET  /api/devices/{device_id}/update-logs      rolling buffer of upgrade output
```

### Modified endpoints

```
PUT  /api/cmdb/{device_id}                     accepts new ssh_port field
GET  /api/cmdb                                 response includes ssh_port
GET  /api/cmdb/{device_id}                     response includes ssh_port; sysinfo trimmed
```

### New files

`server/cgi-bin/openapi_spec.py`, `server/html/swagger.html`,
`pyproject.toml`, `Makefile`, `tests/test_v1100.py`,
`docs/swagger.md`, `docs/update-history.md`.

### Tests

**268 passing** (244 from v1.9.0 + 24 new). The new suite covers:
`HTTPError` exception + rendering, the full ssh_port lifecycle
(default, set, reset-to-default via 0, range validation, list
surfacing), sysinfo trim (whitelist behaviour, non-dict input,
end-to-end through the GET handler), update logs (empty state,
ordered runs, 404 on unknown device, capacity-cap enforcement),
and OpenAPI spec generation (structure, security schemes, critical
endpoints documented, fresh-object-per-call, handler returns 200
with the spec, handler requires auth).

### Compatibility

v1.9.0 and v1.10.0 are mutually compatible. The agent binary is
unchanged in shape — older agents work with the new server, just
truncating upgrade output at the 4 KB the older code allowed.
CMDB records created before v1.10.0 are missing the `ssh_port`
field; the server backfills it with the default 22 on read, so
nothing migrates and nothing breaks.

### Known limitations

- Update logs are populated on the next heartbeat (~60s) after a run
  completes. There's no live streaming. A streaming implementation
  via long-polling or SSE was discussed and deferred — the simpler
  heartbeat approach reuses what already works and the latency is
  acceptable for the actual use case (post-hoc review of what
  happened).
- Swagger UI loads its assets from a pinned CDN version. Fully-air-
  gapped servers will fall back to a plain-text "raw spec at
  /api/openapi.json" message rather than rendering. Bundling Swagger
  UI inline would add ~700 KB to every dashboard page load, which is
  a worse trade-off than the offline degradation.
- `make lint` is scoped to the v1.10.0 baseline files. Expanding to
  the full codebase is its own effort and shouldn't share a release
  with feature work.

---

## v1.9.0 — 2026-04-27

### Added

**CMDB — Configuration Management Database.** A new "CMDB" page in the
sidebar (between Devices and Monitor) gives every enrolled device an
optional metadata layer: a free-text **asset_id** for inventory tags, a
**server_function** field (web, db, dc, logging, …) with autocomplete
populated from the existing fleet, an optional **hypervisor_url**
rendered as a click-through link, and **Markdown documentation** up to
64 KB per asset with side-by-side edit and rendered-preview tabs. The
page joins `devices.json` with the new `cmdb.json` so every enrolled
device is implicitly an asset — no separate enrollment step. A search
box filters across name, asset_id, IP, function, and documentation; a
function dropdown narrows the table to a single role.

**Encrypted credential vault.** Each asset can store up to 25
credentials — root, service accounts, IPMI, web admin panels, whatever
— with per-credential label, username, optional note, and an encrypted
password. The crypto stack is **AES-GCM 256-bit** with **PBKDF2-SHA256
key derivation** at 600 000 iterations (OWASP 2023 minimum), a 32-byte
random salt, and a fresh 12-byte nonce on every encryption. The model
is a **shared admin passphrase** rather than per-user keys: the team
sets one passphrase at vault setup, all admins use it, and rotation
re-encrypts every credential atomically.

The passphrase is **never persisted server-side**. An admin enters it
in the unlock modal, the server derives the key and returns it as hex,
the browser holds it in a single closure variable in JS memory, and
clears it on logout, page reload, or an explicit "Lock" button.
Subsequent credential operations send the key in an `X-RP-Vault-Key`
request header. The server checks every key against an encrypted
canary blob stored in `cmdb_vault.json` so a wrong key never touches
real credentials.

Reveal (the API call that actually returns plaintext) is **admin-only
and audit-logged** with the actor, source IP, asset, and credential
label. Per-credential metadata stays plaintext for searchability — only
the password ciphertext is encrypted. List endpoints redact the
ciphertext entirely; only `/reveal` ever decrypts.

The crypto module (`cmdb_vault.py`) is a sibling of `cve_scanner.py`
and `prometheus_export.py`. It imports the `cryptography` library
lazily, so the rest of the API stays fully alive on servers that don't
have it installed yet — vault operations return a clear error in that
case, but everything else (asset metadata, documentation, search) keeps
working.

**Passphrase rotation.** `POST /api/cmdb/vault/change` takes the old
passphrase, verifies it against the canary, derives the new key, walks
every credential in `cmdb.json`, decrypts with the old key, and
re-encrypts with the new key in memory before persisting. If a
credential fails to decrypt during rotation (corrupt entry), it's
dropped and the event is recorded as `cmdb_vault_change_drop` in the
audit log so the admin can investigate. The new vault metadata is
written first; the new credential file second; a crash mid-rotation
leaves the vault recoverable with the old passphrase.

### Endpoints

```
GET    /api/cmdb                                          list assets + metadata
GET    /api/cmdb/{device_id}                              full asset detail (creds redacted)
PUT    /api/cmdb/{device_id}                              patch metadata + documentation
GET    /api/cmdb/server-functions                         distinct functions for autocomplete
GET    /api/cmdb/vault/status                             configured? KDF? created_at?
POST   /api/cmdb/vault/setup                              admin; one-shot
POST   /api/cmdb/vault/unlock                             returns derived key
POST   /api/cmdb/vault/change                             admin; rotates + re-encrypts
GET    /api/cmdb/{device_id}/credentials                  metadata only
POST   /api/cmdb/{device_id}/credentials                  admin + X-RP-Vault-Key
PUT    /api/cmdb/{device_id}/credentials/{cred_id}        admin (key required only if pw changes)
DELETE /api/cmdb/{device_id}/credentials/{cred_id}        admin
POST   /api/cmdb/{device_id}/credentials/{cred_id}/reveal admin + key, audit-logged
```

### New data files

- `cmdb.json` — `{device_id → record}`, where each record has
  `asset_id`, `server_function`, `hypervisor_url`, `documentation`,
  and a `credentials` list. Each credential is
  `{id, label, username, note, nonce, ct, created_by/at, updated_by/at}`.
- `cmdb_vault.json` — vault metadata only:
  `{kdf, iterations, salt, canary_nonce, canary_ct, created_by/at, rotated_by/at}`.
  Contains zero plaintext, zero key material — safe to back up to the
  same place as the rest of `/var/lib/remotepower`.

### New audit-log actions

`cmdb_update`, `cmdb_vault_setup`, `cmdb_vault_unlock`,
`cmdb_vault_unlock_failed`, `cmdb_vault_change`, `cmdb_vault_change_failed`,
`cmdb_vault_change_drop`, `cmdb_credential_add`, `cmdb_credential_update`,
`cmdb_credential_delete`, `cmdb_credential_reveal`,
`cmdb_credential_reveal_failed`.

### New dependency

`cryptography` (Python). `install-server.sh` installs it via pip with a
distro-package fallback (`python3-cryptography` on Debian/Ubuntu/Fedora,
`python-cryptography` on Arch). It's the only feature that needs it; if
the install fails the rest of the server still runs and CMDB metadata
remains usable — only credential ops report a clean
"vault not installed" error.

### Limits

- 64 KB Markdown documentation per asset
- 25 credentials per asset
- 1 KB max password length
- 64-char labels, 128-char usernames, 512-char notes
- `server_function`: 64 chars, charset `[A-Za-z0-9 _\-/]`
- Vault passphrase: 12-256 chars, must contain at least 2 of
  {lowercase, uppercase, digit, symbol}

### Tests

**244 passing, 0 failing** (1 pre-existing skip). The new suite
`tests/test_v190.py` adds 32 tests across five classes:
`TestVaultCrypto` (KDF derivation, canary verification, fresh nonces,
key-header parsing strictness), `TestVaultEndpoints` (status, setup,
unlock with audit on bad passphrase), `TestAssetCrud` (404 paths,
asset_id charset, hypervisor URL scheme rejection, oversized doc,
search filtering), `TestCredentials` (add/list/delete/reveal,
ciphertext redaction in list, vault-locked vs auth-locked 401
distinction, max-credential cap, full passphrase rotation
re-encrypting two credentials and verifying reveal under the new key),
and `TestServerFunctions` (autocomplete distinct-value sorting).

### Compatibility

v1.8.x clients are fully compatible with v1.9.0 servers — CMDB is a
server-side feature, the agent binary is unchanged. A v1.9.0 server
started against an existing v1.8.x data directory creates `cmdb.json`
and `cmdb_vault.json` lazily on first write. The vault is opt-in: the
CMDB page works in read-only metadata mode until an admin calls
`/api/cmdb/vault/setup`.

---

## v1.8.6 — 2026-04-26

### Added

**SMTP / email notifications.** Email is now a sibling channel to webhooks
— same events, same maintenance-window suppression, same per-event toggles.
The Notifications tab gains an SMTP section: host, port, TLS mode
(STARTTLS / implicit TLS / plain), From address, optional auth, optional
HELO override, recipients list, and a "Send test email" button with
optional override recipient.

The per-event toggle table now has two columns: **Webhook** (existing,
opt-out) and **Email** (new, opt-in per event). Email is opt-in because
nobody wants every device-online event to land in their inbox.

Three TLS modes:
- `starttls` (port 587) — modern default, STARTTLS upgrade after EHLO
- `tls` (port 465) — implicit TLS, the older "SMTPS" port
- `plain` (port 25) — no TLS; only safe to localhost or trusted relays

Auth is optional. Empty username = no AUTH attempted (useful for localhost
relays that allow anonymous submission). Passwords are stored in
`config.json` and masked in `GET /api/config` responses (the UI just sees
a `smtp_password_set: true` flag).

**LDAP / LDAPS authentication.** External auth source for login. Local
users in `users.json` are tried first — emergency local admin always works
even if LDAP is down. Users authenticated via LDAP are auto-provisioned
into `users.json` with the role determined by group membership.

Configuration in the Security tab:
- LDAP URL (`ldaps://` or `ldap://`)
- TLS verification toggle (set to off only for self-signed CAs in dev)
- Service account DN + password (used for the search step; the user's
  own credentials verify the password in a second bind)
- User search base + filter — `(uid={u})` for OpenLDAP/FreeIPA,
  `(sAMAccountName={u})` for AD
- **Required group DN** — empty allows any user with valid creds; set
  this to lock login to a specific group
- **Admin group DN** — members get the `admin` role on login; everyone
  else gets `viewer`. Auto-promotes existing local users on next LDAP
  login but never auto-demotes.
- Two test buttons: "Test connection" (verifies the service account
  bind) and "Test user login" (full auth path with a real username/password
  pair, doesn't create a session)

Library: **ldap3** (pure Python). The module imports lazily, so servers
that don't enable LDAP don't need the library installed at all. To
install: `pip3 install ldap3` (Fedora: `dnf install python3-ldap3`).

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/smtp/test` | Send a test email; optional `{"recipient": "..."}` override |
| POST | `/api/ldap/test` | Verify service-account bind (URL/TLS/creds). Body fields override config for "test before save" UX. |
| POST | `/api/ldap/test-user` | Run the full auth path for one user. Returns DN, role, full name, email. |

### New config keys

| Key | Type | Purpose |
|-----|------|---------|
| `smtp_enabled` | bool | Master toggle for email channel |
| `smtp_host` / `smtp_port` / `smtp_tls` | string / int / enum | Server config |
| `smtp_from` | string | From address (must contain `@`) |
| `smtp_username` / `smtp_password` | string | Optional AUTH; password masked on GET |
| `smtp_helo_name` | string | Override HELO/EHLO hostname |
| `smtp_recipients` | string | Comma/semicolon/whitespace-separated list |
| `email_events` | dict | `{event_name: bool}` per-event opt-in |
| `ldap_enabled` | bool | Master toggle |
| `ldap_url` | string | `ldaps://...` or `ldap://...` |
| `ldap_bind_dn` / `ldap_bind_password` | string | Service account creds |
| `ldap_user_base` | string | Search base |
| `ldap_user_filter` | string | Must contain `{u}` |
| `ldap_required_group` / `ldap_admin_group` | string | Group DNs |
| `ldap_tls_verify` | bool | Default true |
| `ldap_timeout` | int | Seconds, 1–60, default 5 |

### Changed

- All version strings bumped to 1.8.6
- `fire_webhook()` is now a single dispatch point — runs the shared gates
  once, then fans out to webhook AND email channels in turn. The hard
  rename was avoided because of dozens of call sites; the function still
  has the historical name.
- `handle_login` gains an LDAP fallback path. Tried only when local auth
  fails; LdapTransientError logs to audit but presents as plain
  invalid-credentials to the client (no info leak about whether LDAP is
  reachable).
- Auto-provisioned LDAP users get a placeholder `password_hash` that
  never matches anything. Subsequent local-auth attempts fail and fall
  through to LDAP again — there's no way to "downgrade" an LDAP user
  to local-only by accident.
- `users.json` entries gain optional `ldap_dn`, `ldap_full_name`,
  `ldap_email` fields when created via LDAP.

### Tests

30 new tests in `tests/test_v186.py`:
- SMTP: recipients parser (5 cases), per-event email toggle (5 cases),
  input validation (5 cases), email render (2 cases)
- LDAP: filter escaping (2 cases), authenticate() success/failure paths
  (5 cases) using a fake `ldap3` module installed in `sys.modules`,
  required-group enforcement, role mapping
- Wiring + version checks (3 cases)

**Full suite: 212 passing, 0 failing** (1 pre-existing skip).

### Notes

- LDAP requires the `ldap3` library on the server. Empty config + disabled
  toggle is the default, so no library needed unless you turn it on.
  Server emits `LdapTransientError: ldap3 library not installed` if
  enabled without the library — surfaces in the audit log.
- SMTP works with any RFC 5321 server. Tested mentally against Postfix,
  AWS SES, Gmail, Mailgun, Sendgrid, ProtonMail Bridge.
- Email recipients are a flat fleet-wide list (everyone gets every
  enabled event). Per-user opt-in is not a v1.8.6 feature; could happen
  in 1.9.0 if anyone asks.
- The "Test user login" button in the LDAP section is admin-only and
  doesn't create a session — it just runs `authenticate()` against the
  current config and shows what would happen. Useful for verifying the
  filter/group config without making the user log out.
- Enabling LDAP doesn't disable local auth. There's no "LDAP-only" mode
  by design — if LDAP breaks, you can still log in as a local emergency
  admin and fix it.

### Compatibility

- v1.8.5 servers work with v1.8.6 clients (everything's additive).
- v1.8.5 → v1.8.6 needs no migration. SMTP and LDAP are off by default;
  saving Settings once writes the new keys with their defaults.
- Agent binary unchanged from v1.8.5 except for the version string.

---

## v1.8.5 — 2026-04-26

### Fixed

**"Remember me" actually remembers now.** v1.8.4 introduced the checkbox and
the per-token TTL on the server side, but the client always saved the token
to `sessionStorage` — which by definition is wiped when the browser closes.
The 30-day server-side TTL was correct; the browser was just throwing away
the token at the end of every tab session. Particularly visible if you have
2FA enabled because every reload meant another full login dance.

The fix:

- When "remember me" is checked, the token + username are saved to
  **`localStorage`** (persists across browser restarts).
- When unchecked, they go to **`sessionStorage`** as before (cleared with
  the tab — explicit "this is a kiosk / public computer" semantics).
- `getToken()` now reads from both stores, preferring localStorage.
- `getMe()` (new helper) does the same for the username display.
- `checkAuth()` (called on page load) uses `getToken()` instead of reading
  sessionStorage directly — which was the actual bug that made remember-me
  a no-op for users with 2FA.
- `doLogout()` clears both stores so toggling between modes doesn't leave
  stale credentials behind.
- Login flow clears both stores before writing the new token, preventing
  any cross-mode contamination if the user toggles the checkbox.

### Changed

- All version strings bumped to 1.8.5
- No server-side or agent changes — this is a pure client-side bug fix
- No data file changes; existing tokens keep working

### Tests

182 passing, 0 failing (1 pre-existing skip). No new tests; this is a
DOM-only behavior fix that's easier to verify by hand than to mock in
unittest. To verify after deploy:

1. Tick "Remember me", log in, complete 2FA
2. Close the browser entirely (not just the tab)
3. Reopen, navigate to the dashboard URL → should land on the app, not
   the login page

If you uncheck "Remember me" and repeat, the second visit should bounce
you to login as expected (sessionStorage was cleared with the browser).

### Notes

- This is purely a client bug. v1.8.4 servers work fine with v1.8.5
  clients and vice versa. The agent binary is byte-identical apart from
  its version string.
- If you've been logging in with 2FA repeatedly because remember-me
  seemed broken — sorry, that's on me. Should work now.

---

## v1.8.4 — 2026-04-25

### Added

**Settings page reorganized into 4 tabs.** The flat scrolling list was getting
out of hand. New tabs: **General**, **Notifications**, **Security**, **Advanced**.
URL hash drives tab selection so you can bookmark `#settings/security` etc.

**Server identity** (`server_name`). Display name shown in:
- Browser title (`<title>`)
- Login page header
- Webhook payloads (as `_server_name`)
- Push notifications (consumers can render it however they like)

**Default poll interval** for new agent enrollments. Was hardcoded to 60s; now
configurable in 10–3600s range from the General tab. Existing devices keep
their per-device poll interval — change individual devices from their detail
page.

**Online TTL** (when a device is considered offline). Was hardcoded `ONLINE_TTL = 180`;
now a config value with a 90-second floor (`MIN_ONLINE_TTL`) to prevent
configurations where devices would flap between polls.

**CVE details cache TTL** (`cve_cache_days`, default 7). Was hardcoded in
`cve_scanner.py`; now passed from the server config to `scan_device()`.

**Per-event webhook toggles.** Replaces the four legacy boolean flags
(`offline_webhook_enabled`, `monitor_webhook_enabled`, `cve_webhook_enabled`,
`service_webhook_enabled`) with a single `webhook_events` dict listing all
11 event types individually:

- `device_offline`, `device_online`
- `monitor_down`, `monitor_up`
- `patch_alert` (with embedded threshold input on the same row)
- `cve_found` (with severity-filter checkboxes for which severities fire)
- `service_down`, `service_up`
- `log_alert`
- `command_queued`, `command_executed`

Disabled events get logged to the webhook log as `"disabled"` so you can see
what was suppressed.

**CVE severity filter.** `cve_found` webhooks previously fired on critical/high
hardcoded; now you choose which severities fire from
`{critical, high, medium, low, unknown}`. Default unchanged.

**Remember-me on the login page.** Tickbox below password field. Two session
TTLs: short (default 24h, used when unchecked) and long (default 30 days,
used when checked). Both configurable from Security tab. Server-side
admin can pre-tick the box via `remember_me_default`.

Tokens now carry their own TTL in `tokens.json`, so a long session created
with "remember me" doesn't get pruned by the cleanup of short tokens.
Legacy tokens without a TTL field fall back to the old global `TOKEN_TTL`.

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/public-info` | Unauthenticated. Returns `server_name`, `server_version`, `remember_me_default` for the login page |

### New config keys

| Key | Type | Default | Where |
|-----|------|---------|-------|
| `server_name` | string | `""` (renders as "RemotePower") | General |
| `default_poll_interval` | int (seconds) | 60 | General |
| `online_ttl` | int (seconds) | 180 (min 90) | General |
| `cve_cache_days` | int | 7 (1–90) | General |
| `webhook_events` | dict[str, bool] | all true | Notifications |
| `cve_severity_filter` | list[string] | `["critical", "high"]` | Notifications |
| `session_ttl_short` | int (seconds) | 86400 | Security |
| `session_ttl_long` | int (seconds) | 86400 × 30 | Security |
| `remember_me_default` | bool | false | Security |

### Backward compatibility

All four legacy webhook toggle keys (`offline_webhook_enabled`,
`monitor_webhook_enabled`, `cve_webhook_enabled`, `service_webhook_enabled`)
still work as fallbacks when `webhook_events` is not set. When `webhook_events`
is present, it takes precedence. UI saves to the new key from now on, so
upgrades from 1.8.3 are seamless on first save.

The `cve_found` webhook used a hardcoded `('critical', 'high')` allowlist
inside `_detect_new_cve_and_fire_webhook`; this is now driven by
`get_cve_severity_filter()`. Existing servers without the config key get
the same behavior they had before.

### Changed

- All version strings bumped to 1.8.4
- `ONLINE_TTL` (module constant) → `get_online_ttl()` helper. The constant
  `DEFAULT_ONLINE_TTL` still exists for tests.
- `_detect_new_cve_and_fire_webhook()` now respects `webhook_events.cve_found`
  and uses `get_cve_severity_filter()` for severity.
- `fire_webhook()` runs every event through `is_webhook_event_enabled()` and
  applies severity filtering for `cve_found`. Suppressed events are logged
  as `"disabled"` or `"filtered"` for observability.
- `handle_login` reads `remember_me` from the body and stores per-token TTL.
- `verify_token` and `cleanup_tokens` honor `entry['ttl']` per token,
  falling back to `TOKEN_TTL` for legacy tokens.

### Tests

34 new tests in `tests/test_v184.py` covering:
- All 8 config helpers (defaults, explicit values, clamping)
- Legacy → new webhook key migration
- CVE severity filter validation
- Per-token TTL semantics + legacy token fallback
- WEBHOOK_EVENTS contract (event set + entry shape)

`tests/test_api.py` updated to use `DEFAULT_ONLINE_TTL` instead of removed
`ONLINE_TTL` constant. New regression test for the helper clamping behavior.

**Full suite: 182 passing, 0 failing** (1 pre-existing skip).

### Notes

- Going from 1.8.3 → 1.8.4 needs no data migration. Settings open with
  defaults; saving once writes the new keys.
- The Settings tabs preserve URL hash so `https://server/#settings/security`
  jumps straight to the right tab.
- "Remember me" extends the session lifetime on the server side; it does
  *not* persist credentials anywhere on the client. Logging out still
  invalidates the token immediately.

---

## v1.8.3 — 2026-04-25

### Fixed

**SSH/sshd alias resolution.** On Debian/Ubuntu, the SSH unit is named
`ssh.service` and `sshd.service` is just an alias. `journalctl` does NOT
follow systemd unit aliases, so users who typed the RHEL-style
`sshd.service` in their watched-services list got zero log lines forever
even though state checks worked fine.

- Agent: new `_resolve_unit_alias()` helper queries `systemctl show
  <unit> --property=Id` to get the canonical name, then runs
  `journalctl -u <canonical>` instead. Falls through silently to the
  original name on any error.
- `get_services()` now also returns the canonical name in the heartbeat
  payload (under `canonical` key), so the UI can show "sshd.service →
  ssh.service" if you ever want to surface the resolution.
- No data-format breakage; no config changes needed. Existing installs
  with `sshd.service` watched on Debian will start receiving logs after
  the agent self-update.

### Added

**Calendar — shared events page.** Standalone shared calendar at
`/api/calendar`. Fully shared across all users; any authenticated user
can create/edit/delete events. Designed to live next to the existing
Schedule page (which is for cron-driven device commands), not replace it.

- Month-grid view, click a day to create an event, click an event pill
  to edit. Events span across days; days with more than 3 events show
  a "+N more" indicator.
- 7-color palette (blue/green/amber/red/purple/teal/slate). Server
  validates against an explicit allowlist — passing an unknown color
  silently falls back to blue.
- Events have title, optional description, ISO-8601 start (required) and
  end (defaults to start), all-day flag, and color.
- New endpoints:
  - `GET /api/calendar?from=<iso>&to=<iso>` — list events overlapping the range
  - `POST /api/calendar` — create
  - `PUT /api/calendar/{id}` — update
  - `DELETE /api/calendar/{id}` — remove
- Capped at 1000 events per server (`MAX_CALENDAR_EVENTS`).

**Tasks — shared kanban board.** Four states (upcoming / ongoing /
pending / closed). Fully shared with no per-user assignment.

- Drag-and-drop between columns to change state. Optimistic update;
  resyncs from server on failure.
- Optional device linking: every task can be tied to one device or none.
  Device chip shown on the card; filter dropdown on the page narrows
  the board to one device's tasks (or "no device linked").
- Click a task to expand/edit; "+ New task" button.
- New endpoints:
  - `GET /api/tasks?state=<s>&device=<id>` — list with optional filters
  - `POST /api/tasks` — create
  - `PUT /api/tasks/{id}` — update (partial; can be just `{state: 'closed'}`)
  - `DELETE /api/tasks/{id}` — remove
- Capped at 500 tasks per server (`MAX_TASKS`).

### New data files

| File | Purpose |
|------|---------|
| `calendar.json` | Shared calendar events |
| `tasks.json` | Shared task board |

### Changed

- All version strings bumped to 1.8.3
- Agent `get_services()` payload may include a `canonical` key per service
  if the user-supplied unit name was an alias
- Sidebar navigation: new "Calendar" and "Tasks" entries between
  Schedule and the Tools section divider

### Tests

24 new tests in `tests/test_v183.py`:
- Calendar: 8 cases for event validation (color clamping, end-after-start,
  required fields, full palette acceptance)
- Tasks: 9 cases for task validation (state allowlist, partial updates,
  device-id resolution, unlink semantics)
- Agent: 3 cases for `_resolve_unit_alias` with mocked systemctl
- Constants and handlers: 4 wiring checks

Loosened the version assertion in `test_v182.py` from exact-match to
`>= 1.8.2` (same pattern as `test_v181.py`) so the test doesn't break
on every patch bump.

**Full suite: 147 passing, 0 failing** (1 pre-existing skip).

### Notes

- The calendar is intentionally separate from Maintenance and Schedule.
  Maintenance windows suppress webhooks; Schedule drives device commands;
  Calendar is just a shared notepad for "what's happening when". Mixing
  them would be a different design.
- Tasks have no due dates by design — if you need a due date, create a
  calendar event with the same title. The two compose naturally.
- Device linking on tasks is one-to-one (a task has one device or none).
  If you need a task that touches multiple devices, link it to none and
  mention them in the description.
- Both features use the standard X-Token auth (no special role required
  for create/edit/delete). If you want admin-only mutations, add
  `require_admin_auth()` to the handlers — small change.

---

## v1.8.2 — 2026-04-24

### Fixed

**Log tail bug: quiet devices invisible on the Logs page.** In v1.8.0/1.8.1,
the agent silently skipped a unit if `journalctl` returned no recent lines,
and the whole submission was skipped if every watched unit was quiet. Result:
a device with watched services but a calm workload (e.g. sshd on an idle
box, nginx with no traffic) never created an entry in `log_watch.json` and
was indistinguishable from a device not running the agent at all.

- Agent now always includes every watched unit in the submission, with an
  empty list if the unit was quiet
- Agent now always POSTs when it has watched units, even if all are empty
- Server preserves the unit key with an empty array, so the device appears
  on the Logs page as "watched, quiet in this window" rather than absent
- Live tail empty-state now diagnoses the three distinct cases:
  "no devices submitting", "devices reporting but quiet", and "current
  filter matches nothing"

### Added

**Fleet-wide log alert rules** — rules that apply across the whole fleet,
complementing the existing per-device rules from v1.8.0.

- New `log_rules_global.json` storage; new endpoints
  `GET/POST /api/logs/rules/global` and `DELETE /api/logs/rules/global/{id}`
- Wildcard unit: setting `unit="*"` matches any unit on any device (useful
  for catch-all patterns like `OOMkilled`). Specific unit name matches all
  devices running that unit.
- `handle_log_submit` now evaluates both per-device and fleet-wide rules
  against incoming lines. Each `(scope, unit, pattern)` fires at most once
  per submission — so a line matching both scopes produces one alert per
  scope, never two from the same rule.
- Webhook payload includes `scope: "device"` or `scope: "global"` so you
  can tell them apart downstream.

**Alert rules UI: per-device / fleet-wide tabs.** The Logs page now has
a tab switcher above the rules table. "+ Add rule" opens a modal that
adapts to the active tab — fleet-wide mode hides the device picker and
shows a hint about the `*` wildcard.

### Changed

- Live tail polling interval: 10s → **30s**. Always-on now — the
  pause-on-scroll-up behaviour and PAUSED badge are removed. If you want to
  read older lines, uncheck "auto-scroll to newest".
- `handle_log_submit` dedupes alerts within a submission by
  `(scope, unit, pattern)` — previously the same rule could fire multiple
  times if matched lines came in across multiple units.
- All version strings bumped to 1.8.2.

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/logs/rules/global` | List fleet-wide rules |
| POST   | `/api/logs/rules/global` | Create fleet-wide rule |
| DELETE | `/api/logs/rules/global/{id}` | Remove fleet-wide rule |

### Tests

15 new tests in `tests/test_v182.py` — validation (7 cases covering wildcard,
specific units, bad regex, bad units, threshold bounds, empty fields),
empty-array preservation (quiet vs chatty units, mixed submissions),
wildcard matching, and dedupe-key semantics. Full suite:
**123 passing, 0 failing** (1 pre-existing skip).

### Notes

- **All v1.8.1 agents should update** to pick up the empty-submission fix.
  A v1.8.1 agent with a quiet watched unit will still not appear on the
  Logs page even after upgrading the server.
- Fleet-wide rules are capped at 50 per server (`MAX_GLOBAL_LOG_RULES`).
  That's a safety fence, not a target — most deployments need 2-5.
- No changes to data files; `log_rules_global.json` is created on first
  write. Existing `log_watch` rules on device records continue to work
  unchanged.

---

## v1.8.1 — 2026-04-24

### Added

**Dedicated "Logs" page in the sidebar.** The v1.8.0 log-tail feature was
only surfaced inside the per-service drill-down, which was too buried and
had no UI for configuring alert rules (you had to curl the API). This
release makes logs a first-class page.

The new page has three stacked widgets:

- **Search bar** — hits `/api/logs/search` with case-insensitive regex.
  Results grouped by device (collapsible), timestamped, and color-coded
  by severity pattern (FATAL/ERROR/WARN detected automatically).
- **Live tail** — the default view when no search is active. Polls
  `/api/logs/tail` every 10 seconds using a monotonically-advancing
  `since=` cursor; pauses auto-scroll when the user scrolls up
  (shows a "PAUSED" badge), resumes when they scroll back to the bottom.
  Device and unit filter dropdowns narrow the stream.
- **Alert rules table** — cross-fleet view of all `log_watch` rules,
  with an "+ Add rule" button that opens a proper form (device picker,
  unit, regex pattern, threshold). Adding a rule automatically ensures
  the target unit is in `services_watched` so the agent actually
  submits its logs.

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/logs/tail?since=<ts>&device=<id>&unit=<n>` | Incremental fetch for the live-tail page |
| GET    | `/api/logs/rules` | Cross-fleet aggregate of all log_watch rules |

### Fixed

- Service drill-down now **always shows** "State history" and "Recent logs"
  sections even when empty, with explanatory text. Previously the sections
  were silently omitted if the device hadn't submitted logs yet, making it
  look like the feature was broken. ([reported after v1.8.0 ship])
- Empty-state messaging includes the diagnostic hints: agent needs v1.8.0+
  and journalctl access, and logs are submitted every ~5 min so a freshly
  configured unit takes a poll or two before anything shows up.

### Changed

- All version strings bumped to 1.8.1
- "Recent logs" section now auto-expands by default when it has content
  (same for State history) — one fewer click to get to what you opened
  the modal for

### Tests

- Added `tests/test_v181.py` — 7 new tests covering log rules aggregation,
  log tail filtering (since/device), device config round-trip, and version
  bump. Full suite: **108 passing, 0 failing** (1 pre-existing skip).

### Notes

- No agent changes in 1.8.1 — everything is server-side plus UI. v1.8.0
  agents work unchanged with a v1.8.1 server.
- The live tail uses client-side polling, not WebSockets or SSE. A
  genuine push channel would need persistent connection state in the CGI
  model, which doesn't fit. 10-second polling is cheap and survives server
  restarts invisibly.
- Alert rules editor is per-device. A fleet-wide "apply to all devices
  matching this unit" mode is on the roadmap for v1.9.

---

## v1.8.0 — 2026-04-23

### Added

**Service monitoring** — agent reports watched systemd units on each heartbeat.
Per-device `services_watched` list (e.g. `nginx.service`, `postgresql.service`).
Server tracks state, records transitions, fires webhooks.

- Agent calls `systemctl show` per watched unit; reports `ActiveState`,
  `SubState`, and `ActiveEnterTimestamp` on every poll
- Server records state transitions in `service_history.json` (last 100 per
  unit). New webhook events `service_down` (priority 4) and `service_up`
  (priority 3) fire on transitions, with `red_circle,gear` / `green_circle,gear`
  tags
- New "Services" page in the dashboard — fleet matrix with up/down counts,
  per-device drill-down showing state history, recent logs per unit, and
  inline configuration
- New Prometheus metrics: `remotepower_service_active{device,name,group,unit,sub}`
  (1/0 per unit) and `remotepower_services_down_total{device,name,group}`
- Config is pushed from server to agent via heartbeat response — no agent
  restart required to change watched units
- New config key `service_webhook_enabled` (default `true`)

**Log tail + pattern alerts** — agent submits recent journal lines per watched
unit; server keeps a rolling buffer and can fire webhooks on regex matches.

- Agent calls `journalctl -u <unit> --since` every 5 polls (~5 min) and
  submits via new `/api/logs` endpoint
- Server stores per-device, per-unit rolling buffer — bounded at 6 hours,
  2 MB per device
- Per-device `log_watch` rules `[{unit, pattern, threshold}]` — regex matches
  trigger `log_alert` webhooks (priority 4, `warning,scroll` tags)
- New `/api/logs/search?q=<regex>&device=<id>` endpoint — cross-device grep
  over the rolling buffer. No indexing, just regex scan; deliberately not a
  full log analytics stack
- Captured logs appear inline in the per-device service drill-down so you
  can see *why* a service went red without SSH-ing in

**Maintenance windows** — suppress webhook alerts during scheduled windows,
with audit trail.

- Per-device, per-group, or fleet-global scope
- One-shot (`start` + `end` ISO-8601) or recurring (`cron` + `duration` seconds)
- Optional per-window event allowlist — e.g. suppress only `patch_alert`,
  leave `device_offline` still firing
- `in_maintenance(event, payload)` helper wraps every `fire_webhook()` call
  — suppresses transparently, records audit entry in `maint_suppressed.json`
- Built-in lightweight cron evaluator supports `*`, `*/N`, `a,b,c`, and
  single integers across all 5 fields
- New Prometheus metric: `remotepower_maintenance_windows_active`
- New "Maintenance" page with full lifecycle UI — create/list/delete
  windows, view suppression audit trail

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/services` | Fleet-wide service state |
| GET    | `/api/devices/{id}/services` | Per-device with state history + log tails |
| GET    | `/api/devices/{id}/services/config` | Read watched units + log rules |
| POST   | `/api/devices/{id}/services/config` | Set watched units + log rules |
| POST   | `/api/logs` | Agent submits per-unit journal lines |
| GET    | `/api/logs/search?q=<regex>` | Cross-device log search |
| GET    | `/api/devices/{id}/logs` | Full captured buffer for one device |
| GET    | `/api/maintenance` | List all windows + active flag |
| POST   | `/api/maintenance` | Create a window |
| DELETE | `/api/maintenance/{id}` | Remove a window |
| GET    | `/api/maintenance/suppressions` | Audit trail of suppressed webhooks |

### New data files

| File | Purpose |
|------|---------|
| `services.json` | Current service state per device |
| `service_history.json` | State transition log per (device, unit) |
| `log_watch.json` | Rolling log buffer per device + unit |
| `maintenance.json` | Defined windows |
| `maint_suppressed.json` | Audit trail of suppressed webhook events |

### Agent changes (Linux)

- `VERSION = '1.8.0'`
- New functions: `get_services()`, `_parse_systemd_timestamp()`,
  `get_unit_logs()`, `submit_unit_logs()`
- New constants: `SERVICE_CHECK_EVERY = 1` (every poll — cheap),
  `LOG_SUBMIT_EVERY = 5` (every 5 min), `LOG_LOOKBACK_SECONDS = 360`,
  `MAX_LOG_LINES_PER_UNIT = 100`
- Heartbeat loop now reads `services_watched` and `log_watch` from server
  responses — server-driven configuration means no agent restart when you
  change what a device is monitoring

### Webhook events extended

- New events: `service_down`, `service_up`, `log_alert`
- All existing webhook types (Discord / Slack / ntfy / gotify / generic)
  now render these with appropriate titles, priorities, and tags

### Cleanup

- Fixed 4 pre-existing test failures in `tests/test_api.py` for
  `verify_token()` — tests were written for an older `str`-returning
  signature; function has returned `(username, role)` since v1.6.x
- Cleaned up residual comment fragment on `MAX_BODY_BYTES` from v1.7.0
  buffer bump
- Removed a small duplicate in `_cron_match()` introduced during v1.8.0
  authoring

### Notes

- Service monitoring requires `systemctl` — agent silently skips reporting
  on non-systemd hosts
- The log tail deliberately does not do indexing, retention policies, or
  structured parsing. It's a rolling buffer with regex search. If you need
  Loki or Graylog, run those
- Maintenance windows only suppress *webhooks* — the events themselves are
  still recorded in uptime history, monitor history, etc. You're not losing
  visibility, just quiet on the push channel
- Cron evaluator supports the common subset (`*`, `*/N`, lists, literals).
  Ranges like `1-5` and named days like `MON` are not supported — use
  explicit lists instead (e.g. `1,2,3,4,5`)

---

## v1.7.0 — 2026-04-23

### Added

**CVE Scanner** — automatic vulnerability scanning against installed packages
using the free [OSV.dev](https://osv.dev) database. No API key required.

- New agent function `get_package_list()` enumerates installed packages via
  `dpkg-query` / `rpm` / `pacman` / `apk`. Submitted to the server every 6
  hours (or whenever the package set changes) via a new `/api/packages`
  endpoint. Hash-gated — resubmits only when the list actually changes.
- New server module `cve_scanner.py` queries OSV's `/v1/querybatch` (up to
  500 packages per request) and hydrates vulnerability details on first
  encounter. Details cached for 7 days in `cve_details_cache.json`.
- Severity normalized to `critical` / `high` / `medium` / `low` / `unknown`
  from ecosystem-specific labels (Debian/RedHat style) with CVSS base-score
  fallback.
- New "CVEs" page in the dashboard: aggregate severity counts across the
  fleet, per-device breakdown, per-vulnerability drill-down with links to
  upstream advisories and fixed-version information when available.
- Ignore list: mark a CVE as accepted risk either globally or for a specific
  device. Ignored entries are excluded from counts and webhook alerts but
  remain visible (dimmed) in the per-device view.
- New webhook event `cve_found` fires when new critical/high vulnerabilities
  appear in a scan that weren't present in the previous scan (respects the
  ignore list). Priority 5 (urgent) with `rotating_light,shield` tags.
- Supported ecosystems: Debian, Ubuntu, Rocky Linux, AlmaLinux, Red Hat,
  Alpine, Arch Linux. Fedora is not reliably covered by OSV and is flagged
  as `unsupported`.
- New config key `cve_webhook_enabled` (default `true`).

**Prometheus `/metrics` endpoint** — standard text exposition at
`GET /api/metrics`, authenticated via session token or API key. Prometheus's
native `bearer_token` scrape config works unchanged.

Metric families exposed:
- `remotepower_info{version}` — server version
- `remotepower_devices_total` / `remotepower_devices_online`
- `remotepower_device_online{device,name,group,os}` — 1/0 per device
- `remotepower_device_last_seen_timestamp_seconds{...}`
- `remotepower_device_cpu_percent{...}` / `_mem_percent{...}` / `_disk_percent{...}`
- `remotepower_device_upgradable_packages{...,manager}`
- `remotepower_device_cve_findings{...,severity}`
- `remotepower_monitor_up{label,type,target}`
- `remotepower_monitor_last_check_timestamp_seconds{...}`
- `remotepower_commands_pending_total`
- `remotepower_scheduled_jobs_total`
- `remotepower_webhook_deliveries_total{status}`
- `remotepower_webhook_log_size`

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST   | `/api/packages` | Agent submits installed package list (device-auth) |
| POST   | `/api/cve/scan` | Admin triggers CVE scan for one or all devices |
| GET    | `/api/cve/findings` | Aggregate CVE report across all devices |
| GET    | `/api/devices/{id}/cve` | Per-device CVE findings |
| GET    | `/api/cve/ignore` | List all active ignore entries |
| POST   | `/api/cve/ignore` | Mark a CVE as accepted risk |
| DELETE | `/api/cve/ignore/{vuln_id}` | Remove an ignore |
| GET    | `/api/metrics` | Prometheus scrape endpoint |

### New data files

| File | Purpose |
|------|---------|
| `packages.json` | Per-device installed package list + hash + collected timestamp |
| `cve_findings.json` | Per-device scan results |
| `cve_ignore.json` | Global/per-device CVE ignore list |
| `cve_details_cache.json` | OSV vulnerability detail cache (7-day TTL) |

### Agent changes

- Bumped agent version to 1.7.0 (Linux + Windows)
- New constants: `PACKAGE_LIST_EVERY = 360`, `MAX_PACKAGES_SEND = 10000`
- New functions (Linux): `get_os_release()`, `get_package_list()`,
  `send_package_list()` + three hash-cache helpers
- New sidecar file `/etc/remotepower/pkg_hash` stores the hash of the last
  submitted package list so subsequent polls can skip resubmission when
  nothing changed
- Windows agent gets the version bump but no package enumeration (OSV
  doesn't cover Windows app ecosystems well; Windows devices show as
  `unsupported` in the CVE UI)

### Changed

- All version strings bumped to 1.7.0
- `_webhook_message()`, `_webhook_priority()`, `_webhook_tags()` extended
  for the new `cve_found` event
- `GET /api/config` now returns `cve_webhook_enabled`
- `POST /api/config` accepts `cve_webhook_enabled` (bool)
- DELETE guard on `/api/devices/<id>` updated to exclude the new `/cve`
  subresource path

---

## v1.6.3 — 2026-04-22

### Fixed
- Bulk "Upgrade packages" rejected freshly-restarted devices with
  `Unknown or unreported package manager: none`. Root cause: the server
  looked up `sysinfo.packages.manager` on the device record, but `packages`
  is only populated after a patch-info poll — which runs every `PATCH_EVERY`
  (180) polls, i.e. roughly 3 hours after agent restart. On any device that
  had been restarted recently (every Debian box the 1.6.1 service-file fix
  was deployed to) the upgrade button was effectively broken.

  The dispatcher no longer relies on server-side sysinfo at all. It now
  queues a single self-detecting shell snippet that runs `command -v
  apt-get` / `dnf` / `pacman` on the device at execution time and picks
  the right one. This also simplifies the server code — one command, no
  per-device dispatch, no stale-cache failure modes.

### Changed
- `POST /api/upgrade-device` response no longer includes the `manager`
  field (the server doesn't know in advance anymore). The queued exec
  output — visible on the next heartbeat — still shows which manager ran.
- All version strings bumped to 1.6.3.

### Note on custom `apt` commands
The Custom Command dialog runs whatever string you type verbatim. If you
manually type `apt update && apt upgrade -y …` on a box that still has
`NoNewPrivileges=yes` in its agent service file, you'll still see the
`seteuid 105 failed` error — that's expected, and the fix is to deploy
the 1.6.1 service file and do `systemctl daemon-reload && systemctl
restart remotepower-agent` on that host. The bulk "Upgrade packages"
button works around this automatically via the APT_CONFIG override;
custom commands don't, by design.
---
 
## v1.6.2 — 2026-04-22

### Fixed
- Bulk "Upgrade packages" still failed on Debian/Ubuntu with
  `E: seteuid 105 failed - seteuid (1: Operation not permitted)` because the
  `-o APT::Sandbox::User=root` flag was only applied to `apt-get upgrade`.
  But `apt-get update` is the call that actually opens network sockets and
  drops to the `_apt` user — so under systemd hardening (`NoNewPrivileges=yes`,
  restricted cgroups, user namespaces), `apt-get update` returned rc=100 and
  short-circuited the `&&` chain before upgrade ever ran.

  The fix writes a one-line apt config to a tempfile, points `APT_CONFIG` at
  it, and exports that env var for the whole chain. Every `apt-get` call in
  the chain (`update`, `upgrade`, `autoremove`, `clean`) now inherits
  `APT::Sandbox::User "root"` plus the `Dpkg::Options` conffile handling, and
  a `trap` cleans up the tempfile even if any step fails.

  **Server-only fix** — agents don't need to be restarted to pick this up,
  since the command is constructed server-side and dispatched via the
  existing `exec:` channel. Just redeploy the server.

### Changed
- All version strings bumped to 1.6.2.
---
 
## v1.6.1 — 2026-04-22

### Fixed
- Bulk-action icons in the selection bar rendered as oversized default-styled
  buttons — `.btn-shutdown` and `.btn-reboot` had no CSS defined, so SVGs were
  unconstrained. Added matching red/amber/purple button styles with proper 14px
  SVG sizing so the batch bar visually matches the rest of the UI.
- Device "…" dropdown menu was pierced by sibling cards' menu buttons due to
  each `.device-card` sharing a stacking context with `z-index: 20`. The open
  dropdown's parent card is now lifted via `:has(.device-dropdown.active)` plus
  an explicit `z-index: 9999` on the active dropdown wrapper as a fallback.
- Agent `exec:` commands running apt failed with
  `seteuid 105 failed - seteuid (1: Operation not permitted)` because
  `NoNewPrivileges=yes` in `remotepower-agent.service` blocked apt's drop to
  the `_apt` user. Removed the directive — the agent runs as root by design,
  so this hardening was cosmetic. Defence-in-depth added in the new upgrade
  path via `-o APT::Sandbox::User=root`.

### New features
- Bulk "Upgrade packages" action — select multiple devices and run apt/dnf/
  pacman upgrade across all of them in one click. Server dispatches the right
  command per device based on the package manager reported in sysinfo:
  - apt:    `apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get clean`
            (with `APT::Sandbox::User=root` and non-interactive dpkg conffile handling)
  - dnf:    `dnf -y upgrade`
  - pacman: `pacman -Syu --noconfirm`
  Output arrives on the next heartbeat (~60s) via the existing `exec:` pipe.
- "Update all" button renamed to "Update agent" with a clarifying tooltip so
  it isn't confused with package upgrades.

### New API
- `POST /api/upgrade-device` — body `{device_ids: [...]}` or `{device_id: "..."}`.
  Returns per-device results including the detected package manager, or an
  error if the manager is unknown/unreported.

### Changed
- All version strings bumped to 1.6.1.
---
 
## v1.6.0 — 2026-04-21
 
### New features
- Webhook URL visible and editable in Settings UI — no longer hidden after save
- Webhook payloads include `title`, `message`, `priority` for push-friendly notifications
- Push headers (`X-Title`, `X-Priority`, `X-Tags`) for Ntfy, Gotify, Pushover compatibility
- Monitor webhook alerts — `monitor_down` / `monitor_up` events on state change
- Toggle on/off for device offline/online webhook alerts in Settings
- Toggle on/off for monitor webhook alerts in Settings
- Patch alert threshold can be cleared (set to 0 or empty) to disable
- Clear webhook URL button in Settings UI
### Changed
- `GET /api/config` now returns `webhook_url` (was hidden), `offline_webhook_enabled`, `monitor_webhook_enabled`
- Settings page reorganised: "Webhooks" section with toggles replaces "Offline Webhook"
- `fire_webhook()` rewritten with richer payloads, human-readable messages, and push headers
- All version strings bumped to 1.6.0
### New config keys
- `offline_webhook_enabled` (bool, default: true) — toggle offline/online alerts
- `monitor_webhook_enabled` (bool, default: true) — toggle monitor alerts
- `monitor_notified` (internal) — state tracking for monitor alert deduplication
---
 
## v1.3.0 — 2026-04-16
 
### New features
- Tag editor — set and edit device tags directly from the dashboard
- Tag group filtering — filter device grid by tag with one click
- Scheduled commands — queue shutdown or reboot at a specific date and time
- Custom shell commands — run arbitrary commands on devices, output returned via next heartbeat (~60s)
- Monitor history — uptime percentage, sparkline, last 50 check results per target
- Patch alert webhook — fires when a device exceeds a configurable pending update threshold
- Uptime tracking — online/offline state changes stored per device in uptime.json
- Command history page — every action logged with actor, device, and timestamp
- About page — server version, agent version, latest GitHub release check
- Dark/light mode toggle — persisted per browser in localStorage
- Force agent update from dashboard — queue update command like shutdown/reboot
- Network info — agent reports all interfaces, not just primary IP
### Fixed
- Nginx blocking PATCH method — tag API would return 405
- QUERY_STRING not forwarded to CGI — monitor history label lookup always returned empty
- Poller cadence was broken — sysinfo/journal now every 10 polls (~10min), patches every 180 polls (~3hr)
- First-poll sysinfo — agent now sends data immediately on startup instead of waiting
- Exec button shown on offline devices — now dimmed with tooltip
- Tag API existed but no UI to set tags
- Custom command output stored on server but never displayed
### New data files
- `history.json` — command log (last 200 entries)
- `schedule.json` — scheduled jobs
- `uptime.json` — online/offline state changes per device
- `monitor_history.json` — check results per monitor target (last 50)
- `cmd_output.json` — custom command output per device (last 100)
---
 
## v1.2.0 — 2026-04-16
 
### New features
- Agent self-update — SHA-256 verified, atomic replace, systemctl restart, no SSH needed
- Force update from dashboard — queue update command alongside shutdown/reboot
- Dark/light mode toggle
- Server version check against GitHub releases — amber banner when update available
- WoL unicast fix — sends to device's last known IP for routed/VPN networks, broadcast fallback
### Fixed
- Agent log file permission error when running as non-root
- Poller frequency — patches split from sysinfo (patches every 3hr, sysinfo every 10min)
- Agent version bump to 1.2.0
---
 
## v1.1.2 — 2026-04-15
- Fixed agent self-update download URL (static file instead of CGI)
- Fixed agent log file permission for non-root users
- Reduced sysinfo/patch poll frequency to reduce load
## v1.1.1 — 2026-04-15
- Fixed agent log file permission for non-root users
- Fixed agent self-update download URL (static file instead of CGI)
## v1.1.0 — 2026-04-15
- bcrypt password hashing with silent SHA-256 auto-upgrade
- Wake-on-LAN support, MAC reported at enroll time
- Reboot command alongside shutdown
- Multiple admin users with full CRUD in dashboard
- Offline webhook (Ntfy/Gotify/Slack/Discord)
- Patch info via apt/dnf/pacman (dry-run only)
- Uptime + journalctl per device with noise filtering
- Ping/TCP/HTTP service monitoring from server
- Agent self-update — SHA-256 verified, atomic replace
- Multi-distro install scripts (apt/dnf/pacman)
- deploy-server.sh for fast redeploys
## v1.0.0 — 2026-04-14
- Initial release
- Remote shutdown over HTTPS
- PIN enrollment
- No inbound firewall rules on clients
- Flat JSON storage, Nginx + Python CGI
