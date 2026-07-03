# Changelog

All notable changes to RemotePower. Newest first.

## v5.8.0 — "WatchMatters" — unreleased (test)

### Added

- **10 new homelab connectors** (Settings → Integrations): Immich, Paperless-ngx,
  Vaultwarden, Gitea/Forgejo, Syncthing, Frigate, OctoPrint, ESPHome, Homebridge
  and a **RemotePower (peer instance)** connector that surfaces another
  RemotePower's public health (device/offline/open-alert counts via a viewer API
  key — off-site visibility, not federation). 39 connectors in total now (plus
  the Custom HTTP probe).
- **Patch rings (staged auto-patch).** An auto-patch policy can now define
  ordered **rings** (e.g. canary → wave 2 → rest). When it fires it spawns a
  health-gated rollout that patches one ring, verifies it, and only then
  promotes to the next — auto-halting if a host's health score drops. Optional
  per-ring reboot. A policy without rings patches the whole target at once, as
  before. Configure it in the auto-patch policy form.
- **Standalone-container Update.** The Containers view gains an Update action on
  running non-compose containers: the agent pulls the latest image and recreates
  the container with the same configuration (name, env, ports, mounts, restart
  policy, labels, network). Already-current images are a no-op; compose-managed
  containers are refused (update those from their stack). Rides the existing
  RBAC + four-eyes-approval + reported-id checks.
- **SCIM Groups + discovery.** `/scim/v2/Groups` maps SCIM groups to RemotePower
  roles, so an IdP that pushes group membership drives role assignment (adding a
  user to a group sets the role; removing demotes to viewer; the last admin is
  protected). The discovery endpoints `ServiceProviderConfig`, `ResourceTypes`
  and `Schemas` are now served (some IdPs require them). SCIM Users unchanged.
- **3-2-1 backup-rule score** on the device drawer's Backups panel: a per-host
  read of the classic rule — 3 fresh copies, 2 distinct targets/media, 1
  off-site — inferred from the watched-backup data already collected. Purely
  informational (the stale/verify signals still page).
- **Calendar-based on-call rotation.** Set a rotation *start date* and the
  on-call schedule becomes a deterministic "who's on call this week", with dated
  **overrides** for handoffs/swaps and an upcoming-handoffs view in Settings →
  Notifications. Leaving the start date blank keeps the previous automatic
  rotation.
- **"Fix" button on the Alerts page.** Alerts whose event maps to a remediation
  playbook (reboot, service down, disk, drift, failed unit, CVE, container,
  CPU/memory/swap, AV, backup, SSH key, new port, log, patches) now show a Fix
  button that opens the same guided diagnostic→AI→remediation runner previously
  reachable only from the dashboard's needs-attention feed.
- **Empty-state guidance.** A first-run empty Devices page now shows an "Add your
  first device" call-to-action; a filtered-to-empty list offers a Clear-filters
  action instead of the enrol prompt.
- **SNMPv3 (USM) polling.** Agentless SNMP devices can now be polled with
  SNMPv3 instead of a v2c community: per-device user + security level
  (noAuthNoPriv / authNoPriv / authPriv), auth protocols MD5, SHA-1 and the
  SHA-2 family (SHA-224/256/384/512), AES-128 privacy, optional context.
  Engine discovery, time-window resync and response authentication are
  handled automatically; passwords are write-only in the API/UI. DES privacy
  is deliberately not supported (broken cipher — use AES on the agent). All
  existing pollers (sys-group, processors, storage, Mikrotik/Synology vendor
  reads, deep interface walks) work over v3 unchanged.
- **GitHub issue monitor integration.** New `github` connector (Settings →
  Integrations): watch one or more repositories (`owner/repo`, comma-separated,
  optional token for private repos / rate limit; GitHub Enterprise API roots
  work too). A newly opened issue raises a `github_new_issue` alert in the
  Alerts inbox (pull requests are ignored; the first poll only baselines, so
  attaching a repo never floods with its backlog). Webhook / push / needs-
  attention routing for the new `github_issue` kind is off by default — flip it
  on in Settings → Notifications to page on new issues. Dashboard/Integrations
  tiles show repo + open-issue counts like every other connector.

### Added

- **Config as code (declarative export).** `GET /api/config/declarative`
  (admin, Settings → Security → *Download config-as-code*) returns a single
  versioned JSON document of every operator-authored resource — monitors,
  custom checks, alert/automation rules, integrations, webhook destinations,
  service baselines, backup monitors, maintenance windows, autopatch policies,
  scripts, and TLS/DMARC/resolver/IP-reputation targets. Secrets are shown as
  `(redacted)` and webhook URLs collapsed to host-only, so the file is safe to
  commit to version control for review, diffing and off-box backup.
- **Config-as-code import.** `POST /api/config/declarative` reconciles a
  declarative document back into the live config — **dry-run by default**
  (returns a per-collection add/change/remove diff), applied only with
  `?apply=1`. Redacted secrets are rehydrated from the current config by id, so
  a round-trip doesn't wipe unchanged secrets; collections absent from the
  document are left untouched; lossy collections (webhook destinations) are
  skipped. Settings → Security has a picker that previews then applies.
- **Connector plugins.** Drop a `*.py` file into `server/cgi-bin/connectors.d/`
  to add your own homelab integration connector via the same `@_register`
  decorator the built-ins use — no source patch. Root-owned and filesystem-only
  (no UI upload); a plugin that fails to import is logged and skipped. See
  `docs/writing-a-connector.md`.

### Changed

- **Fleet-event log is faster on the SQLite/Postgres backends.**
  `fleet_events.json` is now stored as decomposed rows (a wrapped-list file), so
  each fired event does an O(1) row insert instead of rewriting the whole capped
  event ring — a real saving on busy fleets where events fire constantly. A
  one-time migration decomposes the existing blob on upgrade (SQLite schema v6,
  Postgres v5). The JSON backend is unchanged.
- **Fixed: log-alert / SSH-key Needs-Attention cards were silently missing.**
  The Needs-Attention builder read the fleet-event log as a bare list when it's
  actually stored `{events: […]}`, so it iterated the wrapper's keys and
  processed **zero** events — dropping the NA cards derived from fleet events
  (log alerts, added SSH keys, etc.). It now reads the list correctly, so those
  cards appear again. (Kinds that default to off, like *new listening port*,
  stay suppressed as before.)

### Changed

- **Four-eyes approval is now configurable.** The set of command kinds that
  require a second admin's approval is no longer fixed — Settings → Security lets
  you pick from reboot, shutdown, agent update/upgrade/uninstall, container
  actions (the defaults) plus **Run command, Compose, Service control, Kill
  process and Scan**. A bad/empty selection safely falls back to the default set.
- **Dashboard & account card headers migrated to the canonical `.section-title`.**
  All dashboard-widget and account-page card headers now use the standard header
  element, so in the New UI (industrial skin) they render as the chamfered card
  tab consistently, and every one is translatable. The Old UI keeps its previous
  header appearance. New translations were added for the migrated headers and the
  v5.8.0 UI strings (Chinese / Hindi / Spanish / Arabic).
- **Maintenance windows suppress more of the predictable churn.** A window can
  now silence resource (`metric_warning`/`metric_critical`), drift, failed-unit,
  reboot-required, container and backup-stale alerts in addition to the previous
  set — a per-window event list can still narrow it.
- **Enrollment PINs are stored hashed at rest** (like device and enrollment
  tokens since v5.4.1), so a leaked `pins.json` can't be replayed. Verification
  still accepts a legacy plaintext-keyed PIN mid-TTL across the upgrade.

### Fixed

- **Agentless devices no longer flip offline forever when the server can't
  run `ping`** (#20, reported by @AndiBSE). The ICMP reachability sweep
  shelled out to the `ping` binary — which the Docker image never shipped and
  minimal Debian installs don't have — so netscan-added devices went offline
  after ~2 sweeps and stayed there. Reachability is now tiered: system
  `ping` → an unprivileged ICMP datagram socket (no binary, no CAP_NET_RAW;
  allowed by the `ping_group_range` systemd defaults everywhere modern) → a
  TCP connect probe (success or refused both prove the host is up) as the
  last resort when no ICMP mechanism exists. A working ICMP probe that says
  "down" stays authoritative — the TCP tier never softens a real ICMP
  verdict. The same socket fallback covers the pre-offline "definitely up?"
  guard and `ping`-type monitors; the Docker image, `install-server.sh`
  (apt/dnf/pacman) and the AUR server package now also ship `iputils` so
  real ICMP (and the latency/loss `icmp` monitor) works out of the box.
- **TLS/DANE expiry checks now actually run on schedule.** The watchlist's
  periodic probing existed only as an optional cron script the installer merely
  suggested — and that script read the watchlist as a raw file, so it saw
  nothing under the SQLite/Postgres storage backends even when installed. The
  server now owns the cadence (`run_tls_scan_if_due`, ~6h per target, bounded
  per sweep, edge-triggered `tls_expiry` webhooks honouring per-target
  warn/crit days) on the same maintenance cycle as every other monitor; the
  standalone `remotepower-tls-check` runner is now optional and backend-aware.

## v5.7.0 — "F4ct0rMatters" — 2026-07-03

### Fixed — New UI (light mode / theming), reported by @AndiBSE

- **Devices could not be deleted (#17).** The device drawer's "Remove device"
  action called an undefined function, so the click silently threw and nothing
  happened — for agents, direct-deploy hosts and agentless/netscan rows alike.
  Removing a device now works (name-confirmed, then `DELETE /api/devices/<id>`).
- **Profile menu unreadable in light mode (#18).** The account dropdown used an
  undefined `--card` variable that always fell back to a hard dark colour, so in
  light mode it was dark-on-dark. It now uses the theme-aware surface variable.
- **Accent picker ignored in the New UI (#19).** The industrial skin hardcoded
  `--accent` after the accent presets at equal specificity, so the picker did
  nothing. The picked accent now applies (and keeps the logo blue as the default).
- **Themes did not work in the New UI.** The industrial skin hardcoded the whole
  palette after the theme blocks, so Tokyo/Dracula/Nord/Gruvbox/… were ignored.
  Themes now repaint the New UI while keeping its structure (the card gradient
  now derives from the active palette); named light themes paint their own light
  palette.
- **Accent didn't reach chamfered buttons in light mode.** Chamfer borders (e.g.
  "Enable notifications") stayed blue in light mode while solid fills followed
  the accent. The accent axis is now owned entirely by the presets/picker in
  both modes.
- **Mobile / narrow viewports.** No page scrolls horizontally at 390px anymore;
  header controls, nav rows and the devices grid reflow for touch, and the CMDB
  scoped-credentials row wraps cleanly on a docked-sidebar tablet.

### Added

- **Ticket lifecycle events.** `ticket_opened` and `ticket_resolved` fire from
  every creation path (operator, inbound email, automation) and route to the
  activity feed + webhooks; `ticket_resolved` auto-resolves the ticket's open
  SLA-breach alert. With the recover events below, `WEBHOOK_EVENTS` reaches 103.
- **Config-secret encryption now covers the whole config tree** (opt-in
  `RP_CONFIG_KEY`). Beyond the original five flat fields it now encrypts every
  secret-bearing value at any depth — ACME DNS credentials, webhook tokens/URLs,
  AI API keys, integration secrets — at rest, transparently, with a per-install
  salt and a fast KDF suited to full coverage. No key set = byte-identical no-op.
- **Postgres row-level security extended beyond the device roster** (opt-in
  multi-tenancy). `entity`, `listrow` and `metric_samples` now carry
  device-derived tenant isolation, with non-device rows shared across tenants to
  match the app layer. Default off.
- **`tools/release-prep.py`** — automates the mechanical release chores (version
  bumps, docs keep-N pruning, count refreshes, checklist verification).

### Changed — performance & responsiveness

- **Faster first paint.** Fonts load in parallel (the `@import` chain is gone)
  with preloads; the service worker uses navigation preload. Eight heavy pages
  plus the large Settings page are now inert `<template>`s cloned on first visit,
  cutting the boot DOM ~36%. Always-on background animations were removed and
  off-screen rows on heavy pages are skipped.
- **Lower Postgres write-amplification on the heartbeat.** Eight more
  device-keyed stores (hardware, drift, helm, discovery, secrets, speedtest,
  ACME) moved to per-row storage, so a report rewrites one row instead of the
  whole fleet's blob; the hottest ingests also read a single row.
- **Settings** reorganised into four labelled groups (Setup / Monitoring /
  Connections / System) — same tabs, easier to scan.

### Changed — internals (no behaviour change)

- **api.py decomposition.** The ~57k-line module is down to ~52k: notification
  builders (`notify.py`), the per-host checks engine (`checks.py`), and the
  tickets, provisioning, backups and CMDB subsystems (`*_handlers.py`) moved to
  sibling modules. Every fleet/webhook event now derives from one
  `EVENT_REGISTRY`; the request dispatcher is a declarative route table; and the
  self-locking recorders auto-defer under locks, retiring a recurring
  silent-drop bug class. `app.js` shed ~2,500 more lines into page modules.
- **Housekeeping.** Dead code removed, an orphaned credential scrubber wired up
  (queued ACME commands no longer echo DNS secrets to the admin queue view), and
  the test suite runs ~20% faster.

- **Alerts now self-clear for eight more host conditions.** Several
  edge-triggered alerts fired once but had no recover event, so they sat OPEN
  forever after the operator fixed the underlying issue (e.g. an outdated-kernel
  alert never closed after a reboot). Each now emits a paired recover event that
  auto-resolves the open alert when the condition clears:
  `kernel_outdated`→`kernel_current`, `smart_failure`→`smart_recovered`,
  `cert_file_expiring`→`cert_file_renewed`, `rogue_uid0`→`rogue_uid0_cleared`,
  `av_infected`/`av_warning`→`av_clean`, `reboot_required`→`reboot_cleared`,
  `containers_stale`→`containers_current`, and `port_exposed_world`→
  `port_unexposed` (matched per exact proto+port). All are edge-triggered off
  existing per-host state (no new polling); recover events create no inbox row.
  Point/security/ack events (brute-force, ssh-key-added, new-source login, OOM,
  fail2ban ban, …) deliberately stay non-resolving. `WEBHOOK_EVENTS` 91→99.
  Guardrail: `tests/test_v560_recover.py`.

## v5.6.0 — "HeapMatters" — 2026-07-01

The IaC / automation + alert-tuning release. Everything new is opt-in,
**default-off — no breaking changes.**

- **Whole-project finalize sweep** (security + correctness + docs + UX). Parallel
  per-dimension audits + CodeQL/bandit/gitleaks (all clean) + an authenticated
  live review. Fixed one **Medium** (CMDB→RAG corpus could embed a plaintext
  secret-named field — the denylist now substring-matches `api_key`/`token`/
  `passphrase`/… ) and several defense-in-depth **Low** items (IPv6/extra
  cloud-metadata SSRF deny, CVE-scanner response size cap, agent file-write
  `O_EXCL|O_NOFOLLOW`). Per-device **SLA target overrides now key by hostname**
  (not the internal id). Doc/count refreshes (91 webhook events; 28 integration
  connectors incl. OpenShift + VMware Cloud Director), 5 Hindi i18n fixes, a few
  more box-overflow caps, and a typography fold. See `docs/security-review-5.6.0.md`.

- **Provisioning** (Admin → Provisioning, opt-in): a folder-tree catalog of
  infrastructure blueprints — Terraform, cloud-init, Ansible and iPXE templates.
  Fill in a blueprint's variables and **render** to copy/download (cloud-init can
  bake the agent install one-liner via the `${rp_agent_install}` macro), or **run
  Terraform** server-side — **Plan / Apply / Destroy** — when the separate
  `iac_execute_enabled` gate is on. Persistent per-blueprint state, a per-blueprint
  run lock, and secret variables passed as environment (never written to disk or
  the command line). Admin-only + audited; deleting a blueprint with live state is
  refused until it's destroyed. The standalone **Ansible** page is folded in here
  as an "Ansible playbooks" card.
- **Alert tuning** (Monitoring → Tuning): the noisiest alerts (host + event) and
  sources from the fleet-event timeline, each with a **Silence** toggle. The
  per-row **Ack** button on the Alerts page and the dashboard is now an **X
  "Mute"** that silences one exact alert from one host (inbox + webhook +
  needs-attention) while history keeps recording. Mutes are permanent, managed
  from Tuning.
- **Timesheet watchers**: let specific non-finance users view another user's
  **timesheet** (read-only, hours only, never rates) — granted by user or by whole
  team. Managed under Users; a "Watch for" omnisearch on the Timesheet page
  switches whose week you view.
- **Settings**: the opt-in modules (Tickets, Billing, Provisioning, File manager)
  are consolidated into an **"Optional features"** section. Fixed the Settings
  **Save** button hanging on "Saving…" when a request was dropped.
- **Knowledge base** (Admin → Knowledge base, opt-in `kb_enabled`): operator-authored
  markdown articles — SOPs, how-tos, runbooks — in a category folder tree, searchable,
  admin-authored / all-roles-read. Wired in as a **RAG source** so the AI assistant can
  answer from your own documentation. `GET/POST /api/kb`, `…/{id}`.
- **Automation actions**: the existing event-driven automation engine gains three
  actions that compose subsystems you already have — **open a ticket**, **add a tag**
  and **mute the alert** — alongside the existing run-script / notify. No new webhook
  event; same lock-safe firing path.
- **Settings → Install**: squared the active settings-tab underline and the tab-strip
  scrollbar (were rounded), with clearance under the scrollbar.
- **Alert lifecycle**: two state alerts that fired but never auto-resolved now do —
  **`container_recovered`** (a stopped container running again clears the open
  `container_stopped` alert, per container name) and **`backup_recovered`** (a fresh
  backup clears `backup_stale`, per path). Both edge-triggered, wired through every
  registry. WEBHOOK_EVENTS now **91**.
- **UI consistency**: classic-skin card radii unified to 10px (`.table-card` /
  `.settings-section` matched to `.dash-card`).
- **New AI advisor — Automation suggestions**: reads your recurring alert / fleet-event
  patterns and proposes concrete automation rules (trigger + scope + action: run script /
  notify / open ticket / add tag / mute). 26th AI Insights card.
- **Check catalog** (was "Custom checks"): a library of **~70 ready-made checks** that
  pre-fill the form, a new **`systemd_unit`** agent check (is a named unit active?) with a
  **RemotePower self-infra** set (API / WSGI / scheduler / satellite / scanner units), a
  **device-search typeahead** for host targets, and an option to also add a unit check to
  the host's **Services** watch-list.
- **Site health** pill in the top bar: green **Healthy** when nothing needs attention, red
  **N issues** (offline + open alerts + monitors down) otherwise; click jumps to Alerts.
- **Sidebar:** the synthetic-monitor page **Targets → Remote Checks**, re-sorted into its
  alphabetical slot.
- **Virtualization integrations:** two new read-only connectors — **Red Hat OpenShift**
  (nodes + projects via a ServiceAccount token) and **VMware Cloud Director** (vApp + VM
  counts) — added to the homelab-integrations set (now 28); the vCenter connector relabelled
  **VMware vSphere / ESXi / vCenter**. The **Settings → Proxmox** tab is renamed
  **Virtualization**.
- **API, Swagger, AI &amp; RAG gap-fill:** the OpenAPI/Swagger spec now covers the
  **whole** API surface — a dispatcher-route extractor (`_dispatcher_routes()`) feeds
  the ~280 prefix/templated routes (every `/{id}` sub-resource + the new subsystems)
  to the stubber, which now emits templated-path stubs; virtualization gets a rich
  hand-written spec. Guardrail `tests/test_v560_openapi.py`. **Six new AI advisors** —
  virtualization hygiene, IaC/provisioning review, drift triage, access &amp; credential
  review, network-dependency review, billing review — plus **inline "AI review"
  buttons** on the matching pages (Virtualization, Provisioning, Drift, Network map,
  CVE, Backups, Users, Billing). **Three new RAG sources** — provisioning blueprints,
  staged rollouts, and network topology + unmanaged-host discovery. Fixed the AI-page
  watermark rendering as a solid white blob (child-path fills now forced stroke-only).
- **Virtualization lifecycle parity:** VMware vSphere/vCenter, VMware Cloud Director and
  OpenShift Virtualization (KubeVirt) now get **Proxmox-level control** on the sidebar
  **Virtualization** page — a platform picker lists guests per hypervisor and offers
  **power** (start / shutdown / reboot / suspend / hard stop / reset, filtered to what each
  platform supports) and **snapshots** (create / revert / delete, type-to-confirm revert).
  A new sibling module `hypervisor.py` holds the pure per-platform drivers; every call rides
  the same SSRF-guarded integrations client as the read-only connectors, reads are
  `require_auth`, mutations are admin + audited. Admin-supplied VM/snapshot ids are reduced
  to a single URL-quoted path segment (and OpenShift `namespace/name` validated as RFC-1123)
  so a crafted id can never redirect the authenticated request to another host or API path.
  Endpoints: `GET /api/virt/platforms`, `GET /api/virt/{id}/vms`, `POST /api/virt/{id}/power`,
  `GET /api/virt/{id}/snapshots`, `POST /api/virt/{id}/snapshot`.
- **Security pass** (5-dimension pentest + full SAST stack; CodeQL 0, bandit/gitleaks/
  njsscan/pip-audit clean — see `docs/security-review-5.6.0.md`). No Crit/High/Med. Seven
  Low fixes: two secret-bearing-URL leaks (`healthchecks_url`/`metrics_push.url` in the
  diagnostics bundle + non-admin config; webhook-DLQ host redaction kept basic-auth
  userinfo), a read-only-role write gate on CMDB/runbook edits (`require_write_role`),
  `systemctl` + `useradd`/`usermod` argument-injection `--` guards in the agent, and
  RouterOS/OPNsense connect-time SSRF (peer-IP guard + no-redirect opener).

## v5.5.0 — "ScaleMatters" — 2026-06-29

The persistent-tier + enterprise release: a large opt-in **enterprise-hardening**
program, the **keystone** that lifts the CGI/fork-per-request scale ceiling
(persistent WSGI app server + out-of-band scheduler), **hard multi-tenancy** with
optional Postgres row-level security, plus helpdesk-signal and billing polish.
Everything new here is opt-in and **default-off — no breaking changes.**

### Scale & isolation (keystone)

- **Persistent WSGI app server (opt-in, experimental).** The same `api.py` can now
  run under **gunicorn** with threaded workers and **thread-local request
  isolation** (request context, output buffer and DB connections are per-thread),
  instead of fork-per-request CGI. Validated under load on SQLite and Postgres
  (no cross-request load-cache / correlation-id / response-body bleed). CGI stays
  the default + fallback. `server/conf/remotepower-wsgi.service`; see docs/wsgi.md.
- **Out-of-band maintenance scheduler (opt-in).** A dedicated
  `remotepower-scheduler.service` runs the ~33 `run_*_if_due` sweeps off the
  request path (set `RP_EXTERNAL_SCHEDULER=1` on the worker). **Leader-elected**
  (host file-lock + Postgres `pg_advisory_lock`) so exactly one node runs the
  cadence — HA-safe — and it cut request latency ~25× on a networked Postgres
  backend (no more per-request "is it due?" round-trips).
- **Hard multi-tenancy (opt-in, `tenancy_enforced`).** A tenant entity confines
  tenant admins to their own devices; a default-tenant admin is the cross-tenant
  superadmin. Applied live from Settings → Security.
- **Postgres row-level security (opt-in, `tenancy_rls`, Postgres only).**
  DB-enforced tenant isolation on the `devices` table — `FORCE ROW LEVEL SECURITY`
  + a per-request `app.rp_tenant` GUC, fail-closed — as defense-in-depth beneath
  the app-layer scope. The column/trigger/policy are added **idempotently at
  runtime** when you flip the switch (no migration script).

### Finalize sweep — security, fixes & polish

- **Security review + hardening** (full server/agent audit, SAST — Bandit, gitleaks,
  semgrep, CodeQL — all clean, plus a live authenticated penetration test; see
  `docs/security-review-5.5.0.md`). Fixed: a **High** missing authorization/scope on
  the drift content-fetch endpoint (a read-only or out-of-scope token could queue a
  watched-file read); two **Medium** issues — the DMARC report parser's entity-expansion
  guard now scans the whole report (was first-4 KB only), and the AI-provider client
  now re-checks the peer IP at connect time for plain-HTTP endpoints too; and a **Low** —
  a secret-bearing monitoring URL is withheld from non-admin tokens. No Critical/High/
  Medium ships. Added `Cross-Origin-Opener-Policy`/`Cross-Origin-Resource-Policy` to the
  shipped nginx template.
- **New `failed_unit` event** — a systemd unit entering the failed state now raises a
  first-class alert/webhook (edge-triggered, coalesced per host) instead of only a
  "Needs attention" card. **WEBHOOK_EVENTS → 89.**
- **Fixes:** the "Add integration" picker is a plain dropdown again (no stray
  type-to-filter); the package-upgrade command on dnf hosts now runs
  `dnf upgrade --refresh -y && dnf autoremove -y && dnf clean all`; the Command
  Library "Use" button copies the snippet to the clipboard (it previously did nothing
  useful); the recurring narrow-`<select>`-spans-full-width layout bug is fixed at the
  root (the dropdown wrapper no longer stretches in a stacked settings row).
- **UI polish:** the app-catalog and generated-IaC panes now scroll instead of growing
  unbounded; the Server-status page sections are framed as cards in every theme; one
  off-scale heading folded onto the type scale. About-page description refreshed.
- **Perf:** the synthetic-monitor probe paths read config read-only instead of
  deep-copying the whole config per target.

### Helpdesk signals & billing

- **AV/rootkit scan _warnings_ now alert.** rkhunter `[Warning]` lines (and a stale
  ClamAV signature DB) were only shown on the "Needs attention" card, so a host's
  warnings never reached the Alerts inbox. A new **`av_warning`** event (medium)
  is edge-triggered on the rising warning count, coalesced per host, and routed
  through the existing `av_posture` channel. `av_infected` still supersedes it for
  an active infection. **WEBHOOK_EVENTS → 88.**
- **Ticket attachments (in + out).** Inbound email attachments are now extracted
  and stored (previously text/plain only); operators can **attach files** to an
  email reply (≤15 MB each, ≤10 per message). Every attachment has a
  **download** and an in-browser **preview** (images / PDF / text) — access is
  bound to the owning ticket, served `nosniff`, with opaque ids so they can't be
  fetched across tickets.
- **Ticket auto-reply.** An opt-in, one-time acknowledgement ("Thank you for
  contacting support…") is emailed when a new ticket is auto-created from inbound
  mail. **Loop-safe**: stamped `Auto-Submitted`, sent once per ticket, and never to
  no-reply / mailer-daemon / bounce / postmaster senders. Settings → Advanced →
  Tickets.
- **"View email thread".** A button on every ticket opens the full correspondence
  in a clean, printable window (CSP-safe — built entirely in the browser, no new
  endpoint).
- **Billing is now opt-in.** The **Billing** page (worksheet / invoices / rates &
  fees) is gated behind a new **Settings → Advanced** checkbox, mirroring the
  ticket system. Logging hours on tickets and the weekly **Timesheet** stay
  available regardless.
- **Devices page** shows a small ticket glyph (the Tickets-nav icon) in front of a
  hostname when that host has an open ticket — replacing the prior "ticket" pill.

### Enterprise hardening batch (folded in, all opt-in — defaults unchanged)

A first slice of the enterprise gap-analysis (identity/governance/a11y checkboxes;
each is configured, so existing installs behave exactly as before):

- **Password policy** (Settings → Security): configurable minimum length, optional
  3-of-4 character-class requirement, optional **HaveIBeenPwned** breach check
  (k-anonymity — only a SHA-1 prefix leaves the box, fails open). Applies to new
  users + password changes; existing passwords are never invalidated. Off by default.
- **SSO-only** toggle: refuse local-password logins when an IdP (OIDC/SAML) is
  configured, with a per-account `local_login` break-glass exemption.
- **Idle session timeout**: expire a session after N minutes of inactivity,
  independent of its absolute TTL. Off by default.
- **Config-change auditing**: every Settings save now writes a `config_changed`
  audit row (changed key *names* only — values never logged) — the security-config
  surface (MFA policy, IP allowlist, SSO/SCIM/LDAP, session caps) was previously
  saved with no audit trace.
- **Webhook `schema_version`**: the generic-webhook + SIEM payload envelope now
  carries a contract version so consumers can guard against shape drift.
- **`max_devices` enrollment cap**: refuse new enrollments past a configurable
  limit (existing devices + re-enrollment unaffected).
- **Localization**: dates, numbers and **billing currency** now follow the in-app
  language picker via `Intl` (was the browser locale / a bare `"USD 1,234.00"`).
- **Accessibility (WCAG)**: toast notifications are an `aria-live` status region;
  the active nav carries `aria-current="page"`; the device drawer has a focus trap +
  focus restore + `aria-labelledby`; a skip-to-content link was added.

Batch 2 (credential-at-rest + API contract + observability):

- **API keys are hashed at rest** (SHA-256): a datastore read no longer yields a
  reusable bearer secret (the clearest SOC2 finding). The raw key is shown once at
  creation; a pre-existing plaintext key is accepted and transparently migrated to a
  hash on first use. (Device tokens + enrollment tokens are a deliberate later step.)
- **API versioning**: every route is now also reachable under **`/api/v1/...`** (a
  permanent alias of the unversioned path), so integrators can pin a versioned base
  URL; future breaking changes can land under `/api/v2`.
- **Correlation IDs**: every JSON response carries an **`X-Request-Id`** header
  (honouring an inbound one from a proxy, else minted); a `log_json()` structured-log
  helper (gated by `RP_LOG_LEVEL`) and the slow-handler ring carry the same id.
- **Frontend error reporting**: uncaught client errors (`window.onerror` /
  `unhandledrejection`) are beaconed to **`/api/client-error`** (throttled, scrubbed,
  capped ring) so browser-side failures are visible to operators instead of dying in
  a console.
- **Branded notification email**: alert, fleet-report/digest and SMTP-test emails now
  send a branded HTML alternative (white-label `brand_name` + `brand_accent`) alongside
  the plain-text body, instead of plain text only.
- **List API convention**: list endpoints now share a documented superset convention —
  optional `?q=<substr>` filter, `?sort=<field>&order=`, `?limit`/`?offset`, and
  `?meta=1` for a `{items,total,limit,offset,next}` envelope. With none of these the
  response is byte-for-byte the old bare list (backward-compatible). Applied to the
  audit log, command history, API-keys and client-errors lists.
- **Signed exports**: the compliance **evidence pack** now carries an HMAC-SHA256
  `signature` (over the canonical pack), and the **audit-log archive** download emits an
  `X-RP-Signature: hmac-sha256=…` header over its bytes — tamper-evidence on exports
  (keyed by a new per-install `export_sign.key`, 0600). A WORM forward sink for true
  third-party non-repudiation remains a documented follow-up.
- **Export-key rotation + posture visibility**: an admin can **rotate the export-signing
  key** (Settings → Security), and the **Security posture** page now grades the new
  controls (password policy, idle timeout, SSO-only, signed exports) alongside the
  existing rows.
- **OpenAPI now covers the whole API**: the spec (`/api/openapi.json`, Swagger UI) is
  driven from the live route table — every registered endpoint appears (≈290 paths, up
  from ~28), the hand-written rich specs are kept, and the document advertises the
  versioned **`/api/v1`** base. Uncovered endpoints get an auto-stub instead of being
  absent.
- **Off-host backups + restore-verify (DR)**: the DR backup can now be mirrored to an
  **off-host destination** (`backup.offsite_dir` — a path, typically an NFS/SMB/sshfs
  mount), and a new **Test restore** action (`POST /api/backup/test-restore`,
  Settings → Maintenance) decrypts + decompresses + structure-checks the latest archive
  to prove it's restorable. The posture page grades whether backups are mirrored off-host.
- **Per-tier escalation targets**: an escalation **tier can now page a specific
  destination** (by webhook-destination name or id) instead of always re-notifying every
  channel — so e.g. tier 1 hits Slack and tier 3 pages PagerDuty / a manager
  (Settings → Notifications → On-call & escalation).
- **Availability SLO + error budgets**: a configurable **`slo_target_percent`** (default
  99.9%) now drives a per-monitor **availability / error-budget / burn-rate** computation
  over each monitor's recent check window — exposed at **`GET /api/slo`** and as Prometheus
  gauges (`remotepower_monitor_availability_percent`, `…_slo_budget_remaining_percent`,
  `…_slo_burn_rate`) for Grafana SLO dashboards + burn-rate alerts.
- **Guided onboarding tour**: a first-run coach-mark walkthrough highlights the main
  areas (Dashboard, Devices, Alerts, Search, Settings) with Next/Back/Skip; shows once
  per account (persisted) and is re-runnable via a **Take a tour** button on the docs
  page. CSP-safe (built with DOM + CSSOM, no inline handlers/styles).
- **Postman collection**: `make postman` generates a Postman v2.1 collection from the
  (now fully route-covering) OpenAPI spec — one request per endpoint, foldered by tag,
  with `X-Token` auth + `{{baseUrl}}`/`{{token}}` variables pre-wired. Import into
  Postman / Insomnia / Bruno.
- **Supply-chain: app-self SBOM + SLSA provenance**: `make sbom-self` emits a CycloneDX
  SBOM of the **control plane's own** Python dependencies (`packaging/requirements-server.txt`
  + `tools/gen-self-sbom.py`) — distinct from the fleet SBOM at `/api/sbom`. The release
  workflow now attaches **SLSA build provenance** to the published images
  (`provenance: true`, `id-token: write`).
- **Request-lifecycle isolation (keystone Stage A)**: `_begin_request()` / `_end_request()`
  now bracket every request, resetting the per-request process-local state (the `load()`
  cache + correlation id) at request boundaries while preserving the legitimately
  cross-request cadence timers. A **no-op under the current CGI model**, but it's the
  foundation that makes the codebase safe for a future persistent app server (so request
  B can never see request A's state). Guardrail-tested for cross-request-leak.
- **Enrollment tokens hashed at rest**: one-time enrollment tokens are now stored keyed
  by their SHA-256 hash (with a short `prefix` kept for the list / revoke-by-prefix UX),
  not the plaintext token. A legacy plaintext-keyed token still consumes/lists/revokes
  until it expires. This **completes credential-at-rest** — every bearer secret (API
  keys, device tokens, enrollment tokens, config secrets) is now hashed/encrypted on disk.
- **Device tokens hashed at rest**: a device's auth token is now stored as a SHA-256
  hash (`token_hash`), not plaintext — so a datastore read no longer yields a usable
  agent credential. Fully transparent: the **agent keeps sending its plaintext token**;
  the server compares hashes, accepts a legacy plaintext token, and **migrates it to a
  hash on the device's next heartbeat** (under the existing device lock). New
  enrollments + re-enrollments store only the hash. Completes the credential-at-rest
  work alongside API-key hashing (C1).
- **Append-only (WORM) audit sink**: point `audit_worm_path` at a file the operator
  makes immutable (`chattr +a` / a WORM mount) and every hash-chained audit entry is
  also appended there — a tamper-resistant audit copy independent of the live, bounded
  log. Best-effort; graded on the posture page.
- **Config secrets encrypted at rest (opt-in)**: set **`RP_CONFIG_KEY`** (a stable env
  secret, like `RP_BACKUP_PASSPHRASE`) and the sensitive `config.json` fields —
  `smtp_password`, `oidc_client_secret`, `ldap_bind_password`, `siem_token`,
  `audit_forward_token` — are **AES-256-GCM encrypted at rest** (PBKDF2-SHA256, per-value
  salt/nonce). Encryption is transparent: it happens at `save()`, decryption at
  `load()`, so no secret consumer changes. Default (no key) is byte-for-byte the previous
  plaintext behaviour; a lost/changed key is **fail-graceful** (the field is left as-is,
  reads never crash). Graded on the Security posture page. (Nested secrets — webhook
  tokens, IMAP password, ACME creds — are a documented follow-up.)
- **External key sourcing (Vault/KMS)**: `RP_CONFIG_KEY` and `RP_BACKUP_PASSPHRASE` can
  now be fetched from an **external command** via a `<NAME>_CMD` env var (e.g.
  `RP_CONFIG_KEY_CMD="vault kv get -field=key secret/rp"`) instead of holding the raw
  secret in the process environment (where it leaks via `/proc/<pid>/environ`). The
  command runs at most once per worker (cached); the raw env var still wins when both
  are set.
- **SSO group → role matrix**: a new **`sso_group_roles`** mapping (`{group: role}`,
  Settings → SSO) lets an OIDC/SAML group map to **any** builtin or custom role
  (admin / auditor / a custom finance role / …), not just the prior binary
  admin-or-viewer. `admin` wins when several groups match, the legacy single
  admin-group still maps to admin, and unknown role names are ignored (fail-safe). A
  viewer is promoted to their mapped role on next login; an existing admin / custom-role
  user is **never auto-demoted**.
- **Control-plane uptime**: RemotePower now records its **own** observed availability
  (one hourly "served a request" bucket) and reports it over 24 h / 7 d / 30 d at
  `GET /api/self-test` and as a Prometheus gauge
  (`remotepower_control_plane_uptime_percent{window}`). Honest by construction — the
  denominator starts at the first tracked hour (never counts pre-deployment time) and a
  gap is labelled as downtime *or* an hour with no traffic.
- **Distributed trace-context (W3C)**: an inbound **`traceparent`** header is honoured
  so RemotePower's structured logs (`trace_id`) and **outbound webhooks** join the same
  distributed trace (a fresh child span is attached to each webhook). Full server-side
  spans across request → DB → job remain gated on the future persistent app tier.
- **Scoped service-account API keys**: an API key can now carry an optional **device
  scope** (`scope: {type: groups|tags|sites, values: […]}`, Settings → API keys) that
  confines what the key can see and act on to a subset of the fleet — intersected with
  its role scope, and **binding even an admin-role key** (the point of a service
  account). A key with no scope behaves exactly as before. Enforced at the same RBAC
  chokepoints as role scope (`_caller_scope`/`require_perm`). A key may also carry a
  **source-IP allowlist** (`ip_allow`: IPs/CIDRs) — it's rejected at auth from any other
  IP, so a CI or service-account key can be locked to its egress address.
- **Notification sandbox / test mode**: a new **`notifications_test_mode`** toggle
  (Settings → Notifications) makes a staging/test instance **log** webhook + email
  deliveries instead of sending them — so you can validate that events fire and route
  correctly without spamming real recipients. A per-destination `dry_run` does the same
  for a single webhook destination. The explicit "Send test email" connectivity check
  bypasses it. Default off.

## v5.4.0 — "RackMatters" — 2026-06-29 (shipped within v5.5.0 — no standalone release/tag)

A lightweight **time-tracking + billing** layer on one shared time-entry ledger:
log billable (debtable) or internal hours on tickets and a weekly timesheet, then
turn them — plus recurring fees — into per-customer invoices. No breaking changes.

- **Unified time ledger.** Every logged hour is one entry (hours in 0.25 steps,
  date, billable flag, customer/device/ticket link, note or internal category).
  Store `time_entries.json`; pure math in the new `server/cgi-bin/billing.py`.
- **Hours on tickets.** A **Log hours** button on every ticket — type hours in
  0.25-hour steps, mark billable/internal; billable hours attach to the ticket's
  customer (site, derived from the device). A running total shows on the ticket.
- **Weekly timesheet.** A personal **Timesheet** page (Planning → Timesheet, and
  linked from My Account) with a week navigator, per-day/weekly totals, and ad-hoc
  internal time (meetings, education, admin, travel, projects). Ticket hours roll
  in automatically.
- **Billing (Admin → Billing).** **Worksheet** (billable hours × rate + recurring
  fees → subtotal/VAT/total per customer per month), **Invoices** (draft → sent →
  paid, with void), **Rates & Fees** (named rate card, global currency / default
  rate / VAT / invoice prefix, and per-customer default rate / VAT / billing
  address / recurring license-operation-service fees).
- **Locking.** Issuing an invoice snapshots + **locks** the hours it bills so
  totals can't drift; voiding frees them to re-bill. Amounts are frozen on issue.
- **Finance role.** A new read-only **finance** role views/exports billing without
  admin rights; issuing/voiding invoices + editing rates stay admin-only.
- **Export.** CSV (`?format=csv`) on the ledger, worksheet and invoices; JSON API
  on every list; browser-print PDF for invoices. No new server dependencies.
- New endpoints: `/api/time-entries[/{id}]`, `/api/tickets/{id}/hours`,
  `/api/timesheet`, `/api/billing/config`, `/api/billing/worksheet`,
  `/api/invoices[/{id}]`. WEBHOOK_EVENTS unchanged (billing is not an alerting
  surface). i18n coverage for the new pages (en/zh/hi/es/ar).

## v5.3.0 — "ResolveMatters" — 2026-06-27

A built-in, opt-in **ticket system** (helpdesk) that turns alerts into owned,
tracked, resolvable work, plus an internal **Contacts** directory and a
whole-project hardening / performance / consistency sweep. No breaking changes.

- **Ticket system (Settings → Advanced → Tickets, off by default).** Tickets with
  stable `#RP` numbers; types Incident / Request / Change; priorities P1–P4;
  statuses ongoing / pending-customer / pending-internal / resolved / closed.
  Open from an alert (inherits severity/device/title) or stand-alone.
- **Ownership, teams & groups.** Take ownership (assigns you + your team), assign to
  a group's queue, per-user team (Profile → Team). The Tickets page is four tables —
  New / My open / My team's open / Other — searchable + sortable.
- **SLA.** Per-priority response targets (Settings → Advanced); tickets show time
  left; a background sweep edge-fires a new `ticket_sla_breached` event so breaches
  route through alerts/webhooks. **WEBHOOK_EVENTS now 87.**
- **Master / sub-tickets**, **alert→ticket→auto-resolve** (resolving a ticket
  resolves its linked alert), **inbound-mail auto-create + reply threading**
  (dedicated IMAP, loop-guarded), outbound via existing SMTP with a per-user
  **HTML signature**.
- **AI:** new **Helpdesk triage** advisor + a `tickets` RAG source.
- **Contacts directory** (Admin → Contacts) — a shared team phonebook.
- **Security.** Whole-project review + live pentest; bandit/gitleaks/semgrep/CodeQL
  clean. Fixed a strict-mode (`viewers_can_ack_alerts=false`) alert-permission edge
  via the ticket path; added email-header CRLF hardening. See `docs/security-review-5.3.0.md`.
- **Performance.** Dropped redundant per-heartbeat config/device deepcopies on the
  hot path. **UX/i18n:** SLA time-left + assignee omnisearch, box-overflow caps,
  11 Hindi localisation fixes.

## v5.2.0 — "AccessMatters" — 2026-06-26

A built-in, light WireGuard road-warrior VPN — **WG Access** (Admin -> WG Access).
Reach the dashboard and the fleet over an encrypted tunnel instead of exposing
services publicly. No breaking changes.

- **WG Access — tunnels + clients.** The RemotePower host runs `wireguard-go`
  (userspace, no kernel module) as the hub. Create **tunnels** — each with its own
  UDP port / address pool / endpoint / DNS and a policy: an **"Allow internet
  (full tunnel)"** toggle, a **reach scope** (none / all / site / group / tag,
  reusing RBAC scopes and enforced by per-tunnel hub firewall rules), and an
  optional **time-to-live** (minutes -> years) after which the tunnel is
  auto-deleted. Then add **clients**: each gets a **QR code** + downloadable
  `.conf`, with the private key generated **in the browser** (never sent to the
  server). Clients inherit the tunnel policy and can carry their own TTL.
- **Stats + events.** Per-tunnel RP-host rollup (interface status, connected/total
  clients, pool usage, transfer) and per-client live stats. New events
  `vpn_client_connected` / `vpn_client_disconnected` / `vpn_handshake_stale` flow
  through the alert inbox, activity feed and webhooks; tunnel expiry is
  audit-logged.
- **Security.** Client keys are browser-generated X25519; the per-tunnel hub key is
  root-only. Reach is enforced on the hub with nftables from the tunnel scope. All
  mutations are admin-only and audit-logged. The privileged `remotepower-wg-apply`
  helper takes only a structured JSON spec (argv-only, no shell) so the CGI stays
  unprivileged. The feature shows an "unavailable" notice until `wireguard-go` +
  the helper are installed.
- **AI + finalize sweep.** WG Access posture is now a fleet-knowledge (RAG)
  source — "who has VPN access?" / "is anyone connected?" — feeding a new
  **Remote-access review** AI advisor (over-broad reach scopes, full-tunnel where
  split would do, stale clients to revoke, expiring access). Tunnel pool
  utilisation + aggregate throughput and each client's source endpoint are now
  shown in the WG Access UI. Disabling a tunnel now tears the interface **down**
  (previously the re-sync silently brought it back up). Dashboard-only tunnels
  install an explicit nftables confinement chain so isolation never depends on the
  host's global forwarding state. Plus localisation fixes for the WG Access tables.

See docs/v5.2.0.md.

## v5.1.1 — "ClusterMatters" — 2026-06-26

A small follow-up to v5.1.0, centred on the Proxmox integration, plus the test
and polish gaps from the feature that shipped it. No breaking changes.

- **Proxmox: see the whole cluster, not just one node.** The integration now
  lists guests cluster-wide via `/cluster/resources`, each tagged with its owning
  node (shown as a badge), and resolves the owning node per guest so start /
  shutdown / reboot / snapshot / migrate target the right host even for a guest
  on a non-configured node. vzdump backups are enumerated on every node a guest
  lives on (cluster members write to per-node local storage), so cross-node
  guests are no longer falsely flagged as having no backup. A node-scoped token
  falls back to the original single-node listing, so existing setups are
  unchanged; cluster-wide visibility needs cluster-scope read (`Sys.Audit` on
  `/`). Node names from the cluster response are hostname-validated and
  URL-quoted before they can reach a `/nodes/<node>/…` request path. Contributed
  by **Thomas Bouquet-Gasparoux (@tbouquet)** ([#9](https://github.com/tyxak/remotepower/pull/9)).
- **Hardening the cluster feature.** Added regression tests for the new path
  (node-name injection is dropped, the listing falls back to single-node on a
  permission error / empty response, owning-node resolution is correct, the
  member listing degrades gracefully), gave the Proxmox node badge its own style
  distinct from the tags badge, and surfaced the cluster node summary in the UI
  instead of returning it unused.
- **Restore the page from the URL hash on refresh.** Reloading the app while on
  a deep page (e.g. `#containers`) used to drop you back to home; the page named
  in the hash is now restored on boot, leaving the existing `#device/<id>` and
  `#devices?view=` deep-link handlers untouched. Contributed by **Thomas
  Bouquet-Gasparoux (@tbouquet)** ([#12](https://github.com/tyxak/remotepower/pull/12)).
- **LocalAI API keys are now accepted.** The AI-provider API-key field was
  disabled for LocalAI (and Ollama), but LocalAI added API keys as a way to track
  per-app usage. The field is now optional-but-editable for local providers and
  the key is forwarded as a `Bearer` token. Reported by **@loryanstrant**
  ([#10](https://github.com/tyxak/remotepower/issues/10)).
- **Run embeddings on a different service than chat.** New optional *Embedding
  provider / base URL / API key* fields under Knowledge index (RAG) let you point
  semantic-search embeddings at a separate endpoint — e.g. a dedicated,
  less-contested GPU box — instead of always reusing the chat provider. The
  embedding endpoint gets the same SSRF pre-flight and connect-time guard as the
  chat endpoint, its key is withheld/masked on read like the main key, and
  changing it correctly invalidates the cached vectors. Semantic search can now
  also be enabled when the chat provider has no embeddings endpoint (e.g.
  Anthropic chat + LocalAI embeddings). Requested by **@loryanstrant**
  ([#11](https://github.com/tyxak/remotepower/issues/11)).
- **Whole-project finalize sweep.** A full audit (data-binding, bug hunt, security,
  performance, box-overflow, typography, layout, docs) plus a live authenticated
  pentest of the production site and a clean local CodeQL / bandit / gitleaks run.
  Fixes: the **Infrastructure-as-Code** status/generate/payload endpoints were dead
  on the SQLite / PostgreSQL backend (a storage key was probed with `.exists()`
  instead of the backend-aware check — the whole IaC feature returned "pending"
  forever on Postgres); the **File Manager** column sort moved the arrow but never
  reordered the rows (mismatched sort key); the power/update target resolver and
  six admin validators no longer 500 on a malformed (non-object) request body; a
  CMDB markdown link could break out of its `href` attribute (now escaped — was
  already neutralised by the CSP); the **patch-report CSV and XML** exports now
  include the security-update count (parity with JSON); the AI **security-posture**
  knowledge now reports break-glass from the real per-credential count; several
  dead table-sort columns were corrected and the Compliance remediation table is
  now sortable. Polish: more drawer lists and fleet tables cap at ~15 rows and
  scroll; the Reputation/DMARC, Firewall and Cron pages group each function in its
  own card (matching the DNS page); and the public NOC Status Board and a
  container-heartbeat path got small performance fixes. No breaking changes.

## v5.1.0 — "UnityMatters" — 2026-06-25

Security-signal and localisation release on top of v5.0.1. The codename
**UnityMatters** marks RemotePower's first external community contributions —
five fixes from **Thomas Bouquet-Gasparoux (@tbouquet)** (#3–#7) and the
device-write race report (#8). See [CONTRIBUTORS.md](CONTRIBUTORS.md).

- **fail2ban bans are now a first-class event.** A new fail2ban ban on a host
  fires the `fail2ban_ban` webhook/alert event (jail + banned IPs in the payload)
  — reaching the Alerts inbox, the dashboard activity feed and any configured
  webhook/SIEM. Previously bans were audit-only. Edge-triggered against the prior
  heartbeat snapshot (first snapshot seeded silently); repeat bans on a host
  coalesce into one open alert.
- **Active malware/rootkit detections now alert.** A ClamAV/rkhunter scan that
  reports an active infection fires the new `av_infected` event (previously a
  posture card only, so a real detection never reached the inbox or a webhook).
  Edge-triggered on the rising infected-count; high severity; no recover event —
  a malware finding stays actionable until an operator clears it. `WEBHOOK_EVENTS`
  now 82.
- **Arabic right-to-left layout.** `styles.css` gained `[dir="rtl"]` layout
  overrides so the Arabic locale mirrors the sidebar, navigation, cards, tables
  and drawers — not just the text.
- **More localized UI strings** across the Firewall, Reputation/DMARC, AI
  Insights, Alerts, Checks and the cron / app-catalog / file-manager pages, in all
  five languages (en/zh/hi/es/ar).

Whole-project finalize sweep (security, performance, polish — audited across the
entire codebase, not just the changes above):

- **Security.** Fixed a high-severity webhook dead-letter-queue leak (the admin
  listing echoed a secret-bearing destination URL — now redacted to host) and a
  medium-severity SSRF gap (the AI provider now re-validates the peer IP at
  connect, closing a DNS-rebinding window). Live posture re-verified: strict CSP
  with no `unsafe-inline`, HSTS preload, full security-header set, 401 on every
  unauthenticated API call. See [docs/security-review-5.1.0.md](docs/security-review-5.1.0.md).
- **Performance.** The Needs-Attention, fleet-risk/health and nav-counts caches
  now use the storage-backend mtime helpers, so they actually hit on the
  SQLite/PostgreSQL backend (they were silently recomputing the full-fleet scan on
  every poll in production); the drift-policy heartbeat read skips a config copy.
- **App catalog — add your own apps.** Admins can now add custom one-click Docker
  Compose templates to the catalog (name + compose YAML), alongside the curated
  set; deploys still ride the audited, permission-gated compose path.
- **Polish.** Capped three more variable-length tables (drift files, Proxmox
  snapshots, the netmap dependency editor) so they scroll instead of growing;
  mirrored three RTL accent rails; added a Settings toggle for the
  `allow_internal_monitors` SSRF opt-in; agent backup-verify rate-gate fixed in the
  containerised agent.

Operate-without-SSH feature batch (WolfStack-inspired; all on the test line):

- **Public status page** — the tokenized `/api/public/status` + `status.html`
  gained admin-defined component groups and a rolling incident history (no
  hostname/IP/device-id/alert-title ever leaks to the public projection).
- **Web file manager** — browse / view / edit host files through the enrolled
  agent (no SSH), gated on the `command` permission, audited, and confined to
  allowlisted roots (symlink-resolved). File ops ride a base64-wrapped `files:`
  command (never a shell); mutations are refused in audit / quarantine, reads
  stay allowed for incident response. Opt-in (`file_manager.enabled`).
- **Cron & timer management** — view and edit crontabs and systemd timers from
  the UI. Crontab content rides a base64 `cron:` command and is installed via a
  temp file (`crontab -u <user> <file>`, never a shell); edits go through the
  audited, quarantine-/audit-aware command queue.
- **App catalog** — one-click deploy of curated self-hosted apps (Uptime Kuma,
  IT-Tools, Dozzle, Linkding, whoami) via the existing Docker-Compose stack +
  deploy path (per-device `compose_enabled` opt-in, `containers` perm, audited).
- **Declarative plugin (custom HTTP probe)** — add a code-free integration: poll
  a URL+path, gate on the status code and one optional JSON field. It is an
  ordinary integration instance, so it inherits the SSRF-safe client, poll
  cadence, alerts, secret-scrub and the generic Settings UI.

Correctness, performance and hardening fixes (folded into 5.1.0):

- **Device-write race fixed — data loss on the SQL backend.** ~24 device-write
  API handlers did an unlocked read-modify-write of the device store; under the
  SQLite/PostgreSQL backend a slow admin edit could *delete* a device row (and its
  auth token) for a device that enrolled mid-edit, because the full-set save
  reconciles against a stale snapshot. Every handler now does its read-modify-write
  under `_LockedUpdate(DEVICES_FILE)`. Reported by Thomas Bouquet-Gasparoux
  (@tbouquet, #8).
- **The ~50k-line backend is no longer recompiled on every request.** The CGI
  entry point is now a thin `api_cgi.py` shim that runs the backend from cached
  bytecode instead of letting fcgiwrap recompile the main script each time
  (~0.9s → ~0.15s per request). Contributed by Thomas Bouquet-Gasparoux
  (@tbouquet, #7).
- **`_sanitize_ip` rejects trailing garbage** — the IPv4 branch of the validation
  regex was unanchored, so a valid-IP prefix matched and the whole string passed
  through verbatim into device records and the audit log. Contributed by
  @tbouquet (#3).
- **RAG embedding cache invalidated on model/provider change** — switching the
  embedding model/provider left stale vectors in the cache, silently collapsing
  semantic search to lexical-only on a dimension mismatch. Contributed by
  @tbouquet (#6).
- **`disk_watchdog_pct=0` honoured in the self-test** — an explicitly-disabled
  disk watchdog no longer flags the controller disk red at 85%. Contributed by
  @tbouquet (#4).
- **`PUT /api/drift-policies` accepts a bare-list body again** — a `get_json_obj()`
  coercion had killed the documented bare-array shape, leaving the fleet on its
  stale drift policy. Contributed by @tbouquet (#5).

With thanks to first-time contributor **Thomas Bouquet-Gasparoux (@tbouquet)** for
five fixes (#3–#7) and the device-write race report (#8). See
[CONTRIBUTORS.md](CONTRIBUTORS.md).

## v5.0.1 — "TemperMatters" — 2026-06-22

A stability + polish release that tempers v5.0.0. No breaking changes.

- **Correctness (SQLite/PostgreSQL backends)** — fixed a class of `Path.exists()` checks on DB-backed storage keys that silently read empty under the SQLite/Postgres backend: the **SSH-key drift audit**, **Proxmox stale-snapshot alerts**, and the device drawer's **host-config "current state"** view + export now work on every backend (they were dead on a DB backend). Same root cause as the v5.0.0 backup-runaway fix — now swept across the remaining read paths.
- **EPSS scores load again.** FIRST.org moved EPSS hosting (`epss.cyentia.com` → `epss.empiricalsecurity.com`) and the `-current` feed now serves via a same-host redirect; the old URL failed silently (`HTTP Error 301`) so **EPSS exploit-probability enrichment was dead** for CVE prioritization. Pointed at the new host and the feed fetch now follows the one same-host redirect (still SSRF-guarded — the peer IP is re-validated at every connect).
- **Quieter alerts** — duplicate open alerts for the same condition now **coalesce** into one row (with an occurrence count) instead of stacking up after an upgrade restart; and **agent stop/start** events no longer alert, webhook or raise needs-attention by default (they're expected upgrade churn — still recorded in Recent Activity, and re-enableable in Settings → Notifications).
- **Edit, don't re-create** — **API keys** can now be edited in place (name, role, expiry, rate limit) without deleting + regenerating the secret (which broke consumers); **custom checks** gained an Edit button too.
- **Backups survive redeploys** — `RP_BACKUP_PASSPHRASE` (and other server secrets) now load from `/etc/remotepower/api.env` via the unit's `EnvironmentFile=`, so an upgrade no longer wipes an inline `Environment=` line and silently drops backup encryption.
- **Turnkey self-update** — a ready-made, install-aware update script ships at `packaging/remotepower-server-update.sh` (auto-detects git / pacman / apt, restarts the worker) for the Settings → Install "Run update now" button.
- **Long-session UI performance.** The device grid no longer rebuilds its DOM on the 60s tick while the Devices page is hidden (it created + discarded hundreds of nodes every minute → steady GC churn that made a never-reloaded PWA feel progressively sluggish); the grid now renders on page entry and only re-renders while visible. Page-scoped pollers (e.g. the Logs tail) are stopped when you navigate away. A built-in perf HUD (`rpPerfHud()` in the console, or `?perfhud=1`) shows live JS-heap + DOM-node counts to diagnose any remaining drift.

## v5.0.0 — "CTRLMatters" — 2026-06-22

Control-plane hardening + scale. No breaking changes.

- **Security** — opt-in mutual TLS for agents (CA-verified client certs, optional per-device pin), AES-256-GCM encrypted DR backups (`RP_BACKUP_PASSPHRASE`), break-glass vault reveals (two-person rule + immutable audit + `vault_break_glass` alert), per-API-key rate limiting.
- **Reliability** — server disk-space watchdog (`server_disk_low`/`_ok`), webhook dead-letter queue with retry + event replay, runtime maintenance mode (drain command dispatch during upgrades), graceful SIGTERM for long-poll commands, OSV circuit breaker.
- **Fleet** — bulk device delete + bulk tag, per-command timeout override, agent/server version-compatibility check, one-click rollout rollback (script rollouts).
- **Scale** — cross-device OSV batching (one OSV sweep per ecosystem for the whole fleet).
- **Polish** — copy-to-clipboard everywhere, webhook delivery dots, per-device alert snooze, pending-command nav badge, rename/duplicate saved queries, palette command-history search, one-click Run-diagnostics. `WEBHOOK_EVENTS` now 80 (adds `agent_stopped`, `agent_started`, `vault_break_glass`, `backup_verify_failed`, `rollout_halted`, `server_disk_low`, `server_disk_ok`).
- **CMDB & inventory** — record a host's network interfaces (several NICs, each with its own optional NAT / public IP child for assets behind 1:1 NAT, one flagged primary), edited with a live preview tree. Mark an asset **Decommissioned** to grey it out across the device list and fully silence it (no monitoring, alerts, health or SLA); clearing it restores monitoring. New **Business function** field and a wider two-column asset editor.
- **Network Metrics page** — per-device RX/TX throughput rolled up fleet-wide or by group / tag / site.
- **Network map at fleet scale** — a scope picker (site / group / tag) renders one slice of the topology instead of every node at once.
- **Thermal page** — expand any host to see every sensor (temperature + critical), a ~24h trend sparkline, and a per-host warning/critical Thresholds editor.
- **Backups** — migrate existing plaintext archives to encrypted from the web UI (Server status → Backup → “Encrypt existing backups”, request-only passphrase).
- **Ticketing** — ready-made Jira / ServiceNow / Zendesk webhook formats for the on-ack opt-in, with the opened ticket's link shown on the alert.
- **Settings** — an Install pane with a latest-release version check + guided self-update (runs an operator-set update script); an optional login banner / security notice.
- **Accessibility** — every table column header carries `scope="col"`; icon-only buttons are `aria-label`led and decorative icons `aria-hidden`.
- **AI knowledge index** — the live-state corpus now also covers mount problems, failing custom checks, running process names, and file-descriptor / conntrack saturation, so the assistant can answer those reliability questions from real data.
- **Performance (big fleets)** — the heartbeat hot path no longer rewrites whole-fleet blobs every beat: `containers.json`, `update_logs.json`, `cmds.json` and `uptime.json` are now per-device entity stores (O(1) single-row read/write on SQLite/Postgres instead of O(fleet)), with a safe one-time migration. Dashboard posture and bandwidth roll-ups are computed only when those widgets are on screen.

**Hardening & finalize sweeps** (independently pentested — no Critical/High/Medium findings):

- The legacy `webhook_url` is no longer returned by `GET /api/config` (it embeds a secret — only a `webhook_configured` boolean is exposed now; rotate that webhook after upgrading if you used the legacy field). Per-disk SMART / per-GPU / temperature-trend samples are written outside the hardware lock so they're durable on the SQLite backend.
- Fixed a 500 on the per-device patch report. The agent's audit (read-only) mode now also refuses server-pushed custom monitoring scripts (the fourth command channel). Distro security-flagged update counts are surfaced on the Checks page and in the patch alert. SSRF connect-time guards extended to SNMP, LDAP and Proxmox runtime calls (loopback / link-local / cloud-metadata refused, peer IP re-validated). The containerized agent reads backup, web-access-log, file-log and ACME paths through the host rootfs. The Reputation, DMARC and Scoped-credential tables are now sortable. The NOC Status Board and break-glass list cap their height and scroll. The heartbeat writes `backup_state` once per beat instead of twice; debug instrumentation no longer runs on every request when disabled.
- **Critical fix:** the daily scheduled-backup gate checked `Path.exists()` on `self_backup_state.json`, but under the SQLite/Postgres backend that state is a database row, not a file — so the 24-hour throttle never engaged and a full encrypted backup ran on **every heartbeat**. It now uses the storage-aware existence check; the same class was swept across the backup and cache subsystems.

**Deferred:** user-configurable timezone. See [docs/v5.0.0.md](docs/v5.0.0.md).

## v4.10.0 — "PerimeterMatters" — folded into v5.0.0 (no standalone release)

A perimeter-defense and AI release: a fleet-wide **Firewall + fail2ban** page
(view *and* edit), **20 new AI features** in an AI Insights hub, four new
sources in the fleet-knowledge (RAG) index, and a UI-polish + release-readiness
finalize sweep. No breaking changes, no schema changes.

### Finalize sweep (whole-project)

- **Devices** — hover tooltip on the patches badge; **Reputation** now reads
  "Clean — N unreachable" so the reachable blocklists' clean status is explicit.
- **Risk** — seven more factors (OS end-of-life, overheating, config drift,
  clock skew, gateway down, recent OOM) from already-collected data.
- **Thermal** — per-sensor critical thresholds, a headroom column, GPU
  fan/util/power, and a full per-sensor hover breakdown.
- **Certificates** — ACME revoke/remove now passes `--ecc` for EC certs.
- **Search** — the `/` command palette and the sidebar search now cover every
  page (Firewall, Risk, DNS, GPUs, Integrations, …) and concept keywords.
- **AI / RAG** — a new **Email & DNS** source (DMARC/SPF/DKIM, DNSBL reputation,
  resolver health) grounds the email-deliverability and DNS-hygiene advisors;
  fixed a latent bug where the firewall/integrations/backups RAG toggles didn't
  persist.
- **Security** — firewalld-delete argument validation, IPv6-encoded
  metadata-IP unwrapping in the TLS monitor, and containerized-agent host-path
  fixes for drift / authorized-keys / mailbox reads. No Critical/High/Medium
  findings ([docs/security-review-4.10.0.md](docs/security-review-4.10.0.md)).
- **Performance** — scope-keyed cache on the sidebar badge poll; the agent's
  per-poll service check batched from up to 50 subprocesses into one.
- **Agent audit (read-only) mode** — touch `/etc/remotepower/audit-mode` on a
  host and its agent becomes **observe-only**: it keeps collecting and reporting
  (and read-only lynis/OpenSCAP/CVE assessments still run), but **refuses every
  command** — exec/scripts, reboot/shutdown, config apply, self-update. The flag
  is an operator-owned file the **server can't clear**, so the host can't be
  modified through the agent by design. The server also refuses to queue actions
  for an audit host, and the device shows an **AUDIT** badge. Linux / Windows /
  macOS agents all enforce it.
- **Reports** — the per-device Uptime (SLA) table is now searchable by device or
  group.
- **Site / group / tag-scoped credentials** — define a shared login once at a
  site, group or tag level (a customer's domain admin, a site's switch password)
  and it's **inherited by every member device**. Same encrypted CMDB vault
  (AES-GCM, key from the `X-RP-Vault-Key` header — never stored); every reveal is
  audit-logged. Managed from a card on the **CMDB** page. A scoped operator can
  reveal **its own scope's** credentials (admins see all); create/delete stay
  admin-only.
- **Read-only "Auditor" role** — a new built-in role that sees the oversight
  surfaces an external auditor needs (audit log + hash-chain verify + archive,
  evidence pack, security posture, compliance) but **runs nothing** and never
  reveals a secret. The console complement to agent audit-mode.
- **Agent-stopped ≠ host-offline** — a gracefully stopped agent (`systemctl
  stop`) now fires a distinct **`agent_stopped`** signal ("agent stopped, host
  was up") instead of a silent offline — the first move in an intrusion. Auto-
  recovers (`agent_started`) when the agent resumes. (An ungraceful `kill -9`
  still shows as offline.)
- **Backup integrity verification** — beyond freshness, the agent can run a
  backup's **own integrity check** (`tar -tf`, `restic check`, `borg check`),
  rate-gated and time-bounded; a failed check fires **`backup_verify_failed`**
  (auto-recovers on the next clean check). Enable per monitor in Settings →
  Advanced; status shows in the device drawer. `tar` needs nothing; restic/borg
  need their passphrase in the agent's environment.
- **Per-site (customer) reports** — the fleet posture report (devices, patches,
  SLA, CVEs, health) scoped to one **site**, with a "Report" button per site and
  `GET /api/report/site/{id}` (JSON/CSV). RBAC-scoped.
- **Health-gated rollouts (canary auto-halt)** — opt-in per rollout: after a ring
  is dispatched, if a targeted host's **health score drops below a floor** during
  the verify window (and wasn't already below it), the rollout **auto-halts** and
  fires `rollout_halted`. Fully reversible — it pauses for you to resume or
  cancel, never rolls back on its own. Default off.

### Security → Firewall page (firewall + fail2ban)

Fleet-wide visibility *and* editing for host firewalls and **fail2ban**, in one
place ([docs/firewall.md](docs/firewall.md)).

- **Host firewalls.** Every host's firewall posture (nftables / iptables / ufw /
  firewalld — backend, default policy, active state, rule count and drift
  fingerprint) in one sortable table. Open a host to see its actual ruleset and
  **add or delete rules** — ufw/firewalld port rules and raw nftables/iptables
  rules. Unmonitored hosts still show their posture (flagged), like the other
  telemetry views.
- **fail2ban.** Jails and the IPs each has banned, per host. **Ban or unban** an
  address and **start or stop** a jail. Hosts without fail2ban report it as not
  available.
- **Safe by construction.** Every edit runs through the existing audited,
  permission-gated (`command`) command queue — quarantined hosts are skipped, and
  rule specs are strictly validated server-side (no shell metacharacters) before
  they reach a host. Read-only visibility needs no special permission.
- Agents report fail2ban status and capped per-backend rule lists; the
  containerized agent reports fail2ban as not-available (no host socket).

### AI RAG — three new corpus sources

The fleet-knowledge index (what "Ask my fleet" and the AI assistant retrieve
over) now also indexes — on by default, cheap, no-PII:

- **Firewall & fail2ban** — per-host firewall posture (backends, active state,
  rule counts, policy) and fail2ban jails/bans, plus a fleet "which hosts have
  no active firewall" rollup. Rule *counts* only, never raw rules.
- **Homelab integrations** — health of every connector (Pi-hole, TrueNAS, *arr,
  …) and a down/degraded rollup.
- **Backups** — per-host backup freshness and a fleet "stale backups" rollup.

So the assistant can now answer "which hosts have no firewall?", "is fail2ban
running on web01?", "which integrations are down?" and "are db01's backups
current?" directly from indexed state. Toggle each in Settings → AI → RAG.

### AI Insights — 20 new AI features

The **AI Assistant** page gains an **AI Insights** hub: one-click reports and
advisors that run against your configured provider with RAG/fleet context
attached. New capabilities:

- **Proactive:** daily fleet briefing · log-anomaly digest · alert-noise tuning
  advisor · predictive-maintenance narrative.
- **Incident:** incident root-cause narrative · group-related-alerts ·
  pre-run change-risk review.
- **Natural language → config:** fleet query → structured filter · monitor/check
  from a sentence · reverse-IaC (Ansible from a host's live state).
- **Planning:** CVE remediation plan (KEV-first, staged) · compliance
  remediation plan · capacity & cost forecast · backup/DR-readiness advisor.
- **Advisors:** firewall rule auditor (also a button on the Firewall page) · DNS
  hygiene · email deliverability (DMARC/SPF/DKIM/DNSBL) · homelab integration
  assistant · supply-chain/SBOM Q&A · host one-pager.

Each is a tunable system prompt (Settings → AI → Prompts), rate-limited,
audited, and redaction-aware like the existing AI actions.

### UI polish + finalize sweep

- Firewall/fail2ban detail panels highlight the open host, scroll into view, add
  a Close button, and mark queued edits in-panel (no more stale "did it work?").
  Rule lists are grouped by table/chain with the volatile packet counters
  stripped; banned IPs show an inline Unban.
- The AI Insights hub is grouped (Proactive / Incident / Planning /
  Natural-language / Advisors) with per-category icons.
- Three fleet-scaling dashboard lists (heatmap, upcoming events, timeline) are
  now scroll-capped, plus a11y fixes (labelled toolbar filters, a no-emoji icon
  swap) and a themeable severity-orange.

## v4.9.0 — "ResolutionMatters" — 2026-06-18

Adds an **Admin → DNS dashboard** that reads and writes DNS records directly
through your provider's API, so you can manage zones without leaving RemotePower
or opening each registrar's console. It reuses the scoped API tokens already
stored for ACME DNS-01 issuance — set a token once and it drives both certs and
this dashboard. No breaking changes, no schema changes.

- **DNS dashboard (Admin → DNS).** Pick a provider and zone; list, create, edit
  and delete A / AAAA / CNAME / TXT / MX / NS / SRV / CAA records with TTL,
  MX/SRV priority and Cloudflare's proxied flag.
- **Resolve / dig + propagation.** A live panel resolves a name and shows the
  zone's authoritative answer next to public resolvers (Cloudflare/Google/Quad9/
  OpenDNS) — surfacing drift between provider state and reality. A per-record
  propagation check polls the public resolvers and reports "propagated X/N" after
  an edit. Read-only; queries only the fixed resolver allowlist + authoritative
  NS (private/loopback/link-local/metadata filtered).
- **Resolver health monitor.** Watch names for resolution failures: each is
  re-checked across the public resolvers on a rate-limited cadence, tracking
  latency and NXDOMAIN/failure rates. New `resolver_unhealthy` /
  `resolver_recovered` alert events (flap-dampened — a name must stay down for
  two consecutive checks before alerting) wired through the full webhook/alert/
  channel/feed routing. WEBHOOK_EVENTS is now 72.
- **Alert-resolution timeline (MTTR).** A new section on the Alerts page reports
  time-to-resolution (MTTR) and time-to-ack across recently-resolved alerts —
  overall mean/median, a per-host breakdown, and a timeline classifying how each
  alert was closed (auto recover event / manual operator / muted) with who and
  the note. Pairs with the ack-webhook.
- **Fix:** recover events (`integration_recovered`, `ip_blacklist_cleared`,
  `resolver_recovered`) now reliably auto-resolve their open alert — the matching
  keys (`integration_id` / `ip` / `target`) are persisted on the alert so the
  recovery can find and close it instead of leaving it open.
- **Five providers.** Cloudflare, DigitalOcean, Hetzner DNS, deSEC and Porkbun —
  plain token-REST APIs. deSEC's RRset model and Porkbun's subdomain/body-auth
  form are normalised behind one record shape.
- **Credential reuse.** Tokens come from the existing
  `config['acme_dns_credentials']` store (CF_Token, DO_API_KEY, HETZNER_Token,
  DEDYN_TOKEN, PORKBUN_API_KEY/SECRET) — no second secret store.
- **Admin-only + audited + SSRF-guarded.** Every endpoint is admin-gated; writes
  are audit-logged; deletes require explicit confirmation. Outbound calls reuse
  the hardened opener (no loopback / link-local / cloud-metadata, connect-time
  re-validation, no redirects).
- **Optional encrypted-vault storage.** Provider tokens can be stored in the
  existing CMDB vault (PBKDF2 + AES-256-GCM, passphrase never persisted) instead
  of clear text. The DNS page unlocks the vault on demand, decrypts the token
  per-request via the `X-RP-Vault-Key` header, and never writes plaintext to
  disk. Plaintext `acme_dns_credentials` stays as the fallback for unattended
  ACME automation, which can't supply a passphrase. **Import from config** moves
  credentials you've already entered under ACME → DNS into the vault (encrypting
  them) with no re-typing, and can remove the plaintext copy afterwards.
- **Import from agent → vault, one flow.** If your provider tokens live in
  acme.sh's `account.conf` on a host (e.g. `SAVED_CF_Token` / `SAVED_CF_Key`),
  the agent on that device harvests them on demand: unlock the vault, pick the
  device, click **Import from agent**. The server flags the device for a one-shot
  harvest; the agent (running as root) reads `account.conf` and returns the
  `SAVED_*` credentials over the authenticated heartbeat (never via the
  command-output log); the page polls the agent's next check-in with live status
  and then **encrypts the token straight into the vault** (clearing the transient
  plaintext). Then pick the provider + zone and the records load. The device
  picker lists all agent devices, so it works even before the slow acme.sh scan
  has reported.
- **Fix:** the debug-logging `api()` wrapper dropped the 4th argument, so when
  debug logging was on, per-call options (the `X-RP-Vault-Key` header, an
  AbortController `signal`) were silently lost — e.g. vault-keyed DNS writes
  failed with a spurious "vault locked". The wrapper now forwards all arguments.

## v4.8.0 — "OnboardingMatters" — 2026-06-17

An onboarding release: standing the server up — and adding the hosts you manage —
is now a single command, with HTTPS on by default and no insecure default
password. Plus a full DMARC monitor, accessibility work, and agent parity. No
breaking changes. Full notes in [docs/v4.8.0.md](docs/v4.8.0.md).

- **Turnkey onboarding.** A unified **`install.sh`** wizard provisions server +
  TLS + admin in one run. **One-command Docker** (`docker compose up -d`) serves
  HTTPS by default with no insecure default password (the admin password is
  printed to the container log). A self-hosted **`/install`** endpoint serves a
  "Quick install" agent with the server URL, token and integrity baked in — the
  operator just downloads and runs it and the host appears by its hostname.
  `install.sh agent push --server <url> --token <token> user@host …` bootstraps
  agents over SSH; `install.sh uninstall` cleanly removes the server, agent or
  demo. Heavy-fleet scaling is reframed as an explicit advanced track, and the old
  `Manual.html` is folded into the docs.
- **Reputation/DMARC monitor.** A new page for mail-deliverability posture.
  - **IP reputation (DNSBL).** Add your mail-sending IPs and RemotePower checks
    each against DNS blocklists (Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT,
    PSBL), re-scans periodically, and fires `ip_blacklisted` / `ip_blacklist_cleared`
    alerts on transitions. Endpoints `GET/POST /api/reputation/targets`,
    `DELETE /api/reputation/targets/<id>`, `POST /api/reputation/scan`.
  - **DMARC / SPF / DKIM.** Grades your domains' published SPF/DKIM/DMARC DNS
    records **and** ingests the aggregate (RUA) reports your receivers send back:
    point it at an IMAP mailbox and it polls (scheduled + on-demand), parses the
    gzip/zip XML, and shows per-source SPF/DKIM pass/fail tallies plus mailbox
    health. Endpoints `GET /api/dmarc/reports`, `POST /api/dmarc/fetch`,
    `GET /api/dmarc/imap`, `POST /api/dmarc/imap`.
- **Accessibility.** Every modal dialog now has an accessible name, and every
  native `confirm()`/`prompt()` is replaced with a styled, accessible in-app
  dialog.
- **Agent parity.** macOS reports saturation metrics (1-minute load average +
  file-descriptor utilisation %); Windows reports NVIDIA GPU telemetry.
- **Reliability.** The CVE "Scan all devices" action no longer hangs the browser;
  the audit-log clear action now explains why it was denied.
- **Security hardening.** Tighter scanner temp-workdir permissions, corrected
  containerized-agent host reads, macOS/Windows credential-file hardening, and
  internal lock-safety fixes. Independently tested with wapiti, nikto, nuclei,
  bandit and OWASP ZAP — passed clean.

## v4.7.0 — "IntegrationsMatters" — 2026-06-15

A reach-outward release: monitor the popular software your homelab/fleet already
runs, and run the agent as a container to watch a Docker host. No breaking
changes. Full notes in [docs/v4.7.0.md](docs/v4.7.0.md).

- **Homelab software integrations (26 connectors).** A new read-only server-side
  subsystem polls popular self-hosted software for health on a cadence and folds
  it into the Alerts inbox + dashboard. Connectors: Pi-hole (v6), AdGuard,
  TrueNAS, Unraid, Kubernetes/k3s, vCenter/ESXi, Proxmox Backup Server, UniFi,
  Traefik, Nginx Proxy Manager, Caddy, Netdata, Grafana, Uptime Kuma, Jellyfin,
  Plex, Home Assistant, Nextcloud, qBittorrent, Transmission, Deluge, SABnzbd,
  NZBGet, Servarr (one connector for Sonarr/Radarr/Prowlarr/Lidarr), Bazarr, and
  Overseerr/Jellyseerr. Configure under **Settings → Integrations**.
- **Health → Alerts + widget.** An unhealthy/unreachable target raises an
  `integration_down` alert (severity from the result, auto-resolved on recovery)
  routed through your channels, plus an **Integration health** dashboard widget.
- **Security.** Every outbound call goes through the SSRF guard (loopback /
  link-local / cloud-metadata refused, RFC1918 LAN allowed, peer re-validated at
  connect time, redirects refused); credentials are stored server-side and
  redacted from every response; the raw URL is admin-only. An independent
  adversarial review closed all findings.
- **Show Homelab software.** An instance-wide switch (default on) hides the whole
  feature — stops polling, hides the section + widget — for enterprise instances.
- **Containerized agent.** The Linux agent can run as a container that monitors
  its Docker host with no host install (*Enroll device → Generate Docker
  compose*). Reads the host's facts (shared PID/network namespaces, host rootfs
  read-only), names itself after the host, persists credentials in a volume.
  Published multi-arch at `ghcr.io/tyxak/remotepower-agent`; standard
  capabilities, no `--privileged` (SMART/DMI and Docker-socket container
  inventory are opt-in).
- **Fleet GPU page.** A new **Monitoring → GPUs** page shows every GPU across the
  fleet (NVIDIA + AMD) with utilisation/VRAM meters, temperature, power and fan,
  hottest-busiest first. AMD gains a tooling-free amdgpu sysfs fallback; NVIDIA
  gains fan speed. Each card carries **temperature + utilisation trend sparklines**
  (last ~4 h of samples). Hosts report via `nvidia-smi` / `rocm-smi` (or the
  amdgpu sysfs fallback). Plus richer Dashy-style integration tiles (a dashboard
  widget + a dedicated Integrations page) that surface the live stats the
  connectors pull.
- **GPU thermal alerting.** A GPU at or above the temperature threshold (default
  85 °C, configurable) raises the standard **high-temperature** alert and
  auto-resolves when it cools — it reuses the existing hardware-temperature alert,
  so there is no new alert type to wire up.
- **Unmonitored devices now show their data everywhere.** Telemetry and inventory
  views — thermal, power, storage, exposure, predictive-health/SMART, patches,
  listening ports, processes and GPU — now display **unmonitored** hosts too
  (they're flagged so the UI marks them). Only **alerting** stays suppressed for
  unmonitored devices, the same gate the alert pipeline already used.
- **CSP report hygiene.** The in-app CSP violation reporter now ignores reports
  whose source is a **browser extension** (`moz-extension://`, `chrome-extension://`,
  `safari-web-extension://`, …), so users' browser extensions can no longer
  pollute the security log with violations the app didn't cause.

## v4.6.1 — 2026-06-14

A stability-and-hardening patch on top of v4.6.0 "RepellantMatters". It fixes two
issues that only surface under the optional **SCGI prefork worker**, closes a
**ReDoS** and a defence-in-depth **XSS** finding, and removes a small **UI flash**
on page reload. No breaking changes and no schema changes. Full notes in
[docs/v4.6.1.md](docs/v4.6.1.md).

- **SCGI worker: agentless ICMP devices flapped offline.** The worker runs with
  `NoNewPrivileges=true`, which blocks `ping`'s setuid / file-capability
  elevation, so its raw ICMP socket failed and reachability sweeps reported
  agentless devices down. The unit now grants `AmbientCapabilities=CAP_NET_RAW`,
  so the spawned `ping` inherits the capability across `exec` with no privilege
  escalation. Classic fcgiwrap/CGI was never affected.
- **SCGI worker: Postgres `consuming input failed: EOF detected`.** A forked
  worker child inherited the parent's `psycopg` connection, and two processes
  sharing one socket corrupted the protocol stream. The Postgres backend now tags
  each connection with the PID that opened it and transparently reconnects in a
  child — the same fork-safety guard the SQLite backend already had.
- **Security — ReDoS in `_valid_tls_host`.** The hostname validator used a single
  regex with a nested quantifier that backtracked catastrophically on a long run
  of letters and hyphens. It now validates **label by label** with a fixed-shape
  per-label matcher (linear time, identical accept/reject set), removing the
  denial-of-service surface on input that can reach a certificate SAN.
- **Security — package "upgradable" count coerced before render.** The per-device
  update badge coerces the upgradable count to a number (or `'?'`) before it is
  interpolated into `innerHTML`, so a non-numeric value can never reach the DOM as
  markup. The strict no-inline CSP is an independent second barrier.
- **UI — page subtitle no longer flashes as raw text on reload.** In the
  Industrial (New) UI each page's subtitle is folded into a hover info icon at
  runtime, but the fold was gated on the `data-ui` attribute JavaScript only sets
  after first paint. The subtitle is now hidden by default in CSS and revealed
  inline only in the Old UI, with visibility decided before the icon-attachment
  logic — so it's never left as orphan text.

## v4.6.0 — "RepellantMatters" — 2026-06-14

A visual-identity release paired with a project-wide reliability, security and
performance polish pass. A new **Industrial** interface ("New UI") becomes the
default, with a one-click **New UI / Old UI** toggle so anyone can keep the
classic look — and a thorough sweep of the whole project lands alongside it.
No breaking changes; fully CSP-safe. Full notes in
[docs/v4.6.0.md](docs/v4.6.0.md).

- **Industrial "New UI" (default).** A distinctive skin that drops the generic
  slate-navy template for a warm **graphite/steel** palette (keeping the
  RemotePower **blue** accent), instrument-panel motifs — corner ticks on panels,
  dashed technical rules, mono uppercase eyebrow labels, tabular figures — and
  sharper corners. Implemented as `body[data-ui="industrial"]` layered after the
  theme blocks. The **sidebar/nav are set in self-hosted IBM Plex Mono** and the
  rest of the UI keeps the familiar Inter (no external fonts; the strict CSP
  blocks Google Fonts).
- **New UI / Old UI toggle.** A new **Settings → Interface** tab (and a control in
  **My Account → Appearance**, so non-admins can switch too) flips between the
  Industrial look and the classic one. Per-browser preference (`rp_ui`, default
  `new`), applied instantly with no reload. Wired via `data-action="setUIVersion"`
  through the existing delegated dispatch — no inline scripts/styles/handlers.
- **Navigation.** A dedicated **Admin** sidebar group (Links moved there), and
  every sidebar group is alphabetically sorted.
- **Bind it together.** The device drawer now shows **CPU model, kernel, total
  RAM and total disk** beside the live usage (previously CMDB-page-only); more
  lists and Hardware/SNMP tables cap at ~15 rows then scroll internally; and the
  disk-forecast table sorts correctly by both GB and percent.
- **Security (independently pentested clean — wapiti, nikto, nuclei, bandit,
  OWASP ZAP).** SSRF pre-flights extended to the OPNsense / Proxmox / AI-provider
  / TLS-monitor targets (matching the RouterOS guard); resolved-role checks on
  two read endpoints (a custom operator role could previously read admin-only
  config and a pending-confirmation count); and hardened agent credential
  storage — restrictive ACLs on the Windows token file, atomic 0600 writes on
  macOS, and the Linux command stash routed through the O_NOFOLLOW helpers. See
  [docs/security-review-4.6.0.md](docs/security-review-4.6.0.md).
- **Performance.** The dashboard's 7-day uptime stripe is cached 5 min instead of
  firing a second round-trip every tick; the offline-sweep transition handler
  uses single-row reads; and the agent heartbeat is lighter — memoized tool-path
  and CPU-model lookups, a single memory read, and a non-blocking uptime probe.
- **Correctness fixes.** Custom-script OK↔FAIL alerts no longer drop under the
  SQLite backend; the device runbook now actually injects its RAG context and
  recent-command history; the `kernel_outdated` device-list filter works again;
  and the CMDB asset modal shows real free-memory / free-disk figures.
- **New feature: generate a self-signed certificate from the UI** — *Settings →
  Security → Self-signed certificate*. Admin-only, audited; generates the CA +
  server cert in Python (`cryptography`, no root / no `openssl`) into the data
  dir's `tls/`, reusing the CA on re-issue, and shows the fingerprint +
  agent-enrolment line. Complements `tools/gen-ca.sh` (v4.5.0).
- The audit-log clear now uses the masked in-app password modal (the native
  `prompt()` showed the typed admin password in clear text).
- Predictive health no longer alerts on a disk that's years from failing (only
  reactive high/critical or a ≤180-day ETA), and lists a host's healthy disks
  alongside its at-risk one instead of hiding them.
- **Release distribution.** Releases now ship a **GPG-signed** tarball
  (`make release` → `.tar.gz` + `.sha256` + `.asc`), and a **multi-arch
  (amd64 + arm64)** server image is published to the **GitHub Container
  Registry** on every release —
  `docker pull ghcr.io/tyxak/remotepower:<version>` (or `:latest`).
- Colour themes (nord/dracula/…) continue to apply to the Old UI.

## v4.5.0 — "TrustMatters" — 2026-06-13

TLS onboarding. A one-command self-signed **CA** for instances that can't use a
real cert, fingerprint-verified rollout to agents, and an opt-in TLS mode for the
Docker image. **No breaking changes** — HTTP-only installs and real-cert setups
are untouched. Full details in [docs/v4.5.0.md](docs/v4.5.0.md) and the decision
tree / migration guide in [docs/tls-selfsigned.md](docs/tls-selfsigned.md).

- **Self-signed CA + leaf generator** (`tools/gen-ca.sh`, `make tls-selfsigned
  HOST=…`). Generates a private CA and a server leaf (ECDSA P-256, SAN, EKU
  serverAuth), installs the leaf for nginx, and prints the CA's SHA-256
  fingerprint. Agents trust the **CA**, so `make tls-renew` re-issues the leaf
  without touching a single client.
- **Fingerprint-verified agent rollout.** `install-client.sh --ca-fingerprint
  <sha256>` (and the macOS / Windows installers) fetch the CA over HTTP and
  refuse to trust it unless its fingerprint matches — safe bootstrap with no TLS
  yet. The CA is wired in via `RP_CA_BUNDLE` (systemd EnvironmentFile / launchd
  plist / Windows machine env); all three agents also fall back to the
  conventional CA path. nginx serves the CA at `/ca.crt`.
- **Shared nginx location snippet.** The HTTP and HTTPS server blocks now include
  one `remotepower-locations.conf` (also the Docker config) so they can't drift,
  and HTTPS is a clean uncomment.
- **Docker opt-in TLS.** `RP_TLS_SELFSIGNED=1` makes the container generate a
  CA+leaf into the data volume on first boot and serve HTTPS on :8443, printing
  the fingerprint to `docker logs`.
- **Switching self-signed → real is a server-only change:** because the agent
  trusts the system roots *and* the CA simultaneously, you point nginx at a real
  (Let's Encrypt) cert and reload — agents keep working with no redeploy.
- A real cert is still recommended; the self-signed path is for airgapped /
  internal-only / no-public-DNS deployments.

## v4.4.1 — "DocumentationMatters" — 2026-06-13

A documentation-and-triage release on the heels of the security-themed v4.4.0.
**No breaking changes and no runtime behaviour changes.** Full details in
[docs/v4.4.1.md](docs/v4.4.1.md) and [docs/security-review-4.4.1.md](docs/security-review-4.4.1.md).

**CodeQL code-scanning triage — all 13 alerts are false positives:**
- **XSS / DOM-as-HTML (7):** every flagged `innerHTML` assignment interpolates
  only values that pass through the project `escHtml()` / `escAttr()` sanitizers
  (unrecognised by CodeQL's default model), behind the strict no-inline CSP.
- **SSRF (1, Critical):** `fetch('/api' + path)` is the same-origin front-end API
  client — an origin-pinned relative path, never a user-supplied host.
- **Weak hashing (2):** one is the **HMAC-SHA256** audit chain (strong); the
  other a non-security dedup key already marked `usedforsecurity=False`.
- **Clear-text logging / storage (3):** the admin-gated diagnostics download
  (by design, `no-store`), a non-sensitive `stderr` diagnostic, and the app's
  own atomic `chmod 0600` data-file write.

**Hardening (no behaviour change):**
- The two MD5 cache-key fingerprints in the fleet-checks fast path now pass
  `usedforsecurity=False` — the signal CodeQL's weak-hash query honours. The
  remaining 11 alerts are documented false positives suitable for dismissal.

**Documentation:**
- A coverage pass across all five doc surfaces (in-app Documentation page,
  README, `docs/Manual.html`, per-version notes, did-you-know tips) confirmed
  every shipped feature/function is documented and the headline counts are
  accurate (65 webhook events, the 66-widget dashboard catalog, 18 MCP tools =
  14 read + 4 guarded write). Rotated the version/security-review doc sets to the
  kept window and repointed links to the durable `docs/security.md`.

## v4.4.0 — "FortifyMatters" — 2026-06-13

A security-hardening and bind-it-together release. **No breaking changes.**
Full details in [docs/v4.4.0.md](docs/v4.4.0.md).

**Security (audited + independently pentested with wapiti / nikto / nuclei /
bandit / OWASP ZAP — clean):**
- **Critical:** the `require_admin` gate blocked `viewer`/`mcp` by name, letting
  a custom operator role reach every admin-only endpoint (user/role/key/config
  management and the agent-update signing key). It now checks the resolved
  role's `admin` flag — built-in admin only.
- Scope-guarded the mitigation status / AI-analysis routes (they returned
  captured command output to a scoped operator outside their scope).
- `shlex.quote` on the drift file-fetch and ACME issue/renew/revoke commands —
  closes a watched-path / agent-home shell-quoting break-out.
- RouterOS REST integration now runs the SSRF pre-flight (blocks
  loopback/link-local/metadata, allows the RFC1918 LAN target).
- `/api/metrics` degrades to a minimal payload + `remotepower_scrape_error`
  gauge instead of 500-ing when a single store record is malformed.
- Agent: lynis posture audit uses a private temp file (was a fixed `/tmp` path
  → local symlink-clobber privesc).
- Windows & macOS agents now enforce HTTPS and a TLS 1.2 floor (Linux already
  did) — no cleartext token, no obsolete-TLS downgrade.

**Bind it together:**
- Device drawer: recent-logins table gains a **Last seen** timestamp column
  (agent now reports per-login time); Clock pill reflects the server's
  threshold-aware skew verdict ("skewed" vs "synced").

**Performance:**
- Heartbeat watched-files and host-config-enforce lookups are single-row reads
  (O(1) on SQLite/PG instead of O(fleet)).
- The 15s fleet-checks cache now honours its TTL instead of being busted by
  every heartbeat — the per-host checks loop no longer re-runs on every poll.
- Agent memoizes its OS string (one `/etc/os-release` read per process).

**Polish:**
- Capped the remaining variable-length boxes (fleet AI anomaly results, saved
  links grid, AI-prompt list); folded leftover off-scale font sizes back onto
  the canonical scale.
- Installer ships/wires the optional SCGI worker unit, copies the full static
  tree, and prints a TLS-setup reminder; `docs/install.md` documents the
  password utility, the SCGI worker, and a Let's Encrypt walkthrough.

## v4.3.0 — "ImprovementMatters" — 2026-06-11

A refinement release — no new headline subsystems and **no breaking changes**.
Sharpens what's already there: read-path performance on large fleets,
self-observability, UX polish, and regression guardrails.

- **Faster on bigger fleets.** On the SQLite / PostgreSQL backends, the
  single-device endpoints (per-host Checks, per-device CVE detail, the
  heartbeat's host-config + watched-file lookups, and the firewall / compose /
  RouterOS / OPNsense device actions) now read **one row** via a new
  `storage.device_get(dev_id)` instead of reconstructing the whole fleet per
  request — O(fleet) `json.loads` → O(1). Flat-JSON behaviour is unchanged; the
  returned data is identical.
- **A faster dashboard, especially in Firefox.** Removed the sticky-header /
  modal `backdrop-filter` blurs (Firefox re-blurs per frame), made every
  animation compositor-only (the skeleton shimmer no longer animates
  `background-position`), and added a guardrail test that fails any
  `@keyframes` touching a paint/layout property. The 60s refresh now
  diff-guards: the whole `/api/home` render is skipped when the payload is
  unchanged and each dashboard widget skips its DOM write when its markup
  didn't change. The device-card grid is windowed (60 + "Show more"), all live
  table filters are debounced, the log viewer appends instead of rebuilding,
  English sessions skip the i18n tree-walk, and `transition: all` is gone.
- **Lighter, cached API.** The fleet-checks matrix (Checks page + checksrollup
  widget) is computed at most once per 15s behind a fingerprint-busted,
  scope-safe cache. The bulk read-only GET endpoints (`/api/home`,
  `/api/devices`, attention, alerts, fleet checks) are gzipped when the client
  supports it (~5–10× smaller); token-bearing endpoints stay uncompressed
  (BREACH).
- **Optional persistent API worker.** `cgi-bin/api_worker.py` (SCGI prefork)
  imports api.py once at service start and forks per request — same
  process-isolation semantics as CGI without the per-request Python startup +
  2 MB parse tax on every poll and heartbeat. Opt-in via
  `server/conf/remotepower-api.service` + the commented `scgi_pass` block
  in `server/conf/remotepower.conf`; fcgiwrap keeps working unchanged.
- **Accessibility floor, enforced by tests.** Modals announce as dialogs
  (`role="dialog" aria-modal`), filter/search inputs carry aria-labels, a
  visible `:focus-visible` keyboard ring everywhere, and a guardrail keeps
  icon-only buttons labeled.
- **Device deep links.** The URL becomes `#device/<id>` while a drawer is
  open — paste it in a ticket and it opens straight to that host.
- **Connectivity banner.** Network-level API failures show a persistent
  "can't reach the server" banner with a Retry button, auto-cleared by the
  next successful request.
- **Deploy snapshots + rollback.** `deploy-server.sh` backs up the deployed
  tree before every run (keeps 3) and gains `--rollback`; the SQLite store
  warns loudly when code is rolled back under a newer database; the
  diagnostics bundle includes a `quick_check` integrity verdict; recovery
  procedures documented in `docs/deployment.md`.
- **Heartbeat rate floor (optional).** `heartbeat_min_interval_s` (default
  0 = off) 429s heartbeats arriving faster than the floor so a looping agent
  can't bloat state.
- **Browser smoke tests** (`make e2e`, Playwright; self-skipping): boots the
  real stack (static + SCGI worker), logs in, walks the core pages, fails on
  any uncaught JS error — the first runtime UI tests in the project. Plus:
  real-GPG signed-update verification + log-rotation + malformed-check agent
  tests, a chrome-i18n coverage gate (29 page titles backfilled in 5
  languages), and a typography-scale guardrail.
- **Maintainer QoL.** `make bump VERSION=x.y.z` automates the mechanical
  version-bump surfaces; lint-tool versions pinned; vendored JS libraries
  inventoried in `static/vendor/VENDORED.md`.
- **Security review.** Dedicated v4.3.0 review
  (`docs/security-review-4.3.0.md`) covering the SCGI worker trust model,
  the per-endpoint gzip/BREACH reasoning, the cache scope guarantee, and the
  heartbeat floor; two Low hardenings found and fixed in-release (SCGI
  header-size cap, `0700` deploy-backup directory).
- **Download the archived audit log.** A button on the Audit page and
  `GET /api/audit-log/archive` stream the gzipped archive of evicted entries,
  so the full retained history is reachable without shell access.
- **Diagnostics bundle.** A button on Server status and `GET /api/diagnostics`
  download one JSON support bundle (versions, storage backend, fleet counts,
  recurring-job staleness, audit + hash-chain status, optional-dependency
  presence) with all secrets scrubbed server-side.
- **Slow-request visibility.** Any handler that runs past the slow threshold
  (`slow_handler_ms`, default 1500 ms) is recorded to a capped ring and shown
  on the Server status page — so "which endpoint is slow on the real fleet?" is
  answerable without external profiling. Only slow requests write; the
  heartbeat path is excluded.
- **Rate-limit coverage.** The unauthenticated, crypto-verifying auth callbacks
  (SAML ACS, OIDC callback, WebAuthn login-complete) now enforce a per-IP rate
  limit, matching the password-login / passkey-begin protection.
- **Staleness at a glance.** Cadence jobs (monitors, the KEV/EPSS refresh,
  scheduled scans) surface a last-ran timestamp + staleness badge on the
  Server status page.
- **Per-device offline alert delay.** A device's drawer Settings tab can set
  extra minutes of silence before that host raises a `device_offline` alert
  (0 = default, capped 24h) — for a box on a flaky link you don't want paging
  on every blip. `PATCH /api/devices/<id>/alert-delay`, also saved with the
  rest of the drawer settings.
- **Monitor flap dampening.** Each monitor can require N consecutive failed
  checks before raising `monitor_down` (the monitor add/edit modal's "Alert
  after consecutive failures"; default 1 = unchanged). A recovery before N
  resets the streak; the streak is capped so a long-down monitor stops
  re-writing config.
- **Metric & SNMP flap dampening.** Matching `metric_failures_before_alert`
  (default 1) and `snmp_failures_before_alert` (default 2 — making the existing
  snmp_unreachable threshold configurable) under Settings → Monitoring. A first
  metric breach (ok→warn/crit) is held until it persists N heartbeats; only the
  first breach is dampened — escalation, de-escalation and recovery fire
  immediately. Shared `_metric_damp_hold` covers both the agent and SNMP metric
  paths.
- **Clickable posture fixes.** Each warning in the security-posture self-check
  links straight to the Settings section that fixes it.
- **Consistent loading states.** Tables that flashed empty / showed a bare
  "Loading…" now use the shared skeleton-row treatment.
- **Regression guardrails (tests).** Diffs every `sysinfo` field the Checks
  engine / drawer read against every field the sanitizer persists (the
  `proc_names` / `mailq` / `pkg_scan_ts` bug-class); walks `WEBHOOK_EVENTS`
  against the alert-severity / channel-kind / title / front-end registries (the
  phantom-`service_recover` class); a **performance-regression** test that
  asserts single-device endpoints never reconstruct the whole devices store on
  SQLite; and **golden-file** tests locking the agent's apt/dnf/pacman, systemd
  and openssl text parsers. All fail in CI instead of in a later sweep.

- **AI/RAG knows the live fleet better.** The RAG index now includes each
  device's **open (unresolved) alerts** and **local TLS cert expiry**, plus a
  fleet-wide **open-alerts rollup** (worst-first) — so "what's wrong with the
  fleet / what's alerting on web01" is answered from real state, not a tool
  fan-out. (Watched-service up/down was already indexed.)
- **Fixed:** the custom-script *Assign to devices* picker — `.d-none` was being
  overridden by a later same-specificity `display` rule, so filtered rows
  stayed visible and the count / Select-all disagreed with the screen. The
  hide-utility is now authoritative.

See [docs/v4.3.0.md](docs/v4.3.0.md).

## v4.2.0 — "5ecur1tyM4tter5" — 2026-06-10

Security and integrations. Where v4.1.0 made the fleet *visible*, v4.2.0 makes it
**defensible** — harder sign-in, evidence you can trust, account-model guardrails,
and authorized vulnerability scanning of the hosts and sites you own. No breaking
changes; every new control is off until you turn it on.

- **Authorized vulnerability scanning (the "Pentest" page)** — scan the hosts and
  websites you own with industry tools, orchestrated and scheduled in one place.
  Targets are **authorization-gated**: enrolled hosts (target IP derived
  server-side), or domains you prove you own via an **ACME-style DNS-TXT /
  `.well-known`** check. A **passive** profile (nuclei / nikto / nmap) is safe any
  time; an **active** profile (OWASP ZAP / wapiti) is gated behind an explicit
  authorization attestation and a maintenance window; an on-host **lynis** audit
  runs through the agent. The toolchain runs on a hardened **scanner satellite**
  (no footprint on scanned hosts; pin one per network segment), with quick/full
  intensity, a vhost field, and cron **scheduled scans**.
- **Passkeys (WebAuthn)** — phishing-resistant, passwordless sign-in with a
  security key, phone or biometrics; refuses a cloned authenticator and **satisfies
  the MFA-required policy**. Optional `webauthn` dependency; hidden when absent.
- **SAML 2.0 SSO** — sign in through an enterprise IdP (Okta, Entra, OneLogin,
  Ping, ADFS); signed-assertion verification with replay protection, attribute →
  username / group → role mapping, first-login provisioning, alongside OIDC / LDAP
  / local. Optional `pysaml2` + `xmlsec1`; disabled when absent.
- **Tamper-evident audit log** — entries are hash-chained; a **Verify integrity**
  button reports the first break; clearing requires an admin re-prompt and writes
  an immutable pre-wipe archive.
- **Account guardrails** — enforce MFA (TOTP or passkey) per role, cap concurrent
  sessions per user, set a default API-key expiry, and a graded
  **security-posture self-check** on the Audit page.

See [docs/v4.2.0.md](docs/v4.2.0.md).

**Post-release sweep (2026-06-11, still v4.2.0):** a full-project bind / bughunt /
security / performance pass.

- *Security:* password login now demands a **passkey assertion** for accounts
  whose only second factor is a passkey (it previously minted a session from the
  password alone); `webauthn_enabled=false` actually disables the passkey
  ceremonies; the passkey login-begin endpoint is rate-limited and no longer
  reveals which usernames exist; scan-target file verification refuses loopback;
  audit-log writes are atomic under a file lock. Details in
  [docs/security.md](docs/security.md) (the per-release v4.2.0 review has since
  rotated out of the kept set).
- *Fixed:* `service_down` alerts now auto-resolve when the unit recovers (the
  recover hook listened for an event that was never fired — broken since v3.2.0);
  the mail-queue check and drawer pill work again (the heartbeat sanitizer
  dropped `mailq`); device cards show Memory % and mem/CPU sparklines again;
  the `scan` permission can be granted in the Roles editor; yearly/quarterly
  scan schedules survive past the cron search horizon; stuck "running" scans
  time out after 4h; a finished on-host lynis result is retried instead of lost
  on a flaky heartbeat; container alert excludes also cover restart alerts;
  failed-units attention cards get a routing-matrix toggle; passkey login
  honours Remember-me; six webhook events got proper titles.
- *New:* the Users table shows each account's **MFA method, auth source and
  disabled state**; scan schedules show **last run** and can be **paused /
  resumed**; the Audit page shows a persistent **chain-intact badge** (verified
  on load) and the posture self-check scores chain integrity; lynis scans
  surface the **0–100 hardening index**; "Pentest" and other chrome labels are
  translated in all five languages.
- *Performance:* the daily KEV/EPSS feed refresh runs detached (it could stall
  an unlucky request — worst case a heartbeat — for up to a minute, and
  stampede); the per-request offline sweep no longer rewrites the config file
  when nothing changed (it did so on **every** API request); per-heartbeat
  metrics writes touch one row instead of the whole fleet window (SQLite);
  the sidebar badges poll one bundled endpoint instead of three; the refresh
  bar animates on the compositor; the storage backend no longer forks a
  subprocess per process start.
- *Docs/UI polish:* MCP documentation corrected everywhere (18 tools: 14 read +
  4 guarded write); docs index rebuilt (17 missing topic docs listed); stale
  v2.x changelog leftovers removed from the Manual; internal hostnames scrubbed
  from examples; every variable-length panel capped at ~15 rows with internal
  scroll (command queue, SMART, firewall-rule tables, kanban columns, settings
  lists and more); remaining off-scale font sizes folded onto the canonical
  scale; the last emoji-as-icon instances replaced.

## v4.1.0 — "VisualMatters" — 2026-06-09

Surfaces what the fleet already knows and lets you shape how you see it. A new
**CheckMK-style per-host Checks** matrix (OK/WARN/CRIT/UNKNOWN from data already
collected), **custom checks** (process/port + agent-side file/job/log) assignable
to host/tag/group, more **active monitors** (DNS, ICMP latency/loss, HTTP
assertions, credential-less DB liveness, tag/group targeting), a **composable
65-widget dashboard** (resize/reorder/show-hide/reset/align/share), and a
**host-grouped alert inbox** that folds a host-down storm under its root cause.
Plus a TLS-1.2 floor across the satellite/agent/server hops. No breaking changes;
most features surface data the agent already reports. See
[docs/v4.1.0.md](docs/v4.1.0.md).

### Added
- **Checks page (CheckMK-style)** under Monitoring — every monitored signal on
  every host as OK/WARN/CRIT/UNKNOWN with output; sortable/filterable; per-check
  mute; **Hide muted** and **Hide unmonitored** on by default. Custom checks and
  custom-script results appear as rows.
- **Custom checks** assignable to host/tag/group/fleet: server-evaluated
  *process / port-open / port-closed*, and agent-evaluated *file-present /
  file-absent / job-freshness / log-error-rate* (read-only on-host evaluation,
  pushed in the heartbeat).
- **Monitors**: DNS resolution (+expected address), ICMP latency + packet-loss,
  HTTP status + latency-SLA assertions, credential-less DB liveness
  (PostgreSQL/MySQL/Redis), and tag/group target fan-out for ping/ICMP/TCP.
- **Composable dashboard**: a resizable widget grid with a 65-widget catalog
  (alphabetical add-dropdown), per-widget size, reorder, show/hide, reset, align,
  and shareable layout codes. New Upcoming, Tickets (open quick-ack + recently
  acknowledged), and actionable Alerts widgets; Ask-AI is now a toggleable widget.
- **Host-grouped alert inbox** with root-cause folding — symptom alerts fold
  under an open `device_offline`; group-level Ack-all / Resolve-all.

### Changed / Fixed
- World-exposed-port checks now respect Exposed-page mutes.
- The read-only-filesystem signal is now carried through sanitization (the check
  was previously inert).
- Agent mail-queue probe backs off 1h on a broken MTA to stop journal flooding.
- Dashboard computes its heavy widgets (checks roll-up, disk-fill ETA) only when
  displayed.

### Security
- **TLS 1.2 minimum** enforced on the satellite (both hops), the agent, and the
  server's outbound HTTPS.
- SSH command builder rejects host/user beginning with `-` (defense-in-depth).
- Independently scanned with **wapiti, nikto, nuclei, bandit and OWASP ZAP** —
  clean. See [docs/security.md](docs/security.md) and
  [docs/security-review-4.1.0.md](docs/security-review-4.1.0.md).

### Finalize sweep (bind it together + polish)
- **Bound more agent signals into the UI**: the server-side *process* custom
  check now works (the running-process list is persisted); the device drawer
  surfaces FD/conntrack pressure, clock sync, gateway reachability, mail-queue
  depth, the last OOM-killed process, and per-mount inode% + a read-only badge.
- **UI consistency**: every page table caps at ~15 rows then scrolls; uncapped
  rule/pattern lists now scroll; body/code text folded onto one type scale and a
  broken AI-markdown CSS block (a CSP-migration artifact) repaired.
- Doc accuracy pass (event/tool/widget/line counts corrected).

## v4.0.0 — 2026-06-07

The 4.0 release — a large, polished step that folds together everything since
v3.13. It scales out (optional **PostgreSQL** backend with automatic failover +
read replicas, **relay satellites** for segmented networks, **load-balanced
multi-node**), **encrypts every hop** including the agent→satellite relay,
surfaces far more of what the agent already collects (thermal, power/UPS, SSH-key
audit, endurance, predictive health, KEV/EPSS CVE ranking), adds a **macOS agent**
and a full set of install scripts, and ships a focused **security-hardening** pass
(independently scanned with wapiti, nikto, nuclei, bandit and OWASP ZAP — clean).
No breaking changes for a single-node flat-JSON install; most features surface
data the agent already reports. See [docs/v4.0.0.md](docs/v4.0.0.md).

### Added
- **Encrypt every hop, incl. satellites.** The relay satellite can now serve the
  **agent→satellite hop over HTTPS** (`RP_TLS_CERT`/`RP_TLS_KEY`; warns when
  plaintext), and agents can trust an internal CA without weakening verification
  (`RP_CA_BUNDLE`, keeps `CERT_REQUIRED`). New `docs/satellites.md` walks through
  adding a satellite + the per-hop TLS posture.
- **More install scripts + a deployment map.** `client/install-macos.sh`
  (launchd) joins the Linux/Windows installers; `packaging/satellite-setup.sh`
  installs the relay as a hardened systemd service (optional `--self-signed`).
  New `docs/deployment.md` indexes every component → its install script → when
  you need it (server, agents, satellites, app nodes, LB, Postgres/HA, PgBouncer).
- **Load-balanced multi-node support made real.** A `trust_proxy` setting takes
  the client IP from `X-Forwarded-For` behind a trusted proxy (so the audit log
  / IP allowlist / brute-force detection see the real client, not the balancer;
  off by default, un-spoofable on single-node). Ships an HAProxy LB example
  (`packaging/loadbalancer-haproxy.cfg.example`, + nginx upstream), a PgBouncer
  pooler setup (`packaging/pgbouncer-setup.sh`; the Postgres driver disables
  prepared statements so transaction pooling is safe), and docs/scaling.md now
  documents the shared-file-storage caveat and a transport-encryption matrix.
- **Postgres provisioning + HA scripts** under `packaging/`:
  `postgres-setup.sh` (role/DB/marker/DSN), `postgres-ha-primary.sh` (streaming-
  replication primary: wal settings, replication role + slot, scoped pg_hba),
  and `postgres-ha-standby.sh` (pg_basebackup-bootstrapped standby; guarded with
  `CONFIRM=yes` since it replaces the node's data dir).
- **PostgreSQL high availability — automatic failover + read replicas.** Point
  the DSN at multiple Postgres hosts (`…@pg-primary,pg-standby:5432/…`) and
  RemotePower adds `target_session_attrs=read-write` so libpq always lands on
  the writable primary; on a failover the next request reconnects (with retry
  across the promotion window) to the newly-promoted primary — no config change.
  Optionally set a read-replica DSN (`RP_PG_READ_DSN` or the marker's `dsn_read`)
  to serve pure reads from a replica while every write and locked read-modify-
  write stays on the primary (so replica lag can't cause a lost update). Off by
  default; HA status surfaces in *Settings → Advanced → Storage backend*. See
  [docs/scaling.md](docs/scaling.md).
- **Agentless SSH.** Hosts with **no agent** can now be polled for basic metrics
  and run the occasional command over SSH — set a device's *reachability* to SSH
  and its SSH user (device drawer), then *Poll over SSH*. Non-interactive
  (`BatchMode`, key-only, trust-on-first-use, timeout-bounded); each command is
  admin-only, allowlist-checked, and audited. Off by default; the private key
  (set in *Settings → Security → Agentless SSH*) is write-only. Shells out to the
  system `ssh` — no extra dependency.
- **Cloud inventory import (AWS EC2).** *Settings → Integrations → Cloud import*
  pulls EC2 instances into the fleet as **agentless** device records (tagged
  `cloud`/`aws`/region), read-only and idempotent (stable ids, re-run updates in
  place). AWS SigV4 request signing is implemented on stdlib (`hmac`) — verified
  against AWS's published `get-vanilla` test vector — so no SDK is needed. The
  IAM secret key is write-only (never returned by the API). Azure/GCP later.
- **macOS agent.** A minimal `client/remotepower-agent-mac.py` speaks the same
  enroll / heartbeat / command-queue contract as the Linux and Windows agents,
  so a Mac enrolls into the fleet with metrics (via `sysctl`/`system_profiler`
  + `psutil` when present), runs queued commands, reports per-interface
  bandwidth, and participates in the opt-in secrets scan — no separate
  server-side path. Stdlib-only.
- **Proxmox VM/CT lifecycle.** The Virtualization page can now **reboot, clone,
  and migrate** guests (on top of the existing start/shutdown/snapshots) via the
  Proxmox API. **Destructive, so gated three ways**: admin-only, a per-deployment
  *Settings → Proxmox → Allow lifecycle actions* opt-in (default off), and full
  audit; with 4-eyes approval on, each action waits for a second admin. A
  dry-run preview returns the planned action without touching Proxmox.
- **Tenant isolation (multi-tenancy).** An opt-in *Settings → Security →
  Multi-tenancy* switch partitions the fleet by tenant: a tenant's admins and
  operators see only their own devices, while a platform superadmin (an admin in
  the built-in *default* tenant) still sees everything. Enforced at the same
  chokepoints as RBAC scoping (device roster, per-device access, and every
  scope-filtered fleet view), with explicit cross-tenant isolation tests.
  **Off by default** — enabling it is a deliberate, reversible flip; device
  reassignment between tenants is superadmin-only.
- **Browser push notifications (Web Push).** Operators can get a desktop
  notification for high/critical alerts even when RemotePower isn't the active
  tab. *My Account → Browser notifications* subscribes this browser; an admin
  enables it fleet-wide in *Settings → Notifications*. Standards-based (VAPID +
  RFC 8188 aes128gcm), built on the `cryptography` library already in use — no
  third-party push service and no new dependency. Subscription endpoints are
  SSRF-guarded; the VAPID private key is never exposed by the API.
- **Store-and-forward log buffering.** If a log submission fails (server
  briefly unreachable), the agent now buffers those lines to a bounded on-disk
  outbox and folds them into the next successful submission instead of losing
  them — so log-alert rules have no blind spot across a short outage. Capped on
  lines + size; failsafe (any outbox error degrades to the old drop behaviour).
- **One-click CIS remediation (opt-in).** Failing baseline checks on the
  Compliance page now offer a **Fix** — reboot, install pending updates
  (distro-aware), or clear failed units. Every fix is queued through the
  existing command pipeline, so per-device quarantine, **4-eyes approval**
  (reboot), the queue cap, and audit logging all apply. It only runs on hosts
  where you've turned on *Automatic remediation* in device settings (default
  off); checks with no safe automatic fix (disk-full, swap) stay advisory.
- **Secrets-on-disk scanning (opt-in).** Agents can scan configured paths for
  exposed secrets (private keys, cloud keys, API tokens, passwords) and raise a
  `secret_exposed` alert when a new one appears. **Redacting by design** — the
  agent never transmits a secret's value, only its type, file:line, a masked
  preview, and a sha256 fingerprint; bounded hard on files/size/time. Off by
  default; enable + set scan paths in *Settings → Security*. Findings (with
  per-finding mute for false positives) show on the **Exposure** page. Linux and
  Windows agents both scan.
- **OpenTelemetry export (OTLP).** *Settings → Security → OpenTelemetry export*
  pushes rolled-up fleet gauges (devices online/offline, alerts by severity,
  health score) to an OTLP/HTTP collector — otel-collector, Grafana Alloy, any
  OTLP endpoint. Push piggybacks on heartbeats with a configurable min-interval
  gate; spec-correct OTLP/JSON (int64 fields as strings). SSRF-guarded; token
  write-only. Same numbers Prometheus scrapes at `/api/metrics`, pushed instead.
- **Agent release channels.** Devices can be put on a **Stable** or **Beta**
  channel (device drawer → Release channel). When a beta agent binary is
  published alongside the stable one, beta-channel devices are served it by
  `/api/agent/version` + `/api/agent/download`; otherwise beta resolves to
  stable, so the feature is inert for existing fleets and the default is always
  stable.
- **Network bandwidth (per interface).** The agent now reports per-interface
  throughput — in/out **bytes/sec** (diffed across heartbeats) plus lifetime
  totals — surfaced as a "Network bandwidth" card in the device drawer, busiest
  interface first. Linux and Windows agents both collect it. (Per-process
  byte accounting isn't portable without root-only tooling, so "top talkers"
  here is at interface granularity.)
- **Home Assistant bridge.** A read-only `GET /api/ha?token=…` endpoint (gated
  by the existing status token) returns flat JSON shaped for a Home Assistant
  REST sensor — `state` (ok/warning/critical) plus online/offline and alert
  counts as scalar attributes, and a `problem` on/off field for a binary sensor.
  One-way by design: status only, no control surface.
- **SIEM event streaming.** *Settings → Security → SIEM event streaming* streams
  every fleet event and alert to **Splunk HEC**, **Elasticsearch**, **Grafana
  Loki**, or a raw JSON endpoint — each with its native envelope and auth scheme
  (`Splunk`/`ApiKey`/`Bearer`). SSRF-guarded like outbound webhooks; the token is
  write-only (never returned by the API). Distinct from audit-log forwarding.
  Includes a "Send test event" button.
- **Process-level alerting.** *Settings → Notifications → Process thresholds*
  lets you watch a process by name and fire `process_alert` (edge-triggered,
  with a `process_recovered` follow-up) when it crosses a CPU or memory
  percentage. Evaluated server-side against each heartbeat's top processes;
  routed through the full alert/webhook/dashboard matrix like any other event.
- **Keyboard-first navigation.** The `g`-prefix jump shortcuts (`g h` Home,
  `g d` Devices, `g a` Audit, `g l` Logs, `g c` CVE, `g m` Monitoring, `g r`
  Reports, `g t` Trends, `g v` Server status, `g s` Settings) and the `?` cheat
  sheet now render from one shared list, so every shortcut is documented and
  the two can't drift (the old sheet showed 4 of 8). `/` · `Ctrl-K` palette and
  `Esc` to close unchanged.
- **White-label branding (MSP).** *Settings → Advanced → Branding* lets an admin
  set the **in-app product name** and a **default accent colour** shown to
  everyone — for resellers. Applied live from `GET /api/me`; users can still
  override the accent in My Account. (The login-page logo image is unchanged.)
- **Themes & accents.** *My Account → Appearance* adds a **theme** choice
  (Dark / Light / **Auto** — follows your OS light/dark setting and switches live)
  and six **accent colours** (blue, emerald, violet, amber, rose, cyan). Per
  browser; the header toggle now cycles Dark → Light → Auto.
- **Cost allocation / chargeback.** The **Power** page now estimates monthly
  energy **cost per group and per tag** (each host's measured draw × your
  price/kWh), for showback/chargeback. Scope-filtered; `GET /api/fleet/chargeback`
  returns the rate-independent watt/kWh aggregation and the UI applies your rate.
- **Package hold / pin.** *Patches → Install software* gains **Hold** / **Unhold**
  buttons to pin packages at their current version so a fleet upgrade-all skips
  them — self-detecting across `apt-mark hold`, `dnf`/`yum versionlock`, and
  `zypper` locks. Same target model (device / group / tag / all) and `packages`
  permission as install/uninstall (`POST /api/packages/hold` · `/unhold`).
- **Compliance evidence pack.** *Reports → Evidence pack* downloads a single JSON
  document bundling the current fleet posture report (health, patches, CVEs, CIS
  compliance, uptime), the 90-day compliance-baseline trend, and an audit-log
  excerpt for the period — the artifact auditors ask for, from data RemotePower
  already holds. Admin-only (`GET /api/report/evidence`), and generating one is
  itself audit-logged.
- **SLO error budgets on the uptime report.** The Reports → *Uptime (SLA)* table
  now shows each device's **error budget** — the downtime its SLA target allows
  over the window, how much is **left** (red when exhausted), and **% used** —
  plus a fleet-wide budget in the summary. Derived from the existing uptime data;
  no agent or schema change.
- **Multi-tenancy — foundation (P1).** A tenant registry (`GET/POST /api/tenants`,
  `PUT/DELETE /api/tenants/<id>`), user→tenant assignment
  (`POST /api/tenants/<id>/users`, `tenant_id` on the user record), and the
  caller's tenant in `GET /api/me`. This is **deliberately behaviour-neutral** —
  everyone is in the built-in `default` tenant and nothing is partitioned or
  filtered by tenant yet (the existing RBAC scopes still govern access). The
  enforcing half (per-tenant storage isolation) is intentionally left for a
  reviewed pass. *(Admin/API only in this release; no UI yet.)*
- **SCIM 2.0 user provisioning.** An identity provider (Okta, Azure AD, OneLogin,
  …) can now **create and — critically — deactivate** users automatically via
  `/api/scim/v2/Users`. Deactivation (SCIM `active:false`, `PATCH`, or `DELETE`)
  sets the user disabled, which `verify_token` and login enforce — so an
  offboarded user's access **and live sessions** drop immediately. This closes
  the gap OIDC/LDAP JIT-provisioning leaves (it only ever *creates* on first
  login). Enable + mint a bearer token under *Settings → Authentication → SCIM*;
  provisioned users start as **viewer**; the last enabled admin can't be
  deactivated.
- **Metric history with a time range (24h / 7d / 30d / 90d).** The device **Trend**
  modal now has a range selector and shows real point-in-time history instead of
  just the last ~2 hours. On the **SQLite** or **PostgreSQL** backend, samples are
  stored in an append-only `metric_samples` time-series (one cheap row per sample,
  not a per-device blob rewritten every heartbeat), queried by range and
  **downsampled** so 24-hour and 30-day views stay readable; the x-axis switches
  to dates for long windows. Retention is configurable under *Settings → Advanced
  → Data retention* (**Metric samples (days)**, default 30) and pruned by the
  daily sweep. On the JSON backend the charts show the recent rolling window only
  (this is one of the concrete reasons to switch to a database backend).
- **PostgreSQL storage backend.** A third storage backend (after JSON files and
  SQLite) behind the same `load`/`save`/`LockedUpdate`/`DeviceTxn` abstraction —
  for fleets/operators who want a real RDBMS (concurrency, replication/HA, central
  backups). Same logical schema as SQLite (`devices`/`entity`/`listrow`/`kv`/
  `file_meta`, with the decomposition logic shared so the two DB backends never
  drift); per-file read-modify-write serialised with a Postgres transaction-scoped
  **advisory lock**; the heartbeat fast path is a single-row `INSERT … ON CONFLICT
  DO UPDATE`. Selected via `RP_STORAGE_BACKEND=postgres` or a `storage_backend.json`
  marker (`{"backend":"postgres","dsn":"…"}`); `psycopg` is imported lazily so
  non-Postgres deployments never need it. **Switch from *Settings → Advanced →
  Storage backend*** — pick *PostgreSQL*, paste a connection string, Preview, then
  Migrate & switch: it copies every record into Postgres, verifies the round-trip,
  and only then flips the active backend (the DSN is saved to `storage_backend.json`
  so the server reconnects on restart). Fully reversible. *(A persistent
  app-server/connection-pool layer for true horizontal scale is the next phase —
  the backend itself is done.)*
- **Per-account sidebar favorites.** Star any entry in the sidebar's collapsible
  groups (hover-reveal star, yellow when active, keyboard accessible) and a copy
  pins under the **"Main"** label. Favorites are stored on the user record
  (`GET /api/me` returns them, `POST /api/favorites` saves them), so they follow
  you across browsers and devices; `localStorage` is kept only as a
  fast-first-paint cache and offline/signed-out fallback. Works for real pages
  and the section-jump rows alike.
- **Per-container stale-image badge.** The device-drawer **Containers** table
  shows an **update** badge when a container's running image differs from the
  latest registry digest — the same join the fleet **Image Updates** page uses
  (shared `_image_stale` primitive, so the two never disagree). Locally-built
  and accepted/ignored images are never flagged.
- **Fleet thermal roll-up — "Hottest hosts".** A new **Thermal** page (next to
  Storage) with one row per host showing its hottest sensor (CPU / chipset /
  SMART disk / GPU), sorted hottest-first, flagged ≥75 °C amber / ≥85 °C red.
  Backed by a read-only `GET /api/fleet/thermal` aggregation over the
  `hardware.json` temps the agent already reports. No agent or schema change.
- **CVE prioritization with KEV + EPSS.** The CVEs page ranks by real-world risk:
  a daily refresh joins the CISA **Known-Exploited Vulnerabilities** catalog and
  **FIRST EPSS** scores onto findings (red **KEV** badge, **EPSS %**, a KEV column
  on the device list, KEV-first sort). Feeds fetch through the SSRF-safe opener
  and degrade to plain CVSS if unreachable.
- **Active session management.** *My Account → Active sessions* lists every
  browser/device signed in as you (IP, device, last-active, "this session"), with
  per-session revoke and "sign out all other sessions". `GET /api/me/sessions` +
  `DELETE /api/me/sessions/<id>`; the raw token never leaves the server.
- **Saved & shareable views (Devices).** Save the current Devices filter set as a
  named view (per-account, via `ui_prefs`) and share it by URL (`#devices?view=`).
- **SSD / NVMe endurance.** The drawer SMART table gains a **Wear** column (used %
  + projected end-of-life), amber ≥80 % / red ≥90 %.
- **GPU monitoring.** `nvidia-smi` / `rocm-smi` hosts report a **GPUs** drawer card
  (util / memory / temp / power); GPU temps feed the Thermal roll-up.
- **Local certificate-file inventory.** The agent parses x509 files under common
  cert dirs (`openssl x509`); a **Local certificate files** drawer card shows
  expiry, coloured like the TLS page.
- **Local account audit.** A **Local accounts** drawer card from passwd + shadow
  age + sudo membership, flagged-first (extra UID 0, empty/stale passwords,
  locked). No password hashes leave the host.
- **Power scheduling.** The Schedule page adds **Suspend** and **Wake (WoL)**
  actions alongside shut down / reboot, one-shot or recurring; scheduling a
  power-down on a host with no MAC warns that a scheduled wake won't be possible.
- **Predictive maintenance ("Predictive health" page).** Per-disk SMART counters
  are snapshotted daily (6-month history); a least-squares trend projects an ETA
  when reallocated/pending sectors grow or SSD wear climbs toward 100%. Combines
  the reactive SMART verdict with the predictive trend. The page also lists
  **frequently-restarting hosts** (≥3 returns-to-online in 7 days, from uptime
  history) with their last boot reason.
- **Power & energy ("Power" page).** New agent UPS probe (NUT `upsc` / apcupsd)
  → status, battery, load, runtime, watts. Drawer **UPS / power** card + a fleet
  Power page with a client-side cost/kWh → estimated energy cost.
- **SSH key audit ("SSH keys" page).** Surfaces the fleet's `authorized_keys`
  with OpenSSH SHA256 fingerprints, weak-type flags, and a reuse count.
- **Container log tailing.** A per-container **logs** button in the drawer fetches
  recent `docker`/`podman` logs on demand (`GET /api/devices/<id>/output`).
- **Global omnisearch.** The command palette now also searches open alerts and
  CVE findings (caches warmed on open), not just pages/devices/scripts.
- **Custom report builder.** *Reports → Custom reports*: pick sections
  (devices/health/attention/patches/cve/sla/compliance), choose JSON/CSV,
  download, and optionally schedule each saved report to its own recipients
  (`/api/report/definitions`, `?sections=` filter on `/api/report/fleet`).
- **Container images in SBOMs.** Host CycloneDX/SPDX SBOMs now also list running
  container images as components (`pkg:docker/<image>@<digest|tag>`).
- **Fleet drift-enforcement policy.** Set apply/correct-on-drift by tag or group
  on the Drift page (`/api/drift-policies`); the per-device flag still wins.
- **Alerts for the posture signals.** New edge-triggered events: `disk_predict_fail`
  (predicted disk failure with ETA), `ups_on_battery`/`ups_on_line` (auto-resolving),
  `cert_file_expiring` (≤21d, opt-in — see *Fixed*), `rogue_uid0` (unexpected
  root-equivalent account) — wired into the alert inbox, channels, and activity feed.
- **Metrics push (Prometheus).** Settings → Integrations can periodically POST the
  `/api/metrics` exposition to a Pushgateway / remote target (`metrics_push`
  config, SSRF-safe, interval-gated). Off by default.
- **Richer per-device metric charts.** The device **Trend** modal now draws full
  time-series **area-line charts** for CPU / memory / swap / disk with a
  **timestamped x-axis** (start / middle / end), 0–50–100% gridlines, and
  per-metric **now / min / avg / max** stats — plus a combined **"All metrics"**
  overlay for at-a-glance correlation. Replaces the old latest-value-only
  sparkbars. Pure SVG, CSP-safe.
- **SSO groundwork.** Factored shared `_provision_or_promote_user` /
  `_mint_session` helpers so every SSO path provisions users and mints sessions
  by identical rules (OIDC now routes through them); this is the prerequisite for
  the upcoming SAML support. No behaviour change for existing logins.
- **Windows agent — posture parity (pass 1).** The standalone Windows agent now
  also reports **listening ports** (→ Exposure page + port audit), a **Windows
  Event Log tail** (System/Application criticals/errors/warnings → the Logs page /
  device journal), and **local users** (Get-LocalUser + Administrators membership
  → the account-audit card), in the same shapes the Linux agent sends, on top of
  the existing Windows Update pending (→ Patches). No server changes — the
  heartbeat ingest is OS-agnostic. (Watched-service status, signed self-update and
  packaging are still pending for full parity.)
- **GitOps — drift config from Git.** *Settings → Integrations → GitOps* can pull
  a JSON manifest from a raw Git URL and reconcile your **drift profiles**
  (watched-config-file sets) and their tag/group assignments to match it — so your
  watched-config policy lives in version control. It only manages watched-file
  lists and assignments (never command execution or file-content pushes), only
  touches profiles it created (hand-made ones are left alone), and host
  enforcement still follows each device's existing apply/enforce opt-in.
  `GET/PUT /api/gitops` + `POST /api/gitops/sync?dry=1`; off by default; fetched
  through the SSRF-safe fetcher with a size cap; admin-only; every sync is audited.
- **Customizable dashboard.** A **Customize** button on the Home page lets each
  user show/hide and reorder the dashboard widgets (Fleet health, heat map,
  Needs attention + Recent activity, Fleet roster, Quick links). The layout is
  saved on your account (`ui_prefs.dashboard`) and reuses the existing cards —
  no new data path. New widgets shipped later appear by default without
  resetting a saved layout.
- **Interface language (i18n).** *My Account → Language* switches the UI between
  **English, 中文 (Mandarin), हिन्दी (Hindi), Español, and العربية (Arabic, RTL)**.
  The choice is saved on your user record (`GET /api/me` returns `lang`, `POST
  /api/me/lang` sets it) and synced across devices, with a `localStorage`
  fast-paint cache. UI-only and build-free: a self-hosted `i18n.js` translates
  the navigation chrome by source text, so untranslated strings fall back to
  English and new UI keeps working with no i18n wiring. Arabic switches the
  document to `dir="rtl"`.
- **Change approval now covers the risky actions, not just Run command.** With
  *Settings → Security → Change approval* enabled, reboot, shutdown, package
  update/upgrade, agent uninstall, and container start/stop/restart are also
  parked for a second admin (Confirmations page) instead of executing
  immediately — reusing the existing maker-checker store. Off by default.

### Security
- **Session tokens are hashed at rest.** `tokens.json` is now keyed by the
  SHA-256 of the bearer token, never the token itself — a leaked file yields no
  usable session. Lookups hash the presented token; sessions minted before the
  switch keep resolving until they expire (no forced re-login on upgrade).
  Closes CodeQL "clear-text storage of sensitive information."
- **OIDC token-exchange errors no longer log the response body.** The error body
  from the IdP can echo a client secret or partial token; only the HTTP status +
  OAuth `error` code are logged now. Closes CodeQL "clear-text logging."
- **Anchored webhook-host matching.** `_auto_detect_format` matches a webhook
  URL's host on the apex or a real dotted subdomain, so `discord.com` no longer
  matches `discord.com.attacker.tld`. Closes CodeQL "incomplete URL substring
  sanitization."
- **Cloud import (AWS) goes through the SSRF-safe path.** The EC2 region — which
  is interpolated into the request host — is now validated against the AWS region
  shape, and the fetch uses the anti-rebinding, no-redirect opener.
- **Ansible runs trust host keys on first use** (`accept-new` + a per-run
  known_hosts) instead of disabling host-key checking outright, matching the
  agentless-SSH posture.
- **Independent security scan.** This release was scanned with **wapiti**,
  **nikto**, **nuclei**, **bandit** and **OWASP ZAP** — no findings. Details in
  [docs/security.md](docs/security.md).

### Changed
- **Home "Fleet roster · 7-day status" is now capped at 15 hosts, worst-first.**
  Sorts by most-offline (currently-offline first, then most down-days in the
  7-day stripe) and shows a "+N more" pointer to the Devices page — so the
  widget surfaces what needs attention instead of an unbounded list.
- **No page floods on an extremely large fleet.** The Devices card grid caps at
  300 cards with a "narrow your filter" prompt, and the Thermal / Storage / SSH-key
  / Power roll-up tables cap at 200 rows (sorted, with a "+N more" footer) — the
  page stays responsive on thousand-host fleets. Filtered/paginated views are
  unchanged.

### Added
- **Real themes (not just an accent).** *My Account → Appearance* now offers a
  full set of cohesive themes — Midnight, Tokyo Night, Catppuccin, Dracula, Nord,
  Gruvbox, Rosé Pine, Oceanic, Solarized Dark, plus the light themes Daylight,
  Paper, Solarized Light and Nord Light — each a complete palette (background,
  surface, text, borders, status colours), picked from a swatch grid. "Follow
  system" tracks your OS light/dark. The accent presets still apply on top of any
  theme. Stored per browser.
- **Interface translation now covers the operational UI, not just the chrome.**
  The 5-language UI translation (English, 中文, हिन्दी, Español, العربية — Arabic
  RTL) gained a real engine: it translates **text nodes** (so inline-markup text,
  labels and dynamically-rendered status/empty-state messages all translate) and
  **page subtitles** with their markup preserved, and a `MutationObserver`
  re-translates content rendered after load. It now also translates **attributes**
  (input placeholders, hover tooltips, aria-labels), and never translates the app
  name (the `RemotePower` brand is excluded). The catalog grew to ~1,450 entries —
  page titles + subtitles, status/empty/toast strings, and the controls: buttons,
  section headings, table column headers, field labels and placeholders. The
  in-app Documentation pages and code samples stay in English by design; anything
  uncatalogued still falls back to English gracefully.
- **"Report an issue" button (Help → Documentation, and About).** Opens a
  prefilled GitHub bug report with the app version, browser/environment, current
  page, and recently-captured (scrubbed) client errors — no credentials, no fleet
  data. Public-safe; targets the issue form so it works with blank issues off.
- **Trend button for SNMP device metrics.** Agentless/SNMP hosts now have the
  same **Trend** chart button as agent hosts on the Device metrics page (SNMP
  CPU/RAM/disk already flow into the metric history sink).
- **Richer demo seed.** `seed-demo-data.py` now populates the newest pages:
  board/CPU/GPU temperatures (Thermal, incl. a hot + a critical host), UPS +
  GPU power draw (Power / chargeback, one host on battery), authorized_keys for
  the SSH-key audit (incl. a reused key and a weak `ssh-dss` key), and a
  CISA-KEV / FIRST-EPSS overlay so the CVEs page ranks by real-world risk
  offline. (Also fixed the demo CVE findings to the canonical on-disk shape so
  they actually render.)

### Removed
- **Public/internal ROADMAP files** (`docs/ROADMAP*`) removed from the repo.

### Fixed
- **Agent self-update log shows the right target version.** `/api/agent/version`
  now reads the version string straight from the served binary instead of a
  separately-stored config value that could go stale — so the agent's upgrade log
  no longer prints a confusing mismatched target (e.g. "v3.14.0 → v3.12.0" when it
  was really updating to 4.0.0). The update decision was always hash-based and
  correct; only the displayed version was wrong.
- **No more `utcfromtimestamp` DeprecationWarning in the nginx error log.** The
  calendar/ICS export used `datetime.utcfromtimestamp()`, deprecated in Python
  3.12+, which FastCGI surfaced as a warning on every `/api/calendar.ics` (and
  scheduled-event) request. Switched to timezone-aware `fromtimestamp(…, UTC)`
  (identical output); a guardrail test keeps the deprecated calls out.
- **Every device dropdown is now a searchable `device-combo`.** Five device
  pickers had no type-to-search: *Add agentless device → Connected to (upstream)*,
  the OpenSCAP-scan and one-time-install *Device* targets, and the network-map
  editor's per-node *uplink* and *dependencies* selects. They're now searchable
  combos (the multi-select dependency picker gets the searchable filter, since a
  single-value combo can't apply). The target value-pickers are searchable for
  group/tag too.
- **Stuck "mount stalled/missing" alerts now auto-resolve.** `mount_issue` had no
  recovery, so a stalled NFS/SMB mount alert sat in the inbox forever even after
  the mount came back. A new edge-triggered `mount_recovered` clears the open
  alert for that exact path when the agent reports it healthy again.
- **Host-scoped exposure mutes no longer show as "(empty)".** A mute that
  silenced a whole host (`device_id` only) rendered as a blank "(empty)" row and
  couldn't be removed, because the list only showed process/proto/port — it now
  shows the device and the Remove button works.
- **SNMP devices now have metric trends/graphs.** SNMP-polled (agentless) hosts
  recorded no metric history, so the Trends/graphs were empty for them. The
  poller now appends CPU/memory/busiest-disk to the same time-series the agent
  path uses, so SNMP hosts trend like agent hosts.
- **CVE page: KEV feed status is now visible.** When KEV showed 0 there was no
  way to tell "feed not loaded / errored" from "genuinely no known-exploited
  CVEs". The page now shows the loaded KEV count + last update (or the feed
  error), with a button to refresh the CISA KEV / FIRST EPSS feeds on demand.
- **Button polish.** Icons sat flush against their labels on some buttons; added
  a small gap (icon-only buttons unchanged), and gave the bare Save-branding /
  Save-metrics-push buttons breathing room.
- **RBAC: CMDB now honours device scope (closes a cross-scope gap).** A role
  scoped to a subset of the fleet (by group / tag / site) could previously read
  the CMDB asset list for **all** devices and edit the asset metadata and
  documentation of devices **outside** its scope. The CMDB list is now filtered
  to in-scope assets, and the metadata/documentation write endpoints enforce the
  same per-device scope guard the per-device GET already used. (Credential
  reveal/write were already admin-only — admins are all-scope — so they were
  never affected.) The fleet **posture report** remains a read-only, no-secrets
  aggregate visible to any authenticated user; tightening it to the caller's
  scope is tracked as a follow-up.
- **`cert_file_expiring` no longer floods every host, and is off by default.**
  The agent now inventories only your own **service** certificates (Let's Encrypt
  live, nginx/apache TLS, `/etc/ssl/*.crt`) and never the system **CA trust
  bundle** (`/etc/ssl/certs`, `/etc/pki/ca-trust`, …) — which was hundreds of
  certs per host. The alert is now **opt-in** (*Settings → Security → "Alert on
  expiring local certificate files"*, default off), the server coalesces to **one
  alert per host** (soonest cert + a count), filters CA-bundle paths even from
  older agents, and the Alerts inbox now shows **which** cert and **how many days**
  remain instead of a bare event name. Existing flooded alerts won't auto-clear —
  resolve/clear them once after upgrading.
- **Favorites no longer "reset" on a normal refresh.** The service-worker cache
  is now versioned to `remotepower-shell-v3.14.0` (and `?v=` bumped), so a plain
  F5 loads the current front-end instead of a stale cached shell.
- **UI consistency sweep.** The Reports page's *Scheduled email delivery* and
  *Custom reports* cards no longer touch (both now use the page's standard
  `dash-card mb-16` spacing). Monospace text renders in one font fleet-wide —
  ~47 rules that used the bare OS-default `monospace` now use the shared
  `--font-mono` stack — and a few off-scale font sizes (12.5/11.5/9px) were
  folded onto the canonical type scale.

## v3.13.0 — 2026-06-05

A **bind-it-together** sweep (round four): surface the host signals the agent
already collects but the UI never showed, cap every panel so it scrolls instead
of growing unbounded, and add a round of performance and security hardening. No
breaking changes, no new dependencies — most of this renders data that was
already being reported and stored.

### Added
- **Access — recent logins (device drawer).** A per-user table of recent logins
  and distinct source IPs (`auth.recent_logins`), the data the *new login
  source* alert fires off. Previously had no UI.
- **Scheduled jobs / timers (device drawer).** A failed-first table of every
  systemd timer, what it activates, and its state.
- **Pools / arrays (device drawer).** This host's own ZFS / mdadm / btrfs
  storage & RAID health (state, capacity, scrub) — previously fleet-page only.
- **Listening ports gain Address + Scope.** The drawer Ports card now shows the
  bind address and a world / LAN / local badge per socket (matching the fleet
  Exposure page).
- **Firewall ruleset summary.** The Firewall card shows the active backend, rule
  count and fingerprint (the *firewall changed* drift baseline).
- **Brute-force lockout badge** on device cards, plus **Disk** and **Swap**
  pressure pills in the drawer.
- **Named drift profiles.** Reusable, named sets of watched config files,
  managed from the **Drift** page (create / edit / delete) and assignable to a
  device, tag, or group (`GET/POST /api/drift/profiles`,
  `PUT/DELETE /api/drift/profiles/<id>`, `POST /api/drift/assign`). Resolution
  precedence: an explicit per-device file list (set in the device drawer) wins,
  then an assigned profile (device > tag > group), then the global default.
  The device drift detail now also **explains** where a host's watched list
  comes from (override / profile+scope / default).
- **Network mounts trended.** NFS/SMB/CIFS shares now flow into the daily
  metrics history, so each filesystem — including network shares — gets its own
  line on the **Trends** chart and is covered by disk-fill **forecasting**.
  (Also fixes a pre-existing bug where the per-device Trends endpoint read the
  history store with the wrong shape and returned nothing.)
- **Fleet host-config: collect-all + export.** Two actions on the **Drift**
  page: **Collect all host configs** queues the "send current config" command to
  every agent device (`POST /api/host-config/collect-all`, admin), and **Export
  all host configs** downloads one JSON bundle of every device's desired +
  current config and drift (`GET /api/host-config/export`) — for audit, backup,
  and diffing.
- **Targeted AI buttons across the UI.** One-click, context-scoped AI help
  wherever a question naturally arises: **Software center** (is this package
  version safe / any known CVEs), **Drift detail** (explain what changed and
  whether it's risky), **Exposure** world-reachable rows (should this be exposed
  / how to lock it down), **Forecast** rows (why is this filling / what to clean
  up), **Compliance** failing controls (how to remediate), **failed systemd
  units** and **unhealthy containers** in the device drawer (diagnose), plus an
  **"Ask about my fleet"** omnibox on the Home dashboard (RAG over fleet state).
  All reuse the existing AI provider; nothing is sent unless you click.
- **Software center.** A new card on the **Software policy** page lists every
  package installed across the fleet, aggregated to one row per package with the
  versions in use and how many hosts run each (a "mixed" badge flags packages
  running more than one version). Type to filter; **click a row to expand it and
  see exactly which hosts run which version**. `GET /api/inventory/catalog`.
- **Fleet Query "has package" now shows the installed version.** A
  `has_package` filter result includes the matched package name **and version**
  in a new column, so you don't need a second lookup to answer "which version".
- **Tasks "Linked device" is a type-to-search filterbox.** Matches the device
  combobox used elsewhere, instead of a long native dropdown.
- **Auto-patch policies mirror into the calendar + maintenance windows.**
  Creating (or editing) an auto-patch policy now also creates a linked recurring
  **calendar event** (so the schedule is visible) and a recurring **maintenance
  window** (so alerts are suppressed during the patch run / reboot), both kept in
  sync with the policy and removed when it's deleted or disabled.
- **Controller backup & restore.** A new **full disaster-recovery backup**
  (`GET /api/backup/download`) streams a tar.gz of the entire data directory —
  *including* the encrypted credentials vault and integration secrets — and a
  matching **restore** (`POST /api/backup/restore`) rebuilds the controller from
  it, taking a safety snapshot of the current data first and extracting with
  strict path validation. Admin-only, in **Settings → Advanced → Backup &
  restore** alongside the existing redacted (shareable) ZIP export.

### Changed
- **Risk score decoupled from fleet health, and respects ignores/mutes.** The
  per-asset Risk score no longer blends into or caps the fleet-health score —
  they're independent lenses now (health = Needs-Attention signals; risk =
  security posture). Risk also no longer counts findings you've accepted:
  **ignored CVEs** (the CVE ignore list) and **muted exposure** (Exposure-page
  mutes, including host-level mutes) are excluded from the score and its factor
  breakdown.
- **Every box fits — project-wide.** Beyond the drawer cards, *every* table card
  in the app now caps at ~15 rows and scrolls internally with a sticky header
  (one central `.table-card` rule), so no page — Exposure included, which was not
  wired to the 15/page pagination — grows into kilometers of rows. Paginated
  tables still show 15/page; their pager sits outside the capped card.
- **Network mounts collected.** The metrics collector now uses
  `disk_partitions(all=True)` — previously `all=False` silently omitted *every*
  network filesystem, so NFS/SMB/CIFS mounts never appeared. Network shares are
  now reported (with a `net` badge + their server) in the device drawer and the
  Monitor page, feed per-mount disk-fill alerting, and a hung share is shown as
  *stalled* (probed with a killable timeout so it can't block the heartbeat).
- **Faster loads.** Version-busted static assets are served
  `Cache-Control: immutable, max-age=1y` (no more per-load 304 revalidations);
  front-end scripts load `defer`; `_compute_fleet_risk()` is file-cached for 10s
  so `/api/home` and `/api/risk` share the work.
- **app.js split further.** ~1,800 more lines moved out of the monolithic
  `app.js` into focused classic-script modules (`app-hostconfig.js`,
  `app-compliance.js`, `app-integrations.js`), cutting its parse cost. A new
  load-order test (`tests/test_jsload.py`, V8 via py_mini_racer) guards against a
  function/var being referenced at load time after a future move.
- **More boxes capped.** The device-drawer **Containers** table, the **Drift
  profiles** panel, and the failed-units / mount-issue chip rows now cap and
  scroll instead of growing unbounded (shared `.scroll-cap` / `.scroll-cap-sm`
  utilities).
- **Typography consolidated.** A sweep aligned a set of drifted font sizes onto
  the canonical body (14px) / dense (13px) / caption (12px) scale — the three
  `.hint` variants, several `.5px` oddballs, a card header that read smaller than
  its body, and the drawer device subtitle — so body copy is consistent
  page-to-page.

### Security
- **External SAST + DAST scan: no exploitable findings.** The release was
  scanned with Bandit (SAST) and OWASP ZAP / Nikto / Nuclei / Wapiti / WhatWeb
  (DAST); see [docs/security-review-3.13.0.md](docs/security-review-3.13.0.md).
  Two LOW items found in the new v3.13.0 surface were fixed: a
  decompression-bomb guard on **backup restore** (cap uncompressed size + member
  count), and **RBAC isolation for `/api/ai/chat`** (the fleet context is now
  scope-filtered to the caller and RAG retrieval is admin-only). Two
  non-cryptographic SHA-1 fingerprint hashes were annotated `usedforsecurity=False`.
- **Sandboxed SCAP reports.** Agent-supplied OpenSCAP HTML is served under a
  self-contained sandboxed CSP (`default-src 'none'; … sandbox;`) +
  `X-Frame-Options: DENY`, so stored XSS can't reach an operator's session even
  if the upstream CSP is loosened.
- **OIDC id_token claim checks.** The callback now rejects expired tokens (120s
  skew), issuer mismatches, and wrong-audience tokens, on top of the existing
  state/nonce + back-channel trust.
- **Syslog audit-forward DNS-rebinding fix.** The SIEM forwarder resolves its
  target once to a literal IP, classifies that IP, and connects to the literal —
  closing the rebinding window the HTTP path already guarded.
- **SSRF classifier hardened against IPv6-embedded IPv4.** The shared per-IP
  guard now unwraps v4-mapped (`::ffff:`), 6to4 (`2002::/16`) and NAT64
  (`64:ff9b::/96`) addresses and re-classifies the inner IPv4, and additionally
  rejects multicast and reserved ranges — closing a path that could smuggle
  `169.254.169.254` past the v6 checks. RFC1918 LAN targets stay allowed.

### Fixed
- **Container "Restarts" column in the device drawer.** The per-container table
  now shows `restart_count` (amber, or red at ≥5) — the crash-loop signal the
  `container_restart_loop` alert already fires on but the only container table
  never displayed.
- **MCP-confirmation activity items now open the right page.** Clicking a
  `mcp_confirmation_expired` dashboard item (or the Settings "Confirmations"
  link) fell through to the device drawer instead of the Confirmations page —
  the navigation switch was missing the case.
- **Firewall fingerprint no longer flaps on traffic.** The nftables/ufw
  ruleset hash now zeroes volatile `counter packets … bytes …` statements before
  hashing (as the iptables path already did), so `firewall_changed` only fires on
  a real rule change, not on every heartbeat.
- **Image-updates loading row spans all columns** (`colspan` was one short).
- **`upgrade_and_reboot` now actually reboots.** Queued `exec:` commands ran with
  a fixed 300 s timeout, so a package upgrade taking longer than 5 minutes was
  killed *before* the trailing `systemctl reboot` — the host upgraded but never
  rebooted. Upgrade commands now get a 30-minute timeout, and the reboot has
  fallbacks (`systemctl reboot || /sbin/reboot || reboot`).
- **White form controls themed everywhere.** Bare `<input>` / `<select>` /
  `<textarea>` that were missing the `.form-input` class (the Calendar new-event
  form, the Tasks "Linked device" field, and others) rendered browser-white. A
  global base rule now themes every native control to match the dark UI
  (checkboxes/radios keep their accent styling); fields inside a labelled group
  fill the row. The generic `.btn` class (the Software-policy "Add rule" button)
  had no CSS at all and is now styled like the secondary button. The base rule's
  `:not()` chain is wrapped in `:where()` so it keeps element-level specificity
  and never outranks `.form-input` — otherwise it clobbered `width:100%` and
  misaligned the SMTP / audit-forward / LDAP / retention settings forms.
- **Network mounts in the disk-fill forecast.** NFS/SMB/CIFS shares are included
  in the Forecast projection (they were never excluded; this adds a `net` label)
  once they have a few days of daily history.
- **Password-form accessibility.** Service-secret password fields (SMTP / LDAP /
  Proxmox / AI / audit-token) are wrapped in form elements with no username,
  which the browser flags as an a11y issue — a visually-hidden username field is
  now injected into each so the console warning is gone (no autofill of
  service-account secrets is introduced). The Change-password modal's username
  field is now a visually-hidden text field instead of `type=hidden`.
- **Single-field settings rows stack label-above-input.** Audit-forwarding,
  retention and scheduled-backup rows put the label *beside* the box; they now
  match every other form (label on top, full-width box below).
- **Host Configuration modal keeps a stable size.** Switching its sections
  (Repos / Netplan / … / Cron) no longer resizes and re-centres the window — the
  active section scrolls inside a fixed-height modal, same as the CMDB modal.
- **Host firewall detection (round two).** Beyond scanning all tables + both
  backends + firewalld, the probe now (a) **falls back to `iptables -S`** when
  `iptables-save` is present but errors — the earlier change regressed such hosts
  to "unknown" — taking the max rule count across every readable variant, and
  (b) `_which` now searches `/usr/sbin` and `/sbin`, since a minimal systemd
  service PATH omits them and firewall tools live there (another "unknown" cause).
- **CMDB Hardware panel was empty.** The panel expected `cpu` (model),
  `mem_total_mb`, `disk_total_gb` and `kernel`, but the agent never reported them
  (only `cpu_count`). The agent now sends all four (CPU model from
  `/proc/cpuinfo`, total RAM, total **local** disk deduped by block device so
  btrfs subvolumes don't multi-count, and the kernel release), and the server
  passes them through. CPU-model parsing matches the exact `model name` field so
  the numeric `model :` line isn't shown instead.
- Purely numeric device tags now highlight correctly when selected.
- `escHtml` now also escapes single quotes (matches the other escape helpers).
- The update banner's release-notes link is scheme-validated before render.
- Two latent clip bugs (host-config dump, patch-command history) where content
  was cut off with no scrollbar.

See **[docs/v3.13.0.md](docs/v3.13.0.md)**.

## v3.12.0 — unreleased (dev)

An optional **SQLite storage backend** alongside the default flat-JSON store,
switchable in **Settings → Advanced → Storage backend**. For large fleets with
frequent writes, flat JSON's whole-file rewrites (notably `devices.json` on
every heartbeat) become a bottleneck; SQLite (WAL mode, stdlib `sqlite3`, zero
new dependencies) stores hot data row-per-entity so a device update is a single
row write.

### Added
- **Relay satellites (minimal).** A new standalone forwarder
  (`client/remotepower-satellite.py`, stdlib only) lets agents in a segmented
  network reach the server through it (`agent → satellite → server`). Each
  satellite authenticates with its own token (`X-RP-Satellite`), minted/listed/
  revoked under **Settings → Integrations → Relay satellites**
  (`/api/satellites`); the server records each relay's last-seen/IP, and an
  unknown token is rejected. The agent's own device token still authenticates
  end-to-end, so the satellite is a second, independent layer.
- **Per-asset risk score.** A new **Risk** page (and `GET /api/risk`) computes a
  0–100 risk score for every monitored asset on demand, purely from data already
  collected — open CVEs, world-reachable services, software-policy violations,
  pending updates, contract/license/warranty expiry, mount issues, reboot-
  pending, offline — plus **host-firewall state** (no firewall active / no
  rules), **storage & RAID health** (degraded/faulted pools), **disk SMART
  failures**, **outdated running kernel**, and **failed system services**. Every
  point is attributed to a named factor. The score also blends into fleet
  health, so a high-risk asset can't read as perfectly healthy.
- **Searchable dropdowns.** Any `<select>` that grows past 15 options (a device
  picker on a large fleet, say) automatically gets a small **type-to-filter**
  input above it that hides non-matching options — applied non-invasively to
  page and modal selects (the select keeps its value and listeners). Opt out
  with `data-nofilter`.
- **Large-fleet UI scalability.** Pages that previously rendered an unfiltered
  list now have a **filter box**: Risk, Storage health, Exposure, Software-policy
  violations, Compose stacks, Proxmox LXC, Rollouts, Automation, Compliance and
  MCP Confirmations (via a reusable `filterRows` row/card filter). The **Command
  Queue** gains a filter box plus paging (pending cards 25 at a time, the
  dispatch log 50 at a time) so a large offline fleet no longer renders thousands
  of rows at once.
- **Granular RBAC roles.** Custom roles can now grant any of **10 fine-grained
  action permissions** instead of the old three: `command`, `script`, `reboot`,
  `shutdown`, `patch`, `packages`, `containers`, `services`, `ssh`, `mitigate`.
  The relevant handlers are re-gated accordingly (e.g. container/compose actions
  and watched-service edits move from admin-only to the `containers` / `services`
  permission). The legacy `exec` / `upgrade` umbrellas on existing roles are
  still accepted and transparently expand to their granular members, so no role
  breaks. Roles can also be **scoped to one or more sites** now (`sites` joins
  all/groups/tags). The role editor shows all ten permissions with tooltips and
  a Sites scope option.
- **MCP API keys from the UI.** The New API Key dialog now offers the **MCP**
  role (AI-assistant keys limited to the allow-listed MCP actions) — previously
  only the backend accepted it.
- **Host firewall posture.** The agent now probes every backend it finds —
  **nftables, iptables, ufw, ebtables** — reporting for each whether the tool is
  installed, whether it has an active ruleset, a rough rule count, and (where
  cheap) the default policy. It surfaces in the device drawer under
  **Audit → Firewall** (a per-backend table) and **feeds the risk score**: a host
  with no active firewall is flagged `firewall_off`, and an iptables backend that
  defaults to `ACCEPT` with no rules gets a smaller "effectively open" penalty.
  Older agents that only ship the drift fingerprint fall back to the previous
  behaviour. (`sysinfo.firewall` alongside the existing `firewall_fp`.)
- **Mount issues are now visible.** Mount-point problems (stalled NFS/SMB,
  fstab-vs-mount mismatches) were collected, alerted and risk-scored but never
  shown in the UI. They now appear in the device drawer's **Audit → System Info**
  (a red banner listing each stalled/missing mount) and on **Home → Needs
  Attention** (`mount` items — stalled = critical, missing = warning), so they
  also dent the fleet-health score.
- **Mute all exposure from a host.** The Exposure page's per-socket mute gains a
  **Mute host** button (and the muted-services list a device-scoped rule):
  one click silences new-port / world-exposed alerts for *every* service on an
  accepted appliance or jump host, instead of muting process-by-process.
- **Mount-point monitoring.** The agent compares `/etc/fstab` against live
  mounts and probes mounted network shares (NFS/SMB) for responsiveness — a new
  `mount_issue` event fires (edge-triggered) when an auto fstab entry isn't
  mounted (*missing*) or a network mount hangs (*stalled*, e.g. a dead NFS
  server). The stall probe runs `stat` in a killable subprocess so it can't
  block the heartbeat. Wired through every event registry (high severity).
- **CMDB enrichment.** Each asset's editor gains a **Hardware** tab (CPU, cores,
  RAM, disk total, per-mount disks, network interfaces — read-only, surfaced
  from the agent's heartbeat) and a **Contracts & contacts** tab with editable
  **support contracts**, **customer contacts** (L1/L2/L3 escalation) and
  **licenses** lists (`contracts` / `contacts` / `licenses` on the CMDB record).
  Contract and license expiry dates feed the existing lifecycle-expiry attention
  items, so they alert like warranty/support expiry already did.
- **API key expiry (UI).** The create-key dialog now takes an optional expiry
  date; the keys table shows it (and flags expired/soon keys). The auth path
  already rejected expired keys — this surfaces and sets the date.
- **Webcheck content match.** HTTP monitors gain an optional *body must contain /
  must NOT contain «text»* check (does a GET and inspects the body) — catches a
  `200 OK` that's actually an error page.
- **iCal import/export.** The shared Calendar exports to `.ics`
  (`GET /api/calendar.ics`) and imports `.ics` files
  (`POST /api/calendar/import`) — subscribe in any calendar app or bulk-load
  events.
- **CMDB environment.** Assets get an `environment` field (test / dev / staging /
  prod), shown as a colour-coded badge in the asset list and settable in the
  asset editor.
- **My Account.** A top-right account menu (avatar → My Account / Sign out) and a
  dedicated **My Account** page that consolidates per-user settings: profile
  picture (uploaded, downscaled in-browser, stored under `DATA_DIR/avatars/`),
  a read-only view of your role + granted permissions, **2FA** and **default SSH
  username** (both moved here from Settings → Security), and **My acknowledged
  alerts**. New `GET /api/me`, `GET/POST/DELETE /api/me/avatar`,
  `GET /api/users/<u>/avatar`, and `?mine=1` on the alerts list.
- **Acknowledge → ticket webhook.** Each webhook destination gains a *“Also fire
  on alert ACK”* checkbox. When an operator acknowledges an alert, the flagged
  destinations receive the **full alert record** (id, severity, device, the
  original event payload, who/when acked) — independent of the per-event /
  severity filters — so a `generic` / GitHub-issue / PagerDuty destination can
  open a ticket the moment a human takes ownership. (`webhook_urls[].on_ack`.)
- **Data retention & DB maintenance.** **Settings → Advanced → Data retention &
  maintenance** adds per-log age caps (command history, fleet events, webhook
  log, monitor history, resolved alerts — days; `0` keeps everything) that prune
  automatically once a day, plus a **Run maintenance now** button
  (`POST /api/db-maintenance`, admin) that purges immediately and, under SQLite,
  VACUUMs + checkpoints + runs an integrity check. Open alerts are never purged —
  only resolved ones past their age limit. (`history_retention_days`,
  `fleet_events_retention_days`, `webhook_log_retention_days`,
  `monitor_history_retention_days`, `alerts_retention_days`.)
- **Agent log rotation.** The agent now writes `/var/log/remotepower-agent.log`
  through a self-rotating handler (5 MB × 5 backups, ~25 MB cap) — no
  logrotate/cron drop-in required, falling back to a null handler when not
  running as root.
- **Pluggable storage backend.** A new `storage.py` sits behind the existing
  `load()` / `save()` / `_locked_update()` helpers, so all ~1000 call sites are
  backend-agnostic. Cold files are stored as JSON blobs; hot, high-cardinality
  files are decomposed (`devices`, `alerts`, `cmd_output`, `metrics` →
  row-per-key; `history`, `fleet_events`, `metrics_history` → append tables).
  Concurrency uses WAL + `BEGIN IMMEDIATE`; the `devices` last_seen monotonic
  guard is preserved.
- **In-app migration.** `Settings → Advanced` gains a Storage-backend card with
  a current-backend indicator, a **Preview** (dry-run), and a **Migrate &
  switch** button. New admin endpoints `GET /api/storage-backend/status` and
  `POST /api/storage-backend/migrate` run the migration in-process: snapshot →
  migrate → verify round-trip → flip the active backend (only on success).
- **Migration CLI.** `tools/migrate_storage.py --to sqlite|json`
  (`--dry-run`, `--verify-only`, `--no-snapshot`, `--no-flip`), sharing the same
  core as the endpoint.
- **Listening-port & firewall audit toggle.** Settings → Security →
  *Listening-port & firewall audit* (`port_audit_enabled`, **off by default**) —
  one opt-in switch that gates the `new_port_detected`, `port_exposed_world` and
  `firewall_changed` alerts fleet-wide. These are noisy on Docker hosts (where
  `docker-proxy` publishes every container port to `0.0.0.0`), so they no longer
  fire unless an operator turns the audit on. The baselines keep updating while
  off (so enabling later doesn't fire a catch-up burst) and the Exposure page
  still lists every socket regardless.
- **Surgical exposure mutes.** A per-process **Mute** button on the Exposure
  table (and `POST /api/exposure/mute`, config `exposure_mutes`) silences
  `new_port_detected` / `port_exposed_world` for a known-noisy process (e.g.
  `docker-proxy`) without disabling the whole audit, and resolves matching open
  alerts in the same click. Muted rows are flagged and can be un-muted.
- **Exposure discovery banner.** When alerting is off but world-reachable
  services exist, the Exposure page shows a banner linking to the toggle — the
  always-on visibility leads back to the opt-in alerting.
- **Auto-resolve on suppression.** Turning the audit off resolves the open
  `new_port_detected` / `port_exposed_world` / `firewall_changed` backlog in one
  action (clears the inbox instead of leaving stale alerts).
- **SQLite maintenance.** Hourly WAL checkpoint + weekly `VACUUM` /
  `integrity_check` (due-gated, no-op under JSON); DB size + last integrity
  verdict surfaced on Server Status.
- **`db_integrity_failed` alert.** A failed weekly `integrity_check` now raises a
  **critical** fleet alert (webhook + inbox + activity feed) instead of only
  logging — a corrupt database pages you. Wired through every event registry.
- **Managed mute list.** Settings → Security → Listening-port & firewall audit
  gains a full list of exposure mutes with Add (process / proto / port) and
  Remove, complementing the per-row Mute button on the Exposure page.
- **Dual-backend CI.** `make test-sqlite` (and `make test-both`, now the `check`
  gate) runs the whole suite under `RP_STORAGE_BACKEND=sqlite`. The flat-JSON
  storage-internals tests (flock / `.bak` / `.tmp` / mode-0600) are skipped via
  `@_skip_sqlite`; everything else is green on both backends.
- `fleet_events.json` is kept a cold blob (it is polymorphic in the codebase —
  written dict-wrapped, read bare-list by `_compute_attention`), so it
  round-trips any shape verbatim under SQLite.
- **RAG reindex works under SQLite.** The index rebuild trigger used source-file
  mtimes, which don't exist under SQLite. New `backend_mtime()` + a per-file
  `file_meta` write-time table (touched by every writer) give a backend-agnostic
  change signal; real on-disk docs (`.md`) still use their filesystem mtime.

### Changed
- **Heartbeat is now a single-row write under SQLite.** `handle_heartbeat`
  updates one device row via `BEGIN IMMEDIATE` (`_DeviceUpdate` /
  `storage.DeviceTxn`) instead of reconstructing every device — O(1) read+write
  on the hot path. JSON behaviour is unchanged.
- **Device deletion now purges posture/security baselines.** `handle_device_delete`
  cleans up `port_baseline`, `posture_state`, `ssh_key_baseline`, `brute_force`,
  `software_violations`, `cve_findings`, `snmp_data`, `hardware`, `av_status`
  too — a deleted device no longer ghosts, and a same-id re-enroll can't inherit
  a stale baseline that suppresses its first legitimate alert.
- **Migration catch-up pass.** The migrate flow re-copies any source file a live
  heartbeat wrote during the copy before flipping the active backend, shrinking
  the write-loss window (prefer a low-traffic window for a busy fleet).
- Backup/export, the scheduled tarball backup, and the self-status disk report
  now go through the backend seam (`backend_iter_files()` / `backend_exists()` /
  consistent SQLite online-backup snapshot) instead of globbing/`stat()`-ing the
  `.json` files directly, so they're complete and safe under either backend.
- `save()` / `_locked_update()` gain a `clamp_last_seen` flag (used by the
  migration and test aging helpers to write timestamps faithfully).
- **UI polish.** The world-exposure banner now lays the message and an *Open
  Settings* button out as a clean flex row (the button no longer interrupts the
  sentence mid-flow). The Software-policy *Policy rules* and *Current violations*
  cards get inner padding so their text and the *Add rule* button no longer butt
  against the card border. The settings-search empty hint sits a touch lower so
  it isn't tucked under the search field (and moved off an inline style for CSP).
  The **Channel-routing matrix** and **Per-event toggles** tables now scroll
  inside a fixed-height box with a **sticky header row**, so the Kind / Needs
  Attention / Recent Activity / Alerts / Webhook columns stay labelled however
  far you scroll. The **CMDB asset editor** dialog is now a fixed height, so
  switching tabs (Properties / Documentation / Credentials / Hardware /
  Contracts & contacts / SNMP) no longer resizes and re-centres the window — the
  active tab scrolls internally instead.
- Avatar upload now downscales via a `data:` URL (FileReader) instead of a
  `blob:` URL, so it no longer trips the `img-src 'self' data:` CSP. The avatar
  is also **fetched with the auth token and rendered as a `data:` URL** rather
  than a bare `<img src="/api/me/avatar">` — the endpoint is token-gated, so the
  plain image request was returning 401; it now loads (with an initials
  fallback).

### Notes
- Flat JSON remains the default; existing installs are unaffected until an
  operator opts in. The switch is fully reversible.
- On a network filesystem (NFS/CIFS) SQLite WAL is unsafe; the backend detects
  this and falls back to a rollback journal. A local disk is recommended.

## v3.11.0 — unreleased (dev)

A fleet-posture batch: seven features that turn already-collected (or
cheaply-collectable) agent data into first-class security and operational
signals. No new daemons, no new dependencies — flat JSON + CGI + the
existing heartbeat path throughout.

### Added
- **Attack-surface / Exposure monitor.** The agent already enumerated
  listening sockets but threw away each socket's bind address; it now keeps
  it and classifies an exposure **scope** (`local` / `lan` / `world`). A new
  `port_exposed_world` event fires, edge-triggered, when a service first
  binds to a world-reachable address. New fleet **Exposure** view with a
  World/LAN/Local filter.
- **Fleet Software Policy.** Rules (`banned` / `required` / `min_version`,
  optionally tag-scoped) evaluated against the installed-package inventory
  every host already pushes. Violations are persisted and
  `software_policy_violation` fires edge-triggered. New policy editor +
  violations table.
- **Storage / RAID health.** New agent probe for ZFS / mdadm / btrfs pool
  state, capacity and last-scrub. `storage_degraded` / `storage_recovered`
  (with auto-resolve) and `scrub_overdue` events. New **Storage** view.
- **Access watch.** Recent successful logins and their source IPs are
  collected; `login_new_source` fires on a first-seen source address.
  (Brute-force bursts keep using `brute_force_detected`.)
- **Host firewall drift.** A stable fingerprint of the active ufw/nftables/
  iptables ruleset rides the heartbeat; `firewall_changed` fires when it
  moves from baseline.
- **Scheduled-job failure lens.** Systemd timers are inventoried and
  `timer_failed` fires when a timer's backing job enters a failed state.
- **Scheduled posture digest.** An opt-in daily/weekly email summarising
  offline hosts, pending updates, critical CVEs, policy violations and
  degraded storage, sent over the existing SMTP path. "Send test now" in
  Settings.

### Notes
All seven new events are wired through every registry (alert severity,
channel-routing matrix, dashboard activity feed, friendly titles) and the
event-set guardrail tests; detections are edge-triggered with per-device
state so a steady-state condition does not re-alert each heartbeat.

## Unreleased

### Reliability — false-offline (device flap) hardening
A device that was heartbeating normally could be briefly flagged **offline**.
Root cause: only the heartbeat path does an atomic, lock-protected update of
`devices.json` (the v2.1.2 fix); the ~two dozen other handlers that write
`devices.json` do a non-atomic load→modify→save, so one holding a stale
snapshot could roll a device's `last_seen` *backward*, and the offline sweep
would then fire on the stale value. Three guards:
- **Monotonic `last_seen` on save** — `save()` now refuses to let any device's
  `last_seen` move backward relative to the on-disk value (merge-max under the
  rename lock), so a stale writer can't clobber a heartbeat's update. The
  prevented regression is logged with the calling handler so the offender is
  identifiable.
- **Fresh confirm-read** — before declaring a device offline, the sweep
  re-reads its `last_seen` straight from disk (bypassing the per-request cache),
  turning a stale-snapshot flap into a no-op.
- **ICMP fallback** — if `last_seen` still looks stale, the server pings the
  device; a reachable host **suppresses** the false `device_offline` (a
  non-reachable result is inconclusive — ICMP is often filtered — and falls
  through to alerting as before).

## v3.10.0 — unreleased (dev)

A third bind-it-together and security sweep on top of v3.9.0: agent data that
was collected but stuck at zero now flows through, two real SSRF /
secret-disclosure gaps are closed, and a couple of alert-label bugs are fixed.
No new headline features.

### Security
- **Container image-registry SSRF closed.** The image-update scanner was the one
  outbound path that didn't use the connect-time SSRF guard. It followed 3xx
  redirects, re-resolved DNS between the pre-flight check and the actual fetch
  (a rebinding TOCTOU), and — worst — fetched the bearer-token *realm* URL from
  the registry's `Www-Authenticate` header (attacker-controllable) with no check
  at all, which could send configured registry credentials to an arbitrary host.
  Every fetch — manifest **and** token realm — now routes through the SSRF-safe
  opener (connected-peer re-validation, redirects refused), the realm is
  pre-flighted against the IP classifier and forced to HTTPS. See
  `docs/security-review-3.10.0.md`.
- **`GET /api/config` secret-scrub backstop.** The endpoint redacted known
  secrets by name (a denylist), so the AI-provider `api_key` and the
  per-registry credentials map leaked in cleartext to any authenticated viewer
  or read-only MCP key. A recursive pass now strips any secret-named field at
  any nesting depth before responding, while preserving every `*_set` /
  `*_from_env` indicator and non-secret `*_id` field; only `ai_configured` /
  `registry_credentials_set` booleans are surfaced.
- **TCP uptime monitor + Healthchecks.io ping hardened.** The `tcp` monitor had
  no IP-class SSRF check (the `http` branch did), so it could be used as a blind
  internal port scanner with a boolean oracle, including cloud-metadata
  reachability probing. It now resolves and classifies the target like the http
  path and re-checks the connected peer (anti-rebinding). The Healthchecks.io
  watchdog ping moved off a bare `urlopen` onto the SSRF-safe, no-redirect opener.

### Bind it together
- **Container restart tracking now works fleet-wide.** Docker/Podman containers
  reported `restart_count`, `started_at` and `uptime_seconds` hardcoded to `0`,
  which left the `container_restarting` alert permanently dead and the drawer's
  container-age column blank on every non-Kubernetes host. The agent now fills
  them from a single batched `docker inspect` per heartbeat.
- **ClamAV last-scan time** (parsed from the clamscan SCAN SUMMARY) and
  **per-interface MAC addresses** now show in the device drawer — both were
  already collected and stored server-side but never displayed.

### Fixes
- **Config-drift alert titles** read a payload field (`files`) that neither
  drift event ever sends, so every one rendered "Config drift on host: ?
  file(s)". They now name the file that changed (file-integrity drift) or the
  number of sections that drifted (host-config drift).
- **Devices table view:** the *Hostname* column showed a sort arrow but never
  reordered (its sort key was missing from the column getter); it sorts now.

## v3.9.0 — unreleased (dev)

A second bind-it-together and hardening sweep on top of v3.8.0: more dropped
agent data wired into the UI, a couple of correctness bugs in the alerting and
patch-verification paths fixed, an SSRF gap in the uptime monitor closed, and a
round of front-end polish (sortable tables, Lucide icons, accessibility).

### Security
- **HTTP uptime-monitor SSRF closed.** The `http`/`https` monitor check used a
  literal string-prefix blocklist and a bare `urllib` fetch — so an IPv6
  loopback (`[::1]`), an integer/octal/hex-encoded IPv4, or a hostname that
  rebinds to a metadata/loopback address after the pre-flight check could all
  slip through. The check now runs through the same connect-time SSRF guard the
  webhook/audit/OIDC back-channels use: the *connected* peer IP is re-classified
  (anti-rebinding), redirects are refused, and the shared IP classifier replaces
  the brittle string list. RFC1918 LAN targets stay allowed by design; cloud
  metadata / link-local is always blocked. See `docs/security-review-3.9.0.md`.
- **Inbound-webhook alert links are scheme-validated.** Links attached to an
  inbound alert now pass through the same `http(s)`-only validator the operator
  quick-links and CVE reference-links use, so a `javascript:`/`file:` URL can't
  be stored even if a future renderer makes them clickable.

### Fixes
- **Post-upgrade verification no longer false-alarms or hangs.** The badge
  flipped to *stalled* ("didn't take") whenever the pending count failed to
  strictly drop after an hour — which falsely fired on hosts that had **nothing
  to patch** when a fleet-wide upgrade ran, and on **offline** hosts whose
  command was still undelivered. It also got **stuck on "verifying…" forever**
  when the host had no baseline patch count at queue time (the count was
  unknown), since the before/after comparison could never run. All three now
  resolve sensibly ("nothing to verify" / "still pending"), and the patch report
  gained a **Re-check** button that forces a fresh package scan instead of
  waiting for the periodic one. Tooltips now explain what the verification is.
- **Metric thresholds: a stray `return` could skip disk alerting.** When a
  device's CPU load was easing back through the recovery band, the CPU branch
  returned out of the whole threshold function — so that heartbeat skipped the
  per-mount disk checks *and* dropped the freshly-computed metric state. It now
  just declines to transition the CPU level and carries on.
- **TLS-expiry alerts had the wrong severity and title.** The severity mapper
  and alert title read a `days` field the event never carries (it sends
  `days_left`), so every TLS-expiry alert landed as `high` and titled
  "expires in ?d". Severity now scales with the real days-remaining.

### Bind it together
- **CPU-load history.** Load average was collected on every heartbeat but had no
  time series anywhere. The Trends page now plots a **CPU load (saturation %)**
  series (load ÷ cores) alongside memory/swap/disk.
- **Swap on the metrics sparkline.** The per-device metrics modal tracked
  CPU/memory/disk; swap was recorded by the daily sampler but missing from the
  high-resolution sparkline. It now has its own track.
- **rkhunter last-run time** is shown on the AV-posture pill (the agent reported
  it; the UI never displayed it) — answers "when did this host actually scan?".
- **systemd alias resolution** is surfaced: when you watch `mysql.service` but
  the host runs `mariadb.service`, the Services table now shows the canonical
  unit the agent resolved. The field was being dropped by the heartbeat
  sanitiser.
- **Livepatch state** (e.g. `checked`, `check-failed`) is shown on the kernel
  pill when a patch hasn't been applied — the field that explains *why*.

### Polish
- **Three tables gained their missing sort wiring** — the Log Alert per-device
  rules, the Log Alert fleet-wide rules, and the Maintenance suppression log.
  Their headers advertised sortable columns but clicks did nothing.
- **Typographic glyphs replaced with Lucide SVG icons** on the prominent action
  buttons (Run / Fetch current / Download / Clear) and the toast notifications,
  matching the project's inline-SVG icon convention.
- **Accessibility:** icon-only close buttons (device drawer, console modals,
  mobile menu) now carry an `aria-label`.
- **Command Queue completeness.** ACME renew/revoke/issue actions are now
  recorded in the command history, so they appear in the queue's "recently
  dispatched" log like every other queued command (they used to wait for the
  agent invisibly). Added a **Clear all pending** button (clears every device's
  queue at once, `DELETE /api/command-queue`) and a **Clear log** button for the
  dispatched-command history, alongside the existing per-command cancel and
  per-device clear.
- **One-click container image update.** The Image Updates page gained an
  **Update** button on stale, compose-managed rows — it runs `docker compose
  pull` then `up -d` on each affected host (a new compose `update` action) to
  fetch the new image and recreate the container. The agent now also captures
  each container's **compose working directory** (so the server knows where to
  run it) and **recovers the real image name when `docker ps` reports a bare,
  untagged image ID** (which happens right after a pull that hasn't recreated
  the container — the image previously showed as `sha256:…` and "Local"). Image
  Updates rows now show the **container name** so they're identifiable either
  way. Still operator-initiated — RemotePower never pulls or restarts on its own.

## v3.8.0 — unreleased (dev)

A hardening, bind-it-together, and polish sweep — no new headline features,
but a security pass over v3.5–v3.7, dropped agent data wired into the UI, more
AI-investigate coverage, and consistency fixes.

### Security
- **Change approval no longer bypasses the exec allowlist/denylist.** Parking a
  command for maker-checker approval now runs the same `_check_exec_allowlist`
  the immediate path does — at submit and again at approval — so enabling the
  governance control can't smuggle a command the device would otherwise reject.
- **Ansible runner inventory hardening.** The host alias is sanitised (the
  device name could contain spaces/newlines that injected host-vars), and the
  SSH password is passed via a 0600 JSON extra-vars file instead of the INI —
  closing an injection vector. The runner now also **skips quarantined devices**.
- **2FA recovery-code consumption is now atomic** (under a file lock), so two
  concurrent logins can't both spend the same one-time code.
- **Audit-log forwarding SSRF hardening** — the HTTP forwarder refuses to follow
  redirects (no bounce to a metadata/loopback address) and the syslog target is
  now SSRF-checked like the HTTP one.
- **DNS-rebinding SSRF closed across every outbound back-channel.** The webhook
  sender, audit→SIEM forwarder, and OIDC discovery/token-exchange fetches now
  re-validate the *actual* peer IP at connect time (not just the pre-flight DNS
  lookup), so a hostname that resolves to a public address for the check but an
  internal/metadata address for the fetch is caught and refused. Normal TLS
  verification (SNI + cert chain) is unaffected. The audit forwarder also now
  pins the verified TLS context it previously computed and dropped. See
  `docs/security-review-3.8.0.md`.
- **Maker-checker approval re-checks device state.** Approving a parked
  exec/reboot/script confirmation now rejects the action if the device was
  deleted or quarantined while the request sat in the queue (no orphaned queue
  entry; a quarantined host can't be hit via the approval path).
- **Agent opt-in mandatory signed updates.** Touch
  `/etc/remotepower/require-signed-updates` and the agent refuses to install any
  self-update unless a `release.pub` is pinned *and* the download carries a
  valid signature — flipping the default fail-open window to fail-closed.
- **SFTP upload** rejects oversized files by encoded length *before* base64
  decoding.

### Fixes
- Delete actions for sites / auto-patch / backup jobs / playbooks coerce their
  opaque IDs to strings (an all-digit token could otherwise be mangled).
- RAID member disks now render in the device drawer (the agent emits them as a
  space-separated string; the UI assumed an array and silently dropped them).
- The **Proxmox per-guest backup table** is now sortable (every column), matching
  the other planning tables — it was the one inline table that shipped without
  sort wiring.

### Bind it together
- **Boot reason** is now stored and shown — the agent already reported *why* a
  host last restarted (e.g. `self-update`), but the field was being dropped.
  Surfaced in the device drawer's System Info tab.
- **Failed systemd units** are now persisted and surfaced. The agent has always
  reported them, but the heartbeat sanitiser silently dropped the field — which
  had dead-ended the Fleet Query "failed units" filter, the daily "what changed"
  metrics diff, and the `cis-failed` compliance check (it could never fail).
  They now appear in the device drawer, drive a new Needs-Attention item, and
  feed the fleet health score.
- **Logged-in users** (active login sessions) are likewise now stored and shown
  as a pill in the device drawer's System Info tab — useful "who's on the box
  right now" context that was being dropped.
- Removed an orphaned `_renderHostHealth()` renderer (superseded by the live
  device drawer; it also carried a stray non-SVG glyph).

### AI investigate (broadened)
- Added diagnose/remediate playbooks for many more Needs-Attention kinds, so the
  Investigate button now covers most of what the dashboard surfaces: **malware/AV
  posture**, **stale agent version**, **end-of-life OS**, **hardware health
  (SMART/kernel)**, **stale/missing backup**, **new SSH authorized key**, **new
  listening port**, **agent integrity (hash mismatch)**, **log-pattern
  alerts**, and **failed systemd units** — joining the existing
  disk/memory/swap/cpu/patches/cve/drift/service-down/container/reboot/
  brute-force playbooks (~20 kinds total). Each ships a tailored AI prompt; the
  JS kind/label registries stay in sync.

### Polish
- Audit-forwarding and change-approval settings moved to **Settings → Security**
  (they were under Advanced). The **Confirmations** page is renamed from "MCP
  Confirmations" since it now also handles change-approval requests.
- `docs/terraform-api.md` and the security-headers nginx template confirmed
  current (`Referrer-Policy` + `Permissions-Policy` already present).

## v3.7.0 — unreleased (dev)

Security/governance gaps + two infrastructure features.

### 2FA recovery codes
- Enabling TOTP generates 10 one-time recovery codes (shown once); a recovery
  code is accepted at login in place of the authenticator and consumed on use.
  Regenerate (password-gated) from Settings → Security. Stored hashed.
  `POST /api/totp/recovery-codes`.

### Audit-log forwarding (SIEM / syslog)
- Mirror every audit entry to an external destination — HTTP JSON POST
  (SSRF-guarded, optional bearer) or RFC 5424 syslog over UDP/TCP. Best-effort,
  non-blocking. Settings → Security, with a **Send test entry** button.
  `POST /api/audit/forward-test`.

### Credential rotation reminders
- Per-credential **Rotate every N days** policy in the CMDB vault; credentials
  past their policy are flagged on the dashboard (NA kind `cred_rotation`) and
  badged in the asset view. Anchors on the last password change.

### Desired-state enforcement
- New **Correct on drift** host-config option: re-apply the desired config only
  when the host drifts (vs the existing always-on *Enforce on host*). Audited.

### Change approval (maker-checker)
- Optional second-admin approval for arbitrary command runs (Settings →
  Security). A pending change is approved by a *different* admin on the
  Confirmations page; the requester cannot self-approve. Generalises the MCP
  confirmation queue (`exec_command` action + self-approval guard).

### Proxmox QEMU VM create
- **Create VM** wizard on the Virtualization page (cores/memory/disk/storage/
  bridge/ISO) — mirrors LXC create. `POST /api/proxmox/qemu/create`.

### Ansible playbook runner
- New **Ansible** admin page: store playbooks and run them against a
  group/tag/site/fleet with the server as the control node over SSH. Disabled
  when ansible-playbook isn't installed; admin-defines, exec-gated to run,
  audited. `GET/POST /api/ansible/playbooks`, `…/{id}/run`.

### Docs
- `docs/terraform-api.md` — driving the REST API from Terraform (the community
  restapi provider) instead of a bespoke provider.

## v3.6.0 — unreleased (dev)

A seven-feature batch: act on hosts, not just observe them.

### Remote file manager (SFTP)
- **Files** device action — browse and transfer files in the browser over SFTP,
  tunnelled through the same web-terminal daemon + ticket + SSH path (no new
  inbound ports). Download/upload (≤32 MB), mkdir, delete. Daemon gains a
  `mode: 'sftp'` JSON request/response protocol.

### Backup orchestration
- **Planning → Backups** — define a backup command per device (restic/borg/rsync),
  run it on demand, or schedule it with cron. Admin-defines, `exec`-gated to run,
  quarantine-aware. `GET/POST /api/backup-jobs`, `PUT/DELETE /api/backup-jobs/{id}`,
  `POST /api/backup-jobs/{id}/run`. Closes the loop on `backup_stale` monitoring.

### Host user & SSH-key management
- **Users & keys** device action — add/lock/unlock/delete users and add/revoke
  SSH keys via the agent. `exec`-gated, audited, strict input validation.
  `POST /api/devices/{id}/user-action`.

### Endpoint AV/malware posture
- Agent reports ClamAV/rkhunter status (DB age, infected count, warnings); **AV
  scan** device action runs an on-demand scan. Infections → critical attention,
  stale DB / warnings → warning (NA kind `av_posture`).
  `GET /api/devices/{id}/av`, `POST /api/devices/{id}/av-scan`.

### Host firewall rule management
- **Firewall** device action — allow/deny/delete a port via ufw or firewalld
  (the agent already reported firewall status). `exec`-gated, audited.
  `POST /api/devices/{id}/firewall-action`.

### Auto-patch policy
- **Planning → Auto-patch** — scheduled automatic updates across a group/tag/site/
  whole fleet, optional reboot. Respects maintenance windows + quarantine via the
  normal dispatch. `GET/POST /api/autopatch`, `PUT/DELETE /api/autopatch/{id}`,
  `POST /api/autopatch/{id}/run`.

### Proxmox backup check
- Per-guest vzdump backup recency from the node's `content=backup` storage
  listing, cached opportunistically; guests with no/stale backups (older than
  `proxmox_backup_warn_days`, default 7) become attention items (NA kind
  `proxmox_backup`).

## v3.5.0 — unreleased (dev)

A four-feature batch toward a complete Linux RMM.

### SBOM export
- **Per-host and fleet SBOM** in CycloneDX 1.5 and SPDX 2.3 JSON, generated from
  the package inventory RemotePower already collects. Each component carries a
  package URL (purl); CycloneDX output includes a VEX-style `vulnerabilities[]`
  section built from the host's current CVE findings (ignore-list applied), so a
  single document is both an inventory and a vulnerability report. Buttons on the
  device CVE detail and the CVE Findings page (fleet = ZIP of per-host docs).
  `GET /api/devices/{id}/sbom` and `GET /api/sbom` (`?format=cyclonedx|spdx`).
  Output is deterministic for reproducible re-exports.

### Lifecycle expiry tracking
- **Warranty / license / support-contract expiry** dates per CMDB asset. Expired
  or within 30 days → warning; within 90 days → info. Surface as dashboard
  attention items, feed the fleet health score, and are silenceable as the NA
  kinds `warranty_expiry` / `license_expiry` / `support_expiry`. Mirrors the
  end-of-life-OS pattern (state-derived, no new webhook events).

### Graphical remote access (VNC over SSH)
- **"Remote desktop" device action** opens a browser VNC session (noVNC) tunnelled
  over the web-terminal daemon's SSH connection to the host's loopback VNC port —
  the VNC server is never network-exposed, no inbound firewall rules, no agent
  change. Same admin re-auth + single-use ticket as the web terminal. Linux VNC
  only; RDP is not supported this release.

### Sites & teams
- **First-class fleet grouping** above device `group`, for organising hosts by
  location / team / customer (soft boundary — super-admins see all). Admin → Sites
  for CRUD; "Assign site" on the device drawer; a site filter on the Devices
  roster. `GET/POST /api/sites`, `PUT/DELETE /api/sites/{id}`,
  `PATCH /api/devices/{id}/site` (mutations admin-only, audited).

## v3.4.2 — unreleased (dev)

In development.

### Security & hardening
- **RBAC read/act scoping now covers per-device endpoints that don't live under
  `/api/devices/`.** The dispatch-level scope guard only fired for
  `/api/devices/<id>` paths, so a few per-device routes addressed under other
  prefixes weren't covered. Closed:
  - **Mitigate** (`POST /api/mitigate/<id>/investigate` and `/fix`) now require
    the `exec` permission on an in-scope device — they queue a command on the
    host, so a read-only viewer or an out-of-scope operator can no longer trigger
    a diagnostic or remediation run on a device they shouldn't touch. (Previously
    these only checked that the caller was authenticated.)
  - **ACME action log** (`GET /api/acme/<id>/log/<action>`) is scope-checked, so a
    scoped role can't read certificate-action output for an out-of-scope host.
  - **Batch / install job tracker** (`GET /api/exec/batch` and
    `/api/exec/batch/<id>`) filters per-host status, return codes, command output,
    and job labels (which may name installed packages) to the caller's in-scope
    devices; jobs with no in-scope target are omitted. Unrestricted callers
    (admin / all-scope) see everything, unchanged.
- **CSV report hardening** — the patch report CSV (`GET /api/patch-report.csv`)
  now neutralizes spreadsheet formula injection: any cell starting with `=`, `+`,
  `-`, `@`, tab or CR is prefixed with a single quote so it opens as literal text.
- **OIDC SSRF guard** — the OIDC back-channel fetches (the discovery document and
  the token endpoint) now reject non-`http(s)` URLs and any target that resolves
  to a link-local / cloud-metadata address (e.g. `169.254.169.254`). RFC1918 and
  loopback stay allowed so internal and dev identity providers keep working —
  the same policy the webhook sender uses.
- Fixed: a re-issued software install could be de-duplicated against an
  already-completed identical command, leaving the new job stuck **"pending"
  forever** (its run had already happened, so no fresh output ever arrived). The
  job tracker now resolves such a job from the prior run once the command is no
  longer queued, while a command still waiting to run stays pending as before.
- **`GET /api/config` no longer returns the OIDC client secret or the status
  token as a value.** Both were write-only in the Settings UI (it shows a
  "configured" indicator, never the stored value), but the endpoint — reachable
  by any authenticated user, including a read-only viewer or MCP key — returned
  them in clear text. They're now surfaced only as `*_set` booleans, exactly like
  the SMTP / LDAP / Proxmox passwords. The legacy `webhook_url` (a Slack/Discord
  URL that embeds a secret in its path) is now admin-only too; viewers get the
  `webhook_configured` boolean instead.
- **Inbound webhook / syslog tokens are compared in constant time.** The
  ingest-token check used a plain `==`, unlike every other token comparison in
  the server; it now uses `hmac.compare_digest`, closing a (low-practicality)
  timing side-channel on the `rpwi_…` tokens.
- **CVE reference links are scheme-validated.** A reference URL from the CVE feed
  is now rendered as a link only if it's `http(s)` (a poisoned `javascript:` /
  `data:` reference can't become a clickable link), and the link carries
  `rel="noopener noreferrer"`.

### Bind it together — device detail
The device drawer's **System Info** tab now surfaces data the agent was already
collecting but the detail view didn't show:
- **Top processes** — the host's top processes by CPU (PID / name / CPU% / mem%),
  the same data shown fleet-wide on the Processes page, now also per device.
- **Filesystem type** per mount (ext4 / xfs / zfs / btrfs / nfs …) in the mounts
  table.
- **Reboot required** — a clear amber indicator plus the *reason* (the packages
  that triggered it) when a host needs a reboot, not just on the home feed.
- **Container age** — an Age column in the per-device container list, from the
  container's uptime / start time.
- Fixed: the drawer's **Load avg** pill read the wrong key and was always blank;
  it now shows the 1-minute load average.
- Fixed: the **Fleet Query** results table wires its sort headers eagerly (the ↕
  indicator shows on loading / empty / failed states too) and no longer throws on
  a malformed response.
- Fixed: **pending updates now lower the fleet health score** (and colour the
  heat-map cell). The pending-patch Needs-Attention signal read a non-existent
  top-level `upgradable` field instead of the agent's real
  `sysinfo.packages.upgradable` count, so a host with updates waiting kept a
  perfect 100. A device now loses points for outstanding patches — `info`
  (−2) below 20 pending, `warning` (−8) at 20 or more — exactly like every other
  attention item.
- **Disk forecast — one row per disk, no more 5-year "risks".** Mounts that are
  the same underlying filesystem (btrfs subvolumes, bind mounts — `/`, `/home`,
  `/var/log`, `/srv`, … on one pool) reported identical usage and so printed as
  five identical fill projections; they now collapse into a single row per
  filesystem (representative mount + a `+N` hover listing the rest). And a mount
  that only fills more than ~2 years out is no longer shown as a dated risk —
  the row is kept (current usage is useful) but reads ">2 yr" instead of a
  spurious "fills 2031" projection.
- **Container health, CPU & memory** now show in the device's Containers list.
  The agent already reported each container's health (`healthy` / `unhealthy` /
  `starting`), live CPU%/memory and published ports, but the server dropped those
  fields at the ingest boundary and the table only showed name/status/image/age.
  A container can now be seen as unhealthy or hot at a glance, with its ports.
- **SMART detail — serial number and CRC / uncorrectable counts.** The disk-health
  table adds the drive **serial** (so you know which physical disk to pull) and a
  **CRC / Uncorrectable** column — the very counters that drive the FAILED verdict,
  which were previously invisible (you saw "FAILED" with no "why").
- **Helm releases** now list the deployed **app version** and **last-updated**
  time, not just chart / revision / status.
- **Memory & RAID inventory** gain the DIMM **manufacturer** and **serial** (so you
  can order the right replacement part) and the **member block devices** of each
  RAID array (so a degraded array names the exact disk to swap).
- **Per-device backup freshness.** A new **Backups** section in the device drawer
  (and `GET /api/devices/<id>/backups`) shows each watched backup path's age and
  fresh/stale state — the data that already fired the `backup_stale` alert but was
  never visible per device.

### Reliability & SLA
- **Agentless / SNMP devices now build real 7-day status history.** The
  reachability sweep recorded an uptime event only on a state *change*, so a
  continuously-reachable agentless or SNMP host never got a baseline event and
  was absent from the fleet roster stripe (rendering as all-"unknown"). It now
  records the current state on every probe (de-duplicated), so the stripe fills
  in like an agent device's.
- **SLA no longer counts "no data" as downtime.** Uptime % treated the time
  before RemotePower had any record for a device (e.g. before enrollment) as a
  giant outage — a freshly-deployed host read as ~27% uptime / "22 days down".
  That prefix is now reported as *unknown* and excluded; the SLA is computed only
  over the period actually covered by data.
- **Maintenance windows no longer burn the SLA.** One-shot maintenance windows
  (scheduled start/end, scoped to the device, its group, or fleet-wide) are
  excluded from both downtime and the covered window, so planned work doesn't
  count against uptime.
- **Settable SLA targets** — set a target uptime % per **device**, **tag**,
  **group**, or a fleet **default** (most specific wins) from the Uptime (SLA)
  card. Each row shows its target and whether it's met or breached.
  `GET`/`PUT /api/fleet/sla-targets`.
- **CVE attention items show what's fixable.** A CVE Needs-Attention item now
  notes how many of the findings carry a known fixed version — e.g. "30
  high-severity CVEs · 12 fixable" — so you can see at a glance whether a package
  upgrade would actually clear any of them. The count is over critical/high
  findings only, so it matches the "fixable" figure on the Patches page.
- **Print / PDF posture report now renders reliably.** The report used to print
  by hiding the app and revealing a hidden div via `@media print`, overriding the
  dark theme — which printed blank in some browsers when the theme leaked
  through. It now opens a **standalone window** containing a fully self-contained
  light HTML document (its own inline styles, can't inherit the app theme), so it
  always prints black-on-white. Includes the RemotePower logo, colour-coded
  baseline pass/fail, and a footer. (Allow pop-ups for the site; it warns if
  they're blocked.)
- **UI: separate cards.** The Rollouts page puts "Rollouts" and "Recent installs
  & jobs" in their own boxes, the Users page puts "Custom roles" in its own box,
  and the Automation page puts "Rules" in its own box — instead of running the
  sections together.
- **More in the RAG index.** Added focused docs (`docs/sla.md`,
  `docs/forecast.md`, `docs/health-score.md`) so the AI assistant and fleet
  search can answer questions about SLA targets, the disk forecast, and how the
  health score is calculated. (`deploy-server.sh` syncs `docs/*.md` into the RAG
  corpus.)

### Operations, onboarding & UX
- **Timeline polish.** Row titles inherited the ~16px page default while the
  rest of the row is 11–13px, so titles like "New Listening Port Detected"
  looked oversized — set `.tl-title` to 13px. The kind-filter chip row now wraps
  inside the card (scoped `flex-wrap` on `#timeline-kinds`), and long row detail
  text wraps instead of overflowing.
- **Timeline rows stay inside their card.** The timeline row is a 3-column grid
  (`14px 1fr auto`) but the middle `.tl-main` column had no CSS, so it defaulted
  to `min-width:auto` and a long unbreakable detail (an `snmp recover` string, a
  command line) pushed the column past the card and the row overflowed "out of
  the box". Added `min-width:0` to `.tl-main`/`.tl-head` and `overflow-wrap` so
  long content wraps within the card.
- **CVE "Scan all devices" no longer freezes the browser.** A fleet-wide scan
  does OSV.dev lookups for every device and can run for minutes — long enough
  that the request (or nginx) times out and the page looks hung. The scan button
  now uses an AbortController with a generous client timeout (10 min fleet / 2
  min single) and clear messaging that the scan continues server-side; results
  refresh when done instead of blocking the UI.
- **Timeline now shows CVEs.** The timeline is event-sourced, but CVE findings
  are state — a re-scan of already-known CVEs fires no `cve_found` event, so
  CVEs never appeared even on hosts that clearly have them. The timeline now
  surfaces current critical/high (non-ignored) findings as a synthetic `cve` row
  per device, alongside the event-based rows.
- **OpenSCAP scan survives an agent self-update.** The scan runs in a daemon
  thread; if the agent self-updated/restarted mid-scan, the thread was killed and
  no result was ever reported ("server requests it, then nothing"). The agent now
  defers its self-update while an OpenSCAP scan is in progress (retried on the
  next poll once the scan finishes).
- **Ignored CVEs can be un-ignored.** CVE ignores are stored separately from the
  per-item Needs-Attention/container/device hides, and the "Ignored items"
  settings pane only listed the latter — so a CVE you'd accepted as risk showed
  "(ignored: )" on the device but appeared nowhere you could undo it. The Ignored
  items pane now has an **Ignored CVEs** section (vuln id, scope, reason, when)
  with a **Remove** button (`DELETE /api/cve/ignore/<id>`, which already existed
  but had no UI).
- **Download the full OpenSCAP report.** Each successful scan now uploads the
  complete `oscap` / `usg` HTML report (gzipped); a **Report** link in the
  Compliance → OpenSCAP results row opens it in the browser. Stored one-per-device
  (latest scan) under the data dir; `GET /api/scap/<id>/report` serves it
  (auth + device-scope checked).
- **AI Investigate now covers CVEs and containers.** Two new mitigation
  playbooks: **CVE findings** (diagnoses the OS's pending security updates +
  kernel and proposes a security upgrade) and **stopped/restarting containers**
  (inspects exit code / restart count / OOM / recent logs of the non-running
  containers and proposes a restart). Wired across server playbook, AI prompt,
  and the client `MITIGATE_KINDS`, so the Investigate button appears and works
  for these Needs-Attention items. Investigate now covers: disk, memory, swap,
  cpu, patches, drift, service_down, reboot, brute_force, cve, container.
- **RAG: fleet/agent operations documented for the assistant.** Added
  `docs/fleet-management.md` covering agent self-update / force-update, restart,
  release signing (incl. "signed but INVALID"), the command queue, install /
  uninstall, reboot / WoL, quarantine, SLA targets and OpenSCAP — so the AI
  assistant and fleet search can answer "how do I re-sign the agent / force an
  update / see what's queued / uninstall a package". (`deploy-server.sh` syncs
  `docs/*.md` into the RAG corpus.)
- **Mitigation AI: the suggested fix shows even without a closing marker.** The
  AI analysis pane looked like it "did nothing" when the model's reply was
  truncated or omitted the closing `END_FIX` marker — the strict
  `BEGIN_FIX…END_FIX` parser found nothing, so the summary appeared but no
  actionable fix / Apply-fix option. The parser now falls back to the command(s)
  after `BEGIN_FIX` (up to a blank line / code fence) when `END_FIX` is missing,
  so a usable fix surfaces. The Re-run AI button in the pane lets you re-prompt
  without waiting on the agent again.
- **Mitigation modal: AI analysis & Apply-fix tabs were never visible (root
  cause of "it stalls / all tabs empty").** The AI and Fix panes share a CSS
  class carrying `display:none`; `mitigateTab()` revealed the active pane with
  `style.display = ''`, which only clears the *inline* value and leaves the
  stylesheet `display:none` in force — so tabs 2 and 3 stayed hidden even though
  their content was written correctly (diagnostic, AI summary and suggested fix
  all populated an invisible container). A CSP-migration regression: these were
  originally inline `style="display:none"` (which `''` would have cleared); the
  auto-class generator turned them into a stylesheet rule. Fixed by setting
  `display:'block'` explicitly. This is the actual cause behind the run of "AI
  does nothing" reports — the analysis was working the whole time.
- **Mitigation AI: render can't freeze the step, plus step-by-step debug.**
  `_mitigateRenderFixOptions` ran before the "Done" status update, so a throw in
  it would leave the pane stuck on "Asking the model…" even though the AI call
  succeeded. It's now wrapped in try/catch and the status is always finalised.
  Added `dbg()` breadcrumbs across the flow (enable with
  `localStorage.rp_debug=1`) — start, POST sent, POST returned, render — so a
  stall on any host can be pinpointed to the exact step instead of guessed at.
- **Mitigation AI: "nothing to fix" no longer looks like a stall.** When the
  model judges no fix is needed (it returns `NONE` — common for a transient
  alert that's already recovered, e.g. swap pressure that's since eased), the
  pane showed the summary but no fix box, which read as "the AI step did
  nothing". The status line now states the outcome explicitly — "Done in Ns — no
  fix command proposed" (with a Re-run button), "suggested fix below", or "empty
  response" — so a valid no-op is unambiguous. (Verified the backend returns
  200 in ~16s for this case; the perceived "stall" was the empty fix box.)
- **Mitigation AI no longer stalls indefinitely.** If the AI provider (or nginx)
  never responds, the analysis step used to spin forever — the elapsed counter
  ticked but nothing resolved and there was no clear recovery. It now has a hard
  4-minute client-side timeout that aborts and shows a clear message, and every
  terminal state (timeout, abort, network error, server error, empty response)
  now renders an inline **Re-run AI** button so the step is never a dead end.
- **Command Queue (Admin).** A new Admin → Command Queue page shows every device
  with commands still waiting to be picked up on its next heartbeat — what kind
  (exec / reboot / poll / compose / …) and a readable summary — so you can see
  what's pending on an offline host and **cancel** individual commands or clear a
  device's whole queue before it comes back online. `GET /api/command-queue`,
  `DELETE /api/devices/<id>/command-queue[?index=N]` (admin-only, audited).
- **OpenSCAP picks the right datastream.** The agent chose the *alphabetically
  first* SSG datastream when there was no exact version match — so Debian 13 and
  Ubuntu 24.04 both scanned against `ssg-debian10` (score 0, "not available").
  It now matches by distro family (`ID`, then `ID_LIKE` — so Ubuntu uses the
  `ssg-debian*` content) and the closest version not over the host's (Debian 13 →
  `ssg-debian12`), falling back to the newest available rather than the oldest.
- **OpenSCAP: fetch remote resources + correct CPE dictionary.** The raw-oscap
  scan now passes `--fetch-remote-resources` (several SSG checks reference remote
  OVAL/CVE content; without it oscap silently skips them and can report 0
  applicable rules) and sets `OSCAP_CPE_PATH` to the datastream's matching
  `*-cpe-dictionary.xml`. The missing CPE path was the cause of the "Failed to
  add default CPE to newly created CPE Session [cpe_session.c:58]" → 0-score
  failures on some hosts (e.g. Debian 13). Remote fetch needs host outbound
  network; offline, oscap still runs and just skips the remote checks.
- **OpenSCAP on Ubuntu uses `usg` (Ubuntu Security Guide).** Canonical's `usg`
  ships CIS/STIG content built for the *exact* Ubuntu release — including 24.04,
  where the distro `ssg-ubuntu` datastream lags and a raw oscap run scores 0
  (every rule "not applicable"). When `usg` is installed and the requested
  profile is a CIS/STIG one, the agent now runs `usg audit <profile>`, parses its
  XCCDF results, and reports a real score; non-CIS profiles (e.g. ANSSI) and
  non-Ubuntu hosts fall back to raw oscap unchanged. So on Ubuntu the fix is
  simply `sudo apt install usg` + run a `cis_level1_server` scan.
- **OpenSCAP "0 rules" now tells you the real cause.** The most common reason a
  scan scores 0 is an OS↔content mismatch: oscap's CPE applicability check marks
  every rule "not applicable" when the only installed SCAP content targets a
  different OS than the host (e.g. an Ubuntu 24.04 box with just `ssg-debian12`
  installed). The agent now detects that — a real match needs the host's own
  distro id *and* major version in the datastream name, not just an `ID_LIKE`
  relative — and reports an actionable reason. It distinguishes three causes:
  (1) **wrong distro** (e.g. `ssg-debian` on Ubuntu) → install `ssg-debderived` /
  `ssg-debian` / `scap-security-guide`; (2) **right distro, wrong release** (e.g.
  `ssg-ubuntu2204` content on Ubuntu 24.04, or `ssg-debian12` on Debian 13) →
  install SSG content built for *this* release (a newer `ssg-*` providing the
  matching `ssg-<os><ver>-ds.xml`) — re-installing the same package won't help;
  (3) **content matches but the profile is empty** → pick a profile with real
  coverage (CIS on Ubuntu, ANSSI on Debian).
- **OpenSCAP profile detection fixed + ANSSI guidance.** The agent parsed
  `oscap info` by grepping for `Profile:` lines, but modern oscap prints
  profiles as `Title:` / `Id: …content_profile_<x>` — so the profile list came
  back empty and the UI couldn't offer a host's real profiles. It now extracts
  the `content_profile_<x>` ids regardless of layout (both formats). With that
  working, the scan dropdown surfaces what each datastream actually has — on
  Debian/Ubuntu that's the **ANSSI BP-028** profiles (`anssi_np_nt28_minimal` →
  `…_high`), which have real rules and produce a meaningful score. The UI hint
  now explains the OS→profile mapping (Debian → ANSSI; CIS/PCI-DSS/STIG/OSPP are
  RHEL-only) and flags the Debian `standard` profile as near-empty.
- **OpenSCAP offers only profiles that exist for the host's OS.** Debian's SSG
  datastream has no `cis` / `pci-dss` / `ospp` profiles (those ship in RHEL's
  `scap-security-guide`), so picking them produced confusing "not available" /
  score-0 results. The agent now reports the profiles its datastream actually
  contains; the scan-profile dropdown offers the union supported across the
  in-scope fleet (falling back to the built-in list before the first scan). A
  scan requested for an absent profile is short-circuited with a clear reason,
  and a profile that runs but selects **no applicable rules** (e.g. Debian's
  `standard`) is reported as not-applicable instead of a meaningless 0%. (That
  "0%" was the XCCDF base score over pass/fail rules — with every rule coming
  back *notapplicable*, the score is 0 but nothing was actually assessed. The
  agent now keys off pass+fail, not total, and the server defensively coerces an
  older agent's `available=True / 0 pass / 0 fail` into a not-applicable row so
  existing 0% entries read correctly the moment the server is updated.)
- **Uninstall software via the package manager.** An "Uninstall" button on the
  Install-software card removes the named packages on a device / group / tag
  through the host's own package manager (apt/dnf/yum/zypper/pacman/apk) —
  tracked as a batch job like install, gated on `exec`, honouring quarantine and
  change-windows. Removes the named packages only (no dependency auto-removal or
  config purge). `POST /api/uninstall`.
- **Posture report PDF — actually fixed this time (static page).** The previous
  approaches (in-app `@media print`, then a blob document) printed blank because
  the strict CSP (`style-src/script-src 'self'`, set by nginx on every response
  and inherited by blobs) blocked their inline styles/handlers, and the dark
  theme leaked in. The report is now a **static page** (`report.html` +
  `static/css/report.css` + `static/js/report.js`) served under the normal CSP
  with fully external assets — it opens in a new tab, reuses the session token to
  fetch the report JSON, and renders a light document. It can't inherit the app
  theme, so it prints black-on-white.
- **Release signing stays valid across deploys.** `deploy-server.sh` republishes
  the agent binary on every run, which left the previous detached signature
  stale → the Release Signing page flagged "signed but INVALID" after each
  deploy. When a server-side signing key exists, deploy now **re-signs** the
  freshly-published binary automatically and re-syncs the public key +
  fingerprint into config, so signing stays valid without a manual click.
  (CI/off-server signing is untouched — no server key means this is a no-op.)
- **Release-signing "INVALID" — re-signing now actually fixes it.** Two parts:
  (1) the page now explains *why* it's invalid (`signature_detail` on
  `GET /api/signing/status`); (2) more importantly, **signing is now
  authoritative for the server-side pinned key.** Previously only *generate*
  wrote `release_pubkey`, so if that config value ever drifted from the live
  signing key (an earlier key, a half-finished generate, an externally-set CI
  pubkey), a freshly-made server signature could never verify and the page
  stayed "signed but INVALID" no matter how many times you re-signed. Signing now
  re-exports the signing key's public key + fingerprint into config, so re-sign
  always converges to valid.
- **Button feedback audit.** Swept every `data-action` handler for ones that
  mutate state without acknowledging it; added a confirmation toast to
  "Save query" (Fleet Query). Running an OpenSCAP scan already confirms; install
  / uninstall confirm and toast.
- **Install / OpenSCAP targets are dropdowns, not free text.** The "Install
  software" and "OpenSCAP scan" target pickers (and the one-time-install modal)
  now offer the fleet's actual groups / tags / devices in a dropdown, so you
  can't queue an action against a group or tag that doesn't exist.
- **OpenSCAP reports the real failure.** When the chosen profile isn't in the
  host's datastream (e.g. asking for `cis` against `ssg-debian10`), the scan no
  longer reports the cryptic "no element found: line 1, column 0" — it now
  surfaces oscap's actual error and lists the profiles the datastream *does*
  contain. Docs clarified: Debian/Ubuntu SSG content is `ssg-debian` /
  `ssg-debderived`, not `scap-security-guide` (which is the RHEL name).
- **Confirmations.** Running an OpenSCAP scan now asks for confirmation (naming
  the profile and target) for every scope, not just "all devices".
- **Sidebar search.** A small search box under the Collapse button finds a page
  by its menu title *or* by a concept it contains — type "SLA" or "uptime" and
  Reports comes up, "metrics" → Device Metrics, "cron" → Schedule, "cve" → CVEs.
  Results navigate via the real nav buttons; Enter opens the first match, Escape
  clears. It also deep-links into **Settings sub-panes** — "smtp"/"ldap"/"oidc"
  → Settings ▸ Security, "webhook"/"pagerduty" → Settings ▸ Notifications,
  "prometheus"/"ical" → Settings ▸ Integrations, "backup"/"signing" → Settings ▸
  Advanced, and so on.
- **Install software from repos, by host or tag/group.** A new "Install software"
  action (Patches page) installs one or more repo packages — detecting the
  package manager (apt/dnf/yum/zypper/pacman/apk) — on a single device or across
  a whole group/tag. Package names are strictly validated (no shell injection);
  gated on the `exec` permission and subject to quarantine + change-windows.
  `POST /api/install`. Available both as the "Install software" card (Patches)
  and a **one-time install** button on the Rollouts page (the un-staged sibling
  of a ring rollout) — target a single device or a tag. Each install is now a
  **tracked job**: the Rollouts page shows a "Recent installs & jobs" list with a
  live per-host **checkmark** when each finishes (red on a non-zero exit). Built
  on the exec-batch job machinery; `GET /api/exec/batch` lists jobs,
  `GET /api/exec/batch/<id>` gives per-host status. Fixed: the apt install path
  now applies the `APT::Sandbox::User "root"` workaround (same as upgrades), so
  installs no longer fail with `seteuid 105 failed` on hardened hosts. Fixed: the
  job tracker matched the *full* command but `cmd_output` stores it truncated to
  512 chars, so long installs/scripts were stuck "pending" forever despite a
  successful `rc=0` — the matcher now compares against the same truncated form.
  Added a **Clear** button on the tracker (`DELETE /api/exec/batch`).
- **OpenSCAP scans now target a tag/group** (not just a device): the scan form
  gained a target-type selector (all / group / tag / device); the profile is the
  parameter. (The API already accepted tag/group; this surfaces it.)
- **Settings → Install** — a getting-started checklist that reflects live state
  (admin password set, first device enrolled, a notification channel, scheduled
  backups, 2FA) with a link to each. `GET /api/setup-status`.
- **Signing the agent release now re-verifies the admin password** (mirrors
  disabling enforcement) — it's what every agent trusts.
- **Fleet Query — many more filters.** Added agent version, package manager,
  has-package, monitored / agentless / quarantined, reboot-required, failed
  units, kernel-outdated, third-party updates pending, disk % / memory %
  thresholds, and offline-for-N-days — on top of the existing group/tag/OS/
  online/pending/integrity/CVE.
- **Settings re-categorized.** CVE details cache moved to **Security**; the
  Status endpoint moved to **Integrations**; the duplicate raw-seconds "Session
  timeout" card was consolidated into Security's "Session length" (same keys).

### Linux-RMM additions (deepening the self-hosted Linux story)
- **OpenSCAP deep compliance scans (Compliance page).** Auditor-grade complement
  to the lightweight CIS baseline: the agent runs `oscap xccdf eval` against its
  SCAP Security Guide datastream (CIS / STIG / PCI-DSS profiles) and reports the
  score, pass/fail tallies and failing rule ids. Runs on the endpoint (no new
  server dependency); hosts without `openscap-scanner` / `scap-security-guide`
  report "not available" cleanly. Scans run in a background thread and report on
  the next heartbeat. `POST /api/scap/scan`, `GET /api/scap`.
- **Third-party (non-OS) patch detection.** The agent now also reports available
  updates from **flatpak, snap, pip and npm**; the patch catalog aggregates them
  by manager alongside OS packages.
- **On-call & escalation (Settings → Notifications).** Define escalation **tiers**
  (re-notify your webhook destinations after N minutes a critical/high alert
  stays unacknowledged) and an **on-call rotation** (the named person is included
  in the escalation message). Escalations re-fire the original alert through its
  existing channels — no new event wiring. `GET /api/oncall`.
- **Trends (Planning → Trends).** Zero-dependency multi-series SVG charts over the
  daily samples RemotePower already keeps — fleet health, fleet compliance %, and
  per-device memory / swap / disk history. `GET /api/devices/<id>/metrics-history`.

### Access control
- **Granular RBAC — custom roles with device scoping (Users & Roles).** On top
  of the built-in `admin` (full) and `viewer` (read-only) roles, an admin can now
  define **custom roles** that grant a subset of actions — `exec`, `reboot`,
  `upgrade` — limited to a **scope**: all devices, or only those in named groups
  or tags. A member can act on their scope and nothing else, and the Devices
  roster is filtered to that scope. Server config, user/role/key management and
  saved scripts stay admin-only. Enforced at the command/exec/reboot/upgrade
  dispatch chokepoints via a central `require_perm`. `GET/POST /api/roles`,
  `PUT/DELETE /api/roles/<name>`.
- **RBAC v2 — per-endpoint read scoping.** Scoping now covers reads, not just
  actions: a dispatch-level guard blocks a scoped role from any
  `/api/devices/<id>/…` request for an out-of-scope device, the per-device
  endpoints outside that prefix carry the same guard, and every fleet aggregate
  that emits per-device rows (patch report/catalog, CVE findings, fleet
  query/timeline/events/health/SLA/capacity/anomalies, agent integrity, drift,
  containers, inventory, compliance, network map, log rules, alerts inbox)
  filters to the caller's scope. Fleet posture report + Prometheus stay
  aggregate-only and fleet-wide by design.

- **Bake & sign in the UI (Admin → Release Signing).** A one-click,
  server-side path to signed releases: generate a server-held signing key,
  **Sign current agent**, toggle enforcement, and copy the public key to pin on
  agents. Honest about the trade-off — the UI states that server-side signing
  protects against tampering at rest, not a full server compromise (sign in CI
  for that). Plus **visibility**: an agent that refuses an unsigned/invalid
  self-update reports the reason, listed on the signing page.
- **Cryptographic release signing.** The agent release can now carry a detached
  GPG signature (`tools/sign-agent-release.sh`). An agent with a pinned release
  public key (`/etc/remotepower/release.pub`) verifies that signature before
  installing any self-update and **refuses** on a missing/invalid/wrong-key
  signature — defending against a compromised server that swaps both the binary
  and its advertised hash. Opt-in and fail-closed: no pinned key → behaviour is
  unchanged (sha256-only). The server advertises `signed` + the key fingerprint
  on `/api/agent/version`, serves the signature at `/api/agent/signature`, and
  self-verifies the published signature (shown as `release_signature` in the
  agent-integrity report). Uses the `gpg` binary — no new dependency.
- **Agent integrity attestation.** Each agent now reports the sha256 of its own
  running binary on every heartbeat, and the server attests it against the
  canonical copy it serves. An agent on the current version reporting a
  *different* hash is flagged as a **mismatch** (tamper / corruption / partial
  update) — a critical Needs-Attention item that also pulls down the health
  score. Surfaced on the Reports page (verified / mismatch / unknown counts +
  the actionable rows). New `GET /api/fleet/agent-integrity`.
- **Statistical resource anomalies.** A model-free complement to the AI anomaly
  scan: for each device, RemotePower fits a mean/stdev baseline over its daily
  metric history and flags the latest memory / swap / disk reading when it
  deviates sharply (default ≥ 2.5σ) from that host's own norm. Surfaced on the
  Reports page. New `GET /api/fleet/anomalies?z=` (new pure module
  `anomaly_stats.py`).
- **Device dependency map.** Declare that a device *depends on* upstreams
  (e.g. web → switch) on the Network Map. When an upstream is offline, alerts
  for the downstream devices are **held** — they're collateral, not the root
  cause, so you get the upstream's alert instead of twenty downstream ones. The
  map draws dependency edges (dashed violet, red when the upstream is down). New
  `PUT /api/devices/<id>/depends-on`; suppression is delivery-only (the event
  still lands in the inbox) and never holds a recovery event.
- **Automation rules engine (Admin → Automation).** Turn the events RemotePower
  already fires into actions: *"when event X (at severity S) on devices matching
  group/tags/id → run a saved script and/or notify a destination."* Rules are
  evaluated on every fired event, right after the unmonitored-device guard
  (so automation never touches a silenced host) and independently of the
  notification channel gates. Two action types: **run a saved script** on the
  event's device (auto-remediation — quarantine is still enforced at the
  command chokepoint) and **notify** a specific webhook destination (escalate a
  particular event past its normal routing, e.g. straight to PagerDuty). Each
  rule has a **cooldown** (default 60s) so a flapping event can't hammer an
  action. New `GET`/`POST /api/automation/rules` and
  `PUT`/`DELETE /api/automation/rules/<id>` (mutations admin-only, audited).

### Deployment & compliance additions
- **Staged / ring rollouts (Planning → Rollouts).** Push an OS upgrade or a saved
  script to the fleet in ordered rings — canary → pilot → broad. Each ring is
  dispatched and watched; upgrades use real post-deploy verification, and the
  next ring releases automatically (auto-promote) or on your approval. A ring
  that fails to verify halts the rollout. Pause / resume / cancel / promote, with
  per-rollout history. `GET/POST /api/rollouts`, `POST /api/rollouts/<id>/<action>`.
- **Maintenance change-windows.** A maintenance window can now also **gate
  command/upgrade execution** (new "gate execution" checkbox): exec/upgrade
  commands for covered devices are *held* at the dispatch chokepoint until the
  window is active — distinct from the alert-suppression role. Pairs with staged
  rollouts so changes only land inside an approved window.
- **CIS-style compliance baseline (Compliance page).** A named set of pass/fail
  checks evaluated against each host's reported state — patches, reboot, failed
  units, disk, swap, CVEs, agent integrity. Severity-weighted fleet score, a
  daily trend sparkline, per-check failing-host lists, and per-check enable/
  disable. `GET /api/compliance/baseline`.
- **Software metering: normalization + reclamation.** Meters take optional
  **aliases** (`name = limit | alias1, alias2`) so name variants map onto one
  catalog entry, and the report flags **reclamation candidates** — hosts where
  the software is installed but not seen running.
- **Print-friendly PDF report (Reports page).** A "Print / Save as PDF" button
  renders a clean, self-contained posture report (health, devices, patches,
  CVEs, compliance frameworks + baseline) for the browser's native print/PDF —
  no new dependency.

### Fleet management additions
- **Patch catalog (Patches page).** Pending updates aggregated *by package* —
  "package X is pending on N hosts" — the inverse of the device table. The agent
  now reports upgradable package names (capped). `GET /api/patch-catalog`.
- **Post-deployment verification.** Queuing an upgrade snapshots the pending
  count and forces a re-scan; the Patches table then shows whether it took
  (dropped), stalled, or is pending.
- **Software metering / license compliance (Reports page).** Track install
  counts of named software fleet-wide against an allowance; flags
  over-deployment. `GET /api/inventory/metering`.
- **Fleet heat map (Home).** A grid of device cells coloured by health score —
  scales visually where tables don't.
- **After-hours activity detection (Settings → Dashboard).** Flag selected
  events that fire outside business hours (a 3am login/new port/command);
  surfaces as a Needs Attention item.
- **Ad-hoc fleet query (Fleet → Query).** Filter devices by group / tag / OS /
  online / pending-count / integrity / CVE count, with saved queries.
  `GET /api/fleet/query`.
- **Signed-agent badge on Devices.** A green ✓ next to the version when the
  running binary matches the canonical (signed) build, a red ⚠ on a hash
  mismatch — hover shows the status + short hash.

### Fixes & polish
- **Disk-fill forecast ignores volatile mounts.** Ephemeral / tmpfs-style mounts
  (`/tmp`, `/var/tmp`, `/run`, `/dev/shm`, and `/run/*` `/dev/*` sub-mounts) churn
  as temp files come and go, so a linear "days to full" over them was noise —
  they're now excluded from the forecast entirely. For the mounts that remain, a
  fill date is only shown when the least-squares fit is reasonably clean (R² ≥
  0.5); a heavily-fluctuating mount shows **fluctuating** with no (misleading)
  date instead. `forecast_mounts` gained `noisy` + `r2` fields.
- **SNMP thresholds intermittently ignored — fixed.** The SNMP poll sweep loads
  devices once, then polls each target over the network (seconds). A threshold
  saved *during* a sweep was evaluated against the stale snapshot for that whole
  cycle, so it looked "not applied" and could leave a spurious alert until the
  next sweep (re-saving cleared it). SNMP threshold resolution + alert-state now
  read the **live** device record under the lock, so a saved change takes effect
  immediately. (The agent metric path never had this — it evaluates the same
  locked device it persists.)
- **Disabling signature enforcement now re-verifies the admin password** (a
  security downgrade shouldn't be one accidental click).
- **Cron builder** moved to **Planning → Schedule** (next to the jobs it builds);
  **Fleet anomaly scan** moved to **Security → Compliance**.
- **Home:** the Fleet health panel now has proper spacing above Needs attention /
  Recent activity (was flush against them).
- **Recent activity → Clear now persists.** It used session storage, so cleared
  items reappeared on the next refresh/restart; it now uses a localStorage
  watermark — cleared events stay hidden, newer events still appear.
- **Forecast** gains a device/mount filter, an "at-risk only" toggle, and
  pagination — so a large fleet (many devices × mounts) doesn't render a
  thousand-row table.
- **Timeline** paginates (50 rows + "Load more") instead of dumping every event.
- **CVE scanning now works on Ubuntu derivatives.** Zorin OS, Linux Mint, Pop!_OS
  and elementary carry `ID_LIKE="ubuntu debian"`, and the ecosystem detector
  checked `debian` before `ubuntu` — so a Zorin 18 host was queried as the
  non-existent OSV ecosystem `Debian:18` and came back with **zero** findings on
  thousands of packages. Ubuntu derivatives now map to the `Ubuntu` ecosystem.
- **Recovered resource alerts now clear themselves.** A `metric_recovered` event
  (CPU/memory/disk dropping back below its threshold) now auto-resolves the open
  `metric_warning` / `metric_critical` alert **for that exact metric+target** —
  so recovering disk `/var` doesn't touch the memory alert. These alerts used to
  pile up in the inbox forever after the resource recovered.
- **The fleet posture report no longer over-counts CVEs.** It tallied every
  finding including ones on the ignore list, disagreeing with the live CVE page;
  it now applies the same per-device ignore list, so the two always match.
- **Health-score history survives un-monitoring a device.** The daily sampler
  pruned any series not in the *monitored* set, so flipping a host to
  `monitored:false` permanently deleted its accumulated health history (and
  re-monitoring restarted from zero). It now prunes only genuinely deleted hosts.
- **Command queue: no more lost commands.** The heartbeat dispatch and the
  enqueue paths did unlocked load → modify → save on the queue, so a command
  queued in the exact window of a heartbeat could be silently dropped (or a
  dispatched one resurrected). Both now do the read-modify-write under the queue
  lock.
- **A forced agent upgrade no longer kills an in-progress OpenSCAP scan.** The
  self-update deferral that protects a running scan was bypassed by the one-shot
  force-upgrade path; a force upgrade requested mid-scan is now held locally and
  retried after the scan completes (so the one-shot request isn't lost).
- **`image_update_available`, `image_updated` and `health_recovered`** are now
  first-class notification events with their own per-event toggle in
  Settings → Notifications and a clickable dashboard-feed row (they fired before
  but weren't in the event registry, so you couldn't turn them off).
- **Sortable tables** — the Reports → *Agent integrity* and *Anomalies* tables now
  wire their sort headers (they were the last two unsorted tables); the OpenSCAP
  table sorts from cache on a header click instead of re-fetching `/scap` and
  resetting the profile dropdown mid-interaction.
- **Command palette** — opening a device from the palette now shows the device
  name in the drawer header (it read "undefined"), and the palette can now jump to
  the **Command Queue** admin page.
- A non-JSON error body (an nginx 502/504 HTML page) from any API call no longer
  throws an unhandled rejection that leaves skeleton rows / spinners stuck — the
  call resolves to `null` and the caller's empty/error handling takes over.

## v3.4.1

**Theme: bind it together.** Three cohesion features that connect data which
previously lived on separate pages, plus a smarter command palette.

- **Timeline (Monitoring → Timeline) — whole-fleet or per-device.** A single
  chronological stream — fleet events (offline, drift, CVEs, services, SMART, …)
  and command runs merged newest-first, with severity pills and per-category
  filter chips. The scope selector defaults to **Whole fleet** (every monitored
  host, each row tagged with its device and click-through to that device's
  timeline) and switches to any single device. Jump straight in from the command
  palette or the home health panel. New `GET /api/fleet/timeline` (with
  `?device/kinds/severity/limit` filters) and `GET /api/devices/<id>/timeline`,
  sharing one merge core. The command-run rows are the part you couldn't see
  before: they're not fleet events, so a host's history never showed them.
- **Fleet health score (Home).** A single 0–100 score per device and across the
  fleet, rolled up from the same Needs Attention signals — so the number can
  never disagree with the NA list. The home dashboard gets a health panel: big
  score + grade, a severity breakdown, and the lowest-scoring devices (each a
  click-through into its timeline). New `GET /api/fleet/health`; also embedded in
  the `/api/home` bundle so the panel adds no extra request.
- **Health-score history + alerts.** The fleet/per-device score is sampled once
  per UTC day into a time series (`GET /api/fleet/health/history`), rendered as a
  trend sparkline on the home panel. An opt-in threshold (Settings → Dashboard →
  Health-score alerts, `0` = off) fires a new edge-triggered **`health_degraded`**
  event when a device drops below it — and a `health_recovered` follow-up that
  auto-resolves the alert when it climbs back. Severity scales with the score.
- **Fleet posture Report (Planning → Reports) + scheduled email.** One report
  that binds patches, CVEs, the health score, and compliance into a single
  export — download as JSON or CSV on demand, or have it emailed on a cron
  schedule. New `GET /api/report/fleet?format=json|csv` and
  `GET`/`PUT /api/report/schedule` (admin-only to configure). Delivery runs on
  the heartbeat hot path with a once-per-minute lock so a busy fleet never
  double-sends.
- **Command palette ties it together.** `Ctrl/Cmd-K` now indexes the new
  Timeline, Reports, Alerts, Compliance, and Forecast pages, offers a
  "<device> — timeline" jump for every host, a one-keystroke fleet-report
  download, and your saved scripts.
- **Quick wins — three small joins over data we already collect.**
  - **CVE ↔ patch cross-link.** The Patches page now shows, per device, how many
    outstanding critical/high CVEs a pending patch would fix (badge → the
    device's CVE list). New `cve_fixable` in the patch report.
  - **Software inventory search.** "Which hosts run `openssl` < 3.0.2?" — a
    search card on the Patches page queries the collected package inventory by
    name (+ optional, ecosystem-aware version compare). New
    `GET /api/inventory/search`.
  - **End-of-life OS detection.** Hosts on an out-of-support OS now surface in
    Needs Attention (so they pull down the fleet health score) and fail a new
    compliance control (PCI/HIPAA/SOC 2). Uses os-release data already sent at
    package-scan time — no agent change.
  - **Richer Prometheus metrics.** `/api/metrics` now also exports the fleet and
    per-device health score, needs-attention counts by severity, 24-hour fleet
    event counts by kind, and the CVE-fixable-by-patching total.
  - **iCal feed.** `GET /api/schedule.ics?token=<status token>` publishes your
    scheduled jobs + maintenance windows as a calendar subscription (one-shot
    events exactly; recurring jobs as daily/weekly/monthly RRULEs).
  - **Quiet hours.** Optionally hold non-critical webhook/email notifications
    during a daily window (Settings → Dashboard → Quiet hours; may cross
    midnight). Events still land in the Alerts inbox and Recent Activity;
    anything at/above the chosen severity always pages through.
- **Fleet reporting & integrations (medium).**
  - **SLA / uptime reporting.** Per-device and per-group uptime % over a window
    (7/30/90 days), computed from the uptime transition log, on the Reports
    page; the fleet 30-day uptime is folded into the posture report.
    `GET /api/fleet/sla?days=`.
  - **Capacity dashboard.** Fleet-wide CPU / memory / disk rollup (averages,
    peaks, total disk, top consumers) on the Reports page.
    `GET /api/fleet/capacity`.
  - **Read-only public status page.** A standalone `status.html` (no login)
    shows the fleet health score, device online count, and monitor up/down,
    backed by `GET /api/public/status?token=<status token>` — share the URL for
    a lightweight public status board.
  - **Webhook → on-call/ticketing.** New **PagerDuty** (Events API v2) and
    **Opsgenie** (Alerts API v2) notification destinations alongside the
    existing channels; recover events auto-resolve the PagerDuty incident.

## v3.4.0

Released.

- **Security: stronger password hashing, weak-hash path removed.** When bcrypt
  isn't installed, the `remotepower-passwd` tool and the installer now hash
  admin passwords with salted **PBKDF2-HMAC-SHA256** (600k iterations) — the
  same scheme the server already used — instead of a bare, unsalted SHA-256.
  The installer also passes the password through the environment rather than
  inlining it, so special characters can't break or inject into the setup
  script. The server no longer accepts the **legacy pre-2.3.2 unsalted SHA-256**
  hashes at all (verifying one meant hashing the password with SHA-256, a weak
  algorithm). bcrypt and PBKDF2 hashes are unaffected and still auto-upgrade to
  bcrypt on login. **Action:** any admin whose password hasn't been changed
  since before v2.3.2 must be reset once with `remotepower-passwd` — in practice
  almost no one, since every login since v2.3.2 already upgraded the hash.
- **Reliability & polish.** Pop-up prompts (rename, confirm-to-delete, "describe
  the issue", etc.) now use RemotePower's own styled dialogs instead of the
  browser's native boxes — consistent look, keyboard-friendly (Enter confirms,
  Esc cancels). Outbound-webhook burst protection was widened so a busy
  fleet-wide event isn't throttled, and a round of internal hardening made
  request handling and per-check-in device config more consistent. No change to
  how any feature behaves — these are under-the-hood improvements.
- **UX polish across the new surfaces.** The device drawer's audit panels (now
  14+) render in labeled groups — **Health · Security · Software · Activity ·
  System · Integrations** — instead of one long scroll. Compliance statuses and
  AI-anomaly severities now use the same `sev-pill` vocabulary as the rest of
  the app. New wide tables/modals (compliance, LXC wizard, SMART, discovery)
  scroll instead of overflowing on mobile. Freshly-added nav items carry a
  small **new** badge that clears once you visit them.
- **Delete Proxmox LXC containers.** Each LXC card gets a **Delete** button →
  a type-to-confirm dialog (you type the container's name/VMID). Destructive and
  admin-only: it force-stops a running container, waits for it to go down, then
  deletes it (no purge — backup/replication jobs are left alone). Audited. New
  `delete_lxc` in `proxmox_client.py`; `DELETE /api/proxmox/lxc/<vmid>`.
- **Create Proxmox LXC containers from a wizard.** The Containers page → LXC
  section gets a **Create container** button. The wizard pulls live options
  from the Proxmox API (OS templates, root-disk storages, bridges, next free
  VMID) and creates an unprivileged container in one POST: hostname, template,
  disk size, cores, memory, swap, network (DHCP or static), and a root
  password and/or SSH key. Admin-only, every field validated server-side
  before the API call, and audited (the password is passed straight to Proxmox
  and never logged or stored). New `create_lxc`/`list_templates`/
  `list_storages`/`list_bridges`/`next_vmid` in `proxmox_client.py`.
  Static-IP/gateway validation now range-checks each octet (0–255) and the CIDR
  prefix (0–32) so a typo like `192.168.1.300/33` fails with a clear local error
  instead of an opaque Proxmox 500.
- **Fixed: SMART "UNKNOWN" disks no longer raise false alarms; real failures
  now reliably alert.** A drive smartctl can't assess (USB bridge, virtual
  disk, no SMART support) reports `UNKNOWN` — that was being treated as a
  failure, so it lit up Needs Attention and the device-card badge. Now a single
  shared rule decides "failed" everywhere (event, Needs Attention, badge,
  drawer): SMART says FAILED (or any non-OK status) **or** there are pre-fail
  sector counts; UNKNOWN/PASSED are not failures. The `smart_failure` alert
  also now edge-triggers on the *set* of failing disks, so a second/third disk
  failing re-fires — and a host that was already failing when this shipped
  alerts on its next report instead of staying silent.
- **Webhook send-rate cap.** A global limiter drops outbound webhooks beyond
  **120 per 60 s** (server-wide), so a flapping monitor can't unleash a
  notification storm — while still leaving plenty of headroom for a legitimate
  fleet-wide event (a CVE or kernel rollout fans out one webhook per host).
  Over-cap sends are logged in the webhook log as `rate-limited`. Fail-open:
  a storage glitch never silences alerts.
- **Fixed: new-listening-port detection had silently stopped working** — the
  port-audit step read a per-request sysinfo cache that was never populated, so
  `new_port_detected` never fired. Restored: new ports are again compared
  against the baseline and recorded. (Also unblocks the new resource-forecasting
  and "what changed" history, which used the same cache.)
- **New listening ports are informational by default — no alert.** A new port
  is a useful audit signal but a noisy *alert* (every service restart, new
  container, or dev server opens one), so by default it now lands only in
  **Recent Activity** (and the device's port baseline / drawer) — it no longer
  raises an Alerts-inbox entry, fires a webhook, or posts a Needs-Attention
  card. Want it to nag? Turn any of those channels back on for **New listening
  ports** in Settings → Notifications. (Per-kind channel defaults are new; an
  explicit saved choice always wins.)
- **Host-config enforcement is now an explicit, gated opt-in.** Pushing a
  *desired* host config for the agent to **apply** (it writes `/etc/hosts`,
  netplan, systemd units, users, repos) had silently never happened (the same
  uncached-cache bug). Rather than turn it on for everyone — which would
  suddenly mutate any host with a desired config set — applying now requires a
  per-device **Enforce on host** toggle in the Host Config editor. Off by
  default: a desired config is a drift-monitoring baseline unless you opt in.
  Drift detection was unaffected and always worked.
- **Cross-feature links — the tools now hand off to each other.** Fleet
  anomaly findings link straight to the device drawer and to a prefilled AI
  runbook; compliance FAIL rows get a **Fix →** deep-link to the page that
  remediates them (Patches, CVEs, TLS, Audit, Settings…); discovered LAN hosts
  get **Add as device** (pre-fills the agentless-device form); a failing SMART
  disk, an imminent disk-fill forecast, or a device's CVE findings each offer a
  one-click, context-prefilled runbook; and the drawer's "What changed" links
  to that device's config-drift view. Less hunting between pages.
- **Device cards show a hardware-health pill.** A red **SMART×** or amber
  **kernel** pill appears next to the device name on the Devices page when a
  disk is failing or a newer kernel needs a reboot; clicking it opens that
  device's Health & Hardware section. (`/api/devices` carries a compact
  `hw_health` flag; absent for agentless / pre-v3.4.0 agents.)
- **SMART failures, outdated kernels, and disk-fill forecasts now surface
  fleet-wide.** They already fired webhooks and landed in the Alerts inbox and
  Recent Activity; they now also appear on the home **Needs Attention** digest
  (a dying disk = critical; a newer-kernel reboot = warning; "/ fills in ~N
  days" = warning/critical by urgency), and the new **Hardware health** row in
  the notification routing matrix lets you route them per channel.
- **Disk SMART health.** The agent runs `smartctl` on each physical disk
  (best-effort, skipped if not installed) and reports overall health plus
  the attributes that matter — reallocated/pending/offline-uncorrectable
  sectors, CRC errors, temperature, power-on hours. A FAILED result or any
  pre-fail sector count fires the new **smart_failure** alert (edge-triggered)
  and shows in the device drawer's **Health & Hardware** card.
- **Kernel / livepatch awareness.** Compares the running kernel (`uname -r`)
  against the newest installed kernel package and flags hosts that need a
  reboot to pick it up (new **kernel_outdated** alert). Reads
  `canonical-livepatch`/`kpatch` status where present.
- **Passive hardware inventory.** DIMMs (size/type/speed/serial via
  `dmidecode`), system serial, temperatures (`lm-sensors`), and software-RAID
  array state (`/proc/mdstat`) — all best-effort, shown in the drawer.
- **Resource forecasting.** A compact daily metrics snapshot per device feeds
  a linear projection: *"/ fills in ~18 days at current growth."* Per-mount
  trend (GB/day) and a fill date, soonest first.
- **"What changed?" summaries.** Diffs the daily snapshots over the last
  day/week — pending-update deltas, newly/no-longer listening ports, units
  failed/recovered, reboot-required edges, and per-mount disk growth.
- **On-demand internet speed test.** A drawer button queues a `librespeed-cli`
  run; the agent reports download/upload Mbps + ping/jitter back through the
  command channel. FOSS backend, no EULA prompt; silently unavailable when the
  CLI isn't installed.
- **Local network discovery.** An opt-in per-device LAN scan (passive
  ARP/neighbour table, or an `nmap -sn` sweep when a subnet is given). The
  server cross-references against known device IPs and surfaces the unmanaged
  hosts (`GET /api/discovery`). The agent never enrolls anything itself.
- **Device quarantine.** A per-device admin flag that disables
  exec/reboot/all actions on sensitive hosts — enforced **server-side** at the
  command-queue chokepoint (queued commands are dropped while quarantined;
  poll-interval changes still apply) and audited.
- **Helm release status.** Where `helm` + a kubeconfig are present, the agent
  reports `helm list -A` (visibility only) — release, namespace, chart,
  revision, status — in the drawer.
- **On-demand AI insights.** Four new AI features that ride the existing
  provider layer: **fleet anomaly scan** (`POST /api/ai/anomaly` → ranked
  outliers from the live fleet snapshot), **cron builder**
  (`POST /api/ai/cron` → plain-English → cron expression, validated locally
  with the next 5 run times computed by a stdlib evaluator), **runbook
  suggestions** (`POST /api/devices/<id>/runbook`, RAG-aware), and **CMDB doc
  drafts** (`POST /api/devices/<id>/doc-draft` → Markdown asset page from
  observed state).
- **Compliance reports.** A control-mapped checklist (`GET /api/compliance`)
  that scores PCI DSS / HIPAA / SOC 2 controls **pass/fail/N-A** from data
  RemotePower already collects (patches, CVEs, TLS, firewall posture, MFA,
  audit logging, backups). Honest by design — controls with no signal report
  N-A rather than a false pass. New module `compliance.py`.
- **Synology DSM upgrade over SSH (one button).** Agentless Synology NAS
  devices have no API to trigger a DSM upgrade, so the device's Synology
  panel gets a single **Upgrade DSM & reboot** button that runs the
  built-in upgrade script over SSH (root): it checks for a new DSM and, if
  found, applies it and reboots — launched detached (logs to
  /var/log/dsm-upgrade.log on the NAS). Per-device SSH credentials (a
  private key — preferred, no extra packages — or a password via sshpass)
  are stored write-only; admin-only + audited + per-device opt-in. The SSH
  client lives in ssh_exec.py (pure stdlib, shells out to `ssh`).
  Synology DSM update *status* also now shows in the Patches report (from
  the existing SNMP poll).
- **OPNsense firewall management (REST API).** Agentless OPNsense devices
  get a firewall card (device drawer → Audit → OPNsense) backed by the
  OPNsense API: view, add, enable/disable, and delete **filter** rules and
  outbound/source **NAT** rules. Per-device API key + write-only secret;
  admin-only + audited; new rules land disabled and every change is applied
  to the live ruleset. The OPNsense counterpart to the RouterOS firewall
  console. See `docs/opnsense.md`.
- **RouterOS firewall — NAT add + delete.** The MikroTik firewall console
  could view NAT but only add filter rules and couldn't delete anything.
  Completed the CRUD: add NAT rules (srcnat/dstnat, masquerade/dst-nat/…,
  to-addresses/to-ports), enable/disable NAT rules, and delete buttons on
  both filter and NAT tables. New rules still land disabled for review.
- **RAG over your infrastructure.** The AI assistant now retrieves
  relevant facts from *your* fleet — device state, watched services,
  CVEs, containers, CMDB metadata and asset docs, per-device runbooks,
  recent commands and alerts, plus the RemotePower product docs — and
  injects the most relevant snippets into every request as a cited
  `<retrieved_context>` block. Answers reference your hosts and your
  conventions instead of generic Linux advice, and cite their sources by
  bracketed id (e.g. `[live/web01#cves]`). Pure stdlib, no new
  dependencies. New retrieval engine in `rag_index.py`.
- **Lexical-first, embeddings optional.** Keyword retrieval (BM25 over a
  hand-built inverted index) is the always-on base and works with every
  provider, **including Anthropic**, which has no embeddings endpoint.
  When you run an embedding-capable provider (OpenAI / Ollama / LocalAI)
  and enable embeddings, semantic search is fused with lexical via
  Reciprocal Rank Fusion. Vectors are cached by content hash, so a
  reindex only re-embeds chunks whose text changed.
- **Privacy by construction.** The encrypted credentials vault is never
  indexed (metadata and docs only). History chunks are redacted at index
  time using your AI privacy toggles. Embeddings egress is opt-in and off
  by default for cloud providers; the toggle is pre-checked only for
  local providers, where nothing leaves the building.
- **Settings → AI → Knowledge index.** Enable/disable, pick sources, turn
  on embeddings, set max chunks + history retention, and **Rebuild index**
  with a live status line. A **Test retrieval** box shows exactly which
  chunks a question pulls in (id · kind · device · excerpt, sortable) with
  no model call and no tokens spent.
- **Endpoints.** `GET /api/ai/rag/status`, `POST /api/ai/rag/reindex`
  (admin), `POST /api/ai/rag/search`. Product docs now deploy to
  `/var/lib/remotepower/docs/` (read-only, not web-served) so the indexer
  can answer "how do I do X in RemotePower". See `docs/rag.md`.

## v3.3.4 — unreleased (dev)

In development.

- **Container image-update detection.** The agent now reports each
  container's pulled image digest (`docker/podman images --digests`).
  The server resolves the registry's current manifest digest for that
  `repo:tag` — deduped across the fleet, so the same image on five hosts
  is one registry call — and flags any container running behind it. New
  **Image updates** table on the Containers page (sortable; Image · Tag ·
  Hosts · Status · Registry · Last checked) with a **Scan now** button.
  Registries: Docker Hub, GHCR, lscr.io, Quay, and generic v2.
- **Image-update alerts.** A stale image fires a low-severity
  `image_update_available` event into the alert inbox + webhooks,
  debounced on the digest last alerted (no re-spam across the 12h
  sweep), and auto-resolves (`image_updated`) once every host has pulled
  the current digest. Routable independently via the channel matrix
  ("Container image updates"). Notify-only — RemotePower never pulls.
  Default on; disable with `image_updates_enabled=false`.
- **Compose stacks (upload + deploy).** Upload or paste a
  docker-compose file as a named stack targeted at a device, then
  **up / down / redeploy** it from the Containers page. The agent
  fetches the YAML with its device token (so it never rides the command
  log), writes it under `/var/lib/remotepower/stacks/<name>/`, and runs
  `docker compose` via argv (no shell). **Admin-only, audited, and gated
  behind a per-device `compose_enabled` opt-in (default off)** — a deploy
  can't reach a host until you explicitly enable it there, since it runs
  an arbitrary compose file as root. Status flows back through the normal
  command-output channel. RemotePower runs the file as-is; it doesn't
  sandbox it, build images for you, or auto-restart on changes.
- **Synology NAS monitoring (SNMP).** New `poll_synology` reads DSM
  health from the Synology MIBs (`1.3.6.1.4.1.6574.*`): system / power /
  fan status, temperature, model + DSM version + update-available, and
  per-disk and per-volume (RAID) status. Add the NAS as an agentless SNMP
  device (enable SNMP in DSM → Control Panel → Terminal & SNMP). DSM runs
  net-snmp so its sysObjectID doesn't identify it — the poller probes the
  Synology MIB (one cheap GET; empty for non-Synology) and only then walks
  the disk/RAID tables. Shown in the device's SNMP detail; CPU / memory /
  volume usage already came from the generic UCD/Host-Resources pollers.
- **Agentless reachability (ICMP).** Agentless devices used to be "up"
  forever (a static `manual_status`). They now default to an **ICMP ping
  check** — a cheap-when-not-due sweep pings each one and flips its
  online state, firing `device_offline` / `device_online` (inbox +
  webhooks, 2-fail debounce, Monitored-flag respected) just like agent
  devices. Per-device **Reachability** setting in Actions & Settings:
  *ICMP ping* (default) or *Manual* (set Up/Down by hand, for hosts that
  block ping). `check_offline_webhooks` already skips agentless, so this
  sweep solely owns their up/down.
- **MikroTik RouterOS management (REST).** New `routeros.py` REST client
  (RouterOS **v7+**, HTTPS + basic auth) gives MikroTik devices a
  visibility + management card in the device drawer (agentless devices):
  system + firmware/update state, interfaces with traffic, DHCP leases,
  firewall/NAT counts, routes, wireless clients — plus management actions
  (enable/disable interface, reboot, run a saved script, export config).
  Stored per-device with a write-only password; **admin-only + audited**,
  and management is gated behind the device's RouterOS opt-in. TLS verify
  is off by default (RouterOS self-signed cert). Beyond the SNMP health +
  ICMP reachability MikroTik already had. A full-width **RouterOS console**
  (drawer → Open console) gives the visibility room to breathe, with an
  active **Check for updates** (runs check-for-updates on the router) and
  **Upgrade firmware** (installs + reboots; confirm-gated). RouterOS
  firmware updates also surface on the **Patches page** alongside Linux
  package updates — a periodic check caches installed/latest so the fleet
  has one "what needs updating" view. (Connects even from TLS-1.3-only
  hosts: the client lowers to TLS 1.2 for RouterOS, which maxes at 1.2.)
  The console also has a **Firewall** view: filter + NAT rules in detail,
  per-rule enable/disable, an add-rule form, and **AI** — "Explain" (plain-
  English ruleset summary + risk flags) and "Draft rule" (turns a plain-
  English request into a rule and fills the form). New rules are created
  **disabled** for review; nothing is auto-applied. And a **QoS & traffic**
  view: simple-queue / queue-tree stats, plus **live per-interface
  throughput** (bit/s, from a ~1s two-sample diff — no reliance on
  monitor-traffic streaming).

## v3.3.3 — unreleased (dev)

In development.

- **AI Investigate button on the Alerts inbox.** Each open alert row
  (MAIN → Alerts) gets an **Investigate** button alongside Ack and
  Resolve. It feeds the alert's severity, event type, affected device,
  timestamp, and raw message to the AI and returns what the alert
  means, the most likely cause, and 2–4 concrete next steps or
  commands to verify and resolve it. Backed by a new
  `investigate_alert` system prompt (tunable under Settings → AI).
  Complements the webhook-log "Explain" button, which only rewrites an
  alert into a single paragraph — Investigate is the deeper,
  action-oriented triage.

## v3.3.2 — 2026-05-28

Follow-through on the v3.3.1 UI fixes.

- **Device-table column-shedding now applies everywhere, not just
  installed PWAs.** v3.3.1 scoped the fix to `display-mode: standalone`,
  which missed minimal-ui installs (the PWA default) and the plain
  browser. The breakpoints are now general — whenever the sidebar is
  docked (>720px, not collapsed) the table sheds low-priority columns
  ~200px earlier so the Status pill can't collapse to a lone `…`. A
  width-independent backstop (`.dev-status-cell { overflow: visible }`)
  guarantees no ellipsis regardless of display mode or width.
- **PWA cache delivery.** The service worker is cache-first keyed to
  `?v=<version>`; v3.3.1's later UI commits kept `?v=3.3.1`, so installed
  PWAs served the stale stylesheet and never saw the fixes. The bump to
  v3.3.2 changes `?v=` + `CACHE_NAME`, forcing a refetch — no manual
  cache clear required.
- **Devices-table dots — final fix.** The `overflow: visible` backstop
  alone still left a stray `…` on whichever cell was most squeezed
  (Chrome paints the ellipsis glyph for any clipped cell; Firefox
  doesn't). Switching the whole table to `text-overflow: clip` removes
  the glyph entirely, regardless of which column is narrow.
- **Emoji purge completed.** Residual emoji the v3.3.0 sweep missed
  (`🩺` on the Investigate button, `⚙` on Fine-tuning, `⛔` on the
  command denylist warnings, plus stale doc mentions) → Lucide SVG or
  plain text.
- **Per-device "Prioritise CVEs" AI button** on the CVE page — a
  sparkle on each device row with findings that asks the AI for a ranked
  remediation plan (new `prioritise_cves` system prompt, mirroring
  `prioritise_patches`). The CVE page now has both Prioritise (per
  device) and Triage (per finding).

## v3.3.1 — 2026-05-28

Correctness + polish release on top of v3.3.0. No breaking changes, no
schema changes. Headline is a rework of OFFLINE detection that ends the
device flapping seen in production; the rest is a sweep of live-instance
bugs and UI consistency fixes found while preparing for public
production. The service-worker cache version is bumped, so installed
PWAs pick up the UI fixes automatically.

### OFFLINE detection hardening

- **OFFLINE no longer fires on a single sample.** The per-request sweep
  decided offline the instant one read saw `delta > ttl`, so a late
  beat, a stale read landing before an in-flight heartbeat's rename, or
  the lost-update race produced `OFFLINE` → `ONLINE` in the same second.
  Three layers now guard the decision via `_offline_thresholds`:
  - a fixed jitter **grace** (`OFFLINE_GRACE_S`) folded into the cutoff;
  - a **per-device threshold**,
    `max(global ttl, poll_interval × OFFLINE_MISSED_POLLS) + grace`, so a
    30s poller and a 600s poller no longer share one cutoff;
  - a **debounce** (`offline_pending`): the first sweep past the
    threshold only arms a candidate; `OFFLINE` fires only if a later
    sweep ≥1 poll interval on still sees it silent. A live device beats
    in between and clears the candidate. Recovery stays immediate.
- **Offline bar is now 5 missed polls** (`OFFLINE_MISSED_POLLS = 5`) —
  300s at the default 60s poll, matching `DEFAULT_ONLINE_TTL`.
- `offline_pending` is managed wherever `offline_notified` is, and is
  purged on device delete (which previously leaked `offline_notified`).

### Bug fixes

- **Agent patch status no longer false-warns on clean hosts.**
  `get_patch_info()` distinguished `pacman -Sy` from `pacman -Qu`
  failures with `'pacman -Qu' in str(e.cmd)`, but `str(['pacman','-Qu'])`
  never contains that substring, so every normal `pacman -Qu` exit-1
  ("no upgrades") was reported as `pacman sync failed (rc=1)`. The two
  commands now sit in separate try blocks.
- **Home dashboard CVE/drift counts match the detail pages.** `/api/home`
  aggregated by iterating `cve_findings.json` / `drift_state.json`
  directly, so stale records for deleted devices inflated the tiles. Both
  aggregators now iterate live device ids, matching the detail handlers.
- **Settings reflect real runtime defaults.** `handle_config_get()` only
  echoed keys present in `config.json`, so v3.3.0 flags rendered "off" on
  servers that never set them (notably `webhook_block_local`, whose
  runtime default is "on"). The handler now `setdefault()`s those flags.
- **Fleet events honour `?event=`.** `handle_fleet_events` ignored the
  query filter the UI timeline relies on; it now filters by event name
  (multiple values OR together; unknown names return empty).

### UI

- **Action buttons aligned across pages.** Edit/Delete/Revoke siblings
  mixed 14px icons with raw glyphs (`×` / `✗`) and one-off padding, so
  paired buttons were different sizes; they now share a class and icon
  style. The ACME **force-renew** button — previously rendered with no
  icon — gets its refresh icon.
- **PWA clipping fixed across installed modes.** The docked ~220px
  sidebar wasn't subtracted from the device-table column breakpoints, so
  a narrow PWA window collapsed the Status pill to `…`; the nav scrollbar
  also clipped the "MCP Confirmations" badge. Fixed, scoped to
  `not (display-mode: browser)` so it covers minimal-ui and standalone
  installs (but never the browser tab), with a backstop so the Status
  pill can't render an ellipsis. The PWA manifest now defaults to
  `minimal-ui` for new installs.
- **Maintenance windows show the device hostname** instead of the opaque
  device id (resolved in the list endpoint as `target_name`).
- **"Did you know?" tips on the About page** surface lesser-known
  features, with a button to cycle through them.

## v3.3.0 — 2026-05-27

Audit follow-up release. Three Explore agents swept the code for bugs,
performance issues, and security weaknesses; this release ships the
agreed plan (Phases A–D) end-to-end plus a hash-driven agent self-
update mechanism. No breaking changes; defaults that previously
prioritised compatibility now prioritise safety where it doesn't cost
operator UX.

### Correctness (Phase A)

- **process_service_report and _record_service_transition no longer
  race on concurrent heartbeats.** Both used bare `load()` + `save()`
  on `services.json` / `service_history.json`. Two agents reporting
  at the same time could lose transitions or fire duplicate webhooks.
  Both now use `_LockedUpdate`; transition fires happen after the
  lock releases so slow webhook destinations can't hold the file.
- **`/api/status` `'high load'` flag fixed.** The Python expression
  was `... > os.cpu_count() * 2 if os.cpu_count() else 999` —
  parsed as `(compare) if cpu_count else 999`, so when `os.cpu_count()`
  returned None/0 the entire expression evaluated to 999 (truthy)
  and `'high load'` fired on every status response.
- **`handle_device_delete` cleanup serialised.** All per-device store
  cleanups (CMDS, CONTAINERS, PACKAGES, SERVICES, LOG_WATCH,
  CMD_OUTPUT, UPDATE_LOGS, METRICS, UPTIME, DRIFT_STATE,
  FLEET_EVENTS, service_history, config stale-notified flags) now
  go through `_LockedUpdate` so a concurrent heartbeat can't re-add
  data we just removed.
- **`_compute_attention` loaded `CONFIG_FILE` four times per call.**
  Now loaded once at function top. Saves ~3 disk reads on every
  Home refresh + every badge tick.

### Performance (Phase B)

- **`GET /api/devices?slim=1`** omits the heavy fields (`sysinfo`,
  `listening_ports`, `brute_force_active`, full SNMP metrics). The
  Devices page and CMDB modal opt out by not passing the flag.
- **`GET /api/home`** — one round-trip serves the entire Home
  dashboard. Replaces the 7 parallel `/api/*` calls `loadHome()`
  used to fire on every 60s refresh. CGI = a fresh Python process
  per request, so this cuts dashboard refresh cost by 7×.
- **`GET /api/devices/sysinfo?ids=a,b,c`** — batch endpoint for the
  Monitoring page. `loadListeningPorts` and `loadProcesses`
  previously made 1 + N requests per page load; now one CGI process.
- **File-backed 10s cache for `/api/attention`.** Cache busts when
  any of `devices.json`, `fleet_events.json`, `cve_findings.json`,
  `drift_state.json`, or `ignored_items.json` is newer than the
  cache — heartbeats, scans, and ignore-toggles all show up
  immediately.
- **`_detect_brute_force` short-circuits before loading
  `BRUTE_FORCE_FILE`** when there are no lines to scan or no
  patterns match. An idle host with logs that never trip an SSH
  brute-force signature no longer churns the state file.

### Security (Phase C)

- **Per-IP rate limit on `POST /api/enroll/register`** (10/min/IP).
  The PIN namespace is 10⁶ with a 10-minute window; without
  throttling, brute-forcing the whole PIN space from one IP took
  minutes. Shared helper `_ip_ratelimit()` backs this.
- **Per-IP rate limit on `POST /api/login`** (20/min/IP) layered on
  top of the existing per-username lockout. The username gate
  stops single-account brute-force; the IP gate stops credential-
  stuffing across thousands of usernames from one source.
- **SSRF default flipped.** `webhook_block_local` now defaults to
  `True`, blocking link-local targets (cloud metadata services at
  169.254.169.254) and unspecified addresses. Loopback
  (127.0.0.1, ::1) is still allowed by default via a new
  `webhook_allow_loopback` flag so homelab Gotify/ntfy sidecars
  keep working.
- **Optional admin-only alert mutation** via `viewers_can_ack_alerts`
  (default True for back-compat). When set to False, ack/unack/
  resolve require admin role.
- **Re-enrollment hardening.** The existing gate (existing
  device_id requires current device token via `hmac.compare_digest`)
  is already sound; v3.3.0 adds two things: token rotation on
  successful re-enrollment (so a one-time leak is self-limiting)
  and audit-log entries for both `reenroll` and `reenroll_denied`.

### Agent self-update (Phase D / hash-driven)

- **`check_for_update` is now hash-driven, not version-driven.** The
  agent computes its own binary's sha256, fetches the server's
  canonical sha256 from `/api/agent/version`, and updates on
  mismatch in either direction. Same-version rebuilds, downgrades
  to a known-good binary, and operator-initiated re-pushes all
  trigger the update reliably. Version strings remain in the
  response and the logs for human context but are not the decision
  signal.
- **Server caches the agent sha256** to a sidecar `.sha256` file
  next to the binary so CGI requests don't re-hash every poll.
- Downloaded bytes still verified against the advertised sha256
  before swapping the binary — same constant-time check as before.

### Reliability

- **`_record_fleet_event` archive write moved outside the flock.**
  The gzip append previously held the FLEET_EVENTS_FILE lock
  during decompress-trailing-block + write + flush — serialising
  every concurrent heartbeat behind one slow archive write. Lock
  now scopes the append + trim only.
- **`GET /api/devices?limit=N&offset=N`** — optional pagination
  for very large fleets. No-op by default; stable sort order so a
  paged client walking with increasing offset is deterministic.

### Follow-up additions (still under v3.3.0)

After the initial Phase A–D ship, the rest of the release picks up
the operator-feedback items, the four integrations the user named,
and the documentation refresh.

**Channel routing matrix** (Settings → Dashboard). One matrix per
event kind × four surfaces (Needs Attention, Recent Activity,
Alerts inbox, Webhook). Replaces the prior scattered hide-this-kind
toggles plus the implicit per-event webhook gate. Legacy
`dashboard_hidden_*` config auto-migrates on first read.

`_ALERT_RULES` extended so events that fired webhooks but never
reached the Alerts inbox — `brute_force_detected`, `backup_stale`,
`snapshot_old`, `reboot_required`, `new_port_detected`,
`ssh_key_added`, `monitor_down` — now do. `monitor_up`
auto-resolves the matching `monitor_down` via label+target
sub-match (no device_id needed).

**Log alert improvements**:
- Sample-in-summary: Needs Attention cards, Alerts-inbox titles, and
  webhook subjects show the matched log line (truncated) rather than
  the rule regex. NA card hover tooltip exposes the full pattern + up
  to three captured matches.
- Per-rule `display_template` field with `{device}`, `{unit}`,
  `{pattern}`, `{count}`, `{sample}`, `{sample0..2}` placeholders.
  Live preview in the rule modal.
- Per-rule `exclude_pattern` (regex) skips matching lines before the
  threshold count. Stops Postfix-style warning noise without
  disabling the rule.
- Inline NA card actions: 24h snooze (auto-returns) and "Open in
  Logs" deep-link to the device + unit.

**Uninstall agent** action in the device drawer. Server queues an
`uninstall` command; on next heartbeat the agent stops + disables
its systemd unit, deletes credentials + state + binary, exits via a
detached trampoline. Device record stays so history / tags / groups
survive. Re-heartbeat from the same host clears the badge.

**Integrations**:
- **Healthchecks.io watchdog** — server pings a configurable URL
  every 60 s so an external monitor flips red when RemotePower
  itself stops responding. Settings → Notifications. 5 s timeout;
  failures never propagate into the request pipeline.
- **Prometheus `/api/metrics` status-token auth** — the existing
  endpoint now accepts the status token via `?token=…` in addition
  to session bearer. Standard Prometheus scrape configs work
  without renewing session tokens.
- **GitHub issues** as a webhook destination format. Fine-grained
  PAT with `issues:write` scope. Issue body: human-readable message
  + raw payload in a fenced JSON `<details>`. Labels =
  `["remotepower", "<event>", "<severity if known>"]`.
- **Central ACME DNS-01 credentials** (TLS / DNS page → "DNS
  provider credentials"). 12 providers: Cloudflare, Hetzner,
  Route 53, DigitalOcean, Gandi, OVH, Porkbun, Hurricane Electric,
  deSEC, Namecheap, NameSilo, RFC 2136, acme-dns. Values inject as
  env vars into the queued `acme.sh --issue` command at issuance
  time, so the operator no longer has to hand-edit
  `~/.acme.sh/account.conf` on each device.
  `_scrub_acme_credentials()` redacts secrets from the audit log
  and any UI surface that displays the queued command.

**Edit buttons across operator-managed lists**. Every list that
had Add + Delete now has Edit: log alert rules (per-device +
global), maintenance windows, monitors, TLS targets, backup
monitors, command snippets, scheduled jobs, inbound webhook tokens
(label + scope), users (role), log-ignore patterns. Rotate-only
surfaces (MCP API keys, status token, the opaque secret inside an
inbound webhook token) stay rotate-only by design.

**Emoji-free UI**. The dashboard previously mixed colourful emoji
glyphs with crisp Lucide-style SVGs in the sidebar; replaced every
visible emoji with an SVG via a new `_icon()` helper + the `_ICONS`
dictionary, plain ASCII where decoration was redundant, or removed
where the icon added nothing. Device-icon palette migrated from
emoji to 22 Lucide SVG names; legacy emoji values still render via
fallback. The `applyAiIdentity()` AI-button class stamping now
matches by `data-action` regex instead of sniffing for `✨` in
button text. README + features.md + in-app help-card emoji-free.

**Mobile UX polish**. Two media-query blocks (≤ 720 px and ≤ 480 px)
bring touch targets up to ~44 px, modals go full-viewport with a
sticky action row on phones, device drawer action grid becomes 2-up
(1-up under 480 px), settings tabs wrap into a 3-up grid, all
`.table-card` tables get horizontal scroll with
`-webkit-overflow-scrolling: touch`, form inputs use 16 px font
size so iOS Safari doesn't zoom on focus.

**Operator-reported bug fixes**:
- Dashboard "Critical CVEs" tile honoured the operator's
  `cve_ignore.json` — was showing 3 critical when the CVE page (which
  applies the filter) correctly showed 0.
- Monitoring → Processes sort no longer freezes the browser. The
  static `<thead>` was accumulating click handlers exponentially
  because `_wireHeaders` called `addEventListener` on every
  `wireSortOnly` invocation. The wiring is now idempotent via a
  `dataset.sortWired` flag.
- Monitor targets and TLS / DNS expiry targets gain Edit buttons
  (was Add + Delete only). TLS update preserves the cert's last_check
  / status / days_left / issuer / chain so editing doesn't reset
  the row to "never scanned".
- CMDB device-name cell is now clickable (opens the asset, same as
  the Open button — operators kept trying to click the name).
- Offline check exempts the device that's currently heartbeating
  via `_peek_heartbeat_dev_id()`. Kills the false-positive
  `OFFLINE → ONLINE` flap that fired at the TTL boundary when one
  heartbeat landed at 181 s after the previous commit.
- IP allowlist save handler refuses to enable the gate if the
  caller's IP isn't already in the list — operators can't lock
  themselves out with one click.

**Documentation refresh**. README rewritten without emoji, feature
list extended for v3.3.0. `docs/features.md` gains a "v3.3.0
additions" section covering every operator-visible change.
`docs/README.md`, `docs/api.md`, `docs/ai.md`, `docs/mcp.md`,
`docs/scripts.md`, `docs/custom-scripts.md`, `docs/acme.md` all
have emoji stripped. In-app help / "What's new" doc-card added at
the top of `#docs-container` (defaults to open) so operators see
the v3.3.0 surface without leaving the dashboard.

### Tests

- 1774 unit tests, all passing.
- New `tests/test_v330.py` strict-pin file with regression tests
  for every Phase A–D fix.
- `tests/test_v322.py` strict pins loosened to regex
  (per the standard release convention).

## v3.2.2 — 2026-05-27

Hotfix release. No new features; all changes are bug fixes and configuration
corrections surfaced by real-fleet debugging on a v3.2.1 deployment.

### Fixed

- **Race condition in offline/online detection** (`check_offline_webhooks`).
  Two or more concurrent CGI processes could both observe `offline_notified={}`,
  each fire `device_offline`, and write duplicate alerts and fleet events. The
  read-check-write sequence is now serialised under `_LockedUpdate(CONFIG_FILE)`;
  webhooks and uptime recording fire outside the lock. Same fix covers the
  `patch_alerted` deduplication dict.
- **Debug log timestamps were local time instead of UTC.** Heartbeat entries
  used `datetime.now()` (server local time, CEST) while browser-side entries
  use `toISOString()` (UTC), making the unified debug.log timeline unreadable
  across a 2-hour gap. Both server-side write sites now emit UTC.
- **`online_ttl` example value in source comment was 180.** That value was
  taken as gospel by at least one deployment. `MIN_ONLINE_TTL` dropped from
  300 → 150 in v3.2.1, making a previously-clamped 180 s setting take effect
  and flip devices offline after just 3 missed heartbeats. Comment now shows
  the default (300 s).
- **`MAX_FLEET_EVENTS` raised from 200 → 1000.** The previous cap was sized
  for quiet fleets; active fleets (or fleets with the above race condition
  firing duplicate events) rolled over the Home dashboard activity log in
  under an hour.
- **nginx `client_max_body_size` raised from 64 KB → 2 MB** in both
  `server/conf/remotepower.conf` and `docker/nginx-docker.conf`. The
  server-side limit was raised to 50 MB in v1.7.0 for package-list uploads
  but the nginx configs were not updated. Systems with ≥ ~850 installed
  packages were silently receiving HTTP 413 on every `/api/packages` POST,
  leaving the CVE scanner with a stale or empty package list.
- **nginx rate-limit comment corrected.** The example zone used `rate=30r/m`
  (30 requests per minute per IP). On a LAN where all fleet devices share one
  NAT address, that rate is exceeded by normal heartbeat + browser polling
  traffic. Comment updated to `10r/s` with an explanatory note.

- **Scheduler cron jobs fired dozens of times per minute.** `process_schedule()`
  runs on every CGI request. `_cron_matches()` returns `True` for the entire
  60-second window of the matching minute, so every heartbeat and browser poll
  within that window fired the job again — producing 20+ duplicate
  `upgrade_packages` dispatches per scheduled run. Fixed by stamping
  `last_fired_minute` (epoch // 60) on each recurring job when it fires and
  skipping cron evaluation if the minute has not advanced.
- **Alerts "Mark all" checkbox threw `TypeError: btn is undefined`.** The
  select-all checkbox used `data-action="toggleAllAlerts"` which calls
  `fn()` with no arguments; the function then read `btn.checked` on
  `undefined`. Fixed by switching to `data-change` dispatch which passes the
  checkbox's checked state directly, and updating the function signature to
  match.
- **Monitoring → Custom Scripts sort buttons missing.** The results table
  (`Script / Device / Group / Status / Last output / Last run / Duration`)
  had no `wireSortOnly` wiring, so headers were never made clickable. Fixed
  by adding `wireSortOnly` + `sortRows` to `renderCustomScriptsPage`.

### Changed

- **Sortable tables** — Alerts inbox, CMDB, Drift, ACME certificates,
  Webhook log, Confirmations, Inbound webhooks, Scripts, Listening Ports,
  and Monitoring Custom Scripts results now support click-to-sort column
  headers (shift-click for multi-column). Sort state is persisted in UI prefs.
- **Drift table header corrected.** The thead previously had 4 columns
  (Drift, Missing, Last check, actions) while the tbody rendered 7; Device
  and Group columns were present in rows but had no corresponding headers.

## v3.2.1 — 2026-05-26

Follow-up release on top of v3.2.0. Same big features (alerts inbox,
inbound webhooks, MCP write tools, OIDC SSO, SNMP polling, syslog
ingestion) plus a substantial operability pass driven by real-world
testing on the deployed v3.2.0. No schema migrations.

### Added

- **SNMP integration into the rest of the dashboard.** Beyond the
  initial sys-group poll, every 5-minute sweep now also walks
  `hrProcessorTable` (per-core CPU %), `hrStorageTable` (memory +
  filesystems with used %), the UCD-SNMP-MIB (load averages + raw
  CPU ticks + UCD memory totals), and vendor MIBs (Mikrotik temp /
  voltage / CPU MHz, Ubiquiti UAP/UDM/USW model + firmware + radio
  client counts).
- **SNMP threshold pipeline.** SNMP-derived metrics now fire the same
  `metric_warning` / `metric_critical` / `metric_recovered` events
  as the agent path. Two new metric kinds (`snmp_cpu`, `temp_board`/
  `temp_cpu`); disk/memory percent share the agent's thresholds.
  Defaults: SNMP CPU warn 75 / crit 90 ; temperature warn 70 / crit 85.
- **`snmp_unreachable` / `snmp_dead` / `snmp_recover` events.**
  Unreachable fires at the 2nd consecutive poll failure (single-packet
  UDP loss never alerts); `snmp_dead` escalates at the 72nd
  consecutive failure (~6 hours) at severity=critical; `snmp_recover`
  auto-resolves both rows in the Alerts inbox.
- **`mcp_confirmation_expired` event.** When a pending MCP write
  confirmation ages out at the 1-hour TTL without an operator
  decision, the prune sweep now fires this event into the Alerts
  inbox so silent timeouts don't disappear.
- **MCP write-tool pre-validation.** `run_saved_script` now validates
  the `script_id` BEFORE queuing a confirmation. Bogus IDs return
  400 immediately rather than parking a doomed confirmation.
- **Device Metrics split** — Monitoring → Device Metrics now renders
  agent and SNMP devices in separate tables with appropriate columns
  each. SNMP table has CPU%, Memory%, Storage, Temperature, Uptime;
  agent table is unchanged.
- **Devices page SNMP filter.** Dropdown: Any SNMP / Configured / OK
  / Failing. Quick way to scope to broken SNMP without scanning every
  card.
- **Inbound webhook + syslog hit log** (`inbound_webhook_log.json`).
  Server Status grows a separate "Inbound webhooks & syslog" card
  alongside outbound delivery stats. Both 24h/7d rates with by-kind
  breakdown.
- **Site health card on Server Status.** Load average (1/5/15 min
  from `/proc/loadavg`), system memory % (from `/proc/meminfo`),
  active session count, devices-online %, plus an `ok`/`warn` rollup
  with reason flags.
- **Clear-alerts endpoints + UI.** `DELETE /api/alerts?scope=resolved`
  purges every resolved row; `?scope=all` wipes everything. Toolbar
  buttons "Clear resolved" and "Clear all" on the Alerts page.
- **OIDC test endpoint.** `POST /api/auth/oidc/test` (admin) probes
  the configured issuer, returns the discovered endpoints + warnings
  for common misconfigs. "Test discovery" button on the OIDC pane.
- **Alerts + MCP Confirmations green-at-zero badges.** Always
  visible: green at 0, red at >0. Replaces the disappear-when-empty
  state that operators read as "no inbox exists".
- **README gallery.** Click-through screenshot gallery via GitHub
  `<details>` accordion. Index.png remains the hero.

### Fixed

- **Unmonitored devices polluted the Alerts inbox.** `_record_alert`
  ran BEFORE `fire_webhook`'s monitored-gate. Now mirrors the same
  check — unmonitored devices skip the inbox write too, matching the
  webhook fan-out posture. Fleet-wide events and orphan-device events
  still record.
- **Webhook delivery rate misreported as ~10%.** Server Status
  treated `disabled` / `suppressed` / `filtered` log entries as
  failed delivery attempts. They're decisions to skip, not failures.
  Rate now computed over true attempts only; `skipped` reported
  separately. Site-health flag ignores the all-skipped case.
- **`metric_critical` never landed in the Alerts inbox.** Event was
  absent from `_ALERT_RULES` so 90%+ disk/memory/CPU events fired the
  webhook but never created an inbox row. Now severity=critical in
  the inbox.
- **`_fire_metric_webhook` payload.** Used `kind` while the alert
  inbox expected `metric`. Added `metric` + `level` aliases so titles
  and severity classification work for both threshold paths.
- **MCP write tools — bogus `script_id`.** Used to return 202 +
  confirmation_id even when the referenced script didn't exist.
  Approval would have failed silently. Pre-validation in
  `_mcp_validate_params` fires 400 before the confirmation queue.
- **Sidebar 200 → 220 px.** "MCP Confirmations" + count badge clipped
  at 200 px. Bumped width and matching `.app-content` margin.
- **Duplicate "TLS / DNS" title above ACME Certificates.** Moved
  the title inside the expiry panel so it disappears when viewing
  the ACME panel (which has its own title).

### Security

- **Bearer auth parity audit.** v3.2.0 generalized
  `Authorization: Bearer` to every endpoint (was previously only
  `/api/metrics`). Audit completed: token verification is uniform,
  `X-Token` wins when both headers are present, same-origin check
  runs before dispatch. Notes in `docs/security.md`.
- **Webhook log capacity** bumped 100 → 500 entries so the 24h-window
  rate calc survives a noisy day.
- **MCP confirmations TTL** unchanged at 1 hour; expired rows now
  also fire `mcp_confirmation_expired` so silent ageing is visible.
- Service-worker cache name bumped to `remotepower-shell-v3.2.1`.

## v3.2.0 — 2026-05-26

Feature release: alert inbox with ack/resolve lifecycle, inbound
webhooks from external systems, MCP Stage 4 write tools, OpenID
Connect SSO, SNMPv2c polling for agentless devices, and syslog HTTP
ingestion. No schema migrations.

### Added

- **Alert inbox (B1).** Every actionable webhook event (`device_offline`,
  `cve_found`, `service_down`, `tls_expiring`, `custom_script_fail`, …)
  now writes a row to a mutable ledger at `alerts.json`. Sidebar gets
  a top-level **Alerts** entry with a count badge. Recover events
  (`device_online`, `service_recover`, `custom_script_recover`)
  auto-resolve the matching open alert. Filter views: Open /
  Acknowledged / Resolved / All. Bulk-resolve via checkbox column.
- **Inbound webhooks (B2).** New Settings → Integrations pane creates
  long-secret receive tokens. `POST /api/webhook/in/<token>` accepts a
  small JSON shape (`severity`, `title`, optional `device`, `body`,
  `links`) and routes the alert into the Alerts inbox (B1). Tested
  shapes: Grafana, Alertmanager, Authelia/Authentik, Home Assistant,
  n8n. No outbound fan-out by default.
- **MCP write tools — Stage 4 (A1).** `MCP_ACTION_ALLOWLIST` populated
  with: `reboot_device`, `run_saved_script`, `force_package_scan`,
  `force_acme_rescan`. Destructive tools against devices with
  `require_confirmation=true` return 202 with a `confirmation_id`;
  admin approves at **Admin → MCP Confirmations** before anything
  runs. Audit log records `ai_host` (X-MCP-Client header) and
  `ai_prompt` (X-MCP-Prompt header) on every call. MCP server
  (`mcp/remotepower-mcp.py`) bumped to v3.2.0 with the four write
  tools exposed.
- **OIDC SSO (B3).** Standard confidential-client authorization code
  flow. Configure in Settings → Integrations → OIDC: issuer, client
  ID/secret, scopes, optional admin group. Login page picks up
  `oidc_enabled` from `/api/public-info` and shows a "Sign in with
  SSO" button. Auto-provisions local user on first sign-in with role
  mapped from group membership. Promotes viewer→admin on subsequent
  logins; never auto-demotes. Tested against Authelia, Authentik,
  Keycloak.
- **Bearer auth everywhere.** `get_token_from_request()` now accepts
  `Authorization: Bearer <token>` in addition to `X-Token`. The MCP
  client sends both for compatibility.
- **SNMPv2c polling for agentless devices (B5).** New `server/cgi-bin/snmp.py`
  ships a pure-stdlib SNMPv2c GET client (~300 lines, no pip deps).
  Agentless devices gain a "SNMP" tab in the CMDB asset modal where
  admins enable polling and provide a community string + port. The
  server runs a 5-minute background sweep collecting the sys-group
  OIDs (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`,
  `sysLocation`); operators can "Poll now" from the SNMP tab. Latest
  result lands in `snmp_data.json` and renders in the same tab.
  Community strings are write-only via the API — GET responses redact
  to a preview only.
- **Syslog HTTP ingestion (B6).** Settings → Integrations now creates
  two kinds of inbound tokens — alert webhooks and syslog. Syslog
  tokens accept JSON (`{lines:[...]}`) or plain text at
  `/api/syslog/in/<token>`; RFC 3164/5424 `<PRI>` prefixes are
  parsed for severity. Lines append to the device's `log_watch` under
  unit `syslog`, and existing per-device + global log_alert rules
  fire as if they came from the agent. Suits rsyslog `omhttp`,
  fluent-bit HTTP output, or any tool that can POST.

### SNMP integration follow-up

- **Devices page surfacing.** Agentless device cards now show an
  SNMP status pill (green=polling OK, red=polling failing) next to
  the hostname, plus a "SNMP up Nd" meta cell. The pill tooltip
  carries `sysName` and the most recent error if any. Operators no
  longer need to click into CMDB → SNMP tab to spot a dead switch.
- **`snmp_unreachable` / `snmp_recover` webhook events.** Edge-
  triggered on the **second** consecutive poll failure (single-packet
  UDP loss never alerts). On recovery, the matching open alert in
  the inbox auto-resolves with `resolved_by='auto'`, same as
  `device_offline` / `device_online`. Unmonitored devices skip
  both the background sweep and the webhook fire.
- **MCP `get_snmp_data` read tool.** AI clients can now answer
  "is the core switch up?" via MCP. Returns the full sys-group
  readings + last_ok / last_error.

### Notification badges (#1 follow-up)

- **Sidebar badges are always visible.** "Alerts" and "MCP
  Confirmations" both now render a count badge that's green at 0
  and red at >0, instead of disappearing when empty. The all-clear
  signal was previously read as "nothing to look at" — the badge
  is now a present-tense status indicator.

### v3.2.0 follow-up batch (operability hardening)

- **Webhook log capacity** bumped from 100 → 500 entries. Tight cap was
  flushing real deliveries out of the 24h rate window within hours on
  fleets with frequent suppressed events.
- **Inbound webhook + syslog hit log** added (`inbound_webhook_log.json`).
  Every inbound POST is recorded with its HTTP status, token id, and
  detail. Server Status grows a new "Inbound webhooks & syslog" card
  showing 24h/7d hit rates split by kind.
- **`mcp_confirmation_expired`** webhook event. When a pending MCP
  confirmation ages out at the 1-hour TTL without an operator
  decision, the prune sweep now fires this event (severity: medium)
  so the silent-timeout case lands in the Alerts inbox.
- **`snmp_dead` escalation event**. After 72 consecutive failed polls
  (~6 hours at the 5-minute cadence), a second alert fires at
  severity=critical alongside the original `snmp_unreachable` (high).
  Both auto-resolve on `snmp_recover`.
- **Devices page SNMP filter**. New "Any SNMP / Configured / OK / Failing"
  dropdown next to the status filter — scope the device list to "show
  me everything where SNMP is broken" in one click.
- **Bearer auth security review**. `get_token_from_request()`'s Bearer
  fallback (v3.2.0 initial) audited: token verification is uniform,
  same-origin check still runs before dispatch, X-Token wins when both
  headers are present. New regression suite confirms parity between
  X-Token and Authorization Bearer auth across role gates. Notes
  appended to docs/security.md.

### Webhook delivery rate accuracy

- **Suppressed/disabled/filtered entries no longer count as failed
  attempts.** The Server Status webhook-rate widget used to read
  `1/10 = 10%` on a fleet where every event was operator-suppressed,
  even though every actual outbound POST succeeded. Now the rate is
  computed over true delivery attempts only; suppressed entries
  surface separately as a `skipped` count. Site-health flagging on
  `< 90%` rate also ignores the all-skipped case.

### Changed

- `/api/public-info` adds `oidc_enabled` so the login page can render
  the SSO button without authenticated access.
- New audit-log actions across all four features (full list in
  `docs/v3.2.0.md`).

### Security

- OIDC: id_token signature is not verified — we rely on the
  back-channel HTTPS POST + client_secret authentication to the token
  endpoint (RFC 6749 confidential-client posture). State + nonce are
  both validated. State storage TTL is 10 minutes.
- MCP: all destructive write tools gate through `require_mcp_action()`
  + per-device `require_confirmation`. Admins explicitly cannot call
  the MCP write endpoints — separation keeps the audit log unambiguous.
- Inbound webhook tokens are 32-byte hex secrets with `rpwi_` prefix
  for grep-ability; never reshown after creation.
- Service-worker cache bumped to `remotepower-shell-v3.2.0`.

## v3.1.0 — 2026-05-26

Major UX release: focused sidebar subcategory views, collapsible Help
group, TLS/DNS Expiry split from ACME Certificates, and the full
grouped-navigation overhaul from v3.0.7. No schema changes; no
migrations required. Drop in the new tarball, reload nginx, hard-reload
the browser once to pick up the updated service worker cache
(`remotepower-shell-v3.1.0`).

### Added

- **Focused sidebar subcategory views.** Each sidebar sub-item now shows
  only its own content section when clicked, keeping the page uncluttered:
  - **Monitoring** sub-items: Targets, Device Metrics, Listening Ports,
    Custom Scripts — each shows only that section.
  - **Containers** sub-items: Docker/Podman/K8s and Proxmox LXC — each
    shows only that panel. When navigating directly to Proxmox LXC on an
    unconfigured node a helpful hint is shown instead of a blank screen.
  - **Security → TLS** sub-items: TLS/DNS Expiry and ACME Certificates
    are now separate sidebar entries showing only their respective panel.
  - Navigating to the group's top-level page (keyboard shortcut, command
    palette) still shows all panels together.

- **Collapsible Help group.** Documentation, AI Assistant, API Reference,
  and About are now inside a collapsible sidebar group (`data-group="help"`)
  with state persisted in `localStorage`. Expanded by default.

- **Grouped sidebar navigation** (carried from v3.0.7 dev branch):
  Five collapsible groups — Fleet, Monitoring, Security, Planning, Admin —
  plus standalone Home and Links entries. Admin collapses by default; all
  others expand by default. State persisted in `localStorage`.

- **Links moved to top level.** Links page promoted from Admin to a
  standalone sidebar entry above the Fleet group for faster access.

- **Audit Log moved to Security group.** Contextually placed next to CVEs,
  Patches, and Drift.

- **Calendar recurring events** (carried from v3.0.7).

### Fixed

- **CSP `style-src-attr` violation.** An inline `style="width:100%"` on
  the sidebar documentation table was blocked by the strict CSP policy.
  Replaced with utility class `isl-770` and a corresponding CSS rule.

- **Modal delete buttons invisible.** `element.style.display = ''` cleared
  the inline override but allowed a `d-none` class to silently win. Fixed
  by explicitly setting `'block'`.

### Security

- All pages continue to carry the same strict Content-Security-Policy
  (`default-src 'self'`, no `unsafe-inline`, `unsafe-eval`).
- Service-worker cache name bumped to `remotepower-shell-v3.1.0` so
  stale caches are evicted on first activation.

## v3.0.7 — 2026-05-26

UX overhaul: grouped sidebar navigation, calendar recurring events, and
quality-of-life improvements across monitoring and server management. No
schema changes; no migrations required. Drop in the new tarball, reload
nginx, hard-reload the browser once to pick up the updated service
worker cache (`remotepower-shell-v3.0.7`).

### Added

- **Grouped sidebar navigation.** The flat list of links is now organised
  into five collapsible sections that open and close independently, with
  state persisted in `localStorage`:

  | Group | Pages |
  |-------|-------|
  | **Fleet** | Devices, CMDB, Containers, Virtualization, Network |
  | **Monitoring** | Targets, Device Metrics, Listening Ports, Custom Scripts, Services, Logs |
  | **Security** | TLS/DNS, Patches, CVEs, Drift, Audit |
  | **Planning** | Schedule, Calendar, Tasks, Maintenance, History |
  | **Admin** | Settings, Users, API Keys, Library, Scripts, IaC Generator, Server Status |

  Fleet and Monitoring are open by default. Admin is collapsed. Home and
  Links remain standalone top-level items above all groups.

- **Monitoring section deep-links.** Each of the six items in the
  Monitoring sidebar group navigates to the Monitoring page *and*
  smooth-scrolls directly to its section (`Targets`, `Device Metrics`,
  `Listening Ports`, `Custom Scripts`, `Services`, `Logs`). No manual
  scrolling required.

- **Calendar recurring events.** Events now support recurrence:
  **Daily**, **Weekly**, **Monthly**, or **Yearly**. The recurrence
  field is stored on the base event; the backend expands occurrences
  into any requested window (capped at 500 per query). Recurring events
  display a ↻ glyph in the calendar grid. Opening a recurring event
  shows a **"Delete all occurrences"** confirmation so the entire series
  can be removed in one click.

- **Schedule → Calendar recurring integration.** The "Add to calendar"
  checkbox on the Schedule form now propagates the schedule's recurrence
  to the created calendar event: daily / n-hour schedules → daily,
  weekly → weekly, monthly → monthly. One-shot and custom schedules
  still produce a single calendar entry.

- **Filter box on Listening Ports.** Live substring filter on the
  Monitoring → Listening Ports section; matches port number, process
  name, or device hostname.

- **Filter box on ACME certificates.** Live substring filter on the
  TLS/DNS → ACME section; matches domain or status.

- **"Clear backup archives" button.** Server Status → Backup section now
  has a **✕ Clear backup archives** button. Requires confirmation; calls
  `DELETE /api/self/backup-state`, which removes all `.tar.gz` archives
  from the backup path and resets the backup-state JSON. The action is
  audit-logged under `backup_clear`.

- **Quick Links dashboard widget.** When at least one link is saved, a
  "Quick links" card appears on the Home dashboard — compact category
  grid with amber/accent borders matching the Links page. A "Manage →"
  button navigates directly to the Links page.

### Changed

- **Audit moved to the Security group.** The Audit log is a
  compliance/security tool and now lives alongside TLS/DNS, Patches,
  CVEs, and Drift — not buried in Admin.

- **Links promoted to a standalone sidebar item.** Quick links is
  user-facing (it drives the Home dashboard widget) and should not
  require opening the Admin group. It now sits directly below Home.

- Command palette page label: **"Monitor" → "Monitoring"**.

- `g m` keyboard shortcut label updated to match.

### Fixed

- **Delete buttons invisible in task, calendar-event, and custom-script
  modals** when opening an existing record. `style.display = ''` removes
  the inline override and lets the element's `d-none` class silently win.
  All three modals now set `style.display = 'block'` explicitly
  (`task-delete-btn`, `event-delete-btn`, `cs-modal-delete-btn`).

### Internals

- `showMonitorSection(sectionId, btn)` — new JS function; wraps
  `showPage('monitor', btn)` + `requestAnimationFrame → scrollIntoView`.
- `_expand_event(ev, from_ts, to_ts)` — new Python generator in
  `api.py`; handles all recurrence rules with proper calendar-aware
  monthly arithmetic (`calendar.monthrange`).
- `handle_backup_clear()` — new `DELETE /api/self/backup-state` handler.
- `_renderHomeLinks(links)` / `loadHome()` extended to fetch and render
  the links widget.

## v3.0.6 — 2026-05-25

Production-readiness polish on top of v3.0.5. **Recommended for any
operator running the v3.0.5 release** — every change here strengthens
the existing posture without changing visible behaviour for end users.
No schema changes, no migrations.

### Added

- **`/api/health` liveness endpoint.** Unauthenticated, returns
  `{"status":"ok","version":"<x.y.z>"}` and nothing else. Replaces
  `/` in the Docker `HEALTHCHECK` (probing the full SPA on every
  poll was wasteful) and gives external orchestrators / reverse
  proxies / uptime monitors a cheap, stable endpoint. Path is in
  `_PWCHG_ALLOWED_PATHS` so it works even from a session pending a
  forced password change.

- **CSP violation reporting at `/api/csp-report`.** The strict CSP
  shipped in v3.0.5 has been silently blocking any inline script or
  style the browser tries to execute. With `report-uri /api/csp-report`
  added to the policy directive, every block now POSTs a JSON
  report to the new handler, which appends one audit-log line per
  violation (directive, blocked URI, source file, line, sample). A
  future regression that reintroduces inline code surfaces as a
  logged event instead of a silent visual bug. Endpoint is request-
  size-capped at 16 KB and is the one POST exempted from the same-
  origin CSRF check (browsers sometimes send `Origin: null` on CSP
  reports).

- **Subresource Integrity (SHA-384) on every bundled vendor library.**
  `swagger.html` adds `integrity=` to the static `<link>` and
  `<script>` tags for swagger-ui; `app.js` adds it to the dynamic
  `_loadXtermOnce()` (xterm.js, xterm.min.css, addon-fit) and
  `generateQRCode()` (qrcode-generator) loads. If the file on disk is
  ever overwritten — corrupt deploy, swapped tarball, supply-chain
  compromise — the browser refuses to execute it. Updating a vendor
  version means recomputing one SHA-384; the procedure is documented
  inline next to each `integrity=` attribute.

- **GitHub Actions CI workflow** (`.github/workflows/ci.yml`). Runs
  the full unittest suite on every push and PR to `main`. The
  `TestCSPMigrationFidelity` checks introduced in v3.0.5 are now
  CI-enforced — any commit that reintroduces an inline event
  handler, an unresolved CSS `${…}` template, a `javascript:` URI, a
  duplicate ID, etc. fails the workflow before the PR can merge.
  On main-branch pushes the workflow also runs `make dist` to catch
  "works on dev, breaks on fresh checkout" issues.

### Changed

- Dockerfile `HEALTHCHECK` now probes `/api/health` instead of `/`.
- Both nginx CSP directives carry `report-uri /api/csp-report;` —
  configure-time addition for fresh installs, one-line append for
  existing deploys (see docs/v3.0.6.md §Upgrade).
- Service worker cache name bumped to `remotepower-shell-v3.0.6` so
  the activate handler evicts the previous shell on first reload.

### Internals

- Test suite at **1,560+ tests, all passing**.
- `test_v306.py` holds the strict version pins now; `test_v305.py`'s
  pins loosened to `^3\.\d+\.\d+$` regexes (same convention every
  prior release-bump test followed).

## v3.0.5 — 2026-05-25

A security + UX release on top of v3.0.4. The headline is the Content
Security Policy hardening: `'unsafe-inline'` is gone from both
`script-src` and `style-src`, closing the L1 finding from the v2.3.2
security review. **Recommended for every operator** — the new CSP is
strictly more restrictive, blocks injected inline scripts the previous
policy let through, and several user-visible bugs that the migration
exposed are fixed here.

### Security

- **CSP `'unsafe-inline'` removed from `script-src` and `style-src`.**
  The previous policy let injected inline `<script>` and `onclick=`
  payloads execute (a single missed `escHtml` / `escAttr` was the only
  thing between a stored XSS bug and arbitrary code execution). The
  new policy blocks them in the browser, not just by escape discipline.
  Required removing every inline event handler from `index.html`,
  `swagger.html`, and the long-form `docs/Manual.html`, plus every
  `style=` attribute and `<style>` block — replaced with external CSS,
  utility classes, and `data-action` event delegation. Re-published
  `docs/security-review-3.0.5.md` follows the v2.3.2 format and tracks
  the change.

- **Vendor libraries self-hosted under `/static/vendor/`.** xterm.js
  5.5.0 + addon-fit (web terminal), qrcode-generator 1.4.4 (TOTP
  enrolment QR), Swagger UI 5.17.14 (API docs page), and the Inter +
  JetBrains Mono web fonts (92 woff/woff2 subset files). Previously
  loaded from cdn.jsdelivr.net, cdnjs.cloudflare.com, and bunny.net —
  all blocked under the new strict CSP and, on closer look, were
  *also* blocked under the previous CSP for the cross-origin reason
  (the `'unsafe-inline'` keyword never allowed external origins, so
  these features had been silently broken for any operator who
  actually tried to use them). Browsers only fetch the font subsets
  they need via `unicode-range` — typical pageload is ~30 KB of fonts.

### Fixed

- **AI Assistant page (`/#ai`) rendered blank** under the new CSP.
  Root cause: the auto-class generator that replaced inline
  `style="display:none"` with CSS rules left the JS reveal path
  (`element.style.display = ''`) unable to override the class — the
  exact same pattern as the v3.0.3 `#pwa-install-btn` fix, now
  affecting eight more sites across the AI page, the Services
  maintenance badge, and the Mitigation modal's AI-suggested-fix panel.
  All reveals now use explicit display values so the inline style
  beats the class.

- **"Install app" button stayed visible after install on Chrome.**
  Two layered causes: (1) a leftover `#pwa-install-btn { display: flex; }`
  rule with ID specificity overrode the class-based initial-hide; (2)
  Chrome keeps firing `beforeinstallprompt` on regular browser tabs
  even when the PWA is already installed in that profile, and there's
  no web-page-accessible API for "am I installed?". Fix: removed the
  override rule, and a `localStorage` flag now persists the
  installed-state — set the first time the page loads in standalone
  mode (which the OS always launches at least once post-install), and
  on the `appinstalled` event. Subsequent regular-tab loads on the
  same profile check the flag and suppress the install button.

- **Sidebar UX on mobile / PWA.** On the mobile drawer (≤720px), both
  the ✕ close button and the Collapse button are now hidden — the
  drawer dismisses via tap-outside-to-close (the scrim handler in
  `app.js`). The Collapse button never visually worked at mobile width
  because its CSS rules were gated on `min-width: 769px`, so the
  button was just dead clickable area. When running as an installed
  PWA at >720px, the docked-sidebar collapse-rail rules now apply at
  every width above the mobile breakpoint — previously they missed the
  721–768px gap and a phone-sized desktop-PWA window saw an inert
  Collapse button.

- **Login form, Change Password, and Add User flows** now use real
  `<form>` elements with `<button type="submit">`, so browser password
  managers can reliably extract / autofill credentials. The
  long-standing `[DOM] Password field is not contained in a form`
  warnings on those three flows disappear. (The remaining warnings on
  admin-config secrets — SMTP / LDAP / Proxmox tokens, CMDB vault
  keys — are intentional; password managers shouldn't be autofilling
  service-account credentials.)

- **Service Worker registration hardened against the persistent
  `InvalidStateError`** seen on Chrome / Brave after BFCache restore
  or partitioned-storage hiccups. The v3.0.4 retry chain handled
  transient cases but couldn't recover from a stuck previous
  registration. Now: 4 retries on `InvalidStateError` with linear
  backoff, then a last-resort unregister-all-and-retry from a clean
  slate (capped at one attempt per document so it can't loop), and a
  one-shot guard against the duplicate-fire that happens when
  `pageshow` and the synchronous bootstrap both kick at initial load.

- **`docs/Manual.html` was linked from the in-app Documentation page
  but never actually deployed.** The dashboard's `<a href="/Manual.html">`
  silently 404'd in production for every operator. `Dockerfile`,
  `deploy-server.sh`, and `install-server.sh` now copy it to the web
  root.

### Improved

- **Per-file content-hash cache-busting.** `deploy-server.sh` now
  rewrites the `?v=...` query strings on the deployed `index.html`'s
  `<script>` and `<link>` references to a 12-character SHA-256 prefix
  of each file's content. Previously the version marker only changed
  when `SERVER_VERSION` did, so between-release JS or CSS fixes
  required operators to manually clear browser cache. With this in
  place every deploy invalidates exactly the files that changed.
  Source-tree `index.html` still carries `?v=<SERVER_VERSION>` so the
  regression tests pass; the rewrite happens at install time.

- **Strict CSP regression tests.** `tests/test_v232.py` now scans every
  shipped HTML file (`index.html`, `swagger.html`, `Manual.html`) for
  inline `<script>`, inline `<style>`, inline event handlers, inline
  `style=` attributes, `javascript:` URIs, and any auto-loaded external
  resource. Catches a future commit that tries to reintroduce any of
  these patterns. Vendor-libraries-present check ensures the bundled
  copies stay in tree.

### Internals
- Test suite at **1,545+ tests, all passing**. `test_v303.py` /
  `test_v304.py` pins loosened where they asserted the pre-migration
  inline-handler patterns; new pins live in this release's
  regression coverage.
- Service worker cache name bumped to `remotepower-shell-v3.0.5` so
  the activate handler evicts every cache from earlier releases on
  first reload.

## v3.0.4 — 2026-05-24

A bug-fix release hot on the heels of v3.0.3. Eight real production bugs, all
landed the same evening they were spotted. **Recommended for every operator
who runs the AI features, the metric thresholds, the per-device settings
drawer, or the mobile / PWA UI — i.e. nearly everyone.** No schema changes,
no migrations needed.

### Fixed

- **AI chat returned 500 on every request.** `_http_post_json` in
  `ai_provider.py` referenced `cfg.get('insecure_ssl')` from inside a function
  that never received `cfg` as a parameter. The reference resolved against an
  unbound name and raised `NameError` before the request ever left the box.
  The bug was latent in v3.0.2 — the change that "honoured" the insecure_ssl
  flag never wired it through — and triggered the first time a v3.0.2+ install
  actually exercised the chat path. Fix: explicit `insecure_ssl: bool = False`
  parameter; callers forward `cfg.get('insecure_ssl')`. Anthropic and
  OpenAI-compatible paths both updated. The matching `_http_get_json` got the
  same parameter for symmetry.

- **Monitor page showed "OK" badge while Needs Attention was screaming about a
  swap/memory/CPU warning on the same host.** `handle_devices_list()` returned
  a curated subset of device fields and silently dropped `metric_state`. The
  client's row aggregator iterated `d.metric_state || {}`, got empty, and
  defaulted to "OK" — even though `/api/attention` read the same state on the
  server side directly and was correctly surfacing the alert. Fix: include
  `metric_state` in the device list response. The dict is small (one entry per
  active alert) and cheap to serialise.

- **No 🩺 Investigate button on memory/swap/CPU alerts.** The AI prompt keys
  (`mitigate_memory`, `mitigate_cpu`) have existed in
  `ai_provider.SYSTEM_PROMPTS` since v3.0.1, but `_MITIGATE_PLAYBOOKS` only
  carried `patches / disk / drift / service_down / reboot / brute_force`. The
  alert kind landed in Needs Attention as `'swap'` / `'memory'` / `'cpu'`, no
  playbook lookup match, no button rendered. Fix: three new playbooks with
  concrete read-only diagnostics:
  - **memory**: `free -h`, `/proc/meminfo` top fields, top 20 by `%mem`,
    recent OOM events from `journalctl` + `dmesg`, `vm.swappiness` /
    overcommit sysctls, `systemd-cgtop` snapshot.
  - **swap**: `free -h`, `swapon --show`, per-process `VmSwap` ranking from
    `/proc/*/status`, `vm.swappiness`, PSI memory pressure, recent swap-related
    journal entries.
  - **cpu**: `uptime`, `loadavg`, top 20 by `%cpu`, processes in
    uninterruptible D-state, `mpstat` / `iostat` / `vmstat` for iowait, PSI
    CPU pressure.
  Each is explicitly marked non-destructive (test enforced). The client-side
  `MITIGATE_KINDS` set and `_MITIGATE_KIND_LABELS` dict were *also* updated
  in lockstep (they were a duplicate source of truth that previously had to
  be maintained manually) and a regression test asserts JS/Python parity.

- **"Save settings" button in the device drawer 404'd with "Not found".** The
  drawer's `_drawerSaveSettings()` posts the full bundle (`group`, `tags`,
  `icon`, `monitored`, `poll_interval`, `watched_services`, `log_watch`,
  `watched_files`, `cmd_allowlist`) to `POST /api/devices/<id>` — but no
  bulk handler ever existed. The route fell through to the dispatcher's
  catch-all 404. New `handle_device_save_bulk()` accepts the bundle,
  validates every field with the same rules as the per-field PATCH endpoints,
  writes once atomically, and audits the save with the field list. The
  per-field endpoints still work and are unchanged. Two storage-name
  divergences are handled inside the bulk handler: client's
  `watched_services` is written as `services_watched` (server-side historical
  naming), and client's `cmd_allowlist` is written as `allowed_commands`
  (the canonical field `_check_exec_allowlist()` reads at command-execution
  time). The dispatcher route uses a slash-count guard so it cannot collide
  with any future `/api/devices/<id>/<suffix>` POST route.

- **"Re-run AI" on a mitigation playbook returned 200 OK with every field
  blank.** `_call_ai_with_prompts()` passed arguments to
  `chat_openai_compatible()` in the wrong order — the `messages` parameter
  received the system-prompt STRING, then `payload_messages.extend(messages)`
  iterated it character by character and sent the LLM a messages array like
  `[{role:'system', content:'Alert:...'}, 'Y', 'o', 'u', ...]`. Ollama
  rejected the malformed payload, the provider returned `{ok: False, ...}`,
  and the caller's `ai_result.get('text', '')` happily returned `''`. Fix:
  build a proper `messages=[{role, content}]` list, pass the system prompt
  as `system`, unpack the per-prompt overrides into matching kwargs. And —
  related — the handler now returns 502 with the actual provider error
  message rather than 200 with an empty body, and logs the traceback to
  stderr so future failures are diagnosable.

- **Mobile / PWA sidebar drawer wouldn't collapse.** Tap-outside-to-close
  silently failed because the handler required `e.target === document.body`,
  but real browsers report the click target as the underlying `<div id="app">`
  or `.app-content` rather than body itself. Burger-to-close also broken
  because the burger button (header z-index 100) sits behind the scrim
  (z-index 800) once the drawer is open, so the burger's own `onclick`
  never fires. Only the nav-button-click close path worked, which made the
  drawer feel half-broken. New handler uses explicit `closest('.sidebar')` /
  `closest('.mobile-burger')` / `closest('.nav-btn')` guards instead — any
  tap outside those zones closes the drawer on mobile. Regression test
  forbids the strict `e.target === document.body` pattern from sneaking
  back in.

- **"✨ AI Prioritise Updates" button felt unresponsive.** Click, no
  in-place feedback, eventually a small toast that was easy to miss.
  Operators reported "I clicked it, nothing happened." Two changes: the
  button visibly disables and switches to ⏳ during the API call, and the
  negative-case toasts ("no patch history" / "no upgrade listing in
  history") got rewritten. **Iter 2:** the earlier "use Force re-scan
  packages" suggestion was misleading — `force_package_scan` only
  refreshes the upgradable COUNT, not the listing (the agent's
  `get_patch_info()` discards `out` and only keeps `len()`). The only
  path that populates `patch_history` with a real listing is an
  operator-triggered exec command. Rather than make the operator dig
  for that, ✨ now auto-queues the right per-package-manager listing
  command via `POST /api/exec` after a confirmation prompt (`apt list
  --upgradable`, `dnf check-update`, `pacman -Qu`). One click → wait
  ~60 s for the heartbeat → click ✨ again, AI engages.

- **Mobile burger button didn't close the open drawer.** Tap-outside
  worked (v3.0.4 iter 1 fix), but tapping where the burger visually
  was had no effect on mobile Chrome / installed PWA. Root cause: the
  scrim (z-index 800, `inset: 0`) covers the burger (header z-index
  100) once the drawer is open, so the burger's `onclick` never fires.
  The body-level close handler should catch it via the scrim — and
  does on desktop browsers' touch emulation — but real mobile Chrome
  and PWA installs were unreliable here. Standard mobile-drawer fix:
  a dedicated ✕ button inside the sidebar header, visible only at
  `max-width: 720px`. Always discoverable, always works, no z-order
  trickery.

- **Silent except → logged exceptions on the heartbeat metric path.**
  `handle_heartbeat()` wrapped `process_metric_thresholds()` in a bare
  `except Exception: pass`. Any logic bug there silently broke metric
  state recompute and the operator got no clue. Now logs `class: message`
  + traceback to stderr (`journalctl -u fcgiwrap`) while still keeping the
  heartbeat path resilient.

### Internals
- Test suite at **1,532 tests** — `test_v304.py` holds the strict version
  pins now; `test_v303.py`'s pins loosened to `^3\.\d+\.\d+$` regexes.
  Same convention test_v302.py followed for v3.0.3.
- This release ships preliminary scaffolding for v3.1.0 (the `mcp` role
  enum, an empty `MCP_ACTION_ALLOWLIST`, the `require_mcp_action()` gate, a
  `get_mcp_attribution()` helper that reads `X-MCP-Client` / `X-MCP-Prompt`
  headers, optional `ai_host` / `ai_prompt` kwargs on `audit_log`, and a
  per-device `require_confirmation` field with its own PATCH endpoint). All
  of it is silent — no MCP write tools are yet registered, so even a valid
  `mcp`-role API key still gets 403 on every action attempt. Tests for the
  scaffolding live in `test_v310.py`. Stage 4 of v3.1.0 will populate the
  allowlist.

## v3.0.3 — 2026-05-24

A small, focused security + UX patch on top of v3.0.2. **Recommended for all
operators**, especially anyone whose Install-as-app button stopped working in
Chrome or Brave.

### Fixed
- **PWA install button silently broken.** Chrome and Brave were never showing
  the "Install RemotePower" button. Three layered causes:
  1. A stylesheet rule with ID-selector specificity
     (`#pwa-install-btn { display: none; }`) was overriding the inline reveal —
     when the browser fired `beforeinstallprompt` and the JS cleared the inline
     `display:none`, the stylesheet rule took over and the button stayed hidden.
  2. A timing race: if `beforeinstallprompt` fired before `DOMContentLoaded`
     (common on warm reload when manifest + service worker are already cached),
     the button reference was still `null` and the reveal was a no-op. The
     event only fires once per session, so the button never came back.
  3. The two icons declared `purpose: "any maskable"` as a combined value.
     Some Chrome / Brave builds treat that as maskable-only, which doesn't
     satisfy the installability gate that requires at least one pure-`any`
     icon. Now split into separate `any` + `maskable` entries.

  The service worker cache name was bumped to `remotepower-shell-v3.0.3` so
  existing installs evict the stale shell on first reload. If your install
  button still doesn't appear after upgrading, do one hard reload to pick up
  the new service worker.

- **Mobile drawer scrim rendered as a half-sized floating rectangle.** Opening
  the mobile nav drawer dropped a partial translucent black box near the top
  of the screen instead of dimming the whole page behind the drawer, and
  tap-outside-to-close did nothing. Root cause: two `body::after` rules
  collided. The ambient blue-glow effect (a fixed 800×400 box with
  `translateX(-50%)` and `pointer-events:none`) sets properties that the
  mobile-nav scrim rule didn't override — `inset: 0` only resets
  `top/right/bottom/left`, not `width/height/transform/pointer-events`. The
  scrim now explicitly resets those properties so it fills the viewport and
  catches taps. Mobile-only — desktop never used the scrim path.

- **Mobile hamburger had a visible square box around it.** The
  `.mobile-burger` style carried `border: 1px solid var(--border)`,
  which on the dark theme rendered as a discrete framed button next
  to the logo — easy to mistake for a separate clickable element.
  The hamburger glyph reads fine on its own; the border is now `none`.

- **Quick-SSH icon next to hostnames was unreadable blue on dark
  mode.** The `<a>` carried no explicit `color`, so the browser's
  default link colour bled through and clashed with the dark
  sidebar/table. The icon now uses `color:var(--text)` (near-white
  in dark, near-black in light), so it stays visible in both themes.

### Added
- **`RP_SMTP_PASSWORD` and `RP_LDAP_BIND_PASSWORD` environment variables.**
  The two remaining plaintext secrets in `config.json` can now be supplied
  via the environment — same pattern as `RP_PROXMOX_TOKEN_SECRET` (v2.3.1).
  When the env var is set it takes precedence over the config file, the
  secret stays out of `/var/lib/remotepower/`, and it is **not included in
  the backup export** (so backups can be shared with support safely).

  Set them in your systemd unit or container env:
  ```ini
  # /etc/systemd/system/remotepower.service (or your override)
  Environment=RP_SMTP_PASSWORD=…
  Environment=RP_LDAP_BIND_PASSWORD=…
  ```
  ```yaml
  # docker-compose.yml
  environment:
    RP_SMTP_PASSWORD: "${RP_SMTP_PASSWORD}"
    RP_LDAP_BIND_PASSWORD: "${RP_LDAP_BIND_PASSWORD}"
  ```
  The Settings page detects the env vars and shows a green "✓ Password is
  currently being read from `RP_SMTP_PASSWORD`" hint above the (now disabled)
  config field. Existing setups that keep the password in `config.json` are
  unchanged.

- **Forced password change for default-credential accounts.** A fresh
  install seeds `admin / remotepower`. Since v2.3.2 the UI has shown a red
  banner nagging the operator to change it, but the app remained fully
  usable on the default password — the banner could be ignored. As of
  v3.0.3, **every API call returns 403 until the password is changed**,
  with only `POST /api/users/passwd` and `GET /api/public-info` reachable.
  The dashboard catches the 403, surfaces a clear toast, and routes you
  straight to the change-password form. As soon as the password is changed,
  the flag clears and everything unlocks.

  This applies only to accounts that still carry the `must_change_password`
  flag — once changed, never blocked again. API keys are unaffected (they
  can only be created from an already-cleared account in the first place).

### Internals
- Test suite at **1,453 tests** (`test_v303.py` covers the new behaviour;
  one brittle fixed-offset slice in `test_v227.py` widened to use the
  whole `@media` block).
- `test_v302.py` strict version pins loosened to `3.x.x` regexes since
  `test_v303.py` now holds the strict pin role. Same convention going forward.

### Upgrading from v3.0.2

Drop-in. Pull and redeploy:
```bash
cd /path/to/remotepower
git pull origin main
sudo bash deploy-server.sh
```
- Agents auto-upgrade on next heartbeat. No data migration. `config.json`
  format unchanged.
- If you want to move SMTP / LDAP secrets to the environment now, edit your
  unit / compose file as shown above, restart the server, then **clear the
  fields** in Settings → Notifications (SMTP) and Settings → Security (LDAP)
  and save — that drops the plaintext from `config.json`.
- If your dashboard's Install button has been missing, force a hard reload
  (Ctrl+Shift+R / Cmd+Shift+R) once after upgrading so the new service
  worker takes over.

---

## v3.0.2 — 2026-05-24

### Bug fixes (post-ship polish bundle)
- **Unmonitored devices fired metric/service/log/CVE webhooks anyway.**
  `device_offline` had its own per-device `monitored` check (line ~2256),
  but every other per-device event went through `fire_webhook` unguarded.
  Result: operator marks a device "unmonitored" to silence alerts during
  a migration, gets a Pushover ping about its swap usage anyway. Added a
  single guard inside `fire_webhook` that covers every event carrying a
  `device_id` — metric_warning/_critical, service_down/_up, log_alert,
  cve_found, drift_detected, custom_script_fail/_recover, container_*,
  patch_alert, brute_force_detected, ssh_key_added, tls_expiry,
  reboot_required, new_port_detected, snapshot_old, backup_stale,
  config_drift. Logged as `suppressed (device "X" is unmonitored)` so
  operators can see what got dropped.
- **ACME page rendered one row per device without acme.sh** ("acme.sh not
  installed on this device"). For fleets where most hosts use other cert
  managers, this dominated the table. Now hidden; a discreet count
  surfaces above the table ("N devices without acme.sh hidden").
- **`_get_disk_thresholds` was called but never defined**, guarded by
  `callable(globals().get(...))` so the dead branch was silently always
  taken — per-mount disk threshold overrides in `_compute_attention`
  were ignored. Replaced with the canonical `_resolve_metric_thresholds`.
- **Four CSS variables undefined inside styles.css itself**: `--bg2`,
  `--bg3`, `--border2`, `--font-body`. Used by the device drawer footer,
  table footers, and a few body-text styles — rendered with default
  browser colours in dark mode (white backgrounds, default sans-serif).
  Replaced with the existing equivalents (`--surface2`, `--border`,
  `--font`). New test `TestCssVarsDefined` sweeps every `var(--xxx)`
  reference across `.js`, `.html`, and `.css` against the defined set.
- **URL bar stuck at last settings tab**: `switchSettingsTab` wrote
  `#settings/<tab>` to `location.hash`, but `showPage` for other pages
  never updated the hash. Clicking through Home, Devices, Logs etc.
  left the URL showing `#settings/notifs` (or wherever you were last).
  Both functions now use `history.replaceState` so the URL bar tracks
  the current page without polluting back-button history.

### Improvements
- **Multi-webhook test button** correctly hits `/api/webhook/test` (was
  posting to `/api/webhook-test` — 404).
- **Logs page Search button** handles 400 responses (bad regex etc.) with
  a clear in-UI error instead of a silent UI freeze on TypeError when
  reading `data.results.length` from `{error: '...'}`.
- **Settings search bar** rewrite: re-indexes on every keystroke (was
  cached, so dynamically-rendered sections like the webhook destinations
  list never made it into the index), adds per-tab match badges, dims
  tabs with zero matches, auto-switches to the first matching tab when
  your current tab has nothing, shows a hint line ("23 settings match
  across 3 tabs"). Hides the "I typed something and the page went blank"
  failure mode.
- **Command palette** primes the device cache on open. Previously you had
  to visit the Devices page first or no devices would appear.
- **Bulk-actions button** moved from Settings → Advanced to next to the
  Enroll device button on the Devices page. That's where operators look
  for fleet-wide operations; Settings was the wrong shelf.
- **`var(--ok)` (undefined) replaced with `var(--green)`** — 3 pre-existing
  uses in the Proxmox env hint and custom-script status indicator that
  rendered with default browser colour.

### Internals
- Re-ran AST audit for called-but-undefined names: only `_get_disk_thresholds`
  remained from before (fixed above).
- Re-ran `respond()`-inside-broad-except audit: zero remaining.
- HTML `<div>` open/close balance verified: 1396/1396.
- `var(--xxx)` reference audit: zero undefined across JS, HTML, CSS.

### Tests added this iteration
`TestUnmonitoredDeviceSuppression` (4), `TestAcmeNoCertsRowsFiltering` (2),
`TestUrlBarSync` (2), `TestDeadCodeRemoved` (2), `TestCssVarsDefined` (1).
Total v3.0.2 suite: 1404 tests, all passing.

---

### Initial release content (shipped earlier on 2026-05-24)

### Bug fixes (static-audit catch)
- **Mitigation feature was completely broken since v3.0.1.** Two NameErrors hidden
  by lazy code paths:
  - `_read_body()` called in `handle_mitigate_investigate` and `handle_mitigate_fix`
    but never defined → fixed to `get_json_body()`.
  - `chat_anthropic` / `chat_openai_compatible` called bare from `_call_ai_with_prompts`
    but defined in the `ai_provider` module → prefixed with `ai_provider.`.
  Found by an AST audit of every called-but-undefined name. Mitigation modal was
  hitting 500 on every click; nobody noticed because nobody was clicking it under
  the test load.
- **JSON load cache aliasing.** v3.0.2 introduced a per-request `load()` cache to
  collapse the 4×-per-heartbeat parsing of `config.json`. First version returned
  the cached dict by reference — caller mutations leaked into the cache, and
  `_LockedUpdate` exception aborts left the cache holding in-flight changes that
  were never saved. Fixed: deepcopy on cache hit + explicit cache invalidation
  in `_LockedUpdate.__exit__` when the save is aborted.
- **`current_username()` defined.** Last release shipped with this called from
  three audit-log call sites but never defined; the silent NameError meant the
  Ignore/Cancel buttons on ACME pending actions appeared dead.
- **Agent `server_url` typo.** The force-agent-upgrade path referenced an undefined
  `server_url` (the local in `heartbeat()` is `server`); operator clicked ⚡ and
  got a journal line saying force upgrade failed.
- **Pacman `--disable-sandbox` probe was checking the wrong help text.** The flag
  is an `-S` operation flag, so it shows in `pacman -S --help`, not `pacman --help`.
  CachyOS continued to silent-fail because the probe never matched.

### New — reliability & operations
- **Self-monitoring page (Server status).** New sidebar entry. Reports server
  version + memory, DATA_DIR disk usage with the top 20 largest files, fleet-wide
  device freshness (oldest/freshest heartbeat, current offline count), webhook
  delivery rate (last 24h and 7d), audit log entry count + archive size, scheduled
  backup state. `GET /api/self/status` for external monitoring.
- **Scheduled backup of `/var/lib/remotepower`.** Daily tarball (gzipped), retention
  configurable (default 14 days), output path configurable (default
  `/var/lib/remotepower/backups`). Triggered via the heartbeat hook with a 24h
  sentinel and a stale-lock recovery for crashes mid-backup. Manual "Run backup
  now" button on the Server status page (`POST /api/self/backup-now`). Backup
  excludes the backup dir itself, in-flight `.tmp.*` files, and pre-compressed
  `.gz` archives.
- **Audit log retention by age.** Default 90 days, configurable. Entries older
  than retention are moved to `audit_log_archive.jsonl.gz` (append-only, gzip).
  Old count-only cap retained as a safety net for misconfiguration.
- **Fleet events archive.** Events evicted from the 200-entry rolling log now go
  to `fleet_events_archive.jsonl.gz` instead of being dropped. Surfaces in the
  Server status page as a size readout.
- **Exponential lockout ladder for failed logins.** 10s → 1m → 5m → 30m → 2h.
  Resets on successful login. Brute-force attackers face escalating penalties
  instead of a fixed 10-min wall they can just sit out.

### New — performance
- **Per-request `load()` cache.** CGI gives us a fresh interpreter per request, so
  the cache only lives for one handler's duration — but within that handler,
  `CONFIG_FILE` was being parsed up to 4× per heartbeat and `LONGPOLL_FILE` 3× in
  `handle_longpoll_exec`. The cache deduplicates redundant reads within a
  handler. Invalidated on `save()` and `_save_held()` so writes never leak stale
  data.

### New — features
- **Multi-webhook destinations.** Fire every event to multiple endpoints
  simultaneously with per-destination format adapters. Supported formats: Discord
  (embed with severity colour), Slack (markdown text), Pushover (form-encoded with
  app token + user key, internal priority maps to Pushover priority), Microsoft
  Teams (MessageCard schema with theme colour), ntfy.sh (plain text body + headers),
  and generic JSON. Per-destination filters: limit to specific event names, or set
  a minimum priority threshold. Use case: Pushover for `priority >= warning` only,
  Discord for everything. Legacy single `webhook_url` field still honoured for
  backward compatibility.
- **Per-destination test button.** Fire a synthetic `test` event to a single
  destination from the editor, without touching the persisted config of the other
  destinations.
- **Pushover credentials redacted.** App token + user key are write-once in the UI
  (the GET response only signals whether one is set); also redacted from the
  backup export tarball.
- **Force ACME rescan button.** One-shot flag per device — agent re-scans
  `~/.acme.sh` on next heartbeat instead of waiting for the next hourly cadence.
  Useful when you've issued/renewed via the CLI and don't want to wait for
  RemotePower to catch up. Same flag-on-heartbeat-lock pattern as force-upgrade.
- **Bulk actions modal.** Run an operation across a filtered set of devices: all
  monitored, by group, or by tag. Operations: package upgrade, reboot, shutdown,
  force package scan, force ACME rescan. Destructive operations require typing
  `RUN` to confirm. Reachable from Settings → Advanced or via the command palette.
- **Command palette (`/` or `Ctrl-K`).** Searches pages, devices, and actions.
  Arrow-key navigation, Enter to activate, Esc to close.
- **Keyboard shortcuts.** `?` shows the cheat sheet. `g`-prefix shortcuts:
  `g h/d/l/s/c/m/a/v` for Home/Devices/Logs/Settings/CVE/Monitor/Audit/serVer.
- **Settings search bar.** Filters visible settings sections live as you type.
- **Configurable session timeout.** Both `session_ttl_short` (no remember-me;
  default 24h) and `session_ttl_long` (with remember-me; default 30d) are
  configurable in Settings → Advanced. Existing sessions keep their original TTL.

### Improvements
- **Force-upgrade flag** had been silently dropped after iteration 2's fix landed
  in the wrong scope. Now wired through correctly inside the heartbeat file lock,
  same as `force_iac_collect` and `force_package_scan`.
- **`pacman -S --help`** is now the probe location for `--disable-sandbox` (last
  release checked `pacman --help` which doesn't list operation flags). Falls back
  to parsing `pacman --version` and assuming v7+ supports the flag.
- **Larger archive of historical fleet events** for the Server status page; not
  just the rolling 200-event window.

### Internals — audits run this release
- AST sweep of every called name; resolved 7 suspects (2 real bugs, 5 false positives
  caught by `callable(globals().get(...))` guards or module-level imports).
- AST sweep of every `respond()` call sites wrapped in `try/except Exception`;
  zero remaining (the debug-log handler from last release was the only one).
- Field-shape consistency check — `rc` dominates over `exit_code` (19:2) which is
  acceptable (the 2 are reading legacy data); `unit`/`name`/`hostname` are distinct
  concepts not aliases.

## v3.0.1 — 2026-05-23

### Fixes (iteration 2)
- **Force-upgrade flag silently dropped.** Operator clicked ⚡, got the success toast,
  agent never re-downloaded. Root cause: heartbeat handler copied `force_iac_collect`
  and `force_package_scan` into `saved_dev` inside the file lock, but missed
  `force_agent_upgrade`. The outside-lock check then read `saved_dev` (which never
  had the field) and never set `common_resp['force_agent_upgrade']`. Now handled
  next to the other one-shots, atomic with the rest of the heartbeat write. Removed
  the racy outside-lock clear block.
- **Force-upgrade NameError in agent.** `check_for_update(server_url, force=True)`
  referenced an undefined name — the local in `heartbeat()` is `server`, not
  `server_url`. Visible in agent journal as `Force upgrade failed: name 'server_url'
  is not defined`. One-character fix; both ends now work end-to-end.
- **ACME `.meta` row pollution + NaN KB + dead View log.** `handle_acme_detail`
  listed all files in `ACME_LOGS_DIR` matching the device prefix, including the
  `.meta.json` sidecars. They showed up as bogus actions named `<id>.meta` with
  NaN size and a View Log that 404'd. Filter listing to `.log` files only; timestamp
  now sourced from `meta.queued_at` when available.
- **ACME action "pending forever".** Agent ran the command, reported rc=0 with full
  output — but the meta never updated, so UI polled indefinitely. The server's tag
  regex anchored at `^#acme:` but the agent round-trips the full original cmd
  including the `exec:` prefix (e.g. `exec:#acme:5646fce92976#...`). Changed regex
  to `^(?:exec:)?#acme:` — accepts both forms. Added regression tests.
- **CachyOS shows fully patched** when it isn't. pacman 7's download sandbox user
  (`alpm`) fails on certain hosts; the agent caught the `CalledProcessError` and
  silently reported `upgradable=0`. Now probes `pacman --help` for `--disable-sandbox`
  support, uses it when available, and on real failure reports `upgradable=None`
  ("unknown") instead of lying as "fully patched". Server-side `_UPGRADE_CMD` got
  the same probe + flag treatment.
- **yum branch added** to patch detection and the upgrade command — RHEL 7 / older
  CentOS still ship yum without dnf. Reports as `manager: dnf` so it shares the OSV
  CVE path.
- **"Show N more ports" click did nothing.** `JSON.stringify(hidden)` was embedded
  raw inside a double-quoted `onclick=""` attribute — JSON's double quotes broke
  HTML parse. Escaped via `&quot;` + `&amp;`. Same fix applied to the custom-scripts
  output click handler.
- **Three duplicate `/devices` GETs** on the Monitor page (one per loader: runMonitor,
  loadDeviceMetrics, loadCustomScripts, loadListeningPorts). Added a 500ms in-flight
  cache so they share one fetch.
- **HTML structure error**: dedicated Ignored items pane was being injected outside
  `<div id="page-settings">`, causing it to render globally including on the
  Virtualization page. Moved to a proper sibling of other `.settings-pane` divs.
- **Test that locked in bad behaviour**: `test_v182.test_empty_unit_rejected` matched
  "unit is required" literally — updated to accept the broader "unit or path is
  required" message (rule schema now allows file-path source type).

### Features (iteration 2)
- **ACME / acme.sh integration.** New section on Security → TLS / DNS expiry. Agent
  scans `~/.acme.sh/` and reports cert metadata; server provides issue wizard
  (3-step: domain → DNS provider → confirm), force-renew, revoke, cancel, and
  per-domain log capture. DNS-01 only (Cloudflare prominent, others available).
  Wildcards supported. No must-staple (OCSP being sunset). No HTTP-01 (would
  interfere with nginx/apache). Cancelable pending actions distinguish between
  "still in queue" (cleanly removed) and "already dispatched" (UI stops polling
  but agent may still complete). Full doc at `docs/acme.md`.
- **Mitigation runners with AI.** 🩺 button on every Needs Attention card whose alert
  kind has a server-defined playbook. Three-tab modal: Diagnostic (auto-runs,
  live-polls every 2s) → AI Analysis (auto-fires when diagnostic completes, AI
  proposes one fix command between `BEGIN_FIX`/`END_FIX` markers) → Apply Fix
  (pre-approved playbook fix or AI suggestion, with two-tier safety classifier:
  hard denylist refuses outright; sensitive patterns require typing `RUN`).
  Five new prompt keys (`mitigate_cpu`, `_memory`, `_disk`, `_service`,
  `_patches`) customisable in Settings → AI Assistant. Diagnostic playbooks for
  `patches`, `disk`, `drift`, `service_down`, `reboot`, `brute_force`. Service
  unit names go through strict regex validation before template substitution.
  All actions audit-logged. Full doc at `docs/mitigation.md`.
- **File-path log watching.** Log rules can now reference an arbitrary file path
  instead of a systemd unit. Agent tails the file, handles rotation (inode
  tracking) and truncation, skips existing content on first sight (so a new
  rule doesn't dump the entire historic file). State persisted at
  `/var/lib/remotepower/file-log-state.json`. Submitted as synthetic unit
  `file:<path>`.
- **Attention coverage audit** — three new state-derived kinds now produce Needs
  Attention items whenever the underlying condition is active:
  - `service_down` — any watched systemd unit in `failed` (critical) or
    `inactive` (warning). Carries the unit name as `target` so the 🩺 button
    runs `systemctl status` + `journalctl -u <unit>` automatically. Resolves
    the bug where Jakob stopped palworld.service and saw it only in Recent
    Activity, not in NA.
  - `monitor_down` — any monitor target whose latest probe came back `ok: false`.
  - `custom_script_fail` — any custom monitoring script reporting non-zero `rc`
    in its latest result.
  Full doc at `docs/attention.md`.
- **Dedicated Ignored items settings tab.** Was inside Settings → AI Assistant;
  now its own top-level Settings tab.
- **Collapsible sidebar.** Click ◀ at the top to shrink to a 56-px icon strip;
  click ▶ to expand. Preference saved in `localStorage` and applied before
  first paint.
- **IaC categories default to none-selected.** Empty selection on first load —
  user must opt in to categories before Generate is enabled.

### Earlier in v3.0.1
- **Logs ingestion**: dedupe by line content + parse embedded timestamps. apt.history,
  syslog, and nginx access lines now carry their real date — old re-submissions are
  evicted by the existing TTL instead of perpetually re-stamped as new. Removed the
  2 MB byte cap that was silently dropping nginx and brute-force lines whenever
  apt.history bloat filled the buffer (#4, #8).
- **Runbook**: containers and watched services now appear correctly (containers were
  read from the wrong storage; watched services fell back to the configured list if
  state hadn't been reported yet).
- **Reboot / shutdown**: drawer buttons set rebootTarget/shutdownTarget so the confirm
  modal actually sends a valid device_id.
- **IaC Generator**: fixed NameError on `_is_online`; corrected `result['text']` field
  (was reading `content`); removed bogus `model=None` kwarg.

### Improvements — UI (early v3.0.1)
- **Per-item ignore lists** (#1, #2, #3): × button on each Needs Attention card and on
  each stale container row. Restore from Settings → AI Assistant → Ignored items.
- **Logwatch severity** (#5): each log rule now carries OK / WARN / CRIT. WARN/CRIT
  fire webhooks; OK rules are silent noise-suppressors that confirm an expected
  pattern is still present.
- **IaC Generator**: two buttons — "Generate IaC" (full LLM flow) and "Gather RAW JSON"
  (collect-only, downloads the masked state without spending tokens) (#6).
- **Update banner snooze 30d** (#10): hide a specific version's update notification for
  30 days. Snooze is per-version, so a newer release re-shows the banner.
- **Force-upgrade agent button** (#11): re-deploy the bundled binary regardless of
  version match. Useful for corrupt-update recovery or pushing a rebuild.
- **Settings → Save settings**: button now shows "✓ Settings saved" inline alongside
  the toast (#7).

### Improvements — AI
- **Per-feature AI prompt customization**: Settings → AI Assistant → Prompt customization
  lets you override the system prompt for every AI feature, with a Default button to
  revert. Tune per-model (DeepSeek vs Claude vs Ollama) without code changes.
- **Per-feature AI fine-tuning** (#12): each prompt card has a ⚙ Fine-tuning panel
  for temperature, top_p, max_tokens, and num_ctx (Ollama / LocalAI). Empty fields
  fall back to provider defaults.

### Internal
- **Buffer-overflow audit** (#13): added depth guard to `_iac_mask_secrets` recursion
  (50 levels max); kept existing caps on body bytes (50 MB), journal lines (200×512B),
  cmd output (100×8 KB).
- 1307 unit tests passing.

## v3.0.0 — 2026-05-22

### Added
- **IaC Generator** (new top-level page) — generates Infrastructure-as-Code
  for any device on demand using the configured AI provider:
  - 18 categories: OS & identity, packages, systemd, users, groups, SSH keys,
    network, fstab, containers, repos, firewall, cron, TLS paths, env,
    snaps, kernel modules, sysctl, RemotePower-specific (tags/scripts/host-config).
  - 5 output formats: Terraform (HCL), Ansible (YAML), Pulumi (Python),
    Pulumi (TypeScript), Cloud-init (YAML).
  - On-demand collection: server flags the device, agent runs collectors on
    next heartbeat, server calls LLM with raw state, returns code.
  - Server-side secret masking — env vars whose NAME matches
    PASSWORD|SECRET|TOKEN|KEY|PASS|AUTH|CRED|PRIVATE are redacted before
    the payload leaves the host.
  - Markdown code-fence safety net — strips triple-backtick code-fence wrappers from LLM output.
  - Categories + format + last device persist in browser localStorage.

### Changed
- Three new server endpoints: `POST /api/iac/request`, `GET /api/iac/status/<id>`,
  `POST /api/iac/generate`.
- Agent gains 17 collector functions and processes `force_iac_collect` on
  heartbeat to attach `iac_data` to the following heartbeat.

## v2.9.0 — 2026-05-22

### Added
- **Device Drawer** — clicking any device on Devices or Dashboard opens a
  full-screen slide-in drawer with two tabs:
  - **Actions & Settings**: quick action grid (run command, reboot, shutdown,
    WoL, upgrade packages, scan packages, web terminal, run script, update
    agent, docker compose, host config, CMDB, runbook, maintenance, adjust
    poll, delete) plus inline editable device settings (group, tags, icon,
    monitored, poll interval, watched services, log rules, drift files,
    command allowlist) all with a single Save button.
  - **Audit**: 11 collapsible sections, lazy-loaded on first open — system
    info, listening ports (searchable), packages, logs (filterable by unit),
    command history (last 5 shown, all collapsed, expand per entry), fleet
    events, drift state, CVE summary, containers, metrics, host config.
- **⋮ button** now opens the drawer on the Actions & Settings tab directly.

### Fixed
- **Listening Ports** — `listening_ports` was never stored in `devices.json`
  (whitelist gap). Now persisted in `safe_si` on every heartbeat. Monitor
  page and device drawer now show real data.
- **Command output** — last 5 shown by default, all collapsed. Click to expand
  output. "Show N older commands" button for the rest.

## v2.9.0 — 2026-05-22

### Added
- **Device Drawer** — full-screen slide-in panel (replaces detail modal + ⋮ dropdown).
  - **Actions & Settings tab**: Run command, Reboot, Shutdown, WoL, Upgrade packages,
    Scan packages, Web terminal, Run script, Update agent, Docker compose, Host Config,
    CMDB, Runbook, Maintenance, Adjust poll, Remove device.
    Settings form: group, tags, monitored toggle, poll interval, watched services,
    log watch rules, drift watch files, command allowlist — all inline with Save.
  - **Audit tab**: 11 collapsible sections, all lazy-loaded on first open:
    System info, Listening ports (searchable), Packages, Logs (filterable by unit),
    Command history (last 5 collapsed, expand per entry), Fleet events, Drift state,
    CVE summary, Containers, Metrics, Host config.
- Clicking a device name (Devices or Dashboard) opens the drawer on the Audit tab.
- The ⋮ button opens the drawer on the Actions & Settings tab.

### Fixed
- **Listening ports "No data yet"** — `listening_ports` was not persisted in
  `sysinfo` in devices.json (whitelist gap). Now stored on every heartbeat and
  exposed via `/api/devices/:id/sysinfo`. Monitor page refresh button works.
- **Command output flooding** — detail view now shows last 5 commands collapsed;
  expand per entry; "Show N older" button for the rest.

## v2.8.1 — 2026-05-21

### Fixed
- **Brute-force threshold** raised to 20 (was 10). Now configurable in
  Settings → Dashboard along with the rolling window. Enable/disable toggle.
- **Recent Activity details** — each event now shows the most informative
  payload field inline (source IP for brute-force, user+fingerprint for SSH
  key, port+process for new port, age for backup stale, host+days for TLS).
- **Packages dedup** — update history now suppresses consecutive runs with
  identical "0 upgraded" output so the list stays readable.

### Added
- **Listening Ports on Monitor page** — fleet-wide table grouped by port/proto,
  showing which process is listening and on which devices.
- **Backup file age monitoring** — configure paths + max age in Settings →
  Dashboard. Agent reports mtime each heartbeat; `backup_stale` webhook fires
  edge-triggered; critical item in Needs Attention.
- **Settings → Dashboard** — new tab with brute-force config, backup monitors,
  per-kind Needs Attention toggles, and per-event-type Recent Activity toggles.
  All stored in `config.json` (applies to all users).

## v2.8.0 — 2026-05-21

### Added
- **Disk space in Needs Attention** — mounts above the configured warn/crit
  thresholds now surface as attention items (warning/critical), using the
  same per-device and per-mount thresholds already used for metric webhooks.
- **Listening port audit** — new port on a host fires `new_port_detected`
  webhook (edge-triggered). Baseline stored per device.
- **SSH key audit** — new authorized_key for any user fires `ssh_key_added`
  webhook with user and key fingerprint (edge-triggered). Reads from
  host_config_current, so "Collect all current" must have run at least once.
- **Brute-force detection** — SSH (`Failed password`, `Invalid user`) and
  web (`POST /wp-login.php`, `POST /xmlrpc.php`) failure patterns counted
  per source IP in a 5-minute rolling window. `brute_force_detected` webhook
  fires at 10+ attempts. Web access logs (`nginx.access`, `apache2.access`)
  collected incrementally by the agent.
- **CVE tile shows critical count** — the dashboard tile now displays the
  critical CVE count as the headline number. High-severity count shown below
  as the sub-label. Medium/low remain in the detail page only.

## v2.7.0 — 2026-05-21

### Added
- **Expanded log sources** — agent now auto-detects and watches
  `remotepower-agent`, `nginx`, `apache2`, and `ssh` if they exist,
  with no manual configuration. Logs flow through the existing pipeline.
- **Kernel log collection** — dmesg errors/warnings (emerg→warn levels)
  collected every 5 polls as virtual unit `kernel`. Incremental after
  first run; 24h window on startup.
- **APT history log** — `/var/log/apt/history.log` new-entry tracking
  submitted as virtual unit `apt.history`. Only sends when the file
  actually changes (mtime-gated).
- **Proxmox snapshot age alerts** — Virtualization page load caches
  snapshot ages server-side. Any snapshot older than `proxmox_snapshot_warn_days`
  days (default: 7) appears in Needs Attention.
- **`snapshot_old` webhook event** — edge-triggered once per VM when
  the oldest snapshot first crosses the age threshold. Resets when the
  snapshot is deleted.

## v2.6.1 — 2026-05-21

### Fixed
- **CVE tile always showed 0** — dashboard read `devices[].findings` (doesn't exist);
  the endpoint returns `devices[].counts` and a pre-aggregated `summary` field.
  Tile now reads `summary` directly. Critical/high counts shown in the sub-label.
- **Reboot/shutdown icon flash on mobile refresh** — service worker served stale
  cached HTML on pull-to-refresh, briefly showing elements from a previous build.
  Navigation requests now use network-first (cache is fallback when offline only).
  Cache bumped to `remotepower-shell-v2.6.1` to evict all stale entries.
- **Dead CSS removed** — `tr.has-hover-actions` / `.row-actions` block (marked
  REMOVED in v2.2.5, kept as no-ops for three releases) now deleted.

### Added
- **TLS/DANE expiry in Needs Attention** — cert within 30 days → warning;
  within 7 days or expired → critical. DANE failures also surface here.
  Items appear automatically once `tls_targets.json` has entries and
  `remotepower-tls-check` has run.
- **`tls_expiry` webhook event** — `remotepower-tls-check` fires once per
  threshold crossing (30d warning, 7d critical). Edge-triggered — no repeated
  alerts for the same state.
- **`reboot_required` webhook event** — fires once when a host's
  `/run/reboot-required` flag changes from absent → present (edge-triggered
  in the heartbeat handler).
- **Pending reboot in Needs Attention** — warning item for any monitored
  host with `reboot_required: true` in its latest sysinfo.
- **Stale agent version in Needs Attention** — info item when an agent
  reports a version older than the server. No webhook (informational only).
- **Mobile UX** — `touch-action: manipulation` on all interactive elements
  (eliminates 300ms tap delay); `-webkit-overflow-scrolling: touch` on scroll
  containers; `prefers-reduced-motion` support; minimum 44×44px touch targets
  on coarse-pointer devices.

## v2.6.0 - 2026-05-20

### Host Configuration Management

Define the desired state of each Linux host server-side. The agent
applies it on the next heartbeat (~60 s) and reports current state
every 15 minutes for drift audit.

**Sections managed per device:**

| Section | What it controls | Applied via |
|---|---|---|
| `repos` | Package repositories | `/etc/apt/sources.list` or `/etc/yum.repos.d/remotepower.repo` |
| `netplan` | Network config | `/etc/netplan/01-remotepower.yaml` + `netplan apply` |
| `nmcli` | NM connections | `/etc/NetworkManager/system-connections/remotepower-managed.nmconnection` |
| `resolv_conf` | DNS resolvers | `/etc/resolv.conf` (resolves symlinks) |
| `hosts` | Static host entries | `/etc/hosts` |
| `services` | Enabled systemd units | `systemctl enable --now` |
| `users` | Local users + SSH keys | `useradd`/`usermod` + `authorized_keys` |
| `groups` | Local groups | `groupadd` |
| `sudoers` | Sudo rules | `/etc/sudoers.d/remotepower` (validated with `visudo -c`) |
| `motd` | Login banner | `/etc/motd` |

**Server (`server/cgi-bin/api.py`):**
- Constants: `HOST_CONFIG_TEXT_SECTIONS`, `HOST_CONFIG_STRUCT_SECTIONS`,
  `HOST_CONFIG_ALL_SECTIONS`, `MAX_HOST_CONFIG_SECTION_SIZE` (64 KB),
  `HOST_CONFIG_AUDIT_EVERY` (15 polls).
- `_validate_host_config_section()` — per-section sanitization with
  NUL-byte rejection, size limits, type checking.
- `_audit_host_config_drift()` — compares desired vs current; text
  sections compared with normalized line endings; services use subset
  check; users check existence, shell, groups, authorized_keys; groups
  check existence.
- `_ingest_host_config_current()` — stores current state from agent,
  runs drift audit, fires `config_drift` webhook edge-triggered on
  first drift detection.
- `handle_device_host_config_get()` — `GET /api/devices/:id/host-config`
- `handle_device_host_config_put()` — `PUT /api/devices/:id/host-config`
- `handle_device_host_config_current()` — `GET /api/devices/:id/host-config/current`
- Heartbeat: includes `host_config_desired` in response; ingests
  `host_config_current` from payload.
- New webhook event: `config_drift` (priority 4, amber ⚠ wrench tag).

**Agent (`client/remotepower-agent.py` + binary):**
- `HOST_CONFIG_COLLECT_EVERY = 15` — collect and report every 15 polls.
- `collect_host_config()` — reads repos, netplan, nmcli connection file,
  resolv.conf, /etc/hosts, enabled services, users (UID ≥ 1000,
  authorized_keys), groups (GID ≥ 1000), sudoers drop-in, motd.
- `apply_host_config(desired)` — applies each section independently;
  failures logged but never block other sections; sudoers validated
  with `visudo -c` before rename; netplan runs `netplan apply`;
  authorized_keys written with correct ownership and mode 0600.
- Heartbeat loop: applies immediately when `host_config_desired`
  changes; collects every `HOST_CONFIG_COLLECT_EVERY` polls; includes
  `host_config_current` in payload.

**Frontend:**
- **Host Config** entry added to device dropdown "Configure" menu.
- `host-config-modal` — wide modal with section tabs (Repos, Netplan,
  nmcli, resolv.conf, /etc/hosts, Services, Users, Groups, Sudoers,
  MOTD). Amber drift banner shows which sections have diverged.
- Text sections: monospace textarea with placeholder, per-section
  drift indicator, "⬇ Fetch current" button.
- Services: one-per-line textarea.
- Users: expandable card per user (username, shell, groups,
  authorized_keys textarea). Add/remove buttons.
- Groups: inline row per group (name, optional GID). Add/remove.
- "Save & push to agent" collects all sections and PUT to server.



### Custom monitoring scripts

Define arbitrary bash health checks server-side and push them to
enrolled devices. The agent runs each check every 5 minutes (no agent
restart or update required), captures stdout+stderr, and reports back
over the existing heartbeat channel.

**Exit code contract:** 0 = OK, anything else = FAIL. Deliberately
binary — no MRPE severity levels.

**Server (`server/cgi-bin/api.py`):**
- `CUSTOM_SCRIPTS_FILE` (`custom_scripts.json`) — new data file for
  script definitions.
- Limits: 50 scripts fleet-wide, 10 per device, 32 KB body, 4 KB
  captured output.
- `_ingest_custom_script_results()` — validates script ownership,
  stores results on the device record, fires edge-triggered webhooks
  on status transitions. First result never fires an alert (avoids
  initial assignment flood).
- `_get_custom_scripts_for_device()` — builds the list of assigned
  scripts to include in each heartbeat response.
- `custom_scripts` added to the `common_resp` heartbeat payload.
- Five CRUD endpoints: `GET/POST /api/custom-scripts`,
  `GET/PUT/DELETE /api/custom-scripts/:id`.
- `GET /api/custom-scripts/results` — fleet-wide current results,
  sorted with failing rows first.
- Two new webhook events: `custom_script_fail` (priority 4, red) and
  `custom_script_recover` (priority 3, green). Both have Discord
  titles, ntfy tags, priority, and human-readable message strings.

**Agent (`client/remotepower-agent.py` + binary):**
- `SCRIPT_CHECK_EVERY = 5` — run every 5 polls (~5 min at default
  60 s interval).
- `run_custom_scripts(scripts)` — writes each script to a private
  temp file (chmod 700), runs it with `/bin/bash` and a 30 s timeout,
  captures stdout+stderr merged and capped at 4 KB, deletes the temp
  file. Returns `{script_id: {ok, output, rc, ran_at, duration_ms}}`.
- `custom_scripts` list and `pending_script_results` dict added to
  heartbeat loop state. Scripts list updated from every heartbeat
  response. Results flushed into the next heartbeat payload.

**Frontend:**
- New **Custom Scripts** sidebar entry (terminal icon) between Monitor
  and Services.
- `page-custom-scripts` — stats bar, filter/status toolbar, fleet
  results table, definitions panel (one card per script).
- `custom-script-modal` — create/edit: name, description, script body
  textarea, device picker (checkboxes), Delete button on edit.
- `cs-output-modal` — full output viewer (click any output snippet).
- `loadCustomScripts()`, `renderCustomScriptsPage()`,
  `renderCsDefinitions()`, `openCustomScriptModal()`,
  `saveCustomScript()`, `deleteCustomScript()`,
  `csGenerateWithAI()`.
- **Inline AI generation:** describe the check, click ✨ Generate,
  review the bash script, edit if needed, save. Uses the existing
  `generate_script` system prompt with custom instructions for the
  monitoring context (exit-code contract, output brevity, timeout
  budget). Markdown code fences are stripped from the AI response
  before populating the textarea.

**Docs:**
- `docs/custom-scripts.md` — full reference: how it works, exit code
  convention, creation flow, execution environment, result viewing,
  alert semantics, limits, 5 example scripts, security considerations,
  full API reference.
- `docs/features.md` — new section in the detailed tables and a new
  entry in the "Added in" narrative section. Top summary table updated.
- `README.md` — custom scripts row added to the feature table.
- In-app documentation (Help → Documentation search) — new `doc-card`
  covering creation, results, alerts, and execution details.



### Progressive Web App (PWA) support

RemotePower is now installable as a desktop or mobile app via Chrome
(and any other Chromium-based browser that supports PWAs).

**What changes:**

- **`server/html/manifest.json`** (new) — Web App Manifest with name,
  short name, theme colour (`#3b7eff`), background colour, `standalone`
  display mode, and proper 192×192 and 512×512 icon references.
- **`server/html/sw.js`** (new) — Service worker with a versioned
  cache (`remotepower-shell-v2.4.15`). Strategy:
  - `/api/*` requests are always **network-only** — fleet data is live
    and must never be served from a stale cache.
  - Non-GET and cross-origin requests pass through unmodified.
  - App shell assets (HTML, JS, CSS, icons, manifest) are cached on
    install and served cache-first; newly fetched responses are added
    to cache automatically.
  - Navigation requests that fail offline fall back to the cached
    `index.html` shell so the login page appears rather than a browser
    error.
  - On each SW activate, all caches from previous versions are deleted.
- **`server/html/static/img/icon-192.png`** and **`icon-512.png`**
  (new) — PWA icons at the sizes Chrome requires, generated from the
  existing `logo-square.png`.
- **`server/html/index.html`** — added `<link rel="manifest">`,
  `theme-color` meta tag, `apple-mobile-web-app-*` meta tags, SW
  registration script, and a hidden **Install app** button in the
  header that becomes visible when Chrome determines install criteria
  are met (`beforeinstallprompt`). Clicking it triggers the native
  Chrome install dialog.
- **`server/conf/remotepower.conf`** — three nginx changes:
  1. `worker-src 'self'` added to CSP so the service worker is allowed
     to register.
  2. `location = /sw.js` with `Cache-Control: no-store` so the
     browser always fetches the current SW version.
  3. `location = /manifest.json` with correct `Content-Type:
     application/manifest+json` before the catch-all `.json` deny
     rule that would otherwise block it.
- **`deploy-server.sh`** and **`install-server.sh`** — `sw.js` added
  to the root-asset deploy loop alongside `manifest.json` and
  `favicon.*`.

**No agent changes.** PWA is purely a server/frontend feature.



### Patches page: Pending Reboot indicator

The Patches page now shows a small amber **⟳ Reboot** badge inline
with the hostname for any host that has `/run/reboot-required` on
disk (Debian / Ubuntu). Hovering the badge shows a tooltip confirming
the source. Useful for spotting hosts that were patched but not yet
restarted without opening each device detail individually.

**No agent change required.** The `reboot_required` flag has been
in the agent heartbeat since the early v1.x era. The server now
surfaces it through the patch-report API (`/api/patch-report`) and
the Patches page UI.

- `server/cgi-bin/api.py` — `handle_patch_report()` includes
  `reboot_required: bool` in every device entry. Value is always a
  boolean (`False` for distros that don't set the flag, or agents
  predating the field).
- `server/html/static/js/app.js` — `_registerPatchTable()` row
  renderer checks `d.reboot_required` and injects the badge.

### docs/features.md overhaul

Large sections were missing from `features.md`. Added:

- **AI assistant** — complete feature table covering providers,
  context-aware ✨ buttons, secret redaction, rate limiting,
  free-form chat, and local-model support (Ollama / LocalAI).
  The existing `docs/ai.md` is the full reference; `features.md`
  now has a proper summary table and cross-link.
- **MCP server** — feature table covering the 12 read-only tools
  and the no-write-tools policy.
- **Pending Reboot indicator** row added to the Fleet visibility
  table (this release).
- Top-level summary table extended with AI assistant and MCP rows.
- Added this release's new section under "Added in 2.2.x – 2.4.x".



Documentation and housekeeping release. No server or agent
behaviour changes beyond the version bump.

- `docs/features.md` brought current through v2.4.12 — mailbox
  threshold alerting, the `/api/status` endpoint and the
  recent-activity de-duplication were all missing.
- `CHANGES.md` and `CHANGELOG.md` merged into a single
  `CHANGELOG.md`. The two files had drifted apart and each held
  release entries the other was missing; this is the union.
- `docs/Manual.html` refreshed for current features and bumped
  to 2.4.13. The duplicate copy at the repo root was removed.
- Per-release notes under `docs/` pruned to the most recent
  three (v2.4.11–v2.4.13). `CHANGELOG.md` remains the complete
  history.
- Stale and malformed git tags cleaned up; only the last three
  releases are tagged going forward.
- `README.md` rewritten, led with the project logo.

## v2.4.12 - 2026-05-18

Dashboard fix: the "Recent activity" feed showed the most recent 8
events with no de-duplication, so one noisy host (an hourly
postfix log_alert) filled all 8 rows and buried everything else.
The feed now collapses repeated event+host+subject entries to
their most-recent occurrence — display only, the fleet event log
still records every event. 5 new tests, 1039 total, all passing.

Make-fleet-health-visible release. Mailbox threshold alerting: a
mailbox monitor can carry a threshold; crossing it fires a webhook
(edge-triggered). The Home "Needs attention" panel is now a single
ranked list computed server-side, merging offline devices, CVEs,
drift, patches and mailbox alerts. New /api/status endpoint — a
machine-readable fleet summary for external dashboards (Uptime
Kuma, Homepage, Grafana), behind a dedicated status token. 14 new
tests, 1035 total, all passing.

Documentation release. Audited docs/features.md against ~20
releases of changes — it was missing Proxmox, drift, the mailbox
monitor, the MCP server and more; now current. Added a full
install & admin guide (docs/admin-guide.md). The update-available
banner now shows the actual update commands and states that
RemotePower does not self-update. 11 new tests, 1021 total, all
passing.

Added "Scan packages now" to the device action menu. The agent
normally sends its package inventory + patch count only every few
hundred heartbeats; this one-shot flag makes it send a fresh
report on the next heartbeat or two — handy right after patching
a host. 7 new tests, 1010 total, all passing.

## v2.4.5 - 2026-05-17

Small features release.

### Added

- **"Scan packages now"** in the device action menu. The agent
  normally submits its package inventory + patch count only every
  few hundred heartbeats; this sets a one-shot flag so the device
  sends a fresh report within a heartbeat or two. Useful right
  after patching a host. The flag fires exactly once.

### Tests

- `test_v245.py`: 7 new tests. Total: **1010, all passing.**

### Upgrading from 2.4.4

Drop-in. Deploy the updated agent so hosts can act on the request.

### Caveats

Not instant — the request reaches the agent on one heartbeat and
is reported on the next (~1-2 min). The agent must be on 2.4.5.

## v2.4.4 - 2026-05-17

Bugfix and polish for the mailbox monitor, plus favicon.ico.

### Fixed

- **Mailbox monitor never received its paths.** The 2.4.3
  heartbeat handler read the mailbox path list from a `saved_dev`
  snapshot that the path list was never copied into — so the
  agent always got an empty list and never counted. `saved_dev`
  now carries `mailbox_paths`. A new test asserts the heartbeat
  response includes them.
- **favicon.ico restored.** Browsers auto-request `/favicon.ico`;
  the project shipped only `favicon.png`. A real favicon.ico is
  now included.

### Changed

- **Mailbox config moved to Settings → Mailbox monitor** (was on
  the device detail modal).
- **Dashboard view is now a tile** — same style/size as the
  Devices / Updates / Drift / CVE tiles, instead of a separate
  full-width card.

### Tests

- `test_v244.py`: 7 new tests. Total: **1003, all passing.**

### Upgrading from 2.4.3

Drop-in. A mailbox path configured under 2.4.3 starts working
once 2.4.4 is deployed — no reconfigure needed.

## v2.4.3 - 2026-05-17

Lightweight mailbox monitor.

### Added

- **Mailbox-count monitor.** Give a device one or more directory
  paths; the agent counts the regular files directly inside each
  (the Maildir `new/` convention — one file per unread message)
  and reports the numbers in its heartbeat. No IMAP/SMTP, no
  credentials, no message content — just counts. Configured in
  the device detail view; a "Show on dashboard" checkbox promotes
  a device so its counts appear in a Home-dashboard widget.
  Counting is done with os.scandir (no shell).

### Tests

- `test_v243.py`: 14 new tests. Total: **996, all passing.**

### Upgrading from 2.4.2

Drop-in. Deploy the updated agent to hosts you want to monitor.

### Caveats

The agent change is unit-tested for logic but not verified
end-to-end against a live server — smoke-test on one host first.
Counts refresh every ~5 minutes, not live. Counts files, not
messages (fits Maildir, not mbox). No threshold alerting yet.

## v2.4.2 - 2026-05-17

Small features release.

### Added

- **Default SSH username** — a per-user setting (Settings →
  Security → SSH preferences), stored in ui_prefs, validated as an
  SSH-safe username.
- **Quick SSH link** on the Devices page — an SSH icon next to
  each hostname builds an `ssh://user@host` link (IP when known,
  else hostname) and copies `ssh user@host` to the clipboard. The
  ssh:// hand-off depends on the client machine having an ssh://
  handler; the clipboard copy is the universal fallback.
- **Documentation** — four new Documentation-page cards: Proxmox
  virtualization, LXC containers, snapshots & rollback, quick SSH.

### Tests

- `test_v242.py`: 11 new tests. Total: **982, all passing.**

### Upgrading from 2.4.1

Drop-in, server-side.

## v2.4.1 - 2026-05-17

Bugfix release — CVE severity cache invalidation.

### Fixed

- **Stale CVE cache served wrong severities.** The 2.3.4 / 2.4.0
  severity fixes were correct but couldn't reach findings already
  in `cve_details_cache.json`. Entries written by a pre-2.3.4
  RemotePower carry a severity from the old buggy classifier and
  no `severity_source` field; the TTL-only refresh gate kept
  re-serving them (the tell: `severity: critical` +
  `severity_source: unknown`, an impossible pair from current
  code). Now an entry lacking `severity_source` is treated as
  stale regardless of TTL and re-fetched + re-classified. Self-
  healing — no manual cache wipe. Modern entries still use the
  normal TTL.

### Tests

- `test_v241.py`: 3 new tests (stubbed OSV). Total: **971, all
  passing.**

### Upgrading from 2.4.0

Drop-in, server-side. Stale entries refresh automatically; the
first post-upgrade scan of each device is a little slower.

## v2.4.0 - 2026-05-17

Proxmox snapshots + a CVE severity fix.

### Added

- **Proxmox VM/LXC snapshots.** A Snapshots button on each guest
  (Virtualization page for QEMU, Containers page for LXC) opens a
  modal to create / list / rollback / delete snapshots. Rollback
  is destructive — the UI requires typing the guest name to
  confirm. Delete is irreversible but doesn't touch the running
  guest. Disk-only snapshots (no RAM state). New `proxmox_client`
  methods + `GET /api/proxmox/snapshots`, `POST /api/proxmox/snapshot`.
  (Optional CPU/RAM adjustment and backup-trigger from the
  request are deferred — larger, separate work.)

### Fixed

- **CVE severity: Debian urgency shown as HIGH.**
  DEBIAN-CVE-2018-1000021 was HIGH while OSV rates it 5.0 Medium.
  When an OSV Debian entry has no CVSS, the chain fell back to the
  Debian tracker and mapped Debian's `urgency` straight to
  severity. Debian `urgency` is a patching-priority signal, not
  CVSS severity. The fallback is now capped at `medium` — it can
  never return high/critical.

### Tests

- `test_v240.py`: 17 new tests. One `test_v215` modal-ID test
  updated for the dynamically-created snapshot modal. Total:
  **968, all passing.**

### Upgrading from 2.3.4

Drop-in, server-side.

### Caveats

Not tested against a live Proxmox node (unit tests cover logic,
not API request shapes). Snapshot actions are fire-and-forget —
no task-completion polling. Disk-only snapshots. CVE severity
recomputes on next scan.

## v2.3.4 - 2026-05-17

Fleet-issues bugfix release.

### Fixed

- **CVE severity misclassification.** The CVSS scorer did
  substring matching — `'c:h' in vector` matched `AC:H` (Attack
  Complexity High) as `C:H` (Confidentiality High), so every
  high-attack-complexity CVE scored 7.5/HIGH regardless of real
  impact. A CVSS 2.9 LOW vuln came out HIGH. Now the CVSS vector
  is properly tokenised and the real CVSS v3.1 base-score formula
  applied; <4.0 can never be HIGH. Findings carry a
  `severity_source` field.
- **Unmonitored devices in Recent Activity.** Events for
  `monitored:false` devices are now filtered out of the fleet
  activity feed (at read time, reflecting current state).
- **Drift false positives.** Watched files can now be marked
  `ignored` per device — ignored files are non-critical (out of
  the drift/missing counts, no red status) but stay visible.
- **Services and Logs** moved from the Security nav group to Main.

### Investigated, not changed

- Dashboard time ranges (#3): no regression found — what looks
  like "only yesterday" is the known no-server-side-uptime-history
  limitation, a separate feature, not a bug.
- Mobile rendering: deprioritised per the issue list (resolved by
  switching browsers — browser-specific, not a code defect).

### Tests

- `test_v234.py`: 11 new tests; 3 pre-existing severity tests
  updated for the new `(severity, source)` return. Total: **951,
  all passing.**

### Upgrading from 2.3.3

Drop-in. CVE severities recompute on the next scan.

## v2.3.3 - 2026-05-17

Bugfix release.

### Fixed

- **Virtualization page was undiscoverable.** The Virtualization
  nav entry shipped hidden (`display:none`) and was only revealed
  once Proxmox was enabled — but you enable Proxmox under Settings,
  so the feature couldn't be found in the first place. The nav
  entry is now always visible; the page already handles the
  not-configured state with a "configure under Settings -> Proxmox"
  message.

### Known issue (not fixed)

A reported broken mobile render (page shows almost nothing) is not
addressed — it needs the browser console error to diagnose
properly rather than guess.

### Tests

Full regression: **940 tests, all passing.** No new tests — a
one-line visibility fix.

### Upgrading from 2.3.2

Drop-in.

## v2.3.2 - 2026-05-17

Security release — no new features. Result of a focused security
review (full writeup: docs/security-review-2.3.2.md).

### Fixed

- **Unsalted SHA-256 password fallback → salted PBKDF2.** When
  bcrypt wasn't installed, password hashing fell back to bare
  unsalted `sha256` — rainbow-table-able if `users.json` leaked.
  Now salted PBKDF2-HMAC-SHA256 (600k iterations, stdlib). Legacy
  hashes still verify and upgrade automatically on next login.
- **Default-password warning.** A bare-metal install seeds
  `admin`/`remotepower`. The seeded hash is now properly salted,
  and the account carries a `must_change_password` flag that
  drives a persistent red UI banner until the password is changed.

### Reviewed, unchanged

Login rate-limiting, constant-time compares, TOTP, agent TLS
verification, SSRF guard, security headers / CSP — all reviewed and
sound. Accepted limitations (CSP `'unsafe-inline'`, plaintext
secrets in config.json, CSRF posture) documented in the review.

### Tests

- `test_v232.py`: 11 new tests. Total: **940, all passing.**

### Upgrading from 2.3.1

Drop-in, server-side only. Existing password hashes keep working
and upgrade silently on next login.

## v2.3.1 - 2026-05-17

Security release — Proxmox token secret hardening.

### Changed

- **Proxmox token secret via environment variable.** The token
  secret can now be supplied in `RP_PROXMOX_TOKEN_SECRET` (systemd
  unit / container env); when set it takes precedence over
  `config.json`. Keeps the secret out of the data directory and
  out of the backup export. The `config.json` value remains a
  fallback. Settings → Proxmox detects an env-sourced secret and
  disables the config field.
- **Backup export redacts config.json secrets.** The backup ZIP
  used to include `config.json` verbatim — carrying the live
  Proxmox token, SMTP password and LDAP bind password. All three
  are now redacted in the exported copy (keys kept, values
  replaced with `(redacted)`).

### Tests

- `test_v231.py`: 8 new tests. Total: **929, all passing.**

### Upgrading from 2.3.0

Drop-in. To move the Proxmox secret out of `config.json`: set
`RP_PROXMOX_TOKEN_SECRET`, then clear the field in Settings and
save.

## v2.3.0 - 2026-05-17

Proxmox VE integration.

### Added

- **Proxmox VE integration.** RemotePower connects to a single
  Proxmox node and surfaces its guests:
  - New **Virtualization page** — QEMU VMs with status, CPU/mem,
    uptime; start / graceful-shutdown actions.
  - **LXC containers** appear as a section on the Containers page,
    same start / shutdown actions.
  Server-to-API integration — the RemotePower server calls the
  Proxmox REST API directly, no agent on the Proxmox node. New
  stdlib-only `proxmox_client.py` module.
- **Settings → Proxmox** — host, node, API token ID + secret,
  Verify TLS toggle, Test-connection button. Token secret is
  masked in the config API and stored in `config.json` (mode
  0600, not encrypted — use a scoped API token).
- Action allow-list (`start`/`shutdown`/`stop`/`status`); UI
  exposes start + graceful shutdown only. `migrate`/`clone`/
  `delete` cannot be invoked.

### Tests

- `test_v230.py`: 28 new tests. Total: **921, all passing.**

### Upgrading from 2.2.7

Server-side only, no agent change. Configure under Settings →
Proxmox; until then nothing changes.

### Caveats

Not tested against a live Proxmox node — unit tests cover the
logic, not the API request shapes. No background polling (every
page visit calls the API synchronously). Actions are
fire-and-forget (no task-status confirmation). Single node only.

## v2.2.7 - 2026-05-17

Mobile hotfix.

### Fixed

- **Mobile navigation drawer was unusable** — a wide panel of
  unlabelled icons. Two media-query blocks (a 768px icon-rail and a
  720px drawer) both applied below 720px and fought. The icon-rail
  block is removed; the drawer is now the single mobile layout with
  labels, alignment and padding restored.

### Tests

- `test_v227.py`: 6 tests. Total: **893, all passing.**

### Upgrading from 2.2.6

Drop-in — one CSS file changed.

## v2.2.6 - 2026-05-16

Correctness + telemetry release.

### Fixed

- **CVE scanner false positives on already-patched packages.** The
  scanner turned every OSV hit into a finding with no installed-vs-
  fixed version comparison — flagging e.g. `lua5.1 5.1.5-9build2`
  as vulnerable when it's newer than the ESM fix. New
  `_already_patched()` gate: Debian/Ubuntu uses `dpkg
  --compare-versions`, other ecosystems a tuple comparator;
  fail-safe keeps the finding on any uncertainty. Scan result
  carries a `suppressed_patched` count.
- **Docker random admin password.** Entrypoint generates a strong
  random password (`secrets.token_urlsafe`) when `RP_ADMIN_PASS`
  is unset and prints it once in a banner — no more `changeme`
  plaintext default.
- **Docker healthcheck** used `curl`, never installed → container
  always `unhealthy`. Switched to Python urllib.
- **nginx `duplicate MIME type "text/html"`** warning — removed
  `text/html` from `gzip_types`.
- **`remotepower-passwd` empty-default username** — Enter now
  defaults to the sole user instead of erroring "User '' not found".
- **Mobile modal stacking** — z-index scale normalised into clean
  tiers (dropdowns were at 10000, above modals); opening a modal
  closes the mobile nav + locks body scroll; mobile modals are
  full-bleed sheets.

### Added

- **Drift: expanded watch list** (8 → 13 files: passwd, group,
  login.defs, common-auth, apt sources) + **dormant handling** —
  a watched file absent for 3 consecutive heartbeats goes dormant,
  fires one event then goes quiet, stops counting as drift, and
  auto-revives if the file returns.
- **Agent host-health telemetry** — `get_host_health()` collects
  reboot-required, failed systemd units, logged-in users,
  listening ports, last boot. Surfaced in the device detail modal.
- **Container CPU / memory + health badge** — agent runs
  `docker stats`, parses `(healthy)`/`(unhealthy)` from status.
  Shown on the container card.

### Tests

- `test_v226.py`: 22 new tests.
- `test_v220` missing-file test updated for the dormant behaviour.
- Total: **887 tests, all passing.**

### Not included

New monitor types ("more monitor options") are deferred — they
need check logic + UI forms and warrant their own release.

### Upgrading from 2.2.5

Server + agent drop-in. Rebuild the Docker image for the
healthcheck/entrypoint fixes.

## v2.2.5 - 2026-05-15

Five UX fixes from live driving of the 2.2.4 dashboard.

### Changed

- **Container width 1100 → 1300 px.** Data density grew through
  the 2.2 cycle; 1300 fits 4 Home tiles + wide tables comfortably
  on standard 1920 monitors.
- **Tables / grids gain scroll wrap above 20 rows.** New
  `.scrollable-table-wrap` (sticky thead) and
  `.scrollable-grid-wrap` CSS classes. `tableCtl.render()` toggles
  the wrap on every render based on rendered row count. Devices
  card-grid view also gains the wrap above the same threshold.
- **Home → Recent activity items are clickable.** Each event
  routes to the most relevant page or modal for its class. Switch
  statement with explicit cases for every canonical fleet event;
  contract test asserts parity with `WEBHOOK_EVENT_NAMES`.
- **Favicon stays at document root.** Caught a real deploy bug:
  `deploy-server.sh` only published `*.html` from the doc root, so
  `/favicon.png` returned 404. Added an explicit loop for root
  non-HTML assets (favicon, robots.txt, manifest.json). Removed
  the duplicate `static/img/favicon.png` to keep a single source
  of truth.
- **Detail / Logs / Run hover affordance removed.** The strip was
  persistently fiddly (2.2.1 clipping, 2.2.2 placement). The row
  dropdown chevron exposes the same commands and is
  keyboard-friendly; clicking the device name opens the detail
  modal. CSS rule kept as a `display: none` no-op for back-compat.

### Tests

- `test_v225.py`: 14 new tests.
- `test_v222.TestPolishHotfixes`: three hover-affordance assertions
  inverted to "the strip is gone" — historical evolution preserved
  in test comments.
- Total: **865 tests, all passing.**

### Upgrading from 2.2.4

Drop-in. The favicon fix only takes effect on the next run of
`deploy-server.sh`.

## v2.2.4 - 2026-05-15

Two real-world bugs surfaced by live testing of the Home dashboard.

### Fixed

- **Recent fleet events panel was empty even after devices went
  offline.** Root cause: the activity panel read from the webhook
  delivery log, which only records events that had at least one
  destination (webhook URL or enabled email). Events firing with
  no destinations configured (typical fresh install with only SMTP)
  vanished into the void.
  - New dedicated **fleet event log** at `data/fleet_events.json`
    records every fired event regardless of destinations. Capped at
    `MAX_FLEET_EVENTS = 200`. `'test'` events excluded.
  - `_record_fleet_event(event, payload)` called from the top of
    `fire_webhook`, before all the existing gates. Payload
    summarised to discriminator keys (`device_id, device_name,
    path, unit, metric, cve_id, severity, …`), strings capped at
    256 chars.
  - New endpoint `GET /api/fleet/events?limit=N` (default 50, max
    200, newest first). Auth: any logged-in user (unlike
    `/webhook/log` which is admin-only).
  - Home dashboard `loadHome()` now reads `/fleet/events`; renderer
    adjusted for the `{ts, event, payload}` shape.
  - Empty-state copy updated to reflect the new behaviour.

- **Unmonitored devices appeared in "Needs attention".** Operators
  set `monitored: false` to silence a host (decommissioned, dev
  boxes, hosts being rebuilt) — the dashboard shouldn't bring them
  back up.
  - `_renderHomeAttention` filters `monitored !== false` at the
    top; reuses the filtered list for offline detection, patch
    backlog, and drift cross-reference. Same predicate the alert
    pipeline uses.
  - Drift section gates on the monitored set too (intersected
    with drift overview devices).

### Tests

- `test_v224.py`: 16 new tests covering fleet event recording,
  the endpoint, the no-destinations regression, and frontend
  changes.
- Total: **851 tests, all passing.**

### Upgrading from 2.2.3

Drop-in. New `data/fleet_events.json` created on first event
firing — no migration. On a fresh upgrade the activity panel is
empty until the next event fires; the "Needs attention" panel
benefits immediately.

## v2.2.3 - 2026-05-15

Hotfix to the Home dashboard activity panel — operator SMTP /
webhook tests were drowning real fleet events.

### Fixed

- **Activity panel now filters to canonical fleet events.** The
  JS keeps a `FLEET_EVENTS` allowlist mirroring the server's
  `WEBHOOK_EVENTS` tuple (`device_offline`, `device_online`,
  `monitor_*`, `service_*`, `cve_found`, `patch_alert`, `log_alert`,
  `container_*`, `metric_*`, `command_*`, `drift_detected`). The
  `test` event used for SMTP test deliveries and webhook test
  deliveries is **not** in the list, so test rows no longer
  clutter the dashboard.
- Tests are still recorded in the underlying webhook log
  (Settings → Webhook log view, unchanged) — they just don't
  reach the activity panel.
- The filter runs **before** `slice(0, 8)`, so real events can't
  be crowded off the visible window by a burst of test noise.

### Tests

- `test_v223.TestActivityFilter`: 3 tests. The contract test
  asserts the JS allowlist is exactly equal to the server's
  `WEBHOOK_EVENT_NAMES` — if a future commit adds a fleet event
  to the server tuple without updating the JS, the dashboard
  silently dropping that event surfaces as a test failure.
- Total: **835 tests, all passing.**

### Upgrading from 2.2.2

Drop-in. No data migrations, no agent changes.

## v2.2.2 - 2026-05-15

Small hotfix for three things found in the first browser run of
2.2.1. No new features.

### Fixed

- **Hover-action focus ring clipped on right edge.** The 2.2.1
  hover-revealed `Detail · Logs · Run` strip lived in the narrow
  last cell; focus rings extended beyond the cell's right edge and
  got visibly clipped. v2.2.2 moves the strip to the first cell
  (kept absolutely positioned so visual placement is unchanged),
  bumps `right: 12px` → `right: 24px`, adds `z-index: 2`, suppresses
  the system focus outline in favour of a softer accent border.
- **Home dashboard activity panel hit a 404.** `loadHome()` called
  `/api/webhook-log` — the path should have been `/api/webhook/log`.
  Also adjusted the renderer to handle the actual response shape
  (a flat list, not `{events: [...]}`). Viewers (who don't have
  permission for this endpoint) now see the friendly empty state
  rather than a console error.
- **`handle_webhook_log` 500 on bare-list `webhook_log.json`.**
  Pre-existing bug surfaced by the same test. Some deployments
  (older releases or hand-edited files) have the file as a bare
  list instead of `{entries: [...]}` — handler now accepts both.

### Tests

- `test_v222.py`: 8 new tests covering the three fixes.
- Total: **832 tests, all passing.**

### Upgrading from 2.2.1

Drop-in. No data migrations, no agent changes.

## v2.2.1 - 2026-05-15

Design polish release. No new feature surfaces — nine focused
improvements to how the existing ones look and feel, plus one
sub-feature (drift diff visualisation) that completes the v2.2.0
drift detection story.

### Added — Design polish (10 pieces)

1. **Distro logos next to device names.** Branded SVGs for Ubuntu,
   Debian, Arch, CachyOS, Fedora, RHEL family, openSUSE, Alpine,
   NixOS, Raspbian, FreeBSD, generic Linux. Inline, ~14×14, no
   external requests. Visible on device cards, the minimal table,
   the Drift page, and the Home dashboard. `osIcon()` API
   preserved — existing callers get the upgrade automatically.

2. **Sparkline mini-charts on device cards.** 52×14 SVG line
   charts next to disk and memory percentages. Auto-coloured by
   value (green / amber / red). Client-side ring buffer in
   `window._metricsHistory` builds 24 readings per metric per
   device as you sit on the page.

3. **Refined status colour palette.** New `--green-soft/edge`,
   `--amber-soft/edge`, `--red-soft/edge`, `--accent-soft/edge`
   CSS variables. New `.status-pill` component with five
   variants. Critical-state pulse animation (warning states are
   deliberately *not* pulsing — too noisy at fleet scale).
   `prefers-reduced-motion` honoured.

4. **Skeleton loaders replace centred spinners.** Shimmer-animated
   placeholder rows / cards on 11 HTML tables + 6 JS-injected
   loading states. New `renderSkeletonRows()` and
   `renderSkeletonCards()` helpers.

5. **Home dashboard** — new default landing page. Four big-number
   tiles (devices online, pending updates, drift events, CVE
   findings), "Needs attention" panel, "Recent activity" feed,
   fleet roster with 7-day status stripe per device. The first
   page you see is now fleet-at-a-glance, not the devices list.

6. **✨ identity extended.** Every ✨ button gets `.ai-btn` +
   provider-tinted glow (`.available` for cloud, `.local` for
   Ollama / LocalAI). AI-thinking state shows three sparkles
   cycling. AI-generated markdown content gets a gradient left
   edge. MutationObserver auto-applies to newly-rendered content.

7. **Typography upgrade.** Inter (UI) + JetBrains Mono (technical
   identifiers) via bunny.net — privacy-friendly Google Fonts
   mirror. Graceful fallback to system font stack for air-gapped
   deployments. `font-feature-settings cv02 cv03 cv04 cv11 ss01`
   enabled for the better "1", "a", "g" glyphs.

8. **Per-row hover affordances.** Minimal devices table rows
   reveal a `Detail · Logs · Run` strip on hover. Saves a click vs
   opening the row dropdown. Hidden on mobile (no hover on touch).

9. **Mobile dashboard view.** Phone-sized layout (<720 px):
   sidebar behind a burger button, tile grid stacks, low-priority
   columns hidden, tap targets ≥36 px, modals nearly full-screen.

10. **Logo → Home.** The header logo now navigates to the Home
    dashboard (was: Devices page).

### Added — Drift diff visualisation

The diff view that completes the v2.2.0 drift detection story.

- New endpoint `POST /api/devices/<id>/drift/fetch_content` —
  queues `exec:cat <path>` for each requested path. Denylist
  enforced (`/etc/shadow`, `/etc/gshadow`, rotated `-` siblings).
  Refuses non-watched paths to prevent use as an arbitrary
  file-read primitive.
- New endpoint `GET /api/devices/<id>/drift/content?path=...` —
  returns up to 2 stored captures with sha256.
- New mirror hook `_maybe_mirror_drift_content()` in the heartbeat
  output-ingest path. Detects `exec:cat <watched_path>` outputs
  and mirrors them into `drift_contents.json`. Denylist enforced
  on the mirror side too (defence in depth).
- New storage `data/drift_contents.json`, last 2 captures per
  path, ≤256 KB per capture.
- New UI: "Show diff" button per drifted file. Opens a sub-modal
  that polls for the cat output (every 5s, up to 90s) and renders
  a unified diff between the two most recent captures using
  LCS-based pure-JS `computeDiff()` + `renderDiff()`.
- New CSS: `.diff-view`, `.diff-line.add/del/hunk` for unified
  diff with syntax-coloured backgrounds.

### Tests

- `test_v221.py`: 46 new tests covering drift content fetch (7),
  drift content get (5), drift content mirror (6), and design
  polish asset presence (28 — verifies CSS / JS / HTML structures
  are in place).
- Pre-existing `test_v215.TestHtmlIdReferences`: drift-diff-modal
  IDs added to `KNOWN_DYNAMIC_IDS`.
- Total: **824 tests, all passing.**

### Upgrading from 2.2.0

Drop-in for the server. The new `data/drift_contents.json` file
is created on first content-fetch request — no migration needed.
No agent changes required: drift content fetch uses the existing
`exec:cat` mechanism, supported by every agent v1.0+.

## v2.2.0 - 2026-05-15

First minor-version bump since 2.1.0. Two new feature surfaces, both
tied to current themes in the fleet-management space.

### Added — Configuration drift detection

New **Drift** page under the Security sidebar group. Per-device
file integrity monitoring for a configurable list of config files
(default: SSH config, sudoers, fstab, crontab, hosts, resolv.conf,
nsswitch.conf, PAM sshd).

- Agent computes SHA-256 hashes of watched files every few
  heartbeats and ships them in the heartbeat payload.
  **Hash-only by design** — file contents never cross the wire on
  routine polling. `/etc/sudoers` and `/etc/shadow` can be watched
  without privacy concerns.
- Server stores baselines, detects divergence, fires
  `drift_detected` webhook once per change (debounced — not on
  every poll that reports the same new hash).
- New UI: fleet overview table + per-device detail modal with
  history viewer and "accept as baseline" button. Baseline
  acceptances are audit-logged with actor + timestamp.
- New endpoints: `GET /api/drift`, `GET / POST-baseline / DELETE
  /api/devices/<id>/drift`.
- New webhook event: `drift_detected` (defaults to enabled).
- New storage: `data/drift_state.json`, history capped at 20
  changes per file.
- **Requires agent v2.2.0+** for the agent-side hash reporting.
  Older agents work normally, just don't show drift data.
- Reference: [docs/drift.md](docs/drift.md). Compliance angle:
  SOC 2 CC6.1/CC6.6, ISO 27001 A.12.4.3/A.14.2.4, HIPAA
  164.312(c), PCI DSS 11.5, FedRAMP.

### Added — MCP server (natural-language fleet queries)

New `mcp/remotepower-mcp.py` (~470 lines, pure stdlib Python).
Implements the [Model Context Protocol](https://modelcontextprotocol.io)
so AI hosts like Claude Desktop, Cursor, or VS Code Copilot can
query the fleet in natural English.

- Runs on the **operator's laptop**, not on the RemotePower server.
  Spawned as a stdio subprocess by the AI host.
- Speaks JSON-RPC 2.0 over stdin/stdout; calls RemotePower's REST
  API on behalf of the AI using a regular API token.
- **12 read-only tools**: `list_devices`, `get_device`,
  `get_journal`, `get_services`, `get_containers`, `get_cves`,
  `get_drift`, `get_recent_commands`, `get_runbook`,
  `get_patches`, `get_tls`, `search_devices`.
- Device-name resolution: exact → prefix → substring →
  ambiguity error.
- **No write tools**, by deliberate design. Test suite asserts
  no write-shaped names slipped in. Write tools land in a future
  release with the server-side allow-list and per-token role in
  place — not before.
- Protocol version pinned to `2024-11-05` (widely-supported
  version hosts standardised on).
- Setup, Claude Desktop config snippet, security model,
  troubleshooting: [docs/mcp.md](docs/mcp.md).

### Changed

- **README "What's new"** trimmed to the latest three releases
  (2.2.0, 2.1.9, 2.1.8).
- **In-app Documentation page**: new doc-cards for Drift and MCP.

### Tests

- `test_v220.py` (24 tests): drift ingest behaviour (7), drift
  endpoints (5), MCP protocol (7), MCP device resolution (5).
- `test_v184.TestWebhookEventsConstant`: updated for new
  `drift_detected` event.
- `test_v215.TestHtmlIdReferences`: added drift-detail-modal IDs
  to `KNOWN_DYNAMIC_IDS` allow-list.
- Total: **778 tests, all passing.**

## v2.1.9 - 2026-05-15

Same-day hotfix for runbook hallucination on smaller local models,
plus a demo URL correction.

### Fixed

- **Runbook generator was inventing services, ports, firewall rules
  on smaller local models** (reported on Ollama qwen2.5-coder:14b).
  Three compounding causes, all fixed:
  1. **Ollama defaults to `num_ctx=2048` on the OpenAI-compat
     endpoint** — the snapshot was being truncated mid-content and
     the model invented the rest. `ai_provider.chat_openai_compatible`
     now passes `options.num_ctx=16384` for Ollama / LocalAI
     (ignored by real OpenAI / DeepSeek, which accept unknown body
     keys).
  2. **The v2.1.7 runbook prompt was too elaborate** — 8 verbose
     sections, no explicit anti-fabrication instructions. Rewritten
     to ~1 KB / 6 sections with `CRITICAL RULES` near the top:
     "Use ONLY information from the snapshot. Do NOT invent…", and
     each section has an explicit "if empty, write X" fallback.
  3. **The snapshot itself was too big** — up to 25 KB. Tightened
     to ~8 KB: 20 journal lines (was 40), 5 commands at 200 chars
     each (was 15 × 500), 10 CVEs at 100-char summaries (was 20 ×
     200), 10 containers (was 30), 500-char notes (was 1000),
     trimmed sysinfo to 9 operator-relevant fields, top 5 disks by
     usage.

- **Demo URL is `demoremote.tvipper.com`**, not `demo.tvipper.com`.
  Fixed across all `*.md` and `*.html` in the repo.

### Tests

- `test_v219.py` (8 tests): num_ctx wiring (Ollama/LocalAI yes,
  OpenAI no), prompt anti-hallucination keyword presence + size
  cap, snapshot bounded under 10 KB on synthetic heavily-populated
  device, no bare `demo.tvipper.com` in markdown files.
- Total: **754 tests, all passing.**

### Upgrade note

Existing stored runbooks in `runbooks.json` were written under the
bug. Worth regenerating any you care about via the **✨ Regenerate**
button on each device's detail modal Runbook section.

## v2.1.8 - 2026-05-15

Hotfix for a v2.1.7 bug where the AI fleet context reported every
device as offline.

### Fixed

- **AI fleet context wrongly reported all devices as offline.** The
  `ai_context.py` builder was reading `d.get('online')` directly,
  but `online` is a derived field computed on-the-fly by
  `handle_devices_list` from `last_seen` + `get_online_ttl()` — it's
  not persisted in `devices.json`. Every device looked `online=None`
  → falsy → "offline" in the AI's view. Reported by an operator
  whose live web server showed as offline in an AI chat response.
- Fixed: `ai_context._is_online()` now computes status canonically
  using the same formula as the device-list handler (recent
  heartbeat → online; agentless → manual_status default True).
  `build_fleet_context` and `build_combined_system_prompt` accept
  `now` and `ttl`; callers in `handle_ai_chat` and
  `handle_runbook_generate` pass `get_online_ttl()` so the AI sees
  exactly the same status as the dashboard.
- 5 new regression tests in `test_v217.py`; two pre-existing tests
  rewritten to use `last_seen` instead of the phantom `online`
  field that hid the bug.

Total: **746 tests, all passing.**

## v2.1.7 - 2026-05-14

Two new AI features and a few README/docs polish bits.

### Added

- **AI-generated device runbooks** (`✨ Generate runbook` in the
  device dropdown). Structured Markdown document per device —
  Purpose / Stack / Services / Exposure / Scheduled work / Recent
  activity / Health & risks / Operating notes. Built from the
  device's current state (sysinfo, journal, services, containers,
  CVEs, patch status, recent commands). Saved per-device in
  `runbooks.json`, regenerable any time.
  - New endpoints: `GET / POST-generate / DELETE
    /api/devices/<id>/runbook`.
  - New UI: ✨ Generate runbook modal with elapsed-time ticker;
    Runbook section on the device detail modal with View / Regenerate
    / Delete buttons.
  - Rate-limited under the same per-user-per-day cap as `/api/ai/chat`.
  - No batch "regenerate all" button, deliberately — cost-sensitive.

- **Level-1 RAG context awareness.** Every AI request now prepends
  a project-context block (what RemotePower is, the storage
  conventions, the agent/heartbeat model) plus a fleet snapshot
  (one line per device with name / OS / status / group / tags /
  notes). Online devices first.
  - New `ai_context.py` module (~180 lines, pure stdlib): no
    embeddings, no vector store. For ~5000 lines of docs and ~10
    devices, hand-curated context is cheaper and just as effective
    as a real RAG pipeline.
  - Configurable in Settings → AI assistant → **Context awareness**.
    Two checkboxes: include project context (non-sensitive, default
    on), include fleet snapshot (contains hostnames, default on).
  - Makes the AI stop giving generic Linux advice and start giving
    advice that references your devices, your groups, your conventions.

### Changed

- **README**: demo URL (`https://demoremote.tvipper.com`, demo/demo) now
  visible at the top of Quick start; "What's new" trimmed to the
  latest three releases. Older entries point at CHANGES.md.
- **Documentation page** (in-app): added four new doc-cards covering
  Scripts (script library), AI assistant (✨ button inventory),
  Device runbooks (v2.1.7), and Notification setup (recommended
  baseline + maintenance windows + ✨ Explain on alerts).

### Tests

- `test_v217.py` (26 tests): context module, chat integration,
  runbook generate / get / delete
- `test_v213.py`: updated for the new context-wrapped system prompt
- Total: **741 tests, all passing**

## v2.1.6 - 2026-05-14

Same-day hotfix for two compounding bugs on the Patches page.

### Fixed

- **Patches → Detail button threw "can't access property textContent
  of null".** Two issues stacked:
  1. The 2.1.5 ✨ Prioritise button placed `display:flex` on a
     `<td>`, which removed the cell from its `display:table-cell`
     behaviour and made the Detail buttons render outside the
     table. Fixed: flex container moved to a `<div>` inside the cell.
  2. The Detail handler `openDevicePatchReport()` referenced
     `#device-patch-title` / `#device-patch-body` / `#device-patch-modal`
     — but **those elements were missing from `index.html`
     entirely**. The function had been broken for several releases;
     the new ✨ Prioritise button drew attention to it. Restored
     the missing modal.

### Added — regression test

- `tests/test_v215.py::TestHtmlIdReferences` scans `app.js` for
  every `getElementById(...)` + `(open|close)Modal(...)` reference
  and verifies the ID exists in `index.html` (modulo a
  `KNOWN_DYNAMIC_IDS` allow-list for AI modal + toast). Bugs of
  this exact shape — JS referencing an HTML element that doesn't
  exist — will now fail at build time. Verified by temporarily
  removing the modal: test correctly listed all three missing IDs.

- 715 tests total, all passing.

## v2.1.5 - 2026-05-14

Polish release. Six items queued from real-world use of the 2.1.3/4
AI work plus the long-pending stderr-spam fix.

### Fixed

- **"No Data Provided" from ✨ Investigate** even when the device had
  data. Root cause: the JS was hitting `GET /api/devices/<id>` — a
  route that doesn't exist. Fixed: assemble the snapshot in parallel
  from `/sysinfo`, `/output`, and the devices list. Bails visibly
  ("No data available yet — has the agent checked in?") if there's
  genuinely nothing to send.
- **AI responses now render Markdown.** Models love their `**bold**`
  and `## headers` and `` `code` `` — showing them as raw punctuation
  was jarring. New `renderMarkdown()` helper: HTML-escape *first*,
  then transform — no script-injection vector. Supports headers,
  bold/italic, code fences, inline code, bullet/numbered lists, and
  blockquotes. Used in both the ✨ modal and the AI page chat.
- **Routine heartbeat / lock_wait logs silenced by default.** The
  `rp-silence-heartbeat-logs.sh` patch from 2.1.2 is now redundant —
  all three of its behaviours are the default. Per-request heartbeat,
  the `202 busy` retry log, and both lock_wait variants now require
  `RP_LOG_HEARTBEATS=1` / `RP_LOG_LOCK_WAITS=1` in the CGI env to
  re-enable. **OFFLINE/ONLINE state transitions and real-error
  stderr writes stay unconditional.**

### Changed

- **AI Assistant moved to Help section** (between Documentation and
  API Reference). Was under Planning, which never quite fit.
- **Device-card dropdown is now grouped + collapsible.** Was 22
  items in one vertical list, taller than most cards. New layout:
  - **Power** at top (always visible): shutdown / reboot / WoL / upgrade
  - **Inspect** (open by default): System info / ✨ Investigate / Metrics / Update history
  - **Operate** (collapsed): Web terminal / Custom command / Run script… / docker compose / Agent update
  - **Configure** (collapsed): tags, group, notes, intervals, allowlist, icon, monitoring
  - Remove device in its own danger zone at the bottom

  Native `<details>`/`<summary>` for the collapse — no JS needed.
  Both render sites (grid + table) share one `deviceDropdownHtml()`
  helper now instead of duplicating the 1.5 KB markup.

### Added — four new ✨ button surfaces

| Surface | Label | When it shows |
|---|---|---|
| Services → service detail | **✨ Diagnose** | non-active services |
| TLS → table row | **✨ Triage** | warning / critical / error only |
| Patches → table row | **✨ Prioritise** | devices with pending updates |
| (Helper exists for container logs but unused — covered by existing ✨ Explain on command output) | | |

Four new system-prompt keys: `diagnose_service`, `explain_tls`,
`prioritise_patches`, `explain_container_logs`.

### Documentation

- New **docs/ai.md** (~280 lines): provider selection, privacy
  toggles, rate-limit model, complete ✨ button inventory, AI page
  walkthrough, endpoint reference, system-prompt registry, storage
  layer, troubleshooting for every error users have hit.
- **docs/scripts.md**: added AI integration section covering the
  Generate / Explain / Audit buttons.
- **docs/README.md** index updated.

### Tests

- `test_v215.py` (3 tests): new prompt keys exist + env-gating
  pattern correct + state-transition logs stay unconditional.
- `test_v213.py`: system-prompt registry test updated.
- Total: **711 tests, all passing.**

## v2.1.4 - 2026-05-14

Same-day follow-up to 2.1.3 fixing the JSON.parse-on-every-button bug
against slow local Ollama models, plus a stand-alone AI Assistant page.

### Fixed — `JSON.parse: unexpected character at line 1 column 1`

**Symptom**: 2.1.3 Test Connection succeeded, but every actual ✨
button against Ollama smallthinker (a thinking model) failed with
the above SyntaxError.

**Root cause**: ✨ buttons defaulted to `max_tokens=4000` and the
model needed 60–180 seconds to generate. nginx's default
`fastcgi_read_timeout` of 60s closed the connection first, returning
a 504 HTML page. The JS `api()` helper called `r.json()` on the HTML
body and threw.

**Fix**:

- `HTTP_TIMEOUT_S` in `ai_provider.py` 60 → 300 (5 min)
- Per-button `max_tokens` tuned to the typical response length
  (Explain: 1500, Triage: 1000, Generate-script: 4000, etc.)
- New `aiApi()` JS helper — reads raw text first, surfaces a
  structured error with the HTTP status, response snippet, and a
  contextual hint (including the specific nginx config block to set
  if it looks timeout-shaped)
- Live "(Xs elapsed)" ticker in the ✨ modal and the AI page

**Operator action required for nginx**: add a `location /api/ai/`
block with `fastcgi_read_timeout 300s;` (full snippet in
`docs/v2.1.4.md`). The Python timeout helps but nginx is the
gatekeeper.

### Added — AI Assistant page

Sidebar entry under Planning. Standalone chat UI alongside the
inline buttons:

- **Status header** with provider, base URL, reachability, version
  (Ollama), currently-loaded models with VRAM use + expiry
- **Per-conversation model picker** populated from `GET /api/tags`
  (Ollama), `GET /v1/models` (LocalAI / OpenAI / DeepSeek), or the
  hardcoded fallback list (Anthropic). Overrides the global default
  for this conversation only — Settings still controls the default.
- **Multi-turn chat** with localStorage history (last 40 messages),
  Ctrl/⌘+Enter to send, Clear wipes local history only (audit log
  untouched). Conversation is local to the browser by design — never
  synced server-side.

New system prompt key `free_form` (concise, no filler).

### Added — provider introspection endpoints

- `GET /api/ai/models` — list available models with size / family /
  param-count where the provider exposes it
- `GET /api/ai/stats`  — provider, base_url, version, loaded_models,
  reachable

Both require auth, honour the disabled state, never leak the API key.

### Internal

- `ai_provider.py`: `_http_get_json`, `_ollama_root` (strips a
  trailing `/v1` so operators can paste either URL form),
  `list_models`, `provider_stats`, `CLOUD_MODELS` fallback
- `chat()` accepts `model` kwarg for per-request overrides
- `handle_ai_chat()` accepts `model` and `max_tokens` from body
  (both validated, max_tokens capped to configured limit)
- 8 new tests (708 total, all passing)

## v2.1.3 - 2026-05-14

### Fixed

**About page showed "Latest release 2.0.0 ✓ up to date" on a 2.1.2
box.** Two combining causes: `handle_version_check()` read
`server_version` out of `config.json` (often stale because installers
stamped it once and upgrades didn't refresh it), and the displayed
"latest" was GitHub's most recent tagged release — which is
legitimately older than the running version on a dev build or
between cutting and publishing a release. Fixed: read `local` from
the `SERVER_VERSION` module constant, and clamp `latest = max(github,
local)` so the UI never tells you to "upgrade" to a version older
than what you have.

### Added — AI assistant

Optional LLM integration with five providers behind a single
`/api/ai/chat` endpoint. **Disabled by default**; admin opts in via
Settings → AI assistant.

Providers covered by the OpenAI-compatible adapter (`/v1/chat/completions`):
**OpenAI / ChatGPT**, **DeepSeek**, **Ollama**, **LocalAI**. Anthropic
(Claude) gets its own adapter for `/v1/messages`. Pure stdlib —
no pip-installed packages added.

Settings → AI assistant:

- Provider, model, optional base URL override
- API key (masked on read, last-4 visible, `__clear__` to wipe)
- Privacy toggles for what gets sent: hostnames (off), IPs (off),
  journal content (off), command output (on). Bearer tokens, AWS
  keys, and long hex strings are *always* redacted regardless.
- Per-response token cap, per-user-per-day request cap
- Test-connection button

Inline ✨ buttons funnel through one reusable modal:

| Surface | Label |
|---|---|
| Command output panel | **✨ Explain** |
| Journal panel | **✨ Find the problem** |
| Script editor | **✨ Generate from prompt** (inserts into textarea) |
| Script editor | **✨ Explain** |
| Script editor | **✨ Audit for risks** |
| CVE finding row | **✨ Triage** |
| Device dropdown (⋯ menu) | **✨ Investigate** |
| Webhook log row | **✨ Explain** |

Generated scripts go through the same dry-run + dangerous-pattern
detection as human-written ones — no special AI-trusted path.

Endpoints:

- `GET  /api/ai/config` — masked
- `POST /api/ai/config` — admin, validated, audit-logged
- `POST /api/ai/chat`   — auth, system-prompt key OR literal,
  redacted, rate-limited per user/day, audit-logged (token counts
  + elapsed only — never the prompt/response content)
- `POST /api/ai/test`   — admin smoke test

### Internal

- `ai_provider.py` module (~360 lines, stdlib only): provider
  abstraction, redaction, system prompt registry
- 40 new tests in `tests/test_v213.py`: redaction (always-on + toggle),
  validators, About-page logic (running-ahead, GitHub-ahead, stale-key),
  config CRUD, chat endpoint, rate limiter (per-user isolation,
  zero-means-unlimited). Total suite **700 tests, all passing**.

### Misc

- Favicon link updated to `/favicon.png` (user-added to html root)
  with a shortcut-icon fallback.
- All 9 version-string sites bumped 2.1.2 → 2.1.3.

## v2.1.2 - 2026-05-14

### Fixed

**Lost-update race in heartbeat (THE actual offline bug).** v2.1.0's
`save()` redesign moved the tmp-file write outside the lock so the
critical section was just the rename. Correct for single-shot saves
but it broke an unspoken contract with callers that did
read-modify-write: load → mutate → save was no longer atomic. Two
concurrent heartbeats from different devices interleaved their
load/save windows and the second one's rename clobbered the first
one's `last_seen` update. Devices drifted past TTL and got marked
offline despite heartbeating fine — looked identical to the
original 2.0 flock fluctuation, but the cause was completely
different.

Fix: new `_locked_update(path)` context manager that holds the flock
across load → mutate → save. `handle_heartbeat()` is rewritten around
this primitive so concurrent heartbeats now serialise correctly. The
`compose_projects` update (which previously did a separate save) is
merged into the same atomic transaction.

`save()` itself still uses the v2.1.0 fast-path (tmp+fsync outside
lock) — that optimisation is correct for *single-shot saves where
the caller doesn't read first*. The new primitive is for callers
that do RMW, who now opt in explicitly.

### Internal

13 new tests in `tests/test_v212.py` including a threaded
reproducer for the race (20 concurrent updaters, asserts every
update is preserved) and a deliberate demonstration of the bug
using the old pattern. Total suite: **660 tests, all passing.**

Other admin-action RMW sites (note/group/tag/poll-interval edits)
still use the unsafe pattern but are much lower frequency than
heartbeats. Migrating them to `_locked_update` is queued for a
follow-up release.

## v2.1.1 - 2026-05-13

### Fixed

**Offline regression from 2.1.0.** The 2.1.0 heartbeat handler used
the non-blocking save path for *every* save, including `last_seen`.
Under flock contention that save would 202 silently *before*
`last_seen` was persisted — the agent treated 202 as success, the
server still thought the device was last seen however-long-ago, and
the device drifted past the online TTL → marked offline even though
heartbeats were arriving fine. Fixed: the `DEVICES_FILE` save is back
to blocking (which is now microseconds-fast thanks to the 2.1.0
fsync-outside-lock work). Only the *optional* saves below it
(cmd_output, containers, config, etc.) keep non-blocking semantics.

**Diagnostics were silent.** Two 2.0-era code smells made the offline
bug above invisible to operators: `check_offline_webhooks()` only logged
inside `fire_webhook()`, so an operator without webhooks got a silent
state flip; and `main()` wrapped every per-request maintenance sweep in
`try: ... except Exception: pass`, swallowing every error including
ones an operator most needs to see. Now: state transitions always log
`[remotepower] OFFLINE dev=… last_seen=… delta=…s ttl=…s` regardless
of webhook config; heartbeat arrival logs to stderr (visible in nginx
error log); the bare except-pass blocks are replaced with a `_safe()`
helper that prints the full traceback before continuing.

**`log_alert` webhook now includes the matched line.** Pre-2.1.1 the
message read `host/unit: pattern "X" matched N times` — no actual log
content. The payload already had `sample` (first 3 matching lines);
`_webhook_message` just wasn't using it. Now the message shows the
first matched line (truncated to 200 chars for embed compatibility)
and an `(+ N more matching lines)` footer if there were more.

### Changed

**Default offline TTL bumped from 3 → 5 minutes.** `DEFAULT_ONLINE_TTL`
is now 300s (= 5 missed polls at the 60s default interval).
`MIN_ONLINE_TTL` is now 150s (was 90). Field reports of "device went
offline" turning out to be brief network blips the agent recovered
from. Operators who want the old tighter behaviour can configure
`online_ttl: 180` via Settings → Webhooks.

### Added

**Per-container actions on the Containers page.** Start / Stop /
Restart / Logs buttons on every reported container. New agent
dispatch `container:<runtime>:<action>:<id>` with argv-only invocation
(no `shell=True`), tight ID regex (`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}`),
runtime allowlist (docker | podman; kubectl excluded), and action
allowlist (start, stop, restart, pause, unpause, logs). New endpoint
`POST /api/devices/<id>/containers/action` validates the requested
`container_id` against the agent's last-reported listing — same
security boundary as compose. Kubernetes pods don't get action buttons
since the agent generally doesn't have the kubectl context to act on
them through this path.

**Demo data reflects v2.1 features.** `seed-demo-data.py` now also
seeds `scripts.json` (5 example scripts including one deliberately
flagged dangerous to demo the `⚠ DANGER` badge), `batch_jobs.json`
(one recently-completed batch run for the status modal), and
`log_watch.json` (two log-watch rules and one fired alert showing
the new matched-line format). 6 demo devices report tag-driven
`compose_projects` so the v2.1.0 compose dropdown is visible in the
demo.

### Internal

20 new tests in `tests/test_v211.py` (647 total, all passing).
Bumped all 9 version-string sites from 2.1.0 → 2.1.1.

## v2.1.0 - 2026-05-13

### Fixed

**Flock offline fluctuation.** Heartbeats no longer hold the per-file
flock across `fsync()`. `save()` now writes the per-process unique tmp
file *outside* the lock and holds it only for the rolling-backup copy
and atomic rename — both O(1) metadata ops. Adds an explicit
`non_blocking=True` mode that retries `LOCK_NB` for ~100 ms and raises
`LockBusy` on persistent contention. The heartbeat handler catches
`LockBusy` and returns HTTP 202 (Accepted), which the agent treats as
"delivered, retry next cycle". Result: a busy save no longer stalls
the request past the agent's HTTP timeout, and devices stop flipping
between online and offline. Lock waits >50 ms log to nginx error log
as `[remotepower] lock_wait path=… waited_ms=… mode=…`. See
the v2.1.0 release notes for the full rationale.

**Auto-refresh closes browser window / crashes tab.** Two independent
bugs combined: `escHtml()` didn't escape `'`, so device names like
`O'Brien` broke out of inline `onclick="fn('${escHtml(d.name)}')"`
strings on every 60 s refresh; and `setInterval` kept firing under
open modals and background tabs, re-rendering the device grid out
from under captured event handlers. Fix: new `escAttr()` that
hex-escapes (`\x27` etc.) for JS-in-attribute contexts (73 inline
handler sites converted); refresh pauses when a modal is open or the
tab is hidden; `toggleDropdown` no longer leaks click handlers to
detached DOM nodes.

### Added

**Script library** (`docs/scripts.md`). New **Scripts** page in the
sidebar for multi-line bash scripts, separate from the existing
one-liner Command Library. CRUD + on-demand dry-run using `bash -n`
plus an 11-pattern dangerous-command regex sweep
(rm -rf /, fork bombs, dd to block devices, mkfs against /dev/,
curl|bash, etc.). Body capped at 64 KB; 500 scripts per server.
Routes: `GET/POST/PUT/DELETE /api/scripts[/<id>]`,
`POST /api/scripts/<id>/dry-run`.

**Multi-select script execution.** New "Run script" button on the
batch action bar. Pick a saved script, fan out across the selection.
`POST /api/exec/batch` queues `exec:<body>` on each target;
`GET /api/exec/batch/<id>` returns per-device status with output as
it arrives. Job records have a 1-hour TTL, pruned on access.
Refuses dangerous-pattern scripts without `confirm_dangerous: true`;
refuses syntax-erroring scripts outright.

**docker compose dropdown** (`docs/compose.md`). The Linux agent now
scans `/opt`, `/home`, `/docker`, `/srv` (`find -L -maxdepth 4`,
5 s timeout, 50-project cap, prune list for .git / node_modules /
.cache / venv) for `docker-compose.yml` / `compose.yml` and reports
the listing alongside containers in the heartbeat. Device cards get
a **docker compose (N)** entry in the ⋯ menu with Up / Down /
Restart / Pull / Logs (last 50) buttons. Action endpoint
`POST /api/devices/<id>/compose/action` validates `dir` is one of
the paths the agent itself reported — even an admin token can't aim
`compose:up` at arbitrary paths. Agent enforces the action allowlist
and path validity independently. Output cap 64 KB, timeout 180 s.

### Internal

**`make dist`** target. Builds `dist/remotepower-2.1.0.tar.gz` +
sha256 file, with an explicit exclude list (not gitignore-driven, so
new directories don't accidentally ship). Runs the full test suite
against the staged tree before producing the tarball; a broken
release fails fast.

**`make version`** target prints the current version from
`SERVER_VERSION` in `api.py`. Single source of truth for the tarball
filename + the README badge.

**Docs split.** Top-level `README.md` cut from 807 → 115 lines.
Long-form content lives in topical files under `docs/`: install,
features, architecture, api, security, https, troubleshooting,
upgrading, agent-commands, windows-client, plus the new
scripts.md / compose.md / v2.1.0.md.

**Tests.** 60 new tests in `tests/test_v210.py` covering: real
flock contention triggering LockBusy, every dangerous-pattern regex
with positive + negative cases, script CRUD + sanitisation + size
caps, batch dispatch + TTL pruning, compose ingest sanitisation,
the compose action security boundary, and the no-XSS-on-apostrophes
invariant. Total suite is now **627 tests**, all passing.

## v2.0.0 - 2026-05-08

A visual + organizational refresh. New branding throughout, sidebar restructured for browsability, in-app documentation, code split into separate CSS/JS files for maintainability. No breaking changes for agents — this is a 2.0 because of UI visibility, not API shape.

### Branding

- **Real logo and favicon.** PNG assets now live in `server/html/static/img/`:
  - `favicon.png` → browser tab icon (linked via `<link rel="icon">`)
  - `logo-square.png` → 36×36 in the header bar
  - `logo-primary.png` → big logo with wordmark + "POWER. MANAGE. ANYWHERE." tagline on the login screen
- Header logo is now a clickable link that returns to the Devices page (the home view). Hover state for affordance.
- The placeholder sun-shape SVG that has been there since v1.0 is gone.

### Sidebar reorganized

The flat 18-item list is now grouped:

- **Main** (always visible): Devices, CMDB, Containers, Network, Monitor
- **Security** (collapsible): TLS / DNS, Patches, CVEs, Services, Logs
- **Planning** (collapsible): Schedule, Calendar, Tasks, Maintenance, History
- **Admin** (collapsible, defaults to collapsed): Settings, Users, API Keys, Library, Audit, Links
- **Help**: Documentation (new!), API Reference (was "API Docs"), About

Group state persists per-browser in `localStorage` (`sidebar.<group>.collapsed`). Active page always expands its containing group, so a fresh load shows you where you are even if the group was collapsed.

The four admin items that were in the flat list (Users, API Keys, Audit, Links) plus Settings, Library are all now under the Admin toggle. Day-to-day use only needs Main + Help expanded; admins expand Admin when they need it.

### Documentation page

New "Documentation" entry under Help in the sidebar. Curated set of in-app help cards covering the most common questions:

- Enrolling devices (PIN + API token flows)
- Metric alerts (defaults, per-device, per-mount, hysteresis, trends)
- Web terminal (auth flow, recording, deploy)
- Commands (per-device dropdown, batch mode, library)
- Webhooks (auto-format detection, event list, test events)
- External monitors (probes, schedule)
- Two-factor authentication (enable/disable)
- Tables: filter / sort / density
- Backup & restore
- Troubleshooting (the actual symptoms users hit)
- API access (auth methods, common patterns with curl examples)

Each card is a `<details>` element — expand on click, no JS required for the toggle. Top of page has a substring search that auto-expands matching cards. Cards have a `data-keywords` attribute so search hits things like "ssh" → web terminal even though the summary doesn't say "ssh".

The full reference Manual.html is still around and linked from the troubleshooting section.

### Metric trends on the Monitor page

The Devices page has had the metrics chart modal since v1.7. v1.12.0 surfaced live metric values on the Monitor page; v2.0 adds a "Trend" button next to "Thresholds" on each device row. Same chart as the per-device view (last 60 data points, sparkline-style for CPU / memory / disk). One click takes you from "your fleet's current state" to "this device's history" without leaving the Monitor page.

### Code split (HTML / CSS / JS)

`index.html` was 8088 lines with a 1320-line `<style>` block and 4900-line inline `<script>`. Now:

- `server/html/index.html` — 1835 lines (just the markup + the two external refs)
- `server/html/static/css/styles.css` — 1320 lines (everything from the old `<style>`)
- `server/html/static/js/app.js` — 4930 lines (everything from the old `<script>`)

The split is strictly mechanical — no code was rewritten or restructured. Same selectors, same functions, same global variables, same load order. The script is still injected at the end of body for the same DOMContentLoaded timing it had inline. This makes the file tree navigable for the first time:

- Want to find a CSS rule? `grep '\.foo' static/css/styles.css`
- Want to find a function? `grep 'function foo' static/js/app.js`
- Want to see the page structure? `index.html` is a fifth its old size and now actually readable.

I deliberately did NOT do a deeper refactor (ES modules, build step, component framework). That's a multi-week project and you said "please don't break the code." The mechanical split gets us 80% of the maintainability benefit at ~0% breakage risk. If you want a real architectural rewrite, plan it as a v2.1 in its own session and we'll do it properly.

`deploy-server.sh` updated to rsync the `server/html/static/` tree to `/var/www/remotepower/static/`. The deploy is otherwise identical.

### What's NOT in this release (intentional)

- **No agent changes.** Agents on v1.11.10+ work unchanged. The 2.0 in the version is about UI visibility (visible reorganization, branding) not protocol breakage.
- **No new server endpoints.** Documentation page is pure frontend; sidebar reorganization is pure frontend; metric Trend button reuses the existing `/api/devices/{id}/metrics` endpoint.
- **No SQLite migration.** Considered for v1.12.1, decided flock + atomic write was sufficient for this scale. Same call here. SQLite is the right answer at 1000+ devices, not at 9.

### v2.0 polish (later same day)

After the initial 2.0 build went out, several rounds of polish before declaring done — no version bump.

**Real branding.** Three updated PNGs deployed to `server/html/static/img/`. Login screen no longer adds a dark background frame around the primary logo (the logo asset has its own gradient). Login card widened from 400→480px so the 280px-wide logo has comfortable horizontal margin.

**Multi-doc CMDB.** Assets used to support exactly one Markdown blob in `documentation`. Now they support an arbitrary list of titled docs (`docs: [{id, title, body, created_by, created_at, updated_by, updated_at}]`, capped at 50 per asset). Schema migration is automatic on first read: legacy `documentation` strings synthesise a single doc with `id="legacy"` which gets promoted to a real id on first edit, and the back-compat field is cleared. Three new endpoints: `POST /api/cmdb/{id}/docs`, `PUT /api/cmdb/{id}/docs/{doc_id}`, `DELETE /api/cmdb/{id}/docs/{doc_id}` — all admin-auth, all audit-logged. UI rewritten: docs render as collapsible cards with per-card edit/delete, separate edit modal with Markdown preview tab, "+ Add document" button. The existing single-textarea is gone. 21 tests in `test_v200_docs.py`.

**Demo / read-only mode.** New `RP_READ_ONLY=1` environment variable. When set, `_enforce_read_only()` runs at the top of `main()` before route dispatch and blocks every non-GET request with a 403 + `{"demo": true, "error": "Demo mode...", "detail": "..."}` body, except a small whitelist (login, logout, totp/verify, public-info, openapi.json) needed for visitors to log in and browse. Frontend reads the flag from `/api/public-info` on load, shows a banner if set, surfaces friendly toast on demo-mode 403s instead of generic failure messages. Designed for a public sandbox like `demoremote.tvipper.com`. 17 tests in `test_v200_demo.py`.

**Demo seed script.** `packaging/seed-demo-data.py` populates a target data dir (default `/var/lib/remotepower/`, override with `--data-dir`) with 16 fake homelab devices: hypervisor + NAS + firewall + DNS + reverse proxy + media + git + monitoring + a few agentless network devices. Realistic hostnames using the unallocated `.lab` TLD so they can't collide with anything real. Seeds devices, CMDB metadata, packages, services, containers, CVE findings, monitor history, audit log, etc. Idempotent (deterministic — same input, same output). Re-runnable on a cron if you want `last_seen` to keep looking fresh.

**Demo install script.** `packaging/install-demo.sh <hostname>` sets up a SEPARATE demo vhost alongside your production install — different data dir (`/var/lib/remotepower-demo/` by default), same shared CGI code under `/var/www/remotepower/`. Auto-detects the CGI user, creates the demo data dir owned by it, runs the seed script, generates an nginx server block at `/etc/nginx/sites-available/remotepower-demo` with the per-vhost env vars (`RP_DATA_DIR=/var/lib/remotepower-demo` and `RP_READ_ONLY=1`), enables it, validates with `nginx -t`, reloads. The trick is that fcgiwrap forwards `fastcgi_param` env vars to the CGI process, so two vhosts can share one fcgiwrap pool but operate on different data dirs. TLS is left to the user (certbot reminder printed at the end). Idempotent re-runs re-seed and re-render the nginx config. Production install at `remote.<domain>` is never touched.

**Documentation page expansion.** The original 11 cards covered common workflows. Added 21 more (one per sidebar entry): Devices, CMDB, Containers, Network, Monitor, TLS/DNS, Patches, CVEs, Services, Logs, Schedule, Calendar, Tasks, Maintenance, History, Settings, Users, API Keys, Library, Audit, Links. Each `<details>` card has `data-keywords` so the substring search finds them by alternate terms (e.g. "ssh" → web terminal card, "topology" → Network card). 32 doc cards total now.

**README rewrite.** Front-loaded the Quick Start (server + client + Docker) right after the intro. New "What you can do with it" section grouping headline features in a 2-column visual table. New "Why RemotePower" positioning section (small / lightweight / properly self-hosted / not toy features). Comprehensive feature table reorganised into 6 categories (Fleet visibility, Commands & automation, Alerts & monitoring, CMDB & docs, Auth & access, Operational quality, UX) with version annotations. Architecture diagram updated to reflect the v1.12.1+ persistence (`.bak` rolling backups), the webterm sibling daemon, and the actual current set of state files (~30 JSONs, grouped by purpose). 788 lines total, no duplicate Quick Start sections.

**Tests after polish.** 567 passing (529 from v1.12.1 + 21 multi-doc in `test_v200_docs.py` + 17 demo-mode in `test_v200_demo.py`). No regressions. JS validated with `node --check`. HTML div + `<details>` counts balanced.

**Deploy.**

```bash
sudo bash deploy-server.sh
```

Hard-refresh the browser. For the demo-sandbox use case, deploy a SEPARATE vhost alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.tvipper.com
sudo certbot --nginx -d demoremote.tvipper.com
```

Production at `remote.tvipper.com` keeps working with your real data; the demo at `demoremote.tvipper.com` runs the same CGI code against a separate `/var/lib/remotepower-demo/` data dir with `RP_READ_ONLY=1`. Visitors log in as `demo` / `demo` and can browse everything but every mutation returns a friendly 403 toast.

---

## v1.12.1 - 2026-05-08

A targeted hardening release after a real-world incident: a user's `devices.json` got corrupted by a concurrent-write race between two CGI processes, leaving the file with a complete first JSON document followed by trailing garbage. Effects: dashboard showed no devices, all agents got 403 "Credentials rejected" because the heartbeat handler couldn't find them in the empty-on-load file.

This release makes that class of corruption impossible going forward.

### Storage hardening (the main thing)

`save()` now does:

1. **Round-trip integrity check before any disk write.** Serialise with `allow_nan=False`, then parse the result back. If the data won't round-trip, raise `ValueError` immediately instead of writing it. Catches NaN/Infinity (Python's json silently allows them, but most other tools reject them) and any logic bug producing a malformed structure.

2. **Exclusive flock on a sidecar lock file.** A `<file>.lock` zero-byte sidecar lives alongside each data file, used as a coordination point. `fcntl.flock(LOCK_EX)` serialises writers — two CGI processes both calling `save(DEVICES_FILE, ...)` will queue on the lock instead of racing.

3. **Per-process unique tmp filename.** `<file>.tmp.<pid>.<nonce>` instead of just `<file>.tmp`. Even with the lock, this is belt-and-braces — if two writers ever did manage to be in `save()` simultaneously (lock file deleted, filesystem weirdness), they wouldn't share a tmp file and couldn't trample each other's bytes.

4. **fsync before rename.** Forces the bytes to durable storage before the atomic rename, so a power loss right after the rename doesn't return to a zero-length file. tmpfs and a few other filesystems don't support fsync; we tolerate that gracefully.

5. **Rolling backup.** The current file is copied to `<file>.bak` before every replace. Single rolling backup, not history — if the live file ever ends up corrupted, we have one known-good prior state to fall back to.

`load()` automatically falls back to `.bak` if the canonical file is corrupt:

- Tries `<file>` first
- On `JSONDecodeError`, tries `<file>.bak`
- If `.bak` parses, returns its content and logs a warning to stderr (visible in nginx error log via fcgiwrap)
- If both are corrupt, returns `{}` — same as a missing file — so the rest of the code keeps working in degraded mode rather than crashing the whole CGI

The fallback is the difference between v1.12.0's "one bad write makes the dashboard unusable until manual recovery" and v1.12.1's "one bad write is silently absorbed using the previous heartbeat's state, with a warning logged."

### Why not SQLite?

I considered migrating the hot-path files (`devices.json`, `services.json`, `containers.json`, `metrics.json`, `history.json`) to SQLite. Real analysis:

- ✅ ACID transactions, the corruption you saw is fundamentally impossible
- ❌ Major refactor — 2-3 sessions of work
- ❌ Backup/restore changes (`tar czf` stops being a complete backup)
- ❌ Debugging tools change (no more `jq` over your data)
- ❌ Schema migrations become a thing forever

At the user's scale (~9 devices, 60-second heartbeats = ~9 writes/min), `flock` handles serialisation trivially. SQLite's wins (queries, indexes, joins, large-scale concurrency) don't apply to a key/value lookup workload where the whole dataset fits in memory anyway. The hardening above gives the same correctness guarantee for this scale without losing the ability to `jq` your way through everything during incidents.

If RemotePower ever grows past 1000 devices or the data shape changes meaningfully, SQLite is the right migration. For now, the boring-architecture philosophy wins.

### Multi-select in minimal devices view

The cards mode had checkbox-driven batch select since v1.10; minimal mode shipped without it in v1.11.7. Now minimal has parity:

- Leading checkbox column on every row
- Header checkbox with select-all-visible (respects the active filter — if you've filtered to "production" tag, select-all toggles only those rows)
- Selected rows get a subtle blue background highlight
- Reuses the same `selectedDevices` Set as cards mode, so switching density mid-selection preserves your selection

### Recovery tool for files corrupted before this upgrade

`packaging/recover-corrupted-json.py` is a one-shot fix for any JSON file already corrupted by the v1.12.0 bug. It:

- Scans `/var/lib/remotepower/*.json` (or specific files passed as args)
- Uses `json.JSONDecoder.raw_decode()` to find the first valid JSON document and treat anything trailing as garbage
- Reports what it would do in dry-run mode (the default)
- With `--apply`, makes a `.broken-<ts>` backup and writes the recovered content over the live file

```bash
sudo -u www-data python3 packaging/recover-corrupted-json.py            # dry-run scan
sudo -u www-data python3 packaging/recover-corrupted-json.py --apply    # fix
```

### Tests

**529 passing** (513 from v1.12.0 + 16 new in `test_v1121.py`):

Atomic save (8 tests): basic round-trip, lock sidecar created, .bak created on second save (not first), tmp files cleaned up on success, unique tmp per process, NaN/Inf rejected, no file created on invalid data, mode 600 preserved.

Load with fallback (4 tests): missing returns empty, corrupt falls back to .bak, no .bak returns empty cleanly, both corrupt returns empty without crashing, load() never modifies disk.

End-to-end recovery (1 test): plant corruption, verify load() falls back, verify next save() re-establishes clean state with both files valid.

Concurrent save (1 test): 8-process `multiprocessing.Pool` (spawn context) all writing the same file with read-modify-write loop. Without v1.12.1 hardening, this reliably reproduces a `JSONDecodeError` by the time it finishes; with the hardening, every load returns valid data and every key has the right value.

`test_save_unique_tmp_per_process` (2 tests) — verifies the tmp filename is parameterised by `(pid, nonce)`. Reaches into the implementation intentionally to validate the hardening property described in the module-level comment.

### Compatibility

Drop-in upgrade from v1.12.0. The on-disk format is unchanged — `.bak` and `.lock` sidecars get created on the next save of each file. Existing JSON files keep working as-is.

If you hit the v1.12.0 corruption bug, run `recover-corrupted-json.py --apply` once after upgrading to clean up any leftover damaged files.

### Performance impact

Each `save()` now does:
- One additional file open + flock (~50µs)
- One `shutil.copy2()` for the rolling backup (~1ms for files up to 100KB)
- One `fsync()` (depends on filesystem; typically 1-10ms on a real disk, free on tmpfs)

Heartbeat handler does ~2-3 saves; total added latency per heartbeat: ~5-30ms. Negligible at scale up to thousands of devices/minute.

---

## v1.12.0 - 2026-05-07

A polish release wrapping up the loose ends from v1.11.11 — proper deploy automation, the per-device metric thresholds UI that v1.11.10 only exposed via API, surfacing live metrics on the Monitor page, and a comprehensive manual rewrite. No new server endpoints.

### New: install-webterm.sh

`packaging/install-webterm.sh` handles the v1.11.11 deploy that didn't go smoothly. The original instructions assumed `rp-www`/`rp-webterm` users that don't exist on Debian/Ubuntu (which uses `www-data`); the script now auto-detects the actual CGI user via process heuristic plus fallback through `www-data` → `nginx` → `http` → `rp-www` → `apache`.

What it handles:
- Detects the CGI user by looking for processes (`pgrep -u USER -f '(fcgi|nginx|cgi|php-fpm)'`) and falls back to existence-only if no match.
- Detects the package manager (apt/dnf/pacman/apk/zypper) and installs `python3-websockets` + `python3-asyncssh`.
- Creates the `rp-webterm` daemon user (idempotent — re-runs are safe).
- Adds the daemon user to the CGI user's group so it can read the ticket file.
- Sets up directories with correct ownership: `/var/lib/remotepower/webterm-sessions/` (daemon-owned, mode 750), `/var/lib/remotepower/webterm_tickets.json` (CGI-owned, mode 640).
- Generates the daemon ↔ CGI shared secret to `/etc/remotepower/webterm-secret` and writes it to `config.json` (using `sudo -u $CGI_USER` so file ownership stays correct).
- Renders the systemd unit with the right `User=` / `Group=` / `ReadWritePaths=` substituted in.
- Prints the nginx snippet you need to add (with the right port substituted in) plus the `$connection_upgrade` map docs.
- `--dry-run` mode shows everything it would do without touching the system.

Run as `sudo bash packaging/install-webterm.sh` (or with `--cgi-user www-data` to override detection). At the end it tells you what to paste into nginx and what to verify.

### New: per-device metric thresholds UI

The endpoint shipped in v1.11.10 (`GET|PATCH|DELETE /api/devices/{id}/metric-thresholds`) but had no UI — you had to use `curl`. v1.12.0 adds a full editor accessible from the device dropdown menu (both cards and minimal modes). The modal:

- Shows the device's current sysinfo readings at the top so you know what thresholds make sense (memory %, swap %, load ratio + cpu count, every mount with current %).
- Has warn/crit fields for memory, swap, default-disk, and CPU load ratio. Empty means "use default"; placeholder shows the inherited value, so customised vs. inherited is visually distinct.
- Has a per-mount disk overrides section with add/remove rows. Common case: `/var` at 70/85 (logs grow fast), `/backup` at 95/98 (designed to fill).
- Reset-to-defaults button DELETEs all overrides.
- Validation: paths must start with `/`, both warn+crit required for each mount, warn must be < crit (server-side enforced; client also pre-checks).

Saving clears the device's `metric_state` so the next heartbeat re-evaluates under the new thresholds (this was already in v1.11.10 — just calling it out because it matters when you're tuning live).

### New: live metrics on the Monitor page

The Monitor page used to show only external probes (ping/TCP/HTTP). Now it has a "Device metrics" section underneath that shows every enrolled device's current sysinfo state, color-coded by alert level:

- **Device** column with group badge
- **Alert** column showing aggregate level: critical ⨯ red, warning ⨯ amber, OK ⨯ green, offline (muted gray for non-reporting devices)
- **Memory / Swap / CPU load** columns, each individually colored by that metric's specific alert state
- **Disks** column listing every mount with its percent, each colored by its own state. Long paths are truncated; tooltip shows the full path plus used/total GB.
- **Thresholds** button on each row jumps straight to the per-device threshold editor for that device.

Sortable, filterable (by name, group, tags, or mount path). When sorting by status ascending, critical-state devices come first. Summary line above the table: "N critical • M warning" or "all clear".

The data source is the existing `/api/devices` endpoint — no new server work required. The `metric_state` field already populated by v1.11.10's threshold processor tells us which alerts are live.

### New: comprehensive manual

`Manual.html` rewritten from scratch — was 328 lines of fragmented legacy notes; now a coherent ~470-line document covering everything from the architecture overview through web terminal deployment to troubleshooting. 11 sections with a clickable TOC. Replaces both `Manual.html` and `docs/Manual.html` (kept identical to avoid drift).

New coverage:
- Section 2 (Install): proper subsections for server, web terminal daemon, agent, with the `install-webterm.sh` recommended path
- Section 3 (Enrollment): both PIN and API token flows side-by-side, with the three token-resolution methods explained
- Section 7 (Metrics): all four flows covered — the modal UI, the Monitor-page surfacing, the API, and direct `devices.json` inspection
- Section 8 (Web terminal): full architecture diagram, auth flow walkthrough, security model summary, session-recording details with replay command, retention cron suggestion
- Section 11 (Troubleshooting): the actual symptoms users will hit (404, 502, 1006 close codes, missing per-mount data, CSP blocking xterm.js)

### Tests

**513 passing — unchanged.** No new server endpoints, so no new test coverage required. The install script is bash so wasn't unit-tested; manually verified with `--dry-run --cgi-user www-data` that it produces the right output and doesn't crash.

### Compatibility

Drop-in upgrade from v1.11.11. No schema changes. Existing per-device metric overrides set via API in v1.11.10 work without modification — the new UI just makes them visible and editable. The webterm daemon binary is unchanged from v1.11.11; only the install script around it is new.

### Known limitations carried forward

- xterm.js still loads from cdn.jsdelivr.net (CSP issue if blocked; manual instructions for self-hosting in Manual.html)
- Web terminal session recordings still aren't auto-pruned (cron suggestion in manual)
- Web terminal SSH host-key checking still off by design

---

## v1.11.11 - 2026-05-07

### New feature: web terminal

Browser-based SSH terminal accessible from the dashboard. Click "Web terminal" in the per-device dropdown menu, type SSH user/password and your RemotePower admin password, and you get a live xterm.js terminal connected to the device.

The architecture is a small companion daemon (`remotepower-webterm`) that handles WebSocket and SSH proxying, because RemotePower's CGI-over-fcgiwrap model can't hold persistent connections. The CGI handles auth and audit logging; the daemon handles the bytes.

#### Files added

- `server/webterm/remotepower-webterm.py` (~470 lines) — the daemon. asyncio + `websockets` + `asyncssh`. Listens on 127.0.0.1:8765 by default; nginx proxies `/api/webterm/connect` to it.
- `packaging/remotepower-webterm.service` — systemd unit with hardening (NoNewPrivileges, ProtectSystem=strict, RestrictNamespaces, etc.). Runs as a dedicated `rp-webterm` user.
- `packaging/nginx-webterm.conf` — drop-in nginx snippet for the WebSocket proxy. Requires the `$connection_upgrade` map (standard pattern, documented in the snippet).
- `tests/test_v11111.py` — 21 tests for the CGI-side endpoints.

#### Files modified

- `server/cgi-bin/api.py` — added `handle_webterm_auth`, `handle_webterm_session_audit`, ticket store helpers, two new constants. Routes wired up.
- `server/html/index.html` — "Web terminal" item in the device dropdown menu (both cards mode and minimal mode), modal for SSH credentials + admin password, full-screen terminal view, xterm.js loaded on first use from cdn.jsdelivr.net.

#### Auth flow

1. User clicks "Web terminal" on a device. Modal asks for SSH host (pre-filled from device IP), SSH user, SSH password, and RemotePower admin password.
2. Frontend POSTs to `/api/webterm/auth`. CGI validates the admin password against the user's stored hash. Mismatch → 403 + `webterm_auth_failed` audit entry.
3. CGI generates a 32-byte URL-safe ticket, stores it in `webterm_tickets.json` with TTL = 60 seconds, returns the ticket to the frontend along with the daemon URL.
4. Frontend opens a WebSocket to `wss://<host>/api/webterm/connect?ticket=...`. nginx proxies to the daemon.
5. Daemon reads ticket from URL, validates against `webterm_tickets.json`, deletes it (single-use). Then waits for the first WS message: a JSON blob with `{host, user, port, password, cols, rows}`.
6. Daemon SSH-connects via `asyncssh.connect()`. Opens a PTY shell. Pumps bytes between WS and SSH.
7. Session ends → daemon POSTs metadata back to `/api/webterm/audit`, authenticated via shared secret in `/etc/remotepower/webterm-secret` (matches `config.json[webterm_daemon_secret]`).

#### Session recording

Every session is recorded to `/var/lib/remotepower/webterm-sessions/<session_id>.cast` in [asciinema v2](https://docs.asciinema.org/manual/asciicast/v2/) format. Default is **output-only** — keystrokes are not recorded because they could include `sudo SECRET_VALUE` and similar. Set `RECORD_INPUT=1` in the daemon's environment to also record keystrokes if you have compliance reasons; only do this if you've thought through who can read the session-recording directory.

The format is plain-text JSON Lines with a header and `[delta_seconds, "o", "output"]` records. Replayable in any asciinema player (web, CLI, browser via `asciinema-player.js`); also greppable as raw text. Each recording is capped at 10 MiB — at the cap we stop recording but keep proxying bytes.

#### Security model summary

- Tickets are single-use, 60-second TTL, ~256 bits of entropy
- The daemon binds to 127.0.0.1 only (loopback). nginx terminates TLS for the browser hop
- SSH credentials never persist; live in memory inside the daemon for one session
- SSH host-key verification is OFF by design (the user explicitly chose this host through the dashboard, and adding `known_hosts` management would mean a first-connect prompt for every device — more theatre than security here). If you want strict host-key checking, this is the right discussion to have for v1.12
- Audit POSTs from daemon to CGI authenticated via shared secret, not session token (the daemon is a system service, not a user)
- systemd hardening: dedicated user, no privilege escalation, read-only root filesystem with explicit ReadWritePaths, restricted namespaces

#### Known limitations / open work

- **Browser dependencies are loaded from cdn.jsdelivr.net.** xterm.js is ~250 KB; loading from your own server is more secure (no CDN tampering risk) but more deployment work. v1.11.11 uses the CDN for simplicity. To self-host: download `@xterm/xterm@5.5.0/css/xterm.min.css`, `@xterm/xterm@5.5.0/lib/xterm.min.js`, and `@xterm/addon-fit@0.10.0/lib/addon-fit.min.js` into `server/html/static/` and edit `_loadXtermOnce()` to point there. SRI hashes can then be added.
- **No SSH key auth.** Per your spec, only password auth in v1.11.11. Adding key auth means storing the keys somewhere (CMDB Vault would be the natural place); you didn't ask for it so I didn't build it.
- **Session recordings aren't pruned automatically.** They accumulate in the recordings directory. A cleanup cron / systemd timer is a v1.11.12 task. For now, manage retention with `find /var/lib/remotepower/webterm-sessions -mtime +30 -delete` or similar.
- **The daemon is a single process.** Concurrent sessions all run in the same asyncio event loop, which is fine up to dozens of sessions; if you ever need hundreds, switch to a process-per-session model.
- **Session listing UI not in this release.** You can see sessions in the audit log (action `webterm_session`) and in the on-disk recording files. A "browse sessions" page in the dashboard would be a nice v1.11.12 addition.

#### Deploy steps (one-time)

```bash
# 1. Create the daemon's user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/remotepower rp-webterm
sudo usermod -a -G rp-www rp-webterm   # so it can read the ticket file

# 2. Install Python deps
sudo apt install python3-websockets python3-asyncssh   # or pip install

# 3. Install the daemon binary
sudo install -m 755 server/webterm/remotepower-webterm.py /usr/local/bin/remotepower-webterm

# 4. Generate the shared secret (used for daemon → CGI audit POSTs)
SECRET=$(openssl rand -hex 32)
sudo install -m 640 -o rp-webterm -g rp-webterm /dev/stdin /etc/remotepower/webterm-secret <<< "$SECRET"
# Also store it where the CGI can find it:
sudo -u rp-www python3 -c "
import json, sys
from pathlib import Path
cfg = json.load(open('/var/lib/remotepower/config.json'))
cfg['webterm_daemon_secret'] = '$SECRET'
json.dump(cfg, open('/var/lib/remotepower/config.json', 'w'))
"

# 5. Set up the recordings directory
sudo install -d -m 750 -o rp-webterm -g rp-webterm /var/lib/remotepower/webterm-sessions

# 6. Make the ticket file readable by the daemon
sudo touch /var/lib/remotepower/webterm_tickets.json
sudo chown rp-www:rp-www /var/lib/remotepower/webterm_tickets.json
sudo chmod 640 /var/lib/remotepower/webterm_tickets.json

# 7. Install + start the systemd unit
sudo install -m 644 packaging/remotepower-webterm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotepower-webterm

# 8. Add the nginx snippet (paste contents of packaging/nginx-webterm.conf into
#    your existing server { ... } block, ABOVE any catch-all `location /` rule)
#    Then test and reload:
sudo nginx -t && sudo systemctl reload nginx

# 9. Verify
curl -s http://127.0.0.1:8765 -i  # expect "Connection: Upgrade" expected, won't actually upgrade with curl
sudo journalctl -u remotepower-webterm -f  # watch the daemon
```

The next deploy of `deploy-server.sh` will incorporate steps 1–8 automatically (TODO for the next release).

### Tests

**513 passing** (492 from v1.11.10 + 21 new in `test_v11111.py`):

CGI auth endpoint (10 tests): correct password issues a ticket, ticket persists to disk with right shape, wrong password rejected and audit-logged, success audit-logged, unauthenticated rejected, unknown device 404, missing fields 400, GET method 405, each call issues a fresh ticket.

CGI audit endpoint (6 tests): correct daemon secret accepted, wrong secret rejected, missing secret rejected, no-secret-configured rejects all, audit details land in audit_log.json, GET method 405.

Helpers (5 tests): purge function drops expired and used tickets, daemon constants in sane ranges.

The daemon itself (websocket + SSH proxy) is not unit-tested — it would need a real SSH server in CI. It's tested manually against a real SSH host.

### Compatibility

Drop-in upgrade for the CGI side. The new endpoints are additive; existing flows unchanged.

The daemon is **optional** — if you don't deploy it, the dashboard's "Web terminal" menu item will fail when clicked (the WS connection times out), but everything else keeps working. CGI doesn't depend on the daemon being up.

Existing v1.11.10 agents do NOT need updating for the web terminal feature — the agent isn't involved in this flow at all. SSH goes directly from the RemotePower server to the device, completely outside the agent's pipeline.

### Known issues to test on real hardware

This release was developed without a live SSH server in CI, so some real-world behaviours haven't been exercised:

- **SSH server fingerprint changes.** With `known_hosts=None` we accept any fingerprint. If you reinstall a device, you won't get a "host key changed" warning. Consider this if you have devices that get reimaged.
- **Slow networks.** The 30-second `recv` timeout for the first credential message might be tight if the user is on cellular. Increase if you see "Timed out waiting for SSH credentials" complaints.
- **Idle timeout under nginx.** I set `proxy_read_timeout 1d` in the snippet which should handle long-idle terminals, but some load balancers in front of nginx will close anyway. If sessions die after exactly N minutes idle, that's the upstream proxy.

---

## v1.11.10 - 2026-05-07

### New features

**API enrollment via one-time pre-shared tokens.** Companion to the interactive PIN flow for non-interactive enrollment (Ansible, cloud-init, golden-image stamping). Three admin endpoints:

- `POST /api/enrollment-tokens` — generates a 32-char URL-safe token. Optional `expires_in` (seconds, default 24h, capped at 7 days), `default_group`, `default_tags`, `label`. Token is shown once in the response and never returned again.
- `GET /api/enrollment-tokens` — lists all non-expired tokens, but only returns the first 8 characters of each as a prefix. Designed so listing the page later doesn't leak active credentials.
- `DELETE /api/enrollment-tokens/{prefix}` — revoke by prefix (8+ chars). Refuses to act if the prefix matches multiple tokens.

Token consumption is atomic: `handle_enroll_register` deletes the token before creating the device. If two agents race with the same token, exactly one wins and the other gets HTTP 403. Default group/tags from the token apply at enrollment unless the agent explicitly provides its own.

Agent gets a new `enroll-token` action with `--server`, `--token`, `--name` flags. Token resolution chain:

1. `--token CLI_VALUE`
2. `$REMOTEPOWER_ENROLL_TOKEN` environment variable
3. `/etc/remotepower/enroll-token` file (must be mode 600, deleted after use)

The CLI-arg path leaks into `ps` output for the duration of enrollment. Env var doesn't. File path doesn't and self-cleans on success. Pick whichever fits your secret-distribution model.

Audit logging: token creation and revocation both logged with actor, label, and (for create) the default group/tags.

**Metric alerting (disk, memory, swap, CPU).** Three new webhook events: `metric_warning`, `metric_critical`, `metric_recovered`. Default thresholds:

| Metric | Warning | Critical |
|---|---|---|
| Disk usage (per mount) | 80% | 90% |
| Memory usage | 85% | 95% |
| Swap usage | 20% | 50% |
| CPU 1-min loadavg / cpu_count | 1.5× | 3.0× |

Hysteresis: a metric must drop `METRIC_RECOVERY_BUFFER` (5) percentage points below the warn threshold before `metric_recovered` fires. Without this, a metric oscillating around 80% would generate webhook spam.

State stored in `dev['metric_state']` keyed by `kind:target` (e.g. `disk:/var`, `memory:`). Transitions fire webhooks on every up- or down-shift between `ok` / `warning` / `critical`. Orphan mount states (a mount disappears between heartbeats) are cleaned up automatically.

**Per-device + per-mount overrides.** New endpoint `GET|PATCH|DELETE /api/devices/{id}/metric-thresholds`:

- GET returns `{overrides, effective, defaults, recovery_buffer_percent}` so the dashboard can show effective values without resolving them itself.
- PATCH accepts any subset of `disk_warn_percent`, `disk_crit_percent`, `mem_warn_percent`, `mem_crit_percent`, `swap_warn_percent`, `swap_crit_percent`, `cpu_warn_load_ratio`, `cpu_crit_load_ratio`, plus `disk_per_mount` (a dict keyed by mount path → `{warn, crit}`). Validates `warn < crit` for every kind. Out-of-range values rejected with 400 rather than silently clamped.
- DELETE clears all overrides, reverting to defaults.
- PATCH also clears `metric_state` so the next heartbeat re-evaluates under the new thresholds (otherwise a metric currently in `warning` state would silently stay there even if you raised the threshold).

**Agent metric collection extended.** `get_metrics()` now reports per-mount disk usage (skipping tmpfs/squashfs/overlay/snap/etc.), swap percent, 1-minute load average, and CPU count. Backwards-compatible — older agents without these fields still work, and root-disk alerting falls back to legacy `disk_percent` if `mounts` isn't reported. Per-mount alerting needs the agent updated to v1.11.10+.

### Architectural notes

The web terminal feature (#3 in your request) is **not in this release**. RemotePower's CGI architecture can't do persistent WebSocket connections cleanly — fcgiwrap is request-response only. The recommended path is a separate companion daemon (`remotepower-webterm`, ~300 lines, systemd unit, listens on 127.0.0.1:8765, nginx proxies `/api/webterm/`). Same security model you specified — admin password re-prompt, user types SSH user/password fresh each session, direct SSH connection, session recording. Deferred to v1.11.11 to land properly rather than rushing it.

### Tests

**492 passing** (444 from v1.11.9 + 48 new in `test_v11110.py`):

API enrollment (16 tests):
- Token creation with default and custom expiry, TTL clamping (60s min, 7-day max).
- List endpoint never returns full token values, only 8-char prefixes.
- Expired tokens auto-purged from listing.
- Revoke by prefix (success, 404 on unknown, 400 on too-short prefix).
- Token consumed atomically — second use returns 403.
- Default group/tags from token applied at enrollment.
- PIN path still works (backward compatibility).

Metric alerting (28 tests):
- Threshold resolution: defaults, per-device overrides, per-mount overrides.
- Classification: ok / warning / critical at each boundary.
- Recovery buffer enforced (must drop 5 below warn).
- No webhook fire when state doesn't change between heartbeats.
- State transitions fire correct event (warn / crit / recovered).
- Per-mount disk states isolated per path.
- Orphan mount cleanup when mount disappears.
- CPU load ratio uses cpu_count correctly.
- Endpoint validation: warn < crit, ranges, unknown device 404, admin-only.
- PATCH clears metric_state for re-evaluation.

Webhook event registry (4 tests): the three new events are registered, message generation works for disk/cpu/recovered, priority ordering correct.

### Compatibility

Drop-in upgrade. Existing devices keep working — metric alerting is additive (defaults apply when no overrides are set). Pre-v1.11.10 agents continue to report only the legacy `cpu_percent` / `mem_percent` / `disk_percent` (root-only) fields; root-disk and memory alerts work, but per-mount disk and swap and CPU loadavg alerts need the agent updated. Push agent self-updates via the toolbar Update button or per-device "Agent update" menu item to get the new metric collection.

### Known limitations

- **No global-default override.** `process_metric_thresholds` resolves: per-mount disk → per-device → built-in defaults. There's no "fleet-wide override" tier between per-device and built-in. If you want all your servers to alert at 70% disk instead of 80%, you currently set the override on each device individually. Could add a `config['metric_thresholds']` global tier in v1.11.11 if it's actually annoying — the underlying resolver is structured to make that a one-line change.
- **CPU alerting is loadavg-based, not utilisation.** The choice was "what does `uptime` show you" rather than "what does `top` show you." Loadavg captures runqueue depth + I/O wait, which is usually what's actually worth alerting on. If you want %cpu-utilisation thresholds instead, file a request — easy to add as a separate kind without changing the existing one.
- **Web terminal not in this release.** See above. v1.11.11 target.

---

## v1.11.9 - 2026-05-06

### Bug fixes

**Minimal table extended past the right edge of the page.** Visible as the table being a few pixels wider than the stats row and section headers above it. Reported with screenshot showing the table's right edge sitting outside the column the rest of the page content occupied.

The cause: I set `width: 100%` on the table but didn't set `table-layout: fixed`. CSS tables default to `table-layout: auto`, where the browser sizes columns based on the longest content in each. The `max-width: 200px` I'd put on `<td>` cells was a hint that auto-layout silently ignored — long content like "Debian GNU/Linux 12 (bookworm)" pushed the OS column wider than I'd budgeted for, and the table grew past the container's content width.

Fix: added `table-layout: fixed` to `.devices-minimal-table`, set explicit widths on every column header except OS (which stays auto and gets the remaining space), and dropped the now-redundant `max-width: 200px` on `<td>` cells. With fixed layout, columns are sized strictly by header widths and any overflowing cell content gets clipped with the existing ellipsis rule.

Total of fixed widths comes to ~900px (Status 90 + Name 190 + Hostname 160 + Group 100 + IP 130 + Version 90 + Last seen 100 + Actions 50), which leaves ~152px for OS in a 1052px content area (the standard `max-width: 1100px` container with 24px padding on each side). On narrower viewports the responsive `@media` rules drop low-priority columns before things get cramped.

### Tests

Test suite unchanged at **444 passing** — no Python code changed. The fix is CSS-only.

### Compatibility

Drop-in upgrade. No new dependencies, no schema changes, no agent update needed. Refresh the dashboard after deploying. Affects only the Devices page in minimal density mode; cards, compact, and spacious modes are untouched.

---

## v1.11.8 - 2026-05-06

### Bug fixes

**Monitor checks only ran when the dashboard was open.** Critical bug that's been there since the monitor feature was introduced. The `monitor_interval` config setting (default 300s) was honored by the UI but not by the server — the dashboard refetched `/api/monitor` on a timer, and `/api/monitor` ran the checks synchronously and returned the result. So the actual ping/tcp/http probes only happened when somebody had the page open. Close the tab, walk away for 4 hours, the next page-load showed a 4-hour gap in the history with no checks in between.

The webhook implication is more serious. `monitor_down` and `monitor_up` events fire from inside the same code path. So if a service went down at 14:00 and recovered at 16:00, and nobody had the dashboard open during that window, **neither webhook fired**. The downtime was invisible to anyone relying on alerts.

Symptoms in your case:
```
6.5.2026, 14.50.27  ↑ up  200
6.5.2026, 14.50.13  ↑ up  200
4.5.2026, 20.53.56  ↑ up  200      ← gap of ~18 hours
4.5.2026, 18.40.26  ↑ up  200      ← gap of ~2 hours
```

The gaps are exactly when nobody had the Monitor page loaded.

Fix: extracted the actual check logic into `_execute_monitor_checks(monitors)` and added a periodic runner `run_monitors_if_due()` that's called from `main()` on every CGI request. The periodic runner is gated by `monitor_interval` (clamped to a 60s minimum to prevent CGI-flood disasters). Most CGI hits do nothing — when the gate expires, the same check logic runs and fires the same webhooks as before.

In practice this means monitors run roughly every `monitor_interval` seconds as long as **anything** hits the server. With agents heartbeating every 60s, the trigger frequency is at least once a minute, so monitors will run on schedule. If all agents are offline AND no users are browsing, monitors won't run — but in that scenario you have bigger problems anyway (a `device_offline` webhook will fire from the next-due agent, which will trigger the dispatcher, which will trigger the monitor sweep).

If you've been getting "monitor history shows checks at random times only" — that's why. From v1.11.8 onwards, history fills in regularly.

**Service monitoring was always real-time and is unaffected.** Service state changes ride along in every agent heartbeat (the agent reports unit states every poll), so `service_down` and `service_up` webhooks always fired correctly. No bug here. Mentioning it because the question naturally comes up alongside the monitor bug.

**Dropdown menu in minimal mode was clipped by the table.** v1.11.7 introduced the table-based minimal layout with `overflow: hidden` on the wrap to keep rounded corners working. That overflow rule clipped the ⋯ dropdown menu when it tried to pop out of cells near the bottom or right edge of the table. Reported with screenshot showing the menu cut off mid-item.

Fix: replaced `overflow: hidden` with a per-corner `border-radius` on the first/last `<th>` and `<td>` so the rounded corners survive without an enclosing clip. Then added z-index hoisting on the row `:has()` an open dropdown so the menu sits above all sibling rows. Repositioned the dropdown to anchor right-aligned (it was sometimes pushing off the right edge of the page on narrow viewports).

Tested in Chrome, Safari, Firefox 121+. The `:has()` selector is required for the row-hoist; older browsers fall back to per-cell z-index, which works for everything except possibly the very-bottom row. If you're on Firefox <121 and see the bottom-row menu still clipping, update Firefox.

### Refactor

`handle_monitor_run()` is now a thin wrapper around `_execute_monitor_checks()` + `_persist_monitor_results()`. Both helpers are also called from `run_monitors_if_due()`. No behaviour change for the user-triggered path: pressing Refresh on the Monitor page still runs all checks synchronously and returns them, and side-effect-updates the timestamp so the next periodic sweep doesn't immediately re-check what you just saw.

### Tests

**444 passing** (433 from v1.11.7 + 11 new in `test_v1118.py`):
- Gate logic: empty config no-op, first-call runs, within-interval skips, past-interval runs, timestamp gets updated, back-to-back calls only run once, sub-60s interval clamped at 60.
- Webhook firing: first failure fires `monitor_down`, recovery fires `monitor_up`, persistent state doesn't double-fire.
- User-triggered path still works (regression check).

### Compatibility

Drop-in upgrade. Existing `config.json` keeps working — the new `last_monitor_run` field is created lazily on first run. Existing `monitor_notified` state is preserved. Refresh the dashboard after deploying.

### Known limitations

- **Periodic checks are still gated on CGI requests reaching the server.** A truly idle server (no agents heartbeating, no users browsing) won't run monitors. In practice every install has at least one agent doing 60s heartbeats so this is academic, but if you point this at a server with zero agents and just monitors, you'd want a real cron job. Future v1.12 work could add an out-of-band runner via systemd timer.
- **The `:has()` CSS selector covers the dropdown z-index hoist.** Chrome 105+, Safari 15.4+, Firefox 121+ all support it. Older browsers fall back to per-cell z-index which works for most rows but might clip the very-bottom menu. Modern browser baseline is fine.

---

## v1.11.7 - 2026-05-04

### Bug fixes

**Update history was always empty.** This was a critical agent bug that shipped in v1.10.0 and went unnoticed until somebody actually tried to use the per-device "Update history" panel after running an upgrade.

The flow was supposed to be:
1. Dashboard pushes `exec:apt-get -y upgrade ...` to the device.
2. Server's heartbeat response includes `command: <the script>`.
3. Agent receives the response, runs the script (~30s for `apt-get update && apt-get -y upgrade && ...`).
4. Agent puts the result in the next heartbeat → server detects it's a package upgrade → archives to `update_logs.json` → "Update history" shows it.

Step 4 is what was broken. Look at `client/remotepower-agent` line 1037–1040 (v1.11.6):

```python
if cmd:
    log.info(f"Received command: {cmd}")
    result = execute_command(cmd)
    if result is not None:
        payload['cmd_output'] = result      # <- bug
    payload['executed_command'] = cmd       # <- same bug
```

`payload` had already been POSTed at line 1020. Assigning to it after the POST is a no-op — the next loop iteration resets `payload` at line 959 and the result is lost. The agent journal showed `Command output (rc=0): ...` because `execute_command()` logs locally; `update_logs.json` got nothing because the data never crossed the network.

Fix: send a dedicated minimal follow-up heartbeat right after the command finishes. Carries just `device_id`, `token`, `ip`, `os`, `version`, `cmd_output`, `executed_command` — no sysinfo or journal, those are already on the server from the first heartbeat in this iteration. If the follow-up POST itself fails (network blip, server restart at exactly the wrong moment), the cmd_output gets stashed to `/var/lib/remotepower-pending-cmd.json` (or `/tmp/` if `/var/lib` isn't writable) and picked up by the next successful heartbeat.

If you've been pressing "Upgrade packages" since v1.10.0 and seeing nothing in Update history: the upgrades did run, the data just never came back. From v1.11.7 onwards everything is captured correctly.

The `executed_command` webhook (`command_executed` event) had the same bug — same fix.

### New features

**Per-device "Upgrade packages" in the dropdown menu.** Previously you had to either (a) tick the device's checkbox and use the toolbar batch-action button, or (b) click into the device modal. Both worked but were a step out of the way for what's a common single-device action.

Now there's a direct "Upgrade packages" item in the ⋯ menu on every device, sitting between "Agent update" and "Update history". Same flow as the batch path under the hood — calls `POST /api/upgrade-device` with one device ID. Confirmation dialog explains the `~30–120s` typical wait and where to find the output.

**Minimal density rebuilt as a real `<table>`.** v1.11.6's minimal mode laid out each device as a flex row, which couldn't keep columns aligned across rows — different content widths in OS / IP / Version meant "Online" wasn't under "Online" between rows. Reported by users with multi-line metadata.

Replaced with an actual HTML `<table>`. Each device is one `<tr>` with the same column structure. Columns: Status / Name / Hostname / Group / OS / IP / Version / Last seen / Actions. Sortable by clicking any column header (same UX as the Services / CVEs / Containers / etc. tables — first click ascending, second descending, third clears, shift+click for secondary sort). Rows alternate-tinted on hover. Offline rows are dimmed.

Responsive breakpoints drop columns rather than letting them overflow:
- ≤ 1280px → drops Hostname (Name carries enough)
- ≤ 1080px → drops Version (covered by the per-row patch badge)
- ≤ 920px → drops Group
- ≤ 760px → drops IP
- ≤ 620px → drops OS — at this point the table is only Status / Name / Last seen / Actions

The dropdown ⋯ menu is identical to the cards path — same handlers, same items, same `dropdown-${id}` element id, so `toggleDropdown()` works without modification. The whole behaviour is preserved; just the layout changed.

### Schema additions

- New stash file `/var/lib/remotepower-pending-cmd.json` (or `/tmp/remotepower-pending-cmd.json` for non-root deploys). Holds one cmd_output payload between agent restarts/network failures. Cleared on successful follow-up POST. Schema: `{cmd_output: {...}, executed_command: str, stashed_at: int}`. Permissions: 600 by default, root-only on standard deploys.

- Server-side: no schema changes. The follow-up heartbeat is a regular heartbeat with a subset of fields populated. `update_logs.json` schema unchanged.

### Tests

**433 passing** (425 from v1.11.6 + 8 new in `test_v1117.py`):
- Minimal follow-up payload (`device_id` + `token` + `cmd_output` only) is accepted and stored.
- Heartbeat without cmd_output still works (no regression).
- apt upgrade command lands in `update_logs.json` correctly.
- Non-upgrade command (e.g. `ls /tmp`) lands in `cmd_output.json` but NOT `update_logs.json`.
- `GET /api/devices/{id}/update-logs` returns the archived entry end-to-end.
- Three sequential upgrades all recorded in chronological order.
- Overflow at `MAX_UPDATE_LOGS_PER_DEVICE` evicts the oldest, keeps the most recent.

### Compatibility

Drop-in upgrade. The server is unchanged for all existing flows — it doesn't care whether cmd_output arrives in the same heartbeat as a sysinfo dump or in a dedicated follow-up. So:

- v1.11.7 server + v1.10.0–v1.11.6 agents: still broken (the bug is in the agent), update history still empty. Agent must self-update to v1.11.7.
- v1.11.7 agent + v1.11.0+ server: works correctly. The server happily accepts the follow-up heartbeat.
- v1.11.7 agent + pre-v1.11.0 server: works for cmd_output in general but won't archive to update_logs.json (that file was added in v1.10.0). Out of scope — anyone running v1.11.7 agents will have a recent server.

Refresh the dashboard after the agent self-updates — the next upgrade you trigger will populate Update history within ~60s.

### Known limitations

- **The agent does NOT retroactively recover lost upgrade history.** If you ran an upgrade on v1.10.0–v1.11.6 and the output was dropped, that data is gone forever. The journal on the device still has it (`journalctl -u remotepower-agent | grep "Command output"`), but there's no way to reconstruct an entry from there into `update_logs.json` retroactively. From v1.11.7 onwards, new upgrades are captured.
- **The stash file isn't automatically pruned.** If a stash file gets written and the agent never gets the chance to retry (e.g. you decommission the device with a pending stash), `/var/lib/remotepower-pending-cmd.json` will sit there forever. It's small (16 KB max for an upgrade output payload) and root-readable, so this is mostly cosmetic. The next upgrade overwrites it.

---

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

## v1.10.0 - 2026-04-29

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

## v1.9.0 - 2026-04-27

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

## v1.8.6 - 2026-04-26

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

## v1.8.5 - 2026-04-26

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

## v1.8.4 - 2026-04-25

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

## v1.8.3 - 2026-04-25

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

## v1.8.2 - 2026-04-24

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

## v1.8.1 - 2026-04-24

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

## v1.8.0 - 2026-04-23

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

## v1.7.0 - 2026-04-23

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

## v1.6.3 - 2026-04-22

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

## v1.6.2 - 2026-04-22

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

## v1.6.1 - 2026-04-22

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

## v1.2.0 - 2026-04-16

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

## v2.5.0 - 2026-05-19

### Custom monitoring scripts

Define arbitrary bash health checks server-side and push them to
enrolled devices. The agent runs each check every 5 minutes (no agent
restart or update required), captures stdout+stderr, and reports back
over the existing heartbeat channel.

**Exit code contract:** 0 = OK, anything else = FAIL. Deliberately
binary — no MRPE severity levels.

**Server (`server/cgi-bin/api.py`):**
- `CUSTOM_SCRIPTS_FILE` (`custom_scripts.json`) — new data file for
  script definitions.
- Limits: 50 scripts fleet-wide, 10 per device, 32 KB body, 4 KB
  captured output.
- `_ingest_custom_script_results()` — validates script ownership,
  stores results on the device record, fires edge-triggered webhooks
  on status transitions. First result never fires an alert (avoids
  initial assignment flood).
- `_get_custom_scripts_for_device()` — builds the list of assigned
  scripts to include in each heartbeat response.
- `custom_scripts` added to the `common_resp` heartbeat payload.
- Five CRUD endpoints: `GET/POST /api/custom-scripts`,
  `GET/PUT/DELETE /api/custom-scripts/:id`.
- `GET /api/custom-scripts/results` — fleet-wide current results,
  sorted with failing rows first.
- Two new webhook events: `custom_script_fail` (priority 4, red) and
  `custom_script_recover` (priority 3, green). Both have Discord
  titles, ntfy tags, priority, and human-readable message strings.

**Agent (`client/remotepower-agent.py` + binary):**
- `SCRIPT_CHECK_EVERY = 5` — run every 5 polls (~5 min at default
  60 s interval).
- `run_custom_scripts(scripts)` — writes each script to a private
  temp file (chmod 700), runs it with `/bin/bash` and a 30 s timeout,
  captures stdout+stderr merged and capped at 4 KB, deletes the temp
  file. Returns `{script_id: {ok, output, rc, ran_at, duration_ms}}`.
- `custom_scripts` list and `pending_script_results` dict added to
  heartbeat loop state. Scripts list updated from every heartbeat
  response. Results flushed into the next heartbeat payload.

**Frontend:**
- New **Custom Scripts** sidebar entry (terminal icon) between Monitor
  and Services.
- `page-custom-scripts` — stats bar, filter/status toolbar, fleet
  results table, definitions panel (one card per script).
- `custom-script-modal` — create/edit: name, description, script body
  textarea, device picker (checkboxes), Delete button on edit.
- `cs-output-modal` — full output viewer (click any output snippet).
- `loadCustomScripts()`, `renderCustomScriptsPage()`,
  `renderCsDefinitions()`, `openCustomScriptModal()`,
  `saveCustomScript()`, `deleteCustomScript()`,
  `csGenerateWithAI()`.
- **Inline AI generation:** describe the check, click ✨ Generate,
  review the bash script, edit if needed, save. Uses the existing
  `generate_script` system prompt with custom instructions for the
  monitoring context (exit-code contract, output brevity, timeout
  budget). Markdown code fences are stripped from the AI response
  before populating the textarea.

**Docs:**
- `docs/custom-scripts.md` — full reference: how it works, exit code
  convention, creation flow, execution environment, result viewing,
  alert semantics, limits, 5 example scripts, security considerations,
  full API reference.
- `docs/features.md` — new section in the detailed tables and a new
  entry in the "Added in" narrative section. Top summary table updated.
- `README.md` — custom scripts row added to the feature table.
- In-app documentation (Help → Documentation search) — new `doc-card`
  covering creation, results, alerts, and execution details.



### Progressive Web App (PWA) support

RemotePower is now installable as a desktop or mobile app via Chrome
(and any other Chromium-based browser that supports PWAs).

**What changes:**

- **`server/html/manifest.json`** (new) — Web App Manifest with name,
  short name, theme colour (`#3b7eff`), background colour, `standalone`
  display mode, and proper 192×192 and 512×512 icon references.
- **`server/html/sw.js`** (new) — Service worker with a versioned
  cache (`remotepower-shell-v2.4.15`). Strategy:
  - `/api/*` requests are always **network-only** — fleet data is live
    and must never be served from a stale cache.
  - Non-GET and cross-origin requests pass through unmodified.
  - App shell assets (HTML, JS, CSS, icons, manifest) are cached on
    install and served cache-first; newly fetched responses are added
    to cache automatically.
  - Navigation requests that fail offline fall back to the cached
    `index.html` shell so the login page appears rather than a browser
    error.
  - On each SW activate, all caches from previous versions are deleted.
- **`server/html/static/img/icon-192.png`** and **`icon-512.png`**
  (new) — PWA icons at the sizes Chrome requires, generated from the
  existing `logo-square.png`.
- **`server/html/index.html`** — added `<link rel="manifest">`,
  `theme-color` meta tag, `apple-mobile-web-app-*` meta tags, SW
  registration script, and a hidden **Install app** button in the
  header that becomes visible when Chrome determines install criteria
  are met (`beforeinstallprompt`). Clicking it triggers the native
  Chrome install dialog.
- **`server/conf/remotepower.conf`** — three nginx changes:
  1. `worker-src 'self'` added to CSP so the service worker is allowed
     to register.
  2. `location = /sw.js` with `Cache-Control: no-store` so the
     browser always fetches the current SW version.
  3. `location = /manifest.json` with correct `Content-Type:
     application/manifest+json` before the catch-all `.json` deny
     rule that would otherwise block it.
- **`deploy-server.sh`** and **`install-server.sh`** — `sw.js` added
  to the root-asset deploy loop alongside `manifest.json` and
  `favicon.*`.

**No agent changes.** PWA is purely a server/frontend feature.



### Patches page: Pending Reboot indicator

The Patches page now shows a small amber **⟳ Reboot** badge inline
with the hostname for any host that has `/run/reboot-required` on
disk (Debian / Ubuntu). Hovering the badge shows a tooltip confirming
the source. Useful for spotting hosts that were patched but not yet
restarted without opening each device detail individually.

**No agent change required.** The `reboot_required` flag has been
in the agent heartbeat since the early v1.x era. The server now
surfaces it through the patch-report API (`/api/patch-report`) and
the Patches page UI.

- `server/cgi-bin/api.py` — `handle_patch_report()` includes
  `reboot_required: bool` in every device entry. Value is always a
  boolean (`False` for distros that don't set the flag, or agents
  predating the field).
- `server/html/static/js/app.js` — `_registerPatchTable()` row
  renderer checks `d.reboot_required` and injects the badge.

### docs/features.md overhaul

Large sections were missing from `features.md`. Added:

- **AI assistant** — complete feature table covering providers,
  context-aware ✨ buttons, secret redaction, rate limiting,
  free-form chat, and local-model support (Ollama / LocalAI).
  The existing `docs/ai.md` is the full reference; `features.md`
  now has a proper summary table and cross-link.
- **MCP server** — feature table covering the 12 read-only tools
  and the no-write-tools policy.
- **Pending Reboot indicator** row added to the Fleet visibility
  table (this release).
- Top-level summary table extended with AI assistant and MCP rows.
- Added this release's new section under "Added in 2.2.x – 2.4.x".



Documentation and housekeeping release. No server or agent
behaviour changes beyond the version bump.

- `docs/features.md` brought current through v2.4.12 — mailbox
  threshold alerting, the `/api/status` endpoint and the
  recent-activity de-duplication were all missing.
- `CHANGES.md` and `CHANGELOG.md` merged into a single
  `CHANGELOG.md`. The two files had drifted apart and each held
  release entries the other was missing; this is the union.
- `docs/Manual.html` refreshed for current features and bumped
  to 2.4.13. The duplicate copy at the repo root was removed.
- Per-release notes under `docs/` pruned to the most recent
  three (v2.4.11–v2.4.13). `CHANGELOG.md` remains the complete
  history.
- Stale and malformed git tags cleaned up; only the last three
  releases are tagged going forward.
- `README.md` rewritten, led with the project logo.

## v2.4.12 - 2026-05-18

Dashboard fix: the "Recent activity" feed showed the most recent 8
events with no de-duplication, so one noisy host (an hourly
postfix log_alert) filled all 8 rows and buried everything else.
The feed now collapses repeated event+host+subject entries to
their most-recent occurrence — display only, the fleet event log
still records every event. 5 new tests, 1039 total, all passing.

Make-fleet-health-visible release. Mailbox threshold alerting: a
mailbox monitor can carry a threshold; crossing it fires a webhook
(edge-triggered). The Home "Needs attention" panel is now a single
ranked list computed server-side, merging offline devices, CVEs,
drift, patches and mailbox alerts. New /api/status endpoint — a
machine-readable fleet summary for external dashboards (Uptime
Kuma, Homepage, Grafana), behind a dedicated status token. 14 new
tests, 1035 total, all passing.

Documentation release. Audited docs/features.md against ~20
releases of changes — it was missing Proxmox, drift, the mailbox
monitor, the MCP server and more; now current. Added a full
install & admin guide (docs/admin-guide.md). The update-available
banner now shows the actual update commands and states that
RemotePower does not self-update. 11 new tests, 1021 total, all
passing.

Added "Scan packages now" to the device action menu. The agent
normally sends its package inventory + patch count only every few
hundred heartbeats; this one-shot flag makes it send a fresh
report on the next heartbeat or two — handy right after patching
a host. 7 new tests, 1010 total, all passing.

## v2.4.5 - 2026-05-17

Small features release.

### Added

- **"Scan packages now"** in the device action menu. The agent
  normally submits its package inventory + patch count only every
  few hundred heartbeats; this sets a one-shot flag so the device
  sends a fresh report within a heartbeat or two. Useful right
  after patching a host. The flag fires exactly once.

### Tests

- `test_v245.py`: 7 new tests. Total: **1010, all passing.**

### Upgrading from 2.4.4

Drop-in. Deploy the updated agent so hosts can act on the request.

### Caveats

Not instant — the request reaches the agent on one heartbeat and
is reported on the next (~1-2 min). The agent must be on 2.4.5.

## v2.4.4 - 2026-05-17

Bugfix and polish for the mailbox monitor, plus favicon.ico.

### Fixed

- **Mailbox monitor never received its paths.** The 2.4.3
  heartbeat handler read the mailbox path list from a `saved_dev`
  snapshot that the path list was never copied into — so the
  agent always got an empty list and never counted. `saved_dev`
  now carries `mailbox_paths`. A new test asserts the heartbeat
  response includes them.
- **favicon.ico restored.** Browsers auto-request `/favicon.ico`;
  the project shipped only `favicon.png`. A real favicon.ico is
  now included.

### Changed

- **Mailbox config moved to Settings → Mailbox monitor** (was on
  the device detail modal).
- **Dashboard view is now a tile** — same style/size as the
  Devices / Updates / Drift / CVE tiles, instead of a separate
  full-width card.

### Tests

- `test_v244.py`: 7 new tests. Total: **1003, all passing.**

### Upgrading from 2.4.3

Drop-in. A mailbox path configured under 2.4.3 starts working
once 2.4.4 is deployed — no reconfigure needed.

## v2.4.3 - 2026-05-17

Lightweight mailbox monitor.

### Added

- **Mailbox-count monitor.** Give a device one or more directory
  paths; the agent counts the regular files directly inside each
  (the Maildir `new/` convention — one file per unread message)
  and reports the numbers in its heartbeat. No IMAP/SMTP, no
  credentials, no message content — just counts. Configured in
  the device detail view; a "Show on dashboard" checkbox promotes
  a device so its counts appear in a Home-dashboard widget.
  Counting is done with os.scandir (no shell).

### Tests

- `test_v243.py`: 14 new tests. Total: **996, all passing.**

### Upgrading from 2.4.2

Drop-in. Deploy the updated agent to hosts you want to monitor.

### Caveats

The agent change is unit-tested for logic but not verified
end-to-end against a live server — smoke-test on one host first.
Counts refresh every ~5 minutes, not live. Counts files, not
messages (fits Maildir, not mbox). No threshold alerting yet.

## v2.4.2 - 2026-05-17

Small features release.

### Added

- **Default SSH username** — a per-user setting (Settings →
  Security → SSH preferences), stored in ui_prefs, validated as an
  SSH-safe username.
- **Quick SSH link** on the Devices page — an SSH icon next to
  each hostname builds an `ssh://user@host` link (IP when known,
  else hostname) and copies `ssh user@host` to the clipboard. The
  ssh:// hand-off depends on the client machine having an ssh://
  handler; the clipboard copy is the universal fallback.
- **Documentation** — four new Documentation-page cards: Proxmox
  virtualization, LXC containers, snapshots & rollback, quick SSH.

### Tests

- `test_v242.py`: 11 new tests. Total: **982, all passing.**

### Upgrading from 2.4.1

Drop-in, server-side.

## v2.4.1 - 2026-05-17

Bugfix release — CVE severity cache invalidation.

### Fixed

- **Stale CVE cache served wrong severities.** The 2.3.4 / 2.4.0
  severity fixes were correct but couldn't reach findings already
  in `cve_details_cache.json`. Entries written by a pre-2.3.4
  RemotePower carry a severity from the old buggy classifier and
  no `severity_source` field; the TTL-only refresh gate kept
  re-serving them (the tell: `severity: critical` +
  `severity_source: unknown`, an impossible pair from current
  code). Now an entry lacking `severity_source` is treated as
  stale regardless of TTL and re-fetched + re-classified. Self-
  healing — no manual cache wipe. Modern entries still use the
  normal TTL.

### Tests

- `test_v241.py`: 3 new tests (stubbed OSV). Total: **971, all
  passing.**

### Upgrading from 2.4.0

Drop-in, server-side. Stale entries refresh automatically; the
first post-upgrade scan of each device is a little slower.

## v2.4.0 - 2026-05-17

Proxmox snapshots + a CVE severity fix.

### Added

- **Proxmox VM/LXC snapshots.** A Snapshots button on each guest
  (Virtualization page for QEMU, Containers page for LXC) opens a
  modal to create / list / rollback / delete snapshots. Rollback
  is destructive — the UI requires typing the guest name to
  confirm. Delete is irreversible but doesn't touch the running
  guest. Disk-only snapshots (no RAM state). New `proxmox_client`
  methods + `GET /api/proxmox/snapshots`, `POST /api/proxmox/snapshot`.
  (Optional CPU/RAM adjustment and backup-trigger from the
  request are deferred — larger, separate work.)

### Fixed

- **CVE severity: Debian urgency shown as HIGH.**
  DEBIAN-CVE-2018-1000021 was HIGH while OSV rates it 5.0 Medium.
  When an OSV Debian entry has no CVSS, the chain fell back to the
  Debian tracker and mapped Debian's `urgency` straight to
  severity. Debian `urgency` is a patching-priority signal, not
  CVSS severity. The fallback is now capped at `medium` — it can
  never return high/critical.

### Tests

- `test_v240.py`: 17 new tests. One `test_v215` modal-ID test
  updated for the dynamically-created snapshot modal. Total:
  **968, all passing.**

### Upgrading from 2.3.4

Drop-in, server-side.

### Caveats

Not tested against a live Proxmox node (unit tests cover logic,
not API request shapes). Snapshot actions are fire-and-forget —
no task-completion polling. Disk-only snapshots. CVE severity
recomputes on next scan.

## v2.3.4 - 2026-05-17

Fleet-issues bugfix release.

### Fixed

- **CVE severity misclassification.** The CVSS scorer did
  substring matching — `'c:h' in vector` matched `AC:H` (Attack
  Complexity High) as `C:H` (Confidentiality High), so every
  high-attack-complexity CVE scored 7.5/HIGH regardless of real
  impact. A CVSS 2.9 LOW vuln came out HIGH. Now the CVSS vector
  is properly tokenised and the real CVSS v3.1 base-score formula
  applied; <4.0 can never be HIGH. Findings carry a
  `severity_source` field.
- **Unmonitored devices in Recent Activity.** Events for
  `monitored:false` devices are now filtered out of the fleet
  activity feed (at read time, reflecting current state).
- **Drift false positives.** Watched files can now be marked
  `ignored` per device — ignored files are non-critical (out of
  the drift/missing counts, no red status) but stay visible.
- **Services and Logs** moved from the Security nav group to Main.

### Investigated, not changed

- Dashboard time ranges (#3): no regression found — what looks
  like "only yesterday" is the known no-server-side-uptime-history
  limitation, a separate feature, not a bug.
- Mobile rendering: deprioritised per the issue list (resolved by
  switching browsers — browser-specific, not a code defect).

### Tests

- `test_v234.py`: 11 new tests; 3 pre-existing severity tests
  updated for the new `(severity, source)` return. Total: **951,
  all passing.**

### Upgrading from 2.3.3

Drop-in. CVE severities recompute on the next scan.

## v2.3.3 - 2026-05-17

Bugfix release.

### Fixed

- **Virtualization page was undiscoverable.** The Virtualization
  nav entry shipped hidden (`display:none`) and was only revealed
  once Proxmox was enabled — but you enable Proxmox under Settings,
  so the feature couldn't be found in the first place. The nav
  entry is now always visible; the page already handles the
  not-configured state with a "configure under Settings -> Proxmox"
  message.

### Known issue (not fixed)

A reported broken mobile render (page shows almost nothing) is not
addressed — it needs the browser console error to diagnose
properly rather than guess.

### Tests

Full regression: **940 tests, all passing.** No new tests — a
one-line visibility fix.

### Upgrading from 2.3.2

Drop-in.

## v2.3.2 - 2026-05-17

Security release — no new features. Result of a focused security
review (full writeup: docs/security-review-2.3.2.md).

### Fixed

- **Unsalted SHA-256 password fallback → salted PBKDF2.** When
  bcrypt wasn't installed, password hashing fell back to bare
  unsalted `sha256` — rainbow-table-able if `users.json` leaked.
  Now salted PBKDF2-HMAC-SHA256 (600k iterations, stdlib). Legacy
  hashes still verify and upgrade automatically on next login.
- **Default-password warning.** A bare-metal install seeds
  `admin`/`remotepower`. The seeded hash is now properly salted,
  and the account carries a `must_change_password` flag that
  drives a persistent red UI banner until the password is changed.

### Reviewed, unchanged

Login rate-limiting, constant-time compares, TOTP, agent TLS
verification, SSRF guard, security headers / CSP — all reviewed and
sound. Accepted limitations (CSP `'unsafe-inline'`, plaintext
secrets in config.json, CSRF posture) documented in the review.

### Tests

- `test_v232.py`: 11 new tests. Total: **940, all passing.**

### Upgrading from 2.3.1

Drop-in, server-side only. Existing password hashes keep working
and upgrade silently on next login.

## v2.3.1 - 2026-05-17

Security release — Proxmox token secret hardening.

### Changed

- **Proxmox token secret via environment variable.** The token
  secret can now be supplied in `RP_PROXMOX_TOKEN_SECRET` (systemd
  unit / container env); when set it takes precedence over
  `config.json`. Keeps the secret out of the data directory and
  out of the backup export. The `config.json` value remains a
  fallback. Settings → Proxmox detects an env-sourced secret and
  disables the config field.
- **Backup export redacts config.json secrets.** The backup ZIP
  used to include `config.json` verbatim — carrying the live
  Proxmox token, SMTP password and LDAP bind password. All three
  are now redacted in the exported copy (keys kept, values
  replaced with `(redacted)`).

### Tests

- `test_v231.py`: 8 new tests. Total: **929, all passing.**

### Upgrading from 2.3.0

Drop-in. To move the Proxmox secret out of `config.json`: set
`RP_PROXMOX_TOKEN_SECRET`, then clear the field in Settings and
save.

## v2.3.0 - 2026-05-17

Proxmox VE integration.

### Added

- **Proxmox VE integration.** RemotePower connects to a single
  Proxmox node and surfaces its guests:
  - New **Virtualization page** — QEMU VMs with status, CPU/mem,
    uptime; start / graceful-shutdown actions.
  - **LXC containers** appear as a section on the Containers page,
    same start / shutdown actions.
  Server-to-API integration — the RemotePower server calls the
  Proxmox REST API directly, no agent on the Proxmox node. New
  stdlib-only `proxmox_client.py` module.
- **Settings → Proxmox** — host, node, API token ID + secret,
  Verify TLS toggle, Test-connection button. Token secret is
  masked in the config API and stored in `config.json` (mode
  0600, not encrypted — use a scoped API token).
- Action allow-list (`start`/`shutdown`/`stop`/`status`); UI
  exposes start + graceful shutdown only. `migrate`/`clone`/
  `delete` cannot be invoked.

### Tests

- `test_v230.py`: 28 new tests. Total: **921, all passing.**

### Upgrading from 2.2.7

Server-side only, no agent change. Configure under Settings →
Proxmox; until then nothing changes.

### Caveats

Not tested against a live Proxmox node — unit tests cover the
logic, not the API request shapes. No background polling (every
page visit calls the API synchronously). Actions are
fire-and-forget (no task-status confirmation). Single node only.

## v2.2.7 - 2026-05-17

Mobile hotfix.

### Fixed

- **Mobile navigation drawer was unusable** — a wide panel of
  unlabelled icons. Two media-query blocks (a 768px icon-rail and a
  720px drawer) both applied below 720px and fought. The icon-rail
  block is removed; the drawer is now the single mobile layout with
  labels, alignment and padding restored.

### Tests

- `test_v227.py`: 6 tests. Total: **893, all passing.**

### Upgrading from 2.2.6

Drop-in — one CSS file changed.

## v2.2.6 - 2026-05-16

Correctness + telemetry release.

### Fixed

- **CVE scanner false positives on already-patched packages.** The
  scanner turned every OSV hit into a finding with no installed-vs-
  fixed version comparison — flagging e.g. `lua5.1 5.1.5-9build2`
  as vulnerable when it's newer than the ESM fix. New
  `_already_patched()` gate: Debian/Ubuntu uses `dpkg
  --compare-versions`, other ecosystems a tuple comparator;
  fail-safe keeps the finding on any uncertainty. Scan result
  carries a `suppressed_patched` count.
- **Docker random admin password.** Entrypoint generates a strong
  random password (`secrets.token_urlsafe`) when `RP_ADMIN_PASS`
  is unset and prints it once in a banner — no more `changeme`
  plaintext default.
- **Docker healthcheck** used `curl`, never installed → container
  always `unhealthy`. Switched to Python urllib.
- **nginx `duplicate MIME type "text/html"`** warning — removed
  `text/html` from `gzip_types`.
- **`remotepower-passwd` empty-default username** — Enter now
  defaults to the sole user instead of erroring "User '' not found".
- **Mobile modal stacking** — z-index scale normalised into clean
  tiers (dropdowns were at 10000, above modals); opening a modal
  closes the mobile nav + locks body scroll; mobile modals are
  full-bleed sheets.

### Added

- **Drift: expanded watch list** (8 → 13 files: passwd, group,
  login.defs, common-auth, apt sources) + **dormant handling** —
  a watched file absent for 3 consecutive heartbeats goes dormant,
  fires one event then goes quiet, stops counting as drift, and
  auto-revives if the file returns.
- **Agent host-health telemetry** — `get_host_health()` collects
  reboot-required, failed systemd units, logged-in users,
  listening ports, last boot. Surfaced in the device detail modal.
- **Container CPU / memory + health badge** — agent runs
  `docker stats`, parses `(healthy)`/`(unhealthy)` from status.
  Shown on the container card.

### Tests

- `test_v226.py`: 22 new tests.
- `test_v220` missing-file test updated for the dormant behaviour.
- Total: **887 tests, all passing.**

### Not included

New monitor types ("more monitor options") are deferred — they
need check logic + UI forms and warrant their own release.

### Upgrading from 2.2.5

Server + agent drop-in. Rebuild the Docker image for the
healthcheck/entrypoint fixes.

## v2.2.5 - 2026-05-15

Five UX fixes from live driving of the 2.2.4 dashboard.

### Changed

- **Container width 1100 → 1300 px.** Data density grew through
  the 2.2 cycle; 1300 fits 4 Home tiles + wide tables comfortably
  on standard 1920 monitors.
- **Tables / grids gain scroll wrap above 20 rows.** New
  `.scrollable-table-wrap` (sticky thead) and
  `.scrollable-grid-wrap` CSS classes. `tableCtl.render()` toggles
  the wrap on every render based on rendered row count. Devices
  card-grid view also gains the wrap above the same threshold.
- **Home → Recent activity items are clickable.** Each event
  routes to the most relevant page or modal for its class. Switch
  statement with explicit cases for every canonical fleet event;
  contract test asserts parity with `WEBHOOK_EVENT_NAMES`.
- **Favicon stays at document root.** Caught a real deploy bug:
  `deploy-server.sh` only published `*.html` from the doc root, so
  `/favicon.png` returned 404. Added an explicit loop for root
  non-HTML assets (favicon, robots.txt, manifest.json). Removed
  the duplicate `static/img/favicon.png` to keep a single source
  of truth.
- **Detail / Logs / Run hover affordance removed.** The strip was
  persistently fiddly (2.2.1 clipping, 2.2.2 placement). The row
  dropdown chevron exposes the same commands and is
  keyboard-friendly; clicking the device name opens the detail
  modal. CSS rule kept as a `display: none` no-op for back-compat.

### Tests

- `test_v225.py`: 14 new tests.
- `test_v222.TestPolishHotfixes`: three hover-affordance assertions
  inverted to "the strip is gone" — historical evolution preserved
  in test comments.
- Total: **865 tests, all passing.**

### Upgrading from 2.2.4

Drop-in. The favicon fix only takes effect on the next run of
`deploy-server.sh`.

## v2.2.4 - 2026-05-15

Two real-world bugs surfaced by live testing of the Home dashboard.

### Fixed

- **Recent fleet events panel was empty even after devices went
  offline.** Root cause: the activity panel read from the webhook
  delivery log, which only records events that had at least one
  destination (webhook URL or enabled email). Events firing with
  no destinations configured (typical fresh install with only SMTP)
  vanished into the void.
  - New dedicated **fleet event log** at `data/fleet_events.json`
    records every fired event regardless of destinations. Capped at
    `MAX_FLEET_EVENTS = 200`. `'test'` events excluded.
  - `_record_fleet_event(event, payload)` called from the top of
    `fire_webhook`, before all the existing gates. Payload
    summarised to discriminator keys (`device_id, device_name,
    path, unit, metric, cve_id, severity, …`), strings capped at
    256 chars.
  - New endpoint `GET /api/fleet/events?limit=N` (default 50, max
    200, newest first). Auth: any logged-in user (unlike
    `/webhook/log` which is admin-only).
  - Home dashboard `loadHome()` now reads `/fleet/events`; renderer
    adjusted for the `{ts, event, payload}` shape.
  - Empty-state copy updated to reflect the new behaviour.

- **Unmonitored devices appeared in "Needs attention".** Operators
  set `monitored: false` to silence a host (decommissioned, dev
  boxes, hosts being rebuilt) — the dashboard shouldn't bring them
  back up.
  - `_renderHomeAttention` filters `monitored !== false` at the
    top; reuses the filtered list for offline detection, patch
    backlog, and drift cross-reference. Same predicate the alert
    pipeline uses.
  - Drift section gates on the monitored set too (intersected
    with drift overview devices).

### Tests

- `test_v224.py`: 16 new tests covering fleet event recording,
  the endpoint, the no-destinations regression, and frontend
  changes.
- Total: **851 tests, all passing.**

### Upgrading from 2.2.3

Drop-in. New `data/fleet_events.json` created on first event
firing — no migration. On a fresh upgrade the activity panel is
empty until the next event fires; the "Needs attention" panel
benefits immediately.

## v2.2.3 - 2026-05-15

Hotfix to the Home dashboard activity panel — operator SMTP /
webhook tests were drowning real fleet events.

### Fixed

- **Activity panel now filters to canonical fleet events.** The
  JS keeps a `FLEET_EVENTS` allowlist mirroring the server's
  `WEBHOOK_EVENTS` tuple (`device_offline`, `device_online`,
  `monitor_*`, `service_*`, `cve_found`, `patch_alert`, `log_alert`,
  `container_*`, `metric_*`, `command_*`, `drift_detected`). The
  `test` event used for SMTP test deliveries and webhook test
  deliveries is **not** in the list, so test rows no longer
  clutter the dashboard.
- Tests are still recorded in the underlying webhook log
  (Settings → Webhook log view, unchanged) — they just don't
  reach the activity panel.
- The filter runs **before** `slice(0, 8)`, so real events can't
  be crowded off the visible window by a burst of test noise.

### Tests

- `test_v223.TestActivityFilter`: 3 tests. The contract test
  asserts the JS allowlist is exactly equal to the server's
  `WEBHOOK_EVENT_NAMES` — if a future commit adds a fleet event
  to the server tuple without updating the JS, the dashboard
  silently dropping that event surfaces as a test failure.
- Total: **835 tests, all passing.**

### Upgrading from 2.2.2

Drop-in. No data migrations, no agent changes.

## v2.2.2 - 2026-05-15

Small hotfix for three things found in the first browser run of
2.2.1. No new features.

### Fixed

- **Hover-action focus ring clipped on right edge.** The 2.2.1
  hover-revealed `Detail · Logs · Run` strip lived in the narrow
  last cell; focus rings extended beyond the cell's right edge and
  got visibly clipped. v2.2.2 moves the strip to the first cell
  (kept absolutely positioned so visual placement is unchanged),
  bumps `right: 12px` → `right: 24px`, adds `z-index: 2`, suppresses
  the system focus outline in favour of a softer accent border.
- **Home dashboard activity panel hit a 404.** `loadHome()` called
  `/api/webhook-log` — the path should have been `/api/webhook/log`.
  Also adjusted the renderer to handle the actual response shape
  (a flat list, not `{events: [...]}`). Viewers (who don't have
  permission for this endpoint) now see the friendly empty state
  rather than a console error.
- **`handle_webhook_log` 500 on bare-list `webhook_log.json`.**
  Pre-existing bug surfaced by the same test. Some deployments
  (older releases or hand-edited files) have the file as a bare
  list instead of `{entries: [...]}` — handler now accepts both.

### Tests

- `test_v222.py`: 8 new tests covering the three fixes.
- Total: **832 tests, all passing.**

### Upgrading from 2.2.1

Drop-in. No data migrations, no agent changes.

## v2.2.1 - 2026-05-15

Design polish release. No new feature surfaces — nine focused
improvements to how the existing ones look and feel, plus one
sub-feature (drift diff visualisation) that completes the v2.2.0
drift detection story.

### Added — Design polish (10 pieces)

1. **Distro logos next to device names.** Branded SVGs for Ubuntu,
   Debian, Arch, CachyOS, Fedora, RHEL family, openSUSE, Alpine,
   NixOS, Raspbian, FreeBSD, generic Linux. Inline, ~14×14, no
   external requests. Visible on device cards, the minimal table,
   the Drift page, and the Home dashboard. `osIcon()` API
   preserved — existing callers get the upgrade automatically.

2. **Sparkline mini-charts on device cards.** 52×14 SVG line
   charts next to disk and memory percentages. Auto-coloured by
   value (green / amber / red). Client-side ring buffer in
   `window._metricsHistory` builds 24 readings per metric per
   device as you sit on the page.

3. **Refined status colour palette.** New `--green-soft/edge`,
   `--amber-soft/edge`, `--red-soft/edge`, `--accent-soft/edge`
   CSS variables. New `.status-pill` component with five
   variants. Critical-state pulse animation (warning states are
   deliberately *not* pulsing — too noisy at fleet scale).
   `prefers-reduced-motion` honoured.

4. **Skeleton loaders replace centred spinners.** Shimmer-animated
   placeholder rows / cards on 11 HTML tables + 6 JS-injected
   loading states. New `renderSkeletonRows()` and
   `renderSkeletonCards()` helpers.

5. **Home dashboard** — new default landing page. Four big-number
   tiles (devices online, pending updates, drift events, CVE
   findings), "Needs attention" panel, "Recent activity" feed,
   fleet roster with 7-day status stripe per device. The first
   page you see is now fleet-at-a-glance, not the devices list.

6. **✨ identity extended.** Every ✨ button gets `.ai-btn` +
   provider-tinted glow (`.available` for cloud, `.local` for
   Ollama / LocalAI). AI-thinking state shows three sparkles
   cycling. AI-generated markdown content gets a gradient left
   edge. MutationObserver auto-applies to newly-rendered content.

7. **Typography upgrade.** Inter (UI) + JetBrains Mono (technical
   identifiers) via bunny.net — privacy-friendly Google Fonts
   mirror. Graceful fallback to system font stack for air-gapped
   deployments. `font-feature-settings cv02 cv03 cv04 cv11 ss01`
   enabled for the better "1", "a", "g" glyphs.

8. **Per-row hover affordances.** Minimal devices table rows
   reveal a `Detail · Logs · Run` strip on hover. Saves a click vs
   opening the row dropdown. Hidden on mobile (no hover on touch).

9. **Mobile dashboard view.** Phone-sized layout (<720 px):
   sidebar behind a burger button, tile grid stacks, low-priority
   columns hidden, tap targets ≥36 px, modals nearly full-screen.

10. **Logo → Home.** The header logo now navigates to the Home
    dashboard (was: Devices page).

### Added — Drift diff visualisation

The diff view that completes the v2.2.0 drift detection story.

- New endpoint `POST /api/devices/<id>/drift/fetch_content` —
  queues `exec:cat <path>` for each requested path. Denylist
  enforced (`/etc/shadow`, `/etc/gshadow`, rotated `-` siblings).
  Refuses non-watched paths to prevent use as an arbitrary
  file-read primitive.
- New endpoint `GET /api/devices/<id>/drift/content?path=...` —
  returns up to 2 stored captures with sha256.
- New mirror hook `_maybe_mirror_drift_content()` in the heartbeat
  output-ingest path. Detects `exec:cat <watched_path>` outputs
  and mirrors them into `drift_contents.json`. Denylist enforced
  on the mirror side too (defence in depth).
- New storage `data/drift_contents.json`, last 2 captures per
  path, ≤256 KB per capture.
- New UI: "Show diff" button per drifted file. Opens a sub-modal
  that polls for the cat output (every 5s, up to 90s) and renders
  a unified diff between the two most recent captures using
  LCS-based pure-JS `computeDiff()` + `renderDiff()`.
- New CSS: `.diff-view`, `.diff-line.add/del/hunk` for unified
  diff with syntax-coloured backgrounds.

### Tests

- `test_v221.py`: 46 new tests covering drift content fetch (7),
  drift content get (5), drift content mirror (6), and design
  polish asset presence (28 — verifies CSS / JS / HTML structures
  are in place).
- Pre-existing `test_v215.TestHtmlIdReferences`: drift-diff-modal
  IDs added to `KNOWN_DYNAMIC_IDS`.
- Total: **824 tests, all passing.**

### Upgrading from 2.2.0

Drop-in for the server. The new `data/drift_contents.json` file
is created on first content-fetch request — no migration needed.
No agent changes required: drift content fetch uses the existing
`exec:cat` mechanism, supported by every agent v1.0+.

## v2.2.0 - 2026-05-15

First minor-version bump since 2.1.0. Two new feature surfaces, both
tied to current themes in the fleet-management space.

### Added — Configuration drift detection

New **Drift** page under the Security sidebar group. Per-device
file integrity monitoring for a configurable list of config files
(default: SSH config, sudoers, fstab, crontab, hosts, resolv.conf,
nsswitch.conf, PAM sshd).

- Agent computes SHA-256 hashes of watched files every few
  heartbeats and ships them in the heartbeat payload.
  **Hash-only by design** — file contents never cross the wire on
  routine polling. `/etc/sudoers` and `/etc/shadow` can be watched
  without privacy concerns.
- Server stores baselines, detects divergence, fires
  `drift_detected` webhook once per change (debounced — not on
  every poll that reports the same new hash).
- New UI: fleet overview table + per-device detail modal with
  history viewer and "accept as baseline" button. Baseline
  acceptances are audit-logged with actor + timestamp.
- New endpoints: `GET /api/drift`, `GET / POST-baseline / DELETE
  /api/devices/<id>/drift`.
- New webhook event: `drift_detected` (defaults to enabled).
- New storage: `data/drift_state.json`, history capped at 20
  changes per file.
- **Requires agent v2.2.0+** for the agent-side hash reporting.
  Older agents work normally, just don't show drift data.
- Reference: [docs/drift.md](docs/drift.md). Compliance angle:
  SOC 2 CC6.1/CC6.6, ISO 27001 A.12.4.3/A.14.2.4, HIPAA
  164.312(c), PCI DSS 11.5, FedRAMP.

### Added — MCP server (natural-language fleet queries)

New `mcp/remotepower-mcp.py` (~470 lines, pure stdlib Python).
Implements the [Model Context Protocol](https://modelcontextprotocol.io)
so AI hosts like Claude Desktop, Cursor, or VS Code Copilot can
query the fleet in natural English.

- Runs on the **operator's laptop**, not on the RemotePower server.
  Spawned as a stdio subprocess by the AI host.
- Speaks JSON-RPC 2.0 over stdin/stdout; calls RemotePower's REST
  API on behalf of the AI using a regular API token.
- **12 read-only tools**: `list_devices`, `get_device`,
  `get_journal`, `get_services`, `get_containers`, `get_cves`,
  `get_drift`, `get_recent_commands`, `get_runbook`,
  `get_patches`, `get_tls`, `search_devices`.
- Device-name resolution: exact → prefix → substring →
  ambiguity error.
- **No write tools**, by deliberate design. Test suite asserts
  no write-shaped names slipped in. Write tools land in a future
  release with the server-side allow-list and per-token role in
  place — not before.
- Protocol version pinned to `2024-11-05` (widely-supported
  version hosts standardised on).
- Setup, Claude Desktop config snippet, security model,
  troubleshooting: [docs/mcp.md](docs/mcp.md).

### Changed

- **README "What's new"** trimmed to the latest three releases
  (2.2.0, 2.1.9, 2.1.8).
- **In-app Documentation page**: new doc-cards for Drift and MCP.

### Tests

- `test_v220.py` (24 tests): drift ingest behaviour (7), drift
  endpoints (5), MCP protocol (7), MCP device resolution (5).
- `test_v184.TestWebhookEventsConstant`: updated for new
  `drift_detected` event.
- `test_v215.TestHtmlIdReferences`: added drift-detail-modal IDs
  to `KNOWN_DYNAMIC_IDS` allow-list.
- Total: **778 tests, all passing.**

## v2.1.9 - 2026-05-15

Same-day hotfix for runbook hallucination on smaller local models,
plus a demo URL correction.

### Fixed

- **Runbook generator was inventing services, ports, firewall rules
  on smaller local models** (reported on Ollama qwen2.5-coder:14b).
  Three compounding causes, all fixed:
  1. **Ollama defaults to `num_ctx=2048` on the OpenAI-compat
     endpoint** — the snapshot was being truncated mid-content and
     the model invented the rest. `ai_provider.chat_openai_compatible`
     now passes `options.num_ctx=16384` for Ollama / LocalAI
     (ignored by real OpenAI / DeepSeek, which accept unknown body
     keys).
  2. **The v2.1.7 runbook prompt was too elaborate** — 8 verbose
     sections, no explicit anti-fabrication instructions. Rewritten
     to ~1 KB / 6 sections with `CRITICAL RULES` near the top:
     "Use ONLY information from the snapshot. Do NOT invent…", and
     each section has an explicit "if empty, write X" fallback.
  3. **The snapshot itself was too big** — up to 25 KB. Tightened
     to ~8 KB: 20 journal lines (was 40), 5 commands at 200 chars
     each (was 15 × 500), 10 CVEs at 100-char summaries (was 20 ×
     200), 10 containers (was 30), 500-char notes (was 1000),
     trimmed sysinfo to 9 operator-relevant fields, top 5 disks by
     usage.

- **Demo URL is `demoremote.tvipper.com`**, not `demo.tvipper.com`.
  Fixed across all `*.md` and `*.html` in the repo.

### Tests

- `test_v219.py` (8 tests): num_ctx wiring (Ollama/LocalAI yes,
  OpenAI no), prompt anti-hallucination keyword presence + size
  cap, snapshot bounded under 10 KB on synthetic heavily-populated
  device, no bare `demo.tvipper.com` in markdown files.
- Total: **754 tests, all passing.**

### Upgrade note

Existing stored runbooks in `runbooks.json` were written under the
bug. Worth regenerating any you care about via the **✨ Regenerate**
button on each device's detail modal Runbook section.

## v2.1.8 - 2026-05-15

Hotfix for a v2.1.7 bug where the AI fleet context reported every
device as offline.

### Fixed

- **AI fleet context wrongly reported all devices as offline.** The
  `ai_context.py` builder was reading `d.get('online')` directly,
  but `online` is a derived field computed on-the-fly by
  `handle_devices_list` from `last_seen` + `get_online_ttl()` — it's
  not persisted in `devices.json`. Every device looked `online=None`
  → falsy → "offline" in the AI's view. Reported by an operator
  whose live web server showed as offline in an AI chat response.
- Fixed: `ai_context._is_online()` now computes status canonically
  using the same formula as the device-list handler (recent
  heartbeat → online; agentless → manual_status default True).
  `build_fleet_context` and `build_combined_system_prompt` accept
  `now` and `ttl`; callers in `handle_ai_chat` and
  `handle_runbook_generate` pass `get_online_ttl()` so the AI sees
  exactly the same status as the dashboard.
- 5 new regression tests in `test_v217.py`; two pre-existing tests
  rewritten to use `last_seen` instead of the phantom `online`
  field that hid the bug.

Total: **746 tests, all passing.**

## v2.1.7 - 2026-05-14

Two new AI features and a few README/docs polish bits.

### Added

- **AI-generated device runbooks** (`✨ Generate runbook` in the
  device dropdown). Structured Markdown document per device —
  Purpose / Stack / Services / Exposure / Scheduled work / Recent
  activity / Health & risks / Operating notes. Built from the
  device's current state (sysinfo, journal, services, containers,
  CVEs, patch status, recent commands). Saved per-device in
  `runbooks.json`, regenerable any time.
  - New endpoints: `GET / POST-generate / DELETE
    /api/devices/<id>/runbook`.
  - New UI: ✨ Generate runbook modal with elapsed-time ticker;
    Runbook section on the device detail modal with View / Regenerate
    / Delete buttons.
  - Rate-limited under the same per-user-per-day cap as `/api/ai/chat`.
  - No batch "regenerate all" button, deliberately — cost-sensitive.

- **Level-1 RAG context awareness.** Every AI request now prepends
  a project-context block (what RemotePower is, the storage
  conventions, the agent/heartbeat model) plus a fleet snapshot
  (one line per device with name / OS / status / group / tags /
  notes). Online devices first.
  - New `ai_context.py` module (~180 lines, pure stdlib): no
    embeddings, no vector store. For ~5000 lines of docs and ~10
    devices, hand-curated context is cheaper and just as effective
    as a real RAG pipeline.
  - Configurable in Settings → AI assistant → **Context awareness**.
    Two checkboxes: include project context (non-sensitive, default
    on), include fleet snapshot (contains hostnames, default on).
  - Makes the AI stop giving generic Linux advice and start giving
    advice that references your devices, your groups, your conventions.

### Changed

- **README**: demo URL (`https://demoremote.tvipper.com`, demo/demo) now
  visible at the top of Quick start; "What's new" trimmed to the
  latest three releases. Older entries point at CHANGES.md.
- **Documentation page** (in-app): added four new doc-cards covering
  Scripts (script library), AI assistant (✨ button inventory),
  Device runbooks (v2.1.7), and Notification setup (recommended
  baseline + maintenance windows + ✨ Explain on alerts).

### Tests

- `test_v217.py` (26 tests): context module, chat integration,
  runbook generate / get / delete
- `test_v213.py`: updated for the new context-wrapped system prompt
- Total: **741 tests, all passing**

## v2.1.6 - 2026-05-14

Same-day hotfix for two compounding bugs on the Patches page.

### Fixed

- **Patches → Detail button threw "can't access property textContent
  of null".** Two issues stacked:
  1. The 2.1.5 ✨ Prioritise button placed `display:flex` on a
     `<td>`, which removed the cell from its `display:table-cell`
     behaviour and made the Detail buttons render outside the
     table. Fixed: flex container moved to a `<div>` inside the cell.
  2. The Detail handler `openDevicePatchReport()` referenced
     `#device-patch-title` / `#device-patch-body` / `#device-patch-modal`
     — but **those elements were missing from `index.html`
     entirely**. The function had been broken for several releases;
     the new ✨ Prioritise button drew attention to it. Restored
     the missing modal.

### Added — regression test

- `tests/test_v215.py::TestHtmlIdReferences` scans `app.js` for
  every `getElementById(...)` + `(open|close)Modal(...)` reference
  and verifies the ID exists in `index.html` (modulo a
  `KNOWN_DYNAMIC_IDS` allow-list for AI modal + toast). Bugs of
  this exact shape — JS referencing an HTML element that doesn't
  exist — will now fail at build time. Verified by temporarily
  removing the modal: test correctly listed all three missing IDs.

- 715 tests total, all passing.

## v2.1.5 - 2026-05-14

Polish release. Six items queued from real-world use of the 2.1.3/4
AI work plus the long-pending stderr-spam fix.

### Fixed

- **"No Data Provided" from ✨ Investigate** even when the device had
  data. Root cause: the JS was hitting `GET /api/devices/<id>` — a
  route that doesn't exist. Fixed: assemble the snapshot in parallel
  from `/sysinfo`, `/output`, and the devices list. Bails visibly
  ("No data available yet — has the agent checked in?") if there's
  genuinely nothing to send.
- **AI responses now render Markdown.** Models love their `**bold**`
  and `## headers` and `` `code` `` — showing them as raw punctuation
  was jarring. New `renderMarkdown()` helper: HTML-escape *first*,
  then transform — no script-injection vector. Supports headers,
  bold/italic, code fences, inline code, bullet/numbered lists, and
  blockquotes. Used in both the ✨ modal and the AI page chat.
- **Routine heartbeat / lock_wait logs silenced by default.** The
  `rp-silence-heartbeat-logs.sh` patch from 2.1.2 is now redundant —
  all three of its behaviours are the default. Per-request heartbeat,
  the `202 busy` retry log, and both lock_wait variants now require
  `RP_LOG_HEARTBEATS=1` / `RP_LOG_LOCK_WAITS=1` in the CGI env to
  re-enable. **OFFLINE/ONLINE state transitions and real-error
  stderr writes stay unconditional.**

### Changed

- **AI Assistant moved to Help section** (between Documentation and
  API Reference). Was under Planning, which never quite fit.
- **Device-card dropdown is now grouped + collapsible.** Was 22
  items in one vertical list, taller than most cards. New layout:
  - **Power** at top (always visible): shutdown / reboot / WoL / upgrade
  - **Inspect** (open by default): System info / ✨ Investigate / Metrics / Update history
  - **Operate** (collapsed): Web terminal / Custom command / Run script… / docker compose / Agent update
  - **Configure** (collapsed): tags, group, notes, intervals, allowlist, icon, monitoring
  - Remove device in its own danger zone at the bottom

  Native `<details>`/`<summary>` for the collapse — no JS needed.
  Both render sites (grid + table) share one `deviceDropdownHtml()`
  helper now instead of duplicating the 1.5 KB markup.

### Added — four new ✨ button surfaces

| Surface | Label | When it shows |
|---|---|---|
| Services → service detail | **✨ Diagnose** | non-active services |
| TLS → table row | **✨ Triage** | warning / critical / error only |
| Patches → table row | **✨ Prioritise** | devices with pending updates |
| (Helper exists for container logs but unused — covered by existing ✨ Explain on command output) | | |

Four new system-prompt keys: `diagnose_service`, `explain_tls`,
`prioritise_patches`, `explain_container_logs`.

### Documentation

- New **docs/ai.md** (~280 lines): provider selection, privacy
  toggles, rate-limit model, complete ✨ button inventory, AI page
  walkthrough, endpoint reference, system-prompt registry, storage
  layer, troubleshooting for every error users have hit.
- **docs/scripts.md**: added AI integration section covering the
  Generate / Explain / Audit buttons.
- **docs/README.md** index updated.

### Tests

- `test_v215.py` (3 tests): new prompt keys exist + env-gating
  pattern correct + state-transition logs stay unconditional.
- `test_v213.py`: system-prompt registry test updated.
- Total: **711 tests, all passing.**

## v2.1.4 - 2026-05-14

Same-day follow-up to 2.1.3 fixing the JSON.parse-on-every-button bug
against slow local Ollama models, plus a stand-alone AI Assistant page.

### Fixed — `JSON.parse: unexpected character at line 1 column 1`

**Symptom**: 2.1.3 Test Connection succeeded, but every actual ✨
button against Ollama smallthinker (a thinking model) failed with
the above SyntaxError.

**Root cause**: ✨ buttons defaulted to `max_tokens=4000` and the
model needed 60–180 seconds to generate. nginx's default
`fastcgi_read_timeout` of 60s closed the connection first, returning
a 504 HTML page. The JS `api()` helper called `r.json()` on the HTML
body and threw.

**Fix**:

- `HTTP_TIMEOUT_S` in `ai_provider.py` 60 → 300 (5 min)
- Per-button `max_tokens` tuned to the typical response length
  (Explain: 1500, Triage: 1000, Generate-script: 4000, etc.)
- New `aiApi()` JS helper — reads raw text first, surfaces a
  structured error with the HTTP status, response snippet, and a
  contextual hint (including the specific nginx config block to set
  if it looks timeout-shaped)
- Live "(Xs elapsed)" ticker in the ✨ modal and the AI page

**Operator action required for nginx**: add a `location /api/ai/`
block with `fastcgi_read_timeout 300s;` (full snippet in
`docs/v2.1.4.md`). The Python timeout helps but nginx is the
gatekeeper.

### Added — AI Assistant page

Sidebar entry under Planning. Standalone chat UI alongside the
inline buttons:

- **Status header** with provider, base URL, reachability, version
  (Ollama), currently-loaded models with VRAM use + expiry
- **Per-conversation model picker** populated from `GET /api/tags`
  (Ollama), `GET /v1/models` (LocalAI / OpenAI / DeepSeek), or the
  hardcoded fallback list (Anthropic). Overrides the global default
  for this conversation only — Settings still controls the default.
- **Multi-turn chat** with localStorage history (last 40 messages),
  Ctrl/⌘+Enter to send, Clear wipes local history only (audit log
  untouched). Conversation is local to the browser by design — never
  synced server-side.

New system prompt key `free_form` (concise, no filler).

### Added — provider introspection endpoints

- `GET /api/ai/models` — list available models with size / family /
  param-count where the provider exposes it
- `GET /api/ai/stats`  — provider, base_url, version, loaded_models,
  reachable

Both require auth, honour the disabled state, never leak the API key.

### Internal

- `ai_provider.py`: `_http_get_json`, `_ollama_root` (strips a
  trailing `/v1` so operators can paste either URL form),
  `list_models`, `provider_stats`, `CLOUD_MODELS` fallback
- `chat()` accepts `model` kwarg for per-request overrides
- `handle_ai_chat()` accepts `model` and `max_tokens` from body
  (both validated, max_tokens capped to configured limit)
- 8 new tests (708 total, all passing)

## v2.1.3 - 2026-05-14

### Fixed

**About page showed "Latest release 2.0.0 ✓ up to date" on a 2.1.2
box.** Two combining causes: `handle_version_check()` read
`server_version` out of `config.json` (often stale because installers
stamped it once and upgrades didn't refresh it), and the displayed
"latest" was GitHub's most recent tagged release — which is
legitimately older than the running version on a dev build or
between cutting and publishing a release. Fixed: read `local` from
the `SERVER_VERSION` module constant, and clamp `latest = max(github,
local)` so the UI never tells you to "upgrade" to a version older
than what you have.

### Added — AI assistant

Optional LLM integration with five providers behind a single
`/api/ai/chat` endpoint. **Disabled by default**; admin opts in via
Settings → AI assistant.

Providers covered by the OpenAI-compatible adapter (`/v1/chat/completions`):
**OpenAI / ChatGPT**, **DeepSeek**, **Ollama**, **LocalAI**. Anthropic
(Claude) gets its own adapter for `/v1/messages`. Pure stdlib —
no pip-installed packages added.

Settings → AI assistant:

- Provider, model, optional base URL override
- API key (masked on read, last-4 visible, `__clear__` to wipe)
- Privacy toggles for what gets sent: hostnames (off), IPs (off),
  journal content (off), command output (on). Bearer tokens, AWS
  keys, and long hex strings are *always* redacted regardless.
- Per-response token cap, per-user-per-day request cap
- Test-connection button

Inline ✨ buttons funnel through one reusable modal:

| Surface | Label |
|---|---|
| Command output panel | **✨ Explain** |
| Journal panel | **✨ Find the problem** |
| Script editor | **✨ Generate from prompt** (inserts into textarea) |
| Script editor | **✨ Explain** |
| Script editor | **✨ Audit for risks** |
| CVE finding row | **✨ Triage** |
| Device dropdown (⋯ menu) | **✨ Investigate** |
| Webhook log row | **✨ Explain** |

Generated scripts go through the same dry-run + dangerous-pattern
detection as human-written ones — no special AI-trusted path.

Endpoints:

- `GET  /api/ai/config` — masked
- `POST /api/ai/config` — admin, validated, audit-logged
- `POST /api/ai/chat`   — auth, system-prompt key OR literal,
  redacted, rate-limited per user/day, audit-logged (token counts
  + elapsed only — never the prompt/response content)
- `POST /api/ai/test`   — admin smoke test

### Internal

- `ai_provider.py` module (~360 lines, stdlib only): provider
  abstraction, redaction, system prompt registry
- 40 new tests in `tests/test_v213.py`: redaction (always-on + toggle),
  validators, About-page logic (running-ahead, GitHub-ahead, stale-key),
  config CRUD, chat endpoint, rate limiter (per-user isolation,
  zero-means-unlimited). Total suite **700 tests, all passing**.

### Misc

- Favicon link updated to `/favicon.png` (user-added to html root)
  with a shortcut-icon fallback.
- All 9 version-string sites bumped 2.1.2 → 2.1.3.

## v2.1.2 - 2026-05-14

### Fixed

**Lost-update race in heartbeat (THE actual offline bug).** v2.1.0's
`save()` redesign moved the tmp-file write outside the lock so the
critical section was just the rename. Correct for single-shot saves
but it broke an unspoken contract with callers that did
read-modify-write: load → mutate → save was no longer atomic. Two
concurrent heartbeats from different devices interleaved their
load/save windows and the second one's rename clobbered the first
one's `last_seen` update. Devices drifted past TTL and got marked
offline despite heartbeating fine — looked identical to the
original 2.0 flock fluctuation, but the cause was completely
different.

Fix: new `_locked_update(path)` context manager that holds the flock
across load → mutate → save. `handle_heartbeat()` is rewritten around
this primitive so concurrent heartbeats now serialise correctly. The
`compose_projects` update (which previously did a separate save) is
merged into the same atomic transaction.

`save()` itself still uses the v2.1.0 fast-path (tmp+fsync outside
lock) — that optimisation is correct for *single-shot saves where
the caller doesn't read first*. The new primitive is for callers
that do RMW, who now opt in explicitly.

### Internal

13 new tests in `tests/test_v212.py` including a threaded
reproducer for the race (20 concurrent updaters, asserts every
update is preserved) and a deliberate demonstration of the bug
using the old pattern. Total suite: **660 tests, all passing.**

Other admin-action RMW sites (note/group/tag/poll-interval edits)
still use the unsafe pattern but are much lower frequency than
heartbeats. Migrating them to `_locked_update` is queued for a
follow-up release.

## v2.1.1 - 2026-05-13

### Fixed

**Offline regression from 2.1.0.** The 2.1.0 heartbeat handler used
the non-blocking save path for *every* save, including `last_seen`.
Under flock contention that save would 202 silently *before*
`last_seen` was persisted — the agent treated 202 as success, the
server still thought the device was last seen however-long-ago, and
the device drifted past the online TTL → marked offline even though
heartbeats were arriving fine. Fixed: the `DEVICES_FILE` save is back
to blocking (which is now microseconds-fast thanks to the 2.1.0
fsync-outside-lock work). Only the *optional* saves below it
(cmd_output, containers, config, etc.) keep non-blocking semantics.

**Diagnostics were silent.** Two 2.0-era code smells made the offline
bug above invisible to operators: `check_offline_webhooks()` only logged
inside `fire_webhook()`, so an operator without webhooks got a silent
state flip; and `main()` wrapped every per-request maintenance sweep in
`try: ... except Exception: pass`, swallowing every error including
ones an operator most needs to see. Now: state transitions always log
`[remotepower] OFFLINE dev=… last_seen=… delta=…s ttl=…s` regardless
of webhook config; heartbeat arrival logs to stderr (visible in nginx
error log); the bare except-pass blocks are replaced with a `_safe()`
helper that prints the full traceback before continuing.

**`log_alert` webhook now includes the matched line.** Pre-2.1.1 the
message read `host/unit: pattern "X" matched N times` — no actual log
content. The payload already had `sample` (first 3 matching lines);
`_webhook_message` just wasn't using it. Now the message shows the
first matched line (truncated to 200 chars for embed compatibility)
and an `(+ N more matching lines)` footer if there were more.

### Changed

**Default offline TTL bumped from 3 → 5 minutes.** `DEFAULT_ONLINE_TTL`
is now 300s (= 5 missed polls at the 60s default interval).
`MIN_ONLINE_TTL` is now 150s (was 90). Field reports of "device went
offline" turning out to be brief network blips the agent recovered
from. Operators who want the old tighter behaviour can configure
`online_ttl: 180` via Settings → Webhooks.

### Added

**Per-container actions on the Containers page.** Start / Stop /
Restart / Logs buttons on every reported container. New agent
dispatch `container:<runtime>:<action>:<id>` with argv-only invocation
(no `shell=True`), tight ID regex (`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}`),
runtime allowlist (docker | podman; kubectl excluded), and action
allowlist (start, stop, restart, pause, unpause, logs). New endpoint
`POST /api/devices/<id>/containers/action` validates the requested
`container_id` against the agent's last-reported listing — same
security boundary as compose. Kubernetes pods don't get action buttons
since the agent generally doesn't have the kubectl context to act on
them through this path.

**Demo data reflects v2.1 features.** `seed-demo-data.py` now also
seeds `scripts.json` (5 example scripts including one deliberately
flagged dangerous to demo the `⚠ DANGER` badge), `batch_jobs.json`
(one recently-completed batch run for the status modal), and
`log_watch.json` (two log-watch rules and one fired alert showing
the new matched-line format). 6 demo devices report tag-driven
`compose_projects` so the v2.1.0 compose dropdown is visible in the
demo.

### Internal

20 new tests in `tests/test_v211.py` (647 total, all passing).
Bumped all 9 version-string sites from 2.1.0 → 2.1.1.

## v2.1.0 - 2026-05-13

### Fixed

**Flock offline fluctuation.** Heartbeats no longer hold the per-file
flock across `fsync()`. `save()` now writes the per-process unique tmp
file *outside* the lock and holds it only for the rolling-backup copy
and atomic rename — both O(1) metadata ops. Adds an explicit
`non_blocking=True` mode that retries `LOCK_NB` for ~100 ms and raises
`LockBusy` on persistent contention. The heartbeat handler catches
`LockBusy` and returns HTTP 202 (Accepted), which the agent treats as
"delivered, retry next cycle". Result: a busy save no longer stalls
the request past the agent's HTTP timeout, and devices stop flipping
between online and offline. Lock waits >50 ms log to nginx error log
as `[remotepower] lock_wait path=… waited_ms=… mode=…`. See
the v2.1.0 release notes for the full rationale.

**Auto-refresh closes browser window / crashes tab.** Two independent
bugs combined: `escHtml()` didn't escape `'`, so device names like
`O'Brien` broke out of inline `onclick="fn('${escHtml(d.name)}')"`
strings on every 60 s refresh; and `setInterval` kept firing under
open modals and background tabs, re-rendering the device grid out
from under captured event handlers. Fix: new `escAttr()` that
hex-escapes (`\x27` etc.) for JS-in-attribute contexts (73 inline
handler sites converted); refresh pauses when a modal is open or the
tab is hidden; `toggleDropdown` no longer leaks click handlers to
detached DOM nodes.

### Added

**Script library** (`docs/scripts.md`). New **Scripts** page in the
sidebar for multi-line bash scripts, separate from the existing
one-liner Command Library. CRUD + on-demand dry-run using `bash -n`
plus an 11-pattern dangerous-command regex sweep
(rm -rf /, fork bombs, dd to block devices, mkfs against /dev/,
curl|bash, etc.). Body capped at 64 KB; 500 scripts per server.
Routes: `GET/POST/PUT/DELETE /api/scripts[/<id>]`,
`POST /api/scripts/<id>/dry-run`.

**Multi-select script execution.** New "Run script" button on the
batch action bar. Pick a saved script, fan out across the selection.
`POST /api/exec/batch` queues `exec:<body>` on each target;
`GET /api/exec/batch/<id>` returns per-device status with output as
it arrives. Job records have a 1-hour TTL, pruned on access.
Refuses dangerous-pattern scripts without `confirm_dangerous: true`;
refuses syntax-erroring scripts outright.

**docker compose dropdown** (`docs/compose.md`). The Linux agent now
scans `/opt`, `/home`, `/docker`, `/srv` (`find -L -maxdepth 4`,
5 s timeout, 50-project cap, prune list for .git / node_modules /
.cache / venv) for `docker-compose.yml` / `compose.yml` and reports
the listing alongside containers in the heartbeat. Device cards get
a **docker compose (N)** entry in the ⋯ menu with Up / Down /
Restart / Pull / Logs (last 50) buttons. Action endpoint
`POST /api/devices/<id>/compose/action` validates `dir` is one of
the paths the agent itself reported — even an admin token can't aim
`compose:up` at arbitrary paths. Agent enforces the action allowlist
and path validity independently. Output cap 64 KB, timeout 180 s.

### Internal

**`make dist`** target. Builds `dist/remotepower-2.1.0.tar.gz` +
sha256 file, with an explicit exclude list (not gitignore-driven, so
new directories don't accidentally ship). Runs the full test suite
against the staged tree before producing the tarball; a broken
release fails fast.

**`make version`** target prints the current version from
`SERVER_VERSION` in `api.py`. Single source of truth for the tarball
filename + the README badge.

**Docs split.** Top-level `README.md` cut from 807 → 115 lines.
Long-form content lives in topical files under `docs/`: install,
features, architecture, api, security, https, troubleshooting,
upgrading, agent-commands, windows-client, plus the new
scripts.md / compose.md / v2.1.0.md.

**Tests.** 60 new tests in `tests/test_v210.py` covering: real
flock contention triggering LockBusy, every dangerous-pattern regex
with positive + negative cases, script CRUD + sanitisation + size
caps, batch dispatch + TTL pruning, compose ingest sanitisation,
the compose action security boundary, and the no-XSS-on-apostrophes
invariant. Total suite is now **627 tests**, all passing.

## v2.0.0 - 2026-05-08

A visual + organizational refresh. New branding throughout, sidebar restructured for browsability, in-app documentation, code split into separate CSS/JS files for maintainability. No breaking changes for agents — this is a 2.0 because of UI visibility, not API shape.

### Branding

- **Real logo and favicon.** PNG assets now live in `server/html/static/img/`:
  - `favicon.png` → browser tab icon (linked via `<link rel="icon">`)
  - `logo-square.png` → 36×36 in the header bar
  - `logo-primary.png` → big logo with wordmark + "POWER. MANAGE. ANYWHERE." tagline on the login screen
- Header logo is now a clickable link that returns to the Devices page (the home view). Hover state for affordance.
- The placeholder sun-shape SVG that has been there since v1.0 is gone.

### Sidebar reorganized

The flat 18-item list is now grouped:

- **Main** (always visible): Devices, CMDB, Containers, Network, Monitor
- **Security** (collapsible): TLS / DNS, Patches, CVEs, Services, Logs
- **Planning** (collapsible): Schedule, Calendar, Tasks, Maintenance, History
- **Admin** (collapsible, defaults to collapsed): Settings, Users, API Keys, Library, Audit, Links
- **Help**: Documentation (new!), API Reference (was "API Docs"), About

Group state persists per-browser in `localStorage` (`sidebar.<group>.collapsed`). Active page always expands its containing group, so a fresh load shows you where you are even if the group was collapsed.

The four admin items that were in the flat list (Users, API Keys, Audit, Links) plus Settings, Library are all now under the Admin toggle. Day-to-day use only needs Main + Help expanded; admins expand Admin when they need it.

### Documentation page

New "Documentation" entry under Help in the sidebar. Curated set of in-app help cards covering the most common questions:

- Enrolling devices (PIN + API token flows)
- Metric alerts (defaults, per-device, per-mount, hysteresis, trends)
- Web terminal (auth flow, recording, deploy)
- Commands (per-device dropdown, batch mode, library)
- Webhooks (auto-format detection, event list, test events)
- External monitors (probes, schedule)
- Two-factor authentication (enable/disable)
- Tables: filter / sort / density
- Backup & restore
- Troubleshooting (the actual symptoms users hit)
- API access (auth methods, common patterns with curl examples)

Each card is a `<details>` element — expand on click, no JS required for the toggle. Top of page has a substring search that auto-expands matching cards. Cards have a `data-keywords` attribute so search hits things like "ssh" → web terminal even though the summary doesn't say "ssh".

The full reference Manual.html is still around and linked from the troubleshooting section.

### Metric trends on the Monitor page

The Devices page has had the metrics chart modal since v1.7. v1.12.0 surfaced live metric values on the Monitor page; v2.0 adds a "Trend" button next to "Thresholds" on each device row. Same chart as the per-device view (last 60 data points, sparkline-style for CPU / memory / disk). One click takes you from "your fleet's current state" to "this device's history" without leaving the Monitor page.

### Code split (HTML / CSS / JS)

`index.html` was 8088 lines with a 1320-line `<style>` block and 4900-line inline `<script>`. Now:

- `server/html/index.html` — 1835 lines (just the markup + the two external refs)
- `server/html/static/css/styles.css` — 1320 lines (everything from the old `<style>`)
- `server/html/static/js/app.js` — 4930 lines (everything from the old `<script>`)

The split is strictly mechanical — no code was rewritten or restructured. Same selectors, same functions, same global variables, same load order. The script is still injected at the end of body for the same DOMContentLoaded timing it had inline. This makes the file tree navigable for the first time:

- Want to find a CSS rule? `grep '\.foo' static/css/styles.css`
- Want to find a function? `grep 'function foo' static/js/app.js`
- Want to see the page structure? `index.html` is a fifth its old size and now actually readable.

I deliberately did NOT do a deeper refactor (ES modules, build step, component framework). That's a multi-week project and you said "please don't break the code." The mechanical split gets us 80% of the maintainability benefit at ~0% breakage risk. If you want a real architectural rewrite, plan it as a v2.1 in its own session and we'll do it properly.

`deploy-server.sh` updated to rsync the `server/html/static/` tree to `/var/www/remotepower/static/`. The deploy is otherwise identical.

### What's NOT in this release (intentional)

- **No agent changes.** Agents on v1.11.10+ work unchanged. The 2.0 in the version is about UI visibility (visible reorganization, branding) not protocol breakage.
- **No new server endpoints.** Documentation page is pure frontend; sidebar reorganization is pure frontend; metric Trend button reuses the existing `/api/devices/{id}/metrics` endpoint.
- **No SQLite migration.** Considered for v1.12.1, decided flock + atomic write was sufficient for this scale. Same call here. SQLite is the right answer at 1000+ devices, not at 9.

### v2.0 polish (later same day)

After the initial 2.0 build went out, several rounds of polish before declaring done — no version bump.

**Real branding.** Three updated PNGs deployed to `server/html/static/img/`. Login screen no longer adds a dark background frame around the primary logo (the logo asset has its own gradient). Login card widened from 400→480px so the 280px-wide logo has comfortable horizontal margin.

**Multi-doc CMDB.** Assets used to support exactly one Markdown blob in `documentation`. Now they support an arbitrary list of titled docs (`docs: [{id, title, body, created_by, created_at, updated_by, updated_at}]`, capped at 50 per asset). Schema migration is automatic on first read: legacy `documentation` strings synthesise a single doc with `id="legacy"` which gets promoted to a real id on first edit, and the back-compat field is cleared. Three new endpoints: `POST /api/cmdb/{id}/docs`, `PUT /api/cmdb/{id}/docs/{doc_id}`, `DELETE /api/cmdb/{id}/docs/{doc_id}` — all admin-auth, all audit-logged. UI rewritten: docs render as collapsible cards with per-card edit/delete, separate edit modal with Markdown preview tab, "+ Add document" button. The existing single-textarea is gone. 21 tests in `test_v200_docs.py`.

**Demo / read-only mode.** New `RP_READ_ONLY=1` environment variable. When set, `_enforce_read_only()` runs at the top of `main()` before route dispatch and blocks every non-GET request with a 403 + `{"demo": true, "error": "Demo mode...", "detail": "..."}` body, except a small whitelist (login, logout, totp/verify, public-info, openapi.json) needed for visitors to log in and browse. Frontend reads the flag from `/api/public-info` on load, shows a banner if set, surfaces friendly toast on demo-mode 403s instead of generic failure messages. Designed for a public sandbox like `demoremote.tvipper.com`. 17 tests in `test_v200_demo.py`.

**Demo seed script.** `packaging/seed-demo-data.py` populates a target data dir (default `/var/lib/remotepower/`, override with `--data-dir`) with 16 fake homelab devices: hypervisor + NAS + firewall + DNS + reverse proxy + media + git + monitoring + a few agentless network devices. Realistic hostnames using the unallocated `.lab` TLD so they can't collide with anything real. Seeds devices, CMDB metadata, packages, services, containers, CVE findings, monitor history, audit log, etc. Idempotent (deterministic — same input, same output). Re-runnable on a cron if you want `last_seen` to keep looking fresh.

**Demo install script.** `packaging/install-demo.sh <hostname>` sets up a SEPARATE demo vhost alongside your production install — different data dir (`/var/lib/remotepower-demo/` by default), same shared CGI code under `/var/www/remotepower/`. Auto-detects the CGI user, creates the demo data dir owned by it, runs the seed script, generates an nginx server block at `/etc/nginx/sites-available/remotepower-demo` with the per-vhost env vars (`RP_DATA_DIR=/var/lib/remotepower-demo` and `RP_READ_ONLY=1`), enables it, validates with `nginx -t`, reloads. The trick is that fcgiwrap forwards `fastcgi_param` env vars to the CGI process, so two vhosts can share one fcgiwrap pool but operate on different data dirs. TLS is left to the user (certbot reminder printed at the end). Idempotent re-runs re-seed and re-render the nginx config. Production install at `remote.<domain>` is never touched.

**Documentation page expansion.** The original 11 cards covered common workflows. Added 21 more (one per sidebar entry): Devices, CMDB, Containers, Network, Monitor, TLS/DNS, Patches, CVEs, Services, Logs, Schedule, Calendar, Tasks, Maintenance, History, Settings, Users, API Keys, Library, Audit, Links. Each `<details>` card has `data-keywords` so the substring search finds them by alternate terms (e.g. "ssh" → web terminal card, "topology" → Network card). 32 doc cards total now.

**README rewrite.** Front-loaded the Quick Start (server + client + Docker) right after the intro. New "What you can do with it" section grouping headline features in a 2-column visual table. New "Why RemotePower" positioning section (small / lightweight / properly self-hosted / not toy features). Comprehensive feature table reorganised into 6 categories (Fleet visibility, Commands & automation, Alerts & monitoring, CMDB & docs, Auth & access, Operational quality, UX) with version annotations. Architecture diagram updated to reflect the v1.12.1+ persistence (`.bak` rolling backups), the webterm sibling daemon, and the actual current set of state files (~30 JSONs, grouped by purpose). 788 lines total, no duplicate Quick Start sections.

**Tests after polish.** 567 passing (529 from v1.12.1 + 21 multi-doc in `test_v200_docs.py` + 17 demo-mode in `test_v200_demo.py`). No regressions. JS validated with `node --check`. HTML div + `<details>` counts balanced.

**Deploy.**

```bash
sudo bash deploy-server.sh
```

Hard-refresh the browser. For the demo-sandbox use case, deploy a SEPARATE vhost alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.tvipper.com
sudo certbot --nginx -d demoremote.tvipper.com
```

Production at `remote.tvipper.com` keeps working with your real data; the demo at `demoremote.tvipper.com` runs the same CGI code against a separate `/var/lib/remotepower-demo/` data dir with `RP_READ_ONLY=1`. Visitors log in as `demo` / `demo` and can browse everything but every mutation returns a friendly 403 toast.

---

## v1.12.1 - 2026-05-08

A targeted hardening release after a real-world incident: a user's `devices.json` got corrupted by a concurrent-write race between two CGI processes, leaving the file with a complete first JSON document followed by trailing garbage. Effects: dashboard showed no devices, all agents got 403 "Credentials rejected" because the heartbeat handler couldn't find them in the empty-on-load file.

This release makes that class of corruption impossible going forward.

### Storage hardening (the main thing)

`save()` now does:

1. **Round-trip integrity check before any disk write.** Serialise with `allow_nan=False`, then parse the result back. If the data won't round-trip, raise `ValueError` immediately instead of writing it. Catches NaN/Infinity (Python's json silently allows them, but most other tools reject them) and any logic bug producing a malformed structure.

2. **Exclusive flock on a sidecar lock file.** A `<file>.lock` zero-byte sidecar lives alongside each data file, used as a coordination point. `fcntl.flock(LOCK_EX)` serialises writers — two CGI processes both calling `save(DEVICES_FILE, ...)` will queue on the lock instead of racing.

3. **Per-process unique tmp filename.** `<file>.tmp.<pid>.<nonce>` instead of just `<file>.tmp`. Even with the lock, this is belt-and-braces — if two writers ever did manage to be in `save()` simultaneously (lock file deleted, filesystem weirdness), they wouldn't share a tmp file and couldn't trample each other's bytes.

4. **fsync before rename.** Forces the bytes to durable storage before the atomic rename, so a power loss right after the rename doesn't return to a zero-length file. tmpfs and a few other filesystems don't support fsync; we tolerate that gracefully.

5. **Rolling backup.** The current file is copied to `<file>.bak` before every replace. Single rolling backup, not history — if the live file ever ends up corrupted, we have one known-good prior state to fall back to.

`load()` automatically falls back to `.bak` if the canonical file is corrupt:

- Tries `<file>` first
- On `JSONDecodeError`, tries `<file>.bak`
- If `.bak` parses, returns its content and logs a warning to stderr (visible in nginx error log via fcgiwrap)
- If both are corrupt, returns `{}` — same as a missing file — so the rest of the code keeps working in degraded mode rather than crashing the whole CGI

The fallback is the difference between v1.12.0's "one bad write makes the dashboard unusable until manual recovery" and v1.12.1's "one bad write is silently absorbed using the previous heartbeat's state, with a warning logged."

### Why not SQLite?

I considered migrating the hot-path files (`devices.json`, `services.json`, `containers.json`, `metrics.json`, `history.json`) to SQLite. Real analysis:

- ✅ ACID transactions, the corruption you saw is fundamentally impossible
- ❌ Major refactor — 2-3 sessions of work
- ❌ Backup/restore changes (`tar czf` stops being a complete backup)
- ❌ Debugging tools change (no more `jq` over your data)
- ❌ Schema migrations become a thing forever

At the user's scale (~9 devices, 60-second heartbeats = ~9 writes/min), `flock` handles serialisation trivially. SQLite's wins (queries, indexes, joins, large-scale concurrency) don't apply to a key/value lookup workload where the whole dataset fits in memory anyway. The hardening above gives the same correctness guarantee for this scale without losing the ability to `jq` your way through everything during incidents.

If RemotePower ever grows past 1000 devices or the data shape changes meaningfully, SQLite is the right migration. For now, the boring-architecture philosophy wins.

### Multi-select in minimal devices view

The cards mode had checkbox-driven batch select since v1.10; minimal mode shipped without it in v1.11.7. Now minimal has parity:

- Leading checkbox column on every row
- Header checkbox with select-all-visible (respects the active filter — if you've filtered to "production" tag, select-all toggles only those rows)
- Selected rows get a subtle blue background highlight
- Reuses the same `selectedDevices` Set as cards mode, so switching density mid-selection preserves your selection

### Recovery tool for files corrupted before this upgrade

`packaging/recover-corrupted-json.py` is a one-shot fix for any JSON file already corrupted by the v1.12.0 bug. It:

- Scans `/var/lib/remotepower/*.json` (or specific files passed as args)
- Uses `json.JSONDecoder.raw_decode()` to find the first valid JSON document and treat anything trailing as garbage
- Reports what it would do in dry-run mode (the default)
- With `--apply`, makes a `.broken-<ts>` backup and writes the recovered content over the live file

```bash
sudo -u www-data python3 packaging/recover-corrupted-json.py            # dry-run scan
sudo -u www-data python3 packaging/recover-corrupted-json.py --apply    # fix
```

### Tests

**529 passing** (513 from v1.12.0 + 16 new in `test_v1121.py`):

Atomic save (8 tests): basic round-trip, lock sidecar created, .bak created on second save (not first), tmp files cleaned up on success, unique tmp per process, NaN/Inf rejected, no file created on invalid data, mode 600 preserved.

Load with fallback (4 tests): missing returns empty, corrupt falls back to .bak, no .bak returns empty cleanly, both corrupt returns empty without crashing, load() never modifies disk.

End-to-end recovery (1 test): plant corruption, verify load() falls back, verify next save() re-establishes clean state with both files valid.

Concurrent save (1 test): 8-process `multiprocessing.Pool` (spawn context) all writing the same file with read-modify-write loop. Without v1.12.1 hardening, this reliably reproduces a `JSONDecodeError` by the time it finishes; with the hardening, every load returns valid data and every key has the right value.

`test_save_unique_tmp_per_process` (2 tests) — verifies the tmp filename is parameterised by `(pid, nonce)`. Reaches into the implementation intentionally to validate the hardening property described in the module-level comment.

### Compatibility

Drop-in upgrade from v1.12.0. The on-disk format is unchanged — `.bak` and `.lock` sidecars get created on the next save of each file. Existing JSON files keep working as-is.

If you hit the v1.12.0 corruption bug, run `recover-corrupted-json.py --apply` once after upgrading to clean up any leftover damaged files.

### Performance impact

Each `save()` now does:
- One additional file open + flock (~50µs)
- One `shutil.copy2()` for the rolling backup (~1ms for files up to 100KB)
- One `fsync()` (depends on filesystem; typically 1-10ms on a real disk, free on tmpfs)

Heartbeat handler does ~2-3 saves; total added latency per heartbeat: ~5-30ms. Negligible at scale up to thousands of devices/minute.

---

## v1.12.0 - 2026-05-07

A polish release wrapping up the loose ends from v1.11.11 — proper deploy automation, the per-device metric thresholds UI that v1.11.10 only exposed via API, surfacing live metrics on the Monitor page, and a comprehensive manual rewrite. No new server endpoints.

### New: install-webterm.sh

`packaging/install-webterm.sh` handles the v1.11.11 deploy that didn't go smoothly. The original instructions assumed `rp-www`/`rp-webterm` users that don't exist on Debian/Ubuntu (which uses `www-data`); the script now auto-detects the actual CGI user via process heuristic plus fallback through `www-data` → `nginx` → `http` → `rp-www` → `apache`.

What it handles:
- Detects the CGI user by looking for processes (`pgrep -u USER -f '(fcgi|nginx|cgi|php-fpm)'`) and falls back to existence-only if no match.
- Detects the package manager (apt/dnf/pacman/apk/zypper) and installs `python3-websockets` + `python3-asyncssh`.
- Creates the `rp-webterm` daemon user (idempotent — re-runs are safe).
- Adds the daemon user to the CGI user's group so it can read the ticket file.
- Sets up directories with correct ownership: `/var/lib/remotepower/webterm-sessions/` (daemon-owned, mode 750), `/var/lib/remotepower/webterm_tickets.json` (CGI-owned, mode 640).
- Generates the daemon ↔ CGI shared secret to `/etc/remotepower/webterm-secret` and writes it to `config.json` (using `sudo -u $CGI_USER` so file ownership stays correct).
- Renders the systemd unit with the right `User=` / `Group=` / `ReadWritePaths=` substituted in.
- Prints the nginx snippet you need to add (with the right port substituted in) plus the `$connection_upgrade` map docs.
- `--dry-run` mode shows everything it would do without touching the system.

Run as `sudo bash packaging/install-webterm.sh` (or with `--cgi-user www-data` to override detection). At the end it tells you what to paste into nginx and what to verify.

### New: per-device metric thresholds UI

The endpoint shipped in v1.11.10 (`GET|PATCH|DELETE /api/devices/{id}/metric-thresholds`) but had no UI — you had to use `curl`. v1.12.0 adds a full editor accessible from the device dropdown menu (both cards and minimal modes). The modal:

- Shows the device's current sysinfo readings at the top so you know what thresholds make sense (memory %, swap %, load ratio + cpu count, every mount with current %).
- Has warn/crit fields for memory, swap, default-disk, and CPU load ratio. Empty means "use default"; placeholder shows the inherited value, so customised vs. inherited is visually distinct.
- Has a per-mount disk overrides section with add/remove rows. Common case: `/var` at 70/85 (logs grow fast), `/backup` at 95/98 (designed to fill).
- Reset-to-defaults button DELETEs all overrides.
- Validation: paths must start with `/`, both warn+crit required for each mount, warn must be < crit (server-side enforced; client also pre-checks).

Saving clears the device's `metric_state` so the next heartbeat re-evaluates under the new thresholds (this was already in v1.11.10 — just calling it out because it matters when you're tuning live).

### New: live metrics on the Monitor page

The Monitor page used to show only external probes (ping/TCP/HTTP). Now it has a "Device metrics" section underneath that shows every enrolled device's current sysinfo state, color-coded by alert level:

- **Device** column with group badge
- **Alert** column showing aggregate level: critical ⨯ red, warning ⨯ amber, OK ⨯ green, offline (muted gray for non-reporting devices)
- **Memory / Swap / CPU load** columns, each individually colored by that metric's specific alert state
- **Disks** column listing every mount with its percent, each colored by its own state. Long paths are truncated; tooltip shows the full path plus used/total GB.
- **Thresholds** button on each row jumps straight to the per-device threshold editor for that device.

Sortable, filterable (by name, group, tags, or mount path). When sorting by status ascending, critical-state devices come first. Summary line above the table: "N critical • M warning" or "all clear".

The data source is the existing `/api/devices` endpoint — no new server work required. The `metric_state` field already populated by v1.11.10's threshold processor tells us which alerts are live.

### New: comprehensive manual

`Manual.html` rewritten from scratch — was 328 lines of fragmented legacy notes; now a coherent ~470-line document covering everything from the architecture overview through web terminal deployment to troubleshooting. 11 sections with a clickable TOC. Replaces both `Manual.html` and `docs/Manual.html` (kept identical to avoid drift).

New coverage:
- Section 2 (Install): proper subsections for server, web terminal daemon, agent, with the `install-webterm.sh` recommended path
- Section 3 (Enrollment): both PIN and API token flows side-by-side, with the three token-resolution methods explained
- Section 7 (Metrics): all four flows covered — the modal UI, the Monitor-page surfacing, the API, and direct `devices.json` inspection
- Section 8 (Web terminal): full architecture diagram, auth flow walkthrough, security model summary, session-recording details with replay command, retention cron suggestion
- Section 11 (Troubleshooting): the actual symptoms users will hit (404, 502, 1006 close codes, missing per-mount data, CSP blocking xterm.js)

### Tests

**513 passing — unchanged.** No new server endpoints, so no new test coverage required. The install script is bash so wasn't unit-tested; manually verified with `--dry-run --cgi-user www-data` that it produces the right output and doesn't crash.

### Compatibility

Drop-in upgrade from v1.11.11. No schema changes. Existing per-device metric overrides set via API in v1.11.10 work without modification — the new UI just makes them visible and editable. The webterm daemon binary is unchanged from v1.11.11; only the install script around it is new.

### Known limitations carried forward

- xterm.js still loads from cdn.jsdelivr.net (CSP issue if blocked; manual instructions for self-hosting in Manual.html)
- Web terminal session recordings still aren't auto-pruned (cron suggestion in manual)
- Web terminal SSH host-key checking still off by design

---

## v1.11.11 - 2026-05-07

### New feature: web terminal

Browser-based SSH terminal accessible from the dashboard. Click "Web terminal" in the per-device dropdown menu, type SSH user/password and your RemotePower admin password, and you get a live xterm.js terminal connected to the device.

The architecture is a small companion daemon (`remotepower-webterm`) that handles WebSocket and SSH proxying, because RemotePower's CGI-over-fcgiwrap model can't hold persistent connections. The CGI handles auth and audit logging; the daemon handles the bytes.

#### Files added

- `server/webterm/remotepower-webterm.py` (~470 lines) — the daemon. asyncio + `websockets` + `asyncssh`. Listens on 127.0.0.1:8765 by default; nginx proxies `/api/webterm/connect` to it.
- `packaging/remotepower-webterm.service` — systemd unit with hardening (NoNewPrivileges, ProtectSystem=strict, RestrictNamespaces, etc.). Runs as a dedicated `rp-webterm` user.
- `packaging/nginx-webterm.conf` — drop-in nginx snippet for the WebSocket proxy. Requires the `$connection_upgrade` map (standard pattern, documented in the snippet).
- `tests/test_v11111.py` — 21 tests for the CGI-side endpoints.

#### Files modified

- `server/cgi-bin/api.py` — added `handle_webterm_auth`, `handle_webterm_session_audit`, ticket store helpers, two new constants. Routes wired up.
- `server/html/index.html` — "Web terminal" item in the device dropdown menu (both cards mode and minimal mode), modal for SSH credentials + admin password, full-screen terminal view, xterm.js loaded on first use from cdn.jsdelivr.net.

#### Auth flow

1. User clicks "Web terminal" on a device. Modal asks for SSH host (pre-filled from device IP), SSH user, SSH password, and RemotePower admin password.
2. Frontend POSTs to `/api/webterm/auth`. CGI validates the admin password against the user's stored hash. Mismatch → 403 + `webterm_auth_failed` audit entry.
3. CGI generates a 32-byte URL-safe ticket, stores it in `webterm_tickets.json` with TTL = 60 seconds, returns the ticket to the frontend along with the daemon URL.
4. Frontend opens a WebSocket to `wss://<host>/api/webterm/connect?ticket=...`. nginx proxies to the daemon.
5. Daemon reads ticket from URL, validates against `webterm_tickets.json`, deletes it (single-use). Then waits for the first WS message: a JSON blob with `{host, user, port, password, cols, rows}`.
6. Daemon SSH-connects via `asyncssh.connect()`. Opens a PTY shell. Pumps bytes between WS and SSH.
7. Session ends → daemon POSTs metadata back to `/api/webterm/audit`, authenticated via shared secret in `/etc/remotepower/webterm-secret` (matches `config.json[webterm_daemon_secret]`).

#### Session recording

Every session is recorded to `/var/lib/remotepower/webterm-sessions/<session_id>.cast` in [asciinema v2](https://docs.asciinema.org/manual/asciicast/v2/) format. Default is **output-only** — keystrokes are not recorded because they could include `sudo SECRET_VALUE` and similar. Set `RECORD_INPUT=1` in the daemon's environment to also record keystrokes if you have compliance reasons; only do this if you've thought through who can read the session-recording directory.

The format is plain-text JSON Lines with a header and `[delta_seconds, "o", "output"]` records. Replayable in any asciinema player (web, CLI, browser via `asciinema-player.js`); also greppable as raw text. Each recording is capped at 10 MiB — at the cap we stop recording but keep proxying bytes.

#### Security model summary

- Tickets are single-use, 60-second TTL, ~256 bits of entropy
- The daemon binds to 127.0.0.1 only (loopback). nginx terminates TLS for the browser hop
- SSH credentials never persist; live in memory inside the daemon for one session
- SSH host-key verification is OFF by design (the user explicitly chose this host through the dashboard, and adding `known_hosts` management would mean a first-connect prompt for every device — more theatre than security here). If you want strict host-key checking, this is the right discussion to have for v1.12
- Audit POSTs from daemon to CGI authenticated via shared secret, not session token (the daemon is a system service, not a user)
- systemd hardening: dedicated user, no privilege escalation, read-only root filesystem with explicit ReadWritePaths, restricted namespaces

#### Known limitations / open work

- **Browser dependencies are loaded from cdn.jsdelivr.net.** xterm.js is ~250 KB; loading from your own server is more secure (no CDN tampering risk) but more deployment work. v1.11.11 uses the CDN for simplicity. To self-host: download `@xterm/xterm@5.5.0/css/xterm.min.css`, `@xterm/xterm@5.5.0/lib/xterm.min.js`, and `@xterm/addon-fit@0.10.0/lib/addon-fit.min.js` into `server/html/static/` and edit `_loadXtermOnce()` to point there. SRI hashes can then be added.
- **No SSH key auth.** Per your spec, only password auth in v1.11.11. Adding key auth means storing the keys somewhere (CMDB Vault would be the natural place); you didn't ask for it so I didn't build it.
- **Session recordings aren't pruned automatically.** They accumulate in the recordings directory. A cleanup cron / systemd timer is a v1.11.12 task. For now, manage retention with `find /var/lib/remotepower/webterm-sessions -mtime +30 -delete` or similar.
- **The daemon is a single process.** Concurrent sessions all run in the same asyncio event loop, which is fine up to dozens of sessions; if you ever need hundreds, switch to a process-per-session model.
- **Session listing UI not in this release.** You can see sessions in the audit log (action `webterm_session`) and in the on-disk recording files. A "browse sessions" page in the dashboard would be a nice v1.11.12 addition.

#### Deploy steps (one-time)

```bash
# 1. Create the daemon's user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/remotepower rp-webterm
sudo usermod -a -G rp-www rp-webterm   # so it can read the ticket file

# 2. Install Python deps
sudo apt install python3-websockets python3-asyncssh   # or pip install

# 3. Install the daemon binary
sudo install -m 755 server/webterm/remotepower-webterm.py /usr/local/bin/remotepower-webterm

# 4. Generate the shared secret (used for daemon → CGI audit POSTs)
SECRET=$(openssl rand -hex 32)
sudo install -m 640 -o rp-webterm -g rp-webterm /dev/stdin /etc/remotepower/webterm-secret <<< "$SECRET"
# Also store it where the CGI can find it:
sudo -u rp-www python3 -c "
import json, sys
from pathlib import Path
cfg = json.load(open('/var/lib/remotepower/config.json'))
cfg['webterm_daemon_secret'] = '$SECRET'
json.dump(cfg, open('/var/lib/remotepower/config.json', 'w'))
"

# 5. Set up the recordings directory
sudo install -d -m 750 -o rp-webterm -g rp-webterm /var/lib/remotepower/webterm-sessions

# 6. Make the ticket file readable by the daemon
sudo touch /var/lib/remotepower/webterm_tickets.json
sudo chown rp-www:rp-www /var/lib/remotepower/webterm_tickets.json
sudo chmod 640 /var/lib/remotepower/webterm_tickets.json

# 7. Install + start the systemd unit
sudo install -m 644 packaging/remotepower-webterm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotepower-webterm

# 8. Add the nginx snippet (paste contents of packaging/nginx-webterm.conf into
#    your existing server { ... } block, ABOVE any catch-all `location /` rule)
#    Then test and reload:
sudo nginx -t && sudo systemctl reload nginx

# 9. Verify
curl -s http://127.0.0.1:8765 -i  # expect "Connection: Upgrade" expected, won't actually upgrade with curl
sudo journalctl -u remotepower-webterm -f  # watch the daemon
```

The next deploy of `deploy-server.sh` will incorporate steps 1–8 automatically (TODO for the next release).

### Tests

**513 passing** (492 from v1.11.10 + 21 new in `test_v11111.py`):

CGI auth endpoint (10 tests): correct password issues a ticket, ticket persists to disk with right shape, wrong password rejected and audit-logged, success audit-logged, unauthenticated rejected, unknown device 404, missing fields 400, GET method 405, each call issues a fresh ticket.

CGI audit endpoint (6 tests): correct daemon secret accepted, wrong secret rejected, missing secret rejected, no-secret-configured rejects all, audit details land in audit_log.json, GET method 405.

Helpers (5 tests): purge function drops expired and used tickets, daemon constants in sane ranges.

The daemon itself (websocket + SSH proxy) is not unit-tested — it would need a real SSH server in CI. It's tested manually against a real SSH host.

### Compatibility

Drop-in upgrade for the CGI side. The new endpoints are additive; existing flows unchanged.

The daemon is **optional** — if you don't deploy it, the dashboard's "Web terminal" menu item will fail when clicked (the WS connection times out), but everything else keeps working. CGI doesn't depend on the daemon being up.

Existing v1.11.10 agents do NOT need updating for the web terminal feature — the agent isn't involved in this flow at all. SSH goes directly from the RemotePower server to the device, completely outside the agent's pipeline.

### Known issues to test on real hardware

This release was developed without a live SSH server in CI, so some real-world behaviours haven't been exercised:

- **SSH server fingerprint changes.** With `known_hosts=None` we accept any fingerprint. If you reinstall a device, you won't get a "host key changed" warning. Consider this if you have devices that get reimaged.
- **Slow networks.** The 30-second `recv` timeout for the first credential message might be tight if the user is on cellular. Increase if you see "Timed out waiting for SSH credentials" complaints.
- **Idle timeout under nginx.** I set `proxy_read_timeout 1d` in the snippet which should handle long-idle terminals, but some load balancers in front of nginx will close anyway. If sessions die after exactly N minutes idle, that's the upstream proxy.

---

## v1.11.10 - 2026-05-07

### New features

**API enrollment via one-time pre-shared tokens.** Companion to the interactive PIN flow for non-interactive enrollment (Ansible, cloud-init, golden-image stamping). Three admin endpoints:

- `POST /api/enrollment-tokens` — generates a 32-char URL-safe token. Optional `expires_in` (seconds, default 24h, capped at 7 days), `default_group`, `default_tags`, `label`. Token is shown once in the response and never returned again.
- `GET /api/enrollment-tokens` — lists all non-expired tokens, but only returns the first 8 characters of each as a prefix. Designed so listing the page later doesn't leak active credentials.
- `DELETE /api/enrollment-tokens/{prefix}` — revoke by prefix (8+ chars). Refuses to act if the prefix matches multiple tokens.

Token consumption is atomic: `handle_enroll_register` deletes the token before creating the device. If two agents race with the same token, exactly one wins and the other gets HTTP 403. Default group/tags from the token apply at enrollment unless the agent explicitly provides its own.

Agent gets a new `enroll-token` action with `--server`, `--token`, `--name` flags. Token resolution chain:

1. `--token CLI_VALUE`
2. `$REMOTEPOWER_ENROLL_TOKEN` environment variable
3. `/etc/remotepower/enroll-token` file (must be mode 600, deleted after use)

The CLI-arg path leaks into `ps` output for the duration of enrollment. Env var doesn't. File path doesn't and self-cleans on success. Pick whichever fits your secret-distribution model.

Audit logging: token creation and revocation both logged with actor, label, and (for create) the default group/tags.

**Metric alerting (disk, memory, swap, CPU).** Three new webhook events: `metric_warning`, `metric_critical`, `metric_recovered`. Default thresholds:

| Metric | Warning | Critical |
|---|---|---|
| Disk usage (per mount) | 80% | 90% |
| Memory usage | 85% | 95% |
| Swap usage | 20% | 50% |
| CPU 1-min loadavg / cpu_count | 1.5× | 3.0× |

Hysteresis: a metric must drop `METRIC_RECOVERY_BUFFER` (5) percentage points below the warn threshold before `metric_recovered` fires. Without this, a metric oscillating around 80% would generate webhook spam.

State stored in `dev['metric_state']` keyed by `kind:target` (e.g. `disk:/var`, `memory:`). Transitions fire webhooks on every up- or down-shift between `ok` / `warning` / `critical`. Orphan mount states (a mount disappears between heartbeats) are cleaned up automatically.

**Per-device + per-mount overrides.** New endpoint `GET|PATCH|DELETE /api/devices/{id}/metric-thresholds`:

- GET returns `{overrides, effective, defaults, recovery_buffer_percent}` so the dashboard can show effective values without resolving them itself.
- PATCH accepts any subset of `disk_warn_percent`, `disk_crit_percent`, `mem_warn_percent`, `mem_crit_percent`, `swap_warn_percent`, `swap_crit_percent`, `cpu_warn_load_ratio`, `cpu_crit_load_ratio`, plus `disk_per_mount` (a dict keyed by mount path → `{warn, crit}`). Validates `warn < crit` for every kind. Out-of-range values rejected with 400 rather than silently clamped.
- DELETE clears all overrides, reverting to defaults.
- PATCH also clears `metric_state` so the next heartbeat re-evaluates under the new thresholds (otherwise a metric currently in `warning` state would silently stay there even if you raised the threshold).

**Agent metric collection extended.** `get_metrics()` now reports per-mount disk usage (skipping tmpfs/squashfs/overlay/snap/etc.), swap percent, 1-minute load average, and CPU count. Backwards-compatible — older agents without these fields still work, and root-disk alerting falls back to legacy `disk_percent` if `mounts` isn't reported. Per-mount alerting needs the agent updated to v1.11.10+.

### Architectural notes

The web terminal feature (#3 in your request) is **not in this release**. RemotePower's CGI architecture can't do persistent WebSocket connections cleanly — fcgiwrap is request-response only. The recommended path is a separate companion daemon (`remotepower-webterm`, ~300 lines, systemd unit, listens on 127.0.0.1:8765, nginx proxies `/api/webterm/`). Same security model you specified — admin password re-prompt, user types SSH user/password fresh each session, direct SSH connection, session recording. Deferred to v1.11.11 to land properly rather than rushing it.

### Tests

**492 passing** (444 from v1.11.9 + 48 new in `test_v11110.py`):

API enrollment (16 tests):
- Token creation with default and custom expiry, TTL clamping (60s min, 7-day max).
- List endpoint never returns full token values, only 8-char prefixes.
- Expired tokens auto-purged from listing.
- Revoke by prefix (success, 404 on unknown, 400 on too-short prefix).
- Token consumed atomically — second use returns 403.
- Default group/tags from token applied at enrollment.
- PIN path still works (backward compatibility).

Metric alerting (28 tests):
- Threshold resolution: defaults, per-device overrides, per-mount overrides.
- Classification: ok / warning / critical at each boundary.
- Recovery buffer enforced (must drop 5 below warn).
- No webhook fire when state doesn't change between heartbeats.
- State transitions fire correct event (warn / crit / recovered).
- Per-mount disk states isolated per path.
- Orphan mount cleanup when mount disappears.
- CPU load ratio uses cpu_count correctly.
- Endpoint validation: warn < crit, ranges, unknown device 404, admin-only.
- PATCH clears metric_state for re-evaluation.

Webhook event registry (4 tests): the three new events are registered, message generation works for disk/cpu/recovered, priority ordering correct.

### Compatibility

Drop-in upgrade. Existing devices keep working — metric alerting is additive (defaults apply when no overrides are set). Pre-v1.11.10 agents continue to report only the legacy `cpu_percent` / `mem_percent` / `disk_percent` (root-only) fields; root-disk and memory alerts work, but per-mount disk and swap and CPU loadavg alerts need the agent updated. Push agent self-updates via the toolbar Update button or per-device "Agent update" menu item to get the new metric collection.

### Known limitations

- **No global-default override.** `process_metric_thresholds` resolves: per-mount disk → per-device → built-in defaults. There's no "fleet-wide override" tier between per-device and built-in. If you want all your servers to alert at 70% disk instead of 80%, you currently set the override on each device individually. Could add a `config['metric_thresholds']` global tier in v1.11.11 if it's actually annoying — the underlying resolver is structured to make that a one-line change.
- **CPU alerting is loadavg-based, not utilisation.** The choice was "what does `uptime` show you" rather than "what does `top` show you." Loadavg captures runqueue depth + I/O wait, which is usually what's actually worth alerting on. If you want %cpu-utilisation thresholds instead, file a request — easy to add as a separate kind without changing the existing one.
- **Web terminal not in this release.** See above. v1.11.11 target.

---

## v1.11.9 - 2026-05-06

### Bug fixes

**Minimal table extended past the right edge of the page.** Visible as the table being a few pixels wider than the stats row and section headers above it. Reported with screenshot showing the table's right edge sitting outside the column the rest of the page content occupied.

The cause: I set `width: 100%` on the table but didn't set `table-layout: fixed`. CSS tables default to `table-layout: auto`, where the browser sizes columns based on the longest content in each. The `max-width: 200px` I'd put on `<td>` cells was a hint that auto-layout silently ignored — long content like "Debian GNU/Linux 12 (bookworm)" pushed the OS column wider than I'd budgeted for, and the table grew past the container's content width.

Fix: added `table-layout: fixed` to `.devices-minimal-table`, set explicit widths on every column header except OS (which stays auto and gets the remaining space), and dropped the now-redundant `max-width: 200px` on `<td>` cells. With fixed layout, columns are sized strictly by header widths and any overflowing cell content gets clipped with the existing ellipsis rule.

Total of fixed widths comes to ~900px (Status 90 + Name 190 + Hostname 160 + Group 100 + IP 130 + Version 90 + Last seen 100 + Actions 50), which leaves ~152px for OS in a 1052px content area (the standard `max-width: 1100px` container with 24px padding on each side). On narrower viewports the responsive `@media` rules drop low-priority columns before things get cramped.

### Tests

Test suite unchanged at **444 passing** — no Python code changed. The fix is CSS-only.

### Compatibility

Drop-in upgrade. No new dependencies, no schema changes, no agent update needed. Refresh the dashboard after deploying. Affects only the Devices page in minimal density mode; cards, compact, and spacious modes are untouched.

---

## v1.11.8 - 2026-05-06

### Bug fixes

**Monitor checks only ran when the dashboard was open.** Critical bug that's been there since the monitor feature was introduced. The `monitor_interval` config setting (default 300s) was honored by the UI but not by the server — the dashboard refetched `/api/monitor` on a timer, and `/api/monitor` ran the checks synchronously and returned the result. So the actual ping/tcp/http probes only happened when somebody had the page open. Close the tab, walk away for 4 hours, the next page-load showed a 4-hour gap in the history with no checks in between.

The webhook implication is more serious. `monitor_down` and `monitor_up` events fire from inside the same code path. So if a service went down at 14:00 and recovered at 16:00, and nobody had the dashboard open during that window, **neither webhook fired**. The downtime was invisible to anyone relying on alerts.

Symptoms in your case:
```
6.5.2026, 14.50.27  ↑ up  200
6.5.2026, 14.50.13  ↑ up  200
4.5.2026, 20.53.56  ↑ up  200      ← gap of ~18 hours
4.5.2026, 18.40.26  ↑ up  200      ← gap of ~2 hours
```

The gaps are exactly when nobody had the Monitor page loaded.

Fix: extracted the actual check logic into `_execute_monitor_checks(monitors)` and added a periodic runner `run_monitors_if_due()` that's called from `main()` on every CGI request. The periodic runner is gated by `monitor_interval` (clamped to a 60s minimum to prevent CGI-flood disasters). Most CGI hits do nothing — when the gate expires, the same check logic runs and fires the same webhooks as before.

In practice this means monitors run roughly every `monitor_interval` seconds as long as **anything** hits the server. With agents heartbeating every 60s, the trigger frequency is at least once a minute, so monitors will run on schedule. If all agents are offline AND no users are browsing, monitors won't run — but in that scenario you have bigger problems anyway (a `device_offline` webhook will fire from the next-due agent, which will trigger the dispatcher, which will trigger the monitor sweep).

If you've been getting "monitor history shows checks at random times only" — that's why. From v1.11.8 onwards, history fills in regularly.

**Service monitoring was always real-time and is unaffected.** Service state changes ride along in every agent heartbeat (the agent reports unit states every poll), so `service_down` and `service_up` webhooks always fired correctly. No bug here. Mentioning it because the question naturally comes up alongside the monitor bug.

**Dropdown menu in minimal mode was clipped by the table.** v1.11.7 introduced the table-based minimal layout with `overflow: hidden` on the wrap to keep rounded corners working. That overflow rule clipped the ⋯ dropdown menu when it tried to pop out of cells near the bottom or right edge of the table. Reported with screenshot showing the menu cut off mid-item.

Fix: replaced `overflow: hidden` with a per-corner `border-radius` on the first/last `<th>` and `<td>` so the rounded corners survive without an enclosing clip. Then added z-index hoisting on the row `:has()` an open dropdown so the menu sits above all sibling rows. Repositioned the dropdown to anchor right-aligned (it was sometimes pushing off the right edge of the page on narrow viewports).

Tested in Chrome, Safari, Firefox 121+. The `:has()` selector is required for the row-hoist; older browsers fall back to per-cell z-index, which works for everything except possibly the very-bottom row. If you're on Firefox <121 and see the bottom-row menu still clipping, update Firefox.

### Refactor

`handle_monitor_run()` is now a thin wrapper around `_execute_monitor_checks()` + `_persist_monitor_results()`. Both helpers are also called from `run_monitors_if_due()`. No behaviour change for the user-triggered path: pressing Refresh on the Monitor page still runs all checks synchronously and returns them, and side-effect-updates the timestamp so the next periodic sweep doesn't immediately re-check what you just saw.

### Tests

**444 passing** (433 from v1.11.7 + 11 new in `test_v1118.py`):
- Gate logic: empty config no-op, first-call runs, within-interval skips, past-interval runs, timestamp gets updated, back-to-back calls only run once, sub-60s interval clamped at 60.
- Webhook firing: first failure fires `monitor_down`, recovery fires `monitor_up`, persistent state doesn't double-fire.
- User-triggered path still works (regression check).

### Compatibility

Drop-in upgrade. Existing `config.json` keeps working — the new `last_monitor_run` field is created lazily on first run. Existing `monitor_notified` state is preserved. Refresh the dashboard after deploying.

### Known limitations

- **Periodic checks are still gated on CGI requests reaching the server.** A truly idle server (no agents heartbeating, no users browsing) won't run monitors. In practice every install has at least one agent doing 60s heartbeats so this is academic, but if you point this at a server with zero agents and just monitors, you'd want a real cron job. Future v1.12 work could add an out-of-band runner via systemd timer.
- **The `:has()` CSS selector covers the dropdown z-index hoist.** Chrome 105+, Safari 15.4+, Firefox 121+ all support it. Older browsers fall back to per-cell z-index which works for most rows but might clip the very-bottom menu. Modern browser baseline is fine.

---

## v1.11.7 - 2026-05-04

### Bug fixes

**Update history was always empty.** This was a critical agent bug that shipped in v1.10.0 and went unnoticed until somebody actually tried to use the per-device "Update history" panel after running an upgrade.

The flow was supposed to be:
1. Dashboard pushes `exec:apt-get -y upgrade ...` to the device.
2. Server's heartbeat response includes `command: <the script>`.
3. Agent receives the response, runs the script (~30s for `apt-get update && apt-get -y upgrade && ...`).
4. Agent puts the result in the next heartbeat → server detects it's a package upgrade → archives to `update_logs.json` → "Update history" shows it.

Step 4 is what was broken. Look at `client/remotepower-agent` line 1037–1040 (v1.11.6):

```python
if cmd:
    log.info(f"Received command: {cmd}")
    result = execute_command(cmd)
    if result is not None:
        payload['cmd_output'] = result      # <- bug
    payload['executed_command'] = cmd       # <- same bug
```

`payload` had already been POSTed at line 1020. Assigning to it after the POST is a no-op — the next loop iteration resets `payload` at line 959 and the result is lost. The agent journal showed `Command output (rc=0): ...` because `execute_command()` logs locally; `update_logs.json` got nothing because the data never crossed the network.

Fix: send a dedicated minimal follow-up heartbeat right after the command finishes. Carries just `device_id`, `token`, `ip`, `os`, `version`, `cmd_output`, `executed_command` — no sysinfo or journal, those are already on the server from the first heartbeat in this iteration. If the follow-up POST itself fails (network blip, server restart at exactly the wrong moment), the cmd_output gets stashed to `/var/lib/remotepower-pending-cmd.json` (or `/tmp/` if `/var/lib` isn't writable) and picked up by the next successful heartbeat.

If you've been pressing "Upgrade packages" since v1.10.0 and seeing nothing in Update history: the upgrades did run, the data just never came back. From v1.11.7 onwards everything is captured correctly.

The `executed_command` webhook (`command_executed` event) had the same bug — same fix.

### New features

**Per-device "Upgrade packages" in the dropdown menu.** Previously you had to either (a) tick the device's checkbox and use the toolbar batch-action button, or (b) click into the device modal. Both worked but were a step out of the way for what's a common single-device action.

Now there's a direct "Upgrade packages" item in the ⋯ menu on every device, sitting between "Agent update" and "Update history". Same flow as the batch path under the hood — calls `POST /api/upgrade-device` with one device ID. Confirmation dialog explains the `~30–120s` typical wait and where to find the output.

**Minimal density rebuilt as a real `<table>`.** v1.11.6's minimal mode laid out each device as a flex row, which couldn't keep columns aligned across rows — different content widths in OS / IP / Version meant "Online" wasn't under "Online" between rows. Reported by users with multi-line metadata.

Replaced with an actual HTML `<table>`. Each device is one `<tr>` with the same column structure. Columns: Status / Name / Hostname / Group / OS / IP / Version / Last seen / Actions. Sortable by clicking any column header (same UX as the Services / CVEs / Containers / etc. tables — first click ascending, second descending, third clears, shift+click for secondary sort). Rows alternate-tinted on hover. Offline rows are dimmed.

Responsive breakpoints drop columns rather than letting them overflow:
- ≤ 1280px → drops Hostname (Name carries enough)
- ≤ 1080px → drops Version (covered by the per-row patch badge)
- ≤ 920px → drops Group
- ≤ 760px → drops IP
- ≤ 620px → drops OS — at this point the table is only Status / Name / Last seen / Actions

The dropdown ⋯ menu is identical to the cards path — same handlers, same items, same `dropdown-${id}` element id, so `toggleDropdown()` works without modification. The whole behaviour is preserved; just the layout changed.

### Schema additions

- New stash file `/var/lib/remotepower-pending-cmd.json` (or `/tmp/remotepower-pending-cmd.json` for non-root deploys). Holds one cmd_output payload between agent restarts/network failures. Cleared on successful follow-up POST. Schema: `{cmd_output: {...}, executed_command: str, stashed_at: int}`. Permissions: 600 by default, root-only on standard deploys.

- Server-side: no schema changes. The follow-up heartbeat is a regular heartbeat with a subset of fields populated. `update_logs.json` schema unchanged.

### Tests

**433 passing** (425 from v1.11.6 + 8 new in `test_v1117.py`):
- Minimal follow-up payload (`device_id` + `token` + `cmd_output` only) is accepted and stored.
- Heartbeat without cmd_output still works (no regression).
- apt upgrade command lands in `update_logs.json` correctly.
- Non-upgrade command (e.g. `ls /tmp`) lands in `cmd_output.json` but NOT `update_logs.json`.
- `GET /api/devices/{id}/update-logs` returns the archived entry end-to-end.
- Three sequential upgrades all recorded in chronological order.
- Overflow at `MAX_UPDATE_LOGS_PER_DEVICE` evicts the oldest, keeps the most recent.

### Compatibility

Drop-in upgrade. The server is unchanged for all existing flows — it doesn't care whether cmd_output arrives in the same heartbeat as a sysinfo dump or in a dedicated follow-up. So:

- v1.11.7 server + v1.10.0–v1.11.6 agents: still broken (the bug is in the agent), update history still empty. Agent must self-update to v1.11.7.
- v1.11.7 agent + v1.11.0+ server: works correctly. The server happily accepts the follow-up heartbeat.
- v1.11.7 agent + pre-v1.11.0 server: works for cmd_output in general but won't archive to update_logs.json (that file was added in v1.10.0). Out of scope — anyone running v1.11.7 agents will have a recent server.

Refresh the dashboard after the agent self-updates — the next upgrade you trigger will populate Update history within ~60s.

### Known limitations

- **The agent does NOT retroactively recover lost upgrade history.** If you ran an upgrade on v1.10.0–v1.11.6 and the output was dropped, that data is gone forever. The journal on the device still has it (`journalctl -u remotepower-agent | grep "Command output"`), but there's no way to reconstruct an entry from there into `update_logs.json` retroactively. From v1.11.7 onwards, new upgrades are captured.
- **The stash file isn't automatically pruned.** If a stash file gets written and the agent never gets the chance to retry (e.g. you decommission the device with a pending stash), `/var/lib/remotepower-pending-cmd.json` will sit there forever. It's small (16 KB max for an upgrade output payload) and root-readable, so this is mostly cosmetic. The next upgrade overwrites it.

---

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

## v1.10.0 - 2026-04-29

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

## v1.9.0 - 2026-04-27

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

## v1.8.6 - 2026-04-26

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

## v1.8.5 - 2026-04-26

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

## v1.8.4 - 2026-04-25

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

## v1.8.3 - 2026-04-25

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

## v1.8.2 - 2026-04-24

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

## v1.8.1 - 2026-04-24

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

## v1.8.0 - 2026-04-23

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

## v1.7.0 - 2026-04-23

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

## v1.6.3 - 2026-04-22

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

## v1.6.2 - 2026-04-22

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

## v1.6.1 - 2026-04-22

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

## v1.2.0 - 2026-04-16

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

