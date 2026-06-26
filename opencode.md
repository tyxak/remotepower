# RemotePower — project notes for Claude Code

## Box overflow rule — cap every panel at ~15 lines, then scroll

Every UI box/card/panel that renders a variable number of rows must cap
its height and scroll internally instead of growing unbounded. Use the
shared utilities (defined in `styles.css` near `.audit-scroll`):

- `<table>` cards → wrap in `<div class="scrollable-table-wrap audit-scroll">`
  (sticky header + styled scrollbar, ~360px cap). This is the standard for
  drawer tables (ports, firewall, mounts, containers, SMART, top processes).
- Non-table lists / chip rows → `.scroll-cap` (340px) or `.scroll-cap-sm`
  (132px, for chip rows like failed-units / mount-issues).

When adding any new list/table, add the cap at build time — uncapped boxes
have shipped repeatedly and been patched in follow-ups.

## Typography — one body size, one header size

Canonical scale (CSS literals in `styles.css`; there are no `--fs-*` vars):
**28px** page title (`.page-title`), **16px** section heading
(`.section-title`, `.empty-title`), **14px** body/prose/inputs/buttons,
**13px** dense table-cell/list text (`td`), **12px** hints/captions,
**11px** badges/eyebrows/meta-labels, **10px** tiny badges (deliberate).
Don't introduce new body sizes or `.5px` values — fold onto the scale.
Inputs stay **16px** only where an iOS-zoom guard is intentional.

## CSP is fully migrated — keep it that way

Production serves `script-src 'self'; style-src 'self'` with **no**
`unsafe-inline` (verified live). `index.html` has zero inline `on*=`
handlers / `style=` attrs / inline `<script>`. NEVER reintroduce an inline
event handler or inline style attribute (in static HTML *or* in app.js
`innerHTML` strings) — it silently dies under CSP. Wire events via
`data-action` / `data-home-act` dispatch and set styles with `.style.x`
or a class, not a string `style="…"`. `/api/csp-report` logs violations.

## Docs housekeeping — keep last 5 versions

`docs/vX.Y.Z.md`: keep only the **5 most recent**; delete older on each
bump. `docs/security-review-*.md`: keep the **last ~3**. The in-app
"What's new" cards (`index.html`) also cap at the last 5 versions, with an
"Older releases → CHANGELOG.md"
pointer. `CHANGELOG.md` is the *complete* history and keeps all entries
(its old `See docs/vX.md` pointers may dangle — that's fine). After
deleting version/review docs, grep the repo for live links to them
(README, docs/README.md, features.md, index.html) and
repoint — `docs/security.md` is the durable target for review links.

## Full-viewport overlays MUST live at body level, not inside `.container`

`.container` (the page-content wrapper) is `position:relative; z-index:1`
(it sits above the decorative `body::before/::after` background layers).
That `z-index:1` is a **stacking-context trap**: a `position:fixed`
overlay nested inside it has its own `z-index` sealed *inside* `.container`,
so it can never rise above the fixed `.sidebar` (`z-index:90`, a direct
child of `#app`) — the real comparison is `.container`(z1) vs `.sidebar`
(z90), and the sidebar wins. This shipped as the device-drawer "splits
across the screen" bug (v4.10.0): the drawer was the lone overlay inside
`.container`; below ~820px its panel went full-width, overlapped the
0–240px sidebar strip, and the sidebar painted through it. All 90
`.modal-overlay` nodes already live at **body level** (after
`</div><!-- /app -->`). **Any new fixed full-screen overlay/drawer/modal
must be a direct child of `<body>` (with the modals), never inside
`.container`/`<main>`.** Guardrail: `test_v430_e2e.test_drawer_overlays_
sidebar_at_narrow_width` (Playwright hit-tests the sidebar strip over the
open drawer at 768px).

## Visual: no emoji in UI, use Lucide-style SVG

Never reach for an emoji as an icon. The left sidebar uses inline
SVG (Lucide-style strokes, `stroke="currentColor"`,
`viewBox="0 0 24 24"`) — match that style everywhere:

- Device drawer action buttons
- Settings tabs / section headers
- Table action buttons (Edit, Delete, Inspect, …)
- README badges / headers — plain Markdown or shields.io only

Bad (do not ship):

```html
<button>💻 Run command</button>
<button>🧹 Uninstall agent</button>
```

Good:

```html
<button>
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="2" width="14" height="14"
       stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 3h7v7H3z"/>
  </svg>
  Run command
</button>
```

CLI / agent log output (terminal-only) is allowed plain ASCII without
icons at all. The rule applies to anything that renders in the
browser or in the README.

Reference: https://lucide.dev/icons/

## Sortable tables — ALWAYS wire on new tables

Every new `<table>` added to the UI must wire up sort buttons. The
pattern is:

```js
// In the renderer that builds the tbody:
tableCtl.wireSortOnly('<thead-id>', '<prefs-name>', <rerender-fn>);
const sorted = tableCtl.sortRows('<prefs-name>', rows, r => ({
  col1: r.col1Value,
  col2: r.col2Value,
  // …
}));
```

Plus every sortable `<th>` MUST carry a `data-col="<key>"` attribute
matching the keys returned by the `sortRows` getColumns function.

**Eager wire-up:** call `tableCtl.wireSortOnly(...)` at the *top* of
the loader, before the data fetch / empty-state branches — otherwise
users see column headers with no ↕ indicator until data arrives.

**Why this lives here:** sort regressions shipped multiple times
(Custom Scripts results, Log Alert global rules, Processes) and had
to be patched in follow-up commits. Catch them in code review.

## Marketing site — update it during every test → production release

The public landing page at **https://remotepower.tvipper.com/** lives in
`site/` (gitignored — `index.html` + `assets/`, single self-contained file
with inline CSS and a CSS-only `:target` lightbox). It is **not** the in-app
docs; it's the marketing page. Deploy it by copying `site/` to that host's
web root.

**When promoting a release from test → production, also refresh `site/`** as
part of the same update:

1. Bump the version badge (hero `.badges`) and the footer version to vX.Y.Z.
2. Rewrite the **"New in vX.Y.Z"** section (`#new`) for the new release, and
   fold any genuinely new *permanent* features into the feature-card grid.
3. Refresh screenshots: copy from `docs/screenshots/` into `site/assets/`
   with the lowercase names the page uses (`Dash.png`→`dash.png`,
   `Index.png`→`index.png`, `Monitoring.png`→`monitoring.png`,
   `CVE.png`→`cve.png`, `CMDB.png`→`cmdb.png`, `AI.png`→`ai.png`,
   `Terminal.png`→`terminal.png`, plus any new ones). Add a matching
   `.shot` + `.lightbox` pair per new image.
4. **NEVER change the logo / brand art.** `assets/logo.png`,
   `assets/logo-primary.png`, `assets/favicon.ico` must stay byte-identical —
   if you ever recreate `site/` from scratch, fetch those three from the live
   site (`https://remotepower.tvipper.com/assets/<f>`), don't regenerate them.
5. Verify: every `assets/...` referenced in `index.html` exists, no stale
   version strings remain, and `git status` does **not** list `site/`
   (it's gitignored). Then deploy the site to its host (below).

**Deploying `site/` — automated, two commands** (host `tviweb01` = `10.0.0.4`,
web root `/var/www/remote`, served at remotepower.tvipper.com):

```
rsync -az --delete \
  --exclude='assets/logo.png' --exclude='assets/logo-primary.png' --exclude='assets/favicon.ico' \
  -e "ssh -i ~/.ssh/tvipper" site/ jmo@10.0.0.4:/home/jmo/site-deploy/
ssh -i ~/.ssh/tvipper jmo@10.0.0.4 'sudo -n /usr/local/sbin/deploy-remote-site.sh'
```

- Auth: SSH key `~/.ssh/tvipper` is authorized for `jmo@10.0.0.4`.
- The `rsync` **excludes the logo/favicon files**, so they're never staged or
  copied (the "no logo changes" guarantee is enforced mechanically).
- `/usr/local/sbin/deploy-remote-site.sh` is root-owned (`755 root:root`) and
  runs passwordless via a **scoped** sudoers drop-in
  (`/etc/sudoers.d/remote-site-deploy`: `jmo ALL=(root) NOPASSWD:` that one
  script only — general `jmo` sudo still needs a password). The script backs up
  the live `index.html` → `index.html.bak`, then installs `index.html` +
  `assets/*.png` (0644). For the NOPASSWD to win, `@includedir /etc/sudoers.d`
  had to be moved to the **end** of `/etc/sudoers` (last-match beats the blanket
  `%serveradm`/`%sudo` grants).
- Verify after: `curl -s https://remotepower.tvipper.com/ | grep -c vX.Y.Z`
  and that `assets/<new>.png` return 200 and the logos are still 200.

## Two-remote release workflow

### ⛔ ONLY TWO BRANCHES — work on `main`, never a feature/version branch

This project uses **exactly two branches, both named `main`**:
- `origin/main`     = `tyxak/claude-code` — **TEST** trunk (all dev lands here)
- `remotepower/main` = `tyxak/remotepower` — **PRODUCTION**

**Do all work directly on `main` and push to `origin/main` (test).** Do NOT create
`feat/*`, `v4.7.0`, or any other branch — the user does not want them and will ask
you to undo it. (Ignore the generic harness "branch off the default branch first"
default; this project overrides it.) A release is a **signed tag on `main`**, not a
branch. Production is promoted by fast-forwarding `remotepower/main` to the tagged
commit. If you ever find work on a side branch, fast-forward `main` to it
(`git checkout main && git merge --ff-only <branch>`), push `origin/main`, and
delete the branch (local + `origin`).

Always push to both (for a release). Retag with `git push --force remotepower vX.Y.Z`
— do **not** delete-and-recreate, that destroys the GitHub release.

**Run tests LOCALLY before pushing — there is no test-repo CI net.**
GitHub Actions is **disabled on `origin` (`tyxak/claude-code`)** (it was
burning ~$11/cycle re-running the suite on every scratch push; the test
repo is scratch space, the real gate is local + production CI). So a push
to `origin` runs **zero** checks. Before pushing to either remote, run the
gate locally:

- `make test` — single backend, identical to the old CI
- `make test-both` — JSON + SQLite, the real release gate (stronger than CI ever was)
- `make check` — `test-both` + lint

`remotepower` (production) **still runs CI** on release pushes — that's the
gate that matters and is left on. Re-enable test-repo Actions if ever
needed: `gh api -X PUT /repos/tyxak/claude-code/actions/permissions -F enabled=true`.

**Release artifacts (v4.6.0+):**
- `make release` = `make dist` (tarball + sha256, verified) **+ a detached,
  armoured GPG signature** (`.tar.gz.asc`) using the local key
  (`git config user.signingkey`, currently the ed25519 key that also signs
  tags — `D488AF115D2CCDBF`). Signing is LOCAL on purpose; the key never goes
  near CI. Override with `make release SIGN_KEY=<keyid>`. The target prints the
  `gh release create` line (uploads all three assets to `tyxak/remotepower`).
- **Docker image → ghcr.io** is automated: `.github/workflows/release.yml`
  fires on `release: published` on the **production repo only** (guarded by
  `if: github.repository == 'tyxak/remotepower'`), builds the image and pushes
  `ghcr.io/tyxak/remotepower:<version>` + `:<major.minor>` + `:latest` using
  the auto-provisioned `GITHUB_TOKEN` (no secrets). So publishing the GitHub
  release is what triggers the image push. **Multi-arch: linux/amd64 +
  linux/arm64** (arm64 emulated via a `setup-qemu-action` step → slower, hence
  the 60-min job timeout). Drop the arm64 leg from `platforms:` if build time
  hurts. The workflow file sits dormant on `origin` (Actions disabled there).
- **FIRST PUBLISH ONLY — flip the ghcr package to public.** GitHub creates a new
  container package as **private** by default, so the very first release push
  makes `ghcr.io/tyxak/remotepower` private → `docker pull` 401s for everyone
  without a token. After the first workflow run, make it public ONCE:
  Repo/org → **Packages** → `remotepower` → *Package settings* → *Change
  visibility* → **Public**, or:
  `gh api -X PATCH /user/packages/container/remotepower/visibility -f visibility=public`
  (use `/orgs/tyxak/packages/...` if the package lands under the org). Subsequent
  releases just push new tags — visibility sticks.
- **AUR packages** (`packaging/aur/{remotepower-agent,remotepower-server}/`),
  BOTH PUBLISHED + maintained by `tyxak` (auth via `~/.ssh/id_ed25519`, registered
  in the AUR account; host keys pinned in `~/.ssh/known_hosts`). Both `arch=any`,
  built from the **signed** release tarball, PGP-verified
  (`validpgpkeys=E7B5AD456728B8462A8B54BFD488AF115D2CCDBF`).
  - `remotepower-agent` — turnkey (one script + unit). `update.sh <ver>` exists.
  - `remotepower-server` — installs code→`/var/www/remotepower`, deps (all official
    repo; webauthn/pysaml2 are AUR optdepends), nginx snippet→`/etc/nginx/snippets/`,
    sample vhost + SCGI unit→`/usr/share/doc/`, tmpfiles data dir (http), `/usr/bin/
    remotepower-passwd` symlink. NOT turnkey (user wires nginx + admin). NB: the
    repo `make`/snippet hardcode `/var/www/remotepower`, so the pkg installs there
    (not `/usr/share/webapps`) to keep the snippet working verbatim.
  - Per-release update (after the GH release exists): for each, `./update.sh <ver>`
    (agent has one; for server bump pkgver+sha256 by hand or copy the pattern) →
    `makepkg -f --nodeps` (deps not installed on dev box → use `--nodeps`; arch=any
    file-copy needs none) → copy PKGBUILD/.SRCINFO/.install into the AUR clone
    (`ssh://aur@aur.archlinux.org/<pkg>.git`, branch `master`) → push. `src/`/`pkg/`/
    built pkgs gitignored. Publishing needs the aur.archlinux.org account+SSH key.
- Prod promotion order: `make check` → **flip the `CHANGELOG.md` header
  `## vX.Y.Z — "…" — unreleased (test)` → `— <release date>`** (also fix any PRIOR
  entry still wrongly saying "unreleased (test)" — this step was MISSED on both
  v4.9.0 and v5.0.0, so the published CHANGELOG showed a shipped release as
  "unreleased"; a superseded/test-only version like v4.10.0 becomes
  "folded into vX.Y.Z (no standalone release)") → signed tag → push tag to
  `remotepower` → `make release` → `gh release create v… <tarball> <sha256> <asc>
  --repo tyxak/remotepower` → (workflow pushes the image) → **(first release: set
  the ghcr package public, see above)** → AUR `./update.sh <ver>` + push → site
  rsync → **GitHub wiki refresh** → **CodeQL alert triage** (last two below).
  (The CHANGELOG header flip ideally happens BEFORE the signed tag so the tagged
  tree carries the right date; if missed, fix it in a follow-up commit + push both
  remotes, as was done for v5.0.0 @a073827.)
- **GitHub wiki refresh (7th doc surface — DO THIS EVERY RELEASE).** The wiki at
  `tyxak/remotepower/wiki` is GENERATED from `docs/`, not auto-synced. Refresh it:
  `git clone https://github.com/tyxak/remotepower.wiki.git /tmp/rp-wiki` →
  `python3 tools/gen-wiki.py /tmp/rp-wiki <ver>` (copies docs/*.md with link
  rewriting, excludes the internal set, bumps Home/_Sidebar to the new version) →
  in `/tmp/rp-wiki`: `git add -A && git commit --no-gpg-sign -m "docs: sync wiki
  to v<ver>"` then push with the token:
  `git push "https://x-access-token:$(gh auth token)@github.com/tyxak/remotepower.wiki.git" master`.
  Verify pages 200 (`/wiki/dmarc`, `/wiki/v<ver>`). GOTCHAS: the https wiki clone
  has NO credential helper → push via the `x-access-token` URL; global
  `commit.gpgsign=true` breaks the wiki commit → `--no-gpg-sign`. The codename in
  `gen-wiki.py`'s Home "Current release" line is hardcoded — update it per release.
- **CodeQL alert triage.** The release push re-runs CodeQL on `remotepower`; new
  alerts appear at `/security/code-scanning`. `py/clear-text-storage-sensitive-
  data` on `save()` (0600 file, hashed passwords, by-design secret persistence)
  and on the scrubbed diagnostics bundle are the recurring FALSE-POSITIVE class —
  dismiss via `gh api -X PATCH /repos/tyxak/remotepower/code-scanning/alerts/<n>
  -f state=dismissed -f dismissed_reason="false positive"|"won't fix"
  -f dismissed_comment="…"` (reason values need SPACES; comment ≤280 chars), and
  log the triage in `docs/security-review-<ver>-internal.md`.

## Local SAST: run it BEFORE pushing, keep all three reporting ZERO (v5.0.1+)

The repo carries committed config so CodeQL/bandit/gitleaks scan **clean** and you
catch regressions before the prod CodeQL run. Re-run after ANY code change:
- **CodeQL** (the real gate): `tools/codeql-local.sh` runs the EXACT GitHub
  default suites (python+javascript); CLI cached in `.codeql-cache/` (gitignored,
  ~600MB first run). It honors `.github/codeql/codeql-config.yml` — `paths-ignore`
  (packaging/aur build copies that dupe every finding 2-3×, tests, .codeql-cache,
  site, design, docs) AND, since v5.0.1, the config's `query-filters` (the helper
  post-applies them; GitHub applies them at analyze). FP RULES filtered there (each
  triaged, none exploitable, XSS/injection/SSRF/auth STAY ACTIVE): py/clear-text-
  storage|logging (persists HASHED/encrypted secrets to 0600), py/insecure-protocol
  (tls_monitor probes legacy servers), py/weak-sensitive-data-hashing (HMAC chain +
  usedforsecurity=False fp), js/request-forgery (same-origin fetch under CSP). FIX
  js/xss genuinely, don't filter the rule — patterns CodeQL trusts: textContent/
  appendChild/`new Option`, a `/^[A-Za-z0-9_-]{1,64}$/` id guard at a boundary, or
  passing tainted values as console `%s` args not into the format string.
- **bandit**: `bandit -r server/cgi-bin client -b .bandit-baseline.json` → 0 new.
  Keep 0 HIGH (annotate genuinely by-design lines with `# nosec <ID>` + a reason —
  e.g. the agent root command channel B602, the 0o777-under-0700 scanner workdir
  B103). Regenerate the baseline only after triaging new Med/Low:
  `bandit -r server/cgi-bin client -f json -o .bandit-baseline.json`.
- **gitleaks**: `gitleaks detect -c .gitleaks.toml` (and `--no-git`) → "no leaks".
  `.gitleaks.toml` allowlists gitignored build artifacts + doc EXAMPLE tokens +
  the i18n.js SSH-key MARKER label + `key == '<name>'` config-key-name code.
- Install if missing: `pip install --break-system-packages bandit semgrep`.
- After triaging, write the public `docs/security-review-<ver>.md` (keep last ~3)
  recording the process + fixed findings + the FP-rule reasons — that doc IS the
  transparency. The bar: NO Crit/High/Med ships; nothing exploitable.

## Agent .py / extensionless sync

`client/remotepower-agent.py` and `client/remotepower-agent` must
stay byte-identical. After editing `.py`:

```
cp client/remotepower-agent.py client/remotepower-agent
```

A regression test (`test_agent_extensionless_matches_py`) enforces
this on every release.

**Containerized agent (v4.7.0):** the agent can run in a container to monitor its
Docker HOST (`Dockerfile.agent`, `docker/agent-entrypoint.sh`,
`docker/docker-compose.agent.yml`, image `ghcr.io/tyxak/remotepower-agent`). Any
NEW host-fact read in the agent MUST go through `host_path()` (identity natively;
maps to the bind-mounted host rootfs under `$HOST_ROOT` in a container) or it
reads the slim image, not the host. `_safe_read()` already wraps it; direct
`open()`/`Path()`/glob host reads need it added. Report clean paths with
`unhost_path()`. Self-update + lynis/oscap are disabled in-container (`IN_CONTAINER`).
NEVER mount docker.sock by default — even `:ro` it's effective host root.

## Release codenames (history → current)

- v4.0.0 "—", v4.1.0 "VisualMatters", v4.2.0 "5ecur1tyM4tter5", v4.3.0
  "ImprovementMatters", v4.4.0 "FortifyMatters", v4.4.1 "DocumentationMatters",
  v4.5.0 "TrustMatters", v4.6.0 "RepellantMatters" (Industrial "New UI").
- **v4.6.1** — stability+hardening patch (SCGI-worker CAP_NET_RAW + Postgres
  fork-safety, ReDoS, XSS, subtitle FOUC). **RELEASED TO PROD 2026-06-14.**
- **v4.7.0 = "IntegrationsMatters"** — reach-outward: **homelab software
  integrations** (26 read-only connectors → Alerts + dashboard, SSRF-guarded) +
  a **containerized agent** (run the agent in a container to monitor a Docker host).
- **v4.8.0 = "OnboardingMatters"** — turnkey onboarding (unified
  `install.sh` wizard, one-command Docker, served `/install` one-liner, baked
  quick-install agent, `install.sh agent push` SSH bootstrap, clean uninstall) +
  a **DMARC/SPF/DKIM monitor** (DNS posture + IMAP RUA report ingestion + mailbox
  monitor) + a11y + agent parity + a hardening/finalize sweep.
- **v4.9.0 = "ResolutionMatters"** (RELEASED TO PROD 2026-06-18) — an
  **Admin → DNS dashboard** (read/write records via provider APIs: Cloudflare/
  DigitalOcean/Hetzner/deSEC/Porkbun; reuses `acme_dns_credentials` + optional
  encrypted vault + import-from-agent), **live resolve/dig + propagation** panel,
  a **resolver health monitor** (latency/NXDOMAIN, `resolver_unhealthy`/`_recovered`
  events), an **alert-resolution timeline (MTTR)** on the Alerts page, + a
  whole-project finalize sweep. WEBHOOK_EVENTS now **72**. New modules:
  `dns_zones.py`, `dns_resolve.py`, `resolver_health.py`. Finalize-sweep bug fix:
  recover events (`integration_recovered`/`ip_blacklist_cleared`/`resolver_recovered`)
  now auto-resolve their alert — match keys (`integration_id`/`ip`/`target`) added
  to the `_record_alert` payload whitelist (they were dropped → alerts stuck open).
- **v4.10.0 = "PerimeterMatters"** (superseded by v5.0.0 on test, unsigned,
  NOT prod) — a fleet **Security → Firewall** page (view + edit nftables/iptables/
  ufw/firewalld rules and **fail2ban** jails; agent reports capped rule lists +
  fail2ban status; edits ride the audited `command`-perm queue, server-validated
  `_valid_fw_token`, quarantine-aware; new endpoints `/api/firewall`,
  `/api/fail2ban`, `…/firewall-rule`, `…/fail2ban-action`; modules `dns_zones`-style
  in `api.py` + agent `collect_fail2ban`/`_parse_*_rules`). Plus an **AI Insights
  hub** (20 new `SYSTEM_PROMPTS` keys + labels + the `AI_INSIGHTS` grid on the AI
  page), **3 new RAG sources** (`build_firewall_corpus`/`build_integrations_corpus`/
  `build_backups_corpus` in `rag_index.py`, wired in `_rag_build_corpus` + defaults
  + `_rag_source_files` + Settings UI), and a UI-polish + release-readiness finalize
  sweep. WEBHOOK_EVENTS unchanged at **72** (firewall/fail2ban edits fire audit rows
  + the existing `command_queued`, no new events). 4-audit sweep (security/backend/
  UI/docs) found the new code CLEAN (lock-nesting + recover-whitelist clean,
  injection guard holds); bandit baseline regenerated; gitleaks current-tree = all
  false positives. **2nd finalize sweep + features** folded in (still v4.10.0, no
  bump): a 4th RAG source (`dns_email`) + the RAG save-whitelist bug fix; security/
  perf hardening; **agent audit (read-only) mode** — touch `/etc/remotepower/
  audit-mode` (operator-owned, server can't clear) → the agent refuses every
  command at `execute_command`/`apply_host_config`/`check_for_update`, reports
  `audit_mode` in sysinfo (persisted via `safe_si`), `_queue_command` refuses to
  enqueue, device shows an AUDIT badge; enforced by all 3 agents (Linux + win/mac
  `handle_command`). Plus a searchable per-device SLA table, and **site/group/tag-
  scoped credentials** — a shared login defined once at a scope and inherited by
  member devices, reusing the per-device CMDB vault (AES-GCM, key from the
  `X-RP-Vault-Key` header, never stored), admin-only, audit-logged reveals
  (`SCOPED_VAULT_FILE`, `_scoped_cred_applies`, `/api/scoped-credentials*` +
  `/api/cmdb/<id>/inherited-credentials`; CMDB-page card via `app-cmdb.js`
  `loadScopedCreds`/`scopedCred*`). Plus a **6-feature batch** (all v4.10.0, on test):
  read-only **Auditor** role (`require_admin_or_auditor_auth`), **scope-delegated**
  cred reveal (`_caller_scope_covers_credential`), **agent_stopped/started** signal
  (agent SIGTERM in `main()` → `{agent_stopping}` → distinct event vs offline),
  **backup integrity verification** (agent `collect_backup_verify` restic/borg/tar
  `check`; `backup_verify_failed`/`_verified`), **per-site reports**
  (`_build_fleet_report(site_id)` + `/api/report/site/{id}`), and **health-gated
  rollouts** (opt-in canary auto-halt → `rollout_halted`, fired via a `pending` list
  AFTER the ROLLOUTS_FILE lock). **WEBHOOK_EVENTS now 76.** Per-release detail in
  memory [[project_v4100_perimeter]].
- **v5.0.0 = "CTRLMatters"** (current — ON TEST `origin/main`, unsigned, NOT prod;
  last prod = v4.9.0) — control-plane hardening + scale, built as roadmap T1–T6 in
  one batch then a 14-point finalize sweep. **T1** mutual-TLS agent auth
  (`_agent_mtls_ok`, per-device `mtls_fingerprint` pin), AES-256-GCM encrypted DR
  backups (`backup_crypto.py`, passphrase from `RP_BACKUP_PASSPHRASE` env only),
  two-person break-glass credential reveals, per-API-key rate limits. **T2** server
  disk watchdog, webhook DLQ + replay, runtime maintenance mode (`/api/maintenance-MODE`
  — NB `/api/maintenance` is maintenance WINDOWS), graceful long-poll SIGTERM, OSV
  circuit breaker. **T3** bulk device delete/tag, `exec:to=<n>:` per-command timeout
  (all 3 agents), agent/server version-compat, script-rollout rollback. **T4**
  cross-device OSV batching. **T5** polish (copy buttons, snooze, pending-cmd badge,
  self-test; #U8 timezone deferred). **T6** NOC **Status Board** (`/api/board`,
  loads on nav only) + industrial design pass. **WEBHOOK_EVENTS now 80.** Finalize
  sweep (2026-06-21): no Crit/High/Med (all SAST FP/by-design); fixed DLQ-retry
  attempts-counter + `get_json_body` null→{} coercion (`get_json_obj()`); hardened
  backup-decrypt KDF-iter bounds + mac agent dir 0700; NEW **`posture` RAG source**
  (`build_posture_corpus`, wired all 5 places + UI); docs counts→80 + v5 sections +
  `security-review-5.0.0.md`. Per-release detail in memory [[project_v500_ctrlmatters]].
  **2nd finalize sweep (2026-06-21, 6 audit agents + SAST + live pentest w/ admin
  token):** still v5.0.0, no bump, still test-only. No Crit/High/Med (bandit 2 Highs =
  by-design agent shell-exec + scanner 0777-under-0700-parent; semgrep XML/shell/sql =
  FP — DMARC parser already caps size + rejects DOCTYPE/ENTITY, all SQL parameterized;
  gitleaks current-tree all FP = public PGP fps + doc examples). Fixes: **P1 guaranteed
  500** — `handle_patch_report_device` used an unbound `security_updates` (NameError on
  every call; the other 3 patch-report handlers bound it, this one didn't); **H1 agent
  audit-mode 4th channel** — `run_custom_scripts` ran server-pushed bash as root with NO
  `_audit_mode()` guard (the other 3 channels had it) → guarded the function; **SSRF
  completion** — SNMP (`_device_snmp_target`, was the ONLY fleet outbound with zero IP
  classification), LDAP (`ldap_url` save-time preflight), Proxmox (runtime connect-time
  peer recheck via stdlib `_ssrf_opener` in proxmox_client) now all reject loopback/
  link-local/metadata; **agent host_path()** on 4 more reads (backup_status, web-access-
  logs, file_log, acme — containerized agent was reading the empty container fs);
  **security_updates binding** — distro security-flagged count now shows on Checks page
  (`_host_checks` patches row) + patch_alert payload (reused event, no WEBHOOK_EVENTS
  churn); **get_json_obj()** coercion on bulk-delete/bulk-tags/device-tags/maintenance-
  mode (live probe CONFIRMED a JSON-array body 500s the pre-fix prod); 4 tables wired
  sortable (reputation/dmarc-reports/dmarc-sources/scoped-creds); break-glass list +
  NOC board grid capped/scroll; perf (dbgScrub skips when debug off; backup_state one
  write/beat not two); i18n (Audit-Log subtitle Hindi shadow fix + 6 missing HTMLDICT
  subtitles). Tests: `tests/test_v500_sweep.py`. DEFERRED (documented, low-risk):
  fail2ban→event (would churn WEBHOOK_EVENTS 80→81+, flagship gap for NEXT cycle);
  AI-Insights `explain_tls` card; i18n C4 hardcoded-English renderer labels (~700-string
  known backlog); perf config-deepcopy-per-heartbeat + renderer keyed-diff (audit flagged
  risky). LANGS are en/zh/hi/es/ar (NOT fr/de — a sub-agent assumed wrong; verify).
- **v5.0.1 = "TemperMatters"** (current — ON TEST `origin/main`, unsigned, NOT prod;
  last prod = v5.0.0) — stability/polish release tempering v5.0.0, from a 5-audit
  finalize sweep + an edit-button sweep. **Backend-correctness sweep:** fixed FIVE more
  SQLite-blind `Path.exists()` regressions (same class as the v5.0.0 backup runaway) →
  `backend_exists()` on `HOST_CONFIG_CURRENT_DIR/{id}.json` reads (SSH-key drift audit on
  the heartbeat path, host-config "current state" drawer + fleet export, device-delete
  cleanup) and `PROXMOX_SNAPSHOT_CACHE` (stale-snapshot attention) — all were dead under
  the SQLite/Postgres backend (PROD IS POSTGRES, so broken live). **Quieter alerts:**
  `_record_alert` now COALESCES a repeat firing into the existing OPEN alert (same
  event+identity → bump `count`, refresh ts) instead of appending a dup — only when the
  alert is identifiable (device_id OR an identity field; anonymous events still append,
  so test_v410 monotonic-id with empty `{}` still passes; test_v320 list test switched to
  two distinct devices). Plus integration `notified`-purge guard (don't drop flap flags
  when `configured` is transiently empty during a restart). **agent_stopped/started OFF by
  default** via `CHANNEL_KIND_DEFAULTS['agentlifecycle']` (alerts+webhook+needs_attention
  off, recent_activity kept) — NB a SAVED `channel_routing` overrides the default, so PROD
  (which already has agentlifecycle alerts/webhook off but needs_attention TRUE) needs a
  one-time toggle to fully quiet. **Edit buttons:** sweep found most tables already have
  edit/rename; added the 2 real gaps — **API keys** (new `PATCH /api/apikeys/{id}` =
  `handle_apikeys_update`, edits name/role/expiry/rate, secret immutable; frontend
  edit-mode reuses the create modal via `_apiKeyEditId`) and **custom checks** (frontend
  only — backend `handle_custom_checks_save` already updates-by-id; `_ccEditId`). **Ops:**
  server unit gained `EnvironmentFile=-/etc/remotepower/api.env` so `RP_BACKUP_PASSPHRASE`
  survives redeploys (deploy overwrites the unit → inline `Environment=` was wiped); new
  turnkey `packaging/remotepower-server-update.sh` (git/pacman/apt auto-detect, scoped-sudo
  self-escalate) for the Settings→Install "Run update now" button. Tests: `test_v501.py`
  (strict version pins), `test_v500.py` loosened to `api.SERVER_VERSION`, `test_v501_
  features.py` (apikey update + SQLite-blind source guards), new coalescing/agentlifecycle
  tests in `test_v500_sweep.py`. `make test` green (4227). WEBHOOK_EVENTS unchanged at 80.
  Also done this cycle: About-page + README copy de-staled (Docker/SCGI/SQLite now
  mentioned, "vanilla JS" not "hand-written"), `docs/security.md` review pointers →5.0.0,
  RAG search-results table box-capped.
- **v5.1.0 = "UnityMatters"** (current — ON TEST `origin/main`, unsigned, NOT prod;
  last prod = v5.0.1) — security-signal + localisation release. **Flagship: fail2ban
  bans are now a first-class event** (`fail2ban_ban`) — previously audit-only, now wired
  through every registry (WEBHOOK_EVENTS **81**, `_ALERT_RULES` medium, CHANNEL_KINDS
  `fail2ban` kind → EVENT_KIND_MAP, `_alert_title`/`_webhook_title`/`_webhook_message`,
  app.js FLEET_EVENTS + `_homeActivityAttrs`→firewall page + `_homeNavAction` firewall
  case, test_v184 set). Edge-triggered in the heartbeat vs the PREVIOUS
  `dev['sysinfo']['fail2ban']` snapshot (NO new state file — like reboot_required); seeded
  silently on first sight; new bans capped `[:50]`/beat; buffered in `_fail2ban_pending`
  inside `_DeviceUpdate`, fired AFTER the lock (B2 class). Payload carries NO identity
  field → per-host **coalescing** (one open alert/host, count bumped) so a brute-force
  flood doesn't drown the inbox while each ban still hits webhook/SIEM. No recover event.
  **Arabic RTL**: `styles.css` gained a `[dir="rtl"]` layout-override block (was zero) —
  sidebar/nav/cards/tables/drawers mirror. **i18n**: +18 curated DICT keys (Firewall/
  Reputation/AI/Alerts/Checks, en/zh/hi/es/ar). **Perf cold-blob→ENTITY was ALREADY DONE
  in v5.0.0** (containers/cmds/update_logs/uptime/cmd_output/metrics already use
  `_entity_read_one`/`_entity_write_one` on the hot path) — the deferred-log note was
  STALE; remaining `backup_state.json` (keyed per-(device,path), backup-beats only, already
  load-once/save-once) consciously DEFERRED (risky shape migration, low win). `explain_tls`
  AI card also already shipped in v5.0.1 (another stale deferred note). Targeted test gate
  green on BOTH backends (full `make test-both` not run in the constrained env → prod CI is
  the gate); bandit 0-new + gitleaks clean. Test-window pins widened (v248 4800→5200, v250
  82000→84000, v260 78000→80000). New `test_v510.py` + `test_v510_features.py`; loosened
  `test_v501.py`→dynamic. `docs/security-review-5.1.0.md` (pruned 4.10.0, keep-3).
  **WHOLE-PROJECT FINALIZE SWEEP folded into v5.1.0 (2026-06-24, on test, no bump):**
  7 parallel dimension audits + live authenticated pentest of remote.tvipper.com +
  bandit/gitleaks. Live posture strong (full CSP no-unsafe-inline, HSTS preload,
  COOP/CORP, 401 unauth). **2 real findings FIXED:** (HIGH) webhook DLQ list echoed
  the secret-bearing top-level `url` (Slack/Discord token in path) → `_redact_url_to_host`
  to scheme://host; (MED) AI-provider HTTP had no connect-time peer-IP recheck → added
  `_ssrf_opener` in ai_provider.py mirroring proxmox_client (allow_loopback only when
  insecure_ssl). **Perf:** the attention / fleet-risk-health / nav-counts mtime caches
  used `.exists()/.stat()` on storage keys → DEAD under prod Postgres (recomputed full-
  fleet scan every poll) → swapped to `backend_exists()/backend_mtime()`; `_drift_policy_mode`
  → `_config_ro()`. **Agent:** backup-verify rate-gate read `_safe_read(CONF_DIR/…)`
  (host_path-mapped → read host /etc in a container, never its own writes) → `_safe_state_read`.
  **NEW EVENT av_infected (WEBHOOK_EVENTS 81→82):** ClamAV/rkhunter active infection was
  posture-card-only → now high-severity event, edge-triggered in `_ingest_av` (post-lock,
  rising infected-count), reuses existing `av_posture` CHANNEL_KIND (populated its empty
  event list — no new kind), no recover (sticky). Brittle FLEET_EVENTS windows bumped again
  (test_v223 4800→5200, v225 5200→5800, v248 5200→5600). **Gap-fills:** App-catalog CUSTOM
  apps (admin add/delete compose templates: `_app_catalog_all`/`_app_by_id`, POST
  /api/app-catalog/custom[/delete]); `allow_internal_monitors` Settings toggle (backend
  existed, no UI); `mitigate_failed_units` AI label. **UI:** 3 more tables capped
  (drift/proxmox-snaps/netmap-deps); 3 RTL accent rails mirrored; section-title flex-row
  margin fix (the `:not(#page-home)` id-specificity trap — reset MUST carry the same prefix);
  netmap svg un-capped from .table-card. **i18n:** +17 DICT + 3 HTMLDICT subtitle entries
  (cron/catalog/file-manager chrome) → test_v430_i18n_gate GREEN; fixed 7 visible Hindi
  half-translations. **DEFERRED (documented, low-risk):** alert recovers for container_stopped
  /backup_stale (coalescing mitigates), failed_unit + scap_noncompliant events, fail2ban AI
  card, webhook-replay UI button, opnsense/routeros connect-time IP recheck (LOW, admin-set),
  response byte caps. Commits d97eeb6/8fc97ff/06a9415/dc6416e/d8d30c9. Per-release detail in
  memory [[project_v510_vigilmatters]] + [[project_v510_finalize_sweep]].
- **v5.1.1 = "ClusterMatters"** (**RELEASED TO PRODUCTION 2026-06-26 @3c4751b** — signed
  tag, GH release+sha256(`4f6f6dd1…`)+asc, ghcr 5.1.1/5.1/latest multi-arch, both AUR pushed,
  site+wiki live, prod CI+CodeQL green/0 alerts; prior prod = v5.1.0 @73adec8) —
  #9 Proxmox cluster-wide guest listing (@tbouquet);
  #12 restore page from URL hash on refresh (@tbouquet, merged straight to prod then
  reconciled to test); #10 LocalAI API keys accepted; #11 separate embedding service
  (`rag.embedding_{provider,base_url,api_key}` via `ai_provider.embedding_cfg()`)
  (both @loryanstrant). **Whole-project finalize sweep (2026-06-26, test, no bump):**
  7 audit agents + live pentest + clean CodeQL(0)/bandit(0)/gitleaks. Fixes: IaC dead
  on Postgres (`fpath.exists()`→`backend_exists()`); File-Manager sort name mismatch;
  get_json_obj coercion recurred (`_resolve_targets` + 6 validators + allowlist 500'd on
  array body); CMDB markdown `esc()` escapes `"`/`'`; patch CSV/XML security-update count;
  posture break-glass real per-cred count; dead sort cols + Compliance remediation
  sortable. Perf: container-heartbeat `_config_ro()`; NOC board recursive setTimeout +
  hidden-gate. UI: CMDB lists capped; storage/thermal/ssh-keys/power → audit-scroll;
  DMARC/Firewall/Cron pages wrap each function in a dash-card (DNS pattern). Commits
  c593ff4/c7e9c67. Per-release detail [[project_v511_sweep]]. (NB: this opencode.md
  "Last production release" section below LAGS — authoritative current state is in
  CLAUDE.md; actual last prod is **v5.1.1 "ClusterMatters" @3c4751b, 2026-06-26**.)
- **v5.2.0 = "AccessMatters"** (**RELEASED TO PRODUCTION 2026-06-26 @6e857db** — signed tag
  Good-sig, GH release tarball+sha256(c2208146)+asc, ghcr 5.2.0 multi-arch, both AUR pushed
  [server ships wg-apply helper+sudoers+wireguard-go optdepend], site+wiki[+wg-access page]
  live, prod CI green + CodeQL 0; both mains lockstep at post-release 90b6272. GOTCHA: harness
  classifier hard-blocks prod-deploy + self-perm-grant when the session opened "test only" →
  user runs deploy via `!`. prior prod = v5.1.1) — **WG Access**, a built-in light WireGuard road-warrior VPN
  (Admin → WG Access). Hub = the RP host (userspace `wireguard-go`) → integrations
  pattern via root-owned scoped-sudo helper `packaging/remotepower-wg-apply` (argv-only,
  no shell), NOT the agent channel. Two-level Tunnel→Client (reach-scope RBAC + TTL +
  full/split tunnel; browser X25519 keygen → QR/.conf, privkey never sent). 3 events
  `vpn_client_*` (WEBHOOK_EVENTS now **85**). New `wg_access.py` + `static/js/wg-access.js`.
  **FINALIZE SWEEP folded in (2026-06-27, test, no bump):** 6 audits + live pentest + SAST
  0. 2 Low fixes: disabling a tunnel now tears it DOWN (was re-syncing up); dashboard-only
  tunnels get an explicit nft DROP forward chain. Binding: NEW `vpn` RAG source (5 spots) +
  `remote_access` AI advisor (24th card) + tunnel-stats/endpoint render. i18n +4 DICT/3
  Hindi; dedup `_fmtBytes`; docs + `security-review-5.2.0.md` (keep-3, pruned 5.0.1).
  Per-release detail [[project_v520_accessmatters]].

## Last production release: v5.0.1 "TemperMatters" — RELEASED TO PRODUCTION 2026-06-22

Promoted at `ce79c87` (CHANGELOG date-flip commit): signed tag v5.0.1 (GPG
D488AF115D2CCDBF, Good sig — USER ran `git tag -s` interactively to prime gpg-agent,
I signed `.asc` + pushed in the warm window), `remotepower/main` fast-forwarded
`2db8756→ce79c87` (24-commit v5.0.1 line), **prod CI green + CodeQL 0 open alerts**
(the committed `.github/codeql/codeql-config.yml` paths-ignore + query-filters is
honored by prod default-setup → inherent-FP rules filtered at analyze, genuine queries
clean). GH release on tyxak/remotepower w/ tarball+sha256 (`7d8a7cd0…`)+asc (all
verified, Good sig); ghcr **5.0.1/5.0/latest** anon-pull (public stuck, **multi-arch
amd64+arm64** confirmed in the manifest list); both AUR pkgs bumped+pushed (agent
`951b4ed`, server `37bebec`, PGP-verified makepkg build); marketing site refreshed +
live (remotepower.tvipper.com v5.0.1/TemperMatters, "New in" rewritten, 17 screenshots
refreshed, logos byte-identical, all assets 200); wiki refreshed (54 pages, Home
codename→TemperMatters, dropped v4.7.0 keep-last-5). **Tarball 21M** (the new 9.7M
animated dashboard GIF in docs/screenshots — verified clean, no .enc/backup/.git/secret
leakage). Post-release staging (AUR PKGBUILDs @283a227 + gen-wiki codename @07a3f95)
committed to both remotes past the tag. The whole release ran headless EXCEPT the one
interactive `git tag -s`. Per-release detail in memory [[project_v501_tempermatters]] +
[[project_v501_finalize_sweep]].

(Previous: v5.0.0 "CTRLMatters" — RELEASED TO PRODUCTION 2026-06-22.)

Promoted at `6b8fe8d` (the CRITICAL backup-runaway fix): signed tag v5.0.0 (GPG
D488AF115D2CCDBF, Good sig), both remotes fast-forwarded, prod CI green + **CodeQL
0 alerts** (one js/xss-through-dom #51 in the v5.0.0 netmap scope-picker was FIXED
not dismissed — escaped the static `All` label, cleared on rescan), GH release w/
tarball+sha256 (`b4143e29…`)+asc (all verified), ghcr **5.0.0/5.0/latest** anon-pull
(public, multi-arch), both AUR pkgs bumped+pushed (PGP-verified makepkg build),
marketing site refreshed + live (remotepower.tvipper.com v5.0.0/CTRLMatters, logos
byte-identical), wiki refreshed (54 pages). Tarball 12M, verified clean (no backup
archives/blobs). **Release was paused mid-promote**: user spotted a runaway flood of
`remotepower_data_*.tar.gz.enc` on the live server — the scheduled-backup 24h gate
used `Path.exists()` on a DB-backed state key under SQLite (always False → backup on
EVERY heartbeat). Fixed (`backend_exists()`), regression-tested, THEN promoted. GPG
SIGNING GOTCHA confirmed: headless `git tag -s` times out (pinentry, no TTY) — the
USER ran the signed `git tag -s` interactively (primes gpg-agent); I then signed the
`.asc` + everything else within the warm-cache window. Also: a `git fetch remotepower`
PRUNED the local v5.0.0 tag mid-release (had to recreate+repush it); push tags BEFORE
any fetch. Post-release staging (AUR PKGBUILDs + gen-wiki codename + xss fix) committed
to both remotes past the tag. Per-release detail in memory [[project_v500_ctrlmatters]].

(Previous: v4.9.0 "ResolutionMatters" — RELEASED TO PRODUCTION 2026-06-18.)

Promoted at `ef3b381`: signed tag v4.9.0 (GPG D488AF115D2CCDBF), both remotes
fast-forwarded, prod CI + CodeQL green (0 alerts), GH release w/ tarball+sha256
(`51cb23a2…`)+asc, ghcr 4.9.0/4.9/latest anon-pull (public), both AUR pkgs pushed
(PGP-verified), marketing site live, wiki refreshed (52 pages). Tarball minimal
(12M — Makefile cache excludes unanchored to strip nested `.mypy_cache`). The full
release procedure + gotchas are in the sections above; per-release details in
memory [[project_v490_dns_dashboard]].

(Previous: v4.8.0 "OnboardingMatters" — RELEASED TO PRODUCTION 2026-06-17.)

**PROMOTED TO PROD 2026-06-17** at commit `056711c`: `make check` green (JSON +
SQLite 3911 each, lint clean); signed tag `v4.8.0` (GPG D488AF115D2CCDBF, Good
signature); both remotes fast-forwarded (remotepower/main f99e61b→056711c); GH
release on tyxak/remotepower with tarball + sha256 (`48e9abb…`) + `.asc` (all
verified); prod CI + CodeQL green; multi-arch ghcr.io/tyxak/remotepower **4.8.0 /
4.8 / latest** built + anon-pull-verified (public sticks); **both AUR pkgs bumped +
pushed** (agent 4.8.0 live, server `ee14381`, PGP-verified build); **marketing site
refreshed + deployed live** (remotepower.tvipper.com v4.8.0 verified, logos
byte-identical, dead Manual.html footer link repointed to /docs). AUR staging
PKGBUILDs committed post-release @a0acde2 (both remotes). Independently pentested
this cycle (bandit/semgrep/gitleaks/njsscan/nuclei/wapiti + manual auth/RBAC/SSRF/
traversal/brute-force probes against a local stack) — **no real findings**; SAST
hits all intentional sinks or already-mitigated (see [[project_v480_finalize]]).

### Pre-promotion dev history (now shipped)
v4.8.0 was on `origin/main` (TEST), unsigned, release-ready before promotion. Server
+ agent version = 4.8.0; `make test-both` green (JSON 3894 OK, SQLite 3894 OK). Pushed
@b672dcc.

**v4.8.0 content:** install-easification epic (unified `install.sh` wizard,
one-command Docker w/ HTTPS-by-default, served `/install` one-liner agent, baked
signed quick-install agent that enrols by hostname, `install.sh agent push` SSH
bootstrap, uninstall for server/agent/demo, scaling reframed as advanced) +
Manual.html removed; a **DMARC/SPF/DKIM monitor** (DNS posture + IMAP RUA
aggregate-report ingestion + mailbox monitor); a11y (#U1 modal names, #U3
confirm/prompt migration); agent parity (#A3 Win NVIDIA GPU, mac loadavg/fd); the
multi-version **CVE "Scan all devices" browser-hang fix** (`_close_inherited_fds`);
scanner CWE-732 fix; and the finalize sweep below.

POST-FINALIZE (same v4.8.0, on test): a DMARC **Clear reports** button
(`DELETE /api/dmarc/reports`) @775715f; and an **IP reputation (DNSBL) monitor**
with the page renamed **DMARC → Reputation/DMARC** @85bc35f — `ip_reputation.py`
(pure DNSBL checker) + `/api/reputation/*` + a 6h `run_reputation_scan_if_due`
cadence + an `ip_blacklisted` / `ip_blacklist_cleared` event pair wired through
ALL registries (now **70 webhook events**; only `test_v184`'s expected-set pin
needed bumping). The Reputation/DMARC nav button is now in its alphabetical "R"
slot (Predictive health → Reputation/DMARC → Risk) — the Security sidebar group
is fully A→Z. @69aab04 also added DNSBL **rate-limiting** to the reputation scan
(per-IP cooldown + max-per-run cap + wall-clock budget + inter-IP delay; cadence
has no sleep so it never bursts the DNSBLs or blocks a heartbeat) and a strict
`ip_reputation.valid_zone()` hostname guard on the DNS query name. A surgical
review of all post-finalize code found no gaps. @85046ae fixed live-use spam: DNSBL
`127.255.255.x` status codes (e.g. public-resolver refusal) were miscounted as
listings → false/flapping `ip_blacklisted`; now only `127.0.0.0/8` minus
`127.255.255.0/24` counts, plus flap dampening (`IP_REP_CONFIRM`=2, alerted flag,
clear only on a clean scan). Also dropped the duplicated `name`=IP from the alert
payload and added a DMARC-IMAP `verify_tls` toggle (internal/self-signed Dovecot).

**v4.8.0 SWEEP ROUND 2 (2026-06-17, on test, unsigned) — whole-project, 6 audit
agents + live `remote.tvipper.com` test.** Fixes: (a) **reputation renderer showed a
false "Clean"** when a target's DNSBLs were unreachable (the `127.255.255.x` refusal
the @85046ae fix produces) — `loadReputation` ignored `errors`/`ok`; now an amber
"N unreachable" partial state + listing `codes`/TXT `reason` on hover, all escHtml'd.
(b) integrations `_STATS` gained adguard `protection` + truenas `alerts_warn` chips
(info-only; tile colour was already correct). (c) **perf S1**: heartbeat
`cmd_output.json` → `entity_get`/`entity_set` single-row on the DB backend (it's an
ENTITY file; old `load()` rebuilt every device's window per command-result heartbeat;
mirrors the metrics path). (d) **i18n**: added Reputation/DMARC page coverage (4
HTMLDICT subtitles + 4 section titles ×4 langs) and fixed **21 Hindi nav labels** that
a machine-block dup was overriding. Docs: README +v4.8 bullet, features.md →
"Reputation/DMARC" + DNSBL paragraph. Box-overflow + typography verified clean;
security audit of the new code clean; webhook count is **70** (correct — a "should be
69" report was a regex miscount on `rogue_uid0`). DEFERRED still: cold-blob→ENTITY for
the other heartbeat blobs, client Checks/Alerts tbody diff-guards, systemic Hindi
machine-block half-translation (~700 strings, pre-existing), Arabic `[dir=rtl]` CSS.

**i18n DICT is two stacked blocks — fixing a translation means patching the LATER
(machine) dup, never deleting it.** `i18n.js` `DICT` = a curated block (single-quoted
keys, correct hi) followed by a machine-generated block (double-quoted keys); ~30 keys
appear in BOTH and **the later (machine) one wins**, so a wrong machine-block Hindi
shadows a correct curated one. To fix: regex-replace the machine entry's `"hi":"…"`
in place. DON'T delete the machine dup — `test_themes_i18n.test_sample_static_strings_
translated_all_langs` asserts `"ACME certificates"`/`"Accounts"` exist in **double-
quoted** form, so deletion (leaving only the single-quoted curated copy) fails it.

**v4.8.0 FINALIZE SWEEP (2026-06-17, on test) — durable lessons:**
- **Lock-nesting bit AGAIN (B2, metric webhooks).** `process_metric_thresholds`
  fired `_fire_metric_webhook → fire_webhook` from INSIDE the heartbeat's
  `_DeviceUpdate` lock → nested `BEGIN IMMEDIATE` → alert silently dropped under
  SQLite. Fixed with opt-in `defer=True`: a local `_emit` buffers when deferring
  (caller fires post-lock) but calls the patchable module-level
  `_fire_metric_webhook` otherwise — so the 11 existing metric tests pass
  unchanged. THE RULE KEEPS RECURRING via TRANSITIVE chains a direct
  `fire_webhook`-in-lock grep misses — trace two levels deep.
- **SSRF connect-time recheck is the durable pattern for ANY new outbound
  feature.** Fixed 3 paths: proxmox "Test" (form host skipped the preflight the
  save path runs), AI model-lookup GET (followed redirects, unlike the POST
  path), web-push send (bare urlopen → injected `_ssrf_safe_opener(
  allow_loopback=False, no_redirect=True)`). routeros/opnsense connect-time
  recheck is a known LOW residual (callers preflight; admin-only).
- **New privileged drift mutations need `require_perm('mitigate',[dev_id])`,
  not bare `require_auth`** (a viewer could accept a tamper baseline / wipe
  drift). A test that stubs auth must ALSO stub `require_perm` (test_v220 pattern).
- **Agent: every NEW host-fact read needs `host_path()`** — collect_host_config,
  agent file/job checks, the systemctl probe were direct reads (fixed);
  apply-host-config now disabled in-container.
- **Editing the 40k-line api.py via the edit tool is flaky under the proxy** —
  use a `python3 - <<'PY'` replace-with-`assert count==1` script for multi-anchor
  api.py edits.
- Data-binding already complete; CSP clean (live headers verified); typography
  on-scale (only report.css/swagger.css folded); boxes well-capped (only
  patch-catalog third-party block fixed); i18n chrome correct (fixed Hindi
  "Add X" half-translations). Arabic RTL *text* is correct + `dir=rtl` is set, but
  styles.css has no `[dir=rtl]` layout overrides → RTL layout flip is a documented
  follow-up.
- Deferred perf backlog (HIGH-value but risky → NOT done): promote cold-blob
  `containers.json`/`cmds.json`/`update_logs.json`/`uptime.json`/`backup_state.json`
  to per-device ENTITY files (O(fleet)→O(1) on the heartbeat path); client
  B13/B14 (dashboard re-append every tick, alerts/checks diff-guard).

## Prior production release: v4.7.0 "IntegrationsMatters" — RELEASED TO PRODUCTION 2026-06-15

homelab integrations + rich tiles, containerized agent, fleet GPU page (NVIDIA+AMD,
**trend sparklines** + **thermal alerting** reusing the existing `temp_high` event)
+ a whole-project finalize sweep. **PROMOTED TO PROD 2026-06-15**: signed tag
`v4.7.0` @c8f3cde (re-signed onto the make-dist fix), both remotes fast-forwarded,
GH release on tyxak/remotepower w/ tarball+sha256+asc (all verified), prod CI green,
multi-arch ghcr.io/tyxak/remotepower:4.7.0/:4.7/:latest built + anon-pull-verified
(public sticks — not first publish). Integrations live-verified against the user's
real homelab. **AUR both pkgs bumped+pushed (4.7.0, PGP-verified) and marketing
site refreshed + deployed live (remotepower.tvipper.com, v4.7.0 verified)** — the
release is FULLY done. AUR staging PKGBUILDs committed post-release @a80fa30.

GOTCHA that bit THIS release (fix in c8f3cde): `make dist` runs the suite against a
STAGED tree that EXCLUDES `./.github` (and CLAUDE.md, docs/*-internal.md, site,
deploy). A test that `read_text()`s any excluded path (here
`test_docker_agent.test_release_workflow_publishes_agent_image` reading
`.github/workflows/release.yml`) ERRORS the whole release build — and `make dist`
is NOT in `make check`, so it's only caught at release time. New such tests MUST
`skipTest` when the file is absent. Also add new big local caches (`.codeql-cache`)
to the `make dist` `--exclude` list (it's a hand-maintained list, NOT gitignore).

**v4.7.0 FINALIZE SWEEP (2026-06-15, on test):** whole-project finalization —
NOT just the last commits. Landed: correctness/XSS/SSRF fixes, perf, typography,
box-overflow caps, wider sidebar+PWA sync, docs. Durable lessons it surfaced:
- **Lock-nesting bit AGAIN** (`mcp_confirmation_expired`): `_prune_confirmations`
  fired `fire_webhook` while the caller held `_LockedUpdate(CONFIRMATIONS_FILE)`.
  Fixed (returns payloads → `_fire_expired_confirmations` after the lock). The
  rule keeps recurring — grep new `fire_webhook`/`audit_log` for lock context.
- **`_poll_one_integration` early returns MUST be symmetric** (id/label/type/
  checked) — `_persist_integration_results` subscripts them; a blank-URL instance
  used to KeyError and abort the whole persist batch (silent state+alert loss).
- **`get_json_body()` now coerces non-dict → `{}`** (a top-level JSON array is
  truthy and slipped past `or {}`, 500ing the ~180 `.get()` callers).
- **Unmonitored-data-visibility is a PRINCIPLE**: telemetry/inventory views
  (thermal, power, storage, exposure, SMART disk-health/tracked/unstable, patch
  catalog, listening-ports, processes, GPU) SHOW unmonitored hosts (flagged
  `monitored:false`); ONLY alerting/health/SLA/needs-attention/chargeback
  suppress them. New rows-over-fleet views must include unmonitored + flag them.
- **Sidebar is now 240px** (was 220) — keep `.app-content` margin-left in
  lockstep. The nav-label ellipsis rule is now applied in ALL display modes (the
  PWA-only `not (display-mode: browser)` scope was why the PWA clipped labels the
  browser showed whole). `body{}` now anchors the canonical **14px** body size.
- **SSRF**: Proxmox + AI-provider HTTP are now **no-redirect** (can't replay the
  token/API-key to a rebound host). `tls_monitor` connect-time IP recheck is a
  known follow-up — can't blanket-block private IPs there (internal-host cert
  monitoring is a legit feature); needs a loopback/link-local/metadata-only block.
- Agent containerized reads must use `host_path()` — `/proc/net/arp`, clamav DB,
  rkhunter log were direct reads (fixed). `cpu_percent(interval=None)` now (primed
  at import) — never block 0.5s on the heartbeat hot path.

Durable gotchas that keep biting (verify on every relevant change):
- **FLEET_EVENTS source-window pins are brittle.** Adding events to the `app.js`
  `FLEET_EVENTS` Set pushes `.slice(`/dedup markers past the fixed-size
  `js[start:start+N]` windows in `test_v223`/`test_v248` → bump N. And
  `test_v184.test_expected_event_set` pins the exact WEBHOOK_EVENTS set. (Bit twice
  adding `integration_down`/`integration_recovered`.)

Durable gotchas that keep biting (verify on every relevant change):
- **Heartbeat sanitizer must persist any sysinfo field a check/UI reads.** A
  field the agent sends but `safe_si` drops silently never reaches the server-side
  check or the UI (the `proc_names` / `mailq` / `last_oom_proc` class). v4.6.0 also
  surfaces CPU model / kernel / total RAM / total disk in the device drawer
  (`case 'sysinfo'`) — they're persisted; bind new ones the same way.
- **The denylist-role bug class** (`role not in ('viewer','mcp')`): a custom
  operator role is neither, so it reads as admin. ALWAYS gate on
  `_resolve_role(role).get('admin')`. Fixed in v4.4.0 (require_auth) and again in
  v4.6.0 (`handle_config_get`, the notification-count handler). Grep for the
  pattern before shipping any role gate.
- Box-overflow: `.table-card` caps at 480px; wrap variable tables in
  `scrollable-table-wrap audit-scroll`; bare lists get `.scroll-cap`(-sm). Fold
  font sizes onto {28,16,14,13,12,11,10}px (`tests/test_v430_typography.py`).

The big subsystems (and their "touch every registry" gotchas):

- **Per-host Checks engine** — `_host_checks(dev_id, dev, …)` in `api.py` is the
  ONE place every check row is built (reachability, resources, posture, hardware,
  custom checks, custom-script results). `handle_device_checks` + `handle_fleet_checks`
  + the `checksrollup` dashboard widget all call it; thread new inputs
  (cve_high, disk_eta, custom_defs, scripts, exposure_mutes) through all three.
  Surfaced on the **Checks** page (under Monitoring). Hide-muted + hide-unmonitored
  default ON. World-exposed-port check honours `exposure_mutes`.
- **Custom checks** — `SERVER_CHECK_TYPES` (process/port, evaluated in
  `_eval_custom_check`) vs `AGENT_CHECK_TYPES` (file/job/log, pushed to the agent
  in the heartbeat `agent_checks` key, evaluated by `eval_agent_checks` in the
  agent, reported back in `sysinfo.custom_check_results`).
- **Dashboard widgets — keep `api.DASHBOARD_WIDGETS` (server tuple) and
  `DASH_WIDGETS` (client array, app.js) IN LOCKSTEP** — exact same keys in the
  same order. A guardrail test (`test_v3140.TestDashboardCustomization`) pins
  `js_keys == api.DASHBOARD_WIDGETS`. Every widget key needs a `data-widget="<key>"`
  card in index.html and a renderer. Widget keys must be `[a-z]+` only (the test
  regex is `key:\s*'([a-z]+)'` — no digits/underscores). New widget LOCALS inside
  `_renderHomeWidgets` must be uniquely named — a duplicate `const` is a
  function-scope SyntaxError that only shows in full context (`tests/test_jsload.py`
  V8 guard catches it). Heavy server-backed widgets (checksrollup, diskfill) are
  gated behind the `?w=` enabled-widget hint from the client.
- **Alert correlation** — `_annotate_alert_correlation` tags `_root_cause` /
  `_symptom_of` (symptom set = `ALERT_SYMPTOM_EVENTS`) for the host-grouped inbox.
- **Homelab software integrations (v4.7.0)** — connectors are PURE
  `health(inst, http_client)→dict` parsers in the sibling module
  `server/cgi-bin/integrations.py` (unit-tested with a fake client, in the LINT +
  TYPECHECK baseline). `api.py` owns the rest: `_SSRFIntegrationClient` (reuse the
  `_url_targets_local_or_meta` pre-flight + `_ssrf_safe_opener(allow_loopback=False,
  no_redirect=True)` connect-time guard for ANY new outbound feature),
  `run_integrations_if_due()` in `main()`'s cadence (modeled on the monitors
  subsystem, NOT `_host_checks` — integrations aren't devices), and
  `_persist_integration_results` (flap-dampened `integration_down`/`recovered`;
  fire AFTER the lock). Adding a connector = one decorated function; nothing else.
  Secrets MUST be named `secret` (auto-redacted by `_scrub_config_secrets`); the
  raw `url` is admin-gated. `show_homelab` (default on) is the enterprise kill
  switch — off → no polling, no UI, no widget.

## Adding a RAG source — touch FIVE places (the save whitelist is the silent one)

A new fleet-knowledge source = a pure `build_<x>_corpus(...)` in `rag_index.py`
PLUS wiring in **five** spots, or it half-works:
1. `_AI_DEFAULTS['rag']['sources']` (api.py) — default on/off.
2. `_rag_source_files(sources)` — the store files whose mtime triggers lazy reindex.
3. `_rag_build_corpus(cfg)` — load the store(s) + call the builder (wrap in try/except).
4. **`handle_ai_config_set`'s save whitelist tuple** (api.py ~21268) — a fixed
   `for k in (...)` list. **Miss it and the Settings toggle silently does NOT
   persist** (the value falls back to its default). This bit the v4.10.0
   firewall/integrations/backups sources (whitelist was never extended past
   v4.1.0's 7 keys) — found+fixed in the v4.10.0 finalize sweep (`dns_email`).
5. Settings UI — the `ai-rag-src-<id>` checkbox in `index.html` + `_setSrc` (load)
   + the save object in `app.js`.
The builder must be **defensive about store shape** (dict-of-id OR list) since
`_rag_build_corpus` passes `load(FILE) or {}` straight in. A guardrail test
should assert the source appears in `_AI_SRC` for all of 2/3/4 (see
`tests/test_v4100_rag_sources.py::TestApiWiring`).

## Storage keys: gate on `backend_exists()`, NEVER `Path.exists()` (SQLite-blind bug)

Any `DATA_DIR`-relative `*.json` is a logical storage key. Under the SQLite/
Postgres backend it lives in a DB table, so there is **no file on disk** —
`Path.exists()` returns False for it forever. Code like
`state = load(F) if F.exists() else {}` therefore silently reads `{}` on every
call under SQLite, so any throttle/dedup keyed on that state is defeated.
**Always use `backend_exists(F)`** (the storage-aware check) for a load-gate on a
storage key. This shipped as a **CRITICAL runaway in v5.0.0**: the daily
`_maybe_run_scheduled_backup` gate used `state_file.exists()` → under SQLite the
persisted `last_run` was never read → a full encrypted backup ran on EVERY
heartbeat (hundreds of archives, disk/CPU churn). The sibling
`_maybe_check_disk_space` had it right. Two exceptions that ARE real files and so
correctly use `.exists()`: `STORAGE_MARKER_FILE` (read before the backend is even
chosen) and the `.backup_in_progress` sentinel (a deliberate flock-style lock).
Note `.exists()`+`.stat().st_mtime` cache-invalidation (attention/risk digests)
also can't work on DB rows — those caches just always recompute under SQLite
(perf-only; a real fix needs storage mtime support). Guardrail:
`tests/test_v500_sweep.py::TestScheduledBackupGate` fails under the SQLite leg of
`make test-both` if the gate regresses.

## Never call a self-locking helper while holding _LockedUpdate (SQLite nests → OperationalError)

`audit_log()` AND `fire_webhook()` both take their own `_LockedUpdate` (audit
hash-chain; alert/fleet-event recorders). Under the SQLite backend every file in
`DATA_DIR` shares ONE per-directory connection, so calling either from inside
another `_LockedUpdate` / `_DeviceUpdate` block issues a nested `BEGIN IMMEDIATE`
→ `OperationalError`, which the recorders swallow (`try/except: pass`) — the
alert/event/audit row silently vanishes. Pattern: collect a `pending_audit`
tuple / `pending_webhooks` list inside the lock, fire it AFTER the block exits.
See `_provision_or_promote_user`, the heartbeat's `_reinstall_audit_pending`, the
SNMP-metric path, and `_ingest_custom_script_results` (v4.6.0 fix). When adding
any `fire_webhook`/`audit_log` call, confirm you're not inside a lock.

**This applies to the `_maybe_sample_*` history writers too** — they each take
their own `*_HIST_FILE` `_locked_update`. `_ingest_hardware` was calling
`_maybe_sample_smart` / `_maybe_sample_gpu` from INSIDE its `_locked_update(
HARDWARE_FILE)` block (SMART under `try/except: pass` → silently dropped; GPU bare
→ would raise). It stayed latent because the test fixtures carried no SMART/GPU
data under SQLite. v5.0.0 sweep fix: capture the sample data in a local inside the
lock (`smart_sample`/`gpu_sample`/`temp_sample`), call `_maybe_sample_*` AFTER the
`with` exits. Regression test (`tests/test_v500_thermal.py`) drives the real
ingest path and asserts all three history stores are written under both backends.

## New secret-bearing config field → add it to the GET /api/config scrub (admins too)

`handle_config_get` redacts secrets to a `*_set` / `*_configured` boolean for
EVERYONE, admins included (see `ai.api_key`→`ai_configured`, `oidc_client_secret`
→`_set`). The legacy scalar `webhook_url` was the one exception — returned raw to
admin tokens — until the v5.0.0 sweep (a Slack/Discord/Teams URL embeds its token
in the path, so the URL itself is a reusable credential in a GET body). It now
returns only `webhook_configured`; the Settings UI shows a "configured — leave
blank to keep" placeholder and only POSTs `webhook_url` when the admin types a new
one. RULE: any new config field that holds a token/URL-with-secret/password must be
withheld on read (boolean indicator only) and re-entered to change — never echoed
back, not even to admins. The recursive `_scrub_config_secrets` backstop only
catches secret-NAMED keys; a field like `webhook_url` needs an explicit `pop`.

## Adding a webhook/alert event — touch EVERY registry

A new event type (`fire_webhook('my_event', …)`) has to be registered in
several places or it half-works in ways the test suite and the UI won't
forgive. When adding one:

**Server (`server/cgi-bin/api.py`):**
1. `WEBHOOK_EVENTS` tuple — the canonical list (a guardrail test pins the
   exact set; `tests/test_v184.py` must be updated too).
2. `_ALERT_RULES` — severity mapping. **Miss this and the event fires a
   webhook but never lands in the Alerts inbox** (`_alert_severity` returns
   None → skipped). Silent.
3. `CHANNEL_KINDS` — map it to a channel "kind" so the routing matrix gets a
   row and `EVENT_KIND_MAP` resolves it.
4. `_webhook_title` — friendly title (has a fallback, but add it).

**Frontend (`server/html/static/js/app.js`):**
5. `FLEET_EVENTS` Set — or the event silently disappears from the dashboard
   activity feed (a guardrail test, `tests/test_v223.py`, enforces this set
   equals the server's).
6. `_homeActivityAttrs` switch — click-through routing for the feed item
   (guardrail test `tests/test_v225.py` requires a case for every event).

The three guardrail tests catch 1/5/6 on the next run; 2/3/4 are silent —
verify them by hand. Reference commit: the v3.4.0 `smart_failure` /
`kernel_outdated` events.

**7. RECOVER/CLEAR events — the match key MUST be in the `_record_alert` payload
whitelist (v4.9.0 fix).** `_record_alert` stores only a *whitelisted* subset of
the payload onto the alert (`for key in (...)` ~api.py:4757). `_auto_resolve_alerts`
finds the open alert to close by matching a `sub_match` key. If that key isn't in
the whitelist it was never stored → the recover event silently never resolves the
alert → it sits OPEN FOREVER (and the monitor's `alerted` flag stops it re-firing).
This bit `integration_recovered` (integration_id), `ip_blacklist_cleared` (ip) and
`resolver_recovered` (target) at once. When adding a recover event: add its
matcher branch in `_auto_resolve_alerts` AND ensure the match key is whitelisted in
`_record_alert`. **Regression tests MUST build the alert via the real
`_record_alert`/`fire_webhook` path — a hand-built `{'payload': {...}}` dict
bypasses the whitelist and gives false-green (the old integration test did exactly
this).** See `tests/test_v490_resolver_health.TestAutoResolveRealPath`.

## Version-bump checklist

When bumping to vX.Y.Z:

1. `SERVER_VERSION` in `server/cgi-bin/api.py`
2. `VERSION` in `client/remotepower-agent.py` + sync to extensionless
3. `CACHE_NAME` in `server/html/sw.js`
4. All `?v=` cache-bust occurrences in `server/html/index.html`
5. README version badge
6. Create `tests/test_vXYZ.py` with strict pins
7. Loosen previous `tests/test_vXYZ.py` strict pins to regex
8. Create `docs/vX.Y.Z.md`
9. New top entry in `CHANGELOG.md`
10. Update the in-app Help/Documentation page (the "Documentation"
    page in `server/html/index.html`, ~line 1653) so it describes the
    new version's features — including the "What's new — vX.Y.Z" card.
11. Also bump `VERSION` in `client/remotepower-agent-win.py` and
    `client/remotepower-agent-mac.py`.

The `test_vXYZ.TestVersionBumps` class catches most of these.

**MAJOR-version bumps (e.g. 3.x → 4.0.0):** the *old* `tests/test_vXYZ.py`
version-consistency checks hard-cap the major version in their regexes
(`r"SERVER_VERSION\s*=\s*'3\.\d+\.\d+'"`, `?v=3\.…`, `version-3\.…`,
`remotepower-shell-v3\.…`, `^## v3\.…`, and the `test_v260` post-2.6 alternation).
Bumping past major 3 fails ~120 tests across ~27 old files at once. Fix by
broadening the major in those regexes to `\d+` (e.g. `3\.\d+\.\d+` → `\d+\.\d+\.\d+`),
NOT by editing literal dotted assertions like `assertNotIn("?v=3.13.0")` (those are
correct history checks). A minor/patch bump within the same major doesn't hit this.

**Renaming a dev version into a release:** if the accumulator version (e.g. the
unreleased `v3.14.0`) is promoted straight to the release name (`v4.0.0`), it's a
*rename*, not a new doc — `git mv docs/v3.14.0.md docs/v4.0.0.md`, retitle the
CHANGELOG section + the "What's new" card in place, and repoint links. That keeps
the "last 5 version docs" set at exactly 5 (no deletion needed).

**CSP false-positive guard:** `element.onclick = fn` / `el.addEventListener(...)`
set from JavaScript is NOT a CSP violation — `script-src 'self'` only blocks inline
`on*=` HTML *attributes*, inline `<script>`, and literal `style="…"` inside HTML
strings. Don't "fix" JS event-handler property assignments; they're fine.
