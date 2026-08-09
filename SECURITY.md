# Security Policy

## Supported versions

Security fixes are made against the latest release. Please run a current version
before reporting.

## Reporting a vulnerability

**Please do not open a public issue, PR, or discussion for security
vulnerabilities.**

Report privately via GitHub's **["Report a vulnerability"](https://github.com/tyxak/remotepower/security/advisories/new)**
(Security → Advisories) so we can triage and fix before disclosure.

Please include: affected version, a description and impact, and steps to
reproduce (redact any tokens, credentials, or hostnames).

We aim to acknowledge reports within a few days and will coordinate a fix and
disclosure timeline with you.

## Privileges — what runs as root, and why

Automated scanners flag RemotePower for `sudo` usage. That flag is accurate, and
it is worth being explicit about where privilege is actually held, because the
answer is narrower than "the whole thing runs as root".

**The server does not run as root.** The app server, scheduler and push daemon
run as `www-data` under `NoNewPrivileges=true`, `ProtectSystem=full`,
`ProtectHome=true` and `PrivateTmp=true`. Nothing in the web tier — the API, the
UI, the dashboard you log into — holds root.

**The agent runs as root, by design.** Applying a patch, restarting a unit or
reading SMART data is what the agent is *for*: `dpkg` / `pacman` / `systemctl` /
`smartctl` cannot be driven usefully without privilege. An unprivileged agent
would be a monitoring product that cannot remediate, which is a different
product. The trade is deliberate, and constrained:

- Every subprocess uses the **argv-list form** — no shell interpolation, so
  there is no injection surface — with one exception: the `exec:` command
  channel, which is the operator-facing "run this command on that host" feature
  and is authenticated, authorised and audit-logged as such.
- Agent state lives in `/var/lib/remotepower/` at mode `0700`, enrollment
  credentials at `0600`, written atomically with `O_NOFOLLOW` on every read and
  write to defeat symlink attacks from local non-root users.
- TLS verification is mandatory (`CERT_REQUIRED` + `check_hostname`), and the
  agent never follows HTTP redirects — it posts its own token, so a `3xx` must
  never be replayable to another host.
- Self-updates are SHA-256 verified and applied atomically. Setting
  `/etc/remotepower/require-signed-updates` makes the agent fail **closed**: it
  will refuse any update that is not signed by a pinned release key.
- The systemd unit adds `PrivateTmp`, `ProtectKernelTunables` and
  `ProtectControlGroups`. It deliberately does **not** set
  `ProtectKernelModules` — that directive hides `/lib/modules` and produced
  module-less initramfs images on managed hosts (fixed in v6.2.1).

**`sudo` in the install scripts is installation-time only.** Creating a service
user, writing unit files and installing packages need it; the running services
do not re-acquire it.

Credentials, where they are stored, and their file modes are enumerated in
[`docs/security.md`](docs/security.md).

## Threat model & hardening

RemotePower's security model, SSRF protections, CSP posture, and the per-release
security reviews are documented in [`docs/security.md`](docs/security.md).
