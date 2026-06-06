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

## Threat model & hardening

RemotePower's security model, SSRF protections, CSP posture, and the per-release
security reviews are documented in [`docs/security.md`](docs/security.md).
