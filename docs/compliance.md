# RemotePower — security control mapping (SOC 2 / ISO 27001)

> **What this is:** a mapping of RemotePower's built-in capabilities to the common
> framework control areas auditors ask about — SOC 2 (Trust Services Criteria) and
> ISO/IEC 27001:2022 (Annex A). **What it is not:** a certification, an attestation,
> or a claim that deploying RemotePower makes *you* compliant. Compliance is a
> property of your whole organisation and operating procedures; RemotePower provides
> *technical controls and evidence* that support several criteria. Items marked
> **(operator)** depend on how you configure and run it.

Many of these controls are **opt-in** — see the linked feature docs and
`CHANGELOG.md` for how to enable each.

## Access control & identity

| Capability | SOC 2 | ISO 27001:2022 |
|---|---|---|
| RBAC — admin/viewer/auditor/finance + custom roles scoped to groups/tags/sites | CC6.1, CC6.3 | A.5.15, A.8.2, A.8.3 |
| MFA — TOTP + WebAuthn/passkeys; per-role MFA **enforcement** | CC6.1 | A.5.17, A.8.5 |
| SSO — OIDC / SAML 2.0 / LDAP + SCIM 2.0 provisioning; group→role matrix; SSO-only mode | CC6.1, CC6.2, CC6.3 | A.5.16, A.5.18 |
| Password policy — length / classes / HaveIBeenPwned breach check **(operator)** | CC6.1 | A.5.17 |
| Joiner/mover/leaver — SCIM deprovision revokes access + live sessions at once | CC6.2, CC6.3 | A.5.16, A.5.18 |
| Session controls — concurrent-session caps, idle timeout, active-session revoke | CC6.1 | A.8.5 |
| Service accounts — API keys hashed at rest, per-key device **scope**, source-IP allowlist, rate limit, expiry | CC6.1 | A.5.16, A.8.2 |
| Privileged access — two-person break-glass credential reveal (audited) | CC6.1 | A.8.2, A.8.18 |

## Cryptography & data protection

| Capability | SOC 2 | ISO 27001:2022 |
|---|---|---|
| Encryption at rest — AES-256-GCM DR backups; opt-in config-secret encryption (`RP_CONFIG_KEY`) | CC6.7 | A.8.24 |
| Secrets sourcing — backup/config keys from env **or** an external command (Vault/KMS) | CC6.7 | A.8.24 |
| Credentials at rest — API keys, device tokens, enrolment tokens stored as SHA-256 hashes | CC6.1 | A.8.24 |
| Encryption in transit — TLS 1.2 floor; mutual-TLS agent authentication; CSP / HSTS | CC6.7 | A.8.20, A.8.24 |

## Logging, monitoring & evidence

| Capability | SOC 2 | ISO 27001:2022 |
|---|---|---|
| Audit log — hash-chained (tamper-evident); append-only **WORM** sink option | CC7.2, CC7.3 | A.8.15, A.5.28 |
| Config-change auditing — every settings save records the changed keys | CC8.1 | A.8.32 |
| Centralised logging — webhook/SIEM forwarding, syslog ingest, structured JSON logs + correlation/trace IDs | CC7.2 | A.8.15, A.8.16 |
| Monitoring & alerting — fleet health, service/log/metric alerts, escalation tiers, SLO + error budgets | CC7.1, CC7.2 | A.8.16 |
| Signed evidence — compliance evidence pack + audit-archive export carry HMAC signatures; key rotation | CC7.3 | A.5.28 |
| Self-observability — control-plane uptime, slow-handler ring, client-error beacon | CC7.2 | A.8.16 |

## Vulnerability & configuration management

| Capability | SOC 2 | ISO 27001:2022 |
|---|---|---|
| Vulnerability management — CVE scanning with KEV/EPSS prioritisation; patch status + alerts | CC7.1 | A.8.8 |
| Secure configuration — drift detection + remediation; CIS/posture checks; firewall/fail2ban visibility | CC7.1 | A.8.9 |
| Change management — staged/health-gated rollouts with rollback; audited command queue | CC8.1 | A.8.32 |
| Supply chain — fleet + control-plane SBOM (CycloneDX); SLSA build provenance on release images | CC7.1 | A.5.23, A.8.30 |

## Resilience & operations

| Capability | SOC 2 | ISO 27001:2022 |
|---|---|---|
| Backup & DR — encrypted controller backup, off-host mirroring, **test-restore** verification | A1.2 | A.8.13, A.5.30 |
| Availability — agent/agentless monitoring, maintenance mode/windows, webhook DLQ + replay | A1.1, A1.2 | A.5.30, A.8.16 |
| Boundary protection — SSRF guards on all outbound, per-IP/login rate limits, IP allowlist, CSP | CC6.6 | A.8.20, A.8.23 |
| Multi-tenant isolation — RBAC-scoped soft tenancy (group/tag/site); optional **hard multi-tenancy** (`tenancy_enforced`) with optional Postgres **row-level security** (`tenancy_rls`) **(operator)** | CC6.1 | A.5.15, A.8.2 |

## Operator responsibilities (not provided by the software)

RemotePower supplies technical controls + evidence; **you** still own: the control
*environment* and policies (CC1), risk assessment (CC3), vendor/personnel management
(CC9 / A.5.19, A.6), physical security of your hosts (A.7), and the procedures that
turn these features into operating controls (reviewing the audit log, acting on
alerts, running restore drills, rotating keys). Enable the opt-in controls above,
forward the audit log + alerts to your SIEM, and retain the signed evidence exports
as your audit artifacts.

> Framework control IDs are indicative and current as of the 2022 ISO revision +
> the SOC 2 2017 TSC; map to your auditor's current criteria.

## In-app Compliance page — verdicts you can back up *(v6.3.1)*

The **Compliance** page scores a live control checklist from data the fleet
already reports, across **PCI DSS, HIPAA, SOC 2, ACSC Essential Eight and
SMB1001:2026** (pick the frameworks with the checkboxes). Every control lands
on one of three verdicts:

- **Pass** — observed state satisfies the control.
- **Fail** — observed state violates it, with the offending hosts as evidence.
- **Not assessed** — RemotePower cannot back up a pass. This is deliberate and
  strict: a control does **not** read Pass just because its offenders list is
  empty. If the *capable source* never ran — no host has reported package
  status, no CVE scan is on record, no account baseline exists — the control
  is **Not assessed**, never a silent green. Process controls RemotePower
  doesn't observe (Essential Eight application control / macro policy / user
  hardening; SMB1001 training / IR plan) are shown as Not assessed too, rather
  than hidden — the report discloses its own gaps.

The framework **score is `pass / (pass + fail)`** and ignores Not-assessed, so
"we haven't measured it" can never inflate the number. This is an audit-prep
aid, not a formal attestation — but a green you see is a green the tool can
defend.
